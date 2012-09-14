/* 
 *  ext-dns: a DNS framework
 *  Copyright (C) 2012 Advanced Software Production Line, S.L.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2.1
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free
 *  Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 *  02111-1307 USA
 *  
 *  You may find a copy of the license under this software is released
 *  at COPYING file. This is LGPL software: you are welcome to develop
 *  proprietary applications using this library without any royalty or
 *  fee but returning back any change, improvement or addition in the
 *  form of source code, project image, documentation patches, etc.
 *
 *  For commercial support contact us:
 *          
 *      Postal address:
 *         Advanced Software Production Line, S.L.
 *         C/ Antonio Suarez Nº 10, 
 *         Edificio Alius A, Despacho 102
 *         Alcalá de Henares 28802 (Madrid)
 *         Spain
 *
 *      Email address:
 *         info@aspl.es - http://www.aspl.es/ext-dns
 */
#include <ext-dns.h>
#include <ext-dns-private.h>

extDnsHeader * ext_dns_message_parse_header (extDnsCtx * ctx, const char * buf, int buf_size)
{
	extDnsHeader * header;

	/* return NULL if wrong values are received */
	if (buf == NULL || buf_size == 0)
		return NULL;

	/* get header */
	header           = axl_new (extDnsHeader, 1);
	if (header == NULL)
		return NULL;

	/* process values */
	/* ext_dns_show_byte (ctx, buf[0], "buf[0]");
	   ext_dns_show_byte (ctx, buf[1], "buf[1]"); */

	/* get 16 bit integer */
	header->id       = ext_dns_get_16bit (buf);

	/* ext_dns_int2bin_print (ctx, header->id); */

	header->is_query              = ext_dns_get_bit (buf[2], 7) == 0;

	/* get opcode */
	header->opcode                = (buf[2] & 0x00f >> 3 );
	/* ext_dns_show_byte (ctx, buf[2], "buf[2]");
	   ext_dns_show_byte (ctx, header->opcode, "header->opcode"); */

	/* get other flags */
	header->is_authorative_answer = ext_dns_get_bit (buf[2], 2);
	header->was_truncated         = ext_dns_get_bit (buf[2], 1);
	header->recursion_desired     = ext_dns_get_bit (buf[2], 0);

	header->recursion_available   = ext_dns_get_bit (buf[3], 7);

	/* get response code */
	header->rcode                 = buf[3] & 0x0000f;

	/* get counters */
	header->query_count               = ext_dns_get_16bit (buf + 4);
	header->answer_count              = ext_dns_get_16bit (buf + 6);
	header->authority_count           = ext_dns_get_16bit (buf + 8);
	header->additional_count          = ext_dns_get_16bit (buf + 10);

	return header;
}

char * ext_dns_message_get_label (extDnsCtx * ctx, const char * buffer)
{
	char * label;
	int    bytes_to_read = (char)(buffer[0]) & 0x3f;

	if (bytes_to_read == 0)
		return NULL;
	
	label = axl_new (char, bytes_to_read + 1);

	memcpy (label, buffer + 1, bytes_to_read);

	return label;
}

char * ext_dns_message_get_resource_name (extDnsCtx * ctx, const char * buffer, int buf_size, int * _iterator, axl_bool * _is_label)
{
	/* clear resource name */
	char     * resource_name = NULL;
	char     * label         = NULL;
	char     * aux           = NULL;
	int        offset        = 0;
	int        iterator      = (* _iterator);
	axl_bool   is_label      = axl_false;
	

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Starting to get resource name at iterator=%d, buf_size=%d, buffer[iterator]='%d'",
		     iterator, buf_size, buffer[iterator]);

	while (iterator < buf_size && buffer[iterator]) {
		/* check if this is a we found a label pointer (message
		 * compression 4.1.4 Message compression from RFC1035). */
		if (ext_dns_get_bit (buffer[iterator], 7) && ext_dns_get_bit (buffer[iterator], 6)) {
			
			/* if (is_label == NULL) {
				ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Received a request to process a label compression but found another label at the pointer");
				axl_free (resource_name);
				return NULL;
			}*/ /* end if */
			
			/* found offset label, process it jumping into that position */
			offset = (int)(buffer[iterator] & 0x3f) << 8 | (int)buffer[iterator + 1];
			ext_dns_log (EXT_DNS_LEVEL_DEBUG, "  Found label compression offset=%d, iterator=%d (until now, name is: %s)", offset, iterator, resource_name ? resource_name : "");
			
			if (offset < 12 || offset > buf_size) {
				ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Received a request to process a label compression that is outside the message");
				axl_free (resource_name);

				/* set is label found */
				if (_is_label)
					(* _is_label) = is_label;

				return NULL;
			}
			
			/* notify label found */
			is_label = axl_true;
			
			/* ok, now call the function again to process the label at the position pointed */
			label = ext_dns_message_get_resource_name (ctx, buffer, buf_size, &offset, NULL);

			ext_dns_log (EXT_DNS_LEVEL_DEBUG, "  Label found at the label compression call: %s", label ? label : "");

			iterator ++;

		} else {
			/* get label */
			label = ext_dns_message_get_label (ctx, buffer + iterator);

			/* get length */
			iterator += strlen (label) + 1;
		}
		
		if (label == NULL) 
			break;

		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "  Label='%s', Resource='%s', Is label: %d", 
			     label ? label : "", resource_name ? resource_name : "", is_label ? is_label : 0);

		if (resource_name == NULL) {
			resource_name = label;
			label = NULL;
		} else {
			/* rebuild resource */
			aux = resource_name;
			resource_name = axl_strdup_printf ("%s.%s", resource_name, label);
			axl_free (aux);
		}
		
		axl_free (label);

		/* found one replacement, finish processing here */
		if (is_label)
			break;

	} /* end while */

	/* update caller iterator */
	(* _iterator) = iterator + 1;

	/* set is label found */
	if (_is_label)
		(* _is_label) = is_label;

	return resource_name;
}

axl_bool ext_dns_message_parse_resource_record (extDnsCtx * ctx, extDnsResourceRecord * rr, int * _iterator, const char * buf, int buf_size)
{
	int      iterator = (*_iterator);
	axl_bool is_label;
	int      value;

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Starting to parse resource record at iterator=%d, resource record: %p", iterator, rr);
	if (rr == NULL) {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Received a NULL resource record reference, unable to parse content");
		return axl_false;
	}

	/* store resource name */
	rr->name  = ext_dns_message_get_resource_name (ctx, buf, buf_size, &iterator, &is_label);

	/* failed to get query name */
	if (rr->name == NULL) {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Expected to find owner name in resource record, but found NULL VALUE");
		return axl_false;
	} /* end if */

	/* if (! is_label)
		iterator += strlen (rr->name) + 2;
	else
	iterator += 2; */

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Resource name: '%s' (iterator=%d)", rr->name, iterator);
		
	/* get qtype */
	rr->type  = ext_dns_get_16bit (buf + iterator);
	iterator += 2;
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "qtype received = %d", rr->type);
		
	/* get qclass */
	rr->class = ext_dns_get_16bit (buf + iterator);
	iterator += 2;
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "qclass received = %d", rr->class);

	/* get TTL */
	rr->ttl = ext_dns_get_32bit (buf + iterator);
	iterator +=4;

	/* get RDLENGTH */
	rr->rdlength = ext_dns_get_16bit (buf + iterator);
	iterator += 2;

	/* copy rddata and then process */
	rr->rdata = axl_new (char, rr->rdlength + 1);
	memcpy (rr->rdata, buf + iterator, rr->rdlength);

	/* record current rdata starting position */
	value = iterator;

	/* get values in the rdata session */
	if (rr->type == extDnsTypeA) {
		/* store the IP in readable form */
		rr->name_content = axl_strdup_printf ("%d.%d.%d.%d", 
						      ext_dns_get_8bit (rr->rdata), 
						      ext_dns_get_8bit (rr->rdata + 1), 
						      ext_dns_get_8bit (rr->rdata + 2), 
						      ext_dns_get_8bit (rr->rdata + 3));
	} else if (rr->type == extDnsTypeMX) {
		/* get mx preference */
		rr->preference = ext_dns_get_16bit (rr->rdata);

		/* skip next 16 bits */
		value += 2;
		
		/* get mail exchanger */
		rr->name_content = ext_dns_message_get_resource_name (ctx, buf, buf_size, &value, &is_label);
	} else if (rr->type == extDnsTypeCNAME) {
		/* get mail exchanger */
		rr->name_content = ext_dns_message_get_resource_name (ctx, buf, buf_size, &value, &is_label);
	} else if (rr->type == extDnsTypeNS) {
		/* get mail exchanger */
		rr->name_content = ext_dns_message_get_resource_name (ctx, buf, buf_size, &value, &is_label);
	} else if (rr->type == extDnsTypeTXT) {
		/* get TXT content */
		rr->name_content = axl_new (char, rr->rdlength + 1);
		memcpy (rr->name_content, rr->rdata + 1, rr->rdlength -1);
	} else if (rr->type == extDnsTypePTR) {
		/* get PTR content */
		rr->name_content = ext_dns_message_get_resource_name (ctx, buf, buf_size, &value, &is_label);
	} else if (rr->type == extDnsTypeSOA) {

		/* get mname */
		rr->mname          = ext_dns_message_get_resource_name (ctx, buf, buf_size, &value, &is_label);

		/* get rname */
		rr->contact_address = ext_dns_message_get_resource_name (ctx, buf, buf_size, &value, &is_label);

		/* get serial */
		rr->serial  = ext_dns_get_32bit (buf + value);
		value += 4;

		/* get refresh */
		rr->refresh = ext_dns_get_32bit (buf + value);
		value += 4;

		/* get retry */
		rr->retry = ext_dns_get_32bit (buf + value);
		value += 4;

		/* get expire */
		rr->expire = ext_dns_get_32bit (buf + value);
		value += 4;

		/* get minimum */
		rr->minimum = ext_dns_get_32bit (buf + value);
		value += 4;
	}

	/* next position */
	iterator += rr->rdlength;

	/* set iterator to the last position read */
	(*_iterator) = iterator;

	return axl_true; /* return parse ok */
}

/** 
 * @brief Allows to check if the provided \ref extDnsMessage is query (QR == 0).
 * @param message The extDnsMessage to check to be a query.
 *
 * @return axl_true if the message is a query, otherwise axl_false is
 * returned. Keep in mind that the function will return axl_false in
 * the case of NULL reference received.
 */
axl_bool        ext_dns_message_is_query (extDnsMessage * message)
{
	if (message == NULL || message->header == NULL)
		return axl_false;

	/* return if it is a query */
	return message->header->is_query;
}


axlPointer ext_dns_message_release_and_return (extDnsMessage * message)
{
	ext_dns_message_unref (message);
	return NULL;
}

/** 
 * @internal Allows to parse the DNS message received in buf
 * (buf_size) and according to the header.
 */
extDnsMessage * ext_dns_message_parse_message (extDnsCtx * ctx, extDnsHeader * header, const char * buf, int buf_size)
{
	int             iterator = 12;
	int             count;
	extDnsMessage * message;
	axl_bool        is_label;

	/* create empty message */
	message = axl_new (extDnsMessage, 1);
	if (message == NULL)
		return NULL;

	/* buffer size */
	message->message_size = buf_size;

	/* initialize mutex */
	ext_dns_mutex_create (&message->mutex);
	message->ref_count = 1;

	/* set header */
	message->header = header;
	
	/* parse query question */
	if (header->query_count > 0) {
		/* allocate structure to hold query question */
		message->questions = axl_new (extDnsQuestion, header->query_count);
	}

	/*** QUESTIONS ***/
	count = 0;
	while (count < header->query_count) {

		/* store resource name */
		message->questions[count].qname  = ext_dns_message_get_resource_name (ctx, buf, buf_size, &iterator, &is_label);

		/* failed to get query name */
		if (message->questions[count].qname == NULL)
			break;

		/* if (! is_label)
			iterator += strlen (message->questions[count].qname) + 2;
		else
		iterator += 2;*/

		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Resource name: '%s' (iterator=%d)", message->questions[count].qname, iterator); 
		
		/* get qtype */
		message->questions[count].qtype  = ext_dns_get_16bit (buf + iterator);
		iterator += 2;
		/* ext_dns_log (EXT_DNS_LEVEL_DEBUG, "qtype received = %d", message->questions[count].qtype); */
		
		/* get qclass */
		message->questions[count].qclass = ext_dns_get_16bit (buf + iterator);
		iterator += 2;
		/* ext_dns_log (EXT_DNS_LEVEL_DEBUG, "qclass received = %d", message->questions[count].qclass); */

		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Question item received: %s %s %s",
			     message->questions[count].qname, ext_dns_message_get_qtype_to_str (ctx, message->questions[count].qtype), 
			     ext_dns_message_get_qclass_to_str (ctx, message->questions[count].qclass));

		/* next section */
		count++;
	} /* end if */

	/*** ANSWERS ***/
	/* parse query question */
	if (header->answer_count > 0) {
		
		/* allocate structure to hold query question */
		message->answers = axl_new (extDnsResourceRecord, header->answer_count);
	}
	count = 0;
	while (count < header->answer_count) {
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "ANSWERS: parsing answers=%d count=%d iterator=%d", header->answer_count, count + 1, iterator);

		/* parse resource record */
		if (! ext_dns_message_parse_resource_record (ctx, &message->answers[count], &iterator, buf, buf_size))
			return ext_dns_message_release_and_return (message);

		/* next section */
		count++;
	} /* end if */

	/*** AUTHORITY ***/
	if (header->authority_count > 0) {
		/* allocate structure to hold query question */
		message->authorities = axl_new (extDnsResourceRecord, header->authority_count);
	}
	count = 0;
	while (count < header->authority_count) {

		/* parse resource record */
		if (! ext_dns_message_parse_resource_record (ctx, &message->authorities[count], &iterator, buf, buf_size))
			return ext_dns_message_release_and_return (message);

		/* next section */
		count++;
	} /* end if */

	/*** ADDITIONAL ***/
	if (header->additional_count > 0) {
		/* allocate structure to hold query question */
		message->additionals = axl_new (extDnsResourceRecord, header->additional_count);
	}
	count = 0;
	while (count < header->additional_count) {

		/* parse resource record */
		if (! ext_dns_message_parse_resource_record (ctx, &message->additionals[count], &iterator, buf, buf_size))
			return ext_dns_message_release_and_return (message);

		/* next section */
		count++;
	} /* end if */

	return message;
}


/** 
 * @internal Function to dump DNS resource record into a buffer ready
 * to be sent to the network.
 */
int __ext_dns_message_write_resource_record (extDnsCtx * ctx, extDnsResourceRecord * rr, char * buffer, int buffer_size, int position)
{

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "PLACING Resource record:  Encoding resource name: %s", rr->name);
	position += ext_dns_encode_domain_name (ctx, rr->name, buffer + position);
	
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "   name position after placing name: %d", position);
	
	/* set TYPE */
	ext_dns_set_16bit (rr->type, buffer + position);
	/* ext_dns_show_byte (ctx, buffer[position], "TYPE[0]");
	   ext_dns_show_byte (ctx, buffer[position + 1], "TYPE[1]"); */
	
	/* next two bytes */
	position += 2;
	
	/* set CLASS */
	ext_dns_set_16bit (rr->class, buffer + position);
	/* ext_dns_show_byte (ctx, buffer[position], "CLASS[0]");
	   ext_dns_show_byte (ctx, buffer[position + 1], "CLASS[1]"); */
		
	/* next two bytes */
	position += 2;
	
	/* set TTL */
	ext_dns_set_32bit (rr->ttl, buffer + position);
	
	/* next four bytes */
	position += 4;

	/* set RDLENGTH and RDATA according to the type */
	if (rr->type == extDnsTypeA) {
		/* set RDLENGTH */
		ext_dns_set_16bit (rr->rdlength, buffer + position);
		/* next four bytes */
		position += 2;

		/* set RDATA */
		memcpy (buffer + position, rr->rdata, rr->rdlength);

		/* next record */
		position += rr->rdlength;
	} else if (rr->type == extDnsTypeMX) {
		/* set RDLENGTH */
		/* resource record + initial count + ending \0 + 2 mx preference */
		ext_dns_set_16bit (strlen (rr->name_content) + 4, buffer + position);
		/* next four bytes */
		position += 2;

		/* set MX preference */
		ext_dns_set_16bit (rr->preference, buffer + position);
		position += 2;

		/* encode MX server */
		position += ext_dns_encode_domain_name (ctx, rr->name_content, buffer + position);

		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "   written rdlength: %d", strlen (rr->name_content) + 4);

	} else if (rr->type == extDnsTypeCNAME || rr->type == extDnsTypePTR || rr->type == extDnsTypeNS) {

		/* set RDLENGTH */
		/* resource record + initial count + ending \0 */
		ext_dns_set_16bit (strlen (rr->name_content) + 2, buffer + position);
		/* next four bytes */
		position += 2;

		/* encode CNAME, PTR or NS value */
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "  enconding type %s: %s", ext_dns_message_get_qtype_to_str (ctx, rr->type), rr->name_content);
		position += ext_dns_encode_domain_name (ctx, rr->name_content, buffer + position);

	} else if (rr->type == extDnsTypeTXT) {
		/* set RDLENGTH */
		ext_dns_set_16bit (rr->rdlength, buffer + position);
		/* next four bytes */
		position += 2;

		/* set RDATA as received */
		memcpy (buffer + position, rr->rdata, rr->rdlength);

		/* next record */
		position += rr->rdlength;
	} else if (rr->type == extDnsTypeSOA) {
		/* set RDLENGTH */
		ext_dns_set_16bit (strlen (rr->mname) + strlen (rr->contact_address) + 16, buffer + position);
		/* next four bytes */
		position += 2;

		/* encode mname value */
		position += ext_dns_encode_domain_name (ctx, rr->mname, buffer + position);

		/* encode contact address value */
		position += ext_dns_encode_domain_name (ctx, rr->contact_address, buffer + position);

		/* set serial preference */
		ext_dns_set_32bit (rr->serial, buffer + position);
		position += 4;

		/* set refresh preference */
		ext_dns_set_32bit (rr->refresh, buffer + position);
		position += 4;

		/* set retry preference */
		ext_dns_set_32bit (rr->retry, buffer + position);
		position += 4;

		/* set expire preference */
		ext_dns_set_32bit (rr->expire, buffer + position);
		position += 4;

		/* set minimum preference */
		ext_dns_set_32bit (rr->minimum, buffer + position);
		position += 4;
	} else {
		/**** UNKNOWN RECORD ****/
		/* unknown record type, write it as received */
		ext_dns_set_16bit (rr->rdlength, buffer + position);
		position += 2;

		/* set RDATA as received */
		memcpy (buffer + position, rr->rdata, rr->rdlength);

		/* next record */
		position += rr->rdlength;
	}

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "   after writting rdata section: %d", position);

	return position;
} 


/** 
 * @brief Allows to translate a DNS message represented by an
 * extDnsMessage into its corresponding DNS message following the
 * protocol ready to be sent.
 *
 * @param ctx The context where the message to buffer will take place.
 *
 * @param buffer The buffer where the content will be placed.
 *
 * @param buffer_size The buffer size. It must be 512 bytes size long.
 *
 * @return The function returns the number of bytes written into the
 * buffer or -1 if it fails.
 */
int             ext_dns_message_to_buffer (extDnsCtx * ctx, extDnsMessage * message, char * buffer,  int buffer_size)
{
	int position;
	int count;

	/* check buffer size received */
	if (buffer_size < 512)
		return -1;

	/* check values received */
	if (message == NULL || buffer == NULL || ctx == NULL || message->header == NULL)
		return -1;

	/* clear buffer */
	memset (buffer, 0, 512);

	/* set ID */
	ext_dns_set_16bit (message->header->id, buffer);

	/* set QR */
	if (! message->header->is_query)
		ext_dns_set_bit (buffer + 2, 7);

	/* set opcode */
	if (message->header->opcode) {
		switch (message->header->opcode) {
		case 1:
			/* set inverse query received */
			ext_dns_set_bit (buffer + 2, 3);
			break;
		case 2:
			/* set server status request received */
			ext_dns_set_bit (buffer + 2, 4);
			break;
		default:
			/* reserved for future usage */
			break;
		} /* end if */
	} /* end if */

	/* set AA if defined */
	if (message->header->is_authorative_answer)
		ext_dns_set_bit (buffer + 2, 2);

	/* set TC if defined */
	/* STILL NOT SUPPORTED */

	/* set RD if defined */
	if (message->header->recursion_desired)
		ext_dns_set_bit (buffer + 2, 0);
	/* set RA if defined */
	if (message->header->recursion_available)
		ext_dns_set_bit (buffer + 3, 7);

	/* set RD if requested by the user */
	if (message->header->recursion_desired)
		ext_dns_set_bit (buffer + 2, 0);

	/* set RA if recursion is available */
	ext_dns_set_bit (buffer + 3, 7);

	/* set RCODE */
	if (message->header->rcode) {
		switch (message->header->rcode) {
		case extDnsResponseFormarError:
			/* Format error - the name server was unable to interpret the query */
			/* 01 */
			ext_dns_set_bit (buffer + 3, 0);
			break;
		case extDnsResponseServerFailure:
			/* Server failure - The name server was unable
			 * to process this query due to a problem with
			 * the name server. */
			/* 10 */
			ext_dns_set_bit (buffer + 3, 1);
			break;
		case extDnsResponseNameError:
			/* Name Error - Meaningful only for responses
			 * from an authoritative name server, this
			 * code signifies that the domain name
			 * erferenced in the query does not exist */
			/* 11 */
			ext_dns_set_bit (buffer + 3, 1);
			ext_dns_set_bit (buffer + 3, 0);
			break;
		case extDnsResponseNoImplementedError:
			/* Not implemented - the name server does not
			 * support the requested kind of query. */
			/* 100 */
			ext_dns_set_bit (buffer + 3, 2);
			break;
		case extDnsResponseRefused:
			/* Refused - The name server refuses to
			 * perform the specified operation for policy
			 * reasons. For example, a name server may not
			 * wish to provide the information to the
			 * particular requester, or a name server may
			 * not wish to perform a particular operation
			 * (e.g, zone transfer) for particular data. */
			/* 101 */
			ext_dns_set_bit (buffer + 3, 2);
			ext_dns_set_bit (buffer + 3, 0);
			break;
		default:
			break;
		}
	}

	/* set QDCOUNT count */
	ext_dns_set_16bit (message->header->query_count, buffer + 4);

	/* set ANCOUNT count */
	ext_dns_set_16bit (message->header->answer_count, buffer + 6);

	/* set NSCOUNT count */
	ext_dns_set_16bit (message->header->authority_count, buffer + 8);

	/* set ARCOUNT count */
	ext_dns_set_16bit (message->header->additional_count, buffer + 10);

	/* first position */
	position = 12;

	/*** PLACE QUESTIONS ***/
	count = 0;
	while (count < message->header->query_count) {
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "PLACING QUESTION:  Encoding resource name: %s", message->questions[count].qname);
		position += ext_dns_encode_domain_name (ctx, message->questions[count].qname, buffer + position);
		
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "   qname position after placing name: %d", position);
		
		/* set TYPE */
		ext_dns_set_16bit (message->questions[count].qtype, buffer + position);
		/* ext_dns_show_byte (ctx, buffer[position], "TYPE[0]");
		   ext_dns_show_byte (ctx, buffer[position + 1], "TYPE[1]"); */
		
		/* next two bytes */
		position += 2;

		/* set CLASS */
		ext_dns_set_16bit (message->questions[count].qclass, buffer + position);
		/* ext_dns_show_byte (ctx, buffer[position], "CLASS[0]");
		   ext_dns_show_byte (ctx, buffer[position + 1], "CLASS[1]"); */
		
		/* next two bytes */
		position += 2;

		/* next count */ 
		count++;
	}
	
	/*** PLACE ANSWER ****/
	count = 0;
	while (count < message->header->answer_count) {

		/* dump resource record */
		position = __ext_dns_message_write_resource_record (ctx, &message->answers[count], buffer, buffer_size, position);

		/* next count */ 
		count++;
	}

	/*** PLACE AUTHORITIES ****/
	count = 0;
	while (count < message->header->authority_count) {

		/* dump resource record */
		position = __ext_dns_message_write_resource_record (ctx, &message->authorities[count], buffer, buffer_size, position);

		/* next count */ 
		count++;
	}

	/*** PLACE ADDITIONALS ****/
	count = 0;
	while (count < message->header->additional_count) {

		/* dump resource record */
		position = __ext_dns_message_write_resource_record (ctx, &message->additionals[count], buffer, buffer_size, position);

		/* next count */ 
		count++;
	}

	/* return bytes written in the buffer */
	return position;
}

/** 
 * @brief Allows to run a query to the provided server, getting the
 * reply on the provided handler.
 *
 * @param ctx The context where the query will take place.
 *
 * @param type The type (A, a, MX, mx,...) that is being queried.
 *
 * @param class The class type to query (IN, in, ..).
 *
 * @param name The query name for which the value is requested.
 *
 * @param server The server address to send the query to.
 *
 * @param server_port The server port where to send the query to.
 *
 * @param on_message The handler that will be called with the reply
 * once received.
 *
 * @param data A user defined pointer that is passed to the on_message
 * handler when called.
 * 
 * @return axl_true in the case the query was issued, otherwise
 * axl_false in the case some parameter received is wrong or the
 * function wasn't able to send the query. NOTE you have to check this
 * return value because the on_message handler is only called when the
 * query was sent. In the case the function return axl_false, the
 * query won't be sent and your on_message handler won't be called.
 */
axl_bool            ext_dns_message_query_int (extDnsCtx * ctx, extDnsType _type, extDnsClass _class, const char * name, 
					       const char * server, int server_port,
					       extDnsOnMessageReceived on_message, axlPointer data)
{
	char                 buffer[512];
	extDnsSession      * listener;
	int                  bytes_written;
	extDnsHeader       * header;

	if (_type == -1) 
		return axl_false;
	if (_class == -1) 
		return axl_false;

	/* build the query */
	bytes_written = ext_dns_message_build_query (ctx, name, _type, _class, buffer, &header);
	if (bytes_written <= 0) {
		ext_dns_log (EXT_DNS_LEVEL_WARNING, "ERROR: failed to build query message, buffer reported was %d size\n", bytes_written);
		return axl_false;
	} /* end if */

	/* create listener */
	listener = ext_dns_listener_new2 (ctx, "0.0.0.0", 0, extDnsUdpSession, NULL, NULL);
	if (! ext_dns_session_is_ok (listener, axl_false)) {
		ext_dns_log (EXT_DNS_LEVEL_WARNING, "ERROR: failed to start listener to receive the reply");
		return axl_false; 
	}

	/* configure on received message */
	ext_dns_session_set_on_message (listener, on_message, data);

	/* configure close listener on reply */
	listener->close_on_message = axl_true;

	/* set header to be used to check reply received */
	listener->expected_header = header;

	/* send message */
	if (ext_dns_session_send_udp_s (ctx, listener, buffer, bytes_written, server, 53) != bytes_written) {
		ext_dns_log (EXT_DNS_LEVEL_WARNING, "ERROR: failed to message..");
		return axl_false;
	} /* end if */


	/* message sent */
	return axl_true;
}

/** 
 * @brief Allows to run a query to the provided server, getting the
 * reply on the provided handler.
 *
 * @param ctx The context where the query will take place.
 *
 * @param type The type (A, a, MX, mx,...) that is being queried.
 *
 * @param class The class type to query (IN, in, ..).
 *
 * @param name The query name for which the value is requested.
 *
 * @param server The server address to send the query to.
 *
 * @param server_port The server port where to send the query to.
 *
 * @param on_message The handler that will be called with the reply
 * once received.
 *
 * @param data A user defined pointer that is passed to the on_message
 * handler when called.
 * 
 * @return axl_true in the case the query was issued, otherwise
 * axl_false in the case some parameter received is wrong or the
 * function wasn't able to send the query. NOTE you have to check this
 * return value because the on_message handler is only called when the
 * query was sent. In the case the function return axl_false, the
 * query won't be sent and your on_message handler won't be called.
 */
axl_bool            ext_dns_message_query (extDnsCtx * ctx, const char * type, const char * class, const char * name, 
					   const char * server, int server_port,
					   extDnsOnMessageReceived on_message, axlPointer data)
{
	extDnsType           _type;
	extDnsClass          _class;

	/* check qtype and qclass received */
	_type  = ext_dns_message_get_qtype (ctx, type);
	_class = ext_dns_message_get_qclass (ctx, class);

	/* call query int */
	return ext_dns_message_query_int (ctx, _type, _class, name, server, server_port, on_message, data);
}

/** 
 * @brief Allows to run a query to the provided server, using the
 * provided message as the query to be done, getting the reply on the
 * provided handler.
 *
 * The function works as \ref ext_dns_message_query, but getting the
 * query values from the \ref extDnsMessage object. That message
 * doesn't have to be a query, but it has to have the query section
 * defined so the function call look into type, name and class values.
 *
 * @param ctx The context where the query will take place.
 *
 * @param message The message where the values for type, name and
 * class will be taken from the query section.
 *
 * @param server The server address to send the query to.
 *
 * @param server_port The server port where to send the query to.
 *
 * @param on_message The handler that will be called with the reply
 * once received.
 *
 * @param data A user defined pointer that is passed to the on_message
 * handler when called.
 * 
 * @return axl_true in the case the query was issued, otherwise
 * axl_false in the case some parameter received is wrong or the
 * function wasn't able to send the query. NOTE you have to check this
 * return value because the on_message handler is only called when the
 * query was sent. In the case the function return axl_false, the
 * query won't be sent and your on_message handler won't be called.
 */
axl_bool        ext_dns_message_query_from_msg (extDnsCtx * ctx, extDnsMessage * message,
						const char * server, int server_port,
						extDnsOnMessageReceived on_message, axlPointer data)
{
	/* check message reference */
	if (message == NULL || message->header == NULL)  {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Received null message or a message without header, failed to send from message");
		return axl_false;
	}

	/* no query question found */
	if (message->header->query_count <= 0) {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Found query count %d <= 0, failed to send from message", message->header->query_count);
		return axl_false;
	}

	/* call base common function */
	return ext_dns_message_query_int (ctx, 
					  /* send query values */
					  message->questions[0].qtype, 
					  message->questions[0].qclass,
					  message->questions[0].qname,
					  /* server and port to query */
					  server, server_port,
					  /* reply handlers */
					  on_message, data);
}

/** 
 * @brief Increases the reference to the provided message.
 *
 * @param message The DNS message to release
 *
 * @return axl_true if a reference was acquired to the message object,
 * otherwise axl_false is returned.
 */
axl_bool            ext_dns_message_ref (extDnsMessage * message)
{
	axl_bool result;

	/* check income result */
	if (message == NULL)
		return axl_false;

	/* acquire mutex */
	ext_dns_mutex_lock (&message->mutex);

	message->ref_count++;
	result = (message->ref_count > 1);

	/* release mutex */
	ext_dns_mutex_unlock (&message->mutex);

	return result;
}


/** 
 * @brief Releases a reference to the provided DNS message.
 *
 * @param message The DNS message to release
 */
void ext_dns_message_unref (extDnsMessage * message)
{
	int count;

	if (message == NULL)
		return;

	/* acquire mutex */
	ext_dns_mutex_lock (&message->mutex);

	/* reduce reference */
	message->ref_count--;

	if (message->ref_count != 0) {
		/* release mutex */
		ext_dns_mutex_unlock (&message->mutex);
		return;
	} /* end if */

	/* release mutex */
	ext_dns_mutex_unlock (&message->mutex);
	
	/*** QUESTIONS ***/
	count = 0;
	while (count < message->header->query_count) {
		/* release name */
		axl_free (message->questions[count].qname);
		
		count++;
	}
	if (message->header->query_count > 0)
		axl_free (message->questions);

	/*** ANSWERS ***/
	count = 0;
	if (message->answers) {
		while (count < message->header->answer_count) {
			/* release name */
			axl_free (message->answers[count].name);
			axl_free (message->answers[count].rdata);
			axl_free (message->answers[count].name_content);
			axl_free (message->answers[count].mname);
			axl_free (message->answers[count].contact_address);
			
			count++;
		}
	}
	if (message->header->query_count > 0)
		axl_free (message->answers);

	/*** AUTHORITY ***/
	count = 0;
	if (message->authorities) {
		while (count < message->header->authority_count) {
			/* release name */
			axl_free (message->authorities[count].name);
			axl_free (message->authorities[count].rdata);
			axl_free (message->authorities[count].name_content);
			axl_free (message->authorities[count].mname);
			axl_free (message->authorities[count].contact_address);
			
			count++;
		}
	} /* end if */
	if (message->header->authority_count > 0)
		axl_free (message->authorities);

	/*** ADDITIONAL ***/
	count = 0;
	if (message->additionals) {
		while (count < message->header->additional_count) {
			/* release name */
			axl_free (message->additionals[count].name);
			axl_free (message->additionals[count].rdata);
			axl_free (message->additionals[count].name_content);
			axl_free (message->additionals[count].mname);
			axl_free (message->additionals[count].contact_address);
		
			count++;
		}
	} /* end if */
	if (message->header->additional_count > 0)
		axl_free (message->additionals);

	/* release mutex */
	ext_dns_mutex_destroy (&message->mutex);

	/* release header */
	axl_free (message->header);

	/* release the message holder itself */
	axl_free (message);

	return;
}


/** 
 * @brief Allows to build the provided query on the buffer reference.
 *
 * @param ctx The context where the query is happening
 *
 * @param qname The query owner name being asked
 *
 * @param qtype The query type 
 *
 * @param qclass The query class
 *
 * @param buffer A pointer to an already allocated buffer with at
 * least 512 bytes.
 *
 * @param header A reference to the extDnsHeader that represents the
 * query sent.
 *
 * @return The function returns the number of bytes written into the
 * buffer
 */
int             ext_dns_message_build_query (extDnsCtx * ctx, const char * qname, extDnsType qtype, extDnsClass qclass, char * buffer, extDnsHeader ** header)
{
	int            position;
	extDnsHeader * _header;

	/* Simple "srand()" seed: just use "time()" */
	unsigned int iseed = (unsigned int) time(NULL);
	srand (iseed);

	/* build header */
	_header = axl_new (extDnsHeader, 1);
	if (header == NULL)
		return -1;

	/* clear buffer received */
	memset (buffer, 0, 512);

	/* get id */
	_header->id = rand () % 65536;

	/* set id */
	ext_dns_set_16bit (_header->id, buffer);

	/* set RD */
	ext_dns_set_bit (buffer + 2, 0);

	/* set question count */
	ext_dns_set_16bit (1, buffer + 4);

	/* set initial position */
	position = 12;

	/* now write question */
	position += ext_dns_encode_domain_name (ctx, qname, buffer + position);

	/* place qtype */
	ext_dns_set_16bit (qtype, buffer + position);
	position += 2;

	/* place qclass */
	ext_dns_set_16bit (qclass, buffer + position);
	position += 2;

	/* set header to the caller if defined */
	if (header)
		*header = _header;

	return position;
}


/** 
 * @brief Allows to get the extDnsType code from the qtype string.
 *
 * @param qtype The question type that is being asked to be translated
 *
 * @return extDnsType or -1 if it fails.
 */
extDnsType      ext_dns_message_get_qtype (extDnsCtx * ctx, const char * qtype)
{
	/* get input value */
	if (qtype == NULL || strlen (qtype) == 0)
		return -1;

	if (axl_cmp (qtype, "A") || axl_cmp (qtype, "a"))
		return extDnsTypeA;
	if (axl_cmp (qtype, "NS") || axl_cmp (qtype, "ns"))
		return extDnsTypeNS;
	if (axl_cmp (qtype, "MD") || axl_cmp (qtype, "md"))
		return extDnsTypeMD;
	if (axl_cmp (qtype, "MF") || axl_cmp (qtype, "mf"))
		return extDnsTypeMF;
	if (axl_cmp (qtype, "CNAME") || axl_cmp (qtype, "cname"))
		return extDnsTypeCNAME;
	if (axl_cmp (qtype, "SOA") || axl_cmp (qtype, "soa"))
		return extDnsTypeSOA;
	if (axl_cmp (qtype, "MB") || axl_cmp (qtype, "mb"))
		return extDnsTypeMB;
	if (axl_cmp (qtype, "MG") || axl_cmp (qtype, "mg"))
		return extDnsTypeMG;
	if (axl_cmp (qtype, "MR") || axl_cmp (qtype, "mr"))
		return extDnsTypeMR;
	if (axl_cmp (qtype, "NULL") || axl_cmp (qtype, "null"))
		return extDnsTypeNULL;
	if (axl_cmp (qtype, "WKS") || axl_cmp (qtype, "wks"))
		return extDnsTypeWKS;
	if (axl_cmp (qtype, "PTR") || axl_cmp (qtype, "ptr"))
		return extDnsTypePTR;
	if (axl_cmp (qtype, "HINFO") || axl_cmp (qtype, "hinfo"))
		return extDnsTypeHINFO;
	if (axl_cmp (qtype, "MINFO") || axl_cmp (qtype, "minfo"))
		return extDnsTypeMINFO;
	if (axl_cmp (qtype, "MX") || axl_cmp (qtype, "mx"))
		return extDnsTypeMX;
	if (axl_cmp (qtype, "TXT") || axl_cmp (qtype, "txt"))
		return extDnsTypeTXT;
	if (axl_cmp (qtype, "AAAA") || axl_cmp (qtype, "aaaa"))
		return extDnsTypeAAAA;
	if (axl_cmp (qtype, "AXFR") || axl_cmp (qtype, "axfr"))
		return extDnsTypeAXFR;
	if (axl_cmp (qtype, "MAILB") || axl_cmp (qtype, "mailb"))
		return extDnsTypeMAILB;
	if (axl_cmp (qtype, "MAILA") || axl_cmp (qtype, "maila"))
		return extDnsTypeMAILA;
	if (axl_cmp (qtype, "*"))
		return extDnsTypeANY;

	/* unrecognized character */
	ext_dns_log (EXT_DNS_LEVEL_WARNING, "Unsupported qtype received: %s", qtype ? qtype : "");
	return -1;
}

/** 
 * @brief Allows to get a printable type representation from extDnsType code.
 *
 * @param qtype The question type that is being asked to be translated
 *
 * @return A string representing the type or NULL if it fails.
 */
const char *      ext_dns_message_get_qtype_to_str (extDnsCtx * ctx, extDnsType type)
{
	if (type == extDnsTypeA)
		return "A";
	if (type == extDnsTypeNS)
		return "NS";
	if (type == extDnsTypeMD)
		return "MD";
	if (type == extDnsTypeMF)
		return "MF";
	if (type == extDnsTypeCNAME)
		return "CNAME";
	if (type == extDnsTypeSOA)
		return "SOA";
	if (type == extDnsTypeMB)
		return "MB";
	if (type == extDnsTypeMG)
		return "MG";
	if (type == extDnsTypeMR)
		return "MR";
	if (type == extDnsTypeNULL)
		return "NULL";
	if (type == extDnsTypeWKS)
		return "WKS";
	if (type == extDnsTypePTR)
		return "PTR";
	if (type == extDnsTypeHINFO)
		return "HINFO";
	if (type == extDnsTypeMX)
		return "MX";
	if (type == extDnsTypeTXT)
		return "TXT";
	if (type == extDnsTypeAAAA)
		return "AAAA";
	if (type == extDnsTypeAXFR)
		return "AXFR";
	if (type == extDnsTypeMAILB)
		return "MAILB";
	if (type == extDnsTypeMAILA)
		return "MAILA";
	if (type == extDnsTypeANY)
		return "ANY";

	/* unrecognized type */
	ext_dns_log (EXT_DNS_LEVEL_WARNING, "Unsupported qtype received: %d", type);
	return NULL;
}

/** 
 * @brief Allows to get the extDnsClass code from the qclass string.
 *
 * @param qclass The question class that is being asked to be translated
 *
 * @return extDnsClass or -1 if it fails.
 */
extDnsClass     ext_dns_message_get_qclass (extDnsCtx * ctx, const char * qclass)
{
	/* get input value */
	if (qclass == NULL || strlen (qclass) == 0)
		return -1;

	if (axl_cmp (qclass, "IN") || axl_cmp (qclass, "in"))
		return extDnsClassIN;
	if (axl_cmp (qclass, "CS") || axl_cmp (qclass, "cs"))
		return extDnsClassCS;
	if (axl_cmp (qclass, "CH") || axl_cmp (qclass, "ch"))
		return extDnsClassCH;
	if (axl_cmp (qclass, "HS") || axl_cmp (qclass, "hs"))
		return extDnsClassHS;
	if (axl_cmp (qclass, "*"))
		return extDnsClassANY;

	/* unrecognized class */
	ext_dns_log (EXT_DNS_LEVEL_WARNING, "Unsupported qclass received: %s", qclass ? qclass : "");
	return -1;
}

/** 
 * @brief Allows to get the a user printable string from extDnsClass code.
 *
 * @param class The question class that is being asked to be translated
 *
 * @return The string representing the class or NULL if it fails (unrecognized code)
 */
const char *     ext_dns_message_get_qclass_to_str (extDnsCtx * ctx, extDnsClass class)
{
	if (class == extDnsClassIN)
		return "IN";
	if (class == extDnsClassCS)
		return "CS";
	if (class == extDnsClassCH)
		return "CH";
	if (class == extDnsClassHS)
		return "HS";
	if (class == extDnsClassANY)
		return "*";

	/* unrecognized class */
	ext_dns_log (EXT_DNS_LEVEL_WARNING, "Unsupported class received: %d", class);
	return NULL;
}

