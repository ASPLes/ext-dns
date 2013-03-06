/* 
 *  ext-dns: a framework to build DNS solutions
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

/**
 * \defgroup ext_dns_message extDns Message: API functions to handle and produce DNS requsts and replies
 */

/** 
 * \addtogroup ext_dns_message
 * @{
 */


/* call notify on the on received handler that a
   failure was found */
void _ext_dns_message_notify_failure (extDnsCtx * ctx, extDnsSession * listener, const char * source_address, int source_port)
{
        extDnsOnMessageReceived handler;

	/* unable to notify nothing, without session, no handler to call to */
	if (listener == NULL)
		return;

	if (! listener->on_message)
		return;

	if (! listener->notify_failure)
	        return;
	listener->notify_failure = axl_true;

	/* get handler */
	handler = _ext_dns_message_get_on_received (ctx, listener);
	if (handler == NULL)
	        return;

	/* call to notify on message */
	handler (ctx, listener, source_address, source_port, NULL, listener->on_message_data);
	return;
}

/** 
 * @internal Nice random generation code taken from:
 * http://stackoverflow.com/questions/1640258/need-a-fast-random-generator-for-c
 */
static unsigned long __ext_dns_message_x = 123456789, __ext_dns_message_y = 362436069, __ext_dns_message_z = 521288629;

unsigned long ext_dns_message_rand (void) {

	unsigned long t;
	__ext_dns_message_x ^= __ext_dns_message_x << 16;
	__ext_dns_message_x ^= __ext_dns_message_x >> 5;
	__ext_dns_message_x ^= __ext_dns_message_x << 1;
	
	t = __ext_dns_message_x;
	__ext_dns_message_x = __ext_dns_message_y;
	__ext_dns_message_y = __ext_dns_message_z;
	__ext_dns_message_z = t ^ __ext_dns_message_x ^ __ext_dns_message_y;
	
	return __ext_dns_message_z;
}

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
	header->opcode                = ((int)(buf[2]) & 0x078) >> 3 ;
	/* ext_dns_log (EXT_DNS_LEVEL_DEBUG, "####  OPCODE FOUND: %d", header->opcode); */
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

char * ext_dns_message_get_label (extDnsCtx * ctx, const char * buffer, int buffer_size)
{
	char * label;
	int    bytes_to_read = (char)(buffer[0]) & 0x3f;
	int    iterator;

	if (bytes_to_read == 0 || bytes_to_read > 63)
		return NULL;

	if (bytes_to_read > buffer_size) {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Requested to remove %d bytes to get the label from a smaller buffer %d",
			     bytes_to_read, buffer_size);
		return NULL;
	}

	/* check values from the buffer */
	iterator = 1;
	while (iterator < bytes_to_read) {
		if (! isalnum (buffer[iterator]) && buffer[iterator] != '-' && buffer[iterator] != '_') {
			ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Found non ascii value in label (%d, '%c')", (int)buffer[iterator], (char)buffer[iterator]);
			return NULL;
		}
		iterator++;
	}
	
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
	
	if (iterator >= buf_size) {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Starting to read a resource name on an exhausted buffer (buf_size=%d, iteartor=%d)..",
			     buf_size, iterator);
		return NULL;
	}

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Starting to get resource name at iterator=%d, buf_size=%d, buffer[iterator]='%d'",
		     iterator, buf_size, buffer[iterator]);
		

	/* get basic base where root "." is found */
	if (buffer[iterator] == 0) 
		resource_name = axl_strdup (".");

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
			offset = ((int)(buffer[iterator] & 0x003f) << 8) | ((int)buffer[iterator + 1] & 0x00ff);
			ext_dns_log (EXT_DNS_LEVEL_DEBUG, "  Found label compression offset=%d, iterator=%d (until now, name is: %s)", offset, iterator, resource_name ? resource_name : "");
			
			if (offset < 12 || offset > buf_size) {
				ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Received a request to process a label compression that is outside the message");
				axl_free (resource_name);
				return NULL;
			}
			
			/* notify label found */
			is_label = axl_true;
			
			/* ok, now call the function again to process the label at the position pointed */
			label = ext_dns_message_get_resource_name (ctx, buffer, buf_size, &offset, NULL);
			if (! label) {
				axl_free (resource_name);
				return NULL;
			}

			ext_dns_log (EXT_DNS_LEVEL_DEBUG, "  Label found at the label compression call: %s", label ? label : "");

			iterator ++;

		} else {
			/* get label */
			label = ext_dns_message_get_label (ctx, buffer + iterator, buf_size - iterator);
			if (! label) {
				axl_free (resource_name);
				return NULL;
			}

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

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Found resource name=%s next iterator=%d",
		     resource_name, iterator+1);

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
	} else if (rr->type == extDnsTypeTXT || rr->type == extDnsTypeSPF) {
		/* get TXT, SPF content */
		rr->name_content = axl_new (char, rr->rdlength + 1);
		memcpy (rr->name_content, rr->rdata + 1, rr->rdlength -1);
	} else if (rr->type == extDnsTypeSRV) {

		/* get SRV content */
		/* get SRV prio */
		rr->preference   = ext_dns_get_16bit (buf + value);
		value += 2;
		/* get weight */
		rr->weight       = ext_dns_get_16bit (buf + value);
		value += 2;
		/* get port */
		rr->port         = ext_dns_get_16bit (buf + value);
		value += 2;

		/* get target */
		rr->target = ext_dns_message_get_resource_name (ctx, buf, buf_size, &value, &is_label);

		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "### SRV: Port: %d, Priority: %d, Weight: %d, Target: %s", rr->port, rr->preference, rr->weight, rr->target); 

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
 *
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

/** 
 * @brief Allows to check if the provided message represents a reject
 * reply.
 *
 * @param message The message message to be checked to be a rejection
 * message.
 *
 * @return axl_true if it is a reject message or axl_false if not. The
 * function axl returns axl_false when the reference received is NULL.
 */
axl_bool        ext_dns_message_is_reject (extDnsMessage * message)
{
	if (message == NULL || message->header == NULL)
		return axl_false;

	/* check error code */
	return message->header->rcode == extDnsResponseRefused;
}

/** 
 * @brief Allows to check if the provided message represents a name
 * resolution error.
 *
 * @param message The message message to be checked to be a resolution
 * error message.
 *
 * @return axl_true if it is a resolution error message or axl_false
 * if not. The function axl returns axl_false when the reference
 * received is NULL.
 */
axl_bool        ext_dns_message_is_name_error (extDnsMessage * message)
{
	if (message == NULL || message->header == NULL)
		return axl_false;

	/* check error code */
	return message->header->rcode == extDnsResponseNameError;
}

/** 
 * @brief Allows to check if the message is valid, that is, it represents a reply and has a valid response with a current ttl.
 *
 * @param ctx The context where the operation will take place.
 *
 * @param message The message to be checked.
 *
 * @return axl_true if the message is valid, otherwise axl_false is
 * returned.
 */       
axl_bool        ext_dns_message_is_answer_valid (extDnsCtx * ctx, extDnsMessage * message)
{
	int iterator;

	if (message == NULL || message->header == NULL) {
		return axl_false;
	}

	/* check it is not a query */
	if (message->header->is_query) {
		return axl_false;
	}

	if (message->answers == NULL) {
		return axl_false;
	}

	iterator = 0;
	while (iterator < message->header->answer_count) {
		/* check that the message stamp plus its ttl is still valid */
		if ((message->answers[iterator].ttl + message->stamp) < time (NULL))
			return axl_false;

		iterator++;
	}

	/* valid message */
	return axl_true;
}


axlPointer ext_dns_message_release_and_return (extDnsMessage * message)
{
	ext_dns_message_unref (message);
	return NULL;
}

extDnsMessage * ext_dns_message_create (extDnsHeader * header, int buf_size)
{
	/* create empty message */
	extDnsMessage * message = axl_new (extDnsMessage, 1);
	if (message == NULL)
		return NULL;

	/* buffer size */
	message->message_size = buf_size;

	/* initialize mutex */
	ext_dns_mutex_create (&message->mutex);
	message->ref_count = 1;

	/* set its stamp */
	message->stamp = (int) time (NULL);

	/* set header */
	if (header)
		message->header = header;
	else
		message->header = axl_new (extDnsHeader, 1);

	return message;
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
	message = ext_dns_message_create (header, buf_size);
	if (message == NULL)
		return NULL;

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
			return ext_dns_message_release_and_return (message);

		/* if (! is_label)
			iterator += strlen (message->questions[count].qname) + 2;
		else
		iterator += 2;*/
		if ((iterator + 4) > buf_size || (strlen (message->questions[count].qname) == 0)) {
			ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Found incomplete message in buffer (%d >= %d) or qname is is empty (%d)", 
				     iterator + 4, buf_size,
				     strlen (message->questions[count].qname));
			return ext_dns_message_release_and_return (message);
		}
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Resource name: '%s' (iterator=%d, buffer size=%d)", message->questions[count].qname, iterator, buf_size); 

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
 * @internal Common implementation to build error replies
 */
extDnsMessage * __ext_dns_message_build_reply_common (extDnsCtx * ctx, extDnsMessage * message, extDnsResponseType response)
{
	extDnsMessage * reply;
	int             iterator;

	if (ctx == NULL || message == NULL)
		return NULL;

	/* build the message */
	reply = ext_dns_message_create (NULL, 0);
	if (reply == NULL)
		return NULL;

	/* set and id we are replying to */
	reply->header->id = message->header->id;
	
	/* set authoritative */
	reply->header->is_authorative_answer = axl_true;

	/* copy question section */
	if (message->header->query_count > 0) {
		/* copy the entire reply */
		reply->header->query_count = message->header->query_count; 

		/* reply memory */
		reply->questions = axl_new (extDnsQuestion, reply->header->query_count);
		memcpy (reply->questions, message->questions, sizeof (extDnsQuestion) * reply->header->query_count); 

		/* copy names */
		iterator = 0;
		while (iterator < reply->header->query_count) {
			reply->questions[iterator].qname = axl_strdup (message->questions[iterator].qname);
			iterator++;
		}
	} /* end if */

	/* set op codes */
	reply->header->rcode = response;

	/* copy headers */
	reply->header->recursion_desired = message->header->recursion_desired;
	
	/* return message built */
	return reply;
}


/** 
 * @brief Allows to build a DNS refuse (policy refuse) reply message,
 * taking the id to reply to from the provided message.
 *
 * @param ctx The context where the operation will take place.
 *
 * @param message The message we are going to build a refuse reply to.
 *
 * @return A reference to the message or NULL if it fails.
 */
extDnsMessage * ext_dns_message_build_reject_reply (extDnsCtx * ctx, extDnsMessage * message)
{
	return __ext_dns_message_build_reply_common (ctx, message, extDnsResponseRefused);
}

/** 
 * @brief Allows to build a DNS unknown reply message, taking the id
 * to reply to from the provided message.
 *
 * @param ctx The context where the operation will take place.
 *
 * @param message The message we are going to build a refuse reply to.
 *
 * @return A reference to the message or NULL if it fails.
 */
extDnsMessage * ext_dns_message_build_unknown_reply (extDnsCtx * ctx, extDnsMessage * message)
{
	/* use common function */
	return __ext_dns_message_build_reply_common (ctx, message, extDnsResponseNameError);
}

/** 
 * @brief Allows to build a message reply to the provided message,
 * using as reply to the question the IP provided.
 *
 * @param ctx The context where the operation will take place.
 *
 * @param message A DNS message question that will be used to build a reply.
 *
 * @param ip An IPv4 string value what will be used to complete the
 * ANSWER section of the message. Note the reply created will have IN
 * for the DNS class, and A for the dns type record.
 *
 * @param ttl The ttl to be reported in the reply.
 *
 * @return A reference to a newly created message that represents the
 * reply or NULL if the function fails. 
 */
extDnsMessage * ext_dns_message_build_ipv4_reply (extDnsCtx * ctx, extDnsMessage * message, const char * ip, int ttl)
{
	extDnsMessage   * reply;
	char           ** ip_items;

	if (ctx == NULL || message == NULL || ip == NULL)
		return NULL;

	/* check the ip received is indeed an ip */
	if (! ext_dns_support_is_ipv4 (ip))
		return NULL;

	/* build reply without error */
	reply = __ext_dns_message_build_reply_common (ctx, message, extDnsResponseNoError);

	/* copy questions */
	reply->header->answer_count = 1;
	reply->answers = axl_new (extDnsResourceRecord, 1);

	/* configure answer record type */
	reply->answers[0].name  = axl_strdup (reply->questions[0].qname);
	reply->answers[0].class = extDnsClassIN;
	reply->answers[0].type  = extDnsTypeA;
	reply->answers[0].rdlength = 4;
	reply->answers[0].rdata = axl_new (char, 4);

	/* copy pretty value */
	reply->answers[0].name_content = axl_strdup (ip);

	/* set ttl */
	reply->answers[0].ttl = ttl;

	/* place ip values */
	ip_items = axl_split (ip, 1, ".");
	reply->answers[0].rdata[0] = ext_dns_atoi(ip_items[0]);
	reply->answers[0].rdata[1] = ext_dns_atoi(ip_items[1]);
	reply->answers[0].rdata[2] = ext_dns_atoi(ip_items[2]);
	reply->answers[0].rdata[3] = ext_dns_atoi(ip_items[3]);
	axl_freev (ip_items);

	/* return reply */
	return reply;
}

/** 
 * @brief Given a created reply, this function allows to add an
 * additional A reply to the query replied.
 *
 * @param ctx The context where the operation will take place.
 *
 * @param reply A DNS reply message already created by other functions
 * (like \ref ext_dns_message_build_ipv4_reply).
 *
 * @param ip An IPv4 string value what will be used to complete the
 * ANSWER section of the message. Note the reply created will have IN
 * for the DNS class, and A for the dns type record.
 *
 * @param ttl The ttl to be reported in the reply.
 *
 * @return axl_true in the case of proper operation, otherwise
 * axl_false is returned.
 */
axl_bool        ext_dns_message_add_ipv4_reply (extDnsCtx * ctx, extDnsMessage * reply, const char * ip, int ttl)
{
	/* query if the question section is ok */
	if (reply == NULL || reply->questions == NULL || reply->questions[0].qname == NULL)
		return axl_false;

	/* ok, now query if the IP provided is ok */
	if (! ext_dns_support_is_ipv4 (ip))
		return axl_false;

	/* report result */
	return ext_dns_message_add_answer (ctx, reply, extDnsTypeA, extDnsClassIN, reply->questions[0].qname, ttl, ip);
}

/** 
 * @brief Allows to build a message reply to the provided message,
 * using as reply to the question the name provided.
 *
 * @param ctx The context where the operation will take place.
 *
 * @param message A DNS message question that will be used to build a reply.
 *
 * @param name A name string value what will be used to complete the
 * ANSWER section of the message. Note the reply created will have IN
 * for the DNS class, and CNAME for the dns type record.
 *
 * @param ttl The ttl to be reported in the reply.
 *
 * @return A reference to a newly created message that represents the
 * reply or NULL if the function fails. 
 */
extDnsMessage * ext_dns_message_build_cname_reply (extDnsCtx * ctx, extDnsMessage * message, const char * name, int ttl)
{
	extDnsMessage   * reply;

	if (ctx == NULL || message == NULL || name == NULL)
		return NULL;

	/* build reply without error */
	reply = __ext_dns_message_build_reply_common (ctx, message, extDnsResponseNoError);

	/* copy questions */
	reply->header->answer_count = 1;
	reply->answers = axl_new (extDnsResourceRecord, 1);

	/* configure answer record type */
	reply->answers[0].name  = axl_strdup (reply->questions[0].qname);
	reply->answers[0].class = extDnsClassIN;
	reply->answers[0].type  = extDnsTypeCNAME;

	/* copy pretty value */
	reply->answers[0].name_content = axl_strdup (name);

	/* set ttl */
	reply->answers[0].ttl = ttl;

	/* return reply */
	return reply;	
}

/** 
 * @brief Allows to build a message reply to the provided message,
 * using as reply to the question the name provided.
 *
 * @param ctx The context where the operation will take place.
 *
 * @param message A DNS message question that will be used to build a reply.
 *
 * @param mailer The mailer that will appear in the MX record.
 *
 * @param preference The MX preference.
 *
 * @param ttl The ttl to be reported in the reply.
 *
 * @return A reference to a newly created message that represents the
 * reply or NULL if the function fails. 
 */
extDnsMessage * ext_dns_message_build_mx_reply (extDnsCtx * ctx, extDnsMessage * message, const char * mailer, int preference, int ttl)
{
	extDnsMessage   * reply;

	if (ctx == NULL || message == NULL || mailer == NULL || preference < 0)
		return NULL;

	/* build reply without error */
	reply = __ext_dns_message_build_reply_common (ctx, message, extDnsResponseNoError);

	/* copy questions */
	reply->header->answer_count = 1;
	reply->answers = axl_new (extDnsResourceRecord, 1);

	/* configure answer record type */
	reply->answers[0].name  = axl_strdup (reply->questions[0].qname);
	reply->answers[0].class = extDnsClassIN;
	reply->answers[0].type  = extDnsTypeMX;

	/* MX content */
	reply->answers[0].name_content  = axl_strdup (mailer);
	reply->answers[0].preference    = preference;

	/* set ttl */
	reply->answers[0].ttl = ttl;

	/* return reply */
	return reply;	
}

/** 
 * @brief Allows to build a message reply to the provided message,
 * using as reply to the question the name provided.
 *
 * @param ctx The context where the operation will take place.
 *
 * @param message A DNS message question that will be used to build a reply.
 *
 * @param dns_server The DNS server that will appear in the NS record.
 *
 * @param ttl The ttl to be reported in the reply.
 *
 * @return A reference to a newly created message that represents the
 * reply or NULL if the function fails. 
 */
extDnsMessage * ext_dns_message_build_ns_reply (extDnsCtx * ctx, extDnsMessage * message, const char * dns_server, int ttl)
{
	extDnsMessage   * reply;

	if (ctx == NULL || message == NULL || dns_server == NULL)
		return NULL;

	/* build reply without error */
	reply = __ext_dns_message_build_reply_common (ctx, message, extDnsResponseNoError);

	/* copy questions */
	reply->header->answer_count = 1;
	reply->answers = axl_new (extDnsResourceRecord, 1);

	/* configure answer record type */
	reply->answers[0].name  = axl_strdup (reply->questions[0].qname);
	reply->answers[0].class = extDnsClassIN;
	reply->answers[0].type  = extDnsTypeNS;

	/* NS content */
	reply->answers[0].name_content  = axl_strdup (dns_server);

	/* set ttl */
	reply->answers[0].ttl = ttl;

	/* return reply */
	return reply;	
}

/** 
 * @brief Allows to build a message reply to the provided message,
 * using as reply to the question the name provided.
 *
 * @param ctx The context where the operation will take place.
 *
 * @param message A DNS message question that will be used to build a reply.
 *
 * @param primary_server The primary DNS server name for the SOA record.
 *
 * @param mail_contact The mail contact for this domain.
 *
 * @param serial The serial value for SOA record.
 *
 * @param refresh The refresh value for SOA record.
 *
 * @param retry The retry value for SOA record.
 *
 * @param expire The expire value for SOA record.
 *
 * @param minimum The minimum value for SOA record.
 *
 * @param ttl The ttl to be reported in the reply.
 *
 * @return A reference to a newly created message that represents the
 * reply or NULL if the function fails. 
 */
extDnsMessage * ext_dns_message_build_soa_reply (extDnsCtx * ctx, extDnsMessage * message, 
						 const char * primary_server, const char * mail_contact, 
						 int serial, int refresh, int retry, int expire, int minimum,
						 int ttl)
{
	extDnsMessage   * reply;

	if (ctx == NULL || message == NULL || primary_server == NULL || mail_contact == NULL)
		return NULL;

	/* build reply without error */
	reply = __ext_dns_message_build_reply_common (ctx, message, extDnsResponseNoError);

	/* copy questions */
	reply->header->answer_count = 1;
	reply->answers = axl_new (extDnsResourceRecord, 1);

	/* configure answer record type */
	reply->answers[0].name  = axl_strdup (reply->questions[0].qname);
	reply->answers[0].class = extDnsClassIN;
	reply->answers[0].type  = extDnsTypeSOA;

	/* SOA content */
	reply->answers[0].mname           = axl_strdup (primary_server);
	reply->answers[0].contact_address = axl_strdup (mail_contact);
	axl_replace (reply->answers[0].contact_address, "@", ".");

	/* numeric values */
	reply->answers[0].serial  = serial;
	reply->answers[0].refresh = refresh;
	reply->answers[0].retry   = retry;
	reply->answers[0].expire  = expire;
	reply->answers[0].minimum = minimum;

	/* set ttl */
	reply->answers[0].ttl = ttl;

	/* return reply */
	return reply;		
}

/** 
 * @brief Allows to add a cname reply on the provided reply already
 * created.
 *
 * @param ctx The context where the operation will take place.
 *
 * @param reply The DNS reply where the MX reply will be added.
 *
 * @param name A name string value what will be used to complete the
 * ANSWER section of the message. Note the reply created will have IN
 * for the DNS class, and CNAME for the dns type record.
 *
 * @param ttl The ttl to be reported in the reply.
 *
 * @return axl_true in the case the reply was added, otherwise
 * axl_false is returned.
 */
axl_bool        ext_dns_message_add_cname_reply (extDnsCtx * ctx, extDnsMessage * reply, const char * name, int ttl)
{
	/* query if the question section is ok */
	if (reply == NULL || reply->questions == NULL || reply->questions[0].qname == NULL) {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Failed to add cname value %s, ttl %d to the reply %p, NULL reply, NULL questions section or NULL qname", 
			     name, ttl, reply);
		return axl_false;
	}

	/* report result */
	return ext_dns_message_add_answer (ctx, reply, extDnsTypeCNAME, extDnsClassIN, reply->questions[0].qname, ttl, name);
}

/** 
 * @brief Allows to add a MX reply on the provided reply already
 * created.
 *
 * @param ctx The context where the operation will take place.
 *
 * @param reply The DNS reply where the cname reply will be added.
 *
 * @param mailer The hostname that is going to appear as the mailer host.
 *
 * @param preference The MX preference.
 *
 * @param ttl The ttl to be reported in the reply.
 *
 * @return axl_true in the case the reply was added, otherwise
 * axl_false is returned.
 */
axl_bool        ext_dns_message_add_mx_reply (extDnsCtx * ctx, extDnsMessage * reply, const char * mailer, int preference, int ttl)
{
	axl_bool   result;
	char     * temp;

	/* query if the question section is ok */
	if (reply == NULL || reply->questions == NULL || reply->questions[0].qname == NULL || mailer == NULL || preference < 0) {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, 
			     "Failed to add MX value, received invalid content (null context %p), (null reply %p), (null mailer %p) (wrong preference %d)",
			     ctx, reply, mailer, preference);
		return axl_false;
	} /* end if */

	/* report result */
	temp = axl_strdup_printf ("%d %s", preference, mailer);
	result = ext_dns_message_add_answer (ctx, reply, extDnsTypeMX, extDnsClassIN, reply->questions[0].qname, ttl, temp);
	axl_free (temp);
	return result;
}

/** 
 * @brief Allows to add a cname reply on the provided reply already
 * created.
 *
 * @param ctx The context where the operation will take place.
 *
 * @param reply The DNS reply where the NS reply will be added.
 *
 * @param dns_server DNS servername added to the reply.
 *
 * @param ttl The ttl to be reported in the reply.
 *
 * @return axl_true in the case the reply was added, otherwise
 * axl_false is returned.
 */
axl_bool        ext_dns_message_add_ns_reply (extDnsCtx * ctx, extDnsMessage * reply, const char * dns_server, int ttl)
{
	/* query if the question section is ok */
	if (reply == NULL || reply->questions == NULL || reply->questions[0].qname == NULL) {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Failed to add cname value %s, ttl %d to the reply %p, NULL reply, NULL questions section or NULL qname", 
			     dns_server, ttl, reply);
		return axl_false;
	}

	/* report result */
	return ext_dns_message_add_answer (ctx, reply, extDnsTypeCNAME, extDnsClassIN, reply->questions[0].qname, ttl, dns_server);
}

/** 
 * @brief Allows to add a NS reply on the provided reply already
 * created.
 *
 * @param ctx The context where the operation will take place.
 *
 * @param reply The DNS reply where the NS reply will be added.
 *
 * @param primary_server The primary DNS server name for the SOA record.
 *
 * @param mail_contact The mail contact for this domain.
 *
 * @param serial The serial value for SOA record.
 *
 * @param refresh The refresh value for SOA record.
 *
 * @param retry The retry value for SOA record.
 *
 * @param expire The expire value for SOA record.
 *
 * @param minimum The minimum value for SOA record.
 *
 * @param ttl The ttl to be reported in the reply.
 *
 * @return axl_true in the case the reply was added, otherwise
 * axl_false is returned.
 */
axl_bool        ext_dns_message_add_soa_reply (extDnsCtx * ctx, extDnsMessage * reply, 
					       const char * primary_server, const char * mail_contact, 
					       int serial, int refresh, int retry, int expire, int minimum,
					       int ttl)
{
	char     * temp;
	axl_bool   result;

	/* query if the question section is ok */
	if (reply == NULL || reply->questions == NULL || reply->questions[0].qname == NULL || primary_server == NULL || mail_contact == NULL) {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, 
			     "Failed to add NS value, received invalid content (null context %p), (null reply %p), (null mailer %p) (wrong preference %d)",
			     ctx, reply, primary_server, mail_contact);
		return axl_false;
	} /* end if */

	/* report result */
	temp   = axl_strdup_printf ("%s %s %d %d %d %d %d", primary_server, mail_contact, serial, refresh, retry, expire, minimum);
	result = ext_dns_message_add_answer (ctx, reply, extDnsTypeSOA, extDnsClassIN, reply->questions[0].qname, ttl, temp);
	axl_free (temp);
	return result;
}

/** 
 * @brief Allows to add an additional answer record to the provided
 * message.
 *
 * The message must be a reply (\ref ext_dns_message_is_query). 
 *
 * @param ctx The context where the message to buffer will take place.
 * @param message The reply to be updated with the provided values.
 *
 * @param type The answer record type.
 *
 * @param class The answer record class.
 *
 * @param name The answer record name.
 *
 * @param ttl The record ttl value.
 *
 * @param content The record content to be configured. The following are supported formats for content: 
 *
 * \code
 * Record type      Content
 *
 * A                ipv4
 *
 * AAAA             ipv6
 *
 * CNAME            host domain name
 *
 * SOA              <mname> <rname> <serial> <retry> <expire> 
 *                  ; check RFC1035, page 19 for more information.
 *
 * MX               <preference>
 *                  ; where <preference> is a number and <mailer> is the mailer hostname
 *
 * NS               host domain name
 * \endcode
 *
 * @return axl_true if the answer was added to the reply, otherwise,
 * axl_false is returned. The function also returns axl_false when the
 * value provided doesn't match the type. For example, if extDnsTypeA
 * is provided, content must have a valid IPv4 value.
 */
axl_bool        ext_dns_message_add_answer (extDnsCtx * ctx, extDnsMessage * message, extDnsType type, extDnsClass class, 
					    const char * name, int ttl, const char * content)
{
	axlPointer              ptr;
	extDnsResourceRecord  * rr;
	char                 ** items;

	if (ctx == NULL || message == NULL || name == NULL || content == NULL) {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Failed to add answer, context, message, record name or record content is NULL");
		return axl_false;
	} /* end if */
	
	/* prechecks before doing anything */
	if (type == extDnsTypeA) {
		if (! ext_dns_support_is_ipv4 (content)) {
			ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Failed to add answer, received an IP which isn't valid: %s", content);
			return axl_false;
		}
	} /* end if */

	/* realloc value */
	ptr = axl_realloc (message->answers, sizeof (extDnsResourceRecord) * (message->header->answer_count + 1));
	if (ptr == NULL) {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Failed to add answer, unable to allocate enough memory");
		return axl_false;
	} /* end if */

	/* update references */
	message->answers = ptr;
	message->header->answer_count++;
	
	/* set values */
	rr = &(message->answers[message->header->answer_count - 1]);
	rr->name         = axl_strdup (name);
	rr->name_content = axl_strdup (content);
	rr->class        = class;
	rr->type         = type;
	rr->ttl          = ttl;

	/* init values */
	rr->mname = NULL;
	rr->contact_address = NULL;
	rr->target = NULL;

	if (type == extDnsTypeA) {
		/* encode ip */
		rr->rdlength = 4;
		rr->rdata    = axl_new (char, 4);
		if (rr->rdata == NULL) {
			/* remove this answer from the header because
			 * the data isn't complete */
			message->header->answer_count--;
			ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Failed to add answer, failed to allocate memory for the rdata section");
			return axl_false;
		} /* end if */

		/* parse ip value */
		items = axl_split (content, 1, ".");
		if (items == NULL) {
			/* remove this answer from the header because
			 * the data isn't complete */
			message->header->answer_count--;
			ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Failed to add answer, failed to allocate memory to the answer question");
			return axl_false;
		} /* end if */

		rr->rdata[0] = ext_dns_atoi (items[0]);
		rr->rdata[1] = ext_dns_atoi (items[1]);
		rr->rdata[2] = ext_dns_atoi (items[2]);
		rr->rdata[3] = ext_dns_atoi (items[3]);
		axl_freev (items);
	} else if (type == extDnsTypeMX) {
		/* cear items */
		items = axl_split (content, 1, " ");
		/* clean split */
		axl_stream_clean_split (items);
		
		/* get preference ... */
		rr->preference  = ext_dns_atoi(items[0]);

		/* ... and domain */
		axl_free (rr->name_content);
		rr->name_content = axl_strdup (items[1]);
		
		axl_freev (items);
	} else if (type == extDnsTypeSOA) {
		/* clear items */
		items = axl_split (content, 1, " ");
		/* clean split */
		axl_stream_clean_split (items);
		
		/* get soa values */
		rr->mname              = axl_strdup (items[0]);
		rr->contact_address    = axl_strdup (items[1]);
		axl_replace (rr->contact_address, "@", ".");
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Result of processing contact address: '%s'", rr->contact_address);

		rr->serial   = ext_dns_atoi (items[2]);
		rr->refresh  = ext_dns_atoi (items[3]);
		rr->retry    = ext_dns_atoi (items[4]);
		rr->expire   = ext_dns_atoi (items[5]);
		rr->minimum  = ext_dns_atoi (items[6]);

		/* release items */
		axl_freev (items);
	} /* end if */
	
	return axl_true;
}

/** 
 * @brief Allows to add all answers inside extension message into the
 * first message (second argument).
 *
 * @param ctx The context where the operation will take place.
 *
 * @param message The message that will be updated with all answers found in extension.
 *
 * @param extension The source message where all answers will be
 * copied into message.
 *
 * @return axl_true in the case all answers where copied, otherwise
 * axl_false is returned. The function also returns axl_false in the
 * case some parameter is NULL.
 */
axl_bool        ext_dns_message_add_answer_from_msg (extDnsCtx * ctx, extDnsMessage * message, extDnsMessage * extension)
{
	int iterator = 0;

	if (ctx == NULL || message == NULL || extension == NULL)
		return axl_false;

	while (iterator < extension->header->answer_count) {
		/* add answer */
		if (! ext_dns_message_add_answer (ctx, message, 
						  extension->answers[iterator].type, 
						  extension->answers[iterator].class, 
						  extension->answers[iterator].name, 
						  extension->answers[iterator].ttl, 
						  extension->answers[iterator].name_content))
			return axl_false;

		/* next position */
		iterator++;
	}

	/* added answers */
	return axl_true;
}

int __ext_dns_message_get_resource_size (extDnsResourceRecord * rr)
{
	int result = 2 + 2 + 4 + strlen (rr->name) + 2; /* type, class, ttl, name encoded */
	
	/* now according to the type, add additional values */
	if (rr->type == extDnsTypeA) {
		/* check values */
		result += 2 + rr->rdlength;

	} else if (rr->type == extDnsTypeMX) {
		/* check values */
		result += 2 + strlen (rr->name_content);

	} else if (rr->type == extDnsTypeCNAME || rr->type == extDnsTypePTR || rr->type == extDnsTypeNS) {

		/* check values */
		result += 2 + strlen (rr->name_content) + 2;

	} else if (rr->type == extDnsTypeTXT || rr->type == extDnsTypeSPF) {
		/* check values */
		result += 2 + rr->rdlength;

	} else if (rr->type == extDnsTypeSOA) {

		/* check values */
		result += 26 + strlen (rr->mname) + strlen (rr->contact_address);

	} else {
		/* check values */
		result += 2 + rr->rdlength;
	}

	return result;
}

/** 
 * @internal Function to dump DNS resource record into a buffer ready
 * to be sent to the network.
 */
int __ext_dns_message_write_resource_record (extDnsCtx * ctx, extDnsResourceRecord * rr, char * buffer, int buffer_size, int position)
{
	int limit;
	int result;

	if (rr->name == NULL) {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Recevied request to dump resource record with a NULL reference label..");
		return position;
	}

	/* check values before encoding (the following check protects
	 * name, type, class and ttl) */
	limit = position + __ext_dns_message_get_resource_size (rr);
	if (limit > buffer_size) {
		ext_dns_log (EXT_DNS_LEVEL_WARNING, "found more content %d (bytes) to be placed into the buffer than is accepted %d (bytes) while writting record",
			     limit, buffer_size);
		return -1;
	} /* end if */

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "PLACING Resource record:  Encoding resource name: %s", rr->name);
	result = ext_dns_encode_domain_name (ctx, rr->name, buffer + position, buffer_size - position);
	if (result == -1)
		return -1;
	position += result;
	
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
		result = ext_dns_encode_domain_name (ctx, rr->name_content, buffer + position, buffer_size - position);
		if (result == -1)
			return -1;
		position += result;

		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "   written rdlength: %d", strlen (rr->name_content) + 4);

	} else if (rr->type == extDnsTypeCNAME || rr->type == extDnsTypePTR || rr->type == extDnsTypeNS) {

		/* set RDLENGTH */
		/* resource record + initial count + ending \0 */
		ext_dns_set_16bit (strlen (rr->name_content) + 2, buffer + position);
		/* next four bytes */
		position += 2;

		/* encode CNAME, PTR or NS value */
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "  enconding type %s: %s", ext_dns_message_get_qtype_to_str (ctx, rr->type), rr->name_content);
		result = ext_dns_encode_domain_name (ctx, rr->name_content, buffer + position, buffer_size - position);
		if (result == -1)
			return -1;
		position += result;

	} else if (rr->type == extDnsTypeTXT || rr->type == extDnsTypeSPF) {
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
		ext_dns_set_16bit (strlen (rr->mname) + strlen (rr->contact_address) + 24, buffer + position);
		/* next four bytes */
		position += 2;

		/* encode mname value */
		result = ext_dns_encode_domain_name (ctx, rr->mname, buffer + position, buffer_size - position);
		if (result == -1)
			return -1;
		position += result;

		/* encode contact address value */
		result = ext_dns_encode_domain_name (ctx, rr->contact_address, buffer + position, buffer_size - position);
		if (result == -1)
			return -1;
		position += result;

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
 * @param message The DNS message to be translated into a buffer.
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
	int result;
	int count;
	int limit;

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

		/* check values before encoding */
		limit = position + strlen (message->questions[count].qname) + 6;
		if (limit > buffer_size) {
			ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "found more content %d (bytes) to be placed into the buffer than is accepted %d (bytes)",
				     limit, buffer_size);
			return -1;
		} /* end if */
			
		result = ext_dns_encode_domain_name (ctx, message->questions[count].qname, buffer + position, buffer_size - position);
		if (result == -1)
			return -1;
		position += result;
		
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
		result = __ext_dns_message_write_resource_record (ctx, &message->answers[count], buffer, buffer_size, position);
		if (result == -1) {
			/* recodify number of anwers in the buffer to it match the number */
			ext_dns_set_16bit (count, buffer + 6);
			break;
		}
		position = result;

		/* next count */ 
		count++;
	}

	/*** PLACE AUTHORITIES ****/
	count = 0;
	while (count < message->header->authority_count) {

		/* dump resource record */
		result = __ext_dns_message_write_resource_record (ctx, &message->authorities[count], buffer, buffer_size, position);
		if (result == -1) {
			/* recodify number of anwers in the buffer to it match the number */
			ext_dns_set_16bit (count, buffer + 8);
			break;
		}
		position = result;

		/* next count */ 
		count++;
	}

	/*** PLACE ADDITIONALS ****/
	count = 0;
	while (count < message->header->additional_count) {

		/* dump resource record */
		result = __ext_dns_message_write_resource_record (ctx, &message->additionals[count], buffer, buffer_size, position);
		if (result == -1) {
			/* recodify number of anwers in the buffer to it match the number */
			ext_dns_set_16bit (count, buffer + 10);
			break;
		}
		position = result;

		/* next count */ 
		count++;
	}

	/* return bytes written in the buffer */
	return position;
}

/** 
 * @brief Assuming the provided buffer has a valid DNS message to be
 * send, this function updates that buffer to use the ID from the
 * message's header provided.
 *
 * This function is especially useful when it is reused a message to
 * reply several incoming queries so using \ref ext_dns_message_to_buffer is not enough because that function will
 * write the ID of the message used to reply but not the ID of the
 * incoming query. 
 *
 * This function is especially designed to be used in combination with
 * a result obtained from \ref ext_dns_cache_get.
 *
 * @param message The message to extract the header id from to be written into the buffer.
 *
 * @param buffer A refernce to the buffer where a valid message is
 * written and that must be updated with the provided message's header
 * id.
 * 
 */
void            ext_dns_message_write_header_id (extDnsMessage * message, char * buffer)
{
	if (message == NULL || buffer == NULL)
		return;
	
	/* set ID */
	ext_dns_set_16bit (message->header->id, buffer);
	return;
}

/** 
 * @brief Allows to run a query to the provided server, getting the
 * reply on the provided handler.
 *
 * @param ctx The context where the query will take place.
 *
 * @param _type The type (A, a, MX, mx,...) that is being queried.
 *
 * @param _class The class type to query (IN, in, ..).
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
	axl_bool             sent_status;

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

	/* flag to close listener on reply */
	listener->close_on_reply = axl_true;

	/* configure on received message */
	ext_dns_session_set_on_message (listener, on_message, data);

	/* set header to be used to check reply received */
	listener->expected_header = header;

	/* record here pending to close listener */
	_ext_dns_session_record_pending_reply (ctx, listener);

#if ! defined (__EXT_DNS_DISABLE_DEBUG_CODE)
	/* enable failure simulation, every query to the following name will fail */
	if (axl_cmp (name, "49fkfker3rfed.aspl.es")) 
		sent_status = axl_false;
	else
#endif
	/* send and grab sent status */
	sent_status = ext_dns_session_send_udp_s (ctx, listener, buffer, bytes_written, server, 53) == bytes_written;

	/* send message */
	if (! sent_status) {
		/* remove from tracking */
		_ext_dns_session_remove_from_pending_hash (ctx, listener);

		/* log error found */
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "ERROR: failed to send UDP message, written different number of bytes than expected. Replying to client with unknown code.");

		ext_dns_session_close (listener);
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

typedef struct _extDnsHandleReplyData {
	int             id;
	char          * source_address;
	int             source_port;
	extDnsSession * master_listener;

	/* origianl query question */
	extDnsMessage * message;
} extDnsHandleReplyData;

void ext_dns_message_handle_reply_data_free (extDnsHandleReplyData * data)
{
	/* release query question */
	if (data->message)
		ext_dns_message_unref (data->message);

	axl_free (data->source_address);
	axl_free (data);
	return;
}

void ext_dns_message_handle_reply (extDnsCtx     * ctx,
				   extDnsSession * session,
				   const char    * source_address,
				   int             source_port,
				   extDnsMessage * message,
				   axlPointer      data)
{
	char                    buffer[512];
	int                     bytes_written;
	extDnsHandleReplyData * reply_data = data;
	axl_bool                should_release_message = axl_false;

	/* check if message or session are null */
	if (message == NULL) {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Received NULL reference for message. See previous error. Replying unknown error");

		/* build unknown server reply */
		message = ext_dns_message_build_unknown_reply (ctx, reply_data->message);

		/* set we have to release this reference before finish */
		should_release_message = axl_true;
	} /* end if */

	/* ok, rewrite reply id to match the one sent by the client */
	message->header->id = reply_data->id;

	/* get the reply into a buffer */
	bytes_written = ext_dns_message_to_buffer (ctx, message, buffer, 512);

	if (bytes_written == -1) {
		/* release message before continue */
		if (should_release_message)
			ext_dns_message_unref (message);

		ext_dns_message_handle_reply_data_free (reply_data);

		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "ERROR: failed to build buffer representation for reply received..");
		return;
	}

	/* relay reply to the regression client */
	if (ext_dns_session_send_udp_s (ctx, reply_data->master_listener, buffer, bytes_written, reply_data->source_address, reply_data->source_port) != bytes_written) 
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "ERROR: failed to SEND UDP entire reply, expected to write %d bytes but something different was written", bytes_written);
	else {
		/* store reply in the cache */
		ext_dns_cache_store (ctx, message, reply_data->source_address);
	} /* end if */

	/* release data */
	ext_dns_message_handle_reply_data_free (reply_data);

	/* release message before continue */
	if (should_release_message)
		ext_dns_message_unref (message);

	return;
}

/** 
 * @brief Convenient function that allows doing a query and forward the reply received.
 *
 * This function allows to launch a DNS query, taking the exact query
 * to do from ANSWER section inside message, doing that query to
 * server:server_port and in the case a right reply is received, the
 * reply is relayed to the requesting address which is
 * reply_to_address:reply_to_port.
 *
 * Additionally, the reply will be sent as comming from the address
 * bind by the provided \ref extDnsSession (reply_from).
 *
 * In the case you are using \ref ext_dns_cache "the DNS cache", you
 * can also signal the function to cache the reply (it will call \ref
 * ext_dns_cache_store for you).
 *
 * Here is an examle:
 *
 * \code
 * // let's suppose you've received a query represented by message, and you
 * // want to forward the query to google's public DNS and then relay the reply
 * // to the asking peer. Note also you usually receive the source address of 
 * // the incoming request. That would be done like follows

 * if (! ext_dns_message_query_and_forward_from_msg (ctx, message, "8.8.8.8", 53, 
 *                                                   // reply to the following direction
 *                                                   source_address, source_port,
 *                                                   // listener points to the master listener
 *                                                   // (extDnsSession) that received the query
 *                                                   listener, 
 *                                                   // we want to cache the reply
 *                                                   axl_true)) {
 *      printf ("ERROR: failed to send query..\n");
 *      // ...do some handling handling... 
 * }
 * \endcode
 *
 * @param ctx The context where the operation will take place.
 * @param message The message from where the query will be take
 *
 * @param server The external DNS server address that will receive the request.
 * @param server_port The external DNS server port.
 *
 * @param reply_to_address Once the reply is received, that will be relayed to this direction.
 * @param reply_to_port The port to reply the reply.
 *
 * @param reply_from The session that will be used as reference to make the reply forwarded to appear as coming from it.
 * 
 * @param cache_reply If it is required to cache the reply received.
 *
 * @return The function returns axl_true in the case the request was
 * sent. Otherwise axl_false is returned. The function will also
 * return axl_false in the case message, server, reply_to_address or
 * reply_from is NULL.
 *
 */
axl_bool        ext_dns_message_query_and_forward_from_msg (extDnsCtx * ctx, extDnsMessage * message,
							    const char * server, int server_port,
							    const char * reply_to_address, int reply_to_port,
							    extDnsSession * reply_from, axl_bool cache_reply)
{
	extDnsHandleReplyData * data;

	/* check input parameters */
	if (message == NULL || server == NULL || reply_to_address == NULL || reply_from == NULL)
		return axl_false;

	/* acquire reference before continue */
	if (! ext_dns_message_ref (message))
		return axl_false;

	/* build state data */
	data = axl_new (extDnsHandleReplyData, 1);
	if (data == NULL) {
		ext_dns_message_unref (message);
		return axl_false;
	} /* end if */

	data->id               = message->header->id;
	data->source_address   = axl_strdup (reply_to_address);
	data->source_port      = reply_to_port;
	data->master_listener  = reply_from;
	/* set message reference */
	data->message          = message;
	
	/* send query */
	if (! ext_dns_message_query_from_msg (ctx, message, server, server_port, ext_dns_message_handle_reply, data)) {
		/* message not sent, release */
		ext_dns_message_handle_reply_data_free (data);
	} /* end if */

	return axl_true;
}

/** 
 * @brief Convenient function to get the query name being asked in the message (no matter if it is a query or reply).
 *
 * @param ctx The context where the operation will take place.
 *
 * @param message The message where the query name is being asked.
 *
 * @return The query name value or NULL if it fails.
 */
const char *    ext_dns_message_query_name (extDnsCtx * ctx, extDnsMessage * message)
{
	if (message == NULL || message->questions == NULL)
		return NULL;
	return message->questions[0].qname;
}

/** 
 * @brief Convenient function to get the query class being asked in the
 * message (no matter if it is a query or reply).
 *
 * @param ctx The context where the operation will take place.
 *
 * @param message The message where the query class is being asked.
 *
 * @return The query class value or NULL if it fails.
 */
const char *    ext_dns_message_query_class (extDnsCtx * ctx, extDnsMessage * message)
{
	if (message == NULL || message->questions == NULL)
		return NULL;
	return ext_dns_message_get_qclass_to_str (ctx, message->questions[0].qclass);
}

/** 
 * @brief Convenient function to get the query type being asked in the
 * message (no matter if it is a query or reply).
 *
 * @param ctx The context where the operation will take place.
 *
 * @param message The message where the query type is being asked.
 *
 * @return The query type value or NULL if it fails.
 */
const char *    ext_dns_message_query_type (extDnsCtx * ctx, extDnsMessage * message)
{
	if (message == NULL || message->questions == NULL)
		return NULL;
	return ext_dns_message_get_qtype_to_str (ctx, message->questions[0].qtype);
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
			axl_free (message->answers[count].target);
			
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
			axl_free (message->authorities[count].target);
			
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
			axl_free (message->additionals[count].target);
		
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
 * @brief Allows to get current ref counting (for debugging purposes).
 *
 * @param message The message to get ref counting from.
 *
 * @return The reference counting value, or -1 if it fails (for
 * example, NULL reference).
 */
int             ext_dns_message_ref_count (extDnsMessage * message)
{
	if (message == NULL)
		return -1;
	return message->ref_count;
}

/** 
 * @brief Allows to send a DNS message represented by message to the defined destination.
 *
 * This is a conveniente function built on top of \ref
 * ext_dns_session_send_udp_s which allows to send a \ref
 * extDnsMessage directly instead of a dns message found in a buffer.
 * 
 * @param ctx The context where the operation will take place.
 *
 * @param session The session that is going to be taken as reference
 * to make the send operation to appear coming from it (which is
 * required by DNS RFC while sending replies using UDP).
 *
 * @param message The actual to be sent.
 *
 * @param address The address destination or name where the message will be sent.
 *
 * @param port The destination port
 *
 * @return axl_true if the message was sent, otherwise, axl_false is
 * returned. The function also returns NULL when ctx, session,
 * message, address or port aren't defined (NULL) or has wrong values
 * (port <= 0).
 *
 */ 
axl_bool        ext_dns_message_send_udp_s (extDnsCtx      * ctx, 
					    extDnsSession  * session,
					    extDnsMessage  * message,
					    const char     * address, 
					    int              port)
{
	int  bytes_written;
	char buffer[512];

	/* check input values received */
	if (ctx == NULL || session == NULL || message == NULL || address == NULL || port <= 0)
		return axl_false;

	/* build buffer reply */
	bytes_written = ext_dns_message_to_buffer (ctx, message, buffer, 512);
	if (bytes_written <= 0) {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "failed to dump message into the buffer, unable to send message to %s:%d", address, port);
		return axl_false;
	} /* end if */

	/* send reply */
	if (ext_dns_session_send_udp_s (ctx, session, buffer, bytes_written, address, port) != bytes_written) {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "failed to send %d bytes as reply, different amount of bytes where written", bytes_written);
		return axl_false;
	} /* end if */

	return axl_true;
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
 * buffer or -1 if it fails.
 */
int             ext_dns_message_build_query (extDnsCtx * ctx, const char * qname, extDnsType qtype, extDnsClass qclass, char * buffer, extDnsHeader ** header)
{
	int            position;
	extDnsHeader * _header;
	int            result;

	/* Simple "srand()" seed: just use "time()" */
	/*	unsigned int iseed = (unsigned int) time(NULL);
		srand (iseed); */

	/* build header */
	_header = axl_new (extDnsHeader, 1);
	if (_header == NULL) {
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Failed to allocate memory for the header, unable to send message..\n");
		return -1;
	}

	/* clear buffer received */
	memset (buffer, 0, 512);

	/* get id */
	_header->id = ext_dns_message_rand () % 65536;

	/* set id */
	ext_dns_set_16bit (_header->id, buffer);

	/* set RD */
	ext_dns_set_bit (buffer + 2, 0);

	/* set question count */
	ext_dns_set_16bit (1, buffer + 4);

	/* set initial position */
	position = 12;

	/* now write question */
	result = ext_dns_encode_domain_name (ctx, qname, buffer + position, 512 - position);
	if (result == -1) {
		axl_free (_header);
		return -1;
	}
	position += result;

	/* place qtype */
	ext_dns_set_16bit (qtype, buffer + position);
	position += 2;

	/* place qclass */
	ext_dns_set_16bit (qclass, buffer + position);
	position += 2;

	/* set header to the caller if defined */
	if (header)
		*header = _header;
	else {
		/* release the header in the case the caller doesn't want it */
		axl_free (_header);
	}

	return position;
}


/** 
 * @brief Allows to get the extDnsType code from the qtype string.
 *
 * @param ctx The extDnsCtx where the operation will take place.
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
	if (axl_cmp (qtype, "SRV") || axl_cmp (qtype, "srv"))
		return extDnsTypeSRV;
	if (axl_cmp (qtype, "SPF") || axl_cmp (qtype, "spf"))
		return extDnsTypeSPF;
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
 * @brief Allows to get a printable type representation from \ref extDnsType code.
 *
 * @param ctx The extDnsCtx where the operation will take place.
 *
 * @param type The question type that is being asked to be translated
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
	if (type == extDnsTypeSRV)
		return "SRV";
	if (type == extDnsTypeSPF)
		return "SPF";
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
	return "UNKNOWN";
}

/** 
 * @brief Allows to get the extDnsClass code from the qclass string.
 *
 * @param ctx The extDnsCtx where the operation will take place.
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
 * @param ctx The extDnsCtx where the operation will take place.
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
	return "UNKNOWN";
}

/** 
 * @internal Get the on received handler associated in the provided
 * listener in a thread safe manner.
 */
extDnsOnMessageReceived _ext_dns_message_get_on_received (extDnsCtx * ctx, extDnsSession * listener)
{
        axlPointer ptr;

        if (ctx == NULL || listener == NULL || listener->on_message == NULL)
	       return NULL;
	
	/* acquire mutex */
	ext_dns_mutex_lock (&listener->ref_mutex);

	/* get reference */
	ptr = listener->on_message;

	/* nufilly on received message if this is a listener to receive replies */
	if (listener->close_on_reply) {
	        listener->on_message = NULL;
	} /* end if */

	/* unlock mutex */
	ext_dns_mutex_unlock (&listener->ref_mutex);

	/* return pointer */
	return ptr;
}

/* @} */
