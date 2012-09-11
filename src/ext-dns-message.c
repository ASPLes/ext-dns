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
	ext_dns_show_byte (ctx, buf[0], "buf[0]");
	ext_dns_show_byte (ctx, buf[1], "buf[1]");

	/* get 16 bit integer */
	header->id       = ext_dns_get_16bit (buf);

	ext_dns_int2bin_print (ctx, header->id);

	header->is_query              = ext_dns_extract_bit (buf[2], 7);

	/* get opcode */
	header->opcode                = (buf[2] >> 3 ) & 240;
	ext_dns_show_byte (ctx, buf[2], "buf[2]");
	ext_dns_show_byte (ctx, header->opcode, "header->opcode");

	/* get other flags */
	header->is_authorative_answer = ext_dns_extract_bit (buf[2], 2);
	header->was_truncated         = ext_dns_extract_bit (buf[2], 1);
	header->recursion_desired     = ext_dns_extract_bit (buf[2], 0);

	header->recursion_available   = ext_dns_extract_bit (buf[3], 7);

	/* get response code */
	header->rcode                 = buf[3] & 240;

	/* get counters */
	header->query_count               = ext_dns_get_16bit (buf + 4);
	header->answer_count              = ext_dns_get_16bit (buf + 6);
	header->resources_count           = ext_dns_get_16bit (buf + 8);
	header->additional_records_count  = ext_dns_get_16bit (buf + 10);

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

char * ext_dns_message_get_resource_name (extDnsCtx * ctx, const char * buffer, int buf_size, int iterator)
{
	/* clear resource name */
	char * resource_name = NULL;
	char * label         = NULL;
	char * aux           = NULL;
	
	while (iterator < buf_size && buffer[iterator]) {
		/* get label */
		label = ext_dns_message_get_label (ctx, buffer + iterator);
		
		if (label == NULL) 
			break;
		
		/* get length */
		iterator += strlen (label) + 1;
		
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
	} /* end while */

	return resource_name;
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

	/* create empty message */
	message = axl_new (extDnsMessage, 1);
	if (message == NULL)
		return NULL;

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
		message->questions[count].qname  = ext_dns_message_get_resource_name (ctx, buf, buf_size, iterator);

		/* failed to get query name */
		if (message->questions[count].qname == NULL)
			break;

		iterator += strlen (message->questions[count].qname) + 1;

		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Resource name: '%s'", message->questions[count].qname);
		
		/* get qtype */
		iterator++;
		message->questions[count].qtype  = ext_dns_get_16bit (buf + iterator);
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "qtype received = %d", message->questions[count].qtype);
		
		/* get qclass */
		iterator += 2;
		message->questions[count].qclass = ext_dns_get_16bit (buf + iterator);
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "qclass received = %d", message->questions[count].qclass);

		/* next section */
		count++;
	} /* end if */

	/*** ANSWERS ***/
	/* still not supported */

	/*** AUTHORITY ***/
	/* still not supported */

	/*** ADDITIONAL ***/
	/* still not supported */

	return message;
}

/** 
 * @internal Allows to build a reply using the provided header with
 * the provided data. The result is left into buffer so the user can
 * send it.
 */
int             ext_dns_message_build_reply (extDnsCtx * ctx, extDnsMessage * message, char * buffer, 
					     int ttl, const char * data)
{
	int position;

	/* clear buffer */
	memset (buffer, 0, 512);

	/* set ID */
	ext_dns_set_16bit (message->header->id, buffer);

	/* set QR */
	ext_dns_set_bit (buffer + 2, 7);

	/* set RD if requested by the user */
	if (message->header->recursion_desired)
		ext_dns_set_bit (buffer + 2, 0);

	/* set RA if recursion is available */
	ext_dns_set_bit (buffer + 3, 7);

	/* set QDCOUNT count */
	ext_dns_set_16bit (1, buffer + 4);

	/* set ANCOUNT count */
	ext_dns_set_16bit (1, buffer + 6);

	/* first position */
	position = 12;

	/*** PLACE QUESTION ***/
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "PLACING QUESTION:  Encoding resource name: %s", message->questions[0].qname);
	position += ext_dns_encode_domain_name (ctx, message->questions[0].qname, buffer + position);

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "   qname position after placing name: %d", position);

	/* set TYPE */
	ext_dns_set_16bit (message->questions[0].qtype, buffer + position);
	ext_dns_show_byte (ctx, buffer[position], "TYPE[0]");
	ext_dns_show_byte (ctx, buffer[position + 1], "TYPE[1]");

	/* next two bytes */
	position += 2;

	/* set CLASS */
	ext_dns_set_16bit (message->questions[0].qclass, buffer + position);
	ext_dns_show_byte (ctx, buffer[position], "CLASS[0]");
	ext_dns_show_byte (ctx, buffer[position + 1], "CLASS[1]");

	/* next two bytes */
	position += 2;
	
	/*** PLACE ANSWER ****/
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "PLACING ANSWER:  Encoding resource name: %s", message->questions[0].qname);
	position += ext_dns_encode_domain_name (ctx, message->questions[0].qname, buffer + position);

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "   qname position after placing name: %d", position);

	/* set TYPE */
	ext_dns_set_16bit (message->questions[0].qtype, buffer + position);
	ext_dns_show_byte (ctx, buffer[position], "TYPE[0]");
	ext_dns_show_byte (ctx, buffer[position + 1], "TYPE[1]");

	/* next two bytes */
	position += 2;

	/* set CLASS */
	ext_dns_set_16bit (message->questions[0].qclass, buffer + position);
	ext_dns_show_byte (ctx, buffer[position], "CLASS[0]");
	ext_dns_show_byte (ctx, buffer[position + 1], "CLASS[1]");

	/* next two bytes */
	position += 2;

	/* set TTL */
	ext_dns_set_32bit (ttl, buffer + position);
	ext_dns_show_byte (ctx, buffer[position], "TTL[0]");
	ext_dns_show_byte (ctx, buffer[position + 1], "TTL[1]");
	ext_dns_show_byte (ctx, buffer[position + 2], "TTL[2]");
	ext_dns_show_byte (ctx, buffer[position + 3], "TTL[3]");


	/* next four bytes */
	position += 4;

	/* set RDLENGTH (hard code IP) */
	ext_dns_set_16bit (4, buffer + position);
	ext_dns_show_byte (ctx, buffer[position], "RDLENGTH[0]");
	ext_dns_show_byte (ctx, buffer[position + 1], "RDLENGTH[1]");

	/* next four bytes */
	position += 2;

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Writting A address at position: %d", position);

	buffer[position]     = 192;
	buffer[position + 1] = 168;
	buffer[position + 2] = 1;
	buffer[position + 3] = 44;

	/* return bytes written in the buffer */
	return position + 4;
}


/** 
 * @brief Releases the provided DNS message.
 *
 * @param message The DNS message to release
 */
void ext_dns_message_unref (extDnsMessage * message)
{
	int count;

	if (message == NULL)
		return;

	
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
	/* still not supported */

	/*** AUTHORITY ***/
	/* still not supported */

	/*** ADDITIONAL ***/
	/* still not supported */

	/* release header */
	axl_free (message->header);

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
extDnsType      ext_dns_message_get_qtype (const char * qtype)
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
	if (axl_cmp (qtype, "AXFR") || axl_cmp (qtype, "axfr"))
		return extDnsTypeAXFR;
	if (axl_cmp (qtype, "MAILB") || axl_cmp (qtype, "mailb"))
		return extDnsTypeMAILB;
	if (axl_cmp (qtype, "MAILA") || axl_cmp (qtype, "maila"))
		return extDnsTypeMAILA;
	if (axl_cmp (qtype, "*"))
		return extDnsTypeANY;

	/* unrecognized character */
	return -1;
}

/** 
 * @brief Allows to get the extDnsClass code from the qclass string.
 *
 * @param qclass The question class that is being asked to be translated
 *
 * @return extDnsClass or -1 if it fails.
 */
extDnsClass     ext_dns_message_get_qclass (const char * qclass)
{
	/* get input value */
	if (qclass == NULL || strlen (qclass) == 0)
		return -1;

	if (axl_cmp (qclass, "IN") || axl_cmp (qclass, "in"))
		return extDnsIN;
	if (axl_cmp (qclass, "CS") || axl_cmp (qclass, "cs"))
		return extDnsCS;
	if (axl_cmp (qclass, "CH") || axl_cmp (qclass, "ch"))
		return extDnsCH;
	if (axl_cmp (qclass, "HS") || axl_cmp (qclass, "hs"))
		return extDnsHS;
	if (axl_cmp (qclass, "*"))
		return extDnsClassANY;

	/* unrecognized class */
	return -1;
}
