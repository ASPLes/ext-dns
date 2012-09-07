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


