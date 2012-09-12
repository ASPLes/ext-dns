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
#ifndef __EXT_DNS_MESSAGE_H__
#define __EXT_DNS_MESSAGE_H__

#include <ext-dns.h>

extDnsHeader  * ext_dns_message_parse_header (extDnsCtx * ctx, const char * buf, int buf_size);

extDnsMessage * ext_dns_message_parse_message (extDnsCtx * ctx, extDnsHeader * header, const char * buf, int buf_size);

axl_bool        ext_dns_message_ref (extDnsMessage * message);

void            ext_dns_message_unref (extDnsMessage * message);

int             ext_dns_message_build_query (extDnsCtx * ctx, const char * qname, extDnsType qtype, extDnsClass qclass, 
					     char * buffer, extDnsHeader ** header);

int             ext_dns_message_build_reply (extDnsCtx * ctx, extDnsMessage * message, char * buffer, int ttl, const char * data);

axl_bool            ext_dns_message_query (extDnsCtx * ctx, const char * type, const char * class, const char * name, 
					   const char * server, int server_port,
					   extDnsOnMessageReceived on_message, axlPointer data);
				
extDnsType      ext_dns_message_get_qtype (const char * qtype);

const char *    ext_dns_message_get_qtype_from_str (extDnsType type);

extDnsClass     ext_dns_message_get_qclass (const char * qclass);

const char *    ext_dns_message_get_qclass_from_str (extDnsClass class);

char *          ext_dns_message_get_printable_rdata (extDnsCtx * ctx, extDnsResourceRecord * rr);

#endif /* __EXT_DNS_MESSAGE_H__ */
