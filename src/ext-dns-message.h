/* 
 *  ext-dns: a framework to build DNS solutions
 *  Copyright (C) 2020 Advanced Software Production Line, S.L.
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
 *         Avenida Juan Carlos I Nº13, 2ºC (Torre Garena)
 *         Alcalá de Henares 28806 Madrid
 *         Spain
 *
 *      Email address:
 *         info@aspl.es - http://www.aspl.es/ext-dns
 */
#ifndef __EXT_DNS_MESSAGE_H__
#define __EXT_DNS_MESSAGE_H__

#include <ext-dns.h>

/** 
 * \addtogroup ext_dns_message
 * @{
 */

/** 
 * @brief Max buffer size for DNS messages received.
 */
#define EXT_DNS_MESSAGE_BUFFER_SIZE (2048)

/** 
 * @}
 */

extDnsHeader  * ext_dns_message_parse_header (extDnsCtx * ctx, const char * buf, int buf_size);

extDnsMessage * ext_dns_message_parse_message (extDnsCtx * ctx, extDnsHeader * header, const char * buf, int buf_size);

extDnsMessage * ext_dns_message_build_reject_reply (extDnsCtx * ctx, extDnsMessage * message);

extDnsMessage * ext_dns_message_build_unknown_reply (extDnsCtx * ctx, extDnsMessage * message);

extDnsMessage * ext_dns_message_build_ipv4_reply (extDnsCtx * ctx, extDnsMessage * message, const char * ip, int ttl);

extDnsMessage * ext_dns_message_build_cname_reply (extDnsCtx * ctx, extDnsMessage * message, const char * name, int ttl);

extDnsMessage * ext_dns_message_build_mx_reply (extDnsCtx * ctx, extDnsMessage * message, const char * mailer, int preference, int ttl);

extDnsMessage * ext_dns_message_build_ns_reply (extDnsCtx * ctx, extDnsMessage * message, const char * dns_server, int ttl);

extDnsMessage * ext_dns_message_build_soa_reply (extDnsCtx * ctx, extDnsMessage * message, 
						 const char * primary_server, const char * mail_contact, 
						 int serial, int refresh, int retry, int expire, int minimum,
						 int ttl);

axl_bool        ext_dns_message_add_ipv4_reply (extDnsCtx * ctx, extDnsMessage * reply, const char * ip, int ttl);

axl_bool        ext_dns_message_add_cname_reply (extDnsCtx * ctx, extDnsMessage * reply, const char * name, int ttl);

axl_bool        ext_dns_message_add_mx_reply (extDnsCtx * ctx, extDnsMessage * reply, const char * mailer, int preference, int ttl);

axl_bool        ext_dns_message_add_ns_reply (extDnsCtx * ctx, extDnsMessage * reply, const char * dns_server, int ttl);

axl_bool        ext_dns_message_add_soa_reply (extDnsCtx * ctx, extDnsMessage * reply, 
					       const char * primary_server, const char * mail_contact, 
					       int serial, int refresh, int retry, int expire, int minimum,
					       int ttl);

axl_bool        ext_dns_message_add_answer (extDnsCtx     * ctx, 
					    extDnsMessage * message, 
					    extDnsType      type, 
					    extDnsClass     class, 
					    const char    * name, 
					    int             ttl, 
					    const char    * content);

axl_bool        ext_dns_message_add_answer_from_msg (extDnsCtx * ctx, extDnsMessage * message, extDnsMessage * extension);

axl_bool        ext_dns_message_is_query (extDnsMessage * message);

axl_bool        ext_dns_message_is_reject (extDnsMessage * message);

axl_bool        ext_dns_message_is_name_error (extDnsMessage * message);

axl_bool        ext_dns_message_is_answer_valid (extDnsCtx * ctx, extDnsMessage * message);

axl_bool        ext_dns_message_ref (extDnsMessage * message);

void            ext_dns_message_unref (extDnsMessage * message);

int             ext_dns_message_ref_count (extDnsMessage * message);

axl_bool        ext_dns_message_send_udp_s (extDnsCtx      * ctx, 
					    extDnsSession  * session,
					    extDnsMessage  * message,
					    const char     * address, 
					    int              port);

int             ext_dns_message_build_query (extDnsCtx * ctx, const char * qname, extDnsType qtype, extDnsClass qclass, 
					     char * buffer, extDnsHeader ** header);

int             ext_dns_message_to_buffer (extDnsCtx * ctx, extDnsMessage * message, char * buffer,  int buffer_size);

void            ext_dns_message_write_header_id (extDnsMessage * message, char * buffer);

axl_bool        ext_dns_message_query (extDnsCtx * ctx, const char * type, const char * class, const char * name, 
				       const char * server, int server_port,
				       extDnsOnMessageReceived on_message, axlPointer data);

axl_bool        ext_dns_message_query_int (extDnsCtx * ctx, extDnsType _type, extDnsClass _class, const char * name, 
					   const char * server, int server_port,
					   extDnsOnMessageReceived on_message, axlPointer data);

axl_bool        ext_dns_message_query_from_msg (extDnsCtx * ctx, extDnsMessage * message,
						const char * server, int server_port,
						extDnsOnMessageReceived on_message, axlPointer data);

axl_bool        ext_dns_message_query_and_forward_from_msg (extDnsCtx * ctx, extDnsMessage * message,
							    const char * server, int server_port,
							    const char * reply_to_address, int reply_to_port,
							    extDnsSession * reply_from, axl_bool cache_reply);

const char *    ext_dns_message_query_name (extDnsCtx * ctx, extDnsMessage * message);

const char *    ext_dns_message_query_class (extDnsCtx * ctx, extDnsMessage * message);

const char *    ext_dns_message_query_type (extDnsCtx * ctx, extDnsMessage * message);
				
extDnsType      ext_dns_message_get_qtype (extDnsCtx * ctx, const char * qtype);

const char *    ext_dns_message_get_qtype_to_str (extDnsCtx * ctx, extDnsType type);

extDnsClass     ext_dns_message_get_qclass (extDnsCtx * ctx, const char * qclass);

const char *    ext_dns_message_get_qclass_to_str (extDnsCtx * ctx, extDnsClass class);


/*** private api ***/
void _ext_dns_message_notify_failure (extDnsCtx * ctx, extDnsSession * listener, const char * source_address, int source_port);

extDnsOnMessageReceived _ext_dns_message_get_on_received (extDnsCtx * ctx, extDnsSession * listener);

#endif /* __EXT_DNS_MESSAGE_H__ */
