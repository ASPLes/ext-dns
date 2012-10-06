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

#ifndef __EXT_DNS_SESSION_H__
#define __EXT_DNS_SESSION_H__

#include <ext-dns.h>

extDnsSession   * ext_dns_session_new_empty  (extDnsCtx        * ctx, 
					      EXT_DNS_SOCKET     socket, 
					      extDnsSessionType  type,
					      extDnsPeerRole     role);

extDnsSession   * ext_dns_session_new_empty_from_session (extDnsCtx          * ctx,
							  EXT_DNS_SOCKET       socket,
							  extDnsSession      * __session,
							  extDnsSessionType    type,
							  extDnsPeerRole       role);

int               ext_dns_session_get_id     (extDnsSession * session);

const char      * ext_dns_session_get_port   (extDnsSession * session);

const char      * ext_dns_session_get_host   (extDnsSession * session);

extDnsCtx       * ext_dns_session_get_ctx    (extDnsSession * session);

EXT_DNS_SOCKET    ext_dns_session_get_socket (extDnsSession * session);

extDnsPeerRole    ext_dns_session_get_role   (extDnsSession * session);

axl_bool          ext_dns_session_is_ok      (extDnsSession * session, axl_bool close_on_failure);

axl_bool          ext_dns_session_close      (extDnsSession * session);

void              ext_dns_session_shutdown   (extDnsSession * session);

void              ext_dns_session_set_on_message (extDnsSession            * session, 
						  extDnsOnMessageReceived    on_dns_message, 
						  axlPointer                 data);

void              ext_dns_session_set_on_badrequest (extDnsSession         * session, 
						     extDnsOnBadRequest      on_badrequest, 
						     axlPointer              data);

void              ext_dns_session_set_data (extDnsSession * session,
					    const char    * key,
					    axlDestroyFunc  key_destroy,
					    axlPointer      data,
					    axlDestroyFunc  data_destroy);

axlPointer        ext_dns_session_get_data (extDnsSession * session, 
					    const char    * key);

axl_bool          ext_dns_session_ref        (extDnsSession * session, 
					      const char    * who);

void              ext_dns_session_unref      (extDnsSession * session, 
					      char const    * who);

int               ext_dns_session_send_udp   (extDnsCtx      * ctx, 
					      const char     * content, 
					      int              length, 
					      const char     * address, 
					      int              port,
					      char          ** source_address,
					      int            * source_port);

int               ext_dns_session_send_udp_s (extDnsCtx      * ctx, 
					      extDnsSession  * session,
					      const char     * content, 
					      int              length, 
					      const char     * address, 
					      int              port);

void              ext_dns_session_free       (extDnsSession * session);

void              ext_dns_session_push_error  (extDnsSession  * session, 
					       int              code,
					       const char     * msg);

axl_bool          ext_dns_session_check_socket_limit     (extDnsCtx        * ctx, 
							  EXT_DNS_SOCKET      socket);

axl_bool         ext_dns_session_set_nonblocking_socket (extDnsSession * session);


EXT_DNS_SOCKET     ext_dns_listener_sock_listen      (extDnsCtx           * ctx,
						      extDnsSessionType     type,
						      const char          * host,
						      const char          * port,
						      axlError           ** error);

extDnsSession     * ext_dns_listener_new (extDnsCtx           * ctx,
					  const char          * host, 
					  const char          * port, 
					  extDnsSessionType     type,
					  extDnsListenerReady   on_ready, 
					  axlPointer            user_data);

extDnsSession     * ext_dns_listener_new_full  (extDnsCtx           * ctx,
						const char          * host,
						const char          * port,
						extDnsSessionType     type,
						extDnsListenerReadyFull on_ready_full, 
						axlPointer user_data);

extDnsSession    * ext_dns_listener_new2    (extDnsCtx           * ctx,
					     const char          * host,
					     int                   port,
					     extDnsSessionType     type,
					     extDnsListenerReady   on_ready, 
					     axlPointer            user_data);

struct in_addr * ext_dns_session_gethostbyname (extDnsCtx  * ctx, 
						const char * hostname);

axl_bool          ext_dns_session_set_sock_tcp_nodelay   (EXT_DNS_SOCKET socket,
							  axl_bool      enable);

axl_bool          ext_dns_session_set_sock_block         (EXT_DNS_SOCKET socket,
							  axl_bool      enable);

EXT_DNS_SOCKET    ext_dns_listener_accept (EXT_DNS_SOCKET server_socket);

/** private functions */
void                __ext_dns_session_shutdown_and_record_error (extDnsSession    * session,
								 extDnsStatus       status,
								 const char       * message,
								 ...);

void               __ext_dns_session_notify_bad_request (extDnsCtx      * ctx,
							 extDnsSession  * session,
							 const char     * source_address,
							 int              source_port,
							 const char     * buffer,
							 int              buffer_size,
							 const char     * reason,
							 ...);

#endif /* __EXT_DNS_SESSION_H__ */
