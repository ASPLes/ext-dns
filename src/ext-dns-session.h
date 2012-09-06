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

#ifndef __EXT_DNS_SESSION_H__
#define __EXT_DNS_SESSION_H__

#include <ext-dns.h>

int               ext_dns_session_get_id     (extDnsSession * session);

const char      * ext_dns_session_get_port   (extDnsSession * session);

const char      * ext_dns_session_get_host   (extDnsSession * session);

extDnsCtx       * ext_dns_session_get_ctx    (extDnsSession * session);

EXT_DNS_SOCKET    ext_dns_session_get_socket (extDnsSession * session);

extDnsPeerRole    ext_dns_session_get_role   (extDnsSession * session);

axl_bool          ext_dns_session_is_ok      (extDnsSession * session, axl_bool close_on_failure);

axl_bool          ext_dns_session_close      (extDnsSession * session);

axl_bool          ext_dns_session_ref        (extDnsSession * session, 
					      const char    * who);

void              ext_dns_session_unref      (extDnsSession * session, 
					      char const    * who);

void              ext_dns_session_free       (extDnsSession * session);

void              ext_dns_session_push_error  (extDnsSession  * session, 
					       int              code,
					       const char     * msg);

axl_bool         ext_dns_session_set_nonblocking_socket (extDnsSession * session);

/** private functions */
void                __ext_dns_session_shutdown_and_record_error (extDnsSession    * session,
								 extDnsStatus       status,
								 const char       * message,
								 ...);

#endif /* __EXT_DNS_SESSION_H__ */
