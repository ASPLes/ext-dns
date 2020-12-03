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
#ifndef __EXT_DNS_IO_H__
#define __EXT_DNS_IO_H__

#include <ext-dns.h>

/* api to configure current I/O system */
axl_bool             ext_dns_io_waiting_use                     (extDnsCtx           * ctx,
								 extDnsIoWaitingType   type);

axl_bool             ext_dns_io_waiting_is_available            (extDnsIoWaitingType type);

extDnsIoWaitingType  ext_dns_io_waiting_get_current             (extDnsCtx           * ctx);

void                 ext_dns_io_waiting_set_create_fd_group     (extDnsCtx           * ctx,
								 extDnsIoCreateFdGroup create);

void                 ext_dns_io_waiting_set_destroy_fd_group    (extDnsCtx           * ctx,
								 extDnsIoDestroyFdGroup destroy);

void                 ext_dns_io_waiting_set_clear_fd_group      (extDnsCtx           * ctx,
								 extDnsIoClearFdGroup clear);

void                 ext_dns_io_waiting_set_add_to_fd_group     (extDnsCtx           * ctx,
								 extDnsIoAddToFdGroup add_to);

void                 ext_dns_io_waiting_set_is_set_fd_group     (extDnsCtx           * ctx,
								 extDnsIoIsSetFdGroup is_set);

void                 ext_dns_io_waiting_set_have_dispatch       (extDnsCtx           * ctx,
								 extDnsIoHaveDispatch  have_dispatch);

void                 ext_dns_io_waiting_set_dispatch            (extDnsCtx           * ctx,
								 extDnsIoDispatch      dispatch);

void                 ext_dns_io_waiting_set_wait_on_fd_group    (extDnsCtx           * ctx,
								 extDnsIoWaitOnFdGroup wait_on);

/* api to perform invocations to the current I/O system configured */
axlPointer           ext_dns_io_waiting_invoke_create_fd_group  (extDnsCtx           * ctx,
								 extDnsIoWaitingFor    wait_to);

void                 ext_dns_io_waiting_invoke_destroy_fd_group (extDnsCtx           * ctx,
								 axlPointer            fd_group);

void                 ext_dns_io_waiting_invoke_clear_fd_group   (extDnsCtx           * ctx,
								 axlPointer            fd_group);

axl_bool             ext_dns_io_waiting_invoke_add_to_fd_group  (extDnsCtx           * ctx,
								 EXT_DNS_SOCKET         fds, 
								 extDnsSession    * session, 
								 axlPointer            fd_group);

axl_bool             ext_dns_io_waiting_invoke_is_set_fd_group  (extDnsCtx           * ctx,
								 EXT_DNS_SOCKET        fds, 
								 axlPointer            fd_group,
								 axlPointer            user_data);

axl_bool             ext_dns_io_waiting_invoke_have_dispatch    (extDnsCtx           * ctx,
								 axlPointer            fd_group);

void                 ext_dns_io_waiting_invoke_dispatch         (extDnsCtx           * ctx,
								 axlPointer            fd_group, 
								 extDnsIoDispatchFunc  func,
								 int                   changed,
								 axlPointer            user_data);

int                  ext_dns_io_waiting_invoke_wait             (extDnsCtx           * ctx,
								 axlPointer            fd_group, 
								 int                   max_fds,
								 extDnsIoWaitingFor    wait_to);

void                 ext_dns_io_init (extDnsCtx * ctx);

/* internal API */
axlPointer __ext_dns_io_waiting_default_create  (extDnsCtx * ctx, extDnsIoWaitingFor wait_to);
void       __ext_dns_io_waiting_default_destroy (axlPointer fd_group);
void       __ext_dns_io_waiting_default_clear   (axlPointer __fd_group);
int        __ext_dns_io_waiting_default_wait_on (axlPointer __fd_group, 
						int        max_fds, 
						extDnsIoWaitingFor wait_to);
axl_bool   __ext_dns_io_waiting_default_add_to  (int                fds, 
						extDnsSession    * session,
						axlPointer         __fd_set);
axl_bool   __ext_dns_io_waiting_default_is_set  (int        fds, 
						axlPointer __fd_set, 
						axlPointer user_data);

#endif
