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
#ifndef __EXT_DNS_READER_H__
#define __EXT_DNS_READER_H__

#include <ext-dns.h>

void ext_dns_reader_watch_listener              (extDnsCtx     * ctx,
						 extDnsSession * session);

int  ext_dns_reader_connections_watched         (extDnsCtx     * ctx);

int  ext_dns_reader_run                         (extDnsCtx * ctx);

void ext_dns_reader_stop                        (extDnsCtx * ctx);

int  ext_dns_reader_notify_change_io_api        (extDnsCtx * ctx);

void ext_dns_reader_notify_change_done_io_api   (extDnsCtx * ctx);

/* internal API */
typedef void (*extDnsForeachFunc) (extDnsSession * conn, axlPointer user_data);
typedef void (*extDnsForeachFunc3) (extDnsSession * conn, 
				    axlPointer         user_data, 
				    axlPointer         user_data2,
				    axlPointer         user_data3);

extDnsAsyncQueue * ext_dns_reader_foreach       (extDnsCtx            * ctx,
						extDnsForeachFunc      func,
						axlPointer             user_data);

void               ext_dns_reader_foreach_offline (extDnsCtx           * ctx,
						  extDnsForeachFunc3    func,
						  axlPointer            user_data,
						  axlPointer            user_data2,
						  axlPointer            user_data3);

void               ext_dns_reader_restart (extDnsCtx * ctx);

#endif
