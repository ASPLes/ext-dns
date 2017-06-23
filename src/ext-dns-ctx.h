/* 
 *  ext-dns: a framework to build DNS solutions
 *  Copyright (C) 2017 Advanced Software Production Line, S.L.
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
#ifndef __EXT_DNS_CTX_H__
#define __EXT_DNS_CTX_H__

#include <ext-dns.h>

extDnsCtx * ext_dns_ctx_new (void);

void        ext_dns_ctx_ref                       (extDnsCtx  * ctx);

void        ext_dns_ctx_ref2                      (extDnsCtx  * ctx, const char * who);

void        ext_dns_ctx_unref                     (extDnsCtx ** ctx);

void        ext_dns_ctx_unref2                    (extDnsCtx ** ctx, const char * who);

int         ext_dns_ctx_ref_count                 (extDnsCtx  * ctx);

void        ext_dns_ctx_free                      (extDnsCtx * ctx);

void        ext_dns_ctx_free2                     (extDnsCtx * ctx, const char * who);

void        ext_dns_ctx_set_data                  (extDnsCtx       * ctx, 
						   const char      * key, 
						   axlPointer        value);

void        ext_dns_ctx_set_data_full             (extDnsCtx       * ctx, 
						   const char      * key, 
						   axlPointer        value,
						   axlDestroyFunc    key_destroy,
						   axlDestroyFunc    value_destroy);

axlPointer  ext_dns_ctx_get_data                  (extDnsCtx       * ctx,
						   const char      * key);

axl_bool    ext_dns_ctx_is_black_listed           (extDnsCtx       * ctx,
						   const char      * source_address,
						   axl_bool          refresh_record);

void        ext_dns_ctx_black_list                (extDnsCtx       * ctx, 
						   const char      * source_address,
						   axl_bool          is_permanent,
						   int               seconds);

void        ext_dns_ctx_wait                      (extDnsCtx * ctx);

void        ext_dns_ctx_unlock                    (extDnsCtx * ctx);

void        ext_dns_ctx_set_on_message            (extDnsCtx * ctx,
						   extDnsOnMessageReceived    on_dns_message, 
						   axlPointer                 data);

#endif /* __EXT_DNS_CTX_H__ */
