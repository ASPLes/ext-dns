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
#ifndef __EXT_DNS_CACHE_H__
#define __EXT_DNS_CACHE_H__

#include <ext-dns.h>

void            ext_dns_cache_init (extDnsCtx * ctx, int max_cache_size);

extDnsMessage * ext_dns_cache_get (extDnsCtx * ctx, extDnsClass qclass, extDnsType qtype, const char * query, const char * source_address);

extDnsMessage * ext_dns_cache_get_by_query (extDnsCtx * ctx, extDnsMessage * msg, const char * source_address);

axl_bool        ext_dns_cache_store (extDnsCtx * ctx, extDnsMessage * msg, const char * source_address);

void            ext_dns_cache_stats (extDnsCtx * ctx, extDnsCacheStats * stats);

void            ext_dns_cache_finish (extDnsCtx * ctx);

#endif /* endif */
