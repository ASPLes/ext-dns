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
#ifndef __EXT_DNS_SUPPORT_H__
#define __EXT_DNS_SUPPORT_H__

#include <ext-dns.h>

int      ext_dns_support_getenv_int                 (const char * env_name);

char *   ext_dns_support_getenv                     (const char * env_name);

axl_bool ext_dns_support_setenv                     (const char * env_name, 
						    const char * env_value);

axl_bool ext_dns_support_unsetenv                   (const char * env_name);

int      ext_dns_support_itoa                       (unsigned int   value,
						     char         * buffer,
						     int            buffer_size);

char   * ext_dns_support_inet_ntoa                  (extDnsCtx          * ctx, 
						     struct sockaddr_in * sin);

long int ext_dns_atoi                               (const char * number);     

axl_bool ext_dns_support_is_ipv4                    (const char * value);

void     ext_dns_load_etc_hosts                     (extDnsCtx    * ctx, 
						     const char   * etc_hosts, 
						     axlHash     ** ipv4, 
						     axlHash     ** ipv6);

#endif /* __EXT_DNS_SUPPORT_H__ */
