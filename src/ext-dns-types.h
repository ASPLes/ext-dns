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
#ifndef __EXT_DNS_TYPES_H__
#define __EXT_DNS_TYPES_H__

/*
 * @brief Debug levels to be used with \ref _ext_dns_log, which is used
 * through ext_dns_log macro.
 *
 * The set of functions allowing to activate the debug at run time and
 * its variants are:
 * 
 * - \ref ext_dns_log_is_enabled
 * - \ref ext_dns_log2_is_enabled
 * - \ref ext_dns_log_enable
 * - \ref ext_dns_log2_enable
 *
 * Activate console color log (using ansi characters):
 * 
 * - \ref ext_dns_color_log_is_enabled
 * - \ref ext_dns_color_log_enable
 *
 * @param domain Domain that is registering a log.
 *
 * @param level Log level that is being registered.
 *
 * @param message Message that is being registered.
 */
typedef enum {
	/** 
	 * @internal Log a message as a debug message.
	 */
	EXT_DNS_LEVEL_DEBUG    = 1 << 0,
	/** 
	 * @internal Log a warning message.
	 */
	EXT_DNS_LEVEL_WARNING  = 1 << 1,
	/** 
	 * @internal Log a critical message.
	 */
	EXT_DNS_LEVEL_CRITICAL = 1 << 2,
} extDnsDebugLevel;


/** 
 * @brief A server context where all DNS sever state is stored.
 */
typedef struct _extDnsCtx extDnsCtx;


#endif /* __EXT_DNS_TYPES_H__ */
