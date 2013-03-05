/* 
 *  ext-dnsd: another, but configurable, DNS server
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

#ifndef __EXT_DNSD_H__
#define __EXT_DNSD_H__

/* import gnu source declarations */
#define _GNU_SOURCE

#include <ext-dns.h>

#include <syslog.h>

#ifdef AXL_OS_UNIX
#include <signal.h>
#endif

#include <axl.h>
#include <exarg.h>
#include <sys/wait.h>

typedef struct _childState {
	/* read fds[0], write fds[1] */
	int fds[2];

	/* current child state */
	axl_bool       ready;
	extDnsMutex    mutex;

	/* last command sent */
	char         * last_command;

	int            pid;
	/* when was acquired this child */
	int            stamp;
} childState;

/** common functions **/
void ext_dnsd_forward_request (extDnsCtx     * ctx, 
			       extDnsMessage * message, 
			       extDnsSession * session,
			       const char    * source_address,
			       int             source_port,
			       axl_bool        nocache);

void ext_dnsd_handle_child_cmd (extDnsCtx     * ctx, 
				extDnsMessage * message, 
				extDnsSession * session, 
				childState    * child, 
				const char    * source_address,
				int             source_port,
				const char    * command);

void ext_dnsd_send_request_reply (extDnsCtx     * ctx, 
				  extDnsSession * session, 
				  const char    * source_address, 
				  int             source_port, 
				  extDnsMessage * reply,
				  axl_bool        nocache);
#endif
