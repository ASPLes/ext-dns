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

#include <ext-dns.h>

void on_received  (extDnsCtx     * ctx,
		   extDnsSession * session,
		   const char    * source_address,
		   int             source_port,
		   extDnsMessage * message,
		   axlPointer      data)
{
	int bytes_read;
	char buf[1024];

	printf ("INFO: received message from %s:%d..\n", source_address, source_port);
	
	/* build reply and send reply */
	bytes_read = ext_dns_message_build_reply (ctx, message, buf, 3600, "192.168.0.23");

	/* reply to the UDP resolver */
	ext_dns_session_send_udp_s (ctx, session, buf, bytes_read, source_address, source_port);

	return;
}

int main (int argc, char ** argv) {
	extDnsCtx     * ctx;
	extDnsSession * listener;
	
	/* create context object */
	ctx = ext_dns_ctx_new ();
	if (ctx == NULL) {
		printf ("ERROR: failed to allocate ctx object..\n");
		exit (-1);
	}

	/* init context */
	if (! ext_dns_init_ctx (ctx)) {
		printf ("ERROR: failed to initiatialize ext-dns server context..\n");
		exit (-1);
	}

	/* init a listener */
	listener = ext_dns_listener_new (ctx, "0.0.0.0", "53", extDnsUdpSession, NULL, NULL);
	if (! ext_dns_session_is_ok (listener, axl_false)) {
		printf ("ERROR: failed to start serving requests..\n");
		exit (-1);
	} /* end if */

	/* configure on received handler */
	ext_dns_session_set_on_message (listener, on_received, NULL);

	/* wait and process requests */
	ext_dns_ctx_wait (ctx);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);
	
	
	return 0;
}
