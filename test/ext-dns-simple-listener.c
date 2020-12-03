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
#include <ext-dns.h>

extDnsCtx * ctx;

/*! [On received handler] */
/* For more details about this handler, see extDnsOnMessageReceived */
void on_received  (extDnsCtx     * ctx,
		   /* this is listener where we have received the request */
		   extDnsSession * session,
		   /* this is the remote peer address */
		   const char    * source_address,
		   /* this is the remote port address */
		   int             source_port,
		   /* this is the actual dns message received */
		   extDnsMessage * message,
		   /* your user defined pointer configured at the time this handler was setup */
		   axlPointer      _data)
{
	extDnsMessage   * reply = NULL;

	/* skip messages that are queries */
	if (! ext_dns_message_is_query (message)) {
		printf ("ERROR: received a query message, dropping DNS message..\n");
		return;
	} /* end if */

	/* ok, let's suppose we want to discard all requests comming from certain ip: then just return */
	if (axl_cmp (source_address, "192.168.1.100"))
		return; /* you don't have to release anything */

	printf ("INFO: received a request for name %s (%d)\n", 
		ext_dns_message_query_name (ctx, message), message->header->answer_count);

	/* now let's support we have to rewrite a request from
	   www.evilcompany.com to www.anotherevilcompany.com and in
	   the process provide the IP */
	if (axl_cmp (ext_dns_message_query_name (ctx, message), "www.evilcompany.com")) {
		/* build a forged reply */
		reply = ext_dns_message_build_cname_reply (ctx, message, "www.anotherevilcompany.com", 3600);
		/* now add an additional answer to also set the IP of that site */
		ext_dns_message_add_answer (ctx, reply, extDnsTypeA, extDnsClassIN, "www.anotherevilcompany.com", 3600, "192.168.0.20");
	} /* end if */
		
	/* process reply (if defined) */
	if (reply) {
		/* send reply */
		ext_dns_message_send_udp_s (ctx, session, reply, source_address, source_port);
		/* release reply reference */
		ext_dns_message_unref (reply);
	} /* end if */

	return;
}
/*! [On received handler] */

int main (int argc, char ** argv) {
	extDnsSession * listener;

	/*! [Init ctx]  */
	/* create empty context */
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
	/*! [Init ctx]  */

	/*! [Starting a listener] */
	/* start a listener running on local 53 UDP port */
	listener = ext_dns_listener_new (ctx, "0.0.0.0", "53", extDnsUdpSession, NULL, NULL);
	if (! ext_dns_session_is_ok (listener, axl_false)) {
		printf ("ERROR: failed to start serving requests..\n");
		exit (-1);
	} /* end if */
	/*! [Starting a listener] */

	/*! [Setting on received handler] */
	ext_dns_session_set_on_message (listener, on_received, NULL);
	/*! [Setting on received handler] */

	/*! [Wait and finish] */
	/* block and process all incoming requests */
	ext_dns_ctx_wait (ctx);

	/* terminate context and release all resources (unless application acquired additional references) */
	ext_dns_exit_ctx (ctx, axl_true);
	/*! [Wait and finish] */

	return 0;
}
