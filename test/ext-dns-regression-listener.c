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
	ext_dns_session_send_udp_reply (ctx, session, buf, bytes_read, source_address, source_port);

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
