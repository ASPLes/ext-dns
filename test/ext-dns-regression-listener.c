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

#include <ext-dns.h>

#ifdef AXL_OS_UNIX
#include <signal.h>
#endif

/* server we rely request to */
const char * server = "8.8.8.8";
int          server_port = 53;

typedef struct _HandleReplyData {
	int             id;
	char          * source_address;
	int             source_port;
	extDnsSession * master_listener;
} HandleReplyData;

void handle_reply_data_free (HandleReplyData * data)
{
	axl_free (data->source_address);
	axl_free (data);
	return;
}

void handle_reply (extDnsCtx     * ctx,
		   extDnsSession * session,
		   const char    * source_address,
		   int             source_port,
		   extDnsMessage * message,
		   axlPointer      data)
{
	char              buffer[512];
	int               bytes_written;
	HandleReplyData * reply_data = data;

	if (message->answers) {
		printf ("REPLY: received reply from %s:%d, values: %s %d %d %s\n", 
			server, server_port,
			message->answers[0].name, message->answers[0].type, message->answers[0].class, message->answers[0].name_content); 
	} else {
		printf ("REPLY: received reply from %s:%d\n", server, server_port);
	}

	/* ok, rewrite reply id to match the one sent by the client */
	message->header->id = reply_data->id;

	/* get the reply into a buffer */
	bytes_written = ext_dns_message_to_buffer (ctx, message, buffer, 512);
	if (bytes_written == -1) {
		handle_reply_data_free (reply_data);

		printf ("ERROR: failed to build buffer representation for reply received..\n");
		return;
	}
	printf ("REPLY: build buffer reply in %d bytes\n", bytes_written);

	/* relay reply to the regression client */
	if (ext_dns_session_send_udp_s (ctx, reply_data->master_listener, buffer, bytes_written, reply_data->source_address, reply_data->source_port) != bytes_written) 
		printf ("ERROR: failed to SEND UDP entire reply, expected to write %d bytes but something different was written\n", bytes_written);
	else {
		printf ("INFO: reply sent!\n");

		/* store reply in the cache */
		ext_dns_cache_store (ctx, message);
	}
	

	/* release data */
	handle_reply_data_free (reply_data);
	return;
}

void on_received  (extDnsCtx     * ctx,
		   extDnsSession * session,
		   const char    * source_address,
		   int             source_port,
		   extDnsMessage * message,
		   axlPointer      _data)
{
	axl_bool          result;
	HandleReplyData * data;
	extDnsMessage   * reply;
	char              buffer[512];
	int               bytes_written;

	/* skip messages that are queries */
	if (! ext_dns_message_is_query (message)) {
		printf ("ERROR: received a query message, dropping DNS message..\n");
		return;
	} /* end if */

	printf ("INFO: received message from %s:%d, query type: %s %s %s..\n", 
		source_address, source_port, 
		ext_dns_message_get_qtype_to_str (ctx, message->questions[0].qtype),
		ext_dns_message_get_qclass_to_str (ctx, message->questions[0].qclass),
		message->questions[0].qname);

	/* check for rejections, unknowns or rewrites */
	if (axl_cmp (message->questions[0].qname, "reject.aspl.es") ||
	    axl_cmp (message->questions[0].qname, "rewrite-request.google.com") ||
	    axl_cmp (message->questions[0].qname, "rewrite.asplhosting.com") ||
	    axl_cmp (message->questions[0].qname, "trigger-unknown.aspl.es")) {

		/* build reply */
		if (axl_cmp (message->questions[0].qname, "reject.aspl.es"))
			reply = ext_dns_message_build_reject_reply (ctx, message);
		else if (axl_cmp (message->questions[0].qname, "rewrite-request.google.com"))
			reply = ext_dns_message_build_ipv4_reply (ctx, message, "17.17.17.17", 2000);
		else if (axl_cmp (message->questions[0].qname, "rewrite.asplhosting.com"))
			reply = ext_dns_message_build_cname_reply (ctx, message, "www.aspl.es", 2000);
		else {
			/* trigger case */
			reply = ext_dns_message_build_unknown_reply (ctx, message);
		}
		if (reply == NULL) {
			printf ("ERROR: failed to build message reply, unable to reply to resolver..\n");
			return;
		}

		/* store reply in the cache */
		ext_dns_cache_store (ctx, reply);

		/* build buffer reply */
		bytes_written = ext_dns_message_to_buffer (ctx, reply, buffer, 512);
		if (bytes_written <= 0) {
			printf ("ERROR: failed to dump message into the buffer, unable to reply to resolver..\n");
			return;
		}

		/* update the Id in the buffer to match the incomming
		 * message (to ensure even a cached response) will
		 * have the right Id value in the reply  */
		ext_dns_message_write_header_id (message, buffer);

		printf ("INFO: buffer build from message was: %d bytes\n", bytes_written);

		/* send reply */
		if (ext_dns_session_send_udp_s (ctx, session, buffer, bytes_written, source_address, source_port) != bytes_written) {
			/* release reply */
			ext_dns_message_unref (reply);

			printf ("ERROR: failed to send %d bytes as reply, different amount of bytes where written\n", bytes_written);
			return;
		} /* end if */

		/* release reply */
		ext_dns_message_unref (reply);

		return;
	}
		

	/* build state data */
	data                   = axl_new (HandleReplyData, 1);
	data->id               = message->header->id;
	data->source_address   = axl_strdup (source_address);
	data->source_port      = source_port;
	data->master_listener  = session;
	
	/* send query */
	result = ext_dns_message_query_from_msg (ctx, message, server, server_port, handle_reply, data);

	if (! result) 
		printf ("ERROR: failed to send query to master server..\n");

	return;
}

void     on_bad_request (extDnsCtx     * ctx,
			 extDnsSession * session,
			 const char    * source_address,
			 int             source_port,
			 const char    * buffer,
			 int             buffer_size,
			 const char    * reason,
			 axlPointer      data)
{
	printf ("BAD REQUEST from %s:%d, reason: %s\n", source_address, source_port, reason);
	ext_dns_ctx_black_list (ctx, source_address, axl_false, 3);

	return;
}

#ifdef AXL_OS_UNIX
void __block_test (int value) 
{
	extDnsAsyncQueue * queue;

	printf ("******\n");
	printf ("****** Received a signal (the regression test is failing): pid %d..locking..!!!\n", ext_dns_getpid ());
	printf ("******\n");

	/* block the caller */
	queue = ext_dns_async_queue_new ();
	ext_dns_async_queue_pop (queue);

	return;
}
#endif

extDnsMutex doing_exit_mutex;
axl_bool    __doing_exit = axl_false;

extDnsCtx     * ctx = NULL;

void __terminate_ext_dns_listener (int value)
{
	
	ext_dns_mutex_lock (&doing_exit_mutex);
	if (__doing_exit) {
		ext_dns_mutex_unlock (&doing_exit_mutex);

		return;
	}
	/* printf ("Terminating ext_dns regression listener..\n");*/
	__doing_exit = axl_true;
	ext_dns_mutex_unlock (&doing_exit_mutex);

	/* unlocking listener */
	/* printf ("Calling to unlock listener due to signal received: extDnsCtx %p", ctx); */
	ext_dns_ctx_unlock (ctx);

	return;
}

int main (int argc, char ** argv) {
	extDnsSession * listener;

	/* install default handling to get notification about
	 * segmentation faults */
#ifdef AXL_OS_UNIX
	signal (SIGSEGV, __block_test);
	signal (SIGABRT, __block_test);
	signal (SIGTERM,  __terminate_ext_dns_listener);
#endif
	
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

	/* init cache */
	ext_dns_cache_init (ctx, 1000);

	/* init a listener */
	listener = ext_dns_listener_new (ctx, "0.0.0.0", "53", extDnsUdpSession, NULL, NULL);
	if (! ext_dns_session_is_ok (listener, axl_false)) {
		printf ("ERROR: failed to start serving requests..\n");
		exit (-1);
	} /* end if */

	/* configure on received handler */
	ext_dns_session_set_on_message (listener, on_received, NULL);
	ext_dns_session_set_on_badrequest (listener, on_bad_request, NULL);

	/* wait and process requests */
	ext_dns_ctx_wait (ctx);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);
	
	
	return 0;
}
