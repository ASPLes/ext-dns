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

/* local/private includes */
#include <ext-dns-private.h>

#define LOG_DOMAIN "ext-dns-reader"

/**
 * \defgroup ext_dns_reader extDns Reader: The module that reads you frames. 
 */

/**
 * \addtogroup ext_dns_reader
 * @{
 */

typedef enum {SESSION, 
	      LISTENER, 
	      TERMINATE, 
	      IO_WAIT_CHANGED,
	      IO_WAIT_READY,
	      FOREACH
} WatchType;

typedef struct _extDnsReaderData {
	WatchType            type;
	extDnsSession      * session;
	extDnsForeachFunc    func;
	axlPointer           user_data;
	/* queue used to notify that the foreach operation was
	 * finished: currently only used for type == FOREACH */
	extDnsAsyncQueue   * notify;
} extDnsReaderData;

typedef struct _extDnsOnMessageReceivedData {
	char          * source_address;
	int             source_port;
	extDnsMessage * message;
	extDnsSession * session;
	extDnsCtx     * ctx;
} extDnsOnMessageReceivedData;

axl_bool __ext_dns_reader_consume_signal (extDnsCtx * ctx)
{
	char bytes[2];	
	return recv (ctx->reader_pipe[0], bytes, 1, MSG_DONTWAIT) > 0;
}

axl_bool ext_dns_reader_was_awaken (extDnsCtx * ctx)
{

	if (ext_dns_io_waiting_invoke_is_set_fd_group (ctx, ctx->reader_pipe[0], ctx->on_reading, NULL)) {
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "FOUND SIGNAL AT INTERNAL PIPE, READER IS TIME TO WORK..");
		__ext_dns_reader_consume_signal (ctx);
		return axl_true;
	}
	return axl_false;
}

void ext_dns_reader_awake (extDnsCtx * ctx)
{
	if (send (ctx->reader_pipe[1], "w", 1, 0) != 1)
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Failed to send awaken notification, error was errno=%d", errno);
	return;
}

axlPointer __ext_dns_reader_on_message_received (extDnsOnMessageReceivedData * data)
{
	char          * source_address = data->source_address;
	int             source_port    = data->source_port;
	extDnsMessage * message        = data->message;
	extDnsSession * session        = data->session;
	extDnsCtx     * ctx            = data->ctx;	
	
	/* handler */
	extDnsOnMessageReceived on_received;
	axlPointer              _data;

	/* release data pointer received */
	axl_free (data);

	/* call handler defined on session */
	on_received = session->on_message;
	_data       = session->on_message_data;

	if (on_received == NULL) {
		on_received = ctx->on_message;
		_data       = ctx->on_message_data;
	}

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Received DNS message on session id %d", session->id);

	/* check expected header */
	if (session->expected_header) {
		
		/* do some additional checkings */
		if (session->expected_header->id != message->header->id) {
			ext_dns_log (EXT_DNS_LEVEL_WARNING, "Expected to receive id %d, but found %d, discarding reply",
				     session->expected_header->id, message->header->id);
			on_received = NULL;
		}
	}

	/* call to notify handler */
	if (on_received) {
		on_received (ctx, session, source_address, source_port, message, _data);
	} /* end if */

	/* release source address */
	axl_free (source_address);

	/* check to close session */
	if (session->expected_header) {
		/* release and clear reference */
		axl_free (session->expected_header);
		session->expected_header = NULL;
	} /* end if */

	/* close the listener if indicated so */
	if (session->close_on_reply)  
		ext_dns_session_close (session);

	/* call to release message */
	ext_dns_message_unref (message);
	return NULL;
}

/** 
 * @internal
 * 
 * The main purpose of this function is to dispatch received frames
 * into the appropriate channel. It also makes all checks to ensure the
 * frame receive have all indicators (seqno, channel, message number,
 * payload size correctness,..) to ensure the channel receive correct
 * frames and filter those ones which have something wrong.
 *
 * This function also manage frame fragment joining. There are two
 * levels of frame fragment managed by the ext_dns reader.
 * 
 * We call the first level of fragment, the one described at RFC3080,
 * as the complete frame which belongs to a group of frames which
 * conform a message which was splitted due to channel window size
 * restrictions.
 *
 * The second level of fragment happens when the ext_dns reader receive
 * a frame header which describes a frame size payload to receive but
 * not all payload was actually received. This can happen because
 * ext_dns uses non-blocking socket configuration so it can avoid DOS
 * attack. But this behavior introduce the asynchronous problem of
 * reading at the moment where the whole frame was not received.  We
 * call to this internal frame fragmentation. It is also supported
 * without blocking to ext_dns reader.
 *
 * While reading this function, you have to think about it as a
 * function which is executed for only one frame, received inside only
 * one channel for the given connection.
 *
 * @param connection the connection which have something to be read
 * 
 **/
void __ext_dns_reader_process_socket (extDnsCtx     * ctx, 
				      extDnsSession * session)
{

	char            buf[1024];
	struct sockaddr_in remote_addr;
	socklen_t       sin_size;
	int             bytes_read;

	char          * source_address;
	int             source_port;

	extDnsHeader  * header;
	extDnsMessage * message;

	/* pointer to data received */
	extDnsOnMessageReceivedData * data;

	if (session == NULL) {
		/* consume reader signal  and skip */
		if (__ext_dns_reader_consume_signal (ctx)) 
			return;

		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Received NULL session reference (reader pipe?)");
		return;
	} /* end if */

	/* read content from socket */
	sin_size        = sizeof (remote_addr);
	bytes_read      = recvfrom (session->session, buf, 1023, MSG_DONTWAIT, (struct sockaddr *) &remote_addr, &sin_size);
	buf[bytes_read] = 0;

	/* get source and port address */
	source_address = ext_dns_support_inet_ntoa (ctx, &remote_addr);
	source_port    = ntohs (remote_addr.sin_port);

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Received DNS message over session id=%d (size: %d), from: %s:%d", 
		     ext_dns_session_get_id (session), bytes_read, source_address, source_port);

	/* check here message size to limit incoming queries */
	if (bytes_read > 512) {
		/* check to close session for thise reply */
		if (session->close_on_reply)  
			ext_dns_session_close (session);

		axl_free (source_address);
		ext_dns_log (EXT_DNS_LEVEL_WARNING, "Received a DNS message that is bigger than allowed values (%d > 512)",
			     bytes_read);
		return;
	} /* end if */

	/* get the header */
	header = ext_dns_message_parse_header (ctx, buf, bytes_read);

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Received header id: %u, is query: %d, opcode: %d, AA: %d, TC: %d, RD: %d, RA: %d", 
		     header->id, header->is_query, header->opcode, header->is_authorative_answer, header->was_truncated, 
		     header->recursion_desired, header->recursion_available);
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "             rcode: %d, qcount: %d, ancount: %d, nscount: %d, arcount: %d", 
		     header->rcode, header->query_count, header->answer_count,
		     header->authority_count, header->additional_count);
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "             message size (inc. head): %d", bytes_read);

	/* now parse rest of the message */
	message = ext_dns_message_parse_message (ctx, header, buf, bytes_read);

	if (message == NULL) {
		ext_dns_log (EXT_DNS_LEVEL_WARNING, "Parse error for incoming message from %s:%d, skipping userlevel notification", source_address, source_port);
		axl_free (source_address);

		/* check to close session for thise reply */
		if (session->close_on_reply)  
			ext_dns_session_close (session);

		return;
	}

	/* queue message to be handled in other part */
	if (! session->on_message && ! ctx->on_message) {
		if (session->close_on_reply)  
			ext_dns_session_close (session);

		ext_dns_log (EXT_DNS_LEVEL_WARNING, "Received a DNS message but no on message handler was found configured, dropping DNS message");

		/* release the message */
		ext_dns_message_unref (message);
		return;
	}

	/* build on data */
	data = axl_new (extDnsOnMessageReceivedData, 1);
	if (data == NULL) {
		if (session->close_on_reply)  
			ext_dns_session_close (session);

		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Failed to allocate memory, unable to process message received");
		return;
	} /* end if */

	/* set values */
	data->message        = message;
	data->ctx            = ctx;
	data->session        = session;
	data->source_port    = source_port;
	data->source_address = source_address;

	/* call to invoke dns on message */
	ext_dns_thread_pool_new_task (ctx, (extDnsThreadFunc) __ext_dns_reader_on_message_received, data);

	return;
}

/** 
 * @internal 
 *
 * @brief Classify ext_dns reader items to be managed, that is,
 * connections or listeners.
 * 
 * @param data The internal ext_dns reader data to be managed.
 * 
 * @return axl_true if the item to be managed was clearly read or axl_false if
 * an error on registering the item was produced.
 */
axl_bool   ext_dns_reader_register_watch (extDnsReaderData * data, axlList * con_list, axlList * srv_list)
{
	extDnsSession * session;
	extDnsCtx     * ctx;

	/* get a reference to the session (no matter if it is not
	 * defined) */
	session = data->session;
	ctx        = ext_dns_session_get_ctx (session);

	switch (data->type) {
	case SESSION:
		/* check the session */
		if (!ext_dns_session_is_ok (session, axl_false)) {
			/* check if we can free this session */
			ext_dns_session_unref (session, "ext_dns reader (watch)");
			ext_dns_log (EXT_DNS_LEVEL_DEBUG, "received a non-valid session, ignoring it");

			/* release data */
			axl_free (data);
			return axl_false;
		}
			
		/* now we have a first session, we can start to wait */
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "new session (conn-id=%d) to be watched (%d)", 
			    ext_dns_session_get_id (session), ext_dns_session_get_socket (session));
		axl_list_append (con_list, session);

		break;
	case LISTENER:
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "new listener session to be watched (%d --> %s:%s)",
			    ext_dns_session_get_socket (session), 
			    ext_dns_session_get_host (session), 
			    ext_dns_session_get_port (session));
		axl_list_append (srv_list, session);

		break;
	case TERMINATE:
	case IO_WAIT_CHANGED:
	case IO_WAIT_READY:
	case FOREACH:
		/* just unref ext_dns reader data */
		break;
	} /* end switch */
	
	axl_free (data);
	return axl_true;
}

/** 
 * @internal extDns function to implement ext_dns reader I/O change.
 */
extDnsReaderData * __ext_dns_reader_change_io_mech (extDnsCtx        * ctx,
						   axlPointer       * on_reading, 
						   axlList          * con_list, 
						   axlList          * srv_list, 
						   extDnsReaderData * data)
{
	/* get current context */
	extDnsReaderData * result;

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "found I/O notification change");
	
	/* unref IO waiting object */
	ext_dns_io_waiting_invoke_destroy_fd_group (ctx, *on_reading); 
	*on_reading = NULL;
	
	/* notify preparation done and lock until new
	 * I/O is installed */
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "notify ext_dns reader preparation done");
	ext_dns_async_queue_push (ctx->reader_stopped, INT_TO_PTR(1));
	
	/* free data use the function that includes that knoledge */
	ext_dns_reader_register_watch (data, con_list, srv_list);
	
	/* lock */
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "lock until new API is installed");
	result = ext_dns_async_queue_pop (ctx->reader_queue);

	/* initialize the read set */
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "unlocked, creating new I/O mechanism used current API");
	*on_reading = ext_dns_io_waiting_invoke_create_fd_group (ctx, READ_OPERATIONS);

	return result;
}


/* do a foreach operation */
void ext_dns_reader_foreach_impl (extDnsCtx        * ctx, 
				 axlList          * con_list, 
				 axlList          * srv_list, 
				 extDnsReaderData * data)
{
	axlListCursor * cursor;

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "doing ext_dns reader foreach notification..");

	/* check for null function */
	if (data->func == NULL) 
		goto foreach_impl_notify;

	/* foreach the session list */
	cursor = axl_list_cursor_new (con_list);
	while (axl_list_cursor_has_item (cursor)) {

		/* notify, if the session is ok */
		if (ext_dns_session_is_ok (axl_list_cursor_get (cursor), axl_false)) {
			data->func (axl_list_cursor_get (cursor), data->user_data);
		} /* end if */

		/* next cursor */
		axl_list_cursor_next (cursor);
	} /* end while */
	
	/* free cursor */
	axl_list_cursor_free (cursor);

	/* foreach the session list */
	cursor = axl_list_cursor_new (srv_list);
	while (axl_list_cursor_has_item (cursor)) {
		/* notify, if the session is ok */
		if (ext_dns_session_is_ok (axl_list_cursor_get (cursor), axl_false)) {
			data->func (axl_list_cursor_get (cursor), data->user_data);
		} /* end if */

		/* next cursor */
		axl_list_cursor_next (cursor);
	} /* end while */

	/* free cursor */
	axl_list_cursor_free (cursor);

	/* notify that the foreach operation was completed */
 foreach_impl_notify:
	ext_dns_async_queue_push (data->notify, INT_TO_PTR (1));

	return;
}

/** 
 * @internal
 * @brief Read the next item on the ext_dns reader to be processed
 * 
 * Once an item is read, it is check if something went wrong, in such
 * case the loop keeps on going.
 * 
 * The function also checks for terminating ext_dns reader loop by
 * looking for TERMINATE value into the data->type. In such case axl_false
 * is returned meaning that no further loop should be done by the
 * ext_dns reader.
 *
 * @return axl_true to keep ext_dns reader working, axl_false if ext_dns reader
 * should stop.
 */
axl_bool      ext_dns_reader_read_queue (extDnsCtx  * ctx,
					axlList    * con_list, 
					axlList    * srv_list, 
					axlPointer * on_reading)
{
	/* get current context */
	extDnsReaderData * data;
	int                should_continue;

	do {
		data            = ext_dns_async_queue_pop (ctx->reader_queue);

		/* check if we have to continue working */
		should_continue = (data->type != TERMINATE);

		/* check if the io/wait mech have changed */
		if (data->type == IO_WAIT_CHANGED) {
			/* change io mechanism */
			data = __ext_dns_reader_change_io_mech (ctx,
							       on_reading, 
							       con_list, 
							       srv_list, 
							       data);
		} else if (data->type == FOREACH) {
			/* do a foreach operation */
			ext_dns_reader_foreach_impl (ctx, con_list, srv_list, data);

		} /* end if */

	}while (!ext_dns_reader_register_watch (data, con_list, srv_list));

	return should_continue;
}

/** 
 * @internal Function used by the ext_dns reader main loop to check for
 * more sessions to watch, to check if it has to terminate or to
 * check at run time the I/O waiting mechanism used.
 * 
 * @param con_list The set of sessions already watched.
 *
 * @param srv_list The set of listener sessions already watched.
 *
 * @param on_reading A reference to the I/O waiting object, in the
 * case the I/O waiting mechanism is changed.
 * 
 * @return axl_true to flag the process to continue working to to stop.
 */
axl_bool      ext_dns_reader_read_pending (extDnsCtx  * ctx,
					  axlList    * con_list, 
					  axlList    * srv_list, 
					  axlPointer * on_reading)
{
	/* get current context */
	extDnsReaderData * data;
	int                length;
	axl_bool           should_continue = axl_true;

	length = ext_dns_async_queue_length (ctx->reader_queue);
	while (length > 0) {
		length--;
		data            = ext_dns_async_queue_pop (ctx->reader_queue);

		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "read pending type=%d",
			    data->type);

		/* check if we have to continue working */
		should_continue = (data->type != TERMINATE);

		/* check if the io/wait mech have changed */
		if (data->type == IO_WAIT_CHANGED) {
			/* change io mechanism */
			data = __ext_dns_reader_change_io_mech (ctx, on_reading, con_list, srv_list, data);

		} else if (data->type == FOREACH) {
			/* do a foreach operation */
			ext_dns_reader_foreach_impl (ctx, con_list, srv_list, data);

		} /* end if */

		/* watch the request received, maybe a session or a
		 * ext_dns reader command to process  */
		ext_dns_reader_register_watch (data, con_list, srv_list);
		
	} /* end while */

	return should_continue;
}

/** 
 * @internal Auxiliar function that populates the reading set of file
 * descriptors (on_reading), returning the max fds.
 */
EXT_DNS_SOCKET __ext_dns_reader_build_set_to_watch_aux (extDnsCtx     * ctx,
						      axlPointer      on_reading, 
						      axlListCursor * cursor, 
						      EXT_DNS_SOCKET   current_max)
{
	EXT_DNS_SOCKET     max_fds     = current_max;
	EXT_DNS_SOCKET     fds         = 0;
	extDnsSession    * session;

	axl_list_cursor_first (cursor);
	while (axl_list_cursor_has_item (cursor)) {

		/* get current session */
		session = axl_list_cursor_get (cursor);

		/* check ok status */
		if (! ext_dns_session_is_ok (session, axl_false)) {

			/* FIRST: remove current cursor to ensure the
			 * session is out of our handling before
			 * finishing the reference the reader owns */
			axl_list_cursor_unlink (cursor);

			/* session isn't ok, unref it */
			ext_dns_session_unref (session, "ext_dns reader (build set)");

			continue;
		} /* end if */

		/* get the socket to ge added and get its maximum
		 * value */
		fds        = ext_dns_session_get_socket (session);
		max_fds    = fds > max_fds ? fds: max_fds;

		/* add the socket descriptor into the given on reading
		 * group */
		if (! ext_dns_io_waiting_invoke_add_to_fd_group (ctx, fds, session, on_reading)) {
			
			ext_dns_log (EXT_DNS_LEVEL_WARNING, 
				    "unable to add the session to the ext_dns reader watching set. This could mean you did reach the I/O waiting mechanism limit.");

			/* FIRST: remove current cursor to ensure the
			 * session is out of our handling before
			 * finishing the reference the reader owns */
			axl_list_cursor_unlink (cursor);

			/* set it as not connected */
			if (ext_dns_session_is_ok (session, axl_false))
				__ext_dns_session_shutdown_and_record_error (session, extDnsError, "ext_dns reader (add fail)");
			ext_dns_session_unref (session, "ext_dns reader (add fail)");

			continue;
		} /* end if */

		/* get the next */
		axl_list_cursor_next (cursor);

	} /* end while */

	/* return maximum number for file descriptors */
	return max_fds;
	
} /* end __ext_dns_reader_build_set_to_watch_aux */

EXT_DNS_SOCKET   __ext_dns_reader_build_set_to_watch (extDnsCtx     * ctx,
						      axlPointer      on_reading, 
						      axlListCursor * con_cursor, 
						      axlListCursor * srv_cursor)
{

	EXT_DNS_SOCKET       max_fds     = 0;

	/* add the pipe */
	if (! ext_dns_io_waiting_invoke_add_to_fd_group (ctx, ctx->reader_pipe[0], NULL, on_reading)) 
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Failed to add reader pipe to watching set");

	/* read server sessions */
	max_fds = __ext_dns_reader_build_set_to_watch_aux (ctx, on_reading, srv_cursor, max_fds);

	/* read client session list */
	max_fds = __ext_dns_reader_build_set_to_watch_aux (ctx, on_reading, con_cursor, max_fds);

	/* return maximum number for file descriptors */
	return max_fds;
	
}

void __ext_dns_reader_check_session_list (extDnsCtx     * ctx,
					  axlPointer      on_reading, 
					  axlListCursor * con_cursor, 
					  int             changed)
{

	EXT_DNS_SOCKET       fds        = 0;
	extDnsSession  * session = NULL;
	int                 checked    = 0;

	/* check all sessions */
	axl_list_cursor_first (con_cursor);
	while (axl_list_cursor_has_item (con_cursor)) {

		/* check changed */
		if (changed == checked)
			return;

		/* check if we have to keep on listening on this
		 * session */
		session = axl_list_cursor_get (con_cursor);
		if (!ext_dns_session_is_ok (session, axl_false)) {
			/* FIRST: remove current cursor to ensure the
			 * session is out of our handling before
			 * finishing the reference the reader owns */
			axl_list_cursor_unlink (con_cursor);

			/* session isn't ok, unref it */
			ext_dns_session_unref (session, "ext_dns reader (check list)");
			continue;
		}
		
		/* get the session and socket. */
	        fds = ext_dns_session_get_socket (session);
		
		/* ask if this socket have changed */
		if (ext_dns_io_waiting_invoke_is_set_fd_group (ctx, fds, on_reading, ctx)) {

			/* call to process incoming data, activating
			 * all invocation code (first and second level
			 * handler) */
			__ext_dns_reader_process_socket (ctx, session);

			/* update number of sockets checked */
			checked++;
		}

		/* get the next */
		axl_list_cursor_next (con_cursor);

	} /* end for */

	return;
}

int  __ext_dns_reader_check_listener_list (extDnsCtx     * ctx, 
					  axlPointer      on_reading, 
					  axlListCursor * srv_cursor, 
					  int             changed)
{

	int                fds      = 0;
	int                checked  = 0;
	extDnsSession * session;

	/* check all listeners */
	axl_list_cursor_first (srv_cursor);
	while (axl_list_cursor_has_item (srv_cursor)) {

		/* get the session */
		session = axl_list_cursor_get (srv_cursor);

		if (!ext_dns_session_is_ok (session, axl_false)) {
			ext_dns_log (EXT_DNS_LEVEL_DEBUG, "ext_dns reader found listener id=%d not operational, unreference",
				    ext_dns_session_get_id (session));

			/* FIRST: remove current cursor to ensure the
			 * session is out of our handling before
			 * finishing the reference the reader owns */
			axl_list_cursor_unlink (srv_cursor);

			/* session isn't ok, unref it */
			ext_dns_session_unref (session, "ext_dns reader (process), listener closed");

			/* update checked sessions */
			checked++;

			continue;
		} /* end if */
		
		/* get the session and socket. */
		fds  = ext_dns_session_get_socket (session);
		
		/* check if the socket is activated */
		if (ext_dns_io_waiting_invoke_is_set_fd_group (ctx, fds, on_reading, ctx)) {
			/* init the listener incoming session phase */
			ext_dns_log (EXT_DNS_LEVEL_DEBUG, "listener (%d) have requests, processing..", fds);
			/* ext_dns_listener_accept_sessions (ctx, fds, session); */

			/* update checked sessions */
			checked++;
		} /* end if */

		/* check to stop listener */
		if (checked == changed)
			return 0;

		/* get the next */
		axl_list_cursor_next (srv_cursor);
	}
	
	/* return remaining sockets active */
	return changed - checked;
}

/** 
 * @internal
 *
 * @brief Internal function called to stop ext_dns reader and cleanup
 * memory used.
 * 
 */
void __ext_dns_reader_stop_process (extDnsCtx     * ctx,
				   axlPointer      on_reading, 
				   axlListCursor * con_cursor, 
				   axlListCursor * srv_cursor)

{
	/* stop ext_dns reader process unreferring already managed
	 * sessions */

	ext_dns_async_queue_unref (ctx->reader_queue);

	/* unref listener sessions */
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "cleaning pending %d listener sessions..", axl_list_length (ctx->srv_list));
	ctx->srv_list = NULL;
	axl_list_free (axl_list_cursor_list (srv_cursor));
	axl_list_cursor_free (srv_cursor);

	/* unref initiators sessions */
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "cleaning pending %d peer sessions..", axl_list_length (ctx->con_list));
	ctx->con_list = NULL;
	axl_list_free (axl_list_cursor_list (con_cursor));
	axl_list_cursor_free (con_cursor);

	/* unref IO waiting object */
	ext_dns_io_waiting_invoke_destroy_fd_group (ctx, on_reading); 

	/* signal that the ext_dns reader process is stopped */
	ext_dns_async_queue_push (ctx->reader_stopped, INT_TO_PTR (1));

	return;
}

void __ext_dns_reader_close_session (axlPointer pointer)
{
	/* unref the session */
	ext_dns_session_unref ((extDnsSession *) pointer, "ext_dns reader");

	return;
}

/** 
 * @internal Dispatch function used to process all sockets that have
 * changed.
 * 
 * @param fds The socket that have changed.
 * @param wait_to The purpose that was configured for the file set.
 * @param session The session that is notified for changes.
 */
void __ext_dns_reader_dispatch_session (EXT_DNS_SOCKET        fds,
					extDnsIoWaitingFor    wait_to,
					extDnsSession       * session,
					axlPointer            user_data)
{
	/* cast the reference */
	extDnsCtx * ctx = user_data;

	switch (ext_dns_session_get_role (session)) {
	case extDnsRoleListener:
		/* listener sessions */
		/* ext_dns_listener_accept_sessions (ctx, fds, session); */
		break;
	default:
		/* call to process incoming data, activating all
		 * invocation code (first and second level handler) */
		__ext_dns_reader_process_socket (ctx, session);
		break;
	} /* end if */
	return;
}


axlPointer __ext_dns_reader_run (extDnsCtx * ctx)
{
	EXT_DNS_SOCKET      max_fds     = 0;
	EXT_DNS_SOCKET      result;
	int                error_tries = 0;

	/* initialize the read set */
	if (ctx->on_reading != NULL)
		ext_dns_io_waiting_invoke_destroy_fd_group (ctx, ctx->on_reading);
	ctx->on_reading  = ext_dns_io_waiting_invoke_create_fd_group (ctx, READ_OPERATIONS);

	/* create lists */
	ctx->con_list = axl_list_new (axl_list_always_return_1, __ext_dns_reader_close_session);
	ctx->srv_list = axl_list_new (axl_list_always_return_1, __ext_dns_reader_close_session);

	/* create cursors */
	ctx->con_cursor = axl_list_cursor_new (ctx->con_list);
	ctx->srv_cursor = axl_list_cursor_new (ctx->srv_list);

	/* first step. Waiting blocked for our first session to
	 * listen */
 __ext_dns_reader_run_first_session:
	if (!ext_dns_reader_read_queue (ctx, ctx->con_list, ctx->srv_list, &(ctx->on_reading))) {
		/* seems that the ext_dns reader main loop should
		 * stop */
		__ext_dns_reader_stop_process (ctx, ctx->on_reading, ctx->con_cursor, ctx->srv_cursor);
		return NULL;
	}

	while (axl_true) {
		/* reset descriptor set */
		ext_dns_io_waiting_invoke_clear_fd_group (ctx, ctx->on_reading);

		/* build socket descriptor to be read */
		max_fds = __ext_dns_reader_build_set_to_watch (ctx, ctx->on_reading, ctx->con_cursor, ctx->srv_cursor);

		if ((axl_list_length (ctx->con_list) == 0) && (axl_list_length (ctx->srv_list) == 0)) {

			ext_dns_log (EXT_DNS_LEVEL_DEBUG, "no more session to watch for, putting thread to sleep");
			goto __ext_dns_reader_run_first_session;
		}
		
		/* perform IO blocking wait for read operation */
		result = ext_dns_io_waiting_invoke_wait (ctx, ctx->on_reading, max_fds, READ_OPERATIONS);

		/* do automatic thread pool resize here */
		__ext_dns_thread_pool_automatic_resize (ctx);  

		/* check for timeout error */
		if (result == -1 || result == -2)
			goto process_pending;

		/* check errors */
		if ((result < 0) && (errno != 0)) {

			error_tries++;
			if (error_tries == 2) {
				ext_dns_log (EXT_DNS_LEVEL_CRITICAL, 
					    "tries have been reached on reader, error was=(errno=%d): %s exiting..",
					    errno, ext_dns_errno_get_last_error ());
				return NULL;
			} /* end if */
			continue;
		} /* end if */

		/* check for fatal error */
		if (result == -3) {
			ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "fatal error received from io-wait function, exiting from ext_dns reader process..");
			__ext_dns_reader_stop_process (ctx, ctx->on_reading, ctx->con_cursor, ctx->srv_cursor);
			return NULL;
		}


		/* check for each listener */
		if (result > 0) {
			/* check if the mechanism have automatic
			 * dispatch */
			if (ext_dns_io_waiting_invoke_have_dispatch (ctx, ctx->on_reading)) {
				/* perform automatic dispatch,
				 * providing the dispatch function and
				 * the number of sockets changed */
				ext_dns_io_waiting_invoke_dispatch (ctx, ctx->on_reading, __ext_dns_reader_dispatch_session, result, ctx);

			} else {
				/* check for reader awaken */
				if (ext_dns_reader_was_awaken (ctx)) {
					/* reduce the number of changes */
					result--;
				} /* end if */
				    
				/* call to check listener sessions */
				result = __ext_dns_reader_check_listener_list (ctx, ctx->on_reading, ctx->srv_cursor, result);
			
				/* check for each session to be watch is it have check */
				__ext_dns_reader_check_session_list (ctx, ctx->on_reading, ctx->con_cursor, result);
			} /* end if */
		}

		/* we have finished the session dispatching, so
		 * read the pending queue elements to be watched */
		
		/* reset error tries */
	process_pending:
		error_tries = 0;

		/* read new sessions to be managed */
		if (!ext_dns_reader_read_pending (ctx, ctx->con_list, ctx->srv_list, &(ctx->on_reading))) {
			__ext_dns_reader_stop_process (ctx, ctx->on_reading, ctx->con_cursor, ctx->srv_cursor);
			return NULL;
		}
	}
	return NULL;
}

/** 
 * @brief Function that returns the number of sessions that are
 * currently watched by the reader.
 * @param ctx The context where the reader loop is located.
 * @return Number of sessions watched. 
 */
int  ext_dns_reader_sessions_watched         (extDnsCtx        * ctx)
{
	if (ctx == NULL || ctx->con_list == NULL || ctx->srv_list == NULL)
		return 0;
	
	/* return list */
	return axl_list_length (ctx->con_list) + axl_list_length (ctx->srv_list);
}

/** 
 * @internal
 * 
 * Adds a new session to be watched on ext_dns reader process. This
 * function is for internal ext_dns library use.
 **/
void ext_dns_reader_watch_session (extDnsCtx        * ctx,
				     extDnsSession * session)
{
	/* get current context */
	extDnsReaderData * data;

	v_return_if_fail (ext_dns_session_is_ok (session, axl_false));
	v_return_if_fail (ctx->reader_queue);

	if (!ext_dns_session_set_nonblocking_socket (session)) {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "unable to set non-blocking I/O operation, at session registration, closing session");
 		return;
	}

	/* increase reference counting */
	if (! ext_dns_session_ref (session, "ext_dns reader (watch)")) {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "unable to increase session reference count, dropping session");
		return;
	}

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Accepting conn-id=%d into reader queue %p, library status: %d", 
		    ext_dns_session_get_id (session),
		    ctx->reader_queue,
		    ext_dns_is_exiting (ctx));

	/* prepare data to be queued */
	data             = axl_new (extDnsReaderData, 1);
	data->type       = SESSION;
	data->session = session;

	/* push data */
	ext_dns_async_queue_push (ctx->reader_queue, data);

	return;
}

/** 
 * @internal
 *
 * Install a new listener to watch for new incoming sessions.
 **/
void ext_dns_reader_watch_listener   (extDnsCtx        * ctx,
				     extDnsSession * listener)
{
	/* get current context */
	extDnsReaderData * data;
	v_return_if_fail (listener > 0);
	
	/* prepare data to be queued */
	data             = axl_new (extDnsReaderData, 1);
	data->type       = LISTENER;
	data->session = listener;

	/* push data */
	ext_dns_async_queue_push (ctx->reader_queue, data);

	/* awake listener */
	ext_dns_reader_awake (ctx);

	return;
}

axl_bool __ext_dns_event_fd_init_pipe (extDnsCtx * ctx)
{
	struct sockaddr_in      saddr;
	struct sockaddr_in      sin;

	EXT_DNS_SOCKET           listener_fd;
#if defined(AXL_OS_WIN32)
/*	BOOL                    unit      = axl_true; */
	int                     sin_size  = sizeof (sin);
#else    	
	int                     unit      = 1; 
	socklen_t               sin_size  = sizeof (sin);
#endif	  
	int                     bind_res;
	int                     result;

	/* create listener socket */
	if ((listener_fd = socket(AF_INET, SOCK_STREAM, 0)) <= 2) {
		/* do not allow creating sockets reusing stdin (0),
		   stdout (1), stderr (2) */
		ext_dns_log (EXT_DNS_LEVEL_DEBUG,  "failed to create listener socket: %d (errno=%d:%s)", listener_fd, errno, ext_dns_errno_get_error (errno));
		return -1;
        } /* end if */

#if defined(AXL_OS_WIN32)
	/* Do not issue a reuse addr which causes on windows to reuse
	 * the same address:port for the same process. Under linux,
	 * reusing the address means that consecutive process can
	 * reuse the address without being blocked by a wait
	 * state.  */
	/* setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char  *)&unit, sizeof(BOOL)); */
#else
	setsockopt (listener_fd, SOL_SOCKET, SO_REUSEADDR, &unit, sizeof (unit));
#endif 

	memset(&saddr, 0, sizeof(struct sockaddr_in));
	saddr.sin_family          = AF_INET;
	saddr.sin_port            = 0;
	saddr.sin_addr.s_addr     = htonl (INADDR_LOOPBACK);

	/* call to bind */
	bind_res = bind (listener_fd, (struct sockaddr *)&saddr,  sizeof (struct sockaddr_in));
	if (bind_res == EXT_DNS_SOCKET_ERROR) {
		ext_dns_log (EXT_DNS_LEVEL_DEBUG,  "unable to bind address (port already in use or insufficient permissions). Closing socket: %d", listener_fd);
		ext_dns_close_socket (listener_fd);
		return axl_false;
	}
	
	if (listen (listener_fd, 1) == EXT_DNS_SOCKET_ERROR) {
		ext_dns_log (EXT_DNS_LEVEL_DEBUG,  "an error have occur while executing listen");
		ext_dns_close_socket (listener_fd);
		return axl_false;
        } /* end if */

	/* notify listener */
	if (getsockname (listener_fd, (struct sockaddr *) &sin, &sin_size) < -1) {
		ext_dns_log (EXT_DNS_LEVEL_DEBUG,  "an error have happen while executing getsockname");
		ext_dns_close_socket (listener_fd);
		return axl_false;
	} /* end if */

	ext_dns_log  (EXT_DNS_LEVEL_DEBUG, "created listener running listener at %s:%d (socket: %d)", inet_ntoa(sin.sin_addr), ntohs (sin.sin_port), listener_fd);

	/* on now connect: read side */
	ctx->reader_pipe[0]      = socket (AF_INET, SOCK_STREAM, 0);
	if (ctx->reader_pipe[0] == EXT_DNS_INVALID_SOCKET) {
		ext_dns_log (EXT_DNS_LEVEL_DEBUG,   "Unable to create socket required for pipe");
		ext_dns_close_socket (listener_fd);
		return axl_false;
	} /* end if */

	/* disable nagle */
	ext_dns_session_set_sock_tcp_nodelay (ctx->reader_pipe[0], axl_true);

	/* set non blocking connection */
	ext_dns_session_set_sock_block (ctx->reader_pipe[0], axl_false);  

        memset(&saddr, 0, sizeof(saddr));
	saddr.sin_addr.s_addr     = htonl(INADDR_LOOPBACK);
        saddr.sin_family          = AF_INET;
        saddr.sin_port            = sin.sin_port;

	/* connect in non blocking manner */
	result = connect (ctx->reader_pipe[0], (struct sockaddr *)&saddr, sizeof (saddr));
	if (errno != EXT_DNS_EINPROGRESS) {
		ext_dns_log (EXT_DNS_LEVEL_DEBUG,  "connect () returned %d, errno=%d:%s", 
				  result, errno, ext_dns_errno_get_last_error ());
		ext_dns_close_socket (listener_fd);
		return axl_false;
	}

	/* accept connection */
	ext_dns_log  (EXT_DNS_LEVEL_DEBUG, "calling to accept () socket");
	ctx->reader_pipe[1] = ext_dns_listener_accept (listener_fd);

	if (ctx->reader_pipe[1] <= 0) {
		ext_dns_log (EXT_DNS_LEVEL_DEBUG,  "Unable to accept connection, failed to create pipe");
		ext_dns_close_socket (listener_fd);
		return axl_false;
	}
	/* set pipe read end from result returned by thread */
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Created pipe [%d, %d] for extDns context %p", ctx->reader_pipe[0], ctx->reader_pipe[1], ctx);

	/* disable nagle */
	ext_dns_session_set_sock_tcp_nodelay (ctx->reader_pipe[1], axl_true);

	/* close listener */
	ext_dns_close_socket (listener_fd);

	/* report and return fd */
	return axl_true;
}


/** 
 * @internal
 * 
 * Creates the reader thread process. It will be waiting for any
 * session that have changed to read its connect and send it
 * appropriate channel reader.
 * 
 * @return The function returns axl_true if the ext_dns reader was started
 * properly, otherwise axl_false is returned.
 **/
axl_bool  ext_dns_reader_run (extDnsCtx * ctx) 
{
	v_return_val_if_fail (ctx, axl_false);

	/* init pipe */
	if (! __ext_dns_event_fd_init_pipe (ctx))
		return axl_false;

	/* reader_queue */
	ctx->reader_queue   = ext_dns_async_queue_new ();

	/* reader stopped */
	ctx->reader_stopped = ext_dns_async_queue_new ();

	/* create the ext_dns reader main thread */
	if (! ext_dns_thread_create (&ctx->reader_thread, 
				    (extDnsThreadFunc) __ext_dns_reader_run,
				    ctx,
				    EXT_DNS_THREAD_CONF_END)) {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "unable to start ext_dns reader loop");
		return axl_false;
	} /* end if */
	
	return axl_true;
}

/** 
 * @internal
 * @brief Cleanup ext_dns reader process.
 */
void ext_dns_reader_stop (extDnsCtx * ctx)
{
	/* get current context */
	extDnsReaderData * data;

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "stopping ext_dns reader ..");

	/* create a bacon to signal ext_dns reader that it should stop
	 * and unref resources */
	data       = axl_new (extDnsReaderData, 1);
	data->type = TERMINATE;

	/* push data */
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "pushing data stop signal..");
	ext_dns_async_queue_push (ctx->reader_queue, data);
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "signal sent reader ..");

	/* waiting until the reader is stoped */
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "waiting ext_dns reader 60 seconds to stop");
	if (PTR_TO_INT (ext_dns_async_queue_timedpop (ctx->reader_stopped, 60000000))) {
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "ext_dns reader properly stopped, cleaning thread..");
		/* terminate thread */
		ext_dns_thread_destroy (&ctx->reader_thread, axl_false);

		/* clear queue */
		ext_dns_async_queue_unref (ctx->reader_stopped);
	} else {
		ext_dns_log (EXT_DNS_LEVEL_WARNING, "timeout while waiting ext_dns reader thread to stop..");
	}

	/* clear pipe */
	ext_dns_close_socket (ctx->reader_pipe[0]);
	ext_dns_close_socket (ctx->reader_pipe[1]);

	return;
}

/** 
 * @internal Allows to check notify ext_dns reader to stop its
 * processing and to change its I/O processing model. 
 * 
 * @return The function returns axl_true to notfy that the reader was
 * notified and axl_false if not. In the later case it means that the
 * reader is not running.
 */
axl_bool  ext_dns_reader_notify_change_io_api               (extDnsCtx * ctx)
{
	extDnsReaderData * data;

	/* check if the ext_dns reader is running */
	if (ctx == NULL || ctx->reader_queue == NULL)
		return axl_false;

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "stopping ext_dns reader due to a request for a I/O notify change...");

	/* create a bacon to signal ext_dns reader that it should stop
	 * and unref resources */
	data       = axl_new (extDnsReaderData, 1);
	data->type = IO_WAIT_CHANGED;

	/* push data */
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "pushing signal to notify I/O change..");
	ext_dns_async_queue_push (ctx->reader_queue, data);

	/* waiting until the reader is stoped */
	ext_dns_async_queue_pop (ctx->reader_stopped);

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "done, now ext_dns reader will wait until the new API is installed..");

	return axl_true;
}

/** 
 * @internal Allows to notify ext_dns reader to continue with its
 * normal processing because the new I/O api have been installed.
 */
void ext_dns_reader_notify_change_done_io_api   (extDnsCtx * ctx)
{
	extDnsReaderData * data;

	/* create a bacon to signal ext_dns reader that it should stop
	 * and unref resources */
	data       = axl_new (extDnsReaderData, 1);
	data->type = IO_WAIT_READY;

	/* push data */
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "pushing signal to notify I/O is ready..");
	ext_dns_async_queue_push (ctx->reader_queue, data);

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "notification done..");

	return;
}

/** 
 * @internal Function that allows to preform a foreach operation over
 * all sessions handled by the ext_dns reader.
 * 
 * @param ctx The context where the operation will be implemented.
 *
 * @param func The function to execute on each session. If the
 * function provided is NULL the call will produce to lock until the
 * reader tend the foreach, restarting the reader loop.
 *
 * @param user_data User data to be provided to the function.
 *
 * @return The function returns a reference to the queue that will be
 * used to notify the foreach operation finished.
 */
extDnsAsyncQueue * ext_dns_reader_foreach                     (extDnsCtx            * ctx,
							      extDnsForeachFunc      func,
							      axlPointer             user_data)
{
	extDnsReaderData * data;
	extDnsAsyncQueue * queue;

	v_return_val_if_fail (ctx, NULL);

	/* queue an operation */
	data            = axl_new (extDnsReaderData, 1);
	data->type      = FOREACH;
	data->func      = func;
	data->user_data = user_data;
	queue           = ext_dns_async_queue_new ();
	data->notify    = queue;
	
	/* queue the operation */
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "notify foreach reader operation..");
	ext_dns_async_queue_push (ctx->reader_queue, data);

	/* notification done */
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "finished foreach reader operation..");

	/* return a reference */
	return queue;
}

/** 
 * @internal Iterate over all sessions currently stored on the
 * provided context associated to the ext_dns reader. This function is
 * only usable when the context is stopped.
 */
void               ext_dns_reader_foreach_offline (extDnsCtx           * ctx,
						  extDnsForeachFunc3    func,
						  axlPointer            user_data,
						  axlPointer            user_data2,
						  axlPointer            user_data3)
{
	/* first iterate over all client connextions */
	axl_list_cursor_first (ctx->con_cursor);
	while (axl_list_cursor_has_item (ctx->con_cursor)) {

		/* notify session */
		func (axl_list_cursor_get (ctx->con_cursor), user_data, user_data2, user_data3);

		/* next item */
		axl_list_cursor_next (ctx->con_cursor);
	} /* end while */

	/* now iterate over all server sessions */
	axl_list_cursor_first (ctx->srv_cursor);
	while (axl_list_cursor_has_item (ctx->srv_cursor)) {

		/* notify session */
		func (axl_list_cursor_get (ctx->srv_cursor), user_data, user_data2, user_data3);

		/* next item */
		axl_list_cursor_next (ctx->srv_cursor);
	} /* end while */

	return;
}




/** 
 * @internal Allows to restart the ext_dns reader module, locking the
 * caller until the reader restart its loop.
 */
void ext_dns_reader_restart (extDnsCtx * ctx)
{
	extDnsAsyncQueue * queue;

	/* call to restart */
	queue = ext_dns_reader_foreach (ctx, NULL, NULL);
	ext_dns_async_queue_pop (queue);
	ext_dns_async_queue_unref (queue);
	return;
}

/* @} */
