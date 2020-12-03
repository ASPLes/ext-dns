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
 *         Avenida Juan Carlos I Nº13, 2ºC (Torre Garena)
 *         Alcalá de Henares 28806 Madrid
 *         Spain
 *
 *      Email address:
 *         info@aspl.es - http://www.aspl.es/ext-dns
 */
#include <ext-dns.h>
/* include local private definitions */
#include <ext-dns-private.h>
#include <ext-dns-private-defs.h>

#if defined(AXL_OS_UNIX)
# include <netinet/tcp.h>
#endif

/**
 * \defgroup ext_dns_session extDns Session: API function to start and handle DNS sessions
 */

/** 
 * \addtogroup ext_dns_session
 * @{
 */


int  __ext_dns_listener_get_port (const char  * port)
{
	return strtol (port, NULL, 10);
}

/** 
 * @internal Function to free channel error found.
 * 
 * @param error Error to be deallocated.
 */
void __ext_dns_session_free_error_report (extDnsErrorReport * error)
{
	if (error == NULL)
		return;
	axl_free (error->msg);
	axl_free (error);

	return;
}

/** 
 * @internal Support function for session identificators.
 *
 * This is used to generate and return the next session identifier.
 *
 * @param ctx The context where the operation will be performed.
 *
 * @return Next session identifier available.
 */
int  __ext_dns_session_get_next_id (extDnsCtx * ctx)
{
	/* get current context */
	int         result;

	/* lock */
	ext_dns_mutex_lock (&ctx->session_id_mutex);
	
	/* increase */
	result = ctx->session_id;
	ctx->session_id++;

	/* unlock */
	ext_dns_mutex_unlock (&ctx->session_id_mutex);

	return result;
}

/** 
 * @internal Fucntion that perform the session socket sanity check.
 * 
 * This prevents from having problems while using socket descriptors
 * which could conflict with reserved file descriptors such as 0,1,2..
 *
 * @param ctx The context where the operation will be performed. 
 *
 * @param session The session to check.
 * 
 * @return axl_true if the socket sanity check have passed, otherwise
 * axl_false is returned.
 */
axl_bool      ext_dns_session_do_sanity_check (extDnsCtx * ctx, EXT_DNS_SOCKET session)
{
	/* warn the user if it is used a socket descriptor that could
	 * be used */
	if (ctx && ctx->session_enable_sanity_check) {
		
		if (session < 0) {
			ext_dns_log (EXT_DNS_LEVEL_CRITICAL,
				    "Socket receive is not working, invalid socket descriptor=%d", session);
			return axl_false;
		} /* end if */

		/* check for a valid socket descriptor. */
		switch (session) {
		case 0:
		case 1:
		case 2:
			ext_dns_log (EXT_DNS_LEVEL_CRITICAL, 
			       "created socket descriptor using a reserved socket descriptor (%d), this is likely to cause troubles",
			       session);
			/* return sanity check have failed. */
			return axl_false;
		}
	}

	/* return the sanity check is ok. */
	return axl_true;
}

/** 
 * @brief Allows to enable/disable non-blocking/blocking behavior on
 * the provided socket.
 * 
 * @param socket The socket to be configured.
 *
 * @param enable axl_true to enable blocking I/O, otherwise use
 * axl_false to enable non blocking I/O.
 * 
 * @return axl_true if the operation was properly done, otherwise axl_false is
 * returned.
 */
axl_bool                 ext_dns_session_set_sock_block         (EXT_DNS_SOCKET socket,
								 axl_bool      enable)
{
#if defined(AXL_OS_UNIX)
	int  flags;
#endif

	if (enable) {
		/* enable blocking mode */
#if defined(AXL_OS_WIN32)
		if (!ext_dns_win32_blocking_enable (socket)) {
			return axl_false;
		}
#else
		if ((flags = fcntl (socket, F_GETFL, 0)) < 0) {
			return axl_false;
		} /* end if */

		flags &= ~O_NONBLOCK;
		if (fcntl (socket, F_SETFL, flags) < 0) {
			return axl_false;
		} /* end if */
#endif
	} else {
		/* enable nonblocking mode */
#if defined(AXL_OS_WIN32)
		/* win32 case */
		if (!ext_dns_win32_nonblocking_enable (socket)) {
			return axl_false;
		}
#else
		/* unix case */
		if ((flags = fcntl (socket, F_GETFL, 0)) < 0) {
			return axl_false;
		}
		
		flags |= O_NONBLOCK;
		if (fcntl (socket, F_SETFL, flags) < 0) {
			return axl_false;
		}
#endif
	} /* end if */

	return axl_true;
}


/** 
 * \brief Allows to change session semantic to nonblocking.
 *
 * Sets a session to be non-blocking while sending and receiving
 * data. This function should not be useful for extDns Library
 * consumers.
 * 
 * @param session the session to set as nonblocking.
 * 
 * @return axl_true if nonblocking state was set or axl_false if not.
 */
axl_bool      ext_dns_session_set_nonblocking_socket (extDnsSession * session)
{
	extDnsCtx * ctx;

#if defined(AXL_OS_UNIX)
	int  flags;
#endif
	/* check the reference */
	if (session == NULL)
		return axl_false;

	/* get a reference to context */
	ctx = session->ctx;
	
#if defined(AXL_OS_WIN32)
	if (!ext_dns_win32_nonblocking_enable (session->session)) {
		__ext_dns_session_shutdown_and_record_error (
			session, extDnsError, "unable to set non-blocking I/O");
		return axl_false;
	}
#else
	if ((flags = fcntl (session->session, F_GETFL, 0)) < 0) {
		__ext_dns_session_shutdown_and_record_error (
			session, extDnsError,
			"unable to get socket flags to set non-blocking I/O");
		return axl_false;
	}

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "actual flags state before setting nonblocking: %d", flags);
	flags |= O_NONBLOCK;
	if (fcntl (session->session, F_SETFL, flags) < 0) {
		__ext_dns_session_shutdown_and_record_error (
			session, extDnsError, "unable to set non-blocking I/O");
		return axl_false;
	}
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "actual flags state after setting nonblocking: %d", flags);
#endif
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "setting session as non-blocking");
	return axl_true;
}

/** 
 * @brief Allows to configure tcp no delay flag (enable/disable Nagle
 * algorithm).
 * 
 * @param socket The socket to be configured.
 *
 * @param enable The value to be configured, axl_true to enable tcp no
 * delay.
 * 
 * @return axl_true if the operation is completed.
 */
axl_bool                 ext_dns_session_set_sock_tcp_nodelay   (EXT_DNS_SOCKET socket,
								 axl_bool      enable)
{
	/* local variables */
	int result;

#if defined(AXL_OS_WIN32)
	BOOL   flag = enable ? TRUE : FALSE;
	result      = setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, (char  *)&flag, sizeof(BOOL));
#else
	int    flag = enable;
	result      = setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof (flag));
#endif
	if (result < 0) {
		return axl_false;
	}

	/* properly configured */
	return axl_true;
} /* end */


/** 
 * @internal Allows to configure the socket to be used by the provided
 * session. This function is usually used in conjunction with \ref ext_dns_listener_new_empty.
 *
 * @param conn The session to be configured with the socket
 * provided.
 *
 * @param _socket The socket session to configure.
 *
 * @param real_host Optional reference that can configure the host
 * value associated to the socket provided. You can safely pass NULL,
 * causing the function to figure out which is the right value using
 * the socket provided.
 *
 * @param real_port Optional reference that can configure the port
 * value associated to the socket provided. See <b>real_host</b> param
 * for more information. In real_host is defined, it is required to
 * define this parameter.
 *
 * @return axl_true in the case the function has configured the
 * provided socket, otherwise axl_false is returned.
 */
axl_bool            ext_dns_session_set_socket                (extDnsSession    * session,
							       EXT_DNS_SOCKET      _socket,
							       const char       * real_host,
							       const char       * real_port)
{

	struct sockaddr_in   sin;
#if defined(AXL_OS_WIN32)
	/* windows flavors */
	int                  sin_size = sizeof (sin);
#else
	/* unix flavors */
	socklen_t            sin_size = sizeof (sin);
#endif
	extDnsCtx          * ctx;

	/* check session reference */
	if (session == NULL)
		return axl_false;

	ctx  = session->ctx;

	/* perform sessionection sanity check */
	if (!ext_dns_session_do_sanity_check (ctx, _socket)) 
		return axl_false;

	/* disable nagle */
	ext_dns_session_set_sock_tcp_nodelay (_socket, axl_true);

	/* set socket */
	session->session = _socket;

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Getting host address with role: %d (%d)", session->role, extDnsRoleMasterListener);
	
	/* get remote peer name */
	if (real_host && real_port) {
		/* set host and port from user values */
		session->host = axl_strdup (real_host);
		session->port = axl_strdup (real_port);
	} else {
		if (session->role == extDnsRoleMasterListener) {
			if (getsockname (_socket, (struct sockaddr *) &sin, &sin_size) < 0) {
				ext_dns_log (EXT_DNS_LEVEL_DEBUG, "unable to get local hostname and port");
				return axl_false;
			} /* end if */
		} else {
			if (getpeername (_socket, (struct sockaddr *) &sin, &sin_size) < 0) {
				ext_dns_log (EXT_DNS_LEVEL_DEBUG, "unable to get remote hostname and port");
				return axl_false;
			} /* end if */
		} /* end if */

		/* set host and port from socket recevied */
		session->host = ext_dns_support_inet_ntoa (ctx, &sin);
		session->port = axl_strdup_printf ("%d", ntohs (sin.sin_port));	
	} /* end if */

	/* now set local address */
	if (getsockname (_socket, (struct sockaddr *) &sin, &sin_size) < 0) {
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "unable to get local hostname and port to resolve local address");
		return axl_false;
	} /* end if */

	/* set local addr and local port */
	session->local_addr = ext_dns_support_inet_ntoa (ctx, &sin);
	session->local_port = axl_strdup_printf ("%d", ntohs (sin.sin_port));	

	return axl_true;
}


/** 
 * @brief  Returns the session unique identifier.
 *
 * The session identifier is a unique integer assigned to all session
 * created under extDns Library. This allows extDns programmer to use
 * this identifier for its own application purposes
 *
 * @param session The session to get the id from
 * 
 * @return the unique identifier.
 */
int               ext_dns_session_get_id     (extDnsSession * session)
{
	if (session == NULL)
		return -1;

	return session->id;	
}

/** 
 * @brief Returns the actual host this session is sessionected to.
 *
 * For resolver sessions it provides the port where it is
 * connected. For listener sessions it provides the port where it
 * is listening this session.
 *
 * @param session the session to get host value from
 * 
 * @return the host the given session is connected to or NULL if something fail.
 */
const char         * ext_dns_session_get_host             (extDnsSession * session)
{
	if (session == NULL)
		return NULL;

	return session->host;
}

/** 
 * @brief Returns the actual port this session is connected to.
 *
 * For resolver sessions it provides the port where it is
 * connected. For listener sessions it provides the port where it
 * is listening this session.
 *
 * @param session the session to get the port value.
 * 
 * @return the port or NULL if something fails.
 */
const char      * ext_dns_session_get_port           (extDnsSession * session)
{
	/* check reference received */
	if (session == NULL)
		return NULL;

	return session->port;
}

/** 
 * @brief Allows to get current session role.
 * 
 * @param session The extDnsSession to get the current role from.
 * 
 * @return Current role represented by \ref extDnsPeerRole. If the
 * function receives a NULL reference it will return \ref
 * extDnsRoleUnknown.
 */
extDnsPeerRole      ext_dns_session_get_role               (extDnsSession * session)
{
	/* if null reference received, return unknown role */
	v_return_val_if_fail (session, extDnsRoleUnknown);

	return session->role;
}

/** 
 * @brief Allows to get the extDnsCtx object from the DNS session
 * provided.
 *
 * @param session The session object where to get the context from.
 *
 * @return The context or NULL if something fails.
 */
extDnsCtx * ext_dns_session_get_ctx (extDnsSession * session) {
	/* check result */
	v_return_val_if_fail (session, NULL);

	/* return context */
	return session->ctx;
}

/** 
 * @brief Allows to check if the session is still working.
 *
 * @param session The session to be checked.
 *
 * @param free_on_fail Allows to release session object in the case
 * of failure.
 *
 * @return axl_true in the case the session is working, otherwise
 * axl_false is returned.
 */
axl_bool          ext_dns_session_is_ok      (extDnsSession * session, axl_bool free_on_fail)
{
	axl_bool  result = axl_false;

	/* check session null referencing. */
	if  (session == NULL) 
		return axl_false;

	/* check for the socket this session has */
	ext_dns_mutex_lock  (&(session->ref_mutex));
	result = (session->session < 0) || (! session->is_connected);
	ext_dns_mutex_unlock  (&(session->ref_mutex));

	/* implement free_on_fail flag */
	if (free_on_fail && result) {
		ext_dns_session_close (session);
		return axl_false;
	} /* end if */
	
	/* return current session status. */
	return ! result;
}

/**
 * @internal Function used to record and error and then shutdown the
 * session in the same step.
 *
 * @param conn The session where the error was detected.
 * @param message The message to report
 * 
 */
void                __ext_dns_session_shutdown_and_record_error (extDnsSession    * session,
								 extDnsStatus       status,
								 const char       * message,
								 ...)
{
	va_list     args;
	char      * _msg;
	extDnsCtx * ctx;

	/* log error */
	if (status != extDnsOk && status != extDnsSessionCloseCalled) {

		/* get context reference */
		ctx = session->ctx;

		/* prepare message */
		va_start (args, message);
		_msg = axl_strdup_printfv (message, args);
		va_end (args);

		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, _msg);
		
		/* push an error into the session */
		ext_dns_session_push_error (session, status, _msg);

		/* release message */
		axl_free (_msg);
	} 

	/* close socket */
	ext_dns_session_shutdown (session);

	return;
}



/** 
 * @brief Closes a session and releases all its resources
 * 
 * @param session The session to close
 * 
 * @return axl_true if session was closed and axl_false if not.
 *
 */
axl_bool                    ext_dns_session_close                  (extDnsSession * session)
{
	int         refcount = 0;
	extDnsCtx * ctx;

	/* if the session is a null reference, just return
	 * axl_true */
	if (session == NULL)
		return axl_true;

	/* get a reference to the ctx */
	ctx = session->ctx;

	/* check if session close was already called without locking */
	if (session->close_called)
		return axl_true;

	/* ensure only one call to ext_dns_session_close will
	   progress */
	ext_dns_mutex_lock (&session->op_mutex);
	if (session->close_called) {
		ext_dns_mutex_unlock (&session->op_mutex);
		return axl_true;
	}
	/* flag as session close called */
	session->close_called = axl_true;
	ext_dns_mutex_unlock (&session->op_mutex);

	/* close all channel on this session */
	if (ext_dns_session_is_ok (session, axl_false)) {
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "closing a session id=%d", session->id);

		/* update the session reference to avoid race
		 * conditions caused by deallocations */
		if (! ext_dns_session_ref (session, "ext_dns_session_close")) {

			__ext_dns_session_shutdown_and_record_error (
				session, extDnsError,
				"failed to update reference counting on the session during close operation, skiping clean close operation..");
			ext_dns_session_unref (session, "ext_dns_session_close");
			return axl_true;
		}
		
		/* set the session to be not connected */
		__ext_dns_session_shutdown_and_record_error (
			session, extDnsSessionCloseCalled, "close session called");

		/* update the session reference to avoid race
		 * conditions caused by deallocations */
		refcount = session->ref_count;
		ext_dns_session_unref (session, "ext_dns_session_close");

		/* check special case where the caller have stoped a
		 * listener reference without taking a reference to it */
		if ((refcount - 1) == 0) {
			return axl_true;
		}
	} 

	return axl_true;
}

/** 
 * @brief Allows to close the socket that is supporting the provided
 * session.
 *
 * @param session The session to be shutted down.
 */
void              ext_dns_session_shutdown   (extDnsSession * session)
{
	/* close socket */
	if (session && session->session) {
		ext_dns_close_socket (session->session);
		session->session = -1;
	} /* end if */
	return;
}

/** 
 * @brief Allows to configure the onMessage handler, the callback that
 * is called every time a new message is received over the provided
 * session.
 *
 * Note this handler is only called when a well-formed DNS message is
 * received. Otherwise, badrequest is considered, optionally notified
 * through \ref ext_dns_session_set_on_badrequest, and finally
 * discarded.
 *
 * @param session The session that is configured to received messages
 * on the provided handler.
 *
 * @param on_dns_message The handler where the message will be notified.
 *
 * @param data A pointer to user defined data that will be passed into
 * the handler.
 *
 * Note: only one handler can be configured at the same time for a
 * single session.
 */
void              ext_dns_session_set_on_message (extDnsSession             * session, 
						  extDnsOnMessageReceived     on_dns_message, 
						  axlPointer                  data)
{
	/* check pointer received */
	if (session == NULL)
		return;

	/* set on message */
	session->on_message      = on_dns_message;
	session->on_message_data = data;

	return;
}

/** 
 * @brief Allows to setup a handler which is called every time a bad
 * request is received. 
 * 
 * Because DNS messages are parsed and checked before being notified
 * to user level handler, those messages that aren't considered
 * properly formated are discarded, thus, the user level doesn't have
 * to deal with them.
 *
 * However, it may be required by user level to get notifcation about
 * those messages so especial actions could be taken (like blocking
 * traffic or doing some stats).
 *
 * @param session The session that is going to be configured with a
 * bad request received handler.
 *
 * @param on_bad_request The handler to be called upon reception of a
 * bad request.
 *
 * @param data A pointer to user defined data that will be passed info
 * the handler.
 *
 */
void              ext_dns_session_set_on_badrequest (extDnsSession         * session, 
						     extDnsOnBadRequest      on_bad_request, 
						     axlPointer              data)
{
	/* check pointer received */
	if (session == NULL || on_bad_request == NULL)
		return;

	/* set on message */
	session->on_bad_request      = on_bad_request;
	session->on_bad_request_data = data;

	return;
}

/** 
 * @brief Allows to set a key and a value associated to the provided
 * session which can be used later to retrieve those values.
 *
 * The function also accepts a set of destroy functions that are
 * called automatically when the session is destroyed to release those
 * elements (they are optional).
 *
 * @param session The session where to store the key and value.
 *
 * @param key The under which the data will be associated and
 * indexed. If there is a previously value stored with the same key,
 * it will be replaced by this new value (having key_destroy and
 * data_destroy called if they were defined). NOTE key cannot be
 * NULL. If NULL key value is provided, the function will return
 * without doing anything
 *
 * @param key_destroy The optional key destroy function to be called
 * to release memory hold by the key.
 *
 * @param data The data to be associated to the provided key. If the
 * data is NULL, it will cause the function to remove the key and data
 * associated. Passing the valid key and NULL as data is the way to
 * remove entries from the hash.
 *
 * @param data_destroy The optional data destroy function to be called
 * to release the data reference.
 */
void              ext_dns_session_set_data (extDnsSession * session,
					    const char    * key,
					    axlDestroyFunc  key_destroy,
					    axlPointer      data,
					    axlDestroyFunc  data_destroy)
{
	if (session == NULL || key == NULL)
		return;

	ext_dns_mutex_lock (&session->data_mutex);
	if (data == NULL) {
		/* user requested to remove the value */
		axl_hash_remove (session->data, (axlPointer) key);
	} else {
		/* set (and replace if there weren't some data) */
		axl_hash_insert_full (session->data, (axlPointer) key, key_destroy, (axlPointer) data, data_destroy);
	} /* end if */

	ext_dns_mutex_unlock (&session->data_mutex);

	return;
}

/** 
 * @brief Allows to get the data associated to the provided key on the
 * provided session.
 *
 * Data that can be retrieved by this function were previously stored
 * by \ref ext_dns_session_set_data.
 *
 * @param session The session where the data is stored.
 *
 * @param key The key under which the data was stored.
 *
 * @return A reference to the data or NULL if it fails.
 *
 */
axlPointer        ext_dns_session_get_data (extDnsSession * session, 
					    const char    * key)
{
	axlPointer data;

	if (session == NULL || key == NULL)
		return NULL;

	ext_dns_mutex_lock (&session->data_mutex);

	/* get data */
	data = axl_hash_get (session->data, (axlPointer) key);

	ext_dns_mutex_unlock (&session->data_mutex);

	return data;
}

/**
 * @internal Reference counting update implementation.
 */
axl_bool               ext_dns_session_ref_internal                    (extDnsSession * session, 
									const char       * who,
									axl_bool           check_ref)
{
	extDnsCtx * ctx;

	v_return_val_if_fail (session, axl_false);
	if (check_ref)
		v_return_val_if_fail (ext_dns_session_is_ok (session, axl_false), axl_false);

	/* get a reference to the ctx */
	ctx = session->ctx;
	
	/* lock ref/unref operations over this session */
	ext_dns_mutex_lock   (&session->ref_mutex);

	/* increase and log the session increased */
	session->ref_count++;

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "%d increased session id=%d (%p) reference to %d by %s\n",
		    ext_dns_getpid (),
		    session->id, session,
		    session->ref_count, who ? who : "??" ); 

	/* unlock ref/unref options over this session */
	ext_dns_mutex_unlock (&session->ref_mutex);

	return axl_true;
}

/** 
 * @brief Increase internal ext_dns session reference counting.
 * 
 * Because extDns Library design, several on going threads shares
 * references to the same session for several purposes. 
 * 
 * Session reference counting allows to every on going thread to
 * notify the system that session reference is no longer be used
 * so, if the reference counting reach a zero value, session
 * resources will be deallocated.
 *
 * While using the extDns Library is not required to use this function
 * especially for those applications which are built on top of a
 * profile which is layered on extDns Library. 
 *
 * This is because session handling is done through functions such
 * \ref ext_dns_listener_new and \ref ext_dns_session_close (which
 * automatically handles session reference counting for you).
 *
 * However, while implementing new profiles these function becomes a
 * key concept to ensure the profile implementation don't get lost
 * session references.
 *
 * Keep in mind that using this function implied to use \ref
 * ext_dns_session_unref function in all code path implemented. For
 * each call to \ref ext_dns_session_ref it should exist a call to
 * \ref ext_dns_session_unref. Failing on doing this will cause
 * either memory leak or memory corruption because improper session
 * deallocations.
 * 
 * The function return axl_true to signal that the session reference
 * count was increased in one unit. If the function return axl_false,
 * the session reference count wasn't increased and a call to
 * ext_dns_session_unref should not be done. Here is an example:
 * 
 * \code
 * // try to ref the session
 * if (! ext_dns_session_ref (session, "some known module or file")) {
 *    // unable to ref the session
 *    return;
 * }
 *
 * // session referenced, do work 
 *
 * // finally unref the session
 * ext_dns_session_unref (session, "some known module or file");
 * \endcode
 *
 * @param session the session to operate.
 * @param who who have increased the reference.
 *
 * @return axl_true if the session reference was increased or axl_false if
 * an error was found.
 */
axl_bool               ext_dns_session_ref                    (extDnsSession * session, 
								 const char       * who)
{
	/* checked ref */
	return ext_dns_session_ref_internal (session, who, axl_true);
}

/** 
 * @brief Decrease ext_dns session reference counting.
 *
 * Allows to decrease session reference counting. If this reference
 * counting goes under 0 the session resources will be deallocated. 
 *
 * See also \ref ext_dns_session_ref
 * 
 * @param session The session to operate.
 * @param who        Who have decreased the reference. This is a string value used to log which entity have decreased the session counting.
 */
void               ext_dns_session_unref                  (extDnsSession * session, 
							   char const    * who)
{
	extDnsCtx  * ctx;
	int          count;

	/* do not operate if no reference is received */
	if (session == NULL)
		return;

	/* lock the session being unrefered */
	ext_dns_mutex_lock     (&(session->ref_mutex));

	/* get context */
	ctx = session->ctx;

	/* decrease reference counting */
	session->ref_count--;

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "%d decreased session id=%d (%p) reference count to %d decreased by %s\n", 
		ext_dns_getpid (),
		session->id, session,
		session->ref_count, who ? who : "??");  

	/* get current count */
	count = session->ref_count;
	ext_dns_mutex_unlock (&(session->ref_mutex));

	/* if counf is 0, free the session */
	if (count == 0) {
		ext_dns_session_free (session);
	} /* end if */

	return;
}

void __ext_dns_free_addr_info (axlPointer ptr)
{
	freeaddrinfo (ptr);
	return;
}

/** 
 * @internal wrapper to avoid possible problems caused by the
 * gethostbyname implementation which is not required to be reentrant
 * (thread safe).
 *
 * @param ctx The context where the operation will be performed.
 * 
 * @param hostname The host to translate.
 * 
 * @return A reference to the struct hostent or NULL if it fails to
 * resolv the hostname.
 */
struct addrinfo * ext_dns_session_getaddrinfo (extDnsCtx  * ctx, 
					       const char * hostname,
					       const char * port,
					       axl_bool   * should_release)
{
	/* get current context */
	struct addrinfo    req, *ans = NULL;
	int                ret_val;
	char             * key = NULL;
	axl_bool           skip_cache;

	/* check that context and hostname are valid */
	if (ctx == NULL || hostname == NULL || port == NULL)
		return NULL;

	/* different port, do not cache it */
	skip_cache = (! axl_cmp (port, "53"));

	if (! skip_cache) {
		/*** CACHE CODE ***/

		ctx->hostname_hash_queries++;

		key = axl_strdup_printf ("%s:%s", hostname, port);
		if (key == NULL) 
			return NULL; /* allocation failure */

		/* lock and resolv */
		ext_dns_mutex_lock (&ctx->hostname_mutex);

		/* resolv using the hash */
		ans = axl_hash_get (ctx->hostname_hash, (axlPointer) key);
		if (ans) {
			ctx->hostname_hash_hits++;
			
			/* unlock and return the result */
			ext_dns_mutex_unlock (&ctx->hostname_mutex);
			axl_free (key);
			
			return ans;		
		} /* end if */
	} /* end if */

	/* resolve hostname */
	memset (&req, 0, sizeof(struct addrinfo));
	req.ai_family   = AF_INET;
	req.ai_socktype = SOCK_DGRAM;
	
	ret_val = getaddrinfo (hostname, port, &req, &ans);
	if (ret_val == 0 && ans && key && ! skip_cache) {
		/*** CACHE CODE ***/

		/* now store the result */
		axl_hash_insert_full (ctx->hostname_hash, 
				      /* the hostname */
				      key, axl_free,
				      /* the address */
				      ans, __ext_dns_free_addr_info);
	} /* end if */

	if (! skip_cache) {
		/***  CACHE CODE ***/

		/* unlock and return the result */
		ext_dns_mutex_unlock (&ctx->hostname_mutex);
	} /* end if */

	if (should_release)
		(*should_release) = skip_cache;

	return ans;
	
}

int               __ext_dns_session_send_udp_common   (extDnsCtx     * ctx, 
						       int             session,
						       const char    * content, 
						       int             length, 
						       const char    * address, 
						       int             port,
						       char         ** source_address,
						       int           * source_port)
{
	struct   sockaddr_in dest_addr; 
	int      numbytes; 
	axl_bool close_socket;
#if defined(AXL_OS_WIN32)
	int                  sin_size  = sizeof (dest_addr);
#else    	
	socklen_t            sin_size  = sizeof (dest_addr);
#endif	
	struct   addrinfo  * res;
	int                  val = IP_PMTUDISC_DONT;
	char               * str_port = axl_strdup_printf ("%d", port);
	axl_bool             should_release = axl_false;
	
	/* convertimos el hostname a su direccion IP */
	if ((res = ext_dns_session_getaddrinfo (ctx, address, str_port, &should_release)) == NULL) {
		axl_free (str_port);
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Failed to get host by name for address=%s", address);
		return -1;
	}
	axl_free (str_port);

	/* set default state for closing socket */
	close_socket = axl_false;
	
	if (session == -1) {
		/* create socket */
		if ((session = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {

			/* release addrinfo if indicated */
			if (should_release) { freeaddrinfo (res); }

			ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Failed to create socket, error was errno=%d", errno);
			return -1;
		}

		/* set we have to close the socket after finishing */
		close_socket = axl_true;
	} /* end if */

	/* remove DF flag */
	setsockopt (session, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
	
	/* enviamos el mensaje */
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Sending UDP message to %s:%d (size: %d)", address, port, length);
	if ((numbytes = sendto (session, content, length, MSG_DONTWAIT, res->ai_addr, res->ai_addrlen)) == -1) {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Failed to send message, error was=%d (%s)", errno, ext_dns_errno_get_last_error ());

		/* close socket */
		if (close_socket)
			ext_dns_close_socket (session);

		/* release addrinfo if indicated */
		if (should_release) { freeaddrinfo (res); }

		return -1;
	}

	/* release addrinfo if indicated */
	if (should_release) { freeaddrinfo (res); }

	if (source_port || source_address) {
		sin_size = sizeof (dest_addr);
		if (getsockname (session, (struct sockaddr *) &dest_addr, &sin_size) < 0) {
			/* close socket */
			if (close_socket)
				ext_dns_close_socket (session);

			ext_dns_log (EXT_DNS_LEVEL_DEBUG, "unable to get local hostname and port");
			return axl_false;
		} /* end if */
	} /* end if */

	/* set the source addres and port used by this sending call so the caller can reply if he wants */
	if (source_address)
		(*source_address) = ext_dns_support_inet_ntoa (ctx, &dest_addr);
	if (source_port)
		(*source_port)    = ntohs (dest_addr.sin_port);
	
	/* close socket */
	if (close_socket)
		ext_dns_close_socket (session);
	
	return numbytes;
}

/** 
 * @brief Send the provided message using UDP protocol to the
 * destination.
 *
 * @param ctx The context where the operation will happen.
 *
 * @param content The content to be sent to the remote node.
 *
 * @param length How many bytes we have to take from the content.
 *
 * @param address The peer address to send the message to.
 *
 * @param port The peer port to send the message to.
 *
 * @param source_address Optional pointer that if defined, will hold
 * the source address used to send the message. This is required if
 * you want to wait for a reply.
 *
 * @param source_port Optional pointer that if defined, will hold the
 * source port used to send the message. This is required if you want
 * to wait for a reply.
 *
 * @return Return the number of bytes written or -1 if it fails.
 */
int               ext_dns_session_send_udp   (extDnsCtx     * ctx, 
					      const char    * content, 
					      int             length, 
					      const char    * address, 
					      int             port,
					      char         ** source_address,
					      int           * source_port)
{
	return __ext_dns_session_send_udp_common (ctx, -1, content, length, address, port, source_address, source_port);
}

/** 
 * @brief Send the provided message using UDP protocol to the
 * destination.
 *
 * @param ctx The context where the operation will happen.
 *
 * @param session The session listener from which the reply will be
 * sent.
 *
 * @param content The content to be sent to the remote node.
 *
 * @param length How many bytes we have to take from the content.
 *
 * @param address The peer address to send the message to.
 *
 * @param port The peer port to send the message to.
 *
 * @return Return the number of bytes written or -1 if it fails.
 */
int               ext_dns_session_send_udp_s (extDnsCtx      * ctx, 
					      extDnsSession  * session,
					      const char     * content, 
					      int              length, 
					      const char     * address, 
					      int              port)
{
	/* check session reference */
	if (session == NULL)
		return -1;

	return __ext_dns_session_send_udp_common (ctx, session->session, content, length, address, port, NULL, NULL);
}


/** 
 * @internal Function used by ext_dns to store new error message
 * associated to sessions.
 * 
 * @param session The session where the error will be stored.
 *
 * @param code The code to store.
 *
 * @param msg The message to store, the value provided will be owned
 * by the session and no copy will be allocated. This variable is
 * not optional.
 */
void                ext_dns_session_push_error     (extDnsSession  * session, 
						    int              code,
						    const char     * msg)
{
	extDnsErrorReport * error;
	
	/* check reference received */
	if (session == NULL || msg == NULL)
		return;
	
	/* lock the session during operations */
	ext_dns_mutex_lock (&session->pending_errors_mutex);

	/* initialize pending errors stack on demand */
	if (session->pending_errors == NULL) {
		session->pending_errors = axl_stack_new ((axlDestroyFunc) __ext_dns_session_free_error_report);
		if (session->pending_errors == NULL) {
			ext_dns_mutex_unlock (&session->pending_errors_mutex);
			return;
		} /* end if */
	} /* end if */

	/* create the value */
	error       = axl_new (extDnsErrorReport, 1);
	if (error != NULL) {
		error->code = code;
		error->msg  = axl_strdup (msg);

		/* push the data */
		axl_stack_push (session->pending_errors, error);
			
	} /* end if */
	
	/* unlock */
	ext_dns_mutex_unlock (&session->pending_errors_mutex);

	return;
}


/** 
 * @brief Frees extDns session resources
 * 
 * Free all resources allocated by the extDnsSession. 
 *
 * Generally is not a good a idea to call this function. This is
 * because every session created using the extDns API is registered
 * at some internal process (the extDns reader, sequencer and writer)
 * so they have references to created session to do its job. 
 *
 * To close a session properly call \ref ext_dns_session_close.
 * 
 * @param session the session to free
 */
void               ext_dns_session_free (extDnsSession * session)
{
	extDnsErrorReport * error;
	extDnsCtx         * ctx;
	
	if (session == NULL)
		return;

	/* get a reference to the context reference */
	ctx = session->ctx;

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "freeing session id=%d (%p)", session->id, session);

	/*
	 * NOTE: The order in which the channels and the channel pools
	 * are closed must be this way: first channels and the channel
	 * pools. Doing it other way will produce funny dead-locks.
	 */
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "freeing session id=%d channels", session->id);

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "freeing session custom data holder id=%d", session->id);

	/* free session data hash */
	if (session->data) {
		axl_hash_free (session->data);
		session->data = NULL;
	}

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "freeing session message id=%d", session->id);

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "freeing session host id=%d", session->id);

	/* free host and port */
	if (session->host != NULL) {
		axl_free (session->host);
		axl_free (session->local_addr);
		session->host       = NULL;
		session->local_addr = NULL;
	}
	axl_free (session->host_ip);

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "freeing session port id=%d", session->id);

	if (session->port != NULL) {
		axl_free (session->port);
		axl_free (session->local_port);
		session->port       = NULL;
		session->local_port = NULL;
	}

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "freeing session profiles id=%d", session->id);

	/* release ref mutex */
	ext_dns_mutex_destroy (&session->ref_mutex);

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "freeing session operational mutex id=%d", session->id);

	ext_dns_mutex_destroy (&session->op_mutex);

	/* free items from the stack */
	if (session->pending_errors) {
		while (! axl_stack_is_empty (session->pending_errors)) {
			/* pop error */
			error = axl_stack_pop (session->pending_errors);
			
			/* free the error */
			axl_free (error->msg);
			axl_free (error);
		} /* end if */
		/* free the stack */
		axl_stack_free (session->pending_errors);
		session->pending_errors = NULL;
	} /* end if */
	ext_dns_mutex_destroy (&session->pending_errors_mutex);

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "freeing/terminating session id=%d", session->id);

	/* close session */
	if (session->session != -1) {
		/* it seems that this session is  */
		shutdown (session->session, SHUT_RDWR);
		ext_dns_close_socket (session->session);
		session->session = -1;
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "session socket closed");
	}

	/* release data */
	axl_hash_free (session->data);
	ext_dns_mutex_destroy (&session->data_mutex);

	/* release expected header */
	axl_free (session->expected_header);
	
	/* release reference to context */
	ext_dns_ctx_unref2 (&session->ctx, "end session");

	/* free session */
	axl_free (session);

	return;
}

/** 
 * @internal Function used to check if we have reached our socket
 * creation limit to avoid exhausting it. The idea is that we need to
 * have at least one bucket free before limit is reached so we can
 * still empty the listeners backlog to close them (accept ()).
 *
 * @return axl_true in the case the limit is not reached, otherwise
 * axl_false is returned.
 */
axl_bool ext_dns_session_check_socket_limit (extDnsCtx * ctx, EXT_DNS_SOCKET socket_to_check)
{
	int   soft_limit, hard_limit;
	EXT_DNS_SOCKET temp;

	/* create a temporal socket */
	temp = socket (AF_INET, SOCK_STREAM, 0);
	if (temp == EXT_DNS_INVALID_SOCKET) {
		/* uhmmn.. seems we reached our socket limit, we have
		 * to close the session to avoid keep on iterating
		 * over the listener session because its backlog
		 * could be filled with sockets we can't accept */
		shutdown (socket_to_check, SHUT_RDWR);
		ext_dns_close_socket (socket_to_check);

		/* get values */
		ext_dns_conf_get (ctx, EXT_DNS_SOFT_SOCK_LIMIT, &soft_limit);
		ext_dns_conf_get (ctx, EXT_DNS_HARD_SOCK_LIMIT, &hard_limit);
		
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, 
			    "droping socket session, reached process limit: soft-limit=%d, hard-limit=%d\n",
			    soft_limit, hard_limit);
		return axl_false; /* limit reached */

	} /* end if */
	
	/* close temporal socket */
	ext_dns_close_socket (temp);

	return axl_true; /* session check ok */
}


/** 
 * @brief Returns the socket used by this extDnsSession object.
 * 
 * @param session the session to get the socket.
 * 
 * @return the socket used or -1 if fail
 */
EXT_DNS_SOCKET    ext_dns_session_get_socket           (extDnsSession * session)
{
	/* check reference received */
	if (session == NULL)
		return -1;

	return session->session;
}

/** 
 * @brief Public function that performs a TCP listener accept.
 *
 * @param server_socket The listener socket where the accept() operation will be called.
 *
 * @return Returns a connected socket descriptor or -1 if it fails.
 */
EXT_DNS_SOCKET ext_dns_listener_accept (EXT_DNS_SOCKET server_socket)
{
	struct sockaddr_in inet_addr;
#if defined(AXL_OS_WIN32)
	int               addrlen;
#else
	socklen_t         addrlen;
#endif
	addrlen       = sizeof(struct sockaddr_in);

	/* accept the session new session */
	return accept (server_socket, (struct sockaddr *)&inet_addr, &addrlen);
}

void ext_dns_listener_accept_sessions (extDnsCtx        * ctx,
					  int                server_socket, 
					  extDnsSession * listener)
{
	int   soft_limit, hard_limit, client_socket;

	/* accept the session new session */
	client_socket = ext_dns_listener_accept (server_socket);
	if (client_socket == EXT_DNS_SOCKET_ERROR) {
		/* get values */
		ext_dns_conf_get (ctx, EXT_DNS_SOFT_SOCK_LIMIT, &soft_limit);
		ext_dns_conf_get (ctx, EXT_DNS_HARD_SOCK_LIMIT, &hard_limit);

		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "accept () failed, server_socket=%d, soft-limit=%d, hard-limit=%d: (errno=%d) %s\n",
			    server_socket, soft_limit, hard_limit, errno, ext_dns_errno_get_last_error ());
		return;
	}

	/* check we can support more sockets, if not close current
	 * session: function already closes client socket in the
	 * case of failure */
	if (! ext_dns_session_check_socket_limit (ctx, client_socket))
		return;

	/* instead of negotiate the session at this point simply
	 * accept it to negotiate it inside ext_dns_reader loop.  */
	/* __ext_dns_listener_initial_accept (ext_dns_session_get_ctx (listener), client_socket, listener); */

	return;
}

typedef struct _extDnsListenerData {
	char                     * host;
	int                        port;
	extDnsSessionType          type;
	extDnsListenerReady        on_ready;
	extDnsListenerReadyFull    on_ready_full;
	axlPointer                 user_data;
	axl_bool                   threaded;
	extDnsCtx                * ctx;
}extDnsListenerData;

/** 
 * @brief Starts a generic TCP listener on the provided address and
 * port. This function is used internally by the ext_dns listener
 * module to startup the ext_dns listener TCP session associated,
 * however the function can be used directly to start TCP listeners.
 *
 * @param ctx The context where the listener is started.
 *
 * @param type Session type that is going to be created.
 *
 * @param host Host address to allocate. It can be "127.0.0.1" to only
 * listen for localhost sessions or "0.0.0.0" to listen on any
 * address that the server has installed. It cannot be NULL.
 *
 * @param port The port to listen on. It cannot be NULL and it must be
 * a non-zero string.
 *
 * @param error Optional axlError reference where a textual diagnostic
 * will be reported in case of error.
 *
 * @return The function returns the listener socket or -1 if it
 * fails. Optionally the axlError reports the textual especific error
 * found. If the function returns -2 then some parameter provided was
 * found to be NULL.
 */
EXT_DNS_SOCKET     ext_dns_listener_sock_listen      (extDnsCtx           * ctx,
						      extDnsSessionType     type,
						      const char          * host,
						      const char          * port,
						      axlError           ** error)
{

	struct sockaddr_in   sin;
	EXT_DNS_SOCKET        fd;
#if defined(AXL_OS_WIN32)
/*	BOOL                 unit      = axl_true; */
	int                  sin_size  = sizeof (sin);
#else    	
	int                  unit      = 1; 
	socklen_t            sin_size  = sizeof (sin);
#endif	
	int                  backlog   = 0;
	int                  bind_res;

	struct addrinfo      req, *ans;
	int                  ret_val;

	v_return_val_if_fail (ctx,  -2);
	v_return_val_if_fail (host, -2);
	v_return_val_if_fail (port || ext_dns_strlen (port) == 0, -2);

	/* resolve hostname */
	memset (&req, 0, sizeof(struct addrinfo));
	req.ai_flags    = AI_PASSIVE | AI_NUMERICHOST; 
	req.ai_family   = AF_INET;
	req.ai_socktype = SOCK_DGRAM;
	
	/* try to resolve */
	ret_val = getaddrinfo (host, port, &req, &ans);
	if (ret_val != 0) {
		axl_error_report (error, extDnsNameResolvFailure, "Unable to get hostname by calling getaddrinfo");
		return -1;
	} /* end if */

	/* according to type, create a kind of socket */
	if (type == extDnsTcpSession)
		fd = socket (AF_INET, SOCK_STREAM, 0);
	else if (type == extDnsUdpSession)
		fd = socket (AF_INET, SOCK_DGRAM, 0);
	else {
		axl_error_report (error, extDnsProtocolError, "Unsupported session type provided. It must be TCP or UDP");
		return -1;
	}
		
	if (fd <= 2) {
		/* do not allow creating sockets reusing stdin (0),
		   stdout (1), stderr (2) */
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "failed to create listener socket: %d (errno=%d:%s)", fd, errno, ext_dns_errno_get_error (errno));
		axl_error_report (error, extDnsSocketCreationError, 
				  "failed to create listener socket: %d (errno=%d:%s)", fd, errno, ext_dns_errno_get_error (errno));
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
	setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &unit, sizeof (unit));
#endif 

	/* call to bind */
	bind_res = bind(fd, ans->ai_addr,  ans->ai_addrlen);

	/* release addrinfo */
	freeaddrinfo (ans);

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "bind(2) call returned: %d", bind_res);
	if (bind_res == EXT_DNS_SOCKET_ERROR) {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "unable to bind address (port:%s already in use or insufficient permissions). Closing socket: %d", port, fd);
		axl_error_report (error, extDnsBindError, "unable to bind address (port:%s already in use or insufficient permissions). Closing socket: %d", port, fd);
		ext_dns_close_socket (fd);
		return -1;
	}
	
	if (type == extDnsTcpSession) {
		/* get current backlog configuration */
		ext_dns_conf_get (ctx, EXT_DNS_LISTENER_BACKLOG, &backlog);
		
		if (listen (fd, backlog) == EXT_DNS_SOCKET_ERROR) {
			axl_error_report (error, extDnsSocketCreationError, "an error have occur while executing listen");
			return -1;
		} /* end if */

	} /* end if */

	/* notify listener */
	if (getsockname (fd, (struct sockaddr *) &sin, &sin_size) < 0) {
		axl_error_report (error, extDnsNameResolvFailure, "an error have happen while executing getsockname");
		return -1;
	} /* end if */

	/* report and return fd */
	ext_dns_log  (EXT_DNS_LEVEL_DEBUG, "running listener at %s:%d (socket: %d)", inet_ntoa(sin.sin_addr), ntohs (sin.sin_port), fd);
	return fd;
}

axlPointer __ext_dns_listener_new (extDnsListenerData * data)
{
	char               * host          = data->host;
	extDnsSessionType    type          = data->type;
	axl_bool             threaded      = data->threaded;
	char               * str_port      = axl_strdup_printf ("%d", data->port);
	axlPointer           user_data     = data->user_data;
	extDnsSession      * listener      = NULL;
	extDnsCtx          * ctx           = data->ctx;
	extDnsStatus         status        = extDnsOk;
	char               * host_used;
	axlError           * error         = NULL;
	EXT_DNS_SOCKET        fd;
	struct sockaddr_in   sin;

	/* handlers received (may be both null) */
	extDnsListenerReady      on_ready       = data->on_ready;
	extDnsListenerReadyFull  on_ready_full  = data->on_ready_full;
	
	/* free data */
	axl_free (data);

	/* allocate listener */
	fd = ext_dns_listener_sock_listen (ctx, type, host, str_port, &error);
	
	/* unref the host and port value */
	axl_free (str_port);
	axl_free (host);

	/* listener ok */
	/* seems listener to be created, now create the BEEP
	 * session around it */
	listener = ext_dns_session_new_empty (ctx, fd, type, extDnsRoleMasterListener);
	if (listener == NULL) {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "received NULL listener reference, unable to start server");
		return NULL;
	} /* end if */

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "listener reference created (%p, id: %d, socket: %d, role: %d, requested role: %d)", listener, 
		     ext_dns_session_get_id (listener), fd, listener->role, extDnsRoleMasterListener);

	/* handle returned socket or error */
	switch (fd) {
	case -2:
		__ext_dns_session_shutdown_and_record_error (
			listener, extDnsWrongReference, "Failed to start listener because ext_dns_listener_sock_listener reported NULL parameter received");
		break;
	case -1:
		__ext_dns_session_shutdown_and_record_error (
			listener, extDnsProtocolError,"Failed to start listener, ext_dns_listener_sock_listener reported (code: %d): %s",
			axl_error_get_code (error), axl_error_get (error));
		break;
	default:
		/* register the listener socket at the extDns Reader process.  */
		ext_dns_reader_watch_listener (ctx, listener);

		if (threaded) {
			ext_dns_log (EXT_DNS_LEVEL_DEBUG, "doing listener notification (threaded mode)");
			/* notify listener created */
			host_used = ext_dns_support_inet_ntoa (ctx, &sin);
			if (on_ready != NULL) {
				on_ready (host_used, ntohs (sin.sin_port), extDnsOk, "server ready for requests", user_data);
			} /* end if */
			
			if (on_ready_full != NULL) {
				on_ready_full (host_used, ntohs (sin.sin_port), extDnsOk, "server ready for requests", listener, user_data);
			} /* end if */
			axl_free (host_used);
		} /* end if */

		/* the listener reference */
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "returning listener running at %s:%s (non-threaded mode)", 
			     ext_dns_session_get_host (listener), ext_dns_session_get_port (listener));
		return listener;
	} /* end switch */

	/* according to the invocation */
	if (threaded) {
		/* notify error found to handlers */
		if (on_ready != NULL) 
			on_ready      (NULL, 0, status, NULL, user_data);
		if (on_ready_full != NULL) 
			on_ready_full (NULL, 0, status, NULL, NULL, user_data);
	} else {
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "unable to start ext_dns server, unblocking ext_dns_listener_wait");

		/* notify the listener that an error was found
		 * (because the server didn't suply a handler) */
		ext_dns_mutex_lock (&ctx->listener_unlock);
		ext_dns_async_queue_push (ctx->listener_wait_lock, INT_TO_PTR (axl_true));
		ctx->listener_wait_lock = NULL;
		ext_dns_mutex_unlock (&ctx->listener_unlock);
	} /* end if */

	/* unref error */
	axl_error_free (error);

	/* return listener created */
	return listener;
}

/** 
 * @internal Implementation to support listener creation functions ext_dns_listener_new*
 */
extDnsSession * __ext_dns_listener_new_common  (extDnsCtx               * ctx,
						const char              * host,
						int                       port,
						extDnsSessionType         type,
						extDnsListenerReady       on_ready, 
						extDnsListenerReadyFull   on_ready_full,
						axlPointer                user_data)
{
	extDnsListenerData * data;

	/* check context is initialized */
	if (! ext_dns_init_check (ctx))
		return NULL;
	
	/* prepare function data */
	data                = axl_new (extDnsListenerData, 1);
	data->host          = axl_strdup (host);
	data->port          = port;
	data->type          = type;
	data->on_ready      = on_ready;
	data->on_ready_full = on_ready_full;
	data->user_data     = user_data;
	data->ctx           = ctx;
	data->threaded      = (on_ready != NULL) || (on_ready_full != NULL);
	
	/* make request */
	if (data->threaded) {
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "invoking listener_new threaded mode");
		ext_dns_thread_pool_new_task (ctx, (extDnsThreadFunc) __ext_dns_listener_new, data);
		return NULL;
	}

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "invoking listener_new non-threaded mode");
	return __ext_dns_listener_new (data);	
}


/** 
 * @brief Creates a new extDns Listener accepting incoming sessions
 * on the given <b>host:port</b> configuration and over the given protocol type (\ref extDnsSessionType).
 *
 * If user provides an \ref extDnsListenerReady "on_ready" callback,
 * the listener will be notified on it, in a separated thread, once
 * the process has finished. Check \ref extDnsListenerReady handler
 * documentation which is on_ready handler type.
 * 
 * On that notification will also be passed the host and port actually
 * allocated. Think about using as host 0.0.0.0 and port 0. These
 * values will cause to \ref ext_dns_listener_new to allocate the
 * system configured hostname and a random free port. See \ref
 * ext_dns_handlers "this section" for more info about on_ready
 * parameter.
 *
 * Host and port value provided to this function could be unrefered
 * once returning from this function. The function performs a local
 * copy for those values, that are deallocated at the appropriate moment.
 *
 * Keep in mind that you can actually call several times to this
 * function before calling to \ref ext_dns_ctx_wait, to make your
 * process to be able to accept sessions from several ports and host
 * names at the same time.
 *
 * While providing the port information, make sure your process will
 * have enough rights to allocate the port provided. Usually, ports
 * from 1 to 1024 are reserved to listener programms that runs with
 * priviledges.
 *
 * In the case the optional handler <b>on_ready</b> is not provided,
 * the function will return a reference to the \ref extDnsSession
 * representing the listener created. 
 *
 * In the case the <b>on_ready</b> handler is provided, the function
 * will return NULL.
 *
 * Here is an example to start a ext_dns listener server:
 *
 * @param ctx The context where the operation will be performed.
 *
 * @param host The host to listen on.
 *
 * @param port The port to listen on.
 *
 * @param type The session type that is going to be created.
 *
 * @param on_ready A optional callback to get a notification when
 * ext_dns listener is ready to accept requests.
 *
 * @param user_data A user defined pointer to be passed in to
 * <i>on_ready</i> handler.
 *
 * @return The listener session created (represented by a \ref
 * extDnsSession reference). You must use \ref ext_dns_session_is_ok to check if the server was started.
 * 
 * <b>NOTE:</b> the reference returned is only owned by the ext_dns
 * engine. This is not the case of \ref ext_dns_listener_new where
 * the caller acquires automatically a reference to the session (as
 * well as the ext_dns engine). 
 * 
 * In this case, if your intention is to keep a reference for later
 * operations, you must call to \ref ext_dns_session_ref to avoid
 * losing the reference if the system drops the session. In the
 * same direction, you can't call to \ref ext_dns_session_close if
 * you don't own the reference returned by this function.
 *
 */
extDnsSession * ext_dns_listener_new (extDnsCtx           * ctx,
				      const char          * host, 
				      const char          * port, 
				      extDnsSessionType     type,
				      extDnsListenerReady   on_ready, 
				      axlPointer            user_data)
{
	/* call to int port API */
	return __ext_dns_listener_new_common (ctx, host, __ext_dns_listener_get_port (port), type, on_ready, NULL, user_data);
}

/** 
 * @brief Creates a new listener, allowing to get the session that
 * represents the listener created with the optional handler (\ref
 * extDnsListenerReadyFull).
 *
 * This function provides the same functionality than \ref
 * ext_dns_listener_new and \ref ext_dns_listener_new2 but allowing to
 * get the session (\ref extDnsSession) representing the
 * listener, by configuring the optional handler on_ready_full (\ref
 * extDnsListenerReadyFull).
 *
 * @param ctx The context where the operation will be performed.
 * 
 * @param host The host to listen on.
 *
 * @param port The port to listen on.
 *
 * @param type The type of session to be created.
 *
 * @param on_ready_full A optional callback to get a notification when
 * ext_dns listener is ready to accept requests.
 *
 * @param user_data A user defined pointer to be passed in to <i>on_ready</i> handler.
 *
 * @return The listener session created, or NULL if the optional
 * handler is provided (on_ready).
 *
 * <b>NOTE:</b> the reference returned is only owned by the extDns
 * engine. This is not the case of \ref ext_dns_listener_new where
 * the caller acquires automatically a reference to the session (as
 * well as the ext_dns engine). 
 * 
 * In this case, if your intention is to own a reference to the
 * session for later operations, you must call to \ref ext_dns_session_ref to avoid losing the reference if the system
 * drops the session. In the same direction, you can't call to \ref ext_dns_session_close if you don't own the reference returned by this function.
 * 
 */
extDnsSession * ext_dns_listener_new_full  (extDnsCtx           * ctx,
					    const char          * host,
					    const char          * port,
					    extDnsSessionType     type,
					    extDnsListenerReadyFull on_ready_full, 
					    axlPointer user_data)
{
	/* call to int port API */
	return __ext_dns_listener_new_common (ctx, host, __ext_dns_listener_get_port (port), type, NULL, on_ready_full, user_data);
}

/** 
 * @brief Creates a new extDns Listener accepting incoming sessions on
 * the given <b>host:port</b> configuration, receiving the port
 * configuration as an integer value.
 *
 * See \ref ext_dns_listener_new for more information. 
 *
 * @param ctx The context where the operation will be performed.
 * 
 * @param host The host to listen to.
 *
 * @param port The port to listen to. Value defined for the port must be between 0 up to 65536.
 *
 * @param type The session type that is going to be created.
 *
 * @param on_ready A optional notify callback to get when ext_dns
 * listener is ready to perform replies.
 *
 * @param user_data A user defined pointer to be passed in to
 * <i>on_ready</i> handler.
 *
 * @return The listener session created, or NULL if the optional
 * handler is provided (on_ready).
 *
 * <b>NOTE:</b> the reference returned is only owned by the ext_dns
 * engine. This is not the case of \ref ext_dns_listener_new where
 * the caller acquires automatically a reference to the session (as
 * well as the ext_dns engine).
 * 
 * In this case, if your intention is to keep a reference for later
 * operations, you must call to \ref ext_dns_session_ref to avoid
 * losing the reference if the system drops the session. In the
 * same direction, you can't call to \ref ext_dns_session_close if
 * you don't own the reference returned by this function.
 * 
 */
extDnsSession * ext_dns_listener_new2    (extDnsCtx           * ctx,
					  const char          * host,
					  int                   port,
					  extDnsSessionType     type,
					  extDnsListenerReady   on_ready, 
					  axlPointer            user_data)
{

	/* call to common API */
	return __ext_dns_listener_new_common (ctx, host, port, type, on_ready, NULL, user_data);
}

/** 
 * @brief Allows to create a new \ref extDnsSession from a socket that is
 * already connected.
 *
 * @param ctx     The context where the operation will be performed.
 *
 * @param socket  An already connected socket.  
 *
 * @param type    The type of session is going to be created reusing the provided socket.
 *
 * @param role    The role to be set to the session being created.
 * 
 * @return a newly allocated \ref extDnsSession. 
 */
extDnsSession * ext_dns_session_new_empty  (extDnsCtx        * ctx, 
					    EXT_DNS_SOCKET     socket, 
					    extDnsSessionType  type,
					    extDnsPeerRole     role)
{
	/* creates a new session */
	return ext_dns_session_new_empty_from_session (ctx, socket, NULL, type, role);
}

/**
 * @internal Function to init all mutex associated to this particular
 * session 
 */
void __ext_dns_session_init_mutex (extDnsSession * session)
{
	/* inits all mutex associated to the session provided. */
	ext_dns_mutex_create (&session->ref_mutex);
	ext_dns_mutex_create (&session->op_mutex);
	ext_dns_mutex_create (&session->pending_errors_mutex);
	return;
}

/** 
 * @internal
 *
 * Internal function used to create new session starting from a
 * socket, and optional from internal data stored on the provided
 * session. It is supposed that the socket provided belongs to the
 * session provided.
 *
 * The function tries to creates a new session, using the socket
 * provided. The function also keeps all internal session that for
 * the new session creates extracting that data from the session
 * reference provided. 
 *
 * @param ctx The context where the operation will be performed.
 * 
 * @param socket The socket to be used for the new session.
 *
 * @param session The session where the user space data will be
 * extracted. This reference is optional.
 *
 * @param type The session type (TCP, UDP...).
 *
 * @param role The session role to be set to this function.
 * 
 * @return A newly created session, using the provided data, that
 * must be deallocated using \ref ext_dns_session_close.
 */
extDnsSession * ext_dns_session_new_empty_from_session (extDnsCtx          * ctx,
							EXT_DNS_SOCKET       socket,
							extDnsSession      * __session,
							extDnsSessionType    type,
							extDnsPeerRole       role)
{
	extDnsSession   * session;


	/* create session object without setting socket (this is
	 * done by ext_dns_session_set_sock) */
	session                     = axl_new (extDnsSession, 1);
	EXT_DNS_CHECK_REF (session, NULL);

	session->ctx                = ctx;
	ext_dns_ctx_ref2 (ctx, "new session"); /* acquire a reference to context */
	session->id                 = __ext_dns_session_get_next_id (ctx);

	/* init hash data */
	ext_dns_mutex_create (&session->data_mutex);

	/* set the session type */
	session->type               = type;

	session->is_connected       = axl_true;
	session->ref_count          = 1;

	/* call to init all mutex associated to this particular session */
	__ext_dns_session_init_mutex (session);

	/* creates the user space data */
	if (__session != NULL) {
		
		/* transfer hash used by previous session into the new one */
		session->data       = __session->data;
		/* creates a new hash to keep the session internal state consistent */
		__session->data     = axl_hash_new_full (axl_hash_string, axl_hash_equal_string, 10);
	} else 
		session->data       = axl_hash_new_full (axl_hash_string, axl_hash_equal_string, 10);

	/* establish the session role and its initial next channel
	 * number available. */
	session->role  = role;

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Role configured for new connection %p: %d (%d)", session, session->role, extDnsRoleMasterListener);

	/* set socket provided (do not allow stdin(0), stdout(1), stderr(2) */
	if (socket > 2) {
		if (! ext_dns_session_set_socket (session, socket, NULL, NULL)) {
			ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "failed to configure socket associated to session");
			ext_dns_session_unref (session, "ext_dns_session_new_empty_from_session");
			return NULL;
		} /* end if */
	} else {
		/* set a wrong socket session in the case a not
		   proper value is received */
		ext_dns_log (EXT_DNS_LEVEL_WARNING, "received wrong socket fd, setting invalid fd beacon: -1");
		session->session = -1;
	} /* end if */

	return session;	
}


void               __ext_dns_session_notify_bad_request (extDnsCtx      * ctx,
							 extDnsSession  * session,
							 const char     * source_address,
							 int              source_port,
							 const char     * buffer,
							 int              buffer_size,
							 const char     * reason,
							 ...)
{
	va_list            args;
	char             * _msg;

	/* prepare message */
	va_start (args, reason);
	_msg = axl_strdup_printfv (reason, args);
	va_end (args);

	/* log and release message */
	ext_dns_log (EXT_DNS_LEVEL_WARNING, _msg);

	/* check incoming data received */
	if (session == NULL || session->on_bad_request == NULL) {
		axl_free (_msg);
		return;
	}

	/* call on handler defined */
	session->on_bad_request (ctx, session, source_address, source_port, buffer, buffer_size, _msg, session->on_bad_request_data);

	/* release message */
	axl_free (_msg);

	
	
	return;
}

axl_bool _ext_dns_session_track_pending_replies (extDnsCtx * ctx,
						 axlPointer  user_data,
						 axlPointer  user_data2)
{
	int                       stamp;
	extDnsSession           * session;
	int                       session_stamp;
	axlPointer                data;
	extDnsOnMessageReceived   on_message;

	if (axl_hash_items (ctx->pending_hash) == 0)
		return axl_false; /* nothing to check, don't stop checking */

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Tracking %d pending replies to see if they timed out", axl_hash_items (ctx->pending_hash));

	/* get current stamp */
	stamp = time (NULL);

	/* lock mutex */
	ext_dns_mutex_lock (&ctx->ref_mutex);
	
	/* init pending cursor if it wasn't */
	if (! ctx->pending_cursor)
		ctx->pending_cursor = axl_hash_cursor_new (ctx->pending_hash);

	/* check all items current installed */
	axl_hash_cursor_first (ctx->pending_cursor);
	while (axl_hash_cursor_has_item (ctx->pending_cursor)) {

		/* get session and stamp */
		session       = axl_hash_cursor_get_key (ctx->pending_cursor);
		session_stamp = PTR_TO_INT (axl_hash_cursor_get_value (ctx->pending_cursor));

		if ((session_stamp + 3) < stamp) {
			ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Found query session <%p> timed out after %d seconds, notifying failure", session, stamp - session_stamp);

			/* call to notify error */
			on_message = session->on_message;
			data       = session->on_message_data;
			session->on_message = NULL;
			session->on_message_data = NULL;

			/* unlock mutex */
			ext_dns_mutex_unlock (&ctx->ref_mutex);
			
			if (on_message) 
				on_message (ctx, session, NULL, 0, NULL, data);

			/* close listener */
			ext_dns_session_close (session);			

			/* flag this function to notify failure by reader when it reaches it */
			session->notify_failure = axl_true;

			/* lock mutex */
			ext_dns_mutex_lock (&ctx->ref_mutex);

			/* remove from pending hash */
			axl_hash_cursor_remove (ctx->pending_cursor);
			continue;
		} /* end if */

		/* next cursor */
		axl_hash_cursor_next (ctx->pending_cursor);
	}
	

	/* unlock */
	ext_dns_mutex_unlock (&ctx->ref_mutex);

	return axl_false; /* do not remove the event */
}

void _ext_dns_session_record_pending_reply (extDnsCtx * ctx, extDnsSession * session)
{
	/* lock mutex */
	ext_dns_mutex_lock (&ctx->ref_mutex);

	/* init pending hash (it if wasn't) */
	if (ctx->pending_hash == NULL) {
		/* init hash */
		ctx->pending_hash = axl_hash_new (axl_hash_int, axl_hash_equal_int);

		/* init tracking event */
		ext_dns_thread_pool_new_event (ctx, 1000000, _ext_dns_session_track_pending_replies, NULL, NULL);
	}

	/* insert into the hash current stamp and the session */
	axl_hash_insert (ctx->pending_hash, session, INT_TO_PTR (time (NULL)));

	/* unlock */
	ext_dns_mutex_unlock (&ctx->ref_mutex);
	
	return;
}

/** 
 * @internal Function used to check if a session is in the waiting
 * reply hash to remove it.
 */
void _ext_dns_session_remove_from_pending_hash (extDnsCtx * ctx, extDnsSession * session)
{
	if (ctx == NULL || session == NULL)
		return;

	/* lock mutex */
	ext_dns_mutex_lock (&ctx->ref_mutex);

	/* remove */
	axl_hash_remove (ctx->pending_hash, session);

	/* unlock */
	ext_dns_mutex_unlock (&ctx->ref_mutex);

	return;
}

/* @} */
