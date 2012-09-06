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
/* include local private definitions */
#include <ext-dns-private.h>

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
 * \brief Allows to change connection semantic to nonblocking.
 *
 * Sets a connection to be non-blocking while sending and receiving
 * data. This function should not be useful for extDns Library
 * consumers.
 * 
 * @param connection the connection to set as nonblocking.
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
 * @brief Returns the actual host this session is connected to.
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
 * \ref ext_dns_session_new and \ref ext_dns_session_close (which
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
	
	/* release reference to context */
	ext_dns_ctx_unref2 (&session->ctx, "end session");

	/* free session */
	axl_free (session);

	return;
}
