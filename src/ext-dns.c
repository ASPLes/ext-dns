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
#include <ext-dns-private.h>
#include <signal.h>

/* Ugly hack to have access to vsnprintf function (secure form of
 * vsprintf where the output buffer is limited) but unfortunately is
 * not available in ANSI C. This is only required when compile ext_dns
 * with log support */
#if defined(ENABLE_EXT_DNS_LOG)
int vsnprintf(char *str, size_t size, const char *format, va_list ap);
#endif

#if !defined(AXL_OS_WIN32)
void __ext_dns_sigpipe_do_nothing (int _signal)
{
	/* do nothing sigpipe handler to be able to manage EPIPE error
	 * returned by write. read calls do not fails because we use
	 * the ext_dns reader process that is waiting for changes over
	 * a connection and that changes include remote peer
	 * closing. So, EPIPE (or receive SIGPIPE) can't happen. */
	

	/* the following line is to ensure ancient glibc version that
	 * restores to the default handler once the signal handling is
	 * executed. */
	signal (SIGPIPE, __ext_dns_sigpipe_do_nothing);
	return;
}
#endif


/** 
 * @brief Allows to init a ext-DNS context.
 * @param ctx The context to initiate.
 *
 * @return axl_true if the context was initiated, otherwise axl_false
 * is returned.
 */
axl_bool ext_dns_init_ctx (extDnsCtx * ctx)
{
	int          thread_num;
	int          soft_limit;

	v_return_val_if_fail (ctx, axl_false);

	/**** ext_dns_io.c: init io module */
	ext_dns_io_init (ctx);

	/**** ext_dns.c: init global mutex *****/
	ext_dns_mutex_create (&ctx->listener_mutex);
	ext_dns_mutex_create (&ctx->listener_unlock);
	ext_dns_mutex_create (&ctx->exit_mutex);

#if ! defined(AXL_OS_WIN32)
	/* install sigpipe handler */
	signal (SIGPIPE, __ext_dns_sigpipe_do_nothing);
#endif

#if defined(AXL_OS_WIN32)
	/* init winsock API */
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "init winsocket for windows");
	if (! ext_dns_win32_init (ctx))
		return axl_false;
#endif

	/* init axl library */
	axl_init ();

	/* before starting, check if we are using select(2) system
	 * call method, to adequate the number of sockets that can
	 * *really* handle the FD_* function family, to the number of
	 * sockets that is allowed to handle the process. This is to
	 * avoid race conditions cause to properly create a
	 * connection, which is later not possible to handle at the
	 * select(2) I/O subsystem. */
	if (ext_dns_io_waiting_get_current (ctx) == EXT_DNS_IO_WAIT_SELECT) {
		/* now check if the current process soft limit is
		 * allowed to handle more connection than
		 * EXT_DNS_FD_SETSIZE */
		ext_dns_conf_get (ctx, EXT_DNS_SOFT_SOCK_LIMIT, &soft_limit);
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "select mechanism selected, reconfiguring current socket limit: soft_limit=%d > %d..",
			    soft_limit, EXT_DNS_FD_SETSIZE);
		if (soft_limit > (EXT_DNS_FD_SETSIZE - 1)) {
			/* decrease the limit to avoid funny
			 * problems. it is not required to be
			 * privilege user to run the following
			 * command. */
			ext_dns_conf_set (ctx, EXT_DNS_SOFT_SOCK_LIMIT, (EXT_DNS_FD_SETSIZE - 1), NULL);
			ext_dns_log (EXT_DNS_LEVEL_WARNING, 
				    "found select(2) I/O configured, which can handled up to %d fds, reconfigured process with that value",
				    EXT_DNS_FD_SETSIZE -1);
		} /* end if */
	} 

	/* init reader subsystem */
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "starting ext_dns reader..");
	if (! ext_dns_reader_run (ctx))
		return axl_false;
	
	/* init thread pool (for query receiving) */
	thread_num = ext_dns_thread_pool_get_num ();
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "starting ext_dns thread pool: (%d threads the pool have)..",
		    thread_num);
	ext_dns_thread_pool_init (ctx, thread_num);

	/* flag this context as initialized */
	ctx->initialized = axl_true;

	/* register the ext_dns exit function */
	return axl_true;
}

/** 
 * @brief Terminates the ext-dns library execution on the provided
 * context.
 *
 * Stops all internal ext-dns process and all allocated resources
 * associated to the context. It also close all channels for all
 * connection that where not closed until call this function.
 *
 * This function is reentrant, allowing several threads to call \ref
 * ext_dns_exit_ctx function at the same time. Only one thread will
 * actually release resources allocated.
 *
 * @param ctx The context to terminate. The function do not dealloc
 * the context provided. 
 *
 * @param free_ctx Allows to signal the function if the context
 * provided must be deallocated (by calling to \ref ext_dns_ctx_free).
 */
void     ext_dns_exit_ctx             (extDnsCtx * ctx, 
				       axl_bool    free_ctx)
{
	int            iterator;
	axlDestroyFunc func;

	/* check context is initialized */
	if (! ext_dns_init_check (ctx))
		return;

	/* check if the library is already started */
	if (ctx == NULL || ctx->exit)
		return;

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "shutting down ext_dns library, extDnsCtx %p", ctx);

	ext_dns_mutex_lock (&ctx->exit_mutex);
	if (ctx->exit) {
		ext_dns_mutex_unlock (&ctx->exit_mutex);
		return;
	}
	/* flag other waiting functions to do nothing */
	ext_dns_mutex_lock (&ctx->ref_mutex);
	ctx->exit = axl_true;
	ext_dns_mutex_unlock (&ctx->ref_mutex);
	
	/* unlock */
	ext_dns_mutex_unlock  (&ctx->exit_mutex);

	/* flag the thread pool to not accept more jobs */
	ext_dns_thread_pool_being_closed (ctx);

	/* stop ext_dns writer */
	/* ext_dns_writer_stop (); */

	/* stop ext_dns reader process */
	ext_dns_reader_stop (ctx);

#if defined(AXL_OS_WIN32)
	WSACleanup ();
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "shutting down WinSock2(tm) API");
#endif

	/* clean up ext_dns modules */
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "shutting down ext_dns xml subsystem");

	/* Cleanup function for the XML library. */
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "shutting down xml library");
	axl_end ();

	/* unlock listeners */
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "unlocking ext_dns listeners");
	ext_dns_ctx_unlock (ctx);

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "ext_dns library stopped");

	/* stop the ext_dns thread pool: 
	 * 
	 * In the past, this call was done, however, it is showed that
	 * user applications on top of ext_dns that wants to handle
	 * signals, emitted to all threads running (including the pool)
	 * causes many non-easy to solve problem related to race
	 * conditions.
	 * 
	 * At the end, to release the thread pool is not a big
	 * deal. */
	ext_dns_thread_pool_exit (ctx); 

	/* destroy global mutex */
	ext_dns_mutex_destroy (&ctx->listener_mutex);
	ext_dns_mutex_destroy (&ctx->listener_unlock);

	/* lock/unlock to avoid race condition */
	ext_dns_mutex_lock  (&ctx->exit_mutex);
	ext_dns_mutex_unlock  (&ctx->exit_mutex);
	ext_dns_mutex_destroy (&ctx->exit_mutex);

	/* call to activate ctx cleanups */
	if (ctx->cleanups) {
		/* acquire lock */
		ext_dns_mutex_lock (&ctx->ref_mutex);

		iterator = 0;
		while (iterator < axl_list_length (ctx->cleanups)) {
			/* get clean up function */
			func = axl_list_get_nth (ctx->cleanups, iterator);

			/* call to clean */
			ext_dns_mutex_unlock (&ctx->ref_mutex);
			func (ctx);
			ext_dns_mutex_lock (&ctx->ref_mutex);

			/* next iterator */
			iterator++;
		} /* end while */

		/* terminate list */
		axl_list_free (ctx->cleanups);
		ctx->cleanups = NULL; 

		/* release lock */
		ext_dns_mutex_unlock (&ctx->ref_mutex);
	} /* end if */

	/* release the ctx */
	if (free_ctx)
		ext_dns_ctx_free2 (ctx, "end ctx");

	return;
}

/** 
 * @brief Allows to get a ext_dns configuration, providing a valid
 * ext_dns item.
 * 
 * The function requires the configuration item that is required and a
 * valid reference to a variable to store the result. 
 *
 * @param ctx The context where the operation will be performed.
 * 
 * @param item The configuration item that is being returned.
 *
 * @param value The variable reference required to fill the result.
 * 
 * @return The function returns axl_true if the configuration item is
 * returned. 
 */
axl_bool       ext_dns_conf_get             (extDnsCtx      * ctx,
					    extDnsConfItem   item, 
					    int            * value)
{
#if defined(AXL_OS_WIN32)

#elif defined(AXL_OS_UNIX)
	/* variables for nix world */
	struct rlimit _limit;
#endif	
	/* do common check */
	v_return_val_if_fail (ctx,   axl_false);
	v_return_val_if_fail (value, axl_false);

	/* no context, no configuration */
	if (ctx == NULL)
		return axl_false;

	/* clear value received */
	*value = 0;

#if defined (AXL_OS_WIN32)
#elif defined(AXL_OS_UNIX)
	/* clear not filled result */
	_limit.rlim_cur = 0;
	_limit.rlim_max = 0;	
#endif

	switch (item) {
	case EXT_DNS_SOFT_SOCK_LIMIT:
#if defined (AXL_OS_WIN32)
		/* return the soft sock limit */
		*value = ctx->__ext_dns_conf_soft_sock_limit;
		return axl_true;
#elif defined (AXL_OS_UNIX)
		/* get the limit */
		if (getrlimit (RLIMIT_NOFILE, &_limit) != 0) {
			ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "failed to get current soft limit: %s", ext_dns_errno_get_last_error ());
			return axl_false;
		} /* end if */

		/* return current limit */
		*value = _limit.rlim_cur;
		return axl_true;
#endif		
	case EXT_DNS_HARD_SOCK_LIMIT:
#if defined (AXL_OS_WIN32)
		/* return the hard sockt limit */
		*value = ctx->__ext_dns_conf_hard_sock_limit;
		return axl_true;
#elif defined (AXL_OS_UNIX)
		/* get the limit */
		if (getrlimit (RLIMIT_NOFILE, &_limit) != 0) {
			ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "failed to get current soft limit: %s", ext_dns_errno_get_last_error ());
			return axl_false;
		} /* end if */

		/* return current limit */
		*value = _limit.rlim_max;
		return axl_true;
#endif		
	case EXT_DNS_LISTENER_BACKLOG:
		/* return current backlog value */
		*value = ctx->backlog;
		return axl_true;
	case EXT_DNS_SKIP_THREAD_POOL_WAIT:
		*value = ctx->skip_thread_pool_wait;
		return axl_true;
	default:
		/* configuration found, return axl_false */
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "found a requested for a non existent configuration item");
		return axl_false;
	} /* end if */

	return axl_true;
}

/** 
 * @brief Allows to configure the provided item, with either the
 * integer or the string value, according to the item configuration
 * documentation.
 * 
 * @param ctx The context where the configuration will take place.
 *
 * @param item The item configuration to be set.
 *
 * @param value The integer value to be configured if applies.
 *
 * @param str_value The string value to be configured if applies.
 * 
 * @return axl_true if the configuration was done properly, otherwise
 * axl_false is returned.
 */
axl_bool       ext_dns_conf_set             (extDnsCtx      * ctx,
					    extDnsConfItem   item, 
					    int              value, 
					    const char     * str_value)
{
#if defined(AXL_OS_WIN32)

#elif defined(AXL_OS_UNIX)
	/* variables for nix world */
	struct rlimit _limit;
#endif	
	/* do common check */
	v_return_val_if_fail (ctx,   axl_false);
	v_return_val_if_fail (value, axl_false);

#if defined (AXL_OS_WIN32)
#elif defined(AXL_OS_UNIX)
	/* clear not filled result */
	_limit.rlim_cur = 0;
	_limit.rlim_max = 0;	
#endif

	switch (item) {
	case EXT_DNS_SOFT_SOCK_LIMIT:
#if defined (AXL_OS_WIN32)
		/* check soft limit received */
		if (value > ctx->__ext_dns_conf_hard_sock_limit)
			return axl_false;

		/* configure new soft limit */
		ctx->__ext_dns_conf_soft_sock_limit = value;
		return axl_true;
#elif defined (AXL_OS_UNIX)
		/* get the limit */
		if (getrlimit (RLIMIT_NOFILE, &_limit) != 0) {
			ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "failed to get current soft limit: %s", ext_dns_errno_get_last_error ());
			return axl_false;
		} /* end if */

		/* configure new value */
		_limit.rlim_cur = value;

		/* set new limit */
		if (setrlimit (RLIMIT_NOFILE, &_limit) != 0) {
			ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "failed to set current soft limit: %s", ext_dns_errno_get_last_error ());
			return axl_false;
		} /* end if */

		return axl_true;
#endif		
	case EXT_DNS_HARD_SOCK_LIMIT:
#if defined (AXL_OS_WIN32)
		/* current it is not possible to configure hard sock
		 * limit */
		return axl_false;
#elif defined (AXL_OS_UNIX)
		/* get the limit */
		if (getrlimit (RLIMIT_NOFILE, &_limit) != 0) {
			ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "failed to get current soft limit: %s", ext_dns_errno_get_last_error ());
			return axl_false;
		} /* end if */

		/* configure new value */
		_limit.rlim_max = value;
		
		/* if the hard limit gets lower than the soft limit,
		 * make the lower limit to be equal to the hard
		 * one. */
		if (_limit.rlim_max < _limit.rlim_cur)
			_limit.rlim_max = _limit.rlim_cur;

		/* set new limit */
		if (setrlimit (RLIMIT_NOFILE, &_limit) != 0) {
			ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "failed to set current hard limit: %s", ext_dns_errno_get_last_error ());
			return axl_false;
		} /* end if */
		
		return axl_true;
#endif		
	case EXT_DNS_LISTENER_BACKLOG:
		/* return current backlog value */
		ctx->backlog = value;
		return axl_true;

	case EXT_DNS_SKIP_THREAD_POOL_WAIT:
		ctx->skip_thread_pool_wait = value;
		return axl_true;
	default:
		/* configuration found, return axl_false */
		ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "found a requested for a non existent configuration item");
		return axl_false;
	} /* end if */

	return axl_true;
}

/** 
 * @brief Performs a timeval substract leaving the result in
 * (result). Subtract the `struct timeval' values a and b, storing the
 * result in result.  
 *
 * @param a First parameter to substract
 *
 * @param b Second parameter to substract
 *
 * @param result Result variable. Do no used a or b to place the
 * result.
 *
 * @return 1 if the difference is negative, otherwise 0 (operations
 * implemented is a - b).
 */ 
int     ext_dns_timeval_substract                  (struct timeval * a, 
						    struct timeval * b,
						    struct timeval * result)
{
	/* Perform the carry for the later subtraction by updating
	 * y. */
	if (a->tv_usec < b->tv_usec) {
		int nsec = (b->tv_usec - a->tv_usec) / 1000000 + 1;
		b->tv_usec -= 1000000 * nsec;
		b->tv_sec += nsec;
	}

	if (a->tv_usec - b->tv_usec > 1000000) {
		int nsec = (a->tv_usec - b->tv_usec) / 1000000;
		b->tv_usec += 1000000 * nsec;
		b->tv_sec -= nsec;
	}
	
	/* get the result */
	result->tv_sec = a->tv_sec - b->tv_sec;
	result->tv_usec = a->tv_usec - b->tv_usec;
     
       /* return 1 if result is negative. */
       return a->tv_sec < b->tv_sec;	
}

/** 
 * @brief Allows to check if ext-dns engine started on the provided
 * context is finishing (a call to \ref ext_dns_exit_ctx was done).
 *
 * @param ctx The context to check if it is exiting.
 *
 * @return axl_true in the case the context is finished, otherwise
 * axl_false is returned. The function also returns axl_false when
 * NULL reference is received.
 */
axl_bool ext_dns_is_exiting           (extDnsCtx * ctx)
{
	axl_bool result;
	if (ctx == NULL)
		return axl_false;
	ext_dns_mutex_lock (&ctx->ref_mutex);
	result = ctx->exit;
	ext_dns_mutex_unlock (&ctx->ref_mutex);
	return result;
}

/** 
 * @brief Allows to check if the provided extDnsCtx is initialized
 * (\ref ext_dns_init_ctx).
 * @param ctx The context to be checked for initialization.
 * @return axl_true if the context was initialized, otherwise axl_false is returned.
 */
axl_bool ext_dns_init_check (extDnsCtx * ctx)
{
	if (ctx == NULL || ! ctx->initialized) {
		return axl_false;
	}
	return axl_true;
}

/** 
 * @brief Allows to get current status for log debug info to console.
 * 
 * @param ctx The context that is required to return its current log
 * activation configuration.
 * 
 * @return axl_true if console debug is enabled. Otherwise axl_false.
 */
axl_bool      ext_dns_log_is_enabled (extDnsCtx * ctx)
{
#ifdef ENABLE_EXT_DNS_LOG	
	/* no context, no log */
	if (ctx == NULL)
		return axl_false;

	/* check if the debug function was already checked */
	if (! ctx->debug_checked) {
		/* not checked, get the value and flag as checked */
		ctx->debug         = ext_dns_support_getenv_int ("EXT_DNS_DEBUG") > 0;
		ctx->debug_checked = axl_true;
	} /* end if */

	/* return current status */
	return ctx->debug;

#else
	return axl_false;
#endif
}

/** 
 * @brief Allows to get current status for second level log debug info
 * to console.
 *
 * @param ctx The context where the operation will be performed.
 * 
 * @return axl_true if console debug is enabled. Otherwise axl_false.
 */
axl_bool      ext_dns_log2_is_enabled (extDnsCtx * ctx)
{
#ifdef ENABLE_EXT_DNS_LOG	

	/* no context, no log */
	if (ctx == NULL)
		return axl_false;

	/* check if the debug function was already checked */
	if (! ctx->debug2_checked) {
		/* not checked, get the value and flag as checked */
		ctx->debug2         = ext_dns_support_getenv_int ("EXT_DNS_DEBUG2") > 0;
		ctx->debug2_checked = axl_true;
	} /* end if */

	/* return current status */
	return ctx->debug2;

#else
	return axl_false;
#endif
}

/** 
 * @brief Enable console ext_dns log.
 *
 * You can also enable log by setting EXT_DNS_DEBUG environment
 * variable to 1.
 * 
 * @param ctx The context where the operation will be performed.
 *
 * @param status axl_true enable log, axl_false disables it.
 */
void     ext_dns_log_enable       (extDnsCtx * ctx, axl_bool      status)
{
#ifdef ENABLE_EXT_DNS_LOG	
	/* no context, no log */
	if (ctx == NULL)
		return;

	ctx->debug         = status;
	ctx->debug_checked = axl_true;
	return;
#else
	/* just return */
	return;
#endif
}

/** 
 * @brief Enable console second level ext_dns log.
 * 
 * You can also enable log by setting EXT_DNS_DEBUG2 environment
 * variable to 1.
 *
 * Activating second level debug also requires to call to \ref
 * ext_dns_log_enable (axl_true). In practical terms \ref
 * ext_dns_log_enable (axl_false) disables all log reporting even
 * having \ref ext_dns_log2_enable (axl_true) enabled.
 * 
 * @param ctx The context where the operation will be performed.
 *
 * @param status axl_true enable log, axl_false disables it.
 */
void     ext_dns_log2_enable       (extDnsCtx * ctx, axl_bool      status)
{
#ifdef ENABLE_EXT_DNS_LOG	
	/* no context, no log */
	if (ctx == NULL)
		return;

	ctx->debug2 = status;
	ctx->debug2_checked = axl_true;
	return;
#else
	/* just return */
	return;
#endif
}


/** 
 * @brief Allows to check if the color log is currently enabled.
 *
 * @param ctx The context where the operation will be performed.
 * 
 * @return axl_true if enabled, axl_false if not.
 */
axl_bool      ext_dns_color_log_is_enabled (extDnsCtx * ctx)
{
#ifdef ENABLE_EXT_DNS_LOG	
	/* no context, no log */
	if (ctx == NULL)
		return axl_false;
	if (! ctx->debug_color_checked) {
		ctx->debug_color_checked = axl_true;
		ctx->debug_color         = ext_dns_support_getenv_int ("EXT_DNS_DEBUG_COLOR") > 0;
	} /* end if */

	/* return current result */
	return ctx->debug_color;
#else
	/* always return axl_false */
	return axl_false;
#endif
	
}


/** 
 * @brief Enable console color log. 
 *
 * Note that this doesn't enable logging, just selects color messages if
 * logging is already enabled, see ext_dns_log_enable().
 *
 * This is mainly useful to hunt messages using its color: 
 *  - red:  errors, critical 
 *  - yellow: warnings
 *  - green: info, debug
 *
 * You can also enable color log by setting EXT_DNS_DEBUG_COLOR
 * environment variable to 1.
 * 
 * @param ctx The context where the operation will be performed.
 *
 * @param status axl_true enable color log, axl_false disables it.
 */
void     ext_dns_color_log_enable (extDnsCtx * ctx, axl_bool      status)
{

#ifdef ENABLE_EXT_DNS_LOG
	/* no context, no log */
	if (ctx == NULL)
		return;
	ctx->debug_color_checked = status;
	ctx->debug_color = status;
	return;
#else
	return;
#endif
}

/** 
 * @brief Allows to configure which levels will be filtered from log
 * output. This can be useful to only show debug, warning or critical
 * messages (or any mix).
 *
 * For example, to only show critical, pass filter_string = "debug,
 * warning". To show warnings and criticals, pass filter_string =
 * "debug".
 *
 * To disable any filtering, use filter_string = NULL.
 *
 * @param ctx The ext_dns context that will be configured with a log filter.
 *
 * @param filter_string The filter string to be used. You can separate
 * allowed values as you wish. Allowed filter items are: debug,
 * warning, critical.
 *
 */
void     ext_dns_log_filter_level (extDnsCtx * ctx, const char * filter_string)
{
	v_return_if_fail (ctx);

	/* set that debug filter was configured */
	ctx->debug_filter_checked = axl_true;

	/* enable all levels */
	if (filter_string == NULL) {
		ctx->debug_filter_is_enabled = axl_false;
		return;
	} /* end if */

	/* add each filter bit */
	if (strstr (filter_string, "debug"))
		ctx->debug_filter |= EXT_DNS_LEVEL_DEBUG;
	if (strstr (filter_string, "warning"))
		ctx->debug_filter |= EXT_DNS_LEVEL_WARNING;
	if (strstr (filter_string, "critical"))
		ctx->debug_filter |= EXT_DNS_LEVEL_CRITICAL;

	/* set as enabled */
	ctx->debug_filter_is_enabled = axl_true;
	return;
}


/** 
 * @brief Allows to check if current EXT_DNS_DEBUG_FILTER is enabled. 
 * @param ctx The context where the check will be implemented.
 *
 * @return axl_true if log filtering is enabled, otherwise axl_false
 * is returned.
 */ 
axl_bool    ext_dns_log_filter_is_enabled (extDnsCtx * ctx)
{
	char * value;
	v_return_val_if_fail (ctx, axl_false);
	if (! ctx->debug_filter_checked) {
		/* set as checked */
		ctx->debug_filter_checked = axl_true;
		value = ext_dns_support_getenv ("EXT_DNS_DEBUG_FILTER");
		ext_dns_log_filter_level (ctx, value);
		axl_free (value);
	}

	/* return current status */
	return ctx->debug_filter_is_enabled;
}

/** 
 * @brief Allows to configure an application handler that will be
 * called for each log produced by the ext_dns engine.
 *
 * @param ctx The context where the operation will be performed.
 * 
 * @param handler A reference to the handler to configure or NULL to
 * disable the notification.
 */
void     ext_dns_log_set_handler      (extDnsCtx        * ctx, 
				      extDnsLogHandler   handler)
{
	/* get current context */
	v_return_if_fail (ctx);
	
	/* configure status */
	ctx->debug_handler = handler;
}

/** 
 * @brief Allows to instruct ext_dns to send log strings already
 * formated to log handler configured (ext_dns_log_set_handler).
 *
 * This will make ext_dns to expand string arguments (message and
 * args), causing the argument \ref extDnsLogHandler message argument
 * to receive full content. In this case, args argument will be
 * received as NULL.
 *
 * @param ctx The ext_dns context to configure.
 *
 * @param prepare_string axl_true to prepare string received by debug
 * handler, otherwise use axl_false to leave configured default
 * behaviour.
 */
void     ext_dns_log_set_prepare_log  (extDnsCtx         * ctx,
				      axl_bool            prepare_string)
{
	v_return_if_fail (ctx);
	ctx->prepare_log_string = prepare_string;
}

/** 
 * @brief Allows to get current log handler configured. By default no
 * handler is configured so log produced by the ext_dns execution is
 * dropped to the console.
 *
 * @param ctx The context where the operation will be performed.
 * 
 * @return The handler configured (or NULL) if no handler was found
 * configured.
 */
extDnsLogHandler     ext_dns_log_get_handler      (extDnsCtx * ctx)
{
	/* get current context */
	v_return_val_if_fail (ctx, NULL);
	
	/* configure status */
	return ctx->debug_handler;
}

/** 
 * @internal Internal common log implementation to support several levels
 * of logs.
 * 
 * @param ctx The context where the operation will be performed.
 * @param file The file that produce the log.
 * @param line The line that fired the log.
 * @param log_level The level of the log
 * @param message The message 
 * @param args Arguments for the message.
 */
void _ext_dns_log_common (extDnsCtx        * ctx,
			 const       char * file,
			 int                line,
			 extDnsDebugLevel   log_level,
			 const char       * message,
			 va_list            args)
{

#ifndef ENABLE_EXT_DNS_LOG
	/* do no operation if not defined debug */
	return;
#else
	/* log with mutex */
	int    use_log_mutex = axl_false;
	char * log_string;
	struct timeval stamp;
	char   buffer[1024];

	/* if not EXT_DNS_DEBUG FLAG, do not output anything */
	if (! ext_dns_log_is_enabled (ctx)) {
		return;
	} /* end if */

	if (ctx == NULL) {
		goto ctx_not_defined;
	}

	/* check if debug is filtered */
	if (ext_dns_log_filter_is_enabled (ctx)) {
		/* if the filter removed the current log level, return */
		if ((ctx->debug_filter & log_level) == log_level)
			return;
	} /* end if */

	/* acquire the mutex so multiple threads will not mix their
	 * log messages together */
	use_log_mutex = ctx->use_log_mutex;
	if (use_log_mutex) 
		ext_dns_mutex_lock (&ctx->log_mutex);

	if( ctx->debug_handler) {
		if (ctx->prepare_log_string) {
			/* pass the string already prepared */
			log_string = axl_strdup_printfv (message, args);
			ctx->debug_handler (file, line, log_level, log_string, NULL);
			axl_free (log_string);
		} else {
			/* call a custom debug handler if one has been set */
			ctx->debug_handler (file, line, log_level, message, args);
		} /* end if */
	} else {
		/* printout the process pid */
	ctx_not_defined:

		/* get current stamp */
		gettimeofday (&stamp, NULL);

		/* print the message */
		vsnprintf (buffer, 1023, message, args);
				
	/* drop a log according to the level */
#if defined (__GNUC__)
		if (ext_dns_color_log_is_enabled (ctx)) {
			switch (log_level) {
			case EXT_DNS_LEVEL_DEBUG:
				fprintf (stdout, "\e[1;36m(%d.%d proc %d)\e[0m: (\e[1;32mdebug\e[0m) %s:%d %s\n", 
					 (int) stamp.tv_sec, (int) stamp.tv_usec, getpid (), file ? file : "", line, buffer);
				break;
			case EXT_DNS_LEVEL_WARNING:
				fprintf (stdout, "\e[1;36m(%d.%d proc %d)\e[0m: (\e[1;33mwarning\e[0m) %s:%d %s\n", 
					 (int) stamp.tv_sec, (int) stamp.tv_usec, getpid (), file ? file : "", line, buffer);
				break;
			case EXT_DNS_LEVEL_CRITICAL:
				fprintf (stdout, "\e[1;36m(%d.%d proc %d)\e[0m: (\e[1;31mcritical\e[0m) %s:%d %s\n", 
					 (int) stamp.tv_sec, (int) stamp.tv_usec, getpid (), file ? file : "", line, buffer);
				break;
			}
		}else {
#endif /* __GNUC__ */
			switch (log_level) {
			case EXT_DNS_LEVEL_DEBUG:
				fprintf (stdout, "(%d.%d proc %d): (debug) %s:%d %s\n", 
					 (int) stamp.tv_sec, (int) stamp.tv_usec, getpid (), file ? file : "", line, buffer);
				break;
			case EXT_DNS_LEVEL_WARNING:
				fprintf (stdout, "(%d.%d proc %d): (warning) %s:%d %s\n", 
					 (int) stamp.tv_sec, (int) stamp.tv_usec, getpid (), file ? file : "", line, buffer);
				break;
			case EXT_DNS_LEVEL_CRITICAL:
				fprintf (stdout, "(%d.%d proc %d): (critical) %s:%d %s\n", 
					 (int) stamp.tv_sec, (int) stamp.tv_usec, getpid (), file ? file : "", line, buffer);
				break;
			}
#if defined (__GNUC__)
		} /* end if */
#endif
		/* ensure that the log is dropped to the console */
		fflush (stdout);
		
	} /* end if (ctx->debug_handler) */
	
	/* check to release the mutex if defined the context */
	if (use_log_mutex) 
		ext_dns_mutex_unlock (&ctx->log_mutex);

#endif /* end ENABLE_EXT_DNS_LOG */


	/* return */
	return;
}


/** 
 * @internal Log function used by ext_dns to notify all messages that
 * are generated by the core.
 *
 * Do no use this function directly, use <b>ext_dns_log</b>, which is
 * activated/deactivated according to the compilation flags.
 * 
 * @param ctx The context where the operation will be performed.
 * @param file The file that produce the log.
 * @param line The line that fired the log.
 * @param log_level The message severity
 * @param message The message logged.
 */
void _ext_dns_log (extDnsCtx        * ctx,
		  const       char * file,
		  int                line,
		  extDnsDebugLevel   log_level,
		  const char       * message,
		  ...)
{

#ifndef ENABLE_EXT_DNS_LOG
	/* do no operation if not defined debug */
	return;
#else
	va_list   args;

	/* call to common implementation */
	va_start (args, message);
	_ext_dns_log_common (ctx, file, line, log_level, message, args);
	va_end (args);

	return;
#endif
}

/** 
 * @internal Log function used by ext_dns to notify all second level
 * messages that are generated by the core.
 *
 * Do no use this function directly, use <b>ext_dns_log2</b>, which is
 * activated/deactivated according to the compilation flags.
 * 
 * @param ctx The context where the log will be dropped.
 * @param file The file that contains that fired the log.
 * @param line The line where the log was produced.
 * @param log_level The message severity
 * @param message The message logged.
 */
void _ext_dns_log2 (extDnsCtx        * ctx,
		   const       char * file,
		   int                line,
		   extDnsDebugLevel   log_level,
		   const char       * message,
		  ...)
{

#ifndef ENABLE_EXT_DNS_LOG
	/* do no operation if not defined debug */
	return;
#else
	va_list   args;

	/* if not EXT_DNS_DEBUG2 FLAG, do not output anything */
	if (!ext_dns_log2_is_enabled (ctx)) {
		return;
	} /* end if */
	
	/* call to common implementation */
	va_start (args, message);
	_ext_dns_log_common (ctx, file, line, log_level, message, args);
	va_end (args);

	return;
#endif
}

/** 
 * @internal Allows to extract a particular bit from a byte given the
 * position.
 *
 *    +------------------------+
 *    | 7  6  5  4  3  2  1  0 | position
 *    +------------------------+
 */
int ext_dns_get_bit (char byte, int position) {
	return ( ( byte & (1 << position) ) >> position);
}

/** 
 * @internal Allows to set a particular bit on the first position of
 * the buffer provided.
 *
 *    +------------------------+
 *    | 7  6  5  4  3  2  1  0 | position
 *    +------------------------+
 */
void ext_dns_set_bit (char * buffer, int position) {
	buffer[0] |= (1 << position);
	return;
}

void ext_dns_show_byte (extDnsCtx * ctx, char byte, const char * label) {
	
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "  byte (%s) = %d %d %d %d  %d %d %d %d",
		     label,
		     ext_dns_get_bit (byte, 7),
		     ext_dns_get_bit (byte, 6),
		     ext_dns_get_bit (byte, 5),
		     ext_dns_get_bit (byte, 4),
		     ext_dns_get_bit (byte, 3),
		     ext_dns_get_bit (byte, 2),
		     ext_dns_get_bit (byte, 1),
		     ext_dns_get_bit (byte, 0));
	return;
}

char * ext_dns_int2bin (int a, char *buffer, int buf_size) {
	int i;

	buffer += (buf_size - 1);
	
	for (i = 31; i >= 0; i--) {
		*buffer-- = (a & 1) + '0';
		
		a >>= 1;
	}
	
	return buffer;
}

#define BUF_SIZE 33

void ext_dns_int2bin_print (extDnsCtx * ctx, int value) {
	
	char buffer[BUF_SIZE];
	buffer[BUF_SIZE - 1] = '\0';

	ext_dns_int2bin (value, buffer, BUF_SIZE - 1);
	
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "%d = %s", value, buffer);

	return;
}

/** 
 * @internal Allows to get the 16 bit integer located at the buffer
 * pointer.
 *
 * @param buffer The buffer pointer to extract the 16bit integer from.
 *
 * @return The 16 bit integer value found at the buffer pointer.
 */
int    ext_dns_get_16bit (const char * buffer)
{
	int high_part = buffer[0] << 8;
	int low_part  = buffer[1] & 0x000000ff;

	return (high_part | low_part) & 0x000000ffff;
}

/** 
 * @internal Allows to get the 8bit integer located at the buffer
 * pointer.
 *
 * @param buffer The buffer pointer to extract the 8bit integer from.
 *
 * @erturn The 8 bit integer value found at the buffer pointer.
 */
int    ext_dns_get_8bit  (const char * buffer)
{
	return buffer[0] & 0x00000000ff;
}

/** 
 * @internal Allows to set the 16 bit integer value into the 2 first
 * bytes of the provided buffer.
 *
 * @param value The value to be configured in the buffer.
 *
 * @param buffer The buffer where the content will be placed.
 */
void   ext_dns_set_16bit (int value, char * buffer)
{
	buffer[0] = (value & 0x0000ff00) >> 8;
	buffer[1] = value & 0x000000ff;
	
	return;
}

/** 
 * @internal Allows to set the 32 bit integer value into the 4 first
 * bytes of the provided buffer.
 *
 * @param value The value to be configured in the buffer.
 *
 * @param buffer The buffer where the content will be placed.
 */
void   ext_dns_set_32bit (int value, char * buffer)
{
	buffer[0] = (value & 0x00ff000000) >> 24;
	buffer[1] = (value & 0x0000ff0000) >> 16;
	buffer[2] = (value & 0x000000ff00) >> 8;
	buffer[3] =  value & 0x00000000ff;

	return;
}

/** 
 * @brief Allows to get a 32bits integer value from the buffer.
 *
 * @param buffer The buffer where the integer will be retreived from.
 *
 * @return The integer value reported by the buffer.
 */
int    ext_dns_get_32bit (const char * buffer)
{
	int part1 = (int)(buffer[0] & 0x0ff) << 24;
	int part2 = (int)(buffer[1] & 0x0ff) << 16;
	int part3 = (int)(buffer[2] & 0x0ff) << 8;
	int part4 = (int)(buffer[3] & 0x0ff);

	return part1 | part2 | part3 | part4;
}

/** 
 * @internal Allows to set the the provided value encoded using DNS
 * rules on the buffer provided, returning the last position written.
 */
int    ext_dns_encode_domain_name (extDnsCtx * ctx, const char * value, char * buffer)
{
	int          counter = 0;
	int          iterator = 0;
	char       * last_position = buffer;

	while (value[iterator]) {
		/* copy value */
		buffer[iterator + 1] = value[iterator];
		
		if (buffer[iterator + 1] == '.' || value[iterator + 1] == '\0') {
			/* ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Setting counter value %d, at %d", counter - 1, last_position - buffer); */

			/* set last position count and reset current counter */
			if (value[iterator + 1] == '\0')
				counter++;
			last_position[0] = counter;
			
			/* reset counter */
			counter = 0;

			/* record new last position */
			last_position = buffer + iterator + 1;

			/* next position */
			iterator++;

			continue;
		}

		/* copy value */
		counter ++;

		/* next position */
		iterator++;
	} /* end if */

	/* write last \0 */
	buffer[iterator + 1] = 0;

	iterator ++;

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Total length encoded was: %d, iter=%d (for: %s, real length: %d)", 
		     strlen (buffer) + 1, iterator, value, strlen (value));

	return strlen (buffer) + 1;
}
