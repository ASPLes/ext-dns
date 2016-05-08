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
#include <ext-dns-private.h>
#include <signal.h>

/**
 * \defgroup ext_dns_main Main: basic initialization and common functions
 */

/** 
 * \addtogroup ext_dns_main
 * @{
 */

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
			ctx->debug_handler (file, line, log_level, log_string, args);
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
 *
 * @return The number of bytes that were written to the buffer or -1
 * if it fails.
 */
int    ext_dns_encode_domain_name (extDnsCtx * ctx, const char * value, char * buffer, int buffer_size)
{
	int          counter = 0;
	int          iterator = 0;
	char       * last_position = buffer;

	/* check empty null values and empty records */
	if (value == NULL || value[0] == '\0')
		return -1;

	/* support for root (.) domain */
	if (axl_cmp (value, ".")) {
		buffer[0] = 0;
		return 1;
	} /* end if */

	while (value[iterator] && (iterator + 1) < buffer_size) {
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

		/* check for labels biggers than supported value */
		if (counter > 63) {
			ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "Trying to encode a label that is bigger than allowed (63 bytes): %s", 
				     value);
			return -1;
		}

		/* next position */
		iterator++;
	} /* end if */

	/* check for buffer overflow */
	if ((iterator + 1) >= buffer_size)
		return -1;

	/* write last \0 */
	buffer[iterator + 1] = 0;
	iterator ++;

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Total length encoded was: %d, iter=%d (for: %s, real length: %d)", 
		     ext_dns_strlen (buffer) + 1, iterator, value, ext_dns_strlen (value));

	return ext_dns_strlen (buffer) + 1;
}

/** 
 * @brief Simple wrapper around ext_dns_strlen with support for NULL.
 *
 * @return The number of bytes content string has or 0 if NULL or
 * empty string is received.
 */
int    ext_dns_strlen (const char * content)
{
	int iterator = 0;

	if (content == NULL)
		return 0;

	while (content[iterator])
		iterator++;
	return iterator;
}

/** 
 * @}
 */

/** 
 * \mainpage ext-Dns: a framework to build DNS server solutions 
 *
 * \section intro Introduction
 *
 * ext-Dns is a software solution, written by <a href="http://www.aspl.es">ASPL (Advanced Software Production Line, S.L.)</a>, that is composed by a core library,
 * an extensible forward dns server and some additional tools designed
 * to create DNS server solutions that are able to do any additional
 * operation at the resolution level (running commands, rewritting
 * replies, gathering stats and so on), without any limit.
 *
 * ext-Dns comes to provide a ready to use solution in the case you
 * want to build a DNS server that takes additional actions at the
 * resolution level in an easy way, that is, its design is focused on
 * allowing people to implement whatever they like when a request is
 * received, freeing them from most of the details that involves handling DNS
 * protocol.
 *
 * Note that, if you are looking for a DNS server that just resolves
 * against a database and nothing else, it is better to use another
 * DNS solutions available like: <a href="http://www.powerdns.com">PowerDNS</a> (which we really like it), <a href="http://www.bind9.net">ISC Bind</a>, <a href="http://www.maradns.org">MaraDNS</a> and many more...
 *
 * If you ever wanted to build a DNS server that does certain
 * operations when it receives an incoming request, then ext-dns is
 * for you! 
 *
 * \section what_can_i_do What can I do with ext-DNS framework
 *
 * Briefly with ext-Dns components you can:
 *
 * - Use \ref ext_dns_library_manual "libext-dns", an ANSI C library, to build a custom C DNS server easily with a few API calls. In this case you'll have full power over all details when handling DNS requests. Also, libext-dns is the recommended way if you want to embed a DNS server into your application.
 *
 * - Or use \ref ext_dns_server_manual "ext-DnsD server", a ready to use forward dns-server that uses libext-dns, that completes its actions by calling to a child process to decide what to do. That child resolver can be written in any language (python, bash, perl,...). In this case, you still have access to many details, but limited to supported actions that can be performed child resolvers (\ref contact "contact us" if you have any idea about new \ref ext_dns_server_manual "ext-dnsd commands" that could be added).
 *
 * \section getting_started Getting started with ext-DNS
 *
 * See the following manuals to start using ext-DNS:
 *
 * - \ref ext_dns_install
 * - \ref ext_dns_server_manual
 * - \ref ext_dns_library_manual
 * - \ref ext_dns_library_full_api
 *
 * Additional documenantation and tutorials:
 *
 * - \ref ext_dns_why_write_it
 *  
 *
 * \section commercial_support Commercial support and license
 *
 * ext-Dns and all its components are released under the LGPL2.1
 * license, which means you can use it for commercial and open source
 * products, as long as you meet some requirements. Please, check <a href="http://www.gnu.org/licenses/lgpl-2.1.html">LGPL2 license for more details.</a>
 *
 * Limited support is provided via community mailing list (see below). In
 * the case you want commercial support to get faster to your solution
 * by getting exact information on how to use any of ext-Dns
 * components, fast path resolution, etc, please, contact at: info@aspl.es (spanish and/or
 * english). See more details at: http://www.aspl.es/ext-dns/commercial-support
 *
 * \section contact Contact us
 *
 * Contact us if you find bugs, patches or interesting ideas for the
 * project, or in the case you find any problem while using
 * ext-Dns. You can reach us at <b>ext-Dns mailinst</b> at: <a
 * href="http://lists.aspl.es/cgi-bin/mailman/listinfo/ext-dns">ext-dns
 * users</a>.
 *
 * If you are interested in getting commercial support, you can also contact us at: info@aspl.es (spanish and/or english).
 */

/** 
 * \page ext_dns_install How to install ext-DNS
 *
 * ext-Dns is written using ANSI C, and should compile without any
 * dificulty in any platform with a C compiler. Currently ext-Dns
 * depends on <a href="http://www.aspl.es/xml">Axl Library</a> for
 * some XML functions and for the set of base core library elements
 * like hashes, lists...
 *
 * Please, before continuing, check if there are available ready to
 * use packages for your distribution.
 *
 * First, you must get libaxl available at your host. Please check for
 * instructions at: http://www.aspl.es/xml
 *
 * Once you're done with libaxl, go to http://code.google.com/p/ext-dns/ to get latest source code. The following steps are required to compile ext-dns.tar.gz:
 *
 * \code
 * >> tar xzvf ext-dns-{version}.tar.gz
 * >> cd ext-dns-{version}
 * >> ./configure 
 * >> make
 * >> make install
 * \endcode
 *
 * If everything went right, with previous steps you'll make
 * libext-dns and ext-dnsD server available at your host.
 *
 * Please, report any problem you may find at the mailing list: \ref contact
 */

/** 
 * \page ext_dns_server_manual ext-DnsD administrator manual
 *
 * \section ext_dns_server_manual_index Index
 * 
 * - \ref intro_ext_dnsd
 * - \ref ext_dns_server_configuration
 * - \ref ext_dns_server_status
 * - \ref ext_dnsd_writing_a_child_resolver
 * - \ref ext_dnsd_python_child_resolver
 *
 * \section intro_ext_dnsd ext-DnsD Introduction: how it works, basic description
 *
 * ext-DnsD works as a caching forward dns server for a network,
 * passing all requests to child process, called resolvers, to know
 * how to handle them. The basic working diagram is show as follow:
 * 
 * \code
 *
 *  +------------+    (1) request dns     +------------+  (4) ask external      +---------------------+
 *  | dns client |   -------------->      |  ext-DnsD  | -------------------->  | external dns server |
 *  +------------+     resolution         +------------+   server to resolv     +---------------------+
 *                                            |   ^
 *                           (2) ask child    |   | (3) child resolver signals
 *                           how to handle    |   |     how to handle request: reject,
 *                                 request    |   |     discard, rewrite or forward
 *                                            v   |
 *                                      +-------------------+
 *                                      |    child resolver |
 *                                      +-------------------+
 * \endcode
 * 
 * As the diagrama shows, the server implements all DNS protocol
 * required to handle incoming requests, asking the child what to do
 * on each case, to then reply to the dns client with the value
 * request either because it was reject, rewritten or the particular
 * value reported by the external server.
 *
 * This diagram doesn't reflect other details like how ext-DnsD caches
 * or how it handle bad requests (blacklisting dns clients), but it
 * shows the basic concept to understand how a child resolver works.
 *
 * \section ext_dns_server_configuration ext-DnsD server configuration
 *
 * By default, ext-DnsD configuration is found at /etc/ext-dnsd.conf,
 * but can also be located under a different location using --config
 * flag (-c short option). That configuration has the following form:
 *
 * \htmlinclude ext-dns.example.conf.xml
 *
 * As we see, ext-DnsD configuration is pretty straightforward. It's
 * got a sections to declare what is the DNS server we will use to
 * forward request (as requested by child resolvers), the location of
 * the child resolver script, how many childs to create and other easy
 * to see settings.
 *
 * \section ext_dns_server_status Checking ext-Dnsd server status
 *
 * After successfully starting ext-Dnsd server, you can check its
 * stats by reading the file located at /var/run/ext-dns.status as
 * follows. It will give you lots of useful information about server
 * status:
 *
 * \code
 * >> cat /var/run/ext-dnsd.status 
 * Stamp: 1362599140
 * Child status: 0/10
 * Requests received: 1
 * Requests served: 1
 * Failures found: 0
 * Pending requests: 0
 * Cache stats: 0/1000 (used/max)  0/1 (hits/access) 0.00% (ratio)
 * Command timeout: 15 secs
 * \endcode
 *
 * \section ext_dnsd_writing_a_child_resolver How to write a ext-Dnsd child resolver (child resolver protocol)
 * 
 * A child resolver must be essentially a loop that receives on the
 * standard input a single line when the ext-DnsD wants to ask
 * something, and in turn the child resolver reports one or more
 * lines. 
 *
 * Child resolver receives (note the use of \\n to signify the carry return):
 *
 * \code
 *    INIT\n 
 *
 *       When ext-dnsd starts a child resolver, it sends a INIT\n
 *       command so the can start internal databases and in turn, the
 *       child must return OK\n
 *
 *    RESOLVE [source_ip] [record_name] [record_type] [record_class]\n
 *
 *       When a child resolver receives this command, the ext-dns is asking to resolve
 *       this request. The command includes from where the request is comming and
 *       what kind of DNS query it is. Some examples about this command are:
 *
 *            - RESOLVE 127.0.0.1 www.google.com A IN\n
 *            - RESOLVE 127.0.0.1 google.com MX IN\n
 *
 *       To this command, the child must reply with some of this options:
 *
 *            - FORWARD\n               : make the ext-dnsd to resolver the request with the 
 *                                        external dns server, passing the result directly to the
 *                                        dns client requesting this data.
 *
 *            - DISCARD\n               : silently ignore the request
 *
 *            - REJECT\n                : send a reject reply (Rcode = 5, refused)
 *
 *            - UNKNOWN\n               : send a reply as if it were unknown the value requested
 *
 *            - BLACKLIST [permanent] [seconds]\n  
 *
 *                                      : silently ignore the request, and blacklists the dns client during
 *                                        the provided amount of seconds. During that period all requests from
 *                                        that source will be silently ignored.
 *
 *                                        Here are some examples:
 *                                        - BLACKLIST 3
 *                                        - BLACKLIST permanent
 *
 *            - REPLY ipv4:[value] [ttl] [, more replies] [nocache]\n
 *            - REPLY (name:|cname:)[value] [ttl] [norecurse] [, more replies] [nocache]\n
 *            - REPLY mx:[mailer] [preference] [ttl] [, more replies] [nocache]\n
 *            - REPLY ns:[dns server] [ttl] [, more replies] [nocache]\n
 *            - REPLY soa:[primary server] [mail contact] [serial] [refresh] [retry] [expire] [minimum] [, more replies] [nocache]\n
 *
 *                                      : in this case the reply is directly handled by the child resolver
 *                                        providing a cname as reply to the request (in the case name:/cname: is used)
 *                                        or a particular ipv4 value if ipv4: is used. 
 *
 *                                        The reply also includes the ttl to be used and optionally, an
 *                                        indication about caching the result reported. In the case nocache string
 *                                        is provided, ext-DnsD will not cache the value. 
 *                                        
 *                                        In the case of name: or cname: reply is received,
 *                                        you can also especify norecurse option to enforce
 *                                        ext-dns to avoid recursing to get the IP value associated to that name.
 *
 *                                        In the case you want multiple replies (answers) to the same question, 
 *                                        just add them separated by comma (,).
 *
 *                                        Here are some examples:
 *
 *                                        - REPLY ipv4:127.0.0.1 3600 nocache
 *                                        - REPLY ipv4:127.0.0.1 3600
 *                                        - REPLY ipv4:127.0.0.1 3600, ipv4:192.168.0.154 3600, ipv4:192.168.0.155 3600 nocache
 *
 *                                        - REPLY name:www.aspl.es 3600 
 *                                        - REPLY name:www.google.com 3600, name:www.aspl.es 3600, name:www.asplhosting.com 3600 nocache
 *
 *                                        - REPLY mx:mail3.aspl.es 10 3600, mx:mail4.aspl.es 20 3600
 *                                        - REPLY mx:mail3.aspl.es 10 3600
 *
 *                                        - REPLY ns:nsserver01.aspl.es 3600, ns:nsserver02.aspl.es 3600
 *                                        - REPLY ns:test01.aspl.es 3600
 *
 *                                        - REPLY soa:ns1.account.aspl.es soporte@aspl.es 2012120400 10800 3600 604800 3600
 *
 * \endcode
 * 
 * \section ext_dnsd_python_child_resolver A python child resolver skeleton
 *
 * Full source code for this child resolver can be found at: https://dolphin.aspl.es/svn/publico/ext-dns/server/child-resolver-skel.py
 * 
 * \include child-resolver-skel.py
 */

/** 
 * \page ext_dns_library_manual Libext-dns library manual 
 *
 * \section ext_dns_library_manual Index
 *
 * <b>Section 1: common API</b>
 *  - \ref ext_dns_library_intro
 *
 * <b>Section 2: writing a DNS server</b>
 *  - \ref ext_dns_library_starting_a_listener
 *  - \ref ext_dns_listener_on_received_example
 *
 * \section ext_dns_library_intro Basic concepts before start
 *
 * Libext-dns has a easy to use API, where some objects are used to
 * start a DNS listener, and over those listeners, you configure a set
 * of handlers that are called to notify various events that happens
 * when a request is received. Here are the list of main objects that
 * you must use:
 *
 * - \ref extDnsCtx : this is the context where all state is stored. The library is stateless and supports starting several independent context where listeners and messages shares threads and other subsystems.
 * - \ref extDnsSession : this object represents a single DNS session which may be a listener started by you to receive incoming requests, but it also may represent the other peer when a DNS request or reply is received (via \ref extDnsOnMessageReceived).
 * - \ref extDnsMessage : this object represents a message received or a reply you are building to send to a dns client.
 *
 * There are more modules, \ref ext_dns_types "types" and \ref ext_dns_handlers "handlers" to consider while using libext-dns but these are the most important. Let's see the rest of the API step by step.
 *
 * \section ext_dns_library_starting_a_listener How to create a simple DNS listener
 *
 * In this section, we'll describe how to write a basic DNS
 * listener using libext-dns. Full example can be found at: https://dolphin.aspl.es/svn/publico/ext-dns/test/ext-dns-simple-listener.c
 *
 * Let's start. No matter if you are writing a client or a listener,
 * you must create and initialize a \ref extDnsCtx context. Here is
 * how it is done.
 *
 * \snippet ext-dns-simple-listener.c Init ctx
 * 
 * Now you have started a context, you can start listeners or doing
 * requests to other DNS servers. In this case, we are creating a
 * listener, so, we use the following code to start a DNS server on
 * the local 53 port by doing:
 *
 * \snippet ext-dns-simple-listener.c Starting a listener
 *
 * Now, we've got to configure a handler to get a notification every
 * time a DNS request is received so we can do interesting things with
 * it. Here is how to do it:
 *
 * \snippet ext-dns-simple-listener.c Setting on received handler
 *
 * We will see the content of the on received handler a few steps
 * below. For now, we have to place the code that will ensure our
 * listener doesn't finishes and also the code that finishes the
 * context (and all listeners and clients in play) once we signal the
 * context to finish. 
 *
 * Keep in mind this code isn't necessary if you are embeding
 * libext-dns library into an application that has its own waiting
 * loop. That is, calling to \ref ext_dns_ctx_wait will block the
 * calling thread until the server is signaled to unlock due to a call
 * to \ref ext_dns_ctx_unlock. In any case, this is the waiting plus
 * finalization code:
 *
 * \snippet ext-dns-simple-listener.c Wait and finish
 *
 * \section ext_dns_listener_on_received_example An example of a extDnsOnMessageReceived handler
 *
 * Now, for the on received handler, you must configure a handler that
 * has the following signature. Look also at the example to see how
 * some replies or actions are handled:
 *
 * \snippet ext-dns-simple-listener.c On received handler
 * 
 * 
 */

/** 
 * \page ext_dns_library_full_api Libext-dns API reference
 *
 * Here is the API reference in the case you are using libext-dns (in order of importance):
 *
 * <b>Basic DNS API:</b>
 *
 * - \ref ext_dns_main
 * - \ref ext_dns_ctx
 * - \ref ext_dns_session
 * - \ref ext_dns_message
 * - \ref ext_dns_cache
 *
 * <b>Additional API (handlers, threadhing support, IO handling): </b>
 *
 * - \ref ext_dns_types
 * - \ref ext_dns_handlers
 * - \ref ext_dns_io
 * - \ref ext_dns_reader
 * - \ref ext_dns_thread
 * - \ref ext_dns_thread_pool
 *
 */

/** 
 * \page ext_dns_why_write_it Why did you write ext-Dns framework, especially having powerDns's pipe backend?
 *
 * That's a good question because it goes to the point about why we have written this software.
 *
 * Currently, powerDns's pipe backend is more designed as a
 * "connection" to a program that could allow getting resolution
 * information, than a way to connect to a program that implements
 * resolution policy.
 *
 * This means that powerDns design is more focused to allow resolving
 * certain zones for a particular domain, and in that context, pipe
 * backend may allow accessing to that information.
 *
 * However, ext-Dns server is more designed not only with that target,
 * but to allow the posibility to ask the server to "forward" the
 * request because "you don't oppose to that resolution" (see \ref intro_ext_dnsd for more details about this).
 *
 * This way ext-Dns becomes more a policy-caching-forward DNS server
 * than a zone domain server like powerDns does.
 *
 * Knowing this, we wrote ext-Dns becase we wanted to have a DNS
 * server that could allow an organization to control what is resolved
 * and how, letting accepted requests to continue its normal DNS
 * resolution path.
 *
 * That is, DNS servers like powerDns, no matter what backend they
 * use, hold only domain zone information, whereas ext-Dns holds
 * domain zone information plus policy resolution (and more, like for
 * example, running commands on query received..).
 *
 *
 */
