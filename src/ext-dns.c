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

/** 
 * @brief Allows to init a ext-DNS context.
 * @param ctx The context to initiate.
 *
 * @return axl_true if the context was initiated, otherwise axl_false
 * is returned.
 */
axl_bool ext_dns_init_ctx (extDnsCtx * ctx)
{
	return axl_true;
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
