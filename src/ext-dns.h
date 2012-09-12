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

#ifndef __EXT_DNS_H__
#define __EXT_DNS_H__

/* define default socket pool size for the EXT_DNS_IO_WAIT_SELECT
 * method. If you change this value, you must change the
 * following. This value must be synchronized with FD_SETSIZE. This
 * has been tested on windows to work properly, but under GNU/Linux,
 * the GNUC library just rejects providing this value, no matter where
 * you place them. The only solutions are:
 *
 * [1] Modify /usr/include/bits/typesizes.h the macro __FD_SETSIZE and
 *     update the following values: FD_SETSIZE and EXT_DNS_FD_SETSIZE.
 *
 * [2] Use better mechanism like poll or epoll which are also available 
 *     in the platform that is giving problems.
 * 
 * [3] The last soluction could be the one provided by you. Please report
 *     any solution you may find.
 **/
#ifndef EXT_DNS_FD_SETSIZE
#define EXT_DNS_FD_SETSIZE 1024
#endif
#ifndef FD_SETSIZE
#define FD_SETSIZE 1024
#endif

/* External header includes */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Axl library headers */
#include <axl.h>

/* Direct portable mapping definitions */
#if defined(AXL_OS_UNIX)

/* Portable definitions while using ext-Dns Library */
#define EXT_DNS_EINTR           EINTR
#define EXT_DNS_EWOULDBLOCK     EWOULDBLOCK
#define EXT_DNS_EINPROGRESS     EINPROGRESS
#define EXT_DNS_EAGAIN          EAGAIN
#define EXT_DNS_SOCKET          int
#define EXT_DNS_INVALID_SOCKET  -1
#define EXT_DNS_SOCKET_ERROR    -1
#define ext_dns_close_socket(s) do {if ( s >= 0) {close (s);}} while (0)
#define ext_dns_getpid          getpid
#define ext_dns_sscanf          sscanf
#define ext_dns_is_disconnected (errno == EPIPE)
#define EXT_DNS_FILE_SEPARATOR "/"

#endif /* end defined(AXL_OS_UNIX) */

#if defined(AXL_OS_WIN32)

/* additional includes for the windows platform */

/* _WIN32_WINNT note: If the application including the header defines
 * the _WIN32_WINNT, it must include the bit defined by the value
 * 0x400. */
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x400
#endif
#include <winsock2.h>
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <time.h>

#define EXT_DNS_EINTR           WSAEINTR
#define EXT_DNS_EWOULDBLOCK     WSAEWOULDBLOCK
#define EXT_DNS_EINPROGRESS     WSAEINPROGRESS
#define EXT_DNS_EAGAIN          WSAEWOULDBLOCK
#define SHUT_RDWR              SD_BOTH
#define SHUT_WR                SD_SEND
#define EXT_DNS_SOCKET          SOCKET
#define EXT_DNS_INVALID_SOCKET  INVALID_SOCKET
#define EXT_DNS_SOCKET_ERROR    SOCKET_ERROR
#define ext_dns_close_socket(s) do {if ( s >= 0) {closesocket (s);}} while (0)
#define ext_dns_getpid          _getpid
#define ext_dns_sscanf          sscanf
#define uint16_t               u_short
#define ext_dns_is_disconnected ((errno == WSAESHUTDOWN) || (errno == WSAECONNABORTED) || (errno == WSAECONNRESET))
#define EXT_DNS_FILE_SEPARATOR "\\"

/* a definition to avoid warnings */
#define strlen (int) strlen

/* no link support windows */
#define S_ISLNK(m) (0)

#endif /* end defined(AXL_OS_WINDOWS) */

#if defined(AXL_OS_UNIX)
#include <sys/types.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
#endif

/* additional headers for poll support */
#if defined(EXT_DNS_HAVE_POLL)
#include <sys/poll.h>
#endif

/* additional headers for linux epoll support */
#if defined(EXT_DNS_HAVE_EPOLL)
#include <sys/epoll.h>
#endif

/* Check gnu extensions, providing an alias to disable its precence
 * when no available. */
#if     __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 8)
#  define GNUC_EXTENSION __extension__
#else
#  define GNUC_EXTENSION
#endif

/* define minimal support for int64 constants */
#ifndef _MSC_VER 
#  define INT64_CONSTANT(val) (GNUC_EXTENSION (val##LL))
#else /* _MSC_VER */
#  define INT64_CONSTANT(val) (val##i64)
#endif

/* check for missing definition for S_ISDIR */
#ifndef S_ISDIR
#  ifdef _S_ISDIR
#    define S_ISDIR(x) _S_ISDIR(x)
#  else
#    ifdef S_IFDIR
#      ifndef S_IFMT
#        ifdef _S_IFMT
#          define S_IFMT _S_IFMT
#        endif
#      endif
#       ifdef S_IFMT
#         define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#       endif
#    endif
#  endif
#endif

/* check for missing definition for S_ISREG */
#if defined(_MSC_VER) && (_MSC_VER >= 1400)
# define S_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
#endif 

/** 
 * @brief Returns the minimum from two values.
 * @param a First value to compare.
 * @param b Second value to compare.
 */
#define EXT_DNS_MIN(a,b) ((a) > (b) ? b : a)

/** 
 * @brief Allows to check the reference provided, and returning the
 * return value provided.
 * @param ref The reference to be checke for NULL.
 * @param return_value The return value to return in case of NULL reference.
 */
#define EXT_DNS_CHECK_REF(ref, return_value) do { \
	if (ref == NULL) {   		         \
             return return_value;                \
	}                                        \
} while (0)

/** 
 * @brief Allows to check the reference provided, returning the return
 * value provided, also releasing a second reference with a custom
 * free function.
 * @param ref The reference to be checke for NULL.
 * @param return_value The return value to return in case of NULL reference.
 * @param ref2 Second reference to be released
 * @param free2_func Function to be used to release the second reference.
 */
#define EXT_DNS_CHECK_REF2(ref, return_value, ref2, free2_func) do { \
        if (ref == NULL) {                                          \
               free2_func (ref);                                    \
	       return return_value;                                 \
	}                                                           \
} while (0)

BEGIN_C_DECLS

/* Internal includes and external includes for ext-DNS API
 * consumers. */
#include <ext-dns-types.h>
#include <ext-dns-handlers.h>
#include <ext-dns-ctx.h>
#include <ext-dns-support.h>
#include <ext-dns-thread.h>
#include <ext-dns-thread-pool.h>
#include <ext-dns-io.h>
#include <ext-dns-session.h>
#include <ext-dns-errno.h>
#include <ext-dns-reader.h>
#include <ext-dns-message.h>

END_C_DECLS

#if defined(AXL_OS_WIN32)
#include <ext_dns_win32.h>
#endif

#include <errno.h>

#if defined(AXL_OS_WIN32)
/* errno redefinition for windows platform. this declaration must
 * follow the previous include. */
#ifdef  errno
#undef  errno
#endif
#define errno (WSAGetLastError())
#endif

/* console debug support:
 *
 * If enabled, the log reporting is activated as usual. If log is
 * stripped from ext_dns building all instructions are removed.
 */
#if defined(ENABLE_EXT_DNS_LOG)
# define ext_dns_log(l, m, ...)   do{_ext_dns_log  (ctx, __AXL_FILE__, __AXL_LINE__, l, m, ##__VA_ARGS__);}while(0)
# define ext_dns_log2(l, m, ...)   do{_ext_dns_log2  (ctx, __AXL_FILE__, __AXL_LINE__, l, m, ##__VA_ARGS__);}while(0)
#else
# if defined(AXL_OS_WIN32) && !( defined(__GNUC__) || _MSC_VER >= 1400)
/* default case where '...' is not supported but log is still
 * disabled */
#   define ext_dns_log _ext_dns_log
#   define ext_dns_log2 _ext_dns_log2
# else
#   define ext_dns_log(l, m, ...) /* nothing */
#   define ext_dns_log2(l, m, message, ...) /* nothing */
# endif
#endif

/** 
 * @internal Allows to check a condition and return if it is not meet.
 * 
 * @param expr The expresion to check.
 */
#define v_return_if_fail(expr) \
if (!(expr)) {return;}

/** 
 * @internal Allows to check a condition and return the given value if it
 * is not meet.
 * 
 * @param expr The expresion to check.
 *
 * @param val The value to return if the expression is not meet.
 */
#define v_return_val_if_fail(expr, val) \
if (!(expr)) { return val;}

/** 
 * @internal Allows to check a condition and return if it is not
 * meet. It also provides a way to log an error message.
 * 
 * @param expr The expresion to check.
 *
 * @param msg The message to log in the case a failure is found.
 */
#define v_return_if_fail_msg(expr,msg) \
if (!(expr)) {ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "%s: %s", __AXL_PRETTY_FUNCTION__, msg); return;}

/** 
 * @internal Allows to check a condition and return the given value if
 * it is not meet. It also provides a way to log an error message.
 * 
 * @param expr The expresion to check.
 *
 * @param val The value to return if the expression is not meet.
 *
 * @param msg The message to log in the case a failure is found.
 */
#define v_return_val_if_fail_msg(expr, val, msg) \
if (!(expr)) { ext_dns_log (EXT_DNS_LEVEL_CRITICAL, "%s: %s", __AXL_PRETTY_FUNCTION__, msg); return val;}


BEGIN_C_DECLS

axl_bool ext_dns_init_ctx             (extDnsCtx * ctx);

axl_bool ext_dns_init_check           (extDnsCtx * ctx);

void     ext_dns_exit_ctx             (extDnsCtx * ctx, 
				       axl_bool    free_ctx);

axl_bool ext_dns_is_exiting           (extDnsCtx * ctx);

axl_bool ext_dns_log_is_enabled       (extDnsCtx * ctx);

axl_bool ext_dns_log2_is_enabled      (extDnsCtx * ctx);

void     ext_dns_log_enable           (extDnsCtx * ctx, 
				      axl_bool    status);

void     ext_dns_log2_enable          (extDnsCtx * ctx, 
				      axl_bool    status);

axl_bool ext_dns_color_log_is_enabled (extDnsCtx * ctx);

void     ext_dns_color_log_enable     (extDnsCtx * ctx, 
				      axl_bool    status);

void     ext_dns_log_set_handler      (extDnsCtx         * ctx,
				       extDnsLogHandler    handler);

void     ext_dns_log_set_prepare_log  (extDnsCtx         * ctx,
				       axl_bool            prepare_string);

extDnsLogHandler vortex_log_get_handler (extDnsCtx      * ctx);

void     vortex_log_filter_level     (extDnsCtx * ctx, const char * filter_string);

axl_bool ext_dns_log_is_enabled_acquire_mutex (extDnsCtx * ctx);

void     _ext_dns_log                 (extDnsCtx        * ctx,
				       const       char * file,
				       int                line,
				       extDnsDebugLevel   level, 
				       const char       * message,
				       ...);

void     _ext_dns_log2                (extDnsCtx        * ctx,
				       const       char * file,
				       int                line,
				       extDnsDebugLevel   level, 
				       const char       * message, 
				       ...);

/**
 * @brief Allowed items to use for \ref ext_dns_conf_get.
 */
typedef enum {
	/** 
	 * @brief Gets/sets current soft limit to be used by the library,
	 * regarding the number of connections handled. Soft limit
	 * means it is can be moved to hard limit.
	 *
	 * To configure this value, use the integer parameter at \ref ext_dns_conf_set. Example:
	 * \code
	 * ext_dns_conf_set (EXT_DNS_SOFT_SOCK_LIMIT, 4096, NULL);
	 * \endcode
	 */
	EXT_DNS_SOFT_SOCK_LIMIT = 1,
	/** 
	 * @brief Gets/sets current hard limit to be used by the
	 * library, regarding the number of connections handled. Hard
	 * limit means it is not possible to exceed it.
	 *
	 * To configure this value, use the integer parameter at \ref ext_dns_conf_set. Example:
	 * \code
	 * ext_dns_conf_set (EXT_DNS_HARD_SOCK_LIMIT, 4096, NULL);
	 * \endcode
	 */
	EXT_DNS_HARD_SOCK_LIMIT = 2,
	/** 
	 * @brief Gets/sets current backlog configuration for listener
	 * connections.
	 *
	 * Once a listener is activated, the backlog is the number of
	 * complete connections (with the finished tcp three-way
	 * handshake), that are ready to be accepted by the
	 * application. The default value is 5.
	 *
	 * Once a listener is activated, and its backlog is
	 * configured, it can't be changed. In the case you configure
	 * this value, you must set it (\ref ext_dns_conf_set) after
	 * calling to the family of functions to create ext_dns
	 * listeners (\ref ext_dns_listener_new).
	 *
	 * To configure this value, use the integer parameter at \ref ext_dns_conf_set. Example:
	 * \code
	 * ext_dns_conf_set (EXT_DNS_LISTENER_BACKLOG, 64, NULL);
	 * \endcode
	 */
	EXT_DNS_LISTENER_BACKLOG = 3,
	/** 
	 * @brief Allows to skip thread pool waiting on ext_dns ctx finalization.
	 *
	 * By default, when ext_dns context is finished by calling \ref
	 * ext_dns_exit_ctx, the function waits for all threads running
	 * the in thread pool to finish. However, under some
	 * conditions, this may cause a dead-lock problem especially
	 * when blocking operations are triggered from threads inside the
	 * pool at the time the exit operation happens.
	 *
	 * This parameter allows to signal this ext_dns context to not
	 * wait for threads running in the thread pool.
	 *
	 * To set the value to make ext_dns ctx exit to not wait for
	 * threads in the pool to finish use:
	 *
	 * \code
	 * ext_dns_conf_set (ctx, EXT_DNS_SKIP_THREAD_POOL_WAIT, axl_true, NULL);
	 * \endcode
	 */
	EXT_DNS_SKIP_THREAD_POOL_WAIT = 4
} extDnsConfItem;

axl_bool  ext_dns_conf_get             (extDnsCtx      * ctx,
					extDnsConfItem   item, 
					int            * value);

axl_bool  ext_dns_conf_set             (extDnsCtx      * ctx,
					extDnsConfItem   item, 
					int              value, 
					const char     * str_value);

int      ext_dns_timeval_substract     (struct timeval * a, 
					struct timeval * b,
					struct timeval * result);

int    ext_dns_get_bit (char byte, int position);

void   ext_dns_set_bit     (char * buffer, int position);

void   ext_dns_show_byte (extDnsCtx * ctx, char byte, const char * label);

char * ext_dns_int2bin (int a, char *buffer, int buf_size);

void   ext_dns_int2bin_print (extDnsCtx * ctx, int value);

int    ext_dns_get_8bit  (const char * buffer);

int    ext_dns_get_16bit (const char * buffer);

void   ext_dns_set_16bit (int value, char * buffer);

void   ext_dns_set_32bit (int value, char * buffer);

int    ext_dns_get_32bit (const char * buffer);

int    ext_dns_encode_domain_name (extDnsCtx * ctx, const char * value, char * buffer);

#if defined(__COMPILING_EXT_DNS__) && defined(__GNUC__)
/* makes gcc happy, by prototyping functions which aren't exported
 * while compiling with -ansi. Really uggly hack, please report
 * any idea to solve this issue. */
int  setenv  (const char *name, const char *value, int overwrite);
#endif

END_C_DECLS

/* @} */
#endif
