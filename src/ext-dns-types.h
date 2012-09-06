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
#ifndef __EXT_DNS_TYPES_H__
#define __EXT_DNS_TYPES_H__

/*
 * @brief Debug levels to be used with \ref _ext_dns_log, which is used
 * through ext_dns_log macro.
 *
 * The set of functions allowing to activate the debug at run time and
 * its variants are:
 * 
 * - \ref ext_dns_log_is_enabled
 * - \ref ext_dns_log2_is_enabled
 * - \ref ext_dns_log_enable
 * - \ref ext_dns_log2_enable
 *
 * Activate console color log (using ansi characters):
 * 
 * - \ref ext_dns_color_log_is_enabled
 * - \ref ext_dns_color_log_enable
 *
 * @param domain Domain that is registering a log.
 *
 * @param level Log level that is being registered.
 *
 * @param message Message that is being registered.
 */
typedef enum {
	/** 
	 * @internal Log a message as a debug message.
	 */
	EXT_DNS_LEVEL_DEBUG    = 1 << 0,
	/** 
	 * @internal Log a warning message.
	 */
	EXT_DNS_LEVEL_WARNING  = 1 << 1,
	/** 
	 * @internal Log a critical message.
	 */
	EXT_DNS_LEVEL_CRITICAL = 1 << 2,
} extDnsDebugLevel;


/** 
 * @brief A server context where all DNS sever state is stored.
 */
typedef struct _extDnsCtx extDnsCtx;

/** 
 * @internal Definitions to accomodate the underlaying thread
 * interface to the Vortex thread API.
 */
#if defined(AXL_OS_WIN32)

#define __OS_THREAD_TYPE__ win32_thread_t
#define __OS_MUTEX_TYPE__  HANDLE
#define __OS_COND_TYPE__   win32_cond_t

typedef struct _win32_thread_t {
	HANDLE    handle;
	void*     data;
	unsigned  id;	
} win32_thread_t;

/** 
 * @internal pthread_cond_t definition, fully based on the work done
 * by Dr. Schmidt. Take a look into his article (it is an excelent article): 
 * 
 *  - http://www.cs.wustl.edu/~schmidt/win32-cv-1.html
 * 
 * Just a wonderful work. 
 *
 * Ok. The following is a custom implementation to solve windows API
 * flaw to support conditional variables for critical sections. The
 * solution provided its known to work under all windows platforms
 * starting from NT 4.0. 
 *
 * In the case you are experimenting problems for your particular
 * windows platform, please contact us through the mailing list.
 */
typedef struct _win32_cond_t {
	/* Number of waiting threads. */
	int waiters_count_;
	
	/* Serialize access to <waiters_count_>. */
	CRITICAL_SECTION waiters_count_lock_;

	/* Semaphore used to queue up threads waiting for the
	 * condition to become signaled. */
	HANDLE sema_;

	/* An auto-reset event used by the broadcast/signal thread to
	 * wait for all the waiting thread(s) to wake up and be
	 * released from the semaphore.  */
	HANDLE waiters_done_;

	/* Keeps track of whether we were broadcasting or signaling.
	 * This allows us to optimize the code if we're just
	 * signaling. */
	size_t was_broadcast_;
	
} win32_cond_t;

#elif defined(AXL_OS_UNIX)

#include <pthread.h>
#define __OS_THREAD_TYPE__ pthread_t
#define __OS_MUTEX_TYPE__  pthread_mutex_t
#define __OS_COND_TYPE__   pthread_cond_t

#endif

/** 
 * @brief Thread definition, which encapsulates the os thread API,
 * allowing to provide a unified type for all threading
 * interface. 
 */
typedef __OS_THREAD_TYPE__ extDnsThread;

/** 
 * @brief Mutex definition that encapsulates the underlaying mutex
 * API.
 */
typedef __OS_MUTEX_TYPE__  extDnsMutex;

/** 
 * @brief Conditional variable mutex, encapsulating the underlaying
 * operating system implementation for conditional variables inside
 * critical sections.
 */
typedef __OS_COND_TYPE__   extDnsCond;

/** 
 * @brief Message queue implementation that allows to communicate
 * several threads in a safe manner. 
 */
typedef struct _extDnsAsyncQueue extDnsAsyncQueue;

/** 
 * @brief Handle definition for the family of function that is able to
 * accept the function \ref vortex_thread_create.
 *
 * The function receive a user defined pointer passed to the \ref
 * vortex_thread_create function, and returns an pointer reference
 * that must be used as integer value that could be retrieved if the
 * thread is joined.
 *
 * Keep in mind that there are differences between the windows and the
 * posix thread API, that are supported by this API, about the
 * returning value from the start function. 
 * 
 * While POSIX defines as returning value a pointer (which could be a
 * reference pointing to memory high above 32 bits under 64
 * architectures), the windows API defines an integer value, that
 * could be easily used to return pointers, but only safe on 32bits
 * machines.
 *
 * The moral of the story is that you must use another mechanism to
 * return data from this function to the thread that is expecting data
 * from this function. 
 * 
 * Obviously if you are going to return an status code, there is no
 * problem. This only applies to user defined data that is returned as
 * a reference to allocated data.
 */
typedef axlPointer (* extDnsThreadFunc) (axlPointer user_data);

/** 
 * @brief Thread configuration its to modify default behaviour
 * provided by the thread creation API.
 */
typedef enum  {
	/** 
	 * @brief Marker used to signal \ref vortex_thread_create that
	 * the configuration list is finished.
	 * 
	 * The following is an example on how to create a new thread
	 * without providing any configuration, using defaults:
	 *
	 * \code
	 * VortexThread thread;
	 * if (! vortex_thread_created (&thread, 
	 *                              some_start_function, NULL,
	 *                              VORTEX_THREAD_CONF_END)) {
	 *      // failed to create the thread 
	 * }
	 * // thread created
	 * \endcode
	 */
	EXT_DNS_THREAD_CONF_END = 0,
	/** 
	 * @brief Allows to configure if the thread create can be
	 * joined and waited by other. 
	 *
	 * Default state for all thread created with \ref
	 * ext_dns_thread_create is true, that is, the thread created
	 * is joinable.
	 *
	 * If configured this value, you must provide as the following
	 * value either axl_true or axl_false.
	 *
	 * \code
	 * extDnsThread thread;
	 * if (! ext_dns_thread_create (&thread, some_start_function, NULL, 
	 *                             EXT_DNS_THREAD_CONF_JOINABLE, axl_false,
	 *                             EXT_DNS_THREAD_CONF_END)) {
	 *    // failed to create the thread
	 * }
	 * 
	 * // Nice! thread created
	 * \endcode
	 */
	EXT_DNS_THREAD_CONF_JOINABLE  = 1,
	/** 
	 * @brief Allows to configure that the thread is in detached
	 * state, so no thread can join and wait for it for its
	 * termination but it will also provide.
	 */
	EXT_DNS_THREAD_CONF_DETACHED = 2,
}extDnsThreadConf;


#endif /* __EXT_DNS_TYPES_H__ */
