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
#ifndef __EXT_DNS_THREAD_H__
#define __EXT_DNS_THREAD_H__

#include <ext-dns.h>

BEGIN_C_DECLS

/**
 * \addtogroup ext_dns_thread
 * @{
 */

axl_bool           ext_dns_thread_create   (extDnsThread      * thread_def,
					    extDnsThreadFunc    func,
					    axlPointer          user_data,
					   ...);

axl_bool           ext_dns_thread_destroy  (extDnsThread      * thread_def, 
					    axl_bool            free_data);

void               ext_dns_thread_set_create (extDnsThreadCreateFunc  create_fn);

void               ext_dns_thread_set_destroy(extDnsThreadDestroyFunc destroy_fn);

axl_bool           ext_dns_mutex_create    (extDnsMutex       * mutex_def);

axl_bool           ext_dns_mutex_destroy   (extDnsMutex       * mutex_def);

void               ext_dns_mutex_lock      (extDnsMutex       * mutex_def);

void               ext_dns_mutex_unlock    (extDnsMutex       * mutex_def);

axl_bool           ext_dns_cond_create     (extDnsCond        * cond);

void               ext_dns_cond_signal     (extDnsCond        * cond);

void               ext_dns_cond_broadcast  (extDnsCond        * cond);

/** 
 * @brief Useful macro that allows to perform a call to
 * ext_dns_cond_wait registering the place where the call was started
 * and ended.
 * 
 * @param c The cond variable to use.
 * @param mutex The mutex variable to use.
 */
#define EXT_DNS_COND_WAIT(c, mutex) do{\
ext_dns_cond_wait (c, mutex);\
}while(0);

axl_bool           ext_dns_cond_wait       (extDnsCond        * cond, 
					   extDnsMutex       * mutex);

/** 
 * @brief Useful macro that allows to perform a call to
 * ext_dns_cond_timewait registering the place where the call was
 * started and ended. 
 * 
 * @param r Wait result
 * @param c The cond variable to use.
 * @param mutex The mutex variable to use.
 * @param m The amount of microseconds to wait.
 */
#define EXT_DNS_COND_TIMEDWAIT(r, c, mutex, m) do{\
r = ext_dns_cond_timedwait (c, mutex, m);\
}while(0)


axl_bool           ext_dns_cond_timedwait  (extDnsCond        * cond, 
					   extDnsMutex       * mutex,
					   long                microseconds);

void               ext_dns_cond_destroy    (extDnsCond        * cond);

extDnsAsyncQueue * ext_dns_async_queue_new       (void);

axl_bool           ext_dns_async_queue_push      (extDnsAsyncQueue * queue,
						 axlPointer         data);

axl_bool           ext_dns_async_queue_priority_push  (extDnsAsyncQueue * queue,
						      axlPointer         data);

axl_bool           ext_dns_async_queue_unlocked_push  (extDnsAsyncQueue * queue,
						      axlPointer         data);

axlPointer         ext_dns_async_queue_pop          (extDnsAsyncQueue * queue);

axlPointer         ext_dns_async_queue_unlocked_pop (extDnsAsyncQueue * queue);

axlPointer         ext_dns_async_queue_timedpop  (extDnsAsyncQueue * queue,
						 long               microseconds);

int                ext_dns_async_queue_length    (extDnsAsyncQueue * queue);

int                ext_dns_async_queue_waiters   (extDnsAsyncQueue * queue);

int                ext_dns_async_queue_items     (extDnsAsyncQueue * queue);

axl_bool           ext_dns_async_queue_ref       (extDnsAsyncQueue * queue);

int                ext_dns_async_queue_ref_count (extDnsAsyncQueue * queue);

void               ext_dns_async_queue_unref      (extDnsAsyncQueue * queue);

void               ext_dns_async_queue_release    (extDnsAsyncQueue * queue);

void               ext_dns_async_queue_safe_unref (extDnsAsyncQueue ** queue);

void               ext_dns_async_queue_foreach   (extDnsAsyncQueue         * queue,
						  extDnsAsyncQueueForeach    foreach_func,
						  axlPointer                 user_data);

axlPointer         ext_dns_async_queue_lookup    (extDnsAsyncQueue         * queue,
						  axlLookupFunc              lookup_func,
						  axlPointer                 user_data);

void               ext_dns_async_queue_lock      (extDnsAsyncQueue * queue);

void               ext_dns_async_queue_unlock    (extDnsAsyncQueue * queue);

END_C_DECLS

#endif

/**
 * @}
 */ 
