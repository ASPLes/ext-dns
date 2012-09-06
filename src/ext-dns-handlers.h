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

#ifndef __EXT_DNS_HANDLERS_H__
#define __EXT_DNS_HANDLERS_H__

#include <ext-dns.h>

/** 
 * @brief Handler used by Vortex library to create a new thread. A custom handler
 * can be specified using \ref vortex_thread_set_create
 *
 * @param thread_def A reference to the thread identifier created by
 * the function. This parameter is not optional.
 *
 * @param func The function to execute.
 *
 * @param user_data User defined data to be passed to the function to
 * be executed by the newly created thread.
 *
 * @return The function returns axl_true if the thread was created
 * properly and the variable thread_def is defined with the particular
 * thread reference created.
 *
 * @see vortex_thread_create
 */
typedef axl_bool (* extDnsThreadCreateFunc) (extDnsThread      * thread_def,
                                             extDnsThreadFunc    func,
                                             axlPointer          user_data,
                                             va_list             args);

/** 
 * @brief Handler used by extDns Library to release a thread's resources.
 * A custom handler can be specified using \ref vortex_thread_set_destroy
 *
 * @param thread_def A reference to the thread that must be destroyed.
 *
 * @param free_data Boolean that set whether the thread pointer should
 * be released or not.
 *
 * @return axl_true if the destroy operation was ok, otherwise axl_false is
 * returned.
 *
 * @see vortex_thread_destroy
 */
typedef axl_bool (* extDnsThreadDestroyFunc) (extDnsThread      * thread_def,
                                              axl_bool            free_data);

/** 
 * @brief Handler definition used by \ref vortex_async_queue_foreach
 * to implement a foreach operation over all items inside the provided
 * queue, blocking its access during its process.
 *
 * @param queue The queue that will receive the foreach operation.
 *
 * @param item_stored The item stored on the provided queue.
 *
 * @param position Item position inside the queue. 0 position is the
 * next item to pop.
 *
 * @param user_data User defined optional data provided to the foreach
 * function.
 */
typedef void (*extDnsAsyncQueueForeach) (extDnsAsyncQueue * queue,
					 axlPointer         item_stored,
					 int                position,
					 axlPointer         user_data);

#endif /* __EXT_DNS_HANDLERS_H__ */
