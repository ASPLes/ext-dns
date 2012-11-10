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

#ifndef __EXT_DNS_HANDLERS_H__
#define __EXT_DNS_HANDLERS_H__

#include <ext-dns.h>

/**
 * \defgroup ext_dns_handlers Handlers : handler definitions used by ext-dns API
 */

/** 
 * \addtogroup ext_dns_handlers
 * @{
 */

/** 
 * @brief Handler used by extDns library to create a new thread. A custom handler
 * can be specified using \ref ext_dns_thread_set_create
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
 * @see ext_dns_thread_create
 */
typedef axl_bool (* extDnsThreadCreateFunc) (extDnsThread      * thread_def,
                                             extDnsThreadFunc    func,
                                             axlPointer          user_data,
                                             va_list             args);

/** 
 * @brief Handler used by extDns Library to release a thread's resources.
 * A custom handler can be specified using \ref ext_dns_thread_set_destroy
 *
 * @param thread_def A reference to the thread that must be destroyed.
 *
 * @param free_data Boolean that set whether the thread pointer should
 * be released or not.
 *
 * @return axl_true if the destroy operation was ok, otherwise axl_false is
 * returned.
 *
 * @see ext_dns_thread_destroy
 */
typedef axl_bool (* extDnsThreadDestroyFunc) (extDnsThread      * thread_def,
                                              axl_bool            free_data);

/** 
 * @brief Handler definition used by \ref ext_dns_async_queue_foreach
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

/** 
 * @brief IO handler definition to allow defining the method to be
 * invoked while createing a new fd set.
 *
 * @param ctx The context where the IO set will be created.
 *
 * @param wait_to Allows to configure the file set to be prepared to
 * be used for the set of operations provided. 
 * 
 * @return A newly created fd set pointer, opaque to extDns, to a
 * structure representing the fd set, that will be used to perform IO
 * waiting operation at the \ref ext_dns_io "extDns IO module".
 * 
 */
typedef axlPointer   (* extDnsIoCreateFdGroup)        (extDnsCtx * ctx, extDnsIoWaitingFor wait_to);

/** 
 * @brief IO handler definition to allow defining the method to be
 * invoked while destroying a fd set. 
 *
 * The reference that the handler will receive is the one created by
 * the \ref extDnsIoCreateFdGroup handler.
 * 
 * @param extDnsIoDestroyFdGroup The fd_set, opaque to ext_dns, pointer
 * to a structure representing the fd set to be destroy.
 * 
 */
typedef void     (* extDnsIoDestroyFdGroup)        (axlPointer             fd_set);

/** 
 * @brief IO handler definition to allow defining the method to be
 * invoked while clearing a fd set.
 * 
 * @param extDnsIoClearFdGroup The fd_set, opaque to ext_dns, pointer
 * to a structure representing the fd set to be clear.
 * 
 */
typedef void     (* extDnsIoClearFdGroup)        (axlPointer             fd_set);

/** 
 * @brief IO handler definition to perform the "add to" the fd set
 * operation.
 * 
 * @param fds The socket descriptor to be added.
 *
 * @param fd_group The socket descriptor group to be used as
 * destination for the socket.
 * 
 * @return returns axl_true if the socket descriptor was added, otherwise,
 * axl_false is returned.
 */
typedef axl_bool      (* extDnsIoAddToFdGroup)        (int                    fds,
						       extDnsSession        * session,
						       axlPointer             fd_group);

/** 
 * @brief IO handler definition to perform the "is set" the fd set
 * operation.
 * 
 * @param fds The socket descriptor to be added.
 *
 * @param fd_group The socket descriptor group to be used as
 * destination for the socket.
 *
 * @param user_data User defined pointer provided to the function.
 *
 * @return axl_true if the socket descriptor is active in the given fd
 * group.
 *
 */
typedef axl_bool      (* extDnsIoIsSetFdGroup)        (int                    fds,
						       axlPointer             fd_group,
						       axlPointer             user_data);

/** 
 * @brief Handler definition to allow implementing the have dispatch
 * function at the ext_dns io module.
 *
 * An I/O wait implementation must return axl_true to notify ext_dns engine
 * it support automatic dispatch (which is a far better mechanism,
 * supporting better large set of descriptors), or axl_false, to notify
 * that the \ref ext_dns_io_waiting_set_is_set_fd_group mechanism must
 * be used.
 *
 * In the case the automatic dispatch is implemented, it is also
 * required to implement the \ref extDnsIoDispatch handler.
 * 
 * @param fd_group A reference to the object created by the I/O waiting mechanism.
 * p
 * @return Returns axl_true if the I/O waiting mechanism support automatic
 * dispatch, otherwise axl_false is returned.
 */
typedef axl_bool      (* extDnsIoHaveDispatch)         (axlPointer             fd_group);

/** 
 * @brief User space handler to implement automatic dispatch for I/O
 * waiting mechanism implemented at ext_dns io module.
 *
 * This handler definition is used by:
 * - \ref ext_dns_io_waiting_invoke_dispatch
 *
 * Do not confuse this handler definition with \ref extDnsIoDispatch,
 * which is the handler definition for the actual implemenation for
 * the I/O mechanism to implement automatic dispatch.
 * 
 * @param fds The socket that is being notified and identified to be dispatched.
 * 
 * @param wait_to The purpose of the created I/O waiting mechanism.
 *
 * @param connection Connection where the dispatch operation takes
 * place.
 * 
 * @param user_data Reference to the user data provided to the dispatch function.
 */
typedef void     (* extDnsIoDispatchFunc)         (int                    fds,
						   extDnsIoWaitingFor     wait_to,
						   extDnsSession        * session,
						   axlPointer             user_data);

/** 
 * @brief Handler definition for the automatic dispatch implementation
 * for the particular I/O mechanism selected.
 *
 * This handler is used by:
 *  - \ref ext_dns_io_waiting_set_dispatch
 *  - \ref ext_dns_io_waiting_invoke_dispatch (internally)
 *
 * If this handler is implemented, the \ref extDnsIoHaveDispatch must
 * also be implemented, making it to always return axl_true. If this two
 * handler are implemented, its is not required to implement the "is
 * set?" functionality provided by \ref extDnsIoIsSetFdGroup (\ref
 * ext_dns_io_waiting_set_is_set_fd_group).
 * 
 * @param fd_group A reference to the object created by the I/O
 * waiting mechanism.
 * 
 * @param dispatch_func The dispatch user space function to be called.
 *
 * @param changed The number of descriptors that changed, so, once
 * inspected that number, it is not required to continue.
 *
 * @param user_data User defined data provided to the dispatch
 * function once called.
 */
typedef void     (* extDnsIoDispatch)             (axlPointer             fd_group,
						   extDnsIoDispatchFunc   dispatch_func,
						   int                    changed,
						   axlPointer             user_data);

/** 
 * @brief IO handler definition to allow defining the method to be
 * used while performing a IO blocking wait, by default implemented by
 * the IO "select" call.
 *
 * @param extDnsIoWaitOnFdGroup The handler to set.
 *
 * @param The maximum value for the socket descriptor being watched.
 *
 * @param The requested operation to perform.
 * 
 * @return An error code according to the description found on this
 * function: \ref ext_dns_io_waiting_set_wait_on_fd_group.
 */
typedef int      (* extDnsIoWaitOnFdGroup)       (axlPointer             fd_group,
						  int                    max_fds,
						  extDnsIoWaitingFor     wait_to);

/** 
 * @brief Handler used by async event handlers activated via \ref
 * ext_dns_thread_pool_new_event, which causes the handler definition
 * to be called at the provided milliseconds period.
 *
 * @param ctx The ext_dns context where the async event will be fired.
 * @param user_data User defined pointer that was defined at \ref ext_dns_thread_pool_new_event function.
 * @param user_data2 Second User defined pointer that was defined at \ref ext_dns_thread_pool_new_event function.
 *
 * @return The function returns axl_true to signal the system to
 * remove the handler. Otherwise, axl_false must be returned to cause
 * the event to be fired again in the future at the provided period.
 */
typedef axl_bool (* extDnsThreadAsyncEvent)        (extDnsCtx  * ctx, 
						    axlPointer   user_data,
						    axlPointer   user_data2);

/** 
 * @brief Handler definition that allows a client to print log
 * messages itself.
 *
 * This function is used by: 
 * 
 * - \ref ext_dns_log_set_handler
 * - \ref ext_dns_log_get_handler
 *
 * @param file The file that produced the log.
 *
 * @param line The line where the log was produced.
 *
 * @param log_level The level of the log
 *
 * @param message The message being reported.
 *
 * @param args Arguments for the message.
 */
typedef void (*extDnsLogHandler) (const char       * file,
				  int                line,
				  extDnsDebugLevel   log_level,
				  const char       * message,
				  va_list            args);

/** 
 * @brief Async notification for listener creation.
 *
 * Functions using this handler:
 * - \ref ext_dns_listener_new
 *
 * Optional handler defined to report which host and port have
 * actually allocated a listener peer. If host and port is null means
 * listener have failed to run.
 *
 * You should not free any parameter received, ext_dns system will do
 * this for you.  If you want to actually keep a copy you should use
 * axl_strdup.
 * 
 * @param host the final host binded
 * @param port the final port binded
 * @param status the listener creation status.
 * @param message the message reporting the listener status creation.
 * @param user_data user data passed in to this async notifier.
 */
typedef void (*extDnsListenerReady)           (char  * host, int  port, extDnsStatus status, 
					       char  * message, axlPointer user_data);

/** 
 * @brief Async notification for listener creation, similar to \ref
 * extDnsListenerReady but providing the reference for the \ref extDnsSession created (representing the listener created).
 *
 * Functions using this handler:
 * - \ref ext_dns_listener_new_full
 *
 * Optional handler defined to report which host and port have
 * actually allocated a listener peer. If host and port is null means
 * listener have failed to run.
 *
 * You should not free any parameter received, ext_dns system will do
 * this for you.  If you want to actually keep a copy you should use
 * axl_strdup (deallocating your copy with axl_free).
 *
 * This function is similar to \ref extDnsListenerReady but it also
 * notifies the connection created.
 * 
 * @param host The final host binded.
 *
 * @param port The final port binded.
 *
 * @param status The listener creation status.
 *
 * @param message The message reporting the listener status creation.
 *
 * @param connection The connection representing the listener created
 * (or a NULL reference if status is not \ref extDnsOk).
 * 
 * @param user_data user data passed in to this async notifier.
 */
typedef void (*extDnsListenerReadyFull)           (char  * host, int  port, extDnsStatus status, 
						   char  * message, extDnsSession * connection, 
						   axlPointer user_data);

/** 
 * @brief Defines the set of handler functions that are called to
 * notify a DNS message received on the provided session. This handler
 * definition is also used by DNS cache validation.
 *
 * @param session The DNS session where the message was received.
 *
 * @param source_address The source address where the message comes from.
 *
 * @param source_port The source port where the message comes from.
 *
 * @param message The DNS message received. Note that you must not release this reference (by calling to \ref ext_dns_message_unref). This is done automatically by the library once the handler finishes. In the case you want to have a reference to the message after the handler finishes, then acquire them by calling to \ref ext_dns_message_ref. Note that every reference acquired must be released via \ref ext_dns_message_unref
 *
 * @param data A user defined pointer that was configured along with
 * the handler.
 * 
 */
typedef void     (*extDnsOnMessageReceived) (extDnsCtx     * ctx,
					     extDnsSession * session,
					     const char    * source_address,
					     int             source_port,
					     extDnsMessage * message,
					     axlPointer      data);

/** 
 * @brief Defines the set of handler functions that are called to
 * notify a bad DNS request received (malformed message, incomplete
 * values or wrong values).
 *
 * @param session The DNS session where the message was received.
 *
 * @param source_address The source address where the message comes from.
 *
 * @param source_port The source port where the message comes from.
 *
 * @param buffer The binary message received that was considered as bad request.
 *
 * @param buffer_size The size of the message.
 *
 * @param reason A textual message that indicates why it was
 * considered a bad message.
 *
 * @param data A user defined pointer that was configured along with
 * the handler.
 * 
 */
typedef void     (*extDnsOnBadRequest) (extDnsCtx     * ctx,
					extDnsSession * session,
					const char    * source_address,
					int             source_port,
					const char    * buffer,
					int             buffer_size,
					const char    * reason,
					axlPointer      data);



#endif /* __EXT_DNS_HANDLERS_H__ */

/** 
 * @}
 */
