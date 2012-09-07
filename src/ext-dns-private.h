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
#ifndef __EXT_DNS_PRIVATE_H__
#define __EXT_DNS_PRIVATE_H__

struct _extDnsCtx {
	/** 
	 * @internal Default backlog 
	 */
	int backlog;

	/** 
	 * Flag to skip thread pool wait
	 */
	axl_bool skip_thread_pool_wait;

	/* local log variables */
	axl_bool             debug_checked;
	axl_bool             debug;
	
	axl_bool             debug2_checked;
	axl_bool             debug2;
	
	axl_bool             debug_color_checked;
	axl_bool             debug_color;

	extDnsLogHandler     debug_handler;

	int                  debug_filter;
	axl_bool             debug_filter_checked;
	axl_bool             debug_filter_is_enabled;

	axl_bool             prepare_log_string;

	extDnsMutex          log_mutex;
	axl_bool             use_log_mutex;

	/**** ext-dns io waiting module state ****/
	extDnsIoCreateFdGroup  waiting_create;
	extDnsIoDestroyFdGroup waiting_destroy;
	extDnsIoClearFdGroup   waiting_clear;
	extDnsIoWaitOnFdGroup  waiting_wait_on;
	extDnsIoAddToFdGroup   waiting_add_to;
	extDnsIoIsSetFdGroup   waiting_is_set;
	extDnsIoHaveDispatch   waiting_have_dispatch;
	extDnsIoDispatch       waiting_dispatch;
	extDnsIoWaitingType    waiting_type;

	/** reference counting **/
	extDnsMutex       ref_mutex;
	int               ref_count;

	/** hash reference **/
	axlHash         * data;
	extDnsMutex       data_mutex;

	/*** ext-dns reader module ***/
	extDnsAsyncQueue        * reader_queue;
	extDnsAsyncQueue        * reader_stopped;
	axlPointer                on_reading;
	axlList                 * con_list;
	axlList                 * srv_list;
	axlListCursor           * con_cursor;
	axlListCursor           * srv_cursor;

	/** 
	 * @internal Reference to the thread created for the reader loop.
	 */
	extDnsThread              reader_thread;

	/**** ext-dns thread pool module state ****/
	/** 
	 * @internal Reference to the thread pool.
	 */
	axl_bool                  thread_pool_exclusive;
	extDnsThreadPool *        thread_pool;
	axl_bool                  thread_pool_being_stopped;

	/* @internal Allows to check if the ext-dns library is in exit
	 * transit.
	 */
	axl_bool             exit;
	extDnsMutex          exit_mutex;
	/* @internal Allows to check if the provided ext-dns context is initialized
	 */
	axl_bool             initialized;

	/*** listener unlock mutex ***/
	extDnsMutex          listener_mutex;
	extDnsMutex          listener_unlock;
	extDnsAsyncQueue   * listener_wait_lock;

	/* external cleanup functions */
	axlList            * cleanups;

	extDnsMutex          session_id_mutex;
	int                  session_id;
	axl_bool             session_enable_sanity_check;

	extDnsMutex          inet_ntoa_mutex;
};

struct _extDnsSession {

	/* unique session indentification */
	int               id;

	/* get session type */
	extDnsSessionType type;

	/* the socket this session is associated to */
	EXT_DNS_SOCKET    session;
	axl_bool          is_connected;
	axl_bool          close_called;

	/* the context where this session is running */
	extDnsCtx       * ctx;

	extDnsMutex       ref_mutex;
	int               ref_count;

	extDnsMutex       op_mutex;

	/** 
	 * @brief Stack storing pending channel errors found.
	 */ 
	axlStack * pending_errors;

	/** 
	 * @brief Mutex used to open the pending errors list.
	 */
	extDnsMutex pending_errors_mutex;

	axlHash     * data;
	extDnsMutex * data_mutex;

	/** 
	 * @brief Host name this connection is actually connected to.
	 */
	char       * host;
	char       * host_ip;

	/** 
	 * @brief Port this connection is actually connected to.
	 */
	char       * port;

	/** 
	 * @brief Contains the local address that is used by this connection.
	 */
	char       * local_addr;
	/** 
	 * @brief Contains the local port that is used by this connection.
	 */
	char       * local_port;

	/*** session role indication ***/
	extDnsPeerRole    role;

	/** 
	 * @brief Writer function used by the extDns Library to actually send data.
	 */
	extDnsSendHandler    send;

	/** 
	 * @brief Writer function used by the extDns Library to actually received data
	 */
	extDnsReceiveHandler receive;
};

/** 
 * @internal Type used to store error reported by the remote side
 * while creating channels.
 */
typedef struct _extDnsErrorReport {
	/* error code */
	int    code;
	/* textual diagnostic */
	char * msg;
} extDnsErrorReport;

#endif /* __EXT_DNS_PRIVATE_H__ */
