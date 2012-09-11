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
#include <ext-dns-ctx.h>

/* include local private definitions */
#include <ext-dns-private.h>

/** 
 * @brief Creates an uninitialized ext-DNS context. You must call \ref
 * ext_dns_ctx_init to start it.
 */
extDnsCtx * ext_dns_ctx_new (void) {
	extDnsCtx * ctx;

	/* create a new context */
	ctx           = axl_new (extDnsCtx, 1);
	EXT_DNS_CHECK_REF (ctx, NULL);
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "created extDnsCtx reference %p", ctx);

	/* create the hash to store data */
	ctx->data     = axl_hash_new (axl_hash_string, axl_hash_equal_string);
	EXT_DNS_CHECK_REF2 (ctx->data, NULL, ctx, axl_free);

	/* init mutex for the log */
	ext_dns_mutex_create (&ctx->log_mutex);

	/**** ext_dns_thread_pool.c: init ****/
	ctx->thread_pool_exclusive = axl_true;

	/* init reference counting */
	ext_dns_mutex_create (&ctx->ref_mutex);
	ctx->ref_count = 1;

	/* init session id */
	ctx->session_id = 1;
	ext_dns_mutex_create (&ctx->session_id_mutex);

	/* init hostname hash */
	ext_dns_mutex_create (&ctx->hostname_mutex);
	ctx->hostname_hash = axl_hash_new (axl_hash_string, axl_hash_equal_string);

	/* return context created */
	return ctx;
}

/** 
 * @brief Allows to increase reference count to the extDnsCtx
 * instance.
 *
 * @param ctx The reference to update its reference count.
 */
void        ext_dns_ctx_ref                       (extDnsCtx  * ctx)
{
	ext_dns_ctx_ref2 (ctx, "begin ref");
	return;
}

/** 
 * @brief Allows to increase reference count to the extDnsCtx
 * instance.
 *
 * @param ctx The reference to update its reference count.
 *
 * @param who An string that identifies this ref. Useful for debuging.
 */
void        ext_dns_ctx_ref2                       (extDnsCtx  * ctx, const char * who)
{
	/* do nothing */
	if (ctx == NULL)
		return;

	/* acquire the mutex */
	ext_dns_mutex_lock (&ctx->ref_mutex);
	ctx->ref_count++;

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "%s: increased references to extDnsCtx %p (refs: %d)", who, ctx, ctx->ref_count);

	ext_dns_mutex_unlock (&ctx->ref_mutex);

	return;
}

/** 
 * @brief Allows to get current reference counting state from provided
 * ext_dns context.
 *
 * @param ctx The ext_dns context to get reference counting
 *
 * @return Reference counting or -1 if it fails.
 */
int         ext_dns_ctx_ref_count                 (extDnsCtx  * ctx)
{
	int result;
	if (ctx == NULL)
		return -1;
	
	/* acquire the mutex */
	ext_dns_mutex_lock (&ctx->ref_mutex); 
	result = ctx->ref_count;
	ext_dns_mutex_unlock (&ctx->ref_mutex); 

	return result;
}

/** 
 * @brief Decrease reference count and nullify caller's pointer in the
 * case the count reaches 0.
 *
 * @param ctx The context to decrement reference count. In the case 0
 * is reached the extDnsCtx instance is deallocated and the callers
 * reference is nullified.
 */
void        ext_dns_ctx_unref                     (extDnsCtx ** ctx)
{

	ext_dns_ctx_unref2 (ctx, "unref");
	return;
}

/** 
 * @brief Decrease reference count and nullify caller's pointer in the
 * case the count reaches 0.
 *
 * @param ctx The context to decrement reference count. In the case 0
 * is reached the extDnsCtx instance is deallocated and the callers
 * reference is nullified.
 *
 * @param who An string that identifies this ref. Useful for debuging.
 */
void        ext_dns_ctx_unref2                     (extDnsCtx ** ctx, const char * who)
{
	extDnsCtx * _ctx;
	axl_bool   nullify;

	/* do nothing with a null reference */
	if (ctx == NULL || (*ctx) == NULL)
		return;

	/* get local reference */
	_ctx = (*ctx);

	/* check if we have to nullify after unref */
	ext_dns_mutex_lock (&_ctx->ref_mutex);

	/* do sanity check */
	if (_ctx->ref_count <= 0) {
		ext_dns_mutex_unlock (&_ctx->ref_mutex);

		_ext_dns_log (NULL, __AXL_FILE__, __AXL_LINE__, EXT_DNS_LEVEL_CRITICAL, "attempting to unref extDnsCtx %p object more times than references supported", _ctx);
		/* nullify */
		(*ctx) = NULL;
		return;
	}

	nullify =  (_ctx->ref_count == 1);
	ext_dns_mutex_unlock (&_ctx->ref_mutex);

	/* call to unref */
	ext_dns_ctx_free2 (*ctx, who);
	
	/* check to nullify */
	if (nullify)
		(*ctx) = NULL;
	return;
}

/** 
 * @brief Releases the memory allocated by the provided \ref
 * extDnsCtx.
 * 
 * @param ctx A reference to the context to deallocate.
 */
void        ext_dns_ctx_free (extDnsCtx * ctx)
{
	ext_dns_ctx_free2 (ctx, "end ref");
	return;
}

/** 
 * @brief Releases the memory allocated by the provided \ref
 * extDnsCtx.
 * 
 * @param ctx A reference to the context to deallocate.
 *
 * @param who An string that identifies this ref. Useful for debuging.
 */
void        ext_dns_ctx_free2 (extDnsCtx * ctx, const char * who)
{
	/* do nothing */
	if (ctx == NULL)
		return;

	/* acquire the mutex */
	ext_dns_mutex_lock (&ctx->ref_mutex);
	ctx->ref_count--;

	if (ctx->ref_count != 0) {
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "%s: decreased references to extDnsCtx %p (refs: %d)", who, ctx, ctx->ref_count);

		/* release mutex */
		ext_dns_mutex_unlock (&ctx->ref_mutex);
		return;
	} /* end if */

	/* clear the hash */
	axl_hash_free (ctx->data);
	ctx->data = NULL;

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "finishing extDnsCtx %p", ctx);

	/* release log mutex */
	ext_dns_mutex_destroy (&ctx->log_mutex);
	
	/* release and clean mutex */
	ext_dns_mutex_unlock (&ctx->ref_mutex);
	ext_dns_mutex_destroy (&ctx->ref_mutex);

	/* release hostname hash */
	axl_hash_free (ctx->hostname_hash);
	ext_dns_mutex_destroy (&ctx->hostname_mutex);

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "about.to.free extDnsCtx %p", ctx);

	/* free the context */
	axl_free (ctx);
	
	return;
}

/** 
 * @brief Allows to store arbitrary data associated to the provided
 * context, which can later retrieved using a particular key. 
 * 
 * @param ctx The ctx where the data will be stored.
 *
 * @param key The key to index the value stored. The key must be a
 * string.
 *
 * @param value The value to be stored. 
 */
void        ext_dns_ctx_set_data (extDnsCtx       * ctx, 
				 const char      * key, 
				 axlPointer        value)
{
	v_return_if_fail (ctx && key);

	/* call to configure using full version */
	ext_dns_ctx_set_data_full (ctx, key, value, NULL, NULL);
	return;
}


/** 
 * @brief Allows to store arbitrary data associated to the provided
 * context, which can later retrieved using a particular key. It is
 * also possible to configure a destroy handler for the key and the
 * value stored, ensuring the memory used will be deallocated once the
 * context is terminated (\ref ext_dns_ctx_free) or the value is
 * replaced by a new one.
 * 
 * @param ctx The ctx where the data will be stored.
 * @param key The key to index the value stored. The key must be a string.
 * @param value The value to be stored. If the value to be stored is NULL, the function calls to remove previous content stored on the same key.
 * @param key_destroy Optional key destroy function (use NULL to set no destroy function).
 * @param value_destroy Optional value destroy function (use NULL to set no destroy function).
 */
void        ext_dns_ctx_set_data_full (extDnsCtx       * ctx, 
				      const char      * key, 
				      axlPointer        value,
				      axlDestroyFunc    key_destroy,
				      axlDestroyFunc    value_destroy)
{
	v_return_if_fail (ctx && key);

	ext_dns_mutex_lock (&ctx->data_mutex);

	/* check if the value is not null. It it is null, remove the
	 * value. */
	if (value == NULL) {
		axl_hash_remove (ctx->data, (axlPointer) key);
		ext_dns_mutex_unlock (&ctx->data_mutex);
		return;
	} /* end if */

	/* store the data */
	axl_hash_insert_full (ctx->data, 
			      /* key and function */
			      (axlPointer) key, key_destroy,
			      /* value and function */
			      value, value_destroy);

	ext_dns_mutex_unlock (&ctx->data_mutex);
	return;
}


/** 
 * @brief Allows to retreive data stored on the given context (\ref
 * ext_dns_ctx_set_data) using the provided index key.
 * 
 * @param ctx The context where to lookup the data.
 * @param key The key to use as index for the lookup.
 * 
 * @return A reference to the pointer stored or NULL if it fails.
 */
axlPointer  ext_dns_ctx_get_data (extDnsCtx       * ctx,
				 const char      * key)
{
	axlPointer  data;

	v_return_val_if_fail (ctx && key, NULL);

	/* lookup */
	ext_dns_mutex_lock (&ctx->data_mutex);
	data = axl_hash_get (ctx->data, (axlPointer) key);
	ext_dns_mutex_unlock (&ctx->data_mutex);

	return data;
}


/** 
 * @brief Blocks the caller until the provided ext-dns context is
 * finished.
 * 
 * This function should be called after creating a listener (o
 * listeners) calling to \ref ext_dns_server_new to block current
 * thread.
 * 
 * This function can be avoided if the program structure can ensure
 * that the programm will not exist after calling \ref
 * ext_dns_listener_new. This happens when the program is linked to (or
 * implements) and internal event loop.
 *
 * This function will be unblocked when the ext-dns servers created
 * ends or a failure have occur while creating the listener. To force
 * an unlocking, a call to \ref ext_dns_session_unlock must be done.
 * 
 * @param ctx The context where the operation will be performed.
 */
void ext_dns_ctx_wait (extDnsCtx * ctx)
{
	extDnsAsyncQueue * temp;

	/* check reference received */
	if (ctx == NULL)
		return;

	/* check and init listener_wait_lock if it wasn't: init
	   lock */
	ext_dns_mutex_lock (&ctx->listener_mutex);

	if (PTR_TO_INT (ext_dns_ctx_get_data (ctx, "ed:listener:skip:wait"))) {
		/* seems someone called to unlock before we get
		 * here */
		/* unlock */
		ext_dns_mutex_unlock (&ctx->listener_mutex);
		return;
	} /* end if */
	
	/* create listener locker */
	if (ctx->listener_wait_lock == NULL) 
		ctx->listener_wait_lock = ext_dns_async_queue_new ();

	/* unlock */
	ext_dns_mutex_unlock (&ctx->listener_mutex);

	/* double locking to ensure waiting */
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Locking listener");
	if (ctx->listener_wait_lock != NULL) {
		/* get a local reference to the queue and work with it */
		temp = ctx->listener_wait_lock;

		/* get blocked until the waiting lock is released */
		ext_dns_async_queue_pop   (temp);
		
		/* unref the queue */
		ext_dns_async_queue_unref (temp);
	}
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "(un)Locked listener");

	return;
}

/** 
 * @brief Unlock the thread blocked at the \ref ext_dns_listener_wait.
 * 
 * @param ctx The context where the operation will be performed.
 **/
void ext_dns_ctx_unlock (extDnsCtx * ctx)
{
	/* check reference received */
	if (ctx == NULL || ext_dns_ctx_ref_count (ctx) < 1)
		return;

	/* unlock listener */
	ext_dns_mutex_lock (&ctx->listener_unlock);
	if (ctx->listener_wait_lock != NULL) {

		/* push to signal listener unblocking */
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "(un)Locking listener..");

		/* notify waiters */
		if (ext_dns_async_queue_waiters (ctx->listener_wait_lock) > 0) {
			ext_dns_async_queue_push (ctx->listener_wait_lock, INT_TO_PTR (axl_true));
		} else {
			/* unref */
			ext_dns_async_queue_unref (ctx->listener_wait_lock);
		} /* end if */

		/* nullify */
		ctx->listener_wait_lock = NULL;

		ext_dns_mutex_unlock (&ctx->listener_unlock);
		return;
	} else {
		/* flag this context to unlock ext_dns_listener_wait
		 * caller because he still didn't reached */
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "ext_dns_listener_wait was not called, signalling to do fast unlock");
		ext_dns_ctx_set_data (ctx, "vo:listener:skip:wait", INT_TO_PTR (axl_true));
	}

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "(un)Locking listener: already unlocked..");
	ext_dns_mutex_unlock (&ctx->listener_unlock);
	return;
}

/** 
 * @brief Allows to configure the onMessage handler, the callback that
 * is called every time a new message is received over the provided
 * ctx.
 *
 * Note the handler here configured will be overriden by the handler
 * configured at session level by \ref ext_dns_session_set_on_message.
 *
 * @param ctx The context that is configured to received messages on
 * the provided handler.
 *
 * @param dns_message The handler where the message will be notified.
 *
 * @param data A pointer to user defined data that will be passed into
 * the handler.
 *
 * Note: only one handler can be configured at the same time for a
 * single session.
 */
void              ext_dns_ctx_set_on_message (extDnsCtx                * ctx, 
					      extDnsOnMessageReceived    on_dns_message, 
					      axlPointer                 data)
{
	/* check pointer received */
	if (ctx == NULL || on_dns_message == NULL)
		return;

	/* set on message */
	ctx->on_message      = on_dns_message;
	ctx->on_message_data = data;

	return;
}


