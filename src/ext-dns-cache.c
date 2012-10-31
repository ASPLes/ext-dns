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
#include <ext-dns-cache.h>
#include <ext-dns-private.h>

axl_bool __ext_dns_cache_cleanup (extDnsCtx  * ctx, 
				  axlPointer   user_data,
				  axlPointer   user_data2)
{
	extDnsMessage * msg;
	const char    * query;
	int             items;
	

	/* lock the cache */
	ext_dns_mutex_lock (&(ctx->cache_mutex));

	/* get items */
	items = axl_hash_items (ctx->cache);

	/* init cursor */
	axl_hash_cursor_first (ctx->cache_cursor);
	while (axl_hash_cursor_has_item (ctx->cache_cursor)) {

		/* get the message */
		msg   = axl_hash_cursor_get_value (ctx->cache_cursor);
		query = axl_hash_cursor_get_key (ctx->cache_cursor);

		if (! ext_dns_message_is_answer_valid (ctx, msg)) {
			/* ext_dns_log (EXT_DNS_LEVEL_DEBUG, "  ...item %s is expired", query); */
			axl_hash_cursor_remove (ctx->cache_cursor);
			continue;
		} /* end if */

		/* next item */
		axl_hash_cursor_next (ctx->cache_cursor);
	} /* end while */

	if (items != axl_hash_items (ctx->cache))
		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Cache after cleanup (%d != %d)", items, axl_hash_items (ctx->cache)); 
	
	/* unlock the cache */
	ext_dns_mutex_unlock (&(ctx->cache_mutex));

	return axl_false; /* never remove the handler */
}

/** 
 * @brief Allows to init the DNS memory cache support, with the
 * default configuration on the provided extDnsCtx object.
 *
 * @param ctx The context where the cache will be started.
 *
 * @param max_cache_size Max cache size (number of cached items to be
 * stored; beyond this limit, new requests to store will be discarded).
 *
 * NOTE: that cache support is not enabled by default. You must
 * connect it into your DNS solution that is, you must use \ref
 * ext_dns_cache_store to cache those messages you want and call to
 * \ref ext_dns_cache_get to get them. 
 *
 * Once enabled (using this function) the module will take care of TTL
 * handling and expire cache cleanup.
 *
 * In the case you want to flush the cache, you just have to this
 * function again.
 */
void            ext_dns_cache_init (extDnsCtx * ctx, int max_cache_size)
{
	axlHash       * old_value;
	axlHashCursor * old_cursor;

	if (ctx == NULL)
		return;

	if (ctx->cache) {
		/* user is calling to flush the cache, hold the mutex then */
		old_value  = ctx->cache;
		old_cursor = ctx->cache_cursor;
		
		/* init cache */
		ext_dns_mutex_lock (&ctx->cache_mutex);
		ctx->cache        = axl_hash_new (axl_hash_string, axl_hash_equal_string);
		ctx->cache_cursor = axl_hash_cursor_new (ctx->cache);
		ext_dns_mutex_unlock (&ctx->cache_mutex);

		/* release old cache */
		axl_hash_cursor_free (old_cursor);
		axl_hash_free (old_value);

		return;
	} 

	/* init the cache for first time */
	ctx->cache        = axl_hash_new (axl_hash_string, axl_hash_equal_string);
	ctx->cache_cursor = axl_hash_cursor_new (ctx->cache);
	ext_dns_mutex_create (&ctx->cache_mutex);

	/* init max cache size */
	ctx->max_cache_size = 1000;

	/* start event to cleanup cache every 10 seconds */
	ext_dns_thread_pool_new_event (ctx, 10 * 1000000, __ext_dns_cache_cleanup, ctx, NULL);
	

	return;
	
}

/** 
 * @brief Allows to check if there is a reply stored ready to be
 * served under the provided query class, query type and query name.
 *
 * The value returned by the function is already checked to be valid
 * (TTL is honoured). 
 *
 * Before calling to this function, you must initialize the cache
 * using \ref ext_dns_cache_init
 *
 * In the case you are looking for a cached reply for an incoming
 * query represented by an \ref extDnsMessage you could use \ref ext_dns_cache_get_by_query which is easier.
 *
 * @param ctx The context where the cache query will be executed.
 *
 * @param qclass The class queried
 *
 * @param qtype The type queried
 *
 * @param query The query name 
 *
 * @return A reference to the message that is a valid cached reply to
 * the query or NULL if the cache doesn't have a valid value stored at
 * this time. The message reference returned is owned by the
 * caller. This means you must call \ref ext_dns_message_unref when
 * you no longer need the message.
 */
extDnsMessage * ext_dns_cache_get (extDnsCtx * ctx, extDnsClass qclass, extDnsType qtype, const char * query)
{
	extDnsMessage * msg;
	char          * key;

	if (ctx == NULL || query == NULL) {
		return NULL;
	}

	/* build key name */
	key = axl_strdup_printf ("%s%d%d", query, qtype, qclass);
	if (key == NULL) {
		ext_dns_mutex_unlock (&ctx->cache_mutex);
		ext_dns_log (EXT_DNS_LEVEL_WARNING, "Unable to store item, printf_buffer failed to build key");
		return NULL;;
	} /* end if */

	ext_dns_mutex_lock (&ctx->cache_mutex);
	msg = axl_hash_get (ctx->cache, key);
	if (msg == NULL) {
		axl_free (key);
		/* no message found at this moment */
		ext_dns_mutex_unlock (&ctx->cache_mutex);
		return NULL;
	}

	/* check if the message is valid */
	if (! ext_dns_message_is_answer_valid (ctx, msg)) {
		/* delete this message from the cache */
		axl_hash_remove (ctx->cache, key);
		axl_free (key);

		/* no message found at this moment */
		ext_dns_mutex_unlock (&ctx->cache_mutex);
		return NULL;
	}

	/* found valid message, increase and return */
	if (! ext_dns_message_ref (msg)) {
		/* failed to acquire reference */
		msg = NULL;
	}

	/* no message found at this moment */
	ext_dns_mutex_unlock (&ctx->cache_mutex);

	/* release memory */
	axl_free (key);

	return msg;
}

/** 
 * @brief The same as \ref ext_dns_cache_get but taking question
 * values that indexs the cache from the provided message.
 *
 * This function is a more natural approach in the case you are
 * looking for a cached reply to an incoming request that is
 * represented by the provided msg.
 *
 * @param ctx The context where the cache query will be run.
 *
 * @param msg The message where cache query data (qtype, qclass and
 * qname) will be taken from.
 */
extDnsMessage * ext_dns_cache_get_by_query (extDnsCtx * ctx, extDnsMessage * msg)
{
	/* check input parameters */
	if (ctx == NULL || msg == NULL) {
		return NULL;
	}
	if (msg->questions == NULL || msg->questions[0].qname == NULL) {
		return NULL;
	}

	/* get the value from the cache */
	return ext_dns_cache_get (ctx, msg->questions[0].qclass, msg->questions[0].qtype, msg->questions[0].qname);
}

/** 
 * @brief Allows to store a message in the cache. 
 *
 * The function will acquire a reference to the message and will store
 * it under the appropiate qtype and qclass so next calls to \ref
 * ext_dns_cache_get will report this value (as long as answers ttls
 * are meet).
 *
 * Note the engine will release the message once the message TTL is
 * expired.
 *
 * @param ctx The context where the cached reply will be stored.
 *
 * @param msg The message to be cached. 
 */
void            ext_dns_cache_store (extDnsCtx * ctx, extDnsMessage * msg)
{
	char * key;

	if (ctx == NULL || msg == NULL || ctx->cache == NULL) {
		return;
	}

	/* check to store a reply message */
	if (msg->header == NULL || msg->header->is_query) {
		return;
	} /* end if */

	/* check if the message is valid to be stored */
	if (msg->questions == NULL || msg->questions[0].qname == NULL || msg->answers == NULL) {
		return;
	}

	/* lock */
	ext_dns_mutex_lock (&ctx->cache_mutex);

	/* check cache size */
	if (axl_hash_items (ctx->cache) > ctx->max_cache_size) {
		ext_dns_mutex_unlock (&ctx->cache_mutex);
		ext_dns_log (EXT_DNS_LEVEL_WARNING, "Max cache size limit reached, skipping storing item");

		/*** NOTIFY max cache reached ***/
		return;
	} /* end if */

	/* build key name */
	key = axl_strdup_printf ("%s%d%d", msg->questions[0].qname, msg->questions[0].qtype, msg->questions[0].qclass);
	if (key == NULL) {
		ext_dns_mutex_unlock (&ctx->cache_mutex);
		ext_dns_log (EXT_DNS_LEVEL_WARNING, "Unable to store item, printf_buffer failed to build key");
		return;
	} /* end if */

	/* try to acquire a reference */
	if (! ext_dns_message_ref (msg)) {
		ext_dns_log (EXT_DNS_LEVEL_WARNING, "Failed to store message into cache, unable to acquire a reference");
		ext_dns_mutex_unlock (&ctx->cache_mutex);
		return;
	}


	/* store, unlock and return */
	axl_hash_insert_full (ctx->cache, key, axl_free, msg, (axlDestroyFunc) ext_dns_message_unref);
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "CACHE-STORE: handling now %d items", axl_hash_items (ctx->cache));
	ext_dns_mutex_unlock (&ctx->cache_mutex);



	return;
}

/** 
 * @internal Function used to release memory used by the cache (if it
 * was initialized).
 *
 * @param ctx The context where the cache will be released
 */
void            ext_dns_cache_finish (extDnsCtx * ctx)
{
	if (ctx == NULL || ctx->cache == NULL)
		return;

	axl_hash_cursor_free (ctx->cache_cursor);
	axl_hash_free (ctx->cache);
	ext_dns_mutex_destroy (&(ctx->cache_mutex));
	return;
}

