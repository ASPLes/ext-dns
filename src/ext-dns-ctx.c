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

	return NULL;
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

	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "about.to.free extDnsCtx %p", ctx);

	/* free the context */
	axl_free (ctx);
	
	return;
}


