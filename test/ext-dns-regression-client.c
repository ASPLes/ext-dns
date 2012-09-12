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

const char * dns_server = "8.8.8.8";
int          dns_server_port = 53;

void queue_reply (extDnsCtx     * ctx,
		  extDnsSession * session,
		  const char    * source_address,
		  int             source_port,
		  extDnsMessage * message,
		  axlPointer      data) 
{
	extDnsAsyncQueue * queue = data;

	/* acquire reference to the message */
	if (! ext_dns_message_ref (message)) {
		printf ("ERROR: failed to acquire reference to the message..\n");
		return;
	} /* end if */
		
	/* queue message */
	ext_dns_async_queue_push (queue, message);
	
	return;
}

axl_bool test_01 (void) {
	extDnsCtx     * ctx;

	/* create context object */
	ctx = ext_dns_ctx_new ();
	if (ctx == NULL) {
		printf ("ERROR: failed to allocate ctx object..\n");
		exit (-1);
	}

	/* init context */
	if (! ext_dns_init_ctx (ctx)) {
		printf ("ERROR: failed to initiatialize ext-dns server context..\n");
		exit (-1);
	}

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true; /* return ok */
}

axl_bool test_02 (void) {
	extDnsCtx        * ctx;
	extDnsMessage    * message;
	extDnsAsyncQueue * queue;

	/* create context object */
	ctx = ext_dns_ctx_new ();
	if (ctx == NULL) {
		printf ("ERROR: failed to allocate ctx object..\n");
		return axl_false;
	}

	/* init context */
	if (! ext_dns_init_ctx (ctx)) {
		printf ("ERROR: failed to initiatialize ext-dns server context..\n");
		return axl_false;
	}

	/* run query and check results */
	queue = ext_dns_async_queue_new ();
	ext_dns_message_query (ctx, "a", "in", "www.aspl.es", dns_server, dns_server_port, queue_reply, queue);

	/* get reply (timeout in 3seconds) */
	message = ext_dns_async_queue_timedpop (queue, 3000000);
	if (message == NULL) {
		printf ("ERROR: expected to find message reply but found NULL reference..\n");
		return axl_false;
	}

	/* check message values */
	if (message->header->is_query) {
		printf ("ERROR: expected not to find a query (QR == 0) type message\n");
		return axl_false;
	}

	/* check message values */
	if (message->header->answer_count != 1) {
		printf ("ERROR: expected to find a 1 answer but found: %d\n", message->header->answer_count);
		return axl_false;
	}

	/* check message values */
	if (message->header->query_count != 1) {
		printf ("ERROR: expected to find a 1 query but found: %d\n", message->header->query_count);
		return axl_false;
	}

	/* check message values */
	if (message->header->additional_count != 0) {
		printf ("ERROR: expected to find a 1 query but found: %d\n", message->header->additional_count);
		return axl_false;
	}

	/* check message values */
	if (message->header->authority_count != 0) {
		printf ("ERROR: expected to find a 1 query but found: %d\n", message->header->authority_count);
		return axl_false;
	}

	if (message->answers[0].rdlength != 4) {
		printf ("ERROR: expected to find rdlength 4 for A record query, but found: %d\n", message->answers[0].rdlength);
		return axl_false;
	}

	if (message->answers[0].type != 1) { 
		printf ("ERROR: expected to find type 1 (A) but found %d\n", message->answers[0].type);
		return axl_false;
	}

	if (message->answers[0].class != 1) {
		printf ("ERROR: expected to find class 1 (IN) but found %d\n", message->answers[0].class);
		return axl_false;
	} /* end if */

	/* check values inside */
	/* printf ("values: %s %d %d\n", message->answers[0].name, message->answers[0].type, message->answers[0].class);*/
	if (ext_dns_get_8bit (message->answers[0].rdata) != 89 ||
	    ext_dns_get_8bit (message->answers[0].rdata + 1) != 140 ||
	    ext_dns_get_8bit (message->answers[0].rdata + 2) != 237  ||
	    ext_dns_get_8bit (message->answers[0].rdata + 3) != 75) {
		printf ("ERROR: expected a different value at rdata section..\n");
		return axl_false;
	} /* end if */

	/* release message */
	ext_dns_message_unref (message);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true; /* return ok */
}

typedef axl_bool  (*extDnsRegressionTest) (void);

axl_bool disable_time_checks = axl_true;

void run_test (extDnsRegressionTest test, const char * test_name, const char * message, 
 	       long  limit_seconds, long  limit_microseconds) {

 	struct timeval      start;
 	struct timeval      stop;
 	struct timeval      result;
  
 	/* start test */
 	gettimeofday (&start, NULL);
 	if (test ()) {
 		/* stop test */
 		gettimeofday (&stop, NULL);
		
 		/* get result */
 		ext_dns_timeval_substract (&stop, &start, &result);
		
 		/* check timing results */
 		if ((! disable_time_checks) && limit_seconds >= 0 && limit_microseconds > 0) {
 			if (result.tv_sec >= limit_seconds && result.tv_usec > limit_microseconds) {
 				printf ("%s: %s \n",
 					test_name, message);
 				printf ("***WARNING***: should finish in less than %ld secs, %ld microseconds\n",
 					limit_seconds, limit_microseconds);
 				printf ("                          but finished in %ld secs, %ld microseconds\n", 
 					(long) result.tv_sec, (long) result.tv_usec);
 				exit (-1);
 			} 
 		} /* end if */
		
 		printf ("%s: %s [   OK   ] (finished in %ld secs, %ld microseconds)\n", test_name, message, (long) result.tv_sec, (long) result.tv_usec);
 	} else {
 		printf ("%s: %s [ FAILED ]\n", test_name, message);
 		exit (-1);
 	}
 	return;
}

int main (int argc, char ** argv) {

	/* tests */
	run_test (test_01, "Test 01", "basic extDNS initialization", -1, -1);

	run_test (test_02, "Test 02", "basic A query", -1, -1);
	
	return 0;
}
