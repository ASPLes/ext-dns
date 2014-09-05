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

#include <ext-dns.h>

const char * dns_server = "localhost";
int          dns_server_port = 54;

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

axl_bool check_answer (extDnsCtx * ctx, extDnsResourceRecord * rr, const char * name, extDnsType type, extDnsClass class, const char * name_content)
{
	if (rr == NULL) {
		printf ("ERROR: received null resource record value while checking '%s', type %s, class %s..\n", 
			name, ext_dns_message_get_qtype_to_str (ctx, type), ext_dns_message_get_qclass_to_str (ctx, class));
		return axl_false;
	}

	if (! axl_cmp (rr->name, name)) {
		printf ("ERROR: expected to find %s but found: %s\n", name, rr->name);
		return axl_false;
	}
	if (name_content && ! axl_cmp (rr->name_content, name_content)) {
		printf ("ERROR: expected to find %s inside name content registry but found: %s\n", name_content, rr->name_content);
		return axl_false;
	}
	if (rr->type != type) {
		printf ("ERROR: expected to find record type %d but found: %d\n", type, rr->type);
		return axl_false;
	}
	if (rr->class != class) {
		printf ("ERROR: expected to find record class %d but found: %d\n", class, rr->class);
		return axl_false;
	}

	/* return record ok */
	return axl_true;
}

axl_bool check_header (extDnsMessage * message, axl_bool is_query, int ans_count, int query_count, int authority_count, int additional_count)
{
	/* check message values */
	if (is_query != message->header->is_query) {
		printf ("ERROR (check_header is_query): expected to find a query %d but found %d in the message\n", 
			is_query, message->header->is_query);
		return axl_false;
	}

	/* check message values */
	if (message->header->answer_count != ans_count) {
		printf ("ERROR (check_header answer_count): expected to find a %d answer but found: %d\n", ans_count, message->header->answer_count);
		return axl_false;
	}

	/* check message values */
	if (message->header->query_count != query_count) {
		printf ("ERROR (check_header query_count): expected to find a %d query but found: %d\n", query_count, message->header->query_count);
		return axl_false;
	}

	/* check message values */
	if (message->header->additional_count != additional_count) {
		printf ("ERROR (check_header additional_count): expected to find a %d query but found: %d\n", additional_count, message->header->additional_count);
		return axl_false;
	}

	return axl_true; /* all records ok but authority count... */

	/* check message values */
	if (message->header->authority_count != authority_count) {
		printf ("ERROR (check_header authority_count): expected to find a %d query but found: %d\n", authority_count, message->header->authority_count);
		return axl_false;
	}
	return axl_true; /* all records ok */
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

	if (message->answers[0].type != extDnsTypeA) { 
		printf ("ERROR: expected to find type 1 (A) but found %d\n", message->answers[0].type);
		return axl_false;
	}

	if (message->answers[0].class != extDnsClassIN) {
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

	ext_dns_async_queue_unref (queue);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true; /* return ok */
}

axl_bool test_03 (void) {
	extDnsCtx        * ctx;
	extDnsMessage    * message;
	extDnsAsyncQueue * queue;
	axl_bool           is_mail_aspl_es;

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
	printf ("Test 03: querying to %s:%d\n", dns_server, dns_server_port);
	ext_dns_message_query (ctx, "mx", "in", "aspl.es", dns_server, dns_server_port, queue_reply, queue);

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
	if (message->header->answer_count != 2) {
		printf ("ERROR: expected to find a 2 answer but found: %d\n", message->header->answer_count);
		return axl_false;
	}

	/* check message values */
	if (message->header->query_count != 1) {
		printf ("ERROR: expected to find a 1 query in header but found: %d\n", message->header->query_count);
		return axl_false;
	}

	/* check message values */
	if (message->header->additional_count != 0) {
		printf ("ERROR: expected to find a 0 additional query item (in header) but found: %d\n", message->header->additional_count);
		return axl_false;
	}

	/* check message values */
	if (message->header->authority_count != 0) {
		printf ("ERROR: expected to find a 1 query but found: %d\n", message->header->authority_count);
		return axl_false;
	}

	/* check values inside */
	if (message->answers[0].type != extDnsTypeMX) {
		printf ("ERROR: expected to find MX type record, but found: %d\n", message->answers[0].type);
		return axl_false;
	}
	if (message->answers[0].class != extDnsClassIN) {
		printf ("ERROR: expected to find IN class, but found: %d\n", message->answers[0].class);
		return axl_false;
	}

	/* check which record we are handling */
	is_mail_aspl_es = axl_cmp (message->answers[0].name_content, "mail.aspl.es");
	printf ("Test 03: Found mail.aspl.es in the first record: %d\n", is_mail_aspl_es);

	if (message->answers[0].preference != (is_mail_aspl_es ? 10 : 20)) {
		printf ("ERROR (2): expected to find MX %s preference, but found: %d\n", 
			is_mail_aspl_es ? "10" : "20",
			message->answers[0].preference);
		return axl_false;
	}

	if (! axl_cmp (message->answers[0].name_content, is_mail_aspl_es ? "mail.aspl.es" : "mail2.aspl.es")) {
		printf ("ERROR: expected to find %s but found: %s\n", 
			is_mail_aspl_es ? "mail.aspl.es" : "mail2.aspl.es",
			message->answers[0].name_content);
		return axl_false;
	}

	/* check values inside */
	if (message->answers[1].type != extDnsTypeMX) {
		printf ("ERROR: expected to find MX type record, but found: %d\n", message->answers[1].type);
		return axl_false;
	}
	if (message->answers[1].class != extDnsClassIN) {
		printf ("ERROR: expected to find IN class, but found: %d\n", message->answers[1].class);
		return axl_false;
	}

	if (message->answers[1].preference != (is_mail_aspl_es ? 20 : 10)) {
		printf ("ERROR: expected to find MX %s preference, but found: %d\n", 
			is_mail_aspl_es ? "20" : "10",
			message->answers[1].preference);
		return axl_false;
	}

	if (! axl_cmp (message->answers[1].name_content, is_mail_aspl_es ? "mail2.aspl.es" : "mail.aspl.es")) {
		printf ("ERROR: expected to find mail2.aspl.es but found: %s\n", message->answers[1].name_content);
		return axl_false;
	}

	/* release message */
	ext_dns_message_unref (message);

	ext_dns_async_queue_unref (queue);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true; /* return ok */
}

axl_bool test_04 (void) {
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
	ext_dns_message_query (ctx, "cname", "in", "bugzilla.aspl.es", dns_server, dns_server_port, queue_reply, queue);

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
		printf ("ERROR: expected to find a 2 answer but found: %d\n", message->header->answer_count);
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

	/* printf ("values: %s %d %d %s\n", message->answers[0].name, message->answers[0].type, message->answers[0].class, message->answers[0].name_content); */
	if (! axl_cmp (message->answers[0].name, "bugzilla.aspl.es")) {
		printf ("ERROR: expected to find bugzilla.aspl.es but found: %s\n", message->answers[0].name);
		return axl_false;
	}
	if (message->answers[0].type != extDnsTypeCNAME) {
		printf ("ERROR: expected to find record type %d but found: %d\n", extDnsTypeCNAME, message->answers[0].type);
		return axl_false;
	}
	if (message->answers[0].class != extDnsClassIN) {
		printf ("ERROR: expected to find class %d but found: %d\n", extDnsClassIN, message->answers[0].class);
		return axl_false;
	}

	if (! axl_cmp (message->answers[0].name_content, "dolphin.aspl.es")) {
		printf ("ERROR: expected to find dolphin.aspl.es as CNAME result for bugzilla.aspl.es but found: %s\n", message->answers[0].name_content);
		return axl_false;
	}

	/* release message */
	ext_dns_message_unref (message);

	ext_dns_async_queue_unref (queue);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true; /* return ok */
}

axl_bool test_04a (void) {

	extDnsCtx        * ctx;
	extDnsMessage    * message;
	extDnsAsyncQueue * queue;

	if (! axl_cmp (dns_server, "localhost")) {
		printf ("WARNING: skip asking to %s for this test..because we would need the server to forge record cname.asplhosting.com\n", dns_server);
		return axl_true;
	}

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
	ext_dns_message_query (ctx, "a", "in", "cname.asplhosting.com", dns_server, dns_server_port, queue_reply, queue);

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
	if (message->header->answer_count != 3) {
		printf ("ERROR: expected to find a 3 answer but found: %d\n", message->header->answer_count);
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

	/* printf ("values: %s %d %d %s\n", message->answers[0].name, message->answers[0].type, message->answers[0].class, message->answers[0].name_content); */
	/* printf ("values: %s %d %d %s\n", message->answers[0].name, message->answers[0].type, message->answers[0].class, message->answers[0].name_content);  */
	if (! check_answer (ctx, &message->answers[0], "cname.asplhosting.com", extDnsTypeCNAME, extDnsClassIN, "cname.aspl.es"))
		return axl_false;
	if (! check_answer (ctx, &message->answers[1], "cname.aspl.es", extDnsTypeA, extDnsClassIN, "182.192.10.20"))
		return axl_false;
	if (! check_answer (ctx, &message->answers[2], "cname.aspl.es", extDnsTypeA, extDnsClassIN, "182.192.10.21"))
		return axl_false;

	/* release message */
	ext_dns_message_unref (message);

	ext_dns_async_queue_unref (queue);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true; /* return ok */
}

axl_bool test_05 (void) {
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
	ext_dns_message_query (ctx, "a", "in", "bugzilla.aspl.es", dns_server, dns_server_port, queue_reply, queue);

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
	if (message->header->answer_count != 2) {
		printf ("ERROR: expected to find a 2 answer but found: %d\n", message->header->answer_count);
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

	/* printf ("values: %s %d %d %s\n", message->answers[0].name, message->answers[0].type, message->answers[0].class, message->answers[0].name_content); 
	   printf ("values: %s %d %d %s\n", message->answers[1].name, message->answers[1].type, message->answers[1].class, message->answers[1].name_content); */
	if (! axl_cmp (message->answers[0].name, "bugzilla.aspl.es")) {
		printf ("ERROR: expected to find bugzilla.aspl.es but found: %s\n", message->answers[0].name);
		return axl_false;
	}
	if (message->answers[0].type != extDnsTypeCNAME) {
		printf ("ERROR: expected to find record type %d but found: %d\n", extDnsTypeCNAME, message->answers[0].type);
		return axl_false;
	}
	if (message->answers[0].class != extDnsClassIN) {
		printf ("ERROR: expected to find class %d but found: %d\n", extDnsClassIN, message->answers[0].class);
		return axl_false;
	}

	if (! axl_cmp (message->answers[0].name_content, "dolphin.aspl.es")) {
		printf ("ERROR: expected to find dolphin.aspl.es as CNAME result for bugzilla.aspl.es but found: %s\n", message->answers[0].name_content);
		return axl_false;
	} 

	if (! axl_cmp (message->answers[1].name, "dolphin.aspl.es")) {
		printf ("ERROR: expected to find bugzilla.aspl.es but found: %s\n", message->answers[1].name);
		return axl_false;
	}
	if (message->answers[1].type != extDnsTypeA) {
		printf ("ERROR: expected to find record type %d but found: %d\n", extDnsTypeCNAME, message->answers[1].type);
		return axl_false;
	}
	if (message->answers[1].class != extDnsClassIN) {
		printf ("ERROR: expected to find class %d but found: %d\n", extDnsClassIN, message->answers[1].class);
		return axl_false;
	}

	if (! axl_cmp (message->answers[1].name_content, "213.96.140.9")) {
		printf ("ERROR: expected to find dolphin.aspl.es as CNAME result for bugzilla.aspl.es but found: %s\n", message->answers[1].name_content);
		return axl_false;
	} 

	/* release message */
	ext_dns_message_unref (message);

	ext_dns_async_queue_unref (queue);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true; /* return ok */
}

axl_bool test_06 (void) {

	extDnsCtx        * ctx;
	extDnsMessage    * message;
	extDnsAsyncQueue * queue;
	int                iterator;
	axl_bool           found1 = axl_false, found2 = axl_false, found3 = axl_false;

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
	ext_dns_message_query (ctx, "ns", "in", "aspl.es", dns_server, dns_server_port, queue_reply, queue);

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
	if (message->header->answer_count != 3) {
		printf ("ERROR: expected to find a 3 answer but found: %d\n", message->header->answer_count);
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

	/* printf ("values: %s %d %d %s\n", message->answers[0].name, message->answers[0].type, message->answers[0].class, message->answers[0].name_content); 
	printf ("values: %s %d %d %s\n", message->answers[1].name, message->answers[1].type, message->answers[1].class, message->answers[1].name_content); 
	printf ("values: %s %d %d %s\n", message->answers[2].name, message->answers[2].type, message->answers[2].class, message->answers[2].name_content);  */
	
	iterator = 0;
	while (iterator < 3) {
		if (axl_cmp (message->answers[iterator].name_content, "ns1.cuentadns.com"))
			if (! found1 && check_answer (ctx, &message->answers[iterator], "aspl.es", extDnsTypeNS, extDnsClassIN, "ns1.cuentadns.com")) 
				found1 = axl_true;
		if (axl_cmp (message->answers[iterator].name_content, "ns2.cuentadns.com"))
			if (! found2 && check_answer (ctx, &message->answers[iterator], "aspl.es", extDnsTypeNS, extDnsClassIN, "ns2.cuentadns.com"))
				found2 = axl_true;
		if (axl_cmp (message->answers[iterator].name_content, "ns3.cuentadns.com"))
			if (! found3 && check_answer (ctx, &message->answers[iterator], "aspl.es", extDnsTypeNS, extDnsClassIN, "ns3.cuentadns.com"))
				found3 = axl_true;
		iterator++;
	}

	if (!found1 || !found2 || !found3) {
		printf ("ERROR: expected to find some DNS NS registry that weren't found (ns1.cuentadns.com: %d, ns2.cuentadns.com: %d, ns2.cuentadns.com: %d)..\n",
			found1, found2, found3);
		return axl_false;
	} /* end if */

	/* release message */
	ext_dns_message_unref (message);

	ext_dns_async_queue_unref (queue);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true; /* return ok */
}

axl_bool test_07 (void) {

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
	ext_dns_message_query (ctx, "txt", "in", "aspl.es", dns_server, dns_server_port, queue_reply, queue);

	/* get reply (timeout in 3seconds) */
	message = ext_dns_async_queue_timedpop (queue, 3000000);
	if (message == NULL) {
		printf ("ERROR: expected to find message reply but found NULL reference..\n");
		return axl_false;
	}

	/* check header */
	if (! check_header (message, 
			    /* is query */ axl_false, 
			    /* ans count */ 1, 
			    /* query count */ 1,
			    /* authority count */ 0,
			    /* additional count */ 0))
		return axl_false;

	/* printf ("values: %s %d %d %s\n", message->answers[0].name, message->answers[0].type, message->answers[0].class, message->answers[0].name_content);  */
	if (! check_answer (ctx, &message->answers[0], "aspl.es", extDnsTypeTXT, extDnsClassIN, "v=spf1 a mx ip4:194.140.166.76 ip4:213.96.140.9 mx:aspl.es ~all"))
		return axl_false;

	/* release message */
	ext_dns_message_unref (message);

	ext_dns_async_queue_unref (queue);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true; /* return ok */
}

axl_bool test_08 (void) {

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
	ext_dns_message_query (ctx, "soa", "in", "aspl.es", dns_server, dns_server_port, queue_reply, queue);

	/* get reply (timeout in 3seconds) */
	message = ext_dns_async_queue_timedpop (queue, 3000000);
	if (message == NULL) {
		printf ("ERROR: expected to find message reply but found NULL reference..\n");
		return axl_false;
	}

	/* check header */
	if (! check_header (message, 
			    /* is query */ axl_false, 
			    /* ans count */ 1, 
			    /* query count */ 1,
			    /* authority count */ 0,
			    /* additional count */ 0))
		return axl_false;

	/* printf ("values: %s %d %d %s\n", message->answers[0].name, message->answers[0].type, message->answers[0].class, message->answers[0].name_content);   */
 	if (! check_answer (ctx, &message->answers[0], "aspl.es", extDnsTypeSOA, extDnsClassIN, NULL))
		return axl_false;

	/* check opcode */
	if (message->header->opcode != 0) {
		printf ("ERROR: expected to find no error code (0), but found found: (%d)\n", message->header->opcode);
		return axl_false;
	}

	/* printf ("values: mname=%s, rname=%s, serial=%d, refresh=%d, retry=%d, expire=%d, minimum=%d\n", 
		message->answers[0].mname, message->answers[0].contact_address, message->answers[0].serial, message->answers[0].refresh, 
		message->answers[0].retry, message->answers[0].expire, message->answers[0].minimum);  */
	if (! axl_cmp (message->answers[0].mname, "ns1.cuentadns.com")) {
		printf ("ERROR: expected to find ns1.cuentadns.com but found %s\n", message->answers[0].mname);
		return axl_false;
	}
	if (! axl_cmp (message->answers[0].contact_address, "soporte.aspl.es")) {
		printf ("ERROR: expected to find soporte.aspl.es but found %s\n", message->answers[0].contact_address);
		return axl_false;
	}
	if (message->answers[0].serial <= 2012091403) {
		printf ("ERROR: expected to find something bigger or equal to %d but found %d\n", 2012091403, message->answers[0].serial);
		return axl_false;
	}

	if (message->answers[0].refresh != 10800) {
		printf ("ERROR: expected to find %d but found %d\n", 10800, message->answers[0].refresh);
		return axl_false;
	}

	if (message->answers[0].retry != 3600) {
		printf ("ERROR: expected to find %d but found %d\n", 3600, message->answers[0].retry);
		return axl_false;
	}
	if (message->answers[0].expire != 604800) {
		printf ("ERROR: expected to find %d but found %d\n", 604800, message->answers[0].expire);
		return axl_false;
	}
	if (message->answers[0].minimum != 3600) {
		printf ("ERROR: expected to find %d but found %d\n", 3600, message->answers[0].minimum);
		return axl_false;
	}

	/* printf ("RDLENGTH section size: %d\n", message->answers[0].rdlength); */
	if (message->answers[0].rdlength != 49 && message->answers[0].rdlength != 56) {
		printf ("ERROR: found different rdlength than expected (49, 56) != %d\n", message->answers[0].rdlength);
		return axl_false;
	}

	/* release message */
	ext_dns_message_unref (message);

	ext_dns_async_queue_unref (queue);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true; /* return ok */
}

axl_bool test_09 (void) {

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
	ext_dns_message_query (ctx, "ptr", "in", "69.237.140.89.in-addr.arpa", dns_server, dns_server_port, queue_reply, queue);

	/* get reply (timeout in 3seconds) */
	message = ext_dns_async_queue_timedpop (queue, 3000000);
	if (message == NULL) {
		printf ("ERROR: expected to find message reply but found NULL reference..\n");
		return axl_false;
	}

	/* check header */
	if (! check_header (message, 
			    /* is query */ axl_false, 
			    /* ans count */ 1, 
			    /* query count */ 1,
			    /* authority count */ 0,
			    /* additional count */ 0))
		return axl_false;

	/* printf ("values: %s %d %d %s\n", message->answers[0].name, message->answers[0].type, message->answers[0].class, message->answers[0].name_content);    */
 	if (! check_answer (ctx, &message->answers[0], "69.237.140.89.in-addr.arpa", extDnsTypePTR, extDnsClassIN, "smtp-01.aspl.es"))
		return axl_false;

	/* release message */
	ext_dns_message_unref (message);

	ext_dns_async_queue_unref (queue);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true; /* return ok */
}

axl_bool test_10 (void) {

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
	ext_dns_message_query (ctx, "a", "in", "unknown.aspl.es", dns_server, dns_server_port, queue_reply, queue);

	/* get reply (timeout in 3seconds) */
	message = ext_dns_async_queue_timedpop (queue, 3000000);
	if (message == NULL) {
		printf ("ERROR: expected to find message reply but found NULL reference..\n");
		return axl_false;
	}

	/* check header */
	if (! check_header (message, 
			    /* is query */ axl_false, 
			    /* ans count */ 0, 
			    /* query count */ 1,
			    /* authority count */ 1,
			    /* additional count */ 0))
		return axl_false;

	/* printf ("values: %s %d %d %s\n", message->authorities[0].name, message->authorities[0].type, 
	   message->authorities[0].class, message->authorities[0].name_content);     */
	if (message->header->rcode != extDnsResponseNameError ) {
		printf ("ERROR: expected to find error code %d but found %d\n", message->header->rcode, extDnsResponseNameError);
		return axl_false;
	} /* end if */

	/* printf ("Message size: %d\n", message->message_size); */
	if (message->message_size != 108 && message->message_size != 94 && message->message_size != 33) {
		printf ("ERROR: expected a message size reply of 108, 94 or 33 but found %d\n", 
			message->message_size);
		return axl_false;
	} /* end if */

	/* release message */
	ext_dns_message_unref (message);

	ext_dns_async_queue_unref (queue);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true; /* return ok */
}

axl_bool test_11 (void) {

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
	ext_dns_message_query (ctx, "srv", "in", "_sip._udp.voztele.com", dns_server, dns_server_port, queue_reply, queue);

	/* get reply (timeout in 3seconds) */
	message = ext_dns_async_queue_timedpop (queue, 3000000);
	if (message == NULL) {
		printf ("ERROR: expected to find message reply but found NULL reference..\n");
		return axl_false;
	}

	/* check header */
	if (! check_header (message, 
			    /* is query */ axl_false, 
			    /* ans count */ 1, 
			    /* query count */ 1,
			    /* authority count */ 0,
			    /* additional count */ 0))
		return axl_false;

	/* printf ("values: %s %d %d %s\n", message->answers[0].name, message->answers[0].type, message->answers[0].class, message->answers[0].name_content);     */
	if (! check_answer (ctx, &message->answers[0], "_sip._udp.voztele.com", extDnsTypeSRV, extDnsClassIN, NULL))
		return axl_false; 

	/* printf ("values: %s %d %d %s\n", message->authorities[0].name, message->authorities[0].type, 
	   message->authorities[0].class, message->authorities[0].name_content);     */
	if (message->header->rcode != extDnsResponseNoError ) {
		printf ("ERROR: expected to find error code %d but found %d\n", message->header->rcode, extDnsResponseNoError);
		return axl_false;
	} /* end if */

	/* check additional values */
	if (message->answers[0].preference != 0) {
		printf ("ERROR: expected to find preference 0 but found %d\n", message->answers[0].preference);
		return axl_false;
	}

	/* check additional values */
	if (message->answers[0].weight != 0) {
		printf ("ERROR: expected to find weight 0 but found %d\n", message->answers[0].weight);
		return axl_false;
	}

	/* check additional values */
	if (message->answers[0].port != 5060) {
		printf ("ERROR: expected to find port 5060 but found %d\n", message->answers[0].port);
		return axl_false;
	}

	if (! axl_cmp (message->answers[0].target, "voztele.com")) {
		printf ("ERROR: expected to find target value voztele.com but found %s\n", message->answers[0].target);
		return axl_false;
	}
			

	/* printf ("Message size: %d\n", message->message_size); */
	if (message->message_size != 91 && message->message_size != 70) {
		printf ("ERROR: expected a message size reply of 91 or 70 but found %d\n", 
			message->message_size);
		return axl_false;
	} /* end if */

	if (ext_dns_message_is_reject (message)) {
		printf ("ERROR: expected to NOT find name resolution error but found the function doesn't reports that\n");
		return axl_false;
	}

	/* release message */
	ext_dns_message_unref (message);

	ext_dns_async_queue_unref (queue);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true; /* return ok */
}

axl_bool test_12 (void) {

	extDnsCtx        * ctx;
	extDnsMessage    * message;
	extDnsAsyncQueue * queue;

	if (! axl_cmp (dns_server, "localhost")) {
		printf ("WARNING: skip asking to %s for this test..because we would need the server to reject answering to reject.aspl.es\n", dns_server);
		return axl_true;
	}

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
	ext_dns_message_query (ctx, "a", "in", "reject.aspl.es", dns_server, dns_server_port, queue_reply, queue);

	/* get reply (timeout in 3seconds) */
	message = ext_dns_async_queue_timedpop (queue, 3000000);
	if (message == NULL) {
		printf ("ERROR: expected to find message reply but found NULL reference..\n");
		return axl_false;
	}

	/* check header */
	if (! check_header (message, 
			    /* is query */ axl_false, 
			    /* ans count */ 0, 
			    /* query count */ 1,
			    /* authority count */ 0,
			    /* additional count */ 0))
		return axl_false;

	/* printf ("values: %s %d %d %s\n", message->authorities[0].name, message->authorities[0].type, 
	   message->authorities[0].class, message->authorities[0].name_content);     */
	if (message->header->rcode != extDnsResponseRefused ) {
		printf ("ERROR: expected to find error code %d but found %d\n", message->header->rcode, extDnsResponseNoError);
		return axl_false;
	} /* end if */

	
/*	printf ("Message size: %d\n", message->message_size);  */
	if (message->message_size != 32) {
		printf ("ERROR: expected a message size reply of 12 but found %d\n", 
			message->message_size);
		return axl_false;
	} /* end if */

	if (ext_dns_message_is_name_error (message)) {
		printf ("ERROR: expected to NOT find name resolution error but found the function doesn't reports that\n");
		return axl_false;
	}

	if (! ext_dns_message_is_reject (message)) {
		printf ("ERROR: expected to find name reject error but found the function doesn't reports that\n");
		return axl_false;
	}

	/* release message */
	ext_dns_message_unref (message);

	ext_dns_async_queue_unref (queue);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true; /* return ok */
}

axl_bool test_13 (void) {

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
	ext_dns_message_query (ctx, "a", "in", "reject.aspl.es.builder", dns_server, dns_server_port, queue_reply, queue);

	/* get reply (timeout in 3seconds) */
	message = ext_dns_async_queue_timedpop (queue, 3000000);
	if (message == NULL) {
		printf ("ERROR: expected to find message reply but found NULL reference..\n");
		return axl_false;
	}

	/* check header */
	if (! check_header (message, 
			    /* is query */ axl_false, 
			    /* ans count */ 0, 
			    /* query count */ 1,
			    /* authority count */ 0,
			    /* additional count */ 0))
		return axl_false;

	/*	if (! check_answer (ctx, &message->authorities[0], ".", extDnsTypeSOA, extDnsClassIN, NULL))
		return axl_false;  */

	if (message->header->rcode != extDnsResponseNameError ) {
		printf ("ERROR: expected to find error code %d but found %d\n", message->header->rcode, extDnsResponseNameError);
		return axl_false;
	} /* end if */

	/* printf ("Message size: %d\n", message->message_size); */
	if (message->message_size != 115 && message->message_size != 170 && message->message_size != 40) {
		printf ("ERROR: expected a message size reply of 115, 70 or 40 but found %d\n", 
			message->message_size);
		return axl_false;
	} /* end if */

	if (! ext_dns_message_is_name_error (message)) {
		printf ("ERROR: expected to find name resolution error but found the function doesn't reports that\n");
		return axl_false;
	}

	/* release message */
	ext_dns_message_unref (message);

	ext_dns_async_queue_unref (queue);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true; /* return ok */
}

axl_bool test_14 (void) {

	extDnsCtx        * ctx;
	extDnsMessage    * message;
	extDnsAsyncQueue * queue;

	if (! axl_cmp (dns_server, "localhost")) {
		printf ("WARNING: skip asking to %s for this test..because we would need the server to reject answering to reject.aspl.es\n", dns_server);
		return axl_true;
	}

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
	ext_dns_message_query (ctx, "a", "in", "trigger-unknown.aspl.es", dns_server, dns_server_port, queue_reply, queue);

	/* get reply (timeout in 3seconds) */
	message = ext_dns_async_queue_timedpop (queue, 3000000);
	if (message == NULL) {
		printf ("ERROR: expected to find message reply but found NULL reference..\n");
		return axl_false;
	}

	/* check header */
	if (! check_header (message, 
			    /* is query */ axl_false, 
			    /* ans count */ 0, 
			    /* query count */ 1,
			    /* authority count */ 0,
			    /* additional count */ 0))
		return axl_false;

	/* printf ("values: %s %d %d %s\n", message->authorities[0].name, message->authorities[0].type, 
	   message->authorities[0].class, message->authorities[0].name_content);     */
	if (message->header->rcode != extDnsResponseNameError ) {
		printf ("ERROR: expected to find error code %d but found %d\n", message->header->rcode, extDnsResponseNameError);
		return axl_false;
	} /* end if */

	/* printf ("Message size: %d\n", message->message_size); */
	if (message->message_size != 41) {
		printf ("ERROR: expected a message size reply of 108 or 94 but found %d\n", 
			message->message_size);
		return axl_false;
	} /* end if */

	/* release message */
	ext_dns_message_unref (message);

	ext_dns_async_queue_unref (queue);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true; /* return ok */
}

axl_bool check_ipv4 (const char * ip, axl_bool should_work)
{
	axl_bool result = ext_dns_support_is_ipv4 (ip);

	if (should_work && ! result) {
		printf ("ERROR: expected to find function to detect %s as IPv4 but it wasn't..\n", ip);
		exit (-1);
	} else if (! should_work && result) {
		printf ("ERROR: expected to find function to NOT detect %s as IPv4 but it was..\n", ip);
		exit (-1);
	}
	
	return axl_true;
}

axl_bool test_15 (void) {

	extDnsCtx        * ctx;
	extDnsMessage    * message;
	extDnsAsyncQueue * queue;

	if (! axl_cmp (dns_server, "localhost")) {
		printf ("WARNING: skip asking to %s for this test..because we would need the server to reject answering to reject.aspl.es\n", dns_server);
		return axl_true;
	}

	/* check IPv4 value detection .. */
	check_ipv4 ("192.168.0.12", axl_true);
	check_ipv4 ("1.168.0.12", axl_true);
	check_ipv4 ("1.1.0.1", axl_true);
	check_ipv4 ("192.168.0.255", axl_false);
	check_ipv4 ("255.168.0.12", axl_false);
	check_ipv4 ("0.168.0.0", axl_false);
	check_ipv4 ("0.0.0.0", axl_false);

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
	ext_dns_message_query (ctx, "a", "in", "rewrite-request.google.com", dns_server, dns_server_port, queue_reply, queue);

	/* get reply (timeout in 3seconds) */
	message = ext_dns_async_queue_timedpop (queue, 3000000);
	if (message == NULL) {
		printf ("ERROR: expected to find message reply but found NULL reference..\n");
		return axl_false;
	}

	/* check header */
	if (! check_header (message, 
			    /* is query */ axl_false, 
			    /* ans count */ 1, 
			    /* query count */ 1,
			    /* authority count */ 0,
			    /* additional count */ 0))
		return axl_false;

	/* printf ("values: %s %d %d %s\n", message->answers[0].name, message->answers[0].type, 
	   message->answers[0].class, message->answers[0].name_content);      */
	if (message->header->rcode != extDnsResponseNoError ) {
		printf ("ERROR: expected to find error code %d but found %d\n", message->header->rcode, extDnsResponseNoError);
		return axl_false;
	} /* end if */

	/* printf ("Message size: %d\n", message->message_size); */
	if (message->message_size != 86) {
		printf ("ERROR: expected a message size reply of 86 but found %d\n", 
			message->message_size);
		return axl_false;
	} /* end if */

	/* release message */
	ext_dns_message_unref (message);

	ext_dns_async_queue_unref (queue);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true; /* return ok */
}

axl_bool test_16 (void) {

	extDnsCtx        * ctx;
	extDnsMessage    * message;
	extDnsAsyncQueue * queue;

	if (! axl_cmp (dns_server, "localhost")) {
		printf ("WARNING: skip asking to %s for this test..because we would need the server rewrite rewrite.asplhosting.com\n", dns_server);
		return axl_true;
	}

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
	ext_dns_message_query (ctx, "a", "in", "rewrite.asplhosting.com", dns_server, dns_server_port, queue_reply, queue);

	/* get reply (timeout in 3seconds) */
	message = ext_dns_async_queue_timedpop (queue, 3000000);
	if (message == NULL) {
		printf ("ERROR: expected to find message reply but found NULL reference..\n");
		return axl_false;
	}

	/* check header */
	if (! check_header (message, 
			    /* is query */ axl_false, 
			    /* ans count */ 1, 
			    /* query count */ 1,
			    /* authority count */ 0,
			    /* additional count */ 0))
		return axl_false;

	/* printf ("values: %s %d %d %s\n", message->answers[0].name, message->answers[0].type, 
	   message->answers[0].class, message->answers[0].name_content);      */
	if (message->header->rcode != extDnsResponseNoError ) {
		printf ("ERROR: expected to find error code %d but found %d\n", message->header->rcode, extDnsResponseNoError);
		return axl_false;
	} /* end if */

	/* printf ("Message size: %d\n", message->message_size); */
	if (message->message_size != 86 &&
	    message->message_size != 89) {
		printf ("ERROR: expected a message size reply of 86 but found %d\n", 
			message->message_size);
		return axl_false;
	} /* end if */

	/* release message */
	ext_dns_message_unref (message);

	ext_dns_async_queue_unref (queue);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true; /* return ok */
}

axl_bool test_17 (void) {

	extDnsCtx        * ctx;
	extDnsMessage    * message;
	extDnsAsyncQueue * queue;

	if (! axl_cmp (dns_server, "localhost")) {
		printf ("WARNING: skip asking to %s for this test..because we would need the server rewrite rewrite.asplhosting.com\n", dns_server);
		return axl_true;
	}

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
	ext_dns_message_query (ctx, "a", "in", "www.google-analytics.com", dns_server, dns_server_port, queue_reply, queue);

	/* get reply (timeout in 3seconds) */
	message = ext_dns_async_queue_timedpop (queue, 3000000);
	if (message == NULL) {
		printf ("ERROR: expected to find message reply but found NULL reference..\n");
		return axl_false;
	}

	/* check header */
	if (! check_header (message, 
			    /* is query */ axl_false, 
			    /* ans count */ 9, 
			    /* query count */ 1,
			    /* authority count */ 0,
			    /* additional count */ 0))
		return axl_false;

	/* printf ("values: %s %d %d %s\n", message->answers[0].name, message->answers[0].type, 
	   message->answers[0].class, message->answers[0].name_content);      */
	if (message->header->rcode != extDnsResponseNoError ) {
		printf ("ERROR: expected to find error code %d but found %d\n", message->header->rcode, extDnsResponseNoError);
		return axl_false;
	} /* end if */

	/* printf ("Message size: %d\n", message->message_size); */
	if (message->message_size != 505) {
		printf ("ERROR: expected a message size reply of 86 but found %d\n", 
			message->message_size);
		return axl_false;
	} /* end if */

	/* release message */
	ext_dns_message_unref (message);

	ext_dns_async_queue_unref (queue);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true; /* return ok */
}

axl_bool test_18 (void) {

	extDnsCtx        * ctx;

	if (! axl_cmp (dns_server, "localhost")) {
		printf ("WARNING: skip asking to %s for this test..because we would need the server rewrite rewrite.asplhosting.com\n", dns_server);
		return axl_true;
	}

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
	if (ext_dns_message_query (ctx, "a", "in", "www.asplfkdfskjdfaklsdfjawlekjqrqwjkerksdfjkljwerkwlejrlkjweqklejrlsdfsdf.es", dns_server, dns_server_port, NULL, NULL)) {
		printf ("ERROR: bigger labels aren't allowed and ext-dns message query reported ok..\n");
		return axl_false;
	}

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true; /* return ok */
}

axl_bool test_19 (void) {

	extDnsCtx        * ctx;
	char               buffer[512];
	int                iterator;

	if (! axl_cmp (dns_server, "localhost")) {
		printf ("WARNING: skip asking to %s for this test..because we would need the server rewrite rewrite.asplhosting.com\n", dns_server);
		return axl_true;
	}

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

	
	/* now send header with no content */
	iterator = 0;
	while (iterator < 512) {
		if (ext_dns_session_send_udp (ctx, (const char *) buffer, iterator, dns_server, dns_server_port, NULL, NULL) != iterator) {
			printf ("ERROR: failed to send content to regression test server (content length=%d)\n", iterator);
			return axl_false;
		} /* end if */

		/* next position */
		iterator++;
	} /* end while */

	/* now send a header with content */
	buffer[5] = 17;
	buffer[7] = 9;
	buffer[9] = 8;
	buffer[11] = 21;

	iterator = 0;
	while (iterator < 512) {
		if (ext_dns_session_send_udp (ctx, (const char *) buffer, iterator, dns_server, dns_server_port, NULL, NULL) != iterator) {
			printf ("ERROR: failed to send content to regression test server (content length=%d)\n", iterator);
			return axl_false;
		} /* end if */

		/* next position */
		iterator++;
	} /* end while */
	
	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true; /* return ok */
}

axl_bool test_20 (void) {

	extDnsCtx        * ctx;
	char               buffer[512];
	int                bytes_written;
	int                iterator;

	if (! axl_cmp (dns_server, "localhost")) {
		printf ("WARNING: skip asking to %s for this test..because we would need the server rewrite rewrite.asplhosting.com\n", dns_server);
		return axl_true;
	}

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

	/* build query */
	bytes_written = ext_dns_message_build_query (ctx, "www.aspl.es", extDnsTypeA, extDnsClassIN, buffer, NULL);
	/* now increase number of questions */
	ext_dns_set_16bit (3, buffer + 4);

	/* now send content */
	iterator = 0;
	while (iterator < 10) {
		if (ext_dns_session_send_udp (ctx, buffer, bytes_written, dns_server, dns_server_port, NULL, NULL) != bytes_written) {
			printf ("ERROR: failed to send buffer with wrong message..\n");
			return axl_false;
		} /* end if */

		/* next iterator */
		iterator++;
	} /* end while */

	/* wait a bit */
	printf ("Test 20: waiting for server to remove blacklist for next test (5 seconds)..\n");
	sleep (5);
	fflush (stdout);
	
	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true; /* return ok */
}

axl_bool test_21 (void) {

	extDnsCtx        * ctx;
	int                iterator;
	extDnsAsyncQueue * queue;
	extDnsMessage    * message;

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

	iterator = 0;
	while (iterator < 10) {
		ext_dns_message_query (ctx, "a", "in", "www.google.com", dns_server, dns_server_port, queue_reply, queue);

		/* get reply (timeout in 3seconds) */
		message = ext_dns_async_queue_timedpop (queue, 3000000);
		if (message == NULL) {
			printf ("ERROR: expected to find message reply but found NULL reference (A www.google.com)..\n");
			return axl_false;
		}
		
		/* check header */
		if (! check_header (message, 
				    /* is query */ axl_false, 
				    /* ans count */ 5, 
				    /* query count */ 1,
				    /* authority count */ 0,
				    /* additional count */ 0))
			return axl_false;
		
		if (message->answers[0].type != extDnsTypeA) {
			printf ("ERROR: Expected to receive an A (%d) type in the answer but got %d\n",
				message->answers[0].type, extDnsTypeA);
			return axl_false;
		} /*  end if */

		/* release message */
		ext_dns_message_unref (message);

		/* now do the same query but to other registry */
		ext_dns_message_query (ctx, "aaaa", "in", "www.google.com", dns_server, dns_server_port, queue_reply, queue);

		/* get reply (timeout in 3seconds) */
		message = ext_dns_async_queue_timedpop (queue, 3000000);
		if (message == NULL) {
			printf ("ERROR: expected to find message reply but found NULL reference (AAAA www.google.com)..\n");
			return axl_false;
		}
		
		/* check header */
		if (! check_header (message, 
				    /* is query */ axl_false, 
				    /* ans count */ 1, 
				    /* query count */ 1,
				    /* authority count */ 0,
				    /* additional count */ 0))
			return axl_false;
		
		if (message->answers[0].type != extDnsTypeAAAA) {
			printf ("ERROR: Expected to receive an AAAA (%d) type in the answer but got %d\n",
				message->answers[0].type, extDnsTypeAAAA);
			return axl_false;
		} /*  end if */

		/* release message */
		ext_dns_message_unref (message);

		/* next iterator */
		iterator++;
	} /* end while */
	
	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	ext_dns_async_queue_unref (queue);

	return axl_true; /* return ok */
}

axl_bool test_22 (void) {
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
	ext_dns_message_query (ctx, "a", "in", "49fkfker3rfed.aspl.es", dns_server, dns_server_port, queue_reply, queue);

	/* get reply (timeout in 3seconds) */
	message = ext_dns_async_queue_timedpop (queue, 3000000);
	if (message != NULL) {
		printf ("ERROR: expected to find NULL message reply but found reference defined..\n");
		return axl_false;
	}


	/* release queue */
	ext_dns_async_queue_unref (queue);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);
	

	return axl_true;
}

axl_bool test_23 (void) {
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
	ext_dns_message_query (ctx, "a", "in", "49fkfker3rfed-timeout.aspl.es", dns_server, dns_server_port, queue_reply, queue);

	/* get reply (timeout in 3seconds) */
	message = ext_dns_async_queue_timedpop (queue, 3000000);
	if (message != NULL) {
		printf ("ERROR: expected to find NULL message reply but found reference defined..\n");
		return axl_false;
	}

	/* release queue */
	ext_dns_async_queue_unref (queue);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);
	

	return axl_true;
}

axl_bool test_24 (void) {
	extDnsCtx        * ctx;
	extDnsMessage    * message;
	extDnsAsyncQueue * queue;
	int                bytes_written;
	char               buffer[512];

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

	/* check we cannot pass wrong values */
	queue = ext_dns_async_queue_new ();
	ext_dns_message_query (ctx, "a", "in", '\0', dns_server, dns_server_port, queue_reply, queue);
	ext_dns_message_query (ctx, "a", "in", NULL, dns_server, dns_server_port, queue_reply, queue);

	/* build query */
	bytes_written = ext_dns_message_build_query (ctx, "www.aspl.es", extDnsTypeA, extDnsClassIN, buffer, NULL);
	printf ("Test 24: bytes written into the buffer: %d bytes\n", bytes_written);

	/* break request */
	buffer[12] = 0;
	buffer[13] = 0;

	/* send content */
	if (ext_dns_session_send_udp (ctx, (const char *) buffer, bytes_written, dns_server, dns_server_port, NULL, NULL) != bytes_written) {
		printf ("ERROR: failed to send content to regression test server (content length=%d)\n", bytes_written);
		return axl_false;
	} /* end if */

	/* break request */
	buffer[12] = '.';

	/* send content */
	if (ext_dns_session_send_udp (ctx, (const char *) buffer, bytes_written, dns_server, dns_server_port, NULL, NULL) != bytes_written) {
		printf ("ERROR: failed to send content to regression test server (content length=%d)\n", bytes_written);
		return axl_false;
	} /* end if */

	printf ("Test 24: message sent..\n");

	/* get reply (timeout in 3seconds) */
	message = ext_dns_async_queue_timedpop (queue, 3000000);
	if (message != NULL) {
		printf ("ERROR: expected to find NULL message reply but found reference defined..\n");
		return axl_false;
	}

	/* release queue */
	ext_dns_async_queue_unref (queue);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);
	

	return axl_true;
}

axl_bool __test_25_foreach (axlPointer key, axlPointer data, axlPointer user_data)
{
	printf ("Test 25: '%s' => '%s'\n", (const char *) key, (const char *) data);
	return axl_false; /* do not stop */
}

void test_25_check (axlHash * ipv4, const char * host, const char * key)
{
	if (! axl_cmp ((const char *) axl_hash_get (ipv4, (axlPointer) host), key)) {
		printf ("ERROR: expected to find %s for host %s but found: %s\n", key, host, (const char *) axl_hash_get (ipv4, (axlPointer) host));
		exit (-1);
	}
	return;
}

axl_bool test_25 (void) {

	extDnsCtx        * ctx;
	axlHash          * ipv4;
	axlHash          * ipv6;

	/* create context object */
	ctx = ext_dns_ctx_new ();
	if (ctx == NULL) {
		printf ("ERROR: failed to allocate ctx object..\n");
		return axl_false;
	}

	/* init context */
	if (! ext_dns_init_ctx (ctx)) {
		printf ("ERROR: failed to initiatialize ext-dns server context..\n");
		exit (-1);
	} 

	/* load file */
	ext_dns_load_etc_hosts (ctx, "hosts", &ipv4, &ipv6);

	printf ("Test 25: loaded IPv4 %d items\n", axl_hash_items (ipv4));
	axl_hash_foreach (ipv4, __test_25_foreach, NULL);
	printf ("Test 25: loaded IPv6 %d items\n", axl_hash_items (ipv6));

	if (axl_hash_items (ipv4) != 12) {
		printf ("ERROR: expected to find 12 elements but found %d\n", axl_hash_items (ipv4));
		return axl_false;
	}

	if (axl_hash_items (ipv6) != 0) {
		printf ("ERROR: expected to find 0 elements but found %d\n", axl_hash_items (ipv6));
		return axl_false;
	}

	test_25_check (ipv4, "prueba", "192.168.0.100");
	test_25_check (ipv4, "prueba2", "192.168.0.100");
	test_25_check (ipv4, "prueba3", "192.168.0.100");
	test_25_check (ipv4, "prueba4", "192.168.0.100");

	test_25_check (ipv4, "prueba5", "192.168.1.100");
	test_25_check (ipv4, "test1", "192.168.1.100");
	test_25_check (ipv4, "test2", "192.168.1.100");

	test_25_check (ipv4, "localhost", "127.0.0.1");
	test_25_check (ipv4, "desktop1", "192.168.1.100");
	test_25_check (ipv4, "desktop2", "192.168.1.101");
	test_25_check (ipv4, "desktop3", "192.168.1.102");
	test_25_check (ipv4, "desktop4", "192.168.1.103");

	/* release hashes */
	axl_hash_free (ipv4);
	axl_hash_free (ipv6);

	/* release content */
	ext_dns_exit_ctx (ctx, axl_true);

	return axl_true;
}


typedef axl_bool  (*extDnsRegressionTest) (void);

axl_bool disable_time_checks = axl_true;

axl_bool check_and_run_test (const char * test_list, const char * test_name) 
{
	char ** tests;
	int     iterator;

	if (strstr (test_list, ",")) {
		/* passed test list */
		tests    = axl_split (test_list, 1, ",");
		if (tests == NULL)
			return axl_false;
		iterator = 0;
		while (tests[iterator]) {
			/* check if the user provided the test and if it matches with test_name */
			if (axl_cmp (tests[iterator], test_name)) {
				axl_freev (tests);
				return axl_true;
			}

			/* next position */
			iterator++;
		}
		axl_freev (tests);
		return axl_false;
	} 

	/* single test passed */
	return axl_cmp (test_list, test_name);
}

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
	const char * run_test_name = NULL;
	int iterator;
	
	printf ("** extDns Library: A DNS framework\n");
	printf ("** Copyright (C) 2012 Advanced Software Production Line, S.L.\n**\n");
	printf ("** extDns Regression tests: version=%s\n**\n",
		VERSION);
	printf ("** To gather information about memory consumed (and leaks) use:\n**\n");
	printf ("**     >> libtool --mode=execute valgrind --leak-check=yes --error-limit=no ./ext-dns-regression-client\n**\n");
	printf ("** Additional settings:\n");
	printf ("**\n");
	printf ("**     >> ./ext-dns-regression-client --[run-test=NAME] [dns-server [dns-port]] \n");
	printf ("**        by default dns-server=localhost dns-port=53\n");
	printf ("**\n");
	printf ("**       Providing --run-test=NAME will run only the provided regression test.\n");
	printf ("**       Test available: test_01, test_02, test_03, test_04, test_04a, test_05\n");
	printf ("**                       test_06, test_07, test_08, test_09, test_10\n");
	printf ("**                       test_11, test_12, test_13, test_14, test_15\n");
	printf ("**                       test_16, test_17, test_18, test_19, test_20\n");
	printf ("**                       test_21, test_22, test_23, test_24, test_25\n");
	printf ("**\n");

	/* check for disable-time-checks */
	if (argc > 1 && axl_memcmp (argv[1], "--run-test=", 11)) {
		run_test_name  = argv[1] + 11;
		iterator       = 1;
		argc--;

		printf ("INFO: running test=%s\n", run_test_name);
		while (iterator <= argc) {
			argv[iterator] = argv[iterator+1];
			iterator++;
		} /* end while */
	} /* end if */

	/* check server destination */
	if (argc > 1) 
		dns_server = argv[1];

	if (run_test_name) {
		printf ("INFO: Checking to run test: %s..\n", run_test_name);
		
		if (check_and_run_test (run_test_name, "test_01"))
			run_test (test_01, "Test 01", "basic extDNS initialization", -1, -1);

		if (check_and_run_test (run_test_name, "test_02"))
			run_test (test_02, "Test 02", "basic A query", -1, -1);

		if (check_and_run_test (run_test_name, "test_03"))
			run_test (test_03, "Test 03", "basic MX query", -1, -1);

		if (check_and_run_test (run_test_name, "test_04"))
			run_test (test_04, "Test 04", "basic CNAME query", -1, -1);

		if (check_and_run_test (run_test_name, "test_04a"))
			run_test (test_04a, "Test 04-a", "basic CNAME query (complete reply)", -1, -1);

		if (check_and_run_test (run_test_name, "test_05"))
			run_test (test_05, "Test 05", "basic CNAME as A query", -1, -1);

		if (check_and_run_test (run_test_name, "test_06"))
			run_test (test_06, "Test 06", "basic NS query", -1, -1);

		if (check_and_run_test (run_test_name, "test_07"))
			run_test (test_07, "Test 07", "basic TXT query", -1, -1);

		if (check_and_run_test (run_test_name, "test_08"))
			run_test (test_08, "Test 08", "basic SOA query", -1, -1);

		if (check_and_run_test (run_test_name, "test_09"))
			run_test (test_09, "Test 09", "basic PTR query", -1, -1);

		if (check_and_run_test (run_test_name, "test_10"))
			run_test (test_10, "Test 10", "handle query for unknown records", -1, -1);

		if (check_and_run_test (run_test_name, "test_11"))
			run_test (test_11, "Test 11", "basic SRV query", -1, -1);

		if (check_and_run_test (run_test_name, "test_12"))
			run_test (test_12, "Test 12", "handing reject codes", -1, -1);

		if (check_and_run_test (run_test_name, "test_13"))
			run_test (test_13, "Test 13", "handing query for unknown domains", -1, -1);

		if (check_and_run_test (run_test_name, "test_14"))
			run_test (test_14, "Test 14", "handle fake unknown records", -1, -1);

		if (check_and_run_test (run_test_name, "test_15"))
			run_test (test_15, "Test 15", "handling IPv4 rewritting replies", -1, -1);

		if (check_and_run_test (run_test_name, "test_16"))
			run_test (test_16, "Test 16", "handling CNAME rewritting replies", -1, -1);
		
		if (check_and_run_test (run_test_name, "test_17"))
			run_test (test_17, "Test 17", "handling queries with multiple results ", -1, -1);

		if (check_and_run_test (run_test_name, "test_18"))
			run_test (test_18, "Test 18", "handling longer query names", -1, -1);

		if (check_and_run_test (run_test_name, "test_19"))
			run_test (test_19, "Test 19", "testing malformed messages..", -1, -1);

		if (check_and_run_test (run_test_name, "test_20"))
			run_test (test_20, "Test 20", "testing malformed messages (2)..", -1, -1);

		if (check_and_run_test (run_test_name, "test_21"))
			run_test (test_21, "Test 21", "testing cache (objects with the name name, different type)..", -1, -1);

		if (check_and_run_test (run_test_name, "test_22"))
			run_test (test_22, "Test 22", "testing requests that fails", -1, -1);

		if (check_and_run_test (run_test_name, "test_23"))
			run_test (test_23, "Test 23", "testing requests that timeouts", -1, -1);

		if (check_and_run_test (run_test_name, "test_24"))
			run_test (test_24, "Test 24", "testing sending broken packages with NULL at resource name", -1, -1);

		if (check_and_run_test (run_test_name, "test_25"))
			run_test (test_25, "Test 25", "testing local /etc/hosts support", -1, -1);

		goto finish;
	}

	/* tests */
	run_test (test_01, "Test 01", "basic extDNS initialization", -1, -1);

	run_test (test_02, "Test 02", "basic A query", -1, -1);

	run_test (test_03, "Test 03", "basic MX query", -1, -1);

	run_test (test_04, "Test 04", "basic CNAME query", -1, -1);

	run_test (test_04a, "Test 04-a", "basic CNAME query (complete reply)", -1, -1);

	run_test (test_05, "Test 05", "basic CNAME as A query", -1, -1);

	run_test (test_06, "Test 06", "basic NS query", -1, -1);

	run_test (test_07, "Test 07", "basic TXT query", -1, -1);

	run_test (test_08, "Test 08", "basic SOA query", -1, -1);

	run_test (test_09, "Test 09", "basic PTR query", -1, -1);

	run_test (test_10, "Test 10", "handle query for unknown records", -1, -1);

	run_test (test_11, "Test 11", "basic SRV query", -1, -1);

	run_test (test_12, "Test 12", "handing reject codes", -1, -1);

	run_test (test_13, "Test 13", "handing query for unknown domains", -1, -1);

	run_test (test_14, "Test 14", "handle fake unknown records", -1, -1);

	run_test (test_15, "Test 15", "handling IPv4 rewritting replies", -1, -1);

	run_test (test_16, "Test 16", "handling CNAME rewritting replies", -1, -1);

	run_test (test_17, "Test 17", "handling queries with multiple results ", -1, -1);

	run_test (test_18, "Test 18", "handling longer query names", -1, -1);

	/*** test mal formed messages ***/
	run_test (test_19, "Test 19", "testing malformed messages..", -1, -1);

	/* test sending a query with several queries but only placing one.. */
	run_test (test_20, "Test 20", "testing malformed messages (2)..", -1, -1);

	run_test (test_21, "Test 21", "testing cache (objects with the name name, different type)..", -1, -1);

	run_test (test_22, "Test 22", "testing requests that fails", -1, -1);

	run_test (test_23, "Test 23", "testing requests that timeouts", -1, -1);

	run_test (test_24, "Test 24", "testing sending broken packages with NULL at resource name", -1, -1);

	run_test (test_25, "Test 25", "testing local /etc/hosts support", -1, -1);
	
	/* test sending q query where the replies should have several
	   but only were found a few */

	/* set sending a query message (flagged as is) but no
	 * questions in the body */

finish:

	printf ("**\n");
	printf ("** INFO: All test ok!\n");
	printf ("**\n");
	
	return 0;
}
