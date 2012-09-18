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

const char * dns_server = "localhost";
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

axl_bool check_answer (extDnsResourceRecord * rr, const char * name, extDnsType type, extDnsClass class, const char * name_content)
{
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

	if (! axl_cmp (message->answers[1].name_content, "212.170.101.196")) {
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
			if (! found1 && check_answer (&message->answers[iterator], "aspl.es", extDnsTypeNS, extDnsClassIN, "ns1.cuentadns.com")) 
				found1 = axl_true;
		if (axl_cmp (message->answers[iterator].name_content, "ns2.cuentadns.com"))
			if (! found2 && check_answer (&message->answers[iterator], "aspl.es", extDnsTypeNS, extDnsClassIN, "ns2.cuentadns.com"))
				found2 = axl_true;
		if (axl_cmp (message->answers[iterator].name_content, "ns3.cuentadns.com"))
			if (! found3 && check_answer (&message->answers[iterator], "aspl.es", extDnsTypeNS, extDnsClassIN, "ns3.cuentadns.com"))
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
	if (! check_answer (&message->answers[0], "aspl.es", extDnsTypeTXT, extDnsClassIN, "v=spf1 a mx mx:mx1.registrarmail.net ip4:212.170.101.196 mx:mail.aspl.es mx:mail2.aspl.es -all"))
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
 	if (! check_answer (&message->answers[0], "aspl.es", extDnsTypeSOA, extDnsClassIN, NULL))
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
	if (message->answers[0].serial != 2012091403) {
		printf ("ERROR: expected to find %d but found %d\n", 2012091403, message->answers[0].serial);
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
 	if (! check_answer (&message->answers[0], "69.237.140.89.in-addr.arpa", extDnsTypePTR, extDnsClassIN, "smtp-01.aspl.es"))
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
	if (message->message_size != 108 && message->message_size != 94) {
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

	/* printf ("values: %s %d %d %s\n", message->authorities[0].name, message->authorities[0].type, 
	   message->authorities[0].class, message->authorities[0].name_content);     */
	if (message->header->rcode != extDnsResponseNameError ) {
		printf ("ERROR: expected to find error code %d but found %d\n", message->header->rcode, extDnsResponseNameError);
		return axl_false;
	} /* end if */

	/* printf ("Message size: %d\n", message->message_size); */
	if (message->message_size != 108 && message->message_size != 94) {
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
	printf ("**     >> libtool --mode=execute valgrind --leak-check=yes --error-limit=no ./exn-dns-regression-client\n**\n");
	printf ("** Additional settings:\n");
	printf ("**\n");
	printf ("**     >> ./ext-dns-regression-client --[run-test=NAME] [dns-server [dns-port]] \n");
	printf ("**        by default dns-server=localhost dns-port=53\n");
	printf ("**\n");
	printf ("**       Providing --run-test=NAME will run only the provided regression test.\n");
	printf ("**       Test available: test_01, test_02, test_03, test_04, test_05\n");
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

		goto finish;
	}

	/* tests */
	run_test (test_01, "Test 01", "basic extDNS initialization", -1, -1);

	run_test (test_02, "Test 02", "basic A query", -1, -1);

	run_test (test_03, "Test 03", "basic MX query", -1, -1);

	run_test (test_04, "Test 04", "basic CNAME query", -1, -1);

	run_test (test_05, "Test 05", "basic CNAME as A query", -1, -1);

	run_test (test_06, "Test 06", "basic NS query", -1, -1);

	run_test (test_07, "Test 07", "basic TXT query", -1, -1);

	run_test (test_08, "Test 08", "basic SOA query", -1, -1);

	run_test (test_09, "Test 09", "basic PTR query", -1, -1);

	run_test (test_10, "Test 10", "handle query for unknown records", -1, -1);

	run_test (test_11, "Test 11", "basic SRV query", -1, -1);

finish:

	printf ("**\n");
	printf ("** INFO: All test ok!\n");
	printf ("**\n");
	
	return 0;
}
