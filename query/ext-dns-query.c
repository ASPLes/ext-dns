/* 
 *  ext-dns: a framework to build DNS solutions
 *  Copyright (C) 2020 Advanced Software Production Line, S.L.
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
 *         Avenida Juan Carlos I Nº13, 2ºC (Torre Garena)
 *         Alcalá de Henares 28806 Madrid
 *         Spain
 *
 *      Email address:
 *         info@aspl.es - http://www.aspl.es/ext-dns
 */

#include <ext-dns.h>
#include <exarg.h>

#define HELP_HEADER "ext-dns: a framework to build DNS solutions\n\
Copyright (C) 2012  Advanced Software Production Line, S.L.\n\
\n\
To run a simple A query use:\n\
\n\
  ext-dns-query host-name [dns-server]\n\
\n\
"

#define POST_HEADER "\n\
If you have question, bugs to report, patches, you can reach us\n\
at <ext-dns@lists.aspl.es>."

/* disable verbose */
axl_bool verbose = axl_false;

void install_arguments (int argc, char ** argv) {

	/* install headers for help */
	exarg_add_usage_header  (HELP_HEADER);
	exarg_add_help_header   (HELP_HEADER);
	exarg_post_help_header  (POST_HEADER);
	exarg_post_usage_header (POST_HEADER);

	/* init exarg library */
	exarg_install_arg ("version", "e", EXARG_NONE, 
			   "Shows ext-dns-query version.");
	exarg_install_arg ("verbose", "v", EXARG_NONE, 
			   "Shows enable tool verbose output.");
	exarg_install_arg ("debug", "d", EXARG_NONE, 
			   "Enable ext-dns debug output.");
	exarg_install_arg ("type", "t", EXARG_STRING, 
			   "By default, query sent to the DNS server uses A and class IN. With this flag you can change the query to other resource record type: mx, cname, hinfo, etc.");
	/* debug options */
	exarg_install_arg ("release-resources-on-finish", "z", EXARG_NONE,
			   "By default, the tool will query and show the result and exit without releasing all resources that may be acquired. This is fine in many cases because the application is about to finish so there is no point to release those resources. However, while debugging, you can enable this option to check that the tool do not leak");
	exarg_install_arg ("flood-dns-server", "f", EXARG_INT,
			   "Allows to send send the amount of requests indicated by the user (randomly created) to the server in question. SECURITY CONSIDERATION: this is a debugging tool that you must use with your own server: NEVER against shared servers or DNS servers that aren't yours.");


	/* call to parse arguments */
	exarg_parse (argc, argv);

	/* normal operations */
	if (exarg_is_defined ("version")) {
		printf ("%s\n", VERSION);
		exit (0);
	}

	if (exarg_is_defined ("verbose")) {
		verbose = axl_true;
	}

	return;
}

void ext_dns_query_on_message (extDnsCtx     * ctx,
			       extDnsSession * session,
			       const char    * source_address,
			       int             source_port,
			       extDnsMessage * message,
			       axlPointer      data)
{
	extDnsAsyncQueue * queue = data;
	
	if (verbose)
		printf ("INFO: received message from %s:%d (queue: %p)..\n", source_address, source_port, queue);

	/* increase reference counting to avoid having the message
	 * deleted after this handler finishes. */
	ext_dns_message_ref (message);

	/* push queue */
	ext_dns_async_queue_push (queue, message);

	return;
}

void ext_dns_query_show_message_as_host (extDnsCtx * ctx, extDnsMessage * message, const char * server, int server_port)
{
	int    count = 0;
	/* extDnsResourceRecord * record; */

	printf ("Using domain server:\n");
	printf ("Name: %s\n", server);
	printf ("Address: %s#%d\n", server, server_port);
	printf ("Aliases: \n");
	printf ("\n");

	if (message->header->answer_count == 0) {
		printf ("%s has no %s record\n", 
			message->questions[0].qname, ext_dns_message_get_qtype_to_str (ctx, message->questions[0].qtype));
		return;
	}

	while (count < message->header->answer_count) {
		
		/* get next count */
		if (message->answers[count].type == extDnsTypeA)
			printf ("%s has address %s\n", message->answers[count].name, message->answers[count].name_content);
		else if (message->answers[count].type == extDnsTypeMX)
			printf ("%s mail is handled by %s\n", message->answers[count].name, message->answers[count].name_content);
		else
			printf ("%s  %s  %s  ttl:%d   rdlength:%d\n", 
				message->answers[count].name, 
				ext_dns_message_get_qtype_to_str (ctx, message->answers[count].type), 
				ext_dns_message_get_qclass_to_str (ctx, message->answers[count].class), 
				message->answers[count].ttl,
				message->answers[count].rdlength);


		/* next answer */
		count++;
	}

	return;
}

/** flooding names */
const char * const flood_names [] = { 
	"google.com", 
	"yahoo.com", 
	"microsoft.com", 
	"elmundo.es", 
	"apple.com", 
	"nasdac.com", 
	"microsoft.com", 
	"aspl.es" 
};

void ext_dns_query_flood_server (extDnsCtx * ctx) 
{
	ExArgument * arg;
	const char * server = NULL;
	int flood_requests;
	int iterator;
	char * name;

	/* get first param */
	arg = exarg_get_params ();

	/* get server asked */
	server = exarg_param_get (arg);
	if (server == NULL) {
		printf ("ERROR: you must provide a server name to query to\n");
		exit (-1);
	} /* end if */

	/* get flood requests */
	flood_requests = exarg_get_int ("flood-dns-server");
	
	printf ("FLOODING: sending %d requests without waiting to: %s:53\n", flood_requests, server);

	/* create base name */
	iterator = 0;
	while (iterator < flood_requests) {
		/* get name to query */
		name = axl_strdup_printf ("www%d.%s", iterator, flood_names[iterator % 8]);
		ext_dns_message_query (ctx, "A", "IN", name, server, 53, NULL, NULL);
		axl_free (name);

		iterator++;
	} /* end while */
	

	return;
}

void ext_dns_query_do_request (extDnsCtx * ctx) {
	ExArgument    * arg;
	const char    * qname;
	/* by default A type is used */
	const char    * qtype  = "A";
	extDnsType      _qtype;

	/* by default IN class is used */
	const char    * qclass = "IN";
	extDnsClass     _qclass;
	const char    * server = NULL;

	/* queue to wait for reply */
	extDnsAsyncQueue * queue;
	extDnsMessage    * message;

	/* get first param */
	arg = exarg_get_params ();

	/* get question name */
	qname = exarg_param_get (arg);

	/* get server asked */
	arg = exarg_param_next (arg);
	if (exarg_param_get (arg))
		server = exarg_param_get (arg);

	if (server == NULL) {
		printf ("ERROR: you must provide a server name to query to\n");
		exit (-1);
	}

	if (verbose)
		printf ("Running query: %s type:%s class:%s %s %s\n", 
			qname, qtype, qclass, server ? "to" : "", 
			server ? server : "");

	/* check for type query */
	if (exarg_is_defined ("type"))
		qtype = exarg_get_string ("type");

	/* check qtype and qclass received */
	_qtype  = ext_dns_message_get_qtype (ctx, qtype);
	_qclass = ext_dns_message_get_qclass (ctx, qclass);
	if (_qtype == -1) {
		printf ("ERROR: provided a wrong qtype value: %s\n", qtype);
		exit (-1);
	} /* end if */
	if (_qclass == -1) {
		printf ("ERROR: provided a wrong qclass value: %s\n", qclass);
		exit (-1);
	} /* end if */

	/* create queue */
	queue = ext_dns_async_queue_new ();
	if (! ext_dns_message_query_int (ctx, _qtype, _qclass, qname, server, 53,
					 ext_dns_query_on_message, queue)) {
		printf ("ERROR: unable to send query to %s\n", qname);
		exit (-1);
	} /* end if */

	/* wait for reply */
	message = ext_dns_async_queue_timedpop (queue, 5000000);
	if (message == NULL) {
		printf ("ERROR: timeout reached while waiting for reply..\n");
		exit (-1);
	}

	/* release queue */
	ext_dns_async_queue_unref (queue);

	/*** message ***/
	ext_dns_query_show_message_as_host (ctx, message, server, 53);

	/* release message */
	ext_dns_message_unref (message);


	return;
}

int main (int argc, char ** argv)
{
	extDnsCtx     * ctx;

	/* install arguments */
	install_arguments (argc, argv);
	
	/* create context object */
	ctx = ext_dns_ctx_new ();
	if (ctx == NULL) {
		printf ("ERROR: failed to allocate ctx object..\n");
		exit (-1);
	}

	/* check for debug output */
	if (exarg_is_defined ("debug")) {
		ext_dns_log_enable (ctx, axl_true);
		ext_dns_log2_enable (ctx, axl_true);
		ext_dns_color_log_enable (ctx, axl_true);
	}

	/* init context */
	if (! ext_dns_init_ctx (ctx)) {
		printf ("ERROR: failed to initiatialize ext-dns server context..\n");
		exit (-1);
	}	

	/* check for query */
	if (exarg_get_params_num () > 0) {
		if (exarg_is_defined ("flood-dns-server")) {
			ext_dns_query_flood_server (ctx);
		} else {
			ext_dns_query_do_request (ctx);
		}
	} /* end if */

	if (exarg_is_defined ("release-resources-on-finish")) {
		/* terminate process */
		ext_dns_exit_ctx (ctx, axl_true);

		/* finish exarg */
		exarg_end ();
	} /* end if */

	return 0;
}
