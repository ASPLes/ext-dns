/* 
 *  ext-dnsd: another, but configurable, DNS server
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

#define HELP_HEADER "ext-dnsd: another, but configurable, DNS server \n\
Copyright (C) 2012  Advanced Software Production Line, S.L.\n"


#define POST_HEADER "\n\
If you have question, bugs to report, patches, you can reach us\n\
at <ext-dns@lists.aspl.es>."

#include <ext-dnsd.h>

axl_bool verbose = axl_false;
axl_bool forward_all_requests = axl_true;

axlDoc     * config = NULL;
const char * path = "/etc/ext-dns/ext-dns.conf";
const char * __pidfile = "/var/run/ext-dnsd.pid";
const char * __blkbrd  = "/var/run/ext-dnsd.status";

/* server we rely request to */
const char * server = "8.8.8.8";
int          server_port = 53;

/* hash to provide results from /etc/hosts */
axlHash    * etchosts = NULL;
axlHash    * etchosts_ipv6 = NULL;
extDnsMutex  etchosts_mutex;


typedef struct _HandleReplyData {
	int             id;
	char          * source_address;
	int             source_port;
	extDnsSession * master_listener;
	extDnsMessage * reply;
	axl_bool        nocache;
} HandleReplyData;

/** 
 * @internal Structure to hold child pending requests.
 */
typedef struct _childPendingRequest {
	extDnsMessage * msg;
	char          * command;
	int             stamp;
	extDnsCtx     * ctx;
	extDnsSession * session;
	char          * source_address;
	int             source_port;

	/* child that finally handles this */
	childState    * child;
} childPendingRequest;

/** reference to childs created and their state **/
childState   * children;
int            children_number;
extDnsMutex    children_mutex;
const char   * child_resolver = NULL;

/** additional global status **/
axlList      * pending_requests;
int            max_pnd_reqs = 150;
int            command_timeout = -1;

/** stats */
extDnsMutex    stat_mutex;
extDnsMutex    pnd_req_mutex;
long int       requests_received = 0;
long int       requests_served   = 0;
long int       failures_found    = 0;

void increase_failures_found (void) {
	ext_dns_mutex_lock (&stat_mutex);
	failures_found ++;
	ext_dns_mutex_unlock (&stat_mutex);
	return;
}

void increase_requests_served (void) {
	ext_dns_mutex_lock (&stat_mutex);
	requests_served ++;
	ext_dns_mutex_unlock (&stat_mutex);
	return;
}

void __release_pending_request (axlPointer _ptr) {
	childPendingRequest * ptr = _ptr;
	if (ptr == NULL)
		return;
	ext_dns_message_unref (ptr->msg);
	axl_free (ptr->command);
	axl_free (ptr->source_address);
	axl_free (ptr);

	return;
}

int ext_dnsd_equal_requests (axlPointer _ptr_a, axlPointer _ptr_b)
{
	if (_ptr_a == _ptr_b)
		return 0;
	return 1;
} /* end if */

void ext_dnsd_finish_childs (void) {
	int iterator = 0;

	while (iterator < children_number) {
		ext_dns_mutex_destroy (&(children[iterator].mutex));
		axl_free (children[iterator].last_command);

		/* next iterator */
		iterator++;
	}

	axl_free (children);
	ext_dns_mutex_destroy (&children_mutex);

	return;
}

void ext_dnsd_release_child_by_pid (int pid)
{
	int          iterator;

	ext_dns_mutex_lock (&children_mutex);

	iterator = 0;
	while (iterator < children_number) {

		/* count */
		if (children[iterator].pid == pid) {
			/* flag child as not usable */
			children[iterator].pid = -1;
			break;
		}

		/* next iterator */
		iterator++;
	} /* end if */

	ext_dns_mutex_unlock (&children_mutex);
	
	/* no child was found */
	return;
}

void ext_dnsd_release_child (childState * child)
{
	ext_dns_mutex_lock (&children_mutex);

	/* flag as ready */
	child->ready = axl_true;

	/* child finished, release it */
	axl_free (child->last_command);
	child->last_command = NULL;

	ext_dns_mutex_unlock (&children_mutex);

	return;
}

int          ext_dnsd_get_children_ready (void)
{
	int total = 0;
	int iterator;

	ext_dns_mutex_lock (&children_mutex);

	iterator = 0;
	while (iterator < children_number) {

		/* count */
		if (children[iterator].ready) 
			total++;

		/* next iterator */
		iterator++;
	} /* end if */

	ext_dns_mutex_unlock (&children_mutex);
	
	/* no child was found */
	return total;
}

int          ext_dnsd_get_children_dead (void)
{
	int total = 0;
	int iterator;

	ext_dns_mutex_lock (&children_mutex);

	iterator = 0;
	while (iterator < children_number) {

		/* count */
		if (children[iterator].pid == -1) 
			total++;

		/* next iterator */
		iterator++;
	} /* end if */

	ext_dns_mutex_unlock (&children_mutex);
	
	/* no child was found */
	return total;
}

childState * ext_dnsd_find_free_child (char * command)
{
	int          iterator;
	childState * child = NULL;

	ext_dns_mutex_lock (&children_mutex);

	iterator = 0;
	while (iterator < children_number) {

		if (children[iterator].ready && children[iterator].pid > 0) {
			/* flag it as not ready */
			children[iterator].ready = axl_false;

			/* get the reference */
			child = &(children[iterator]);

			/* prepare child and send query to a child */
			child->last_command = axl_strdup (command);

			/* record current stamp */
			children[iterator].stamp = time (NULL);

			ext_dns_mutex_unlock (&children_mutex);
			
			return child;
		} /* end if */
		
		/* next iterator */
		iterator++;
	} /* end if */

	ext_dns_mutex_unlock (&children_mutex);
	
	/* no child was found */
	return NULL;
}


void handle_reply_data_free (HandleReplyData * data)
{
	if (data->reply) 
		ext_dns_message_unref (data->reply);
	axl_free (data->source_address);
	axl_free (data);
	return;
}

int  ext_dnsd_readline (int fd, char  * buffer, int  maxlen)
{
	int         n, rc;
	int         desp = 0;
	char        c, *ptr;

	/* read current next line */
	ptr = (buffer + desp);
	for (n = 1; n < (maxlen - desp); n++) {
	__ext_dnsd_readline_again:
		if (( rc = read (fd, &c, 1)) == 1) {
			*ptr++ = c;
			if (c == '\x0A')
				break;
		}else if (rc == 0) {
			if (n == 1)
				return 0;
			else
				break;
		} else {
			if (errno == EXT_DNS_EINTR) 
				goto __ext_dnsd_readline_again;
			if ((errno == EXT_DNS_EWOULDBLOCK) || (errno == EXT_DNS_EAGAIN) || (rc == -2)) 
				return (-2);
			return (-1);
		}
	}

	*ptr = 0;
	return (n + desp);

}

axl_bool send_command (const char * command, childState * child, char * reply, int reply_size)
{
	int  bytes_written;

	/* printf ("sending command %s to child %d\n", command, child->pid); */
	
	/* send command */
	bytes_written = strlen (command);
	if (write (child->fds[1], command, bytes_written) != bytes_written) {
		syslog (LOG_ERR, "ERROR: failed to send command to child, error was errno=%d (%s)", errno, ext_dns_errno_get_last_error ());
		return axl_false;
	}
	if (write (child->fds[1], "\n", 1) != 1) {
		syslog (LOG_ERR, "ERROR: failed to write trailing command, error was errno=%d (%s)", errno, ext_dns_errno_get_last_error ());
		return axl_false;
	}

	/* printf ("reading reply to command..\n"); */

	/* now wait for reply */
	bytes_written = ext_dnsd_readline (child->fds[0], reply, reply_size);

	if (bytes_written <= 0) {
		syslog (LOG_ERR, "ERROR: failed to receive content from child, error was errno=%d (%s)", 
			errno, errno == 0 ? "" :ext_dns_errno_get_last_error ());
		return bytes_written;
	} /* end if */

	/* printf ("data received '%s' (size: %d)\n", reply, bytes_written); */

	/* trim content and recalculate */
	axl_stream_trim (reply);
	bytes_written = strlen (reply);

	/* printf ("bytes received %d\n", bytes_written); */
	return bytes_written;
}

axl_bool ext_dnsd_send_reply (extDnsCtx * ctx, extDnsSession * session, const char * source_address, int source_port, extDnsMessage * reply, axl_bool release_message)
{
	char     buffer[512];
	int      bytes_written;
	axl_bool result = axl_false;

	/* build buffer reply */
	bytes_written = ext_dns_message_to_buffer (ctx, reply, buffer, 512);
	if (bytes_written <= 0) {
		syslog (LOG_ERR, "ERROR: failed to dump message into the buffer, unable to reply to resolver..");
		goto return_result;
	}

	/* send reply */
	if (ext_dns_session_send_udp_s (ctx, session, buffer, bytes_written, source_address, source_port) != bytes_written) {
		syslog (LOG_ERR, "ERROR: failed to send %d bytes as reply, different amount of bytes where written", bytes_written);
		goto return_result;
	} /* end if */

	/* reached this point we were able to send the message */
	result = axl_true;

return_result:
	
	/* release reply */
	if (release_message)
		ext_dns_message_unref (reply);
	
	return axl_true;
}

void handle_reply_complete_cname (extDnsCtx     * ctx,
				  extDnsSession * session,
				  const char    * source_address,
				  int             source_port,
				  extDnsMessage * message,
				  axlPointer      data)
{
	HandleReplyData * handle_reply = (HandleReplyData *) data;

	/* add the message content into the reply */
	if (! ext_dns_message_add_answer_from_msg (ctx, handle_reply->reply, message)) {
		handle_reply_data_free (data);
		return;
	}

	/* send reply, but waithout releasing reply=axl_false which is
	 * done after the function finishes or it if fails */
	if (! ext_dnsd_send_reply (ctx, handle_reply->master_listener, handle_reply->source_address, handle_reply->source_port, handle_reply->reply, axl_false)) {
		handle_reply_data_free (data);
		return;
	}

	/* store reply in the cache */
	if (! handle_reply->nocache) 
		ext_dns_cache_store (ctx, handle_reply->reply, handle_reply->source_address);

	handle_reply_data_free (data);
	
	return;
}

extDnsMessage * ext_dnsd_parse_and_handle_reply (extDnsCtx     * ctx, 
						 extDnsMessage * query, 
						 const char    * reply_buffer,
						 extDnsSession * session,
						 const char    * source_address,
						 int             source_port)
{
	char           ** items;
	extDnsMessage   * reply = NULL;
	int               iterator;
	
	/* get pieces for multiple replies */
	if (strstr (reply_buffer, ",")) {
		/* multiple reply found */
		items = axl_split (reply_buffer, 1, ",");

		/* check result */
		if (items == NULL)
			return NULL;
		
		/* now get and accumulate the reply */
		iterator = 0;
		while (items[iterator]) {

			/* call to get and accumulate replies into a single object */
			reply = ext_dnsd_parse_and_handle_reply_single (ctx, query, reply, items[iterator], session, source_address, source_port);
			if (PTR_TO_INT(reply) == 2 || reply == NULL)
				break;
			if (reply)
				ext_dns_log (EXT_DNS_LEVEL_DEBUG, "MULTIPLE-REPLY: Replies hold in the header: %d", reply->header->answer_count);

			/* next iterator */
			iterator++;
		} /* end while */

		return reply;
	} /* end if */

	/* report single reply received */
	return ext_dnsd_parse_and_handle_reply_single (ctx, query, reply, reply_buffer, session, source_address, source_port);
}

extDnsMessage * ext_dnsd_parse_and_handle_reply_single (extDnsCtx     * ctx, 
							extDnsMessage * query, 
							extDnsMessage * reply,
							const char    * reply_buffer,
							extDnsSession * session,
							const char    * source_address,
							int             source_port)
{
	char           ** items;
	HandleReplyData * handle_reply;
	extDnsMessage   * aux;
	const char      * value;
	int               preference;
	int               ttl;
	int               desp = 0;
	axl_bool          nocache;
	axl_bool          norecurse;

	/* check for additional flags */
	nocache = !(strstr (reply_buffer, "nocache") == NULL);
	if (exarg_is_defined ("debug"))
		syslog (LOG_INFO, "nocache indication was=%d (inside: %s)", nocache, reply_buffer);

	/* check for additional flags */
	norecurse = !(strstr (reply_buffer, "norecurse") == NULL);
	if (exarg_is_defined ("debug"))
		syslog (LOG_INFO, "norecurse indication was=%d (inside: %s)", norecurse, reply_buffer);
	
	/* get items */
	items = axl_split (reply_buffer, 1, " ");

	/* configure desp according to the data inside the reply buffer */
	if (axl_cmp (items[0], "REPLY"))
	    desp = 1;

	/* clean split */
	axl_stream_clean_split (items);

	/* check result */
	if (axl_memcmp (items[desp], "ipv4:", 5)) {

		/* get value */
		value = items[desp] + 5;

		/* check if the value reported a valid ipv4 value */
		if (! ext_dns_support_is_ipv4 (value)) {
			syslog (LOG_ERR, "ERROR: reported something that is not an IP %s..", value ? value : "(null value)" );
			axl_freev (items);

			/* update stats */
			increase_failures_found ();

			return NULL;
		} /* end if */

		/* get ttl */
		ttl = ext_dns_atoi (items[desp + 1]);
		if (exarg_is_defined ("debug"))
			syslog (LOG_INFO, "Script reported to use IP %s (with ttl %d) as reply..", items[desp] + 5, ttl);

		/* build reply */
		if (reply) {
			ext_dns_message_add_ipv4_reply (ctx, reply, value, ttl);
		} else
			reply = ext_dns_message_build_ipv4_reply (ctx, query, value, ttl);
		
	} else if (axl_memcmp (items[desp], "name:", 5) || axl_memcmp (items[desp], "cname:", 6)) {
		/* get ttl */
		ttl = ext_dns_atoi (items[desp + 1]);

		/* get value */
		value = items[desp] + 5;
		if (axl_memcmp (items[desp], "cname:", 6))
			value = items[desp] + 6;

		if (exarg_is_defined ("debug"))
			syslog (LOG_INFO, "Script reported to use Name %s (with ttl %d) as reply..", value, ttl);

		/* build reply */
		if (reply) 
			ext_dns_message_add_cname_reply (ctx, reply, value, ttl);
		else
			reply = ext_dns_message_build_cname_reply (ctx, query, value, ttl);
		if (reply == NULL) {
			syslog (LOG_ERR, "Failed to build cname reply with name=%s ttl=%d (memory allocation error)", value, ttl);
			increase_failures_found ();
			axl_freev (items);
			return INT_TO_PTR (2); /* report to do anything */
		} /* end if */

		if (exarg_is_defined ("debug"))
			syslog (LOG_INFO, "INFO: created partial cname reply  %p, references: %d", reply, ext_dns_message_ref_count (reply));

		/* because we are going to reply a CNAME, we need to
		 * add the IP that resolves that request. Check if the
		 * cache have that value */
		aux   = ext_dns_cache_get (ctx, extDnsClassIN, extDnsTypeA, value, source_address);
		if (aux == NULL) {
			/* only recurse when the user didn't state anything against */
			if (! norecurse) {
				/* build reply data */
				handle_reply                  = axl_new (HandleReplyData, 1);
				if (handle_reply == NULL) {
					/* release reply */
					ext_dns_message_unref (reply);
					axl_freev (items);
					return INT_TO_PTR (2); /* report failure */
				} /* end if */
				
				handle_reply->source_address  = axl_strdup (source_address);
				handle_reply->source_port     = source_port;
				handle_reply->master_listener = session;
				handle_reply->reply           = reply;
				handle_reply->nocache         = nocache;
				
				/* found that the value A isn't found in the
				 * case, we have to ask for it */
				ext_dns_message_query_int (ctx, extDnsClassIN, extDnsTypeA, value,
							   server, server_port, handle_reply_complete_cname, handle_reply);
				axl_freev (items);
				return INT_TO_PTR (2); /* report that we are asking to complete the request */
			} /* end if */

		} else {
			/* ok, extend reply with the provided value and reply */
			if (exarg_is_defined ("debug")) {
				syslog (LOG_INFO, "Reusing cache value associated to %s, to reply cname value %s",
					ext_dns_message_query_name (ctx, aux), ext_dns_message_query_name (ctx, reply));
			} /* end if */
			ext_dns_message_add_answer_from_msg (ctx, reply, aux);
			ext_dns_message_unref (aux);

		} /* end if */
	} else if (axl_memcmp (items[desp], "mx:", 3)) {

		/* get value */
		value = items[desp] + 3;

		/* get ttl */
		preference = ext_dns_atoi (items[desp + 1]);

		/* get ttl */
		ttl = ext_dns_atoi (items[desp + 2]);

		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "MX: creating or adding MX reply %s %d %d",
			     value, preference, ttl);
		if (reply) {
			ext_dns_message_add_mx_reply (ctx, reply, value, preference, ttl);
		} else
			reply = ext_dns_message_build_mx_reply (ctx, query, value, preference, ttl);

	} else if (axl_memcmp (items[desp], "ns:", 3)) { /* support for NS records */ 

		/* get value */
		value = items[desp] + 3;

		/* get ttl */
		ttl   = ext_dns_atoi (items[desp + 1]);

		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "NS: creating or adding NS reply %s %d", value, ttl);
		if (reply) {
			ext_dns_message_add_ns_reply (ctx, reply, value, ttl);
		} else
			reply = ext_dns_message_build_ns_reply (ctx, query, value, ttl);

	} else if (axl_memcmp (items[desp], "soa:", 4)) { /* support for NS records */ 

		/* get value */
		value = items[desp] + 4;

		/* get ttl */
		ttl   = ext_dns_atoi (items[desp + 7]);

		ext_dns_log (EXT_DNS_LEVEL_DEBUG, "SOA: creating or adding SOA reply (mname: %s, rname: %s, ttl: %d, reply: %p)",
			     value, items[desp + 1], ttl, reply);
		if (reply) {
			ext_dns_message_add_soa_reply (ctx, reply, 
						       /* soa main server (mname) */
						       value,  
						       /* mail contact (rname) */
						       items[desp + 1], 
						       /* serial */
						       ext_dns_atoi(items[desp + 2]), 
						       /* refresh */
						       ext_dns_atoi(items[desp + 3]), 
						       /* retry */
						       ext_dns_atoi(items[desp + 4]), 
						       /* expire */
						       ext_dns_atoi(items[desp + 5]), 
						       /* minimum */
						       ext_dns_atoi(items[desp + 6]), 
						       ttl);
		} else
			reply = ext_dns_message_build_soa_reply (
				ctx, query, 
				/* soa main server (mname) */
				value,  
				/* mail contact (rname) */
				items[desp + 1], 
				/* serial */
				ext_dns_atoi(items[desp + 2]), 
				/* refresh */
				ext_dns_atoi(items[desp + 3]), 
				/* retry */
				ext_dns_atoi(items[desp + 4]), 
				/* expire */
				ext_dns_atoi(items[desp + 5]), 
				/* minimum */
				ext_dns_atoi(items[desp + 6]), 
				ttl);
	}

	axl_freev (items);
	return reply;
}

/** 
 * @internal Allows to get the first integer found in a string.
 */
int ext_dnsd_server_get_int (const char * reply_buffer)
{
	int iterator = 0;

	while (reply_buffer[iterator]) {
		if (reply_buffer[iterator] == '0' ||
		    reply_buffer[iterator] == '1' ||
		    reply_buffer[iterator] == '2' ||
		    reply_buffer[iterator] == '3' ||
		    reply_buffer[iterator] == '4' ||
		    reply_buffer[iterator] == '5' ||
		    reply_buffer[iterator] == '6' ||
		    reply_buffer[iterator] == '7' ||
		    reply_buffer[iterator] == '8' ||
		    reply_buffer[iterator] == '9')
			return ext_dns_atoi (reply_buffer + iterator);

		/* next position */
		iterator++;
	} /* end if */
	return 0;
}

/** 
 * @internal Function that checks if we are able to resolve the
 * provided query via values found inside local /etc/hosts.
 */
extDnsMessage * ext_dns_resolve_via_etc_hosts (extDnsCtx * ctx, extDnsMessage * message) {
	const char * value;

	/* get type and class */
	const char * type  = ext_dns_message_query_type (ctx, message);
	const char * class = ext_dns_message_query_class (ctx, message);

	if (axl_cmp (class, "IN")) {
		if (axl_cmp (type, "A")) { 

			/* ok, found a IN A request, try to resolve via /etc/hosts */
			ext_dns_mutex_lock (&etchosts_mutex);
			value = (const char *) axl_hash_get (etchosts, (axlPointer) ext_dns_message_query_name (ctx, message));
			ext_dns_mutex_unlock (&etchosts_mutex);

			if (value) {
				/* build reply (low ttl=5) */
				return ext_dns_message_build_ipv4_reply (ctx, message, value, 5);
			} /* end if */
			
		} else if (axl_cmp (type, "AAAA")) {
			/* ok, found a IN AAAA request, try to resolve via /etc/hosts */
		}
	}

	return NULL;
}

/* call to queue */
void ext_dnsd_queue_pending_reply (extDnsCtx     * ctx, 
				   extDnsSession * session, 
				   extDnsMessage * message, 
				   const char    * command,
				   const char    * source_address, 
				   int             source_port)
{
	childPendingRequest * request;

	request = axl_new (childPendingRequest, 1);
	if (request == NULL)
		return;
	request->msg = message;
	ext_dns_message_ref (message);

	request->session = session;
	request->command = axl_strdup (command);

	/* record source address */
	request->source_address = axl_strdup (source_address);
	request->source_port    = source_port;

	/* setup an stamp */
	request->stamp = time (NULL);

	/* store request */
	ext_dns_mutex_lock (&pnd_req_mutex);
	axl_list_append (pending_requests, request);
	ext_dns_mutex_unlock (&pnd_req_mutex);

	return;
}

void on_received  (extDnsCtx     * ctx,
		   extDnsSession * session,
		   const char    * source_address,
		   int             source_port,
		   extDnsMessage * message,
		   axlPointer      _data)
{
	char            * command;
	childState      * child;
	extDnsMessage   * reply = NULL;

	/* skip messages that are queries */
	if (! ext_dns_message_is_query (message)) {
		syslog (LOG_ERR, "ERROR: received a query message, dropping DNS message..");
		return;
	} /* end if */

	/* update stats */
	ext_dns_mutex_lock (&stat_mutex);
	requests_received ++;
	ext_dns_mutex_unlock (&stat_mutex);
	
	if (exarg_is_defined ("debug")) {
		syslog (LOG_INFO, "received message from %s:%d, query type: %s %s %s..", 
			source_address, source_port, 
			ext_dns_message_get_qtype_to_str (ctx, message->questions[0].qtype),
			ext_dns_message_get_qclass_to_str (ctx, message->questions[0].qclass),
			message->questions[0].qname);
	} /* end if */

	/* check for forward all requests */
	if (forward_all_requests)  {
		/* call to forward request */
		ext_dnsd_forward_request (ctx, message, session, source_address, source_port, axl_true);
		return;
	} /* end if */

	/* build query line to be resolved by child process */
	command = axl_strdup_printf ("RESOLVE %s %s %s %s", 
				     source_address,
				     message->questions[0].qname,
				     ext_dns_message_get_qtype_to_str (ctx, message->questions[0].qtype),
				     ext_dns_message_get_qclass_to_str (ctx, message->questions[0].qclass));

	/* find a free child */
	child = ext_dnsd_find_free_child (command);
	if (child == NULL) {
		/* update stats */
		increase_failures_found ();

		syslog (LOG_ERR, "ERROR: failed to get a child to attend request %s, replying unknown", command);

		if (axl_list_length (pending_requests) < max_pnd_reqs) {
			/* call to queue */
			ext_dnsd_queue_pending_reply (ctx, session, message, command, source_address, source_port);
			axl_free (command);
			return;
		} /* end if */
		axl_free (command);
		
		/* build the unknown reply */
		reply = ext_dns_message_build_unknown_reply (ctx, message);
		ext_dnsd_send_request_reply (ctx, session, source_address, source_port, reply, axl_false);
		return;
	} /* end if */

	ext_dnsd_handle_child_cmd (ctx, message, session, child, source_address, source_port, command);
	axl_free (command);
	return;
}

void ext_dnsd_handle_child_cmd (extDnsCtx     * ctx, 
				extDnsMessage * message, 
				extDnsSession * session, 
				childState    * child, 
				const char    * source_address,
				int             source_port,
				const char    * command)
{

	axl_bool          permanent;
	int               bytes_written;
	char              reply_buffer[4096];
	extDnsMessage   * reply = NULL;
	axl_bool          nocache;

	/* send command and process reply */
	bytes_written = send_command (command, child, reply_buffer, 4096);
	if (bytes_written <= 0) {
		/* update stats */
		increase_failures_found ();

		syslog (LOG_ERR, "ERROR: unable to send command to child process (bytes_written=%d)", bytes_written);
		/* kill child and recreate a new child */
		return;
	} /* end if */

	/* release child */
	ext_dnsd_release_child (child);

	/* check for additional flags */
	nocache = !(strstr (reply_buffer, "nocache") == NULL);
	if (exarg_is_defined ("debug"))
		syslog (LOG_INFO, "nocache indication was=%d (inside: %s)", nocache, reply_buffer);

	/* get reply */
	if (axl_memcmp (reply_buffer, "DISCARD", 7)) {
		if (exarg_is_defined ("debug"))
			syslog (LOG_INFO, "child requested to DISCARD request..");
		return;
	} else if (axl_memcmp (reply_buffer, "UNKNOWN", 7)) {
		if (exarg_is_defined ("debug"))
			syslog (LOG_INFO, "child requested to send UNKNOWN code reply..");

		/* build the unknown reply */
		reply = ext_dns_message_build_unknown_reply (ctx, message);
	} else if (axl_memcmp (reply_buffer, "REJECT", 6)) {
		if (exarg_is_defined ("debug"))
			syslog (LOG_INFO, "child requested to REJECT request..");
		
		/* build the reject reply */
		reply = ext_dns_message_build_unknown_reply (ctx, message);
	} else if (axl_memcmp (reply_buffer, "BLACKLIST", 9)) {
		if (exarg_is_defined ("debug"))
			syslog (LOG_INFO, "child requested to BLACKLIST %s..", source_address);
		
		/* notify we have to skip replying to this peer. */
		reply = INT_TO_PTR (2);

		/* get permanent status */
		permanent = !(strstr (reply_buffer, "permanent") == NULL);

		/* call to blacklist */
		ext_dns_ctx_black_list (ctx, source_address, permanent, ext_dnsd_server_get_int (reply_buffer));

	} else if (axl_memcmp (reply_buffer, "FORWARD", 7)) {
		/* syslog (LOG_INFO, "child requested to continue and resolve request as usual using forward dns server..\n"); */

		/* check if we can resolve via /etc/hosts */
		reply = ext_dns_resolve_via_etc_hosts (ctx, message);

	} else if (axl_memcmp (reply_buffer, "REPLY ", 6)) {
		/* parse reply received */
		reply = ext_dnsd_parse_and_handle_reply (ctx, message, reply_buffer, session, source_address, source_port);
		if (reply == NULL) {
			syslog (LOG_INFO, "ERROR: child reported NULL content which means there's a failure or the child resolver application is not properly handling command: %s, forwarding query to serve request", command);
		} /* end if */
	} else {
		syslog (LOG_INFO, "ERROR: unrecognized command reply found from child: %s..", reply_buffer);
		/* update stats */
		increase_failures_found ();

		/* report unknown in this case */
		reply = ext_dns_message_build_unknown_reply (ctx, message);
	}

	if (exarg_is_defined ("debug"))
		syslog (LOG_INFO, "INFO: after processing, handlers requested to skip further processing %p", reply);

	/* check if handlers requested to return because they are
	 * completing pending requests or because a feailure was found */
	if (PTR_TO_INT(reply) == 2) 
		return;

	if (exarg_is_defined ("debug"))
		syslog (LOG_INFO, "INFO: after processing command reply from child resolver, reply value is %p", reply);
	
	if (reply) {
		/* send reply */
		ext_dnsd_send_request_reply (ctx, session, source_address, source_port, reply, nocache);
		return;
	} /* end if */

	/* call to forward request */
	ext_dnsd_forward_request (ctx, message, session, source_address, source_port, nocache);

	return;
}

void ext_dnsd_send_request_reply (extDnsCtx     * ctx, 
				  extDnsSession * session, 
				  const char    * source_address, 
				  int             source_port, 
				  extDnsMessage * reply,
				  axl_bool        nocache)
{
	if (reply == NULL)
		return;

	/* store reply in the cache */
	if (! nocache) {
		if (exarg_is_defined ("debug"))
			syslog (LOG_INFO, "INFO: caching value because nocache option wasn't found");
		ext_dns_cache_store (ctx, reply, source_address);
	}
	
	/* update stats */
	increase_requests_served ();
	
	/* found reply we've got now, send it back to the user */
	ext_dnsd_send_reply (ctx, session, source_address, source_port, reply, axl_true);
	return;
}

void ext_dnsd_forward_request (extDnsCtx     * ctx, 
			       extDnsMessage * message, 
			       extDnsSession * session,
			       const char    * source_address,
			       int             source_port,
			       axl_bool        nocache)
{
	axl_bool result;
	
	/* send query */
	result = ext_dns_message_query_and_forward_from_msg (ctx, message, server, server_port, source_address, source_port, session, nocache);

	if (! result) {
		syslog (LOG_ERR, "ERROR: failed to send query to master server..");
		/* update stats */
		increase_failures_found ();
	} else {
		/* update stats */
		increase_requests_served ();
	}

	return;
}

void     on_bad_request (extDnsCtx     * ctx,
			 extDnsSession * session,
			 const char    * source_address,
			 int             source_port,
			 const char    * buffer,
			 int             buffer_size,
			 const char    * reason,
			 axlPointer      data)
{
	syslog (LOG_ERR, "BAD REQUEST from %s:%d, reason: %s (blacklisting for 3 seconds)", source_address, source_port, reason);
	ext_dns_ctx_black_list (ctx, source_address, axl_false, 3);
	return;
}

extDnsMutex doing_exit_mutex;
axl_bool    __doing_exit = axl_false;

extDnsCtx     * ctx = NULL;

void __terminate_ext_dns_listener (int value)
{

	/* reinstall signal handler */
	signal (value, __terminate_ext_dns_listener);
	
	ext_dns_mutex_lock (&doing_exit_mutex);
	if (__doing_exit) {
		ext_dns_mutex_unlock (&doing_exit_mutex);

		return;
	}
	/* printf ("Terminating ext_dns regression listener..\n");*/
	__doing_exit = axl_true;
	ext_dns_mutex_unlock (&doing_exit_mutex);

	syslog (LOG_INFO, "Received signal %d, finishing server..", value);

	unlink (__blkbrd);

	/* unlocking listener */
	/* printf ("Calling to unlock listener due to signal received: extDnsCtx %p", ctx); */
	ext_dns_ctx_unlock (ctx);

	return;
}

/**
 * @internal Implementation to detach turbulence from console.
 */
void ext_dnsd_detach_process (void)
{
	pid_t   pid;
	/* fork */
	pid = fork ();
	switch (pid) {
	case -1:
		syslog (LOG_ERR, "unable to detach process, failed to executing child process");
		exit (-1);
	case 0:
		/* running inside the child process */
		syslog (LOG_INFO, "running child created in detached mode");
		return;
	default:
		/* child process created (parent code) */
		break;
	} /* end switch */

	/* terminate current process */
	syslog (LOG_INFO, "finishing parent process (created child: %d, parent: %d)..", pid, getpid ());
	exit (0);
	return;
}

/**
 * @internal Places current process identifier into the file provided
 * by the user.
 */
void ext_dnsd_place_pidfile (void)
{
	FILE * pid_file = NULL;
	int    pid      = getpid ();
	char   buffer[20];
	int    size;

	/* open pid file or create it to place the pid file */
	pid_file = fopen (__pidfile, "w");
	if (pid_file == NULL) {
		printf ("ERROR: Unable to open pid file at: %s", __pidfile);
		exit (-1);
	} /* end if */
	
	/* stringfy pid */
	size = axl_stream_printf_buffer (buffer, 20, NULL, "%d", pid);
	syslog (LOG_INFO, "signaling PID %d at %s", pid, __pidfile);
	fwrite (buffer, size, 1, pid_file);
	fclose (pid_file);
	return;
}

void install_arguments (int argc, char ** argv) {

	/* install headers for help */
	exarg_add_usage_header  (HELP_HEADER);
	exarg_add_help_header   (HELP_HEADER);
	exarg_post_help_header  (POST_HEADER);
	exarg_post_usage_header (POST_HEADER);

	/* init exarg library */
	exarg_install_arg ("version", "e", EXARG_NONE, 
			   "Shows ext-dnsd version.");
	exarg_install_arg ("verbose", "v", EXARG_NONE, 
			   "Shows enable tool verbose output.");
	exarg_install_arg ("debug", "d", EXARG_NONE, 
			   "Enable ext-dns debug output.");
	exarg_install_arg ("config", "c", EXARG_STRING, 
			   "Path to the server configuration file.");
	exarg_install_arg ("detach", NULL, EXARG_NONE,
			   "Makes ext-dnsd to detach from console, starting in background.");

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

void load_configuration_file (void) 
{  
	axlError   * error;

	/* initialize axl library */
	if (! axl_init ()) {
		printf ("ERROR: Unable to initialize Axl library\n");
		exit (-1);
	}

	/* get path to the configuration file */
	if (exarg_get_string ("config"))
		path = exarg_get_string ("config");
	
	/* parse document */
	config = axl_doc_parse_from_file (path, &error);
	if (config == NULL) {
		printf ("ERROR: unable to open file located '%s', error was: '%s'\n", 
			path, axl_error_get (error));

		/* release memory */
		axl_error_free (error);
		exit (-1);
	}
	
	syslog (LOG_INFO, "configuration from %s loaded ok", path);

	return;
}

void start_listeners (void)
{
	extDnsSession  * listener;
	axlNode        * node;
	char           * listen_declaration;
	char          ** values;

	/* find first listener node */
	node = axl_doc_get (config, "/ext-dns-server/listen");
	if (node == NULL) {
		printf ("ERROR: unable to find any listen declaration at configuration file %s, unable to start any listener..\n", path);
		exit (-1);
	} /* end if */

	while (node) {

		/* get listener declaration */
		listen_declaration = axl_strdup (ATTR_VALUE (node, "value"));
		if (listen_declaration == NULL) {
			printf ("ERROR: found NULL value declaration inside <listen /> node declaration\n");
			exit (-1);
		} /* end if */
		axl_stream_trim (listen_declaration);
		
		values = axl_split (listen_declaration, 1, ":");
		if (values == NULL) {
			printf ("ERROR: listen declaration isn't properly formated: %s (it must be host:port)\n", 
				listen_declaration);
			exit (-1);
		} /* end if */

		if (values[0] == NULL || values[1] == NULL) {
			printf ("ERROR: received NULL values at 0 and 1 position..\n");
			exit (-1);
		} /* end if */

		axl_free (listen_declaration);

		/* check listener values */
		if (axl_cmp (values[0], "0.0.0.0")) {
			printf ("ERROR: you can't setup that listening address '%s' because will give you problems. Please, especify the particular address(es) that ext-dnsd is going to use\n", values[0]);
			exit (-1);
		} /* end if */
		
		/* init a listener */
		listener = ext_dns_listener_new (ctx, values[0], values[1], extDnsUdpSession, NULL, NULL);


		if (! ext_dns_session_is_ok (listener, axl_false)) {
			printf ("ERROR: failed to start serving requests at %s:%s..\n", values[0], values[1]);
			if (! exarg_is_defined ("debug"))
				printf ("       (run with -d to get more information about the error)\n");
			/* release values */
			axl_stream_freev (values);
			exit (-1);
		} /* end if */

		/* release values */
		axl_stream_freev (values);
	
		/* configure on received handler */
		ext_dns_session_set_on_message (listener, on_received, NULL);
		ext_dns_session_set_on_badrequest (listener, on_bad_request, NULL);
		

		/* next node declaration */
		node = axl_node_get_next_called (node, "listen");
	}

	return;
}

/**
 * @internal Spawn a process from pfunc, returning it's pid. 
 *
 */
int ext_dns_create_child (int fds[2], const char * child_resolver) {
	pid_t pid;
	int pipes[4];
	
	if (pipe (&pipes[0]) < 0)  /* Parent read/child write pipe */
		return -1;
	if (pipe (&pipes[2]) < 0) /* Child read/parent write pipe */
		return -1;
	
	if ((pid = fork()) > 0) {
		/* Parent process */
		fds[0] = pipes[0];
		fds[1] = pipes[3];

		close (pipes[1]);
		close (pipes[2]);
		
		return pid;
		
	}  /* end if */

	/* close unused descriptors */
	close (pipes[0]);
	close (pipes[3]);

	/* rfds = pipes[2] 
	   wfds = pipes[1] */
	
	/* redirect standard file descriptors */
	/* stdin */
	close (0);
	dup (pipes[2]);
	/* stdout */
	close (1);
	dup (pipes[1]);

	/* call to exec child */
	execl (child_resolver, child_resolver, NULL);
	
	exit(0);
	
	/* should never reached */
	return -1; 
}

int skip_pending_tasks = 0;

void do_kill (int pid, const char * last_command, int diff) {
	if (pid <= 1)
		return;

	kill (pid, SIGTERM);
	syslog (LOG_INFO, "ERROR: killed child resolver pid %d because it was working for more than %d seconds, processing command: %s",
		pid, diff, last_command);
	return;
}

/* call to create child process and to exit if a failure is found */
axl_bool ext_dnsd_create_child_process (childState * child, axl_bool exit_on_failure)
{
	char reply[20];

	if (child == NULL)
		return axl_false;

	/* start child and set initial state */
	child->ready = axl_true;
	ext_dns_mutex_create (&child->mutex);

	/* create and get child pid */
	child->pid = ext_dns_create_child (child->fds, child_resolver);

	/* printf ("child created with pid %d, fds [%d, %d]\n", childs[iterator].pid, childs[iterator].fds[0], childs[iterator].fds[1]); */

	if (child->pid < 0) {
		printf ("ERROR: failed to create child process from child resolver '%s', error was errno=%d\n", child_resolver, errno);
		if (exit_on_failure)
			exit (-1);
		return axl_false;
	} /* end if */
	
	/* send init command to check if the child is working */
	if (! send_command ("INIT", child, reply, 20)) {
		printf ("ERROR: child resolver (pid %d) %s didn't reply to INIT command..\n", child->pid, child_resolver);
		if (exit_on_failure)
			exit (-1);
		return axl_false;
	} /* end if */
	
	if (! axl_cmp (reply, "OK")) {
		printf ("ERROR: child resolver (pid %d) %s didn't reply OK to INIT command..\n", child->pid, child_resolver);
		if (exit_on_failure)
			exit (-1);
		return axl_false;
	} /* end if */
	
	
	syslog (LOG_INFO, "child resolver (pid %d) %s created..", child->pid, child_resolver);
	
	/* report ok status */
	return axl_true;
}

axlPointer ext_dnsd_handle_pending_request (axlPointer _ptr)
{
	childPendingRequest * pnd_req = _ptr;
	extDnsCtx           * ctx     = pnd_req->ctx;

	/* call to handle child command */
	ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Calling to handle pending request: %s with child %d", pnd_req->command, pnd_req->child->pid);
	ext_dnsd_handle_child_cmd (pnd_req->ctx, 
				   pnd_req->msg, 
				   pnd_req->session, 
				   pnd_req->child, 
				   pnd_req->source_address, 
				   pnd_req->source_port, 
				   pnd_req->command);

	/* release pending request */
	__release_pending_request (pnd_req);

	return NULL;
}

axl_bool check_pending_tasks  (extDnsCtx * ctx,
			       axlPointer  user_data,
			       axlPointer  user_data2)
{
	int                    children_ready;
	int                    children_dead;
	FILE                 * file;
	char                 * msg;
	mode_t                 old_umask;
	const char           * label = "";
	int                    iterator;
	int                    diff;
	extDnsCacheStats       cache_stats;
	float                  ratio;
	childState           * child;
	childPendingRequest  * pnd_req;

	skip_pending_tasks++;
	if (skip_pending_tasks < 3)
		return axl_false; /* do not stop */
	skip_pending_tasks = 4;

	/* check childs to be created */
	ext_dns_mutex_lock (&children_mutex);
	iterator = 0;
	while (iterator < children_number) {

		/* show childs blocked */
		if (children[iterator].pid == -1) {
			/* call to start child */
			syslog (LOG_INFO, "Starting a new child process...");
			ext_dnsd_create_child_process (&children[iterator], axl_false);
		} /* end if */

		iterator++;
	} /* end while */
	ext_dns_mutex_unlock (&children_mutex);

	/* get child ready */
	children_ready = ext_dnsd_get_children_ready ();
	children_dead = ext_dnsd_get_children_dead ();

	old_umask = umask (0077);

	/* call to check pending requests to be requeued */
	file = fopen (__blkbrd, "w");

	/* place stamp */
	msg = axl_strdup_printf ("Stamp: %d\n", time (NULL));
	fwrite (msg, strlen (msg), 1, file);
	axl_free (msg);
	
	/* child status */
	if (children_ready == 0)
		label = " (all children busy)";
	msg = axl_strdup_printf ("Child status: %d/%d%s\n", children_number - children_ready, children_number, label);
	fwrite (msg, strlen (msg), 1, file);
	axl_free (msg);

	if (children_dead > 0) {
		msg = axl_strdup_printf ("Children dead: %d%s\n", children_dead);
		fwrite (msg, strlen (msg), 1, file);
		axl_free (msg);
	} /* end if */

	/* some stas */
	msg = axl_strdup_printf ("Requests received: %d\n", requests_received);
	fwrite (msg, strlen (msg), 1, file);
	axl_free (msg);

	msg = axl_strdup_printf ("Requests served: %d\n", requests_served);
	fwrite (msg, strlen (msg), 1, file);
	axl_free (msg);

	msg = axl_strdup_printf ("Failures found: %d\n", failures_found);
	fwrite (msg, strlen (msg), 1, file);
	axl_free (msg);

	/* pending requests */
	msg = axl_strdup_printf ("Pending requests: %d\n", axl_list_length (pending_requests));
	fwrite (msg, strlen (msg), 1, file);
	axl_free (msg);

	/* pending requests */
	ext_dns_cache_stats (ctx, &cache_stats);
	ratio = 0;
	if (cache_stats.cache_access > 0)
		ratio = ((float)cache_stats.cache_hits / (float)cache_stats.cache_access) * 100;
	msg = axl_strdup_printf ("Cache stats: %d/%d (used/max)  %d/%d (hits/access) %.2f% (ratio)\n", 
				 cache_stats.cache_items, cache_stats.cache_size, 
				 cache_stats.cache_hits, cache_stats.cache_access,
				 ratio);
	fwrite (msg, strlen (msg), 1, file);
	axl_free (msg);

	/* show command timeout */
	if (command_timeout > 0) 
		msg = axl_strdup_printf ("Command timeout: %d secs\n", command_timeout);
	else 
		msg = axl_strdup_printf ("Command timeout: disabled\n", command_timeout);
	fwrite (msg, strlen (msg), 1, file);
	axl_free (msg);

	/* show pending childs */
	ext_dns_mutex_lock (&children_mutex);
	iterator = 0;
	while (iterator < children_number) {

		/* show childs blocked */
		if (! children[iterator].ready && children[iterator].pid > 0) {
			/* pending requests */
			diff = time (NULL) - children[iterator].stamp;
			msg  = axl_strdup_printf ("Child busy: pid %d, working for: %d secs, cmd: %s\n", 
						  children[iterator].pid, diff, children[iterator].last_command);
			fwrite (msg, strlen (msg), 1, file);
			axl_free (msg);	

			if (diff > command_timeout) {
				/* call to implement kill */
				do_kill (children[iterator].pid, children[iterator].last_command, diff);
			} /* end if */
		}
		
		/* next iterator */
		iterator++;
	} /* end if */
	ext_dns_mutex_unlock (&children_mutex);

	/* close file */
	fclose (file);

	/* restore umask */
	umask (old_umask);

	/* process pending requests */
	while (axl_list_length (pending_requests) > 0) {
		ext_dns_mutex_lock (&pnd_req_mutex);
		
		/* get first pending request */
		pnd_req = axl_list_get_first (pending_requests);
		if (pnd_req == NULL) {
			ext_dns_mutex_unlock (&pnd_req_mutex);
			return axl_false; /* do not remove the event */
		} /* end if */

		/* find a free child */
		child = ext_dnsd_find_free_child (pnd_req->command);
		if (child == NULL) {
			ext_dns_mutex_unlock (&pnd_req_mutex);
			return axl_false; /* do not remove the event */
		} /* end if */

		/* remove the first position */
		axl_list_unlink_first (pending_requests);

		/* set the child that will handle this request */
		pnd_req->child = child;

		/* unlock */
		ext_dns_mutex_unlock (&pnd_req_mutex);

		/* call to handle this request on its own thread */
		ext_dns_thread_pool_new_task (ctx, ext_dnsd_handle_pending_request, pnd_req);
	}

	return axl_false; /* do not remove the event */
}

void init_structures_and_handlers (void) {

	/* init mutex stats */
	ext_dns_mutex_create (&stat_mutex);
	ext_dns_mutex_create (&pnd_req_mutex);

	/* init pending requests list */
	pending_requests = axl_list_new (ext_dnsd_equal_requests, __release_pending_request);
	if (pending_requests == NULL) {
		syslog (LOG_INFO, "Unable to acquire memory to hold pending request list");
		exit (-1);
	} /* end if */

	/* init tracking event */
	ext_dns_thread_pool_new_event (ctx, 1000000, check_pending_tasks, NULL, NULL);

	return;
}

void start_child_applications (void)
{
	axlNode        * node;
	int              iterator;

	/* find first listener node */
	node = axl_doc_get (config, "/ext-dns-server/child-resolver");
	if (node == NULL) {
		syslog (LOG_INFO, "no <child-resolver> config was found, enable forward for all requests");
		return;
		/* printf ("ERROR: unable to find any listen declaration at configuration file %s, unable to start any listener..\n", path);
		   exit (-1); */
	} /* end if */

	/* get child resolver */
	child_resolver = ATTR_VALUE (node, "value");
	if (child_resolver == NULL || strlen (child_resolver) == 0) {
		syslog (LOG_INFO, "no <child-resolver> value config was found, enable forward for all requests");
		return;
		/* printf ("ERROR: child resolver application wasn't found defined (it is empty or NULL)\n");
		   exit (-1); */
	}

	/* find first listener node */
	node = axl_doc_get (config, "/ext-dns-server/child-number");
	if (node == NULL) {
		syslog (LOG_INFO, "no <child-resolver> config was found, enable forward for all requests");
		return;
		/* printf ("ERROR: unable to find any listen declaration at configuration file %s, unable to start any listener..\n", path);
		   exit (-1); */
	} /* end if */

	if (! ATTR_VALUE (node, "value") || strlen (ATTR_VALUE (node, "value")) == 0) {
		printf ("ERROR: child number value not defined\n");
		exit (-1);
	}

	/* child number */
	children_number = ext_dns_atoi (ATTR_VALUE (node, "value"));

	/* check child number */
	if (children_number <= 0) {
		printf ("ERROR: child number received is %d. It must be bigger than 0\n", children_number);
		exit (-1);
	}

	/* allocate memory to handle child state */
	children = axl_new (childState, children_number);

	iterator     = 0;
	while (iterator < children_number) {

		/* call to create child process and to exit if a failure is found */
		ext_dnsd_create_child_process (&children[iterator], axl_true);

		/* next iterator */
		iterator++;
	} /* end while */

	/* do not forward directly all requests, but first ask child
	   resolvers */
	forward_all_requests = axl_false;

	return;
	
}

void child_terminated (int _signal) {
	int exit_status = 0;
	int pid;

	pid = wait (&exit_status);
	syslog (LOG_INFO, "Child %d finished with %d\n", pid, exit_status);

	/* reinstall signal */
	signal (SIGCHLD, child_terminated);

	/* release child by pid */
	ext_dnsd_release_child_by_pid (pid);

	return;
}

void clear_etc_hosts (void) {
	axlHash * temp;

	temp = etchosts;

	/* lock, change and unlock */
	ext_dns_mutex_lock (&etchosts_mutex);
	etchosts = NULL;
	ext_dns_mutex_unlock (&etchosts_mutex);
	
	axl_hash_free (etchosts);
	return;
}

void start_etc_hosts_resolution (void) {
	axlNode  * node;
	char     * line = NULL;
	size_t     len  = 0;
	FILE     * fp;
	ssize_t    read;
	char    ** items;
	int        iterator;

	/* hashes built */
	axlHash  * temp1;
	axlHash  * temp2;

	/* old hashes */
	axlHash  * old1;
	axlHash  * old2;


	/* get current node configuration */
	node = axl_doc_get (config, "/ext-dns-server/resolve-from-etc-hosts");
	if (node == NULL) {
		clear_etc_hosts ();
		return ;
	} /* end if */

	if (! HAS_ATTR_VALUE (node, "value", "yes")) {
		clear_etc_hosts ();
		return ;
	} /* end if */

	fp = fopen("/etc/hosts", "r");
	if (fp == NULL) {
		return;
	} /* end if */

	/* create temporal hashes */
	temp1 = axl_hash_new (axl_hash_string, axl_hash_equal_string);
	temp2 = axl_hash_new (axl_hash_string, axl_hash_equal_string);

	/* ok, load the new etc/hosts */
	while ((read = getline (&line, &len, fp)) != -1) {
		/* clear and check for empty lines */
		axl_stream_trim (line);
		if (line == NULL || strlen (line) == 0)
			continue;
		
		/* skip comments */
		if (line[0] == '#')
			continue;

		/* prepare the line */
		iterator = 0;
		while (line[iterator]) {
			if (line[iterator] == '\t' || line[iterator] == '\r')
				line[iterator] = ' ';
			iterator++;
		} /* end while */

		/* process line */
		items = axl_split (line, 1, " ");
		axl_stream_clean_split (items);
		if (items[0] == NULL || items[1] == NULL) {
			axl_freev (items);
			continue;
		} /* end if */

		iterator = 1;
		while (items[iterator]) {
			ext_dns_log (EXT_DNS_LEVEL_DEBUG, "Found resolution %s -> %s", items[iterator], items[0]);
			
			/* check if this is a ipv4 or ipv6 value */
			if (!(strstr (items[0], ":") == NULL)) 
				axl_hash_insert_full (temp2, axl_strdup (items[iterator]), axl_free, axl_strdup(items[0]), axl_free);
			else
				axl_hash_insert_full (temp1, axl_strdup (items[iterator]), axl_free, axl_strdup (items[0]), axl_free);

			iterator++;
		} /* end if */

		/* clear first position */
		axl_freev (items);
	}

	/* release and close */
	if (line)
		free (line);
	fclose (fp);

	/* now set new values */
	ext_dns_mutex_lock (&etchosts_mutex);
	old1 = etchosts;
	etchosts = temp1;

	old2 = etchosts_ipv6;
	etchosts_ipv6 = temp2;
	ext_dns_mutex_unlock (&etchosts_mutex);

	/* release old values */
	axl_hash_free (old1);
	axl_hash_free (old2);

	return;
}

void reload_configuration (int _signal) {

	/* release cache */
	syslog (LOG_INFO, "Reloading ext-dnsd server..");
	ext_dns_cache_init (ctx, 0);
	syslog (LOG_INFO, "Cache flushed..");

	/* reload /etc/hosts resolution */
	start_etc_hosts_resolution ();

	/* reload configuration (to be done) */

	/* reinstall signal */
	signal (SIGHUP, reload_configuration);
	return;
}

void setup_thread_num (void) {
	axlNode    * node;
	const char * number_str;
	int          number;

	/* find first listener node */
	node = axl_doc_get (config, "/ext-dns-server/child-number");
	if (node == NULL)
		return;
	number_str = ATTR_VALUE (node, "value");
	if (number_str == NULL || strlen (number_str) == 0) {
		syslog (LOG_INFO, "no <child-number> value config was found, defaulting to 5");
		return;
		/* printf ("ERROR: child resolver application wasn't found defined (it is empty or NULL)\n");
		   exit (-1); */
	}
	
	number = ext_dns_atoi (number_str);
	if (number <= 0) {
		syslog (LOG_ERR, "Leaving default thread number because found invalid value: %s", number_str);
		return;
	} /* end if */

	/* setup this number of threads */
	syslog (LOG_INFO, "Calling to setup %d threads", number + 1);
	ext_dns_thread_pool_set_num (number + 1);

	number_str = ATTR_VALUE (node, "command-timeout");
	if (axl_cmp (number_str, "disable"))
		command_timeout = 0;
	else {
		/* get command timeout and default value */
		if (number_str)
			command_timeout = ext_dns_atoi (number_str);
		else
			command_timeout = 15;
		if (command_timeout == 0)
			command_timeout = 15;
	} /* end if */

	return;
} /* end if */

#ifdef AXL_OS_UNIX
void __block_server (int value) 
{
	extDnsAsyncQueue * queue;
	axlNode          * node;
	const char       * action = "hold";

	syslog (LOG_INFO, "****** Received a signal (ext-dnsd is failing): pid %d", ext_dns_getpid ());

	/* install signal again */
	signal (value, __block_server);

	/* find first listener node */
	node = axl_doc_get (config, "/ext-dns-server/failure-action");
	if (node && HAS_ATTR (node, "value"))
		action = ATTR_VALUE (node, "value");

	if (axl_cmp (action, "abort")) {
		syslog (LOG_INFO, "****** finishing process because failure-action = 'abort': pid %d", ext_dns_getpid ());
		exit (value);
	}

	if (axl_cmp (action, "hold")) {
		syslog (LOG_INFO, "****** holding process because failure-action = 'hold': pid %d", ext_dns_getpid ());

		/* block the caller */
		queue = ext_dns_async_queue_new ();
		ext_dns_async_queue_pop (queue);
	} /* end if */

	if (axl_cmp (action, "continue")) {
		/* continue */
		syslog (LOG_INFO, "****** continue as if nothing had happened because failure-action = 'continue': pid %d", ext_dns_getpid ());
	} /* end if */

	syslog (LOG_INFO, "****** unsupported failure action, finishing process: pid %d", ext_dns_getpid ());
	exit (value);

	return;
}
#endif

int main (int argc, char ** argv) {

	/* install default handling to get notification about
	 * segmentation faults */
#ifdef AXL_OS_UNIX
	signal (SIGTERM,  __terminate_ext_dns_listener);
	signal (SIGQUIT,  __terminate_ext_dns_listener);
	signal (SIGCHLD, child_terminated);
	signal (SIGHUP, reload_configuration);
	signal (SIGSEGV, __block_server);
	signal (SIGABRT, __block_server);
#endif

	/* open syslog */
	openlog ("ext-dnsd", LOG_PID, LOG_DAEMON);

	/* install arguments */
	install_arguments (argc, argv);	

	/* check detach operation */
	if (exarg_is_defined ("detach")) {
		ext_dnsd_detach_process ();
		/* caller do not follow */
	} /* end if */

	/* place pid file */
	ext_dnsd_place_pidfile ();

	/* parse configuration file */
	load_configuration_file ();
	
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

	/* setup threads for childs */
	setup_thread_num ();

	/* init context */
	if (! ext_dns_init_ctx (ctx)) {
		printf ("ERROR: failed to initiatialize ext-dns server context..\n");
		exit (-1);
	} 

	/* init structures and handlers */
	init_structures_and_handlers ();

	/* init cache */
	ext_dns_cache_init (ctx, 1000);

	/* check and start /etc/hosts resolution */
	ext_dns_mutex_create (&etchosts_mutex);
	start_etc_hosts_resolution ();

	/* start listener declarations */
	start_listeners ();

	/* now start child applications */
	start_child_applications ();
	
	/* wait and process requests */
	syslog (LOG_INFO, "ext-dnsD started OK");
	ext_dns_ctx_wait (ctx);

	syslog (LOG_INFO, "Releasing ext-dns resources..");

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	/* finish exarg */
	exarg_end ();	

	/* free configuration object */
	axl_doc_free (config);

	/* finalize childs */
	ext_dnsd_finish_childs ();

	unlink (__blkbrd);

	/* release hashes */
	ext_dns_mutex_destroy (&etchosts_mutex);
	axl_hash_free (etchosts_ipv6);
	axl_hash_free (etchosts);
	axl_list_free (pending_requests);
	
	return 0;
}
