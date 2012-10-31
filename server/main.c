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

#include <ext-dns.h>

#include <syslog.h>

#ifdef AXL_OS_UNIX
#include <signal.h>
#endif

#include <axl.h>
#include <exarg.h>
#include <sys/wait.h>



axl_bool verbose = axl_false;

axlDoc     * config = NULL;
const char * path = "/etc/ext-dnsd.conf";

/* server we rely request to */
const char * server = "8.8.8.8";
int          server_port = 53;

typedef struct _HandleReplyData {
	int             id;
	char          * source_address;
	int             source_port;
	extDnsSession * master_listener;
} HandleReplyData;

typedef struct _childState {
	/* read fds[0], write fds[1] */
	int fds[2];

	/* current child state */
	axl_bool       ready;
	extDnsMutex    mutex;

	/* last command sent */
	char         * last_command;

	int            pid;
} childState;

/** reference to childs created and their state **/
childState * children;
int          child_number;
extDnsMutex  children_mutex;

void ext_dnsd_finish_childs (void) {
	int iterator = 0;

	while (iterator < child_number) {
		ext_dns_mutex_destroy (&(children[iterator].mutex));
		axl_free (children[iterator].last_command);

		/* next iterator */
		iterator++;
	}

	axl_free (children);
	ext_dns_mutex_destroy (&children_mutex);

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

childState * ext_dnsd_find_free_child (char * command)
{
	int          iterator;
	childState * child = NULL;

	ext_dns_mutex_lock (&children_mutex);

	iterator = 0;
	while (iterator < child_number) {

		if (children[iterator].ready) {
			/* flag it as not ready */
			children[iterator].ready = axl_false;

			/* get the reference */
			child = &(children[iterator]);

			/* prepare child and send query to a child */
			child->last_command = command;

			ext_dns_mutex_unlock (&children_mutex);
			
			return child;
		}
		
		/* next iterator */
		iterator++;
	} /* end if */

	ext_dns_mutex_unlock (&children_mutex);
	
	/* no child was found */
	return NULL;
}


void handle_reply_data_free (HandleReplyData * data)
{
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
		syslog (LOG_ERR, "ERROR: failed to send command to child, error was errno=%d (%s)\n", errno, ext_dns_errno_get_last_error ());
		return axl_false;
	}
	if (write (child->fds[1], "\n", 1) != 1) {
		syslog (LOG_ERR, "ERROR: failed to write trailing command, error was errno=%d (%s)\n", errno, ext_dns_errno_get_last_error ());
		return axl_false;
	}

	/* printf ("reading reply to command..\n"); */

	/* now wait for reply */
	bytes_written = ext_dnsd_readline (child->fds[0], reply, reply_size);

	if (bytes_written < 0) {
		syslog (LOG_ERR, "ERROR: failed to receive content from child, error was errno=%d (%s)\n", errno, ext_dns_errno_get_last_error ());
		return axl_false;
	} /* end if */

	/* printf ("data received '%s' (size: %d)\n", reply, bytes_written); */

	/* trim content and recalculate */
	axl_stream_trim (reply);
	bytes_written = strlen (reply);

	/* printf ("bytes received %d\n", bytes_written); */
	return bytes_written;
}

void handle_reply_complete_cname (extDnsCtx     * ctx,
				  extDnsSession * session,
				  const char    * source_address,
				  int             source_port,
				  extDnsMessage * message,
				  axlPointer      data)
{
	
	return;
}

void handle_reply (extDnsCtx     * ctx,
		   extDnsSession * session,
		   const char    * source_address,
		   int             source_port,
		   extDnsMessage * message,
		   axlPointer      data)
{
	char              buffer[512];
	int               bytes_written;
	HandleReplyData * reply_data = data;

	/* ok, rewrite reply id to match the one sent by the client */
	message->header->id = reply_data->id;

	/* get the reply into a buffer */
	bytes_written = ext_dns_message_to_buffer (ctx, message, buffer, 512);
	if (bytes_written == -1) {
		/* handle_reply_data_free (reply_data); */
		/* not required to release data here because this is
		 * done by the engine when the session is finished */

		syslog (LOG_ERR, "ERROR: failed to build buffer representation for reply received..\n");
		return;
	}

	/* relay reply to the regression client */
	if (ext_dns_session_send_udp_s (ctx, reply_data->master_listener, buffer, bytes_written, reply_data->source_address, reply_data->source_port) != bytes_written) 
		syslog (LOG_ERR, "ERROR: failed to SEND UDP entire reply, expected to write %d bytes but something different was written\n", bytes_written);
	else {
		/* store reply in the cache */
		ext_dns_cache_store (ctx, message);
	}

	/* handle_reply_data_free (reply_data); */
	/* not required to release data here because this is done by
	 * the engine when the session is finished */
	return;
}

axl_bool ext_dnsd_send_reply (extDnsCtx * ctx, extDnsSession * session, const char * source_address, int source_port, extDnsMessage * reply, axl_bool release_message)
{
	char     buffer[512];
	int      bytes_written;
	axl_bool result = axl_false;

	/* build buffer reply */
	bytes_written = ext_dns_message_to_buffer (ctx, reply, buffer, 512);
	if (bytes_written <= 0) {
		syslog (LOG_ERR, "ERROR: failed to dump message into the buffer, unable to reply to resolver..\n");
		goto return_result;
	}

	/* send reply */
	if (ext_dns_session_send_udp_s (ctx, session, buffer, bytes_written, source_address, source_port) != bytes_written) {
		syslog (LOG_ERR, "ERROR: failed to send %d bytes as reply, different amount of bytes where written\n", bytes_written);
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


extDnsMessage * ext_dnsd_handle_reply (extDnsCtx     * ctx, 
				       extDnsMessage * query, 
				       const char    * reply_buffer,
				       extDnsSession * session,
				       const char    * source_address,
				       int             source_port)
{
	int              ttl;
	char          ** items = axl_split (reply_buffer, 1, " ");
	extDnsMessage  * reply = NULL;
	const char     * value;
	extDnsMessage  * aux;
	
	/* check result */
	if (items == NULL)
		return NULL;

	/* clean split */
	axl_stream_clean_split (items);

	/* check result */
	if (axl_memcmp (items[1], "ipv4:", 5)) {

		/* get value */
		value = items[1] + 5;

		/* check if the value reported a valid ipv4 value */
		if (! ext_dns_support_is_ipv4 (value)) {
			syslog (LOG_ERR, "ERROR: reported something that is not an IP %s..\n", value ? value : "(null value)" );
			axl_freev (items);
			return NULL;
		} /* end if */

		/* get ttl */
		ttl = atoi (items[2]);
		syslog (LOG_INFO, "Script reported to use IP %s (with ttl %d) as reply..\n", items[1] + 5, ttl);

		/* build reply */
		reply = ext_dns_message_build_ipv4_reply (ctx, query, value, ttl);
		
	} else if (axl_memcmp (items[1], "name:", 5)) {
		/* get ttl */
		ttl = atoi (items[2]);

		/* get value */
		value = items[1] + 5;

		syslog (LOG_INFO, "Script reported to use Name %s (with ttl %d) as reply..\n", value, ttl);

		/* build reply */
		reply = ext_dns_message_build_cname_reply (ctx, query, value, ttl);
		if (reply) {
			/* because we are going to reply a CNAME, we need to
			 * add the IP that resolves that request. Check if the
			 * cache have that value */
			syslog (LOG_INFO, "Caching in cache for %s", value);
			aux   = ext_dns_cache_get (ctx, extDnsClassIN, extDnsTypeA, value);
			if (aux == NULL) {
				/* found that the value A isn't found in the
				 * case, we have to ask for it */
				ext_dns_message_query_int (ctx, extDnsClassIN, extDnsTypeA, value,
							   server, server_port, handle_reply_complete_cname, reply);
				return INT_TO_PTR (2); /* report that we are asking to complete the request */
			} /* end if */
		} /* end if */
	}

	axl_freev (items);
	return reply;
}


void on_received  (extDnsCtx     * ctx,
		   extDnsSession * session,
		   const char    * source_address,
		   int             source_port,
		   extDnsMessage * message,
		   axlPointer      _data)
{
	axl_bool          result;
	HandleReplyData * data;
	char            * command;
	childState      * child;
	char              reply_buffer[1024];
	extDnsMessage   * reply = NULL;
	int               bytes_written;

	/* skip messages that are queries */
	if (! ext_dns_message_is_query (message)) {
		syslog (LOG_ERR, "ERROR: received a query message, dropping DNS message..\n");
		return;
	} /* end if */

	syslog (LOG_INFO, "received message from %s:%d, query type: %s %s %s..\n", 
		source_address, source_port, 
		ext_dns_message_get_qtype_to_str (ctx, message->questions[0].qtype),
		ext_dns_message_get_qclass_to_str (ctx, message->questions[0].qclass),
		message->questions[0].qname);

	/* build query line to be resolved by child process */
	command = axl_strdup_printf ("RESOLVE %s %s %s %s", 
				     source_address,
				     message->questions[0].qname,
				     ext_dns_message_get_qtype_to_str (ctx, message->questions[0].qtype),
				     ext_dns_message_get_qclass_to_str (ctx, message->questions[0].qclass));

	/* find a free child */
	child = ext_dnsd_find_free_child (command);

	bytes_written = send_command (command, child, reply_buffer, 1024);
	if (bytes_written <= 0) {
		syslog (LOG_ERR, "ERROR: unable to send command to child process (bytes_written=%d)\n", bytes_written);
		/* kill child and recreate a new child */
		return;
	} /* end if */

	/* release child */
	ext_dnsd_release_child (child);
	
	/* get reply */
	if (axl_cmp (reply_buffer, "DISCARD")) {
		syslog (LOG_INFO, "child requested to DISCARD request..\n");
		return;
	} else if (axl_cmp (reply_buffer, "UNKNOWN")) {
		syslog (LOG_INFO, "child requested to send UNKNOWN code reply..\n");

		/* build the unknown reply */
		reply = ext_dns_message_build_unknown_reply (ctx, message);
	} else if (axl_cmp (reply_buffer, "REJECT")) {
		syslog (LOG_INFO, "child requested to REJECT request..\n");
		
		/* build the reject reply */
		reply = ext_dns_message_build_unknown_reply (ctx, message);

	} else if (axl_cmp (reply_buffer, "FORWARD")) {
		/* syslog (LOG_INFO, "child requested to continue and resolve request as usual using forward dns server..\n"); */
	} else if (axl_memcmp (reply_buffer, "REPLY ", 6)) {
		/* parse reply received */
		reply = ext_dnsd_handle_reply (ctx, message, reply_buffer, session, source_address, source_port);
	} else {
		syslog (LOG_INFO, "ERROR: unrecognized command reply found from child: %s..\n", reply_buffer);
		return; /* do not handle the request in this case */
	}

	/* check if handlers requested to return because they are
	 * completing pending requests */
	if (PTR_TO_INT(reply) == 2) 
		return;

	if (reply) {
		/* store reply in the cache */
		ext_dns_cache_store (ctx, reply);

		/* found reply we've got now, send it back to the user */
		ext_dnsd_send_reply (ctx, session, source_address, source_port, reply, axl_true);
		return;
	} /* end if */

	/* build state data */
	data                   = axl_new (HandleReplyData, 1);
	data->id               = message->header->id;
	data->source_address   = axl_strdup (source_address);
	data->source_port      = source_port;
	data->master_listener  = session;

	/* link this data to the session to be released in the case on
	 * received isn't called */
	ext_dns_session_set_data (session, axl_strdup_printf ("%p", data), axl_free, data, (axlDestroyFunc) handle_reply_data_free); 
	
	/* send query */
	result = ext_dns_message_query_from_msg (ctx, message, server, server_port, handle_reply, data);

	if (! result) {
		syslog (LOG_ERR, "ERROR: failed to send query to master server..\n");
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
	syslog (LOG_ERR, "BAD REQUEST from %s:%d, reason: %s\n", source_address, source_port, reason);

	return;
}

extDnsMutex doing_exit_mutex;
axl_bool    __doing_exit = axl_false;

extDnsCtx     * ctx = NULL;

void __terminate_ext_dns_listener (int value)
{
	
	ext_dns_mutex_lock (&doing_exit_mutex);
	if (__doing_exit) {
		ext_dns_mutex_unlock (&doing_exit_mutex);

		return;
	}
	/* printf ("Terminating ext_dns regression listener..\n");*/
	__doing_exit = axl_true;
	ext_dns_mutex_unlock (&doing_exit_mutex);

	syslog (LOG_INFO, "Received signal %d, finishing server..", value);

	/* unlocking listener */
	/* printf ("Calling to unlock listener due to signal received: extDnsCtx %p", ctx); */
	ext_dns_ctx_unlock (ctx);

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
	
	syslog (LOG_INFO, "configuration from %s loaded ok\n", path);

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

void start_child_applications (void)
{
	axlNode        * node;
	const char     * child_resolver;
	int              iterator;
	char             reply[20];

	/* find first listener node */
	node = axl_doc_get (config, "/ext-dns-server/child-resolver");
	if (node == NULL) {
		printf ("ERROR: unable to find any listen declaration at configuration file %s, unable to start any listener..\n", path);
		exit (-1);
	} /* end if */

	/* get child resolver */
	child_resolver = ATTR_VALUE (node, "value");
	if (child_resolver == NULL || strlen (child_resolver) == 0) {
		printf ("ERROR: child resolver application wasn't found defined (it is empty or NULL)\n");
		exit (-1);
	}

	/* find first listener node */
	node = axl_doc_get (config, "/ext-dns-server/child-number");
	if (node == NULL) {
		printf ("ERROR: unable to find any listen declaration at configuration file %s, unable to start any listener..\n", path);
		exit (-1);
	} /* end if */

	if (! ATTR_VALUE (node, "value") || strlen (ATTR_VALUE (node, "value")) == 0) {
		printf ("ERROR: child number value not defined\n");
		exit (-1);
	}

	/* child number */
	child_number = atoi (ATTR_VALUE (node, "value"));

	/* check child number */
	if (child_number <= 0) {
		printf ("ERROR: child number received is %d. It must be bigger than 0\n", child_number);
		exit (-1);
	}

	/* allocate memory to handle child state */
	children = axl_new (childState, child_number);

	iterator     = 0;
	while (iterator < child_number) {
		/* start child and set initial state */
		children[iterator].ready = axl_true;
		ext_dns_mutex_create (&children[iterator].mutex);

		/* create and get child pid */
		children[iterator].pid = ext_dns_create_child (children[iterator].fds, child_resolver);

		/* printf ("child created with pid %d, fds [%d, %d]\n", childs[iterator].pid, childs[iterator].fds[0], childs[iterator].fds[1]); */

		if (children[iterator].pid < 0) {
			printf ("ERROR: failed to create child process from child resolver '%s', error was errno=%d\n", child_resolver, errno);
			exit (-1);
		} /* end if */

		/* send init command to check if the child is working */
		if (! send_command ("INIT", &children[iterator], reply, 20)) {
			printf ("ERROR: child resolver (pid %d) %s didn't reply to INIT command..\n", children[iterator].pid, child_resolver);
			exit (-1);
		}

		if (! axl_cmp (reply, "OK")) {
			printf ("ERROR: child resolver (pid %d) %s didn't reply OK to INIT command..\n", children[iterator].pid, child_resolver);
			exit (-1);
		}
			

		syslog (LOG_INFO, "child resolver (pid %d) %s created..\n", children[iterator].pid, child_resolver);

		/* next iterator */
		iterator++;
	} /* end while */

	return;
	
}

void child_terminated (int _signal) {
	int exit_status = 0;
	int pid;

	pid = wait (&exit_status);
	syslog (LOG_INFO, "Child %d finished with %d\n", pid, exit_status);

	/* reinstall signal */
	signal (SIGCHLD, child_terminated);

	return;
}

int main (int argc, char ** argv) {

	/* install default handling to get notification about
	 * segmentation faults */
#ifdef AXL_OS_UNIX
	signal (SIGTERM,  __terminate_ext_dns_listener);
	signal (SIGQUIT,  __terminate_ext_dns_listener);
	signal (SIGCHLD, child_terminated);
#endif

	/* open syslog */
	openlog ("ext-dnsd", LOG_PID, LOG_DAEMON);

	/* install arguments */
	install_arguments (argc, argv);	

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

	/* init context */
	if (! ext_dns_init_ctx (ctx)) {
		printf ("ERROR: failed to initiatialize ext-dns server context..\n");
		exit (-1);
	} 

	/* init cache */
	ext_dns_cache_init (ctx, 1000);

	/* start listener declarations */
	start_listeners ();

	/* now start child applications */
	start_child_applications ();
	
	/* wait and process requests */
	syslog (LOG_INFO, "ext-dnsD started OK");
	ext_dns_ctx_wait (ctx);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	/* finish exarg */
	exarg_end ();	

	/* free configuration object */
	axl_doc_free (config);

	/* finalize childs */
	ext_dnsd_finish_childs ();
	
	return 0;
}
