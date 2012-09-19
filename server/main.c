/* 
 *  ext-dns: another, but configurable, DNS server
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
childState * childs;
int child_number;

void handle_reply_data_free (HandleReplyData * data)
{
	axl_free (data->source_address);
	axl_free (data);
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

	if (message->answers) {
		printf ("REPLY: received reply from %s:%d, values: %s %d %d %s\n", 
			server, server_port,
			message->answers[0].name, message->answers[0].type, message->answers[0].class, message->answers[0].name_content); 
	} else {
		printf ("REPLY: received reply from %s:%d\n", server, server_port);
	}

	/* ok, rewrite reply id to match the one sent by the client */
	message->header->id = reply_data->id;

	/* get the reply into a buffer */
	bytes_written = ext_dns_message_to_buffer (ctx, message, buffer, 512);
	if (bytes_written == -1) {
		handle_reply_data_free (reply_data);

		printf ("ERROR: failed to build buffer representation for reply received..\n");
		return;
	}
	printf ("REPLY: build buffer reply in %d bytes\n", bytes_written);

	/* relay reply to the regression client */
	if (ext_dns_session_send_udp_s (ctx, reply_data->master_listener, buffer, bytes_written, reply_data->source_address, reply_data->source_port) != bytes_written) 
		printf ("ERROR: failed to SEND UDP entire reply, expected to write %d bytes but something different was written\n", bytes_written);
	else
		printf ("INFO: reply sent!\n");
	

	/* release data */
	handle_reply_data_free (reply_data);
	return;
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

	/* skip messages that are queries */
	if (! ext_dns_message_is_query (message)) {
		printf ("ERROR: received a query message, dropping DNS message..\n");
		return;
	} /* end if */

	printf ("INFO: received message from %s:%d, query type: %s %s %s..\n", 
		source_address, source_port, 
		ext_dns_message_get_qtype_to_str (ctx, message->questions[0].qtype),
		ext_dns_message_get_qclass_to_str (ctx, message->questions[0].qclass),
		message->questions[0].qname);

	/* build state data */
	data                   = axl_new (HandleReplyData, 1);
	data->id               = message->header->id;
	data->source_address   = axl_strdup (source_address);
	data->source_port      = source_port;
	data->master_listener  = session;
	
	/* send query */
	result = ext_dns_message_query_from_msg (ctx, message, server, server_port, handle_reply, data);

	if (! result) 
		printf ("ERROR: failed to send query to master server..\n");

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
	
	printf ("INFO: configuration from %s loaded ok\n", path);

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

		/* release values */
		axl_stream_freev (values);

		if (! ext_dns_session_is_ok (listener, axl_false)) {
			printf ("ERROR: failed to start serving requests..\n");
			exit (-1);
		} /* end if */
	
		/* configure on received handler */
		ext_dns_session_set_on_message (listener, on_received, NULL);

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

	/* printf ("INFO: sending command %s to child %d\n", command, child->pid); */
	
	/* send command */
	bytes_written = strlen (command);
	if (write (child->fds[1], command, bytes_written) != bytes_written) {
		printf ("ERROR: failed to send command to child, error was errno=%d (%s)\n", errno, ext_dns_errno_get_last_error ());
		return axl_false;
	}
	if (write (child->fds[1], "\n", 1) != 1) {
		printf ("ERROR: failed to write trailing command, error was errno=%d (%s)\n", errno, ext_dns_errno_get_last_error ());
		return axl_false;
	}

	/* printf ("INFO: reading reply to command..\n"); */

	/* now wait for reply */
	bytes_written = ext_dnsd_readline (child->fds[0], reply, reply_size);

	if (bytes_written < 0) {
		printf ("ERROR: failed to receive content from child, error was errno=%d (%s)\n", errno, ext_dns_errno_get_last_error ());
		return axl_false;
	} /* end if */

	/* trim content and recalculate */
	axl_stream_trim (reply);
	bytes_written = strlen (reply);

	/* printf ("INFO: bytes received %d\n", bytes_written); */
	return bytes_written;
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
	childs = axl_new (childState, child_number);

	iterator     = 0;
	while (iterator < child_number) {
		/* start child and set initial state */
		childs[iterator].ready = axl_true;
		ext_dns_mutex_create (&childs[iterator].mutex);

		/* create and get child pid */
		childs[iterator].pid = ext_dns_create_child (childs[iterator].fds, child_resolver);

		/* printf ("INFO: child created with pid %d, fds [%d, %d]\n", childs[iterator].pid, childs[iterator].fds[0], childs[iterator].fds[1]); */

		if (childs[iterator].pid < 0) {
			printf ("ERROR: failed to create child process from child resolver '%s', error was errno=%d\n", child_resolver, errno);
			exit (-1);
		} /* end if */

		/* send init command to check if the child is working */
		if (! send_command ("INIT", &childs[iterator], reply, 20)) {
			printf ("ERROR: child resolver (pid %d) %s didn't reply to INIT command..\n", childs[iterator].pid, child_resolver);
			exit (-1);
		}

		if (! axl_cmp (reply, "OK")) {
			printf ("ERROR: child resolver (pid %d) %s didn't reply OK to INIT command..\n", childs[iterator].pid, child_resolver);
			exit (-1);
		}
			

		printf ("INFO: child resolver (pid %d) %s created..\n", childs[iterator].pid, child_resolver);

		/* next iterator */
		iterator++;
	} /* end while */

	return;
	
}

void child_terminated (int _signal) {
	int exit_status = 0;
	int pid;

	pid = wait (&exit_status);
	printf ("INFO: Child %d finished with %d\n", pid, exit_status);

	/* reinstall signal */
	signal (SIGCHLD, child_terminated);

	return;
}

int main (int argc, char ** argv) {

	/* install default handling to get notification about
	 * segmentation faults */
#ifdef AXL_OS_UNIX
	signal (SIGTERM,  __terminate_ext_dns_listener);
	signal (SIGCHLD, child_terminated);
#endif

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

	/* start listener declarations */
	start_listeners ();

	/* now start child applications */
	start_child_applications ();
	
	/* wait and process requests */
	ext_dns_ctx_wait (ctx);

	/* terminate process */
	ext_dns_exit_ctx (ctx, axl_true);

	/* finish exarg */
	exarg_end ();	
	
	return 0;
}
