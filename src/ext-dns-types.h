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
#ifndef __EXT_DNS_TYPES_H__
#define __EXT_DNS_TYPES_H__

/**
 * \defgroup ext_dns_types extDns Types: type definitions used by the library
 */

/** 
 * \addtogroup ext_dns_message
 * @{
 */


/*
 * @brief Debug levels to be used with \ref _ext_dns_log, which is used
 * through ext_dns_log macro.
 *
 * The set of functions allowing to activate the debug at run time and
 * its variants are:
 * 
 * - \ref ext_dns_log_is_enabled
 * - \ref ext_dns_log2_is_enabled
 * - \ref ext_dns_log_enable
 * - \ref ext_dns_log2_enable
 *
 * Activate console color log (using ansi characters):
 * 
 * - \ref ext_dns_color_log_is_enabled
 * - \ref ext_dns_color_log_enable
 *
 * @param domain Domain that is registering a log.
 *
 * @param level Log level that is being registered.
 *
 * @param message Message that is being registered.
 */
typedef enum {
	/** 
	 * @internal Log a message as a debug message.
	 */
	EXT_DNS_LEVEL_DEBUG    = 1 << 0,
	/** 
	 * @internal Log a warning message.
	 */
	EXT_DNS_LEVEL_WARNING  = 1 << 1,
	/** 
	 * @internal Log a critical message.
	 */
	EXT_DNS_LEVEL_CRITICAL = 1 << 2,
} extDnsDebugLevel;


/** 
 * @brief A single library context where all state is stored.
 *
 * Before you can start using ext-dns API you must create an \ref
 * extDnsCtx object by calling to \ref ext_dns_ctx_new and then
 * initialize it by using \ref ext_dns_init_ctx.
 *
 * You can grab or release more references to the object by calling to \ref ext_dns_ctx_ref and \ref ext_dns_ctx_unref.
 *
 * In the case you are finishing clients or servers started with that context, you must call to \ref ext_dns_exit_ctx.
 */
typedef struct _extDnsCtx extDnsCtx;

/** 
 * @internal Definitions to accomodate the underlaying thread
 * interface to the extDns thread API.
 */
#if defined(AXL_OS_WIN32)

#define __OS_THREAD_TYPE__ win32_thread_t
#define __OS_MUTEX_TYPE__  HANDLE
#define __OS_COND_TYPE__   win32_cond_t

typedef struct _win32_thread_t {
	HANDLE    handle;
	void*     data;
	unsigned  id;	
} win32_thread_t;

/** 
 * @internal pthread_cond_t definition, fully based on the work done
 * by Dr. Schmidt. Take a look into his article (it is an excelent article): 
 * 
 *  - http://www.cs.wustl.edu/~schmidt/win32-cv-1.html
 * 
 * Just a wonderful work. 
 *
 * Ok. The following is a custom implementation to solve windows API
 * flaw to support conditional variables for critical sections. The
 * solution provided its known to work under all windows platforms
 * starting from NT 4.0. 
 *
 * In the case you are experimenting problems for your particular
 * windows platform, please contact us through the mailing list.
 */
typedef struct _win32_cond_t {
	/* Number of waiting threads. */
	int waiters_count_;
	
	/* Serialize access to <waiters_count_>. */
	CRITICAL_SECTION waiters_count_lock_;

	/* Semaphore used to queue up threads waiting for the
	 * condition to become signaled. */
	HANDLE sema_;

	/* An auto-reset event used by the broadcast/signal thread to
	 * wait for all the waiting thread(s) to wake up and be
	 * released from the semaphore.  */
	HANDLE waiters_done_;

	/* Keeps track of whether we were broadcasting or signaling.
	 * This allows us to optimize the code if we're just
	 * signaling. */
	size_t was_broadcast_;
	
} win32_cond_t;

#elif defined(AXL_OS_UNIX)

#include <pthread.h>
#define __OS_THREAD_TYPE__ pthread_t
#define __OS_MUTEX_TYPE__  pthread_mutex_t
#define __OS_COND_TYPE__   pthread_cond_t

#endif

/** 
 * @brief Thread definition, which encapsulates the os thread API,
 * allowing to provide a unified type for all threading
 * interface. 
 */
typedef __OS_THREAD_TYPE__ extDnsThread;

/** 
 * @brief Mutex definition that encapsulates the underlaying mutex
 * API.
 */
typedef __OS_MUTEX_TYPE__  extDnsMutex;

/** 
 * @brief Conditional variable mutex, encapsulating the underlaying
 * operating system implementation for conditional variables inside
 * critical sections.
 */
typedef __OS_COND_TYPE__   extDnsCond;

/** 
 * @brief Message queue implementation that allows to communicate
 * several threads in a safe manner. 
 */
typedef struct _extDnsAsyncQueue extDnsAsyncQueue;

/** 
 * @brief Handle definition for the family of function that is able to
 * accept the function \ref ext_dns_thread_create.
 *
 * The function receive a user defined pointer passed to the \ref
 * ext_dns_thread_create function, and returns an pointer reference
 * that must be used as integer value that could be retrieved if the
 * thread is joined.
 *
 * Keep in mind that there are differences between the windows and the
 * posix thread API, that are supported by this API, about the
 * returning value from the start function. 
 * 
 * While POSIX defines as returning value a pointer (which could be a
 * reference pointing to memory high above 32 bits under 64
 * architectures), the windows API defines an integer value, that
 * could be easily used to return pointers, but only safe on 32bits
 * machines.
 *
 * The moral of the story is that you must use another mechanism to
 * return data from this function to the thread that is expecting data
 * from this function. 
 * 
 * Obviously if you are going to return an status code, there is no
 * problem. This only applies to user defined data that is returned as
 * a reference to allocated data.
 */
typedef axlPointer (* extDnsThreadFunc) (axlPointer user_data);

/** 
 * @brief Thread configuration its to modify default behaviour
 * provided by the thread creation API.
 */
typedef enum  {
	/** 
	 * @brief Marker used to signal \ref ext_dns_thread_create that
	 * the configuration list is finished.
	 * 
	 * The following is an example on how to create a new thread
	 * without providing any configuration, using defaults:
	 *
	 * \code
	 * extDnsThread thread;
	 * if (! ext_dns_thread_created (&thread, 
	 *                              some_start_function, NULL,
	 *                              EXT_DNS_THREAD_CONF_END)) {
	 *      // failed to create the thread 
	 * }
	 * // thread created
	 * \endcode
	 */
	EXT_DNS_THREAD_CONF_END = 0,
	/** 
	 * @brief Allows to configure if the thread create can be
	 * joined and waited by other. 
	 *
	 * Default state for all thread created with \ref
	 * ext_dns_thread_create is true, that is, the thread created
	 * is joinable.
	 *
	 * If configured this value, you must provide as the following
	 * value either axl_true or axl_false.
	 *
	 * \code
	 * extDnsThread thread;
	 * if (! ext_dns_thread_create (&thread, some_start_function, NULL, 
	 *                             EXT_DNS_THREAD_CONF_JOINABLE, axl_false,
	 *                             EXT_DNS_THREAD_CONF_END)) {
	 *    // failed to create the thread
	 * }
	 * 
	 * // Nice! thread created
	 * \endcode
	 */
	EXT_DNS_THREAD_CONF_JOINABLE  = 1,
	/** 
	 * @brief Allows to configure that the thread is in detached
	 * state, so no thread can join and wait for it for its
	 * termination but it will also provide.
	 */
	EXT_DNS_THREAD_CONF_DETACHED = 2,
}extDnsThreadConf;

/**
 * @brief Enumeration type that allows to use the waiting mechanism to
 * be used by the core library to perform wait on changes on sockets
 * handled.
 */

typedef enum {
	/**
	 * @brief Allows to configure the select(2) system call based
	 * mechanism. It is known to be available on any platform,
	 * however it has some limitations while handling big set of
	 * sockets, and it is limited to a maximum number of sockets,
	 * which is configured at the compilation process.
	 *
         * Its main disadvantage it that it can't handle
	 * more connections than the number provided at the
	 * compilation process. See <ext_dns.h> file, variable
	 * FD_SETSIZE and EXT_DNS_FD_SETSIZE.
	 */
	EXT_DNS_IO_WAIT_SELECT = 1,
	/**
	 * @brief Allows to configure the poll(2) system call based
	 * mechanism. 
	 * 
	 * It is also a widely available mechanism on POSIX
	 * envirionments, but not on Microsoft Windows. It doesn't
	 * have some limitations found on select(2) call, but it is
	 * known to not scale very well handling big socket sets as
	 * happens with select(2) (\ref EXT_DNS_IO_WAIT_SELECT).
	 *
	 * This mechanism solves the runtime limitation that provides
	 * select(2), making it possible to handle any number of
	 * connections without providing any previous knowledge during
	 * the compilation process. 
	 * 
	 * Several third party tests shows it performs badly while
	 * handling many connections compared to (\ref EXT_DNS_IO_WAIT_EPOLL) epoll(2).
	 *
	 * However, reports showing that results, handles over 50.000
	 * connections at the same time (up to 400.000!). In many
	 * cases this is not going your production environment.
	 *
	 * At the same time, many reports (and our test results) shows
	 * that select(2), poll(2) and epoll(2) performs the same
	 * while handling up to 10.000 connections at the same time.
	 */
	EXT_DNS_IO_WAIT_POLL   = 2,
	/**
	 * @brief Allows to configure the epoll(2) system call based
	 * mechanism.
	 * 
	 * It is a mechanism available on GNU/Linux starting from
	 * kernel 2.6. It is supposed to be a better implementation
	 * than poll(2) and select(2) due the way notifications are
	 * done.
	 *
	 * It is currently selected by default if your kernel support
	 * it. It has the advantage that performs very well with
	 * little set of connections (0-10.000) like
	 * (\ref EXT_DNS_IO_WAIT_POLL) poll(2) and (\ref EXT_DNS_IO_WAIT_SELECT)
	 * select(2), but scaling much better when going to up heavy
	 * set of connections (50.000-400.000).
	 *
	 * It has also the advantage to not require defining a maximum
	 * socket number to be handled at the compilation process.
	 */
	EXT_DNS_IO_WAIT_EPOLL  = 3,
} extDnsIoWaitingType;

/** 
 * @brief Allows to specify which type of operation should be
 * implemented while calling to extDns Library internal IO blocking
 * abstraction.
 */
typedef enum {
	/** 
	 * @brief A read watching operation is requested. If this
	 * value is received, the fd set containins a set of socket
	 * descriptors which should be watched for incoming data to be
	 * received.
	 */
	READ_OPERATIONS  = 1 << 0, 
	/** 
	 * @brief A write watching operation is requested. If this
	 * value is received, the fd set contains a set of socket that
	 * is being requested for its availability to perform a write
	 * operation on them.
	 */
	WRITE_OPERATIONS = 1 << 1
} extDnsIoWaitingFor;

/** 
 * @brief Structure that represents a single session server (name
 * server) or client session (resolver)
 */
typedef struct _extDnsSession extDnsSession;

/** 
 * @brief extDns Operation Status.
 * 
 * This enum is used to represent different extDns Library status,
 * especially while operating with \ref extDnsSession references.
 */
typedef enum {
	/** 
	 * @brief Represents an Error while extDns Library was operating.
	 *
	 * The operation asked to be done by extDns Library could be
	 * completed.
	 */
	extDnsError                  = 1,
	/** 
	 * @brief Represents the operation have been successfully completed.
	 *
	 * The operation asked to be done by extDns Library have been
	 * completed.
	 */
	extDnsOk                     = 2,

	/** 
	 * @brief The operation wasn't completed because an error to
	 * tcp bind call. This usually means the listener can be
	 * started because the port is already in use.
	 */
	extDnsBindError              = 3,

	/** 
	 * @brief The operation can't be completed because a wrong
	 * reference (memory address) was received. This also include
	 * NULL references where this is not expected.
	 */
	extDnsWrongReference         = 4,

	/** 
	 * @brief The operation can't be completed because a failure
	 * resolving a name was found (usually a failure in the
	 * gethostbyname function). 
	 */ 
	extDnsNameResolvFailure      = 5,

	/** 
	 * @brief A failure was found while creating a socket.
	 */
	extDnsSocketCreationError    = 6,

	/** 
	 * @brief Found socket created to be using reserved system
	 * socket descriptors. This will cause problems.
	 */
	extDnsSocketSanityError      = 7,

	/** 
	 * @brief Session error. Unable to connect to remote
	 * host. Remote hosting is refusing the session.
	 */
	extDnsSessionError           = 8,

	/** 
	 * @brief Session error after timeout. Unable to connect to
	 * remote host after after timeout expired.
	 */
	extDnsSessionTimeoutError    = 9,
	/** 
	 * @brief Session is in transit to be closed. 
	 */
	extDnsSessionCloseCalled     = 10,
	/** 
	 * @brief The session was terminated due to a call to \ref
	 * ext_dns_session_shutdown or an internal implementation
	 * that closes the session without taking place the DNS
	 * session close negociation.
	 */
	extDnsSessionForcedClose     = 11,
	/** 
	 * @brief Found a protocol error while operating.
	 */
	extDnsProtocolError          = 12,
	/** 
	 * @brief  The session was closed or not accepted due to a filter installed. 
	 */
	extDnsSessionFiltered        = 13,
	/** 
	 * @brief Memory allocation failed.
	 */
	extDnsMemoryFail             = 14,
	/** 
	 * @brief When a session is closed by the remote side but
	 * without going through the DNS clean close.
	 */
	extDnsUnnotifiedSessionClose = 15
} extDnsStatus;

/** 
 * @brief Allows to classify the role of the connection.
 *
 * You can get current role for a given connection using \ref ext_dns_session_get_role.
 * 
 */
typedef enum {
	/** 
	 * @brief This value is used to represent an unknown role state.
	 */
	extDnsRoleUnknown,
	
	/** 
	 * @brief The connection is acting as a Resolver one.
	 */
	extDnsRoleResolver,

	/** 
	 * @brief The connection is acting as a Listener one.
	 */
	extDnsRoleListener,
	
	/** 
	 * @brief Special case that represents listener connections
	 * (TCP) that accepts connections to process DNS requests via
	 * TCP
	 */
	extDnsRoleMasterListener
	
} extDnsPeerRole;

/** 
 * @brief Allows to signal which type of session is running a \ref
 * extDnsSession object.
 */
typedef enum {
	/** 
	 * @brief TCP based DNS session
	 */
	extDnsTcpSession = 1,
	/** 
	 * @brief UDP based DNS session
	 */
	extDnsUdpSession = 2
} extDnsSessionType;

/** 
 * @brief Type of DNS message supported (RFC).
 */
typedef enum {
	
	/**
	 * Unknown query value received. 
	 */
	extDnsUnknownQueryType = -1,
	/** 
	 * Standard query (RFC opcode 0 QUERY)
	 */
	extDnsStandardQuery    = 0,
	/** 
	 * Inverse query (RFC opcode 1 IQUERY)
	 */
	extDnsInverseQuery     = 1,
	/** 
	 * Server status request (RFC opcode 2 STATUS)
	 */
	extDnsSeverStatusQuery = 2
} extDnsQueryType;

/** 
 * @brief Type of responses we can receive or send via DNS message.
 */
typedef enum {
	/** 
	 * @brief No error condition.
	 */
	extDnsResponseNoError            = 0,
	/** 
	 * @brief Format error - The name server was unable to
	 * interpret the query.
	 */
	extDnsResponseFormarError        = 1,
	/** 
	 * @brief Server failure - The name server was unable to
	 * process this query due to a problem with the name server.
	 */
	extDnsResponseServerFailure      = 2,
	/** 
	 * @brief Name Error - Meaningful only for responses from an
	 * authoritative name server, this code signifies that the
	 * domain name referenced in the query does not exist.
	 */
	extDnsResponseNameError          = 3,
	/** 
	 * @brief Not Implemented - The name server does not support
	 * the requested kind of query.
	 */
	extDnsResponseNoImplementedError = 4,
	/** 
	 * @brief Refused - The name server refuses to perform the
	 * specified operation for policy reasons. For example, a name
	 * server may not wish to provide the information to ahe
	 * particular requester, or a name server may not wish to
	 * perform a particular operation.
	 */
	extDnsResponseRefused            = 5
} extDnsResponseType;


/** 
 * @brief Header information for each DNS message. 
 */ 
typedef struct _extDnsHeader {
	/** 
	 * @brief Unique message id for query or reply being
	 * implemented.
	 */ 
	unsigned int       id;
	/** 
	 * @brief Holds information about if this message is a query
	 * or a reply.
	 */
	axl_bool           is_query;
	/** 
	 * @brief Additional information for this message. Check each
	 * code to know more about them.
	 */
	extDnsQueryType    opcode;

	/** 
	 * @brief Flag to indicate this is an authorative answer.
	 */
	axl_bool           is_authorative_answer;
	/** 
	 * @brief Flag to indicate this is a truncated DNS message.
	 */
	axl_bool           was_truncated;
	/** 
	 * @brief Flag to indicate that the client requested to make
	 * recursion to resolve the DNS query.
	 */
	axl_bool           recursion_desired;
	/** 
	 * @brief Flag to indicate that the server support recursion.
	 */
	axl_bool           recursion_available;

	/** 
	 * @brief Flag to indicate the type of response.
	 */
	extDnsResponseType rcode;
	/** 
	 * @brief How many query elements are inside the
	 * message->questions section inside the message.
	 */
	int                query_count;
	/** 
	 * @brief How many anser elements are inside the
	 * message->answers section inside the message.
	 */
	int                answer_count;
	/** 
	 * @brief How many authority elements are inside the
	 * message->authorities section inside the message.
	 */
	int                authority_count;
	/** 
	 * @brief How many additional elements are inside the
	 * message->additionals section inside the message.
	 */
	int                additional_count;

	/* private records */

} extDnsHeader;

/** 
 * TYPE fields are used in resource records.  Note that these types
 * are a subset of QTYPEs.
 */
typedef enum {
	/** 
	 * A host address.
	 */
	extDnsTypeA      = 1,
	/** 
	 * An authoritative name server
	 */
	extDnsTypeNS     = 2,
	/** 
	 * A mail destination (Obsolete - use MX)
	 */
	extDnsTypeMD     = 3,
	/** 
	 * Amail forwarder (Obsolete - use MX)
	 */
	extDnsTypeMF     = 4,
	/** 
	 * The canonical name for an alias
	 */
	extDnsTypeCNAME  = 5,
	/** 
	 * Marks the start of a zone of authority
	 */
	extDnsTypeSOA    = 6,
	/** 
	 * A mailbox domain name (EXPERIMENTAL)
	 */
	extDnsTypeMB     = 7,
	/** 
	 * A mail group member (EXPERIMENTAL)
	 */
	extDnsTypeMG     = 8,
	/** 
	 * A mail group member (EXPERIMENTAL)
	 */
	extDnsTypeMR     = 9,
	/** 
	 * A null RR (EXPERIMENTAL)
	 */
	extDnsTypeNULL   = 10,
	/** 
	 * A well known service description
	 */
	extDnsTypeWKS    = 11,
	/** 
	 * A domain name pointer.
	 */
	extDnsTypePTR    = 12,
	/** 
	 * Host information
	 */
	extDnsTypeHINFO  = 13,
	/** 
	 * Mailbox or mail list information
	 */
	extDnsTypeMINFO  = 14,
	/** 
	 * Mail exchange
	 */
	extDnsTypeMX     = 15,
	/** 
	 * Text strings
	 */
	extDnsTypeTXT    = 16,
	/** 
	 * IPv6 addresses
	 */
	extDnsTypeAAAA   = 28,
	/** 
	 * SRV support type
	 */
	extDnsTypeSRV    = 33,
	/** 
	 * SPF support type
	 */
	extDnsTypeSPF    = 99,
	/** 
	 * A request for a transfer of an entire zone
	 */
	extDnsTypeAXFR   = 252,
	/** 
	 * A request for mailbox-related records (MB, MG or MR)
	 */
	extDnsTypeMAILB  = 253,
	/** 
	 * A request for mail agent RRs (Obsolete - see MX)
	 */
	extDnsTypeMAILA  = 254,
	/** 
	 * A request for all records
	 */
	extDnsTypeANY    = 255
} extDnsType;

/** 
 * CLASS values. CLASS fields appear in resource records.  The
 * following CLASS mnemonics and values are defined:
 */ 
typedef enum {
	/** 
	 * The Internet
	 */
	extDnsClassIN         = 1,
	/** 
	 * The CSNET class (Obsolete - used only for examples in some
	 * obsolete RFCs)
	 */
	extDnsClassCS         = 2,
	/** 
	 * The CHAOS class
	 */
	extDnsClassCH         = 3,
	/** 
	 * Hesiod [Dyer 87]
	 */
	extDnsClassHS         = 4,
	/** 
	 * Any class
	 */
	extDnsClassANY   = 255
} extDnsClass;

/** 
 * @brief Represents a question inside the question section.
 */ 
typedef struct _extDnsQuestion {
	/** 
	 * @brief Question name being asked inside the question
	 * section.
	 */
	char         * qname;
	/** 
	 * @brief Question type being asked.
	 */
	extDnsType     qtype;
	/** 
	 * @brief Question class being asked.
	 */
	extDnsClass    qclass;
} extDnsQuestion;

/** 
 * @brief Public structure that defines a single resource record. This
 * is a generic structure where, according to the record type each
 * value is filled with the right content. Not all attributes are used
 * at the same time.
 */
typedef struct _extDnsResourceRecord {
	/** 
	 * @brief Record name.
	 */
	char         * name;
	/** 
	 * @brief Record type.
	 */
	extDnsType     type;
	/** 
	 * @brief Record class.
	 */
	extDnsClass    class;
	/** 
	 * @brief Record ttl.
	 */
	int            ttl;

	/** 
	 * @brief Printable, easy to read content to show what's
	 * inside this record. MX exchange, NS nsdname, A the IP,
	 * CNAME the hostname alias, TXT and SPF. */
	char         * name_content;

	/** 
	 * @brief MX preference and SRV priority 
	 */
	int            preference;
	/** 
	 * @brief Weight attribute for SRV records. Only used for SRV records.
	 */
	int            weight; 
	/** 
	 * @brief Port attribute for SRV records. Only used for SRV records.
	 */
	int            port;
	/** 
	 * @brief Target value for SRV records. Only used for SRV records.
	 */
	char         * target;

	/** 
	 * SOA specific values */
	char         * mname;
	char         * contact_address;
	int            serial;
	int            refresh;
	int            retry;
	int            expire;
	int            minimum;

	/** 
	 * @brief Raw rdlength data found in the DNS record at the wire.
	 */
	int            rdlength;
	/** 
	 * @brief Raw rdata data found in the DNS record at the wire.
	 */
	char         * rdata;
} extDnsResourceRecord;

/** 
 * @brief Data type that represents a single DNS message.
 *
 * The \ref extDnsMessage is one of the most important API definition
 * because is is used to create DNS messages or as a representation
 * for messages received (via \ref extDnsOnMessageReceived handler,
 * usually configured by \ref ext_dns_session_set_on_message or by \ref ext_dns_ctx_set_on_message).
 *
 * The \ref extDnsMessage may represent a query or a reply (\ref ext_dns_message_is_query), and when it represents an error reply,
 * you can use several functions to know what is the exact error type
 * (\ref ext_dns_message_is_reject , \ref ext_dns_message_is_name_error or \ref ext_dns_message_is_answer_valid).
 *
 * Every \ref extDnsMessage object has a reference counting associated
 * with it. You can use the following functions to acquire references
 * to the object via \ref ext_dns_message_ref and \ref ext_dns_message_unref to release them.
 *
 * Please, check the \ref ext_dns_message "extDnsMessage API" for more
 * information about available options and \ref ext_dns_library_manual "libext-dns manual".
 */
typedef struct _extDnsMessage {
	/** 
	 * @brief The reference to the header of the DNS package. It
	 * contains information about every section contained in this
	 * DNS message.
	 */
	extDnsHeader         * header;
	/** 
	 * @brief The reference to the question section where each
	 * position represents a question.
	 */
	extDnsQuestion       * questions;
	
	/** 
	 * @brief The reference to the answers section where each
	 * position represents an answer.
	 */
	extDnsResourceRecord * answers;
	
	/** 
	 * @brief The reference to the authorities section where each
	 * posisition represents an answer.
	 */
	extDnsResourceRecord * authorities;

	/** 
	 * @brief The reference to the additional section where each
	 * posisition represents an additional section to the
	 * query/reply.
	 */
	extDnsResourceRecord * additionals;

	/* private definitions, do not touch them, may change in
	 * future releases */
	extDnsMutex            mutex;
	int                    ref_count;

	/* message size */
	int                    message_size;

	/** 
	 * @brief When this message was created. 
	 */ 
	int                    stamp;
} extDnsMessage;

/** 
 * @brief Object used by \ref ext_dns_cache_stats to report current
 * cache stats on a particular context.
 */
typedef struct _extDnsCacheStats {
	/** 
	 * @brief Current caché size
	 */
	int cache_size;
	/** 
	 * @brief Number of items stored in the cache
	 */
	int cache_items;
	
	/** 
	 * @brief Current cache hits
	 */
	int cache_hits;

	/** 
	 * @brief Current cache total access so far.
	 */
	int cache_access;
} extDnsCacheStats;

#endif /* __EXT_DNS_TYPES_H__ */

/* @} */
