

#ifndef LIB7CUP_H
#define LIB7CUP_H

/* Maximum number of simultaneous connections to a server */
#define 7CUP_MAX_CONNECTIONS 16

#include <glib.h>

#include <errno.h>
#include <string.h>
#include <glib/gi18n.h>
#include <sys/types.h>
#ifdef __GNUC__
	#include <unistd.h>
#endif

#ifndef G_GNUC_NULL_TERMINATED
#	if __GNUC__ >= 4
#		define G_GNUC_NULL_TERMINATED __attribute__((__sentinel__))
#	else
#		define G_GNUC_NULL_TERMINATED
#	endif /* __GNUC__ >= 4 */
#endif /* G_GNUC_NULL_TERMINATED */

#ifdef _WIN32
#	include "win32dep.h"
#else
#	include <arpa/inet.h>
#	include <netinet/in.h>
#	include <sys/socket.h>
#endif

#include <json-glib/json-glib.h>

#ifndef PURPLE_PLUGINS
#	define PURPLE_PLUGINS
#endif

#include "accountopt.h"
#include "blist.h"
#include "core.h"
#include "connection.h"
#include "debug.h"
#include "dnsquery.h"
#include "proxy.h"
#include "prpl.h"
#include "request.h"
#include "savedstatuses.h"
#include "sslconn.h"
#include "version.h"

#if GLIB_MAJOR_VERSION >= 2 && GLIB_MINOR_VERSION >= 12
#	define atoll(a) g_ascii_strtoll(a, NULL, 0)
#endif

#define 7CUP_PLUGIN_ID "prpl-7cupsoftea"
#define 7CUP_PLUGIN_VERSION "0.1"

typedef struct _SevenCupAccount SevenCupAccount;
typedef struct _SevenCupBuddy SevenCupBuddy;

typedef void (*SevenCupFunc)(SevenCupAccount *sa);

struct _SevenCupAccount {
	PurpleAccount *account;
	PurpleConnection *pc;
	GSList *conns; /**< A list of all active connections */
	GQueue *waiting_conns; /**< A list of all connections waiting to process */
	GSList *dns_queries;
	GHashTable *cookie_table;
	GHashTable *hostname_ip_cache;
	
	GHashTable *sent_messages_hash;
	guint poll_timeout;
};

struct _SevenCupBuddy {
	SevenCupAccount *sa;
	PurpleBuddy *buddy;
};


#endif /* LIB7CUP_H */
