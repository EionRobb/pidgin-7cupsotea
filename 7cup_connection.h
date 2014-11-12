
#ifndef 7CUP_CONNECTION_H
#define 7CUP_CONNECTION_H

#include "lib7cup.h"

typedef void (*SevenCupProxyCallbackFunc)(SevenCupAccount *sa, JsonObject *obj, gpointer user_data);
typedef void (*SevenCupProxyCallbackErrorFunc)(SevenCupAccount *sa, const gchar *data, gssize data_len, gpointer user_data);

/*
 * This is a bitmask.
 */
typedef enum
{
	7CUP_METHOD_GET  = 0x0001,
	7CUP_METHOD_POST = 0x0002,
	7CUP_METHOD_SSL  = 0x0004
} SevenCupMethod;

typedef struct _SevenCupConnection SevenCupConnection;
struct _SevenCupConnection {
	SevenCupAccount *sa;
	SevenCupMethod method;
	gchar *hostname;
	gchar *url;
	GString *request;
	SevenCupProxyCallbackFunc callback;
	gpointer user_data;
	char *rx_buf;
	size_t rx_len;
	PurpleProxyConnectData *connect_data;
	PurpleSslConnection *ssl_conn;
	int fd;
	guint input_watcher;
	gboolean connection_keepalive;
	time_t request_time;
	guint retry_count;
	guint timeout_watcher;
	SevenCupProxyCallbackErrorFunc error_callback;
};

void sevencup_connection_destroy(SevenCupConnection *scon);
void sevencup_connection_close(SevenCupConnection *scon);
SevenCupConnection *sevencup_post_or_get(SevenCupAccount *sa, SevenCupMethod method,
		const gchar *host, const gchar *url, const gchar *postdata,
		SevenCupProxyCallbackFunc callback_func, gpointer user_data,
		gboolean keepalive);
gchar *sevencup_cookies_to_string(SevenCupAccount *sa);

#endif /* 7CUP_CONNECTION_H */
