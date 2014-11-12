#include "lib7cup.h"
#include "7cup_connection.h"

#if !PURPLE_VERSION_CHECK(3, 0, 0)
	#define purple_connection_error purple_connection_error_reason
	#define purple_notify_user_info_add_pair_html purple_notify_user_info_add_pair
#endif

static const gchar *
sevencup_md5(const gchar *data)
{
	PurpleCipherContext *context;
	static gchar digest[41];
	
	context = purple_cipher_context_new_by_name("md5", NULL);
	g_return_val_if_fail(context != NULL, NULL);
	
	purple_cipher_context_append(context, data, strlen(data));
	
	if (!purple_cipher_context_digest_to_str(context, sizeof(digest), digest, NULL))
		return NULL;
	
	purple_cipher_context_destroy(context);
	
	return digest;
}

static guint active_icon_downloads = 0;

static void
steam_get_icon_cb(PurpleUtilFetchUrlData *url_data, gpointer user_data, const gchar *url_text, gsize len, const gchar *error_message)
{
	PurpleBuddy *buddy = user_data;
	SevenCupBuddy *sbuddy;
	
	if (!buddy || !buddy->proto_data)
		return;
	
	sbuddy = buddy->proto_data;
	
	purple_buddy_icons_set_for_user(buddy->account, buddy->name, g_memdup(url_text, len), len, sbuddy->avatar);
	
	active_icon_downloads--;
}

static void
steam_get_icon_now(PurpleBuddy *buddy)
{
	const gchar *old_avatar = purple_buddy_icons_get_checksum_for_user(buddy);
	SevenCupBuddy *sbuddy;
	
	purple_debug_info("steam", "getting new buddy icon for %s\n", buddy->name);
	
	if (!buddy || !buddy->proto_data)
	{
		purple_debug_info("steam", "no buddy proto_data :(\n");
		return;
	}
	
	sbuddy = buddy->proto_data;
	if (!sbuddy->avatar || (old_avatar && g_str_equal(sbuddy->avatar, old_avatar)))
		return;
	
#if PURPLE_VERSION_CHECK(3, 0, 0)
	purple_util_fetch_url_request(buddy->account, sbuddy->avatar, TRUE, NULL, FALSE, NULL, FALSE, -1, steam_get_icon_cb, buddy);
#else
	purple_util_fetch_url_request(sbuddy->avatar, TRUE, NULL, FALSE, NULL, FALSE, steam_get_icon_cb, buddy);
#endif

	active_icon_downloads++;
}

static gboolean
steam_get_icon_queuepop(gpointer data)
{
	PurpleBuddy *buddy = data;
	
	// Only allow 4 simultaneous downloads
	if (active_icon_downloads > 4)
		return TRUE;
	
	steam_get_icon_now(buddy);
	return FALSE;
}

static void
steam_get_icon(PurpleBuddy *buddy)
{
	if (!buddy) return;
	
	purple_timeout_add(100, steam_get_icon_queuepop, (gpointer)buddy);
}

static void
sevencup_send_message(SevenCupAccount *sa, const gchar *convID, const gchar *message)
{
	GString *post  = g_string_new(NULL);
	
	gchar *msgHash = sevencup_md5(message);
	
	g_string_append_printf(post, "convID=%s&", purple_url_encode(convID));
	g_string_append_printf(post, "comment=%s&", purple_url_encode(message));
	g_string_append_printf(post, "msgHash=%s&", purple_url_encode(msgHash ? msgHash : ""));
	
	sevencup_post_or_get(sa, 7CUP_METHOD_POST | 7CUP_METHOD_SSL, NULL, "/connect/checkConvMessages.php", post, sevencup_check_conv_cb, NULL, TRUE);
	
	g_string_free(post);
	g_free(msgHash);
}

static void
sevencup_check_conv_cb(SevenCupAccount *sa, JsonObject *obj, gpointer user_data)
{
	JsonArray *messages = NULL;
	guint index;
	const gchar *convID;
	PurpleConversation *conv;
	
	convID = json_object_get_string_member(obj, "convID");
	
	if (json_object_has_member(obj, "messages"))
		messages = json_object_get_array_member(obj, "messages");
	
	for(index = 0; messages != NULL && index < json_array_get_length(messages); index++)
	{
		
	}
}

static void
sevencup_check_conv_messages(SevenCupAccount *sa, const gchar *convID, gint lastMessage)
{
	GString *post  = g_string_new(NULL);
	
	g_string_append_printf(post, "convID=%s&", purple_url_encode(convID));
	g_string_append_printf(post, "lastMessage=%d&", lastMessage);
	g_string_append(post, "lp=false&");
	
	sevencup_post_or_get(sa, 7CUP_METHOD_POST | 7CUP_METHOD_SSL, NULL, "/connect/checkConvMessages.php", post, sevencup_check_conv_cb, NULL, TRUE);
	
	g_string_free(post);
}

static void
sevencup_conversations_cb(SevenCupAccount *sa, JsonObject *obj, gpointer user_data)
{
	JsonArray *messages = NULL;
	guint index;
	gint secure = GPOINTER_TO_INT(user_data);
	guint server_timestamp;
	time_t local_timestamp;
	GString *users_to_update = g_string_new(NULL);
	
	server_timestamp = (guint) json_object_get_int_member(obj, "timestamp");
	local_timestamp = time(NULL);
	
	if (json_object_has_member(obj, "messages"))
		messages = json_object_get_array_member(obj, "messages");
	
	if (messages != NULL)
	for(index = 0; index < json_array_get_length(messages); index++)
	{
		JsonObject *message = json_array_get_object_element(messages, index);
		const gchar *type = json_object_get_string_member(message, "type");
		purple_debug_info("steam", "new message of type %s\n", type);
		if (g_str_equal(type, "typing"))
		{
			serv_got_typing(sa->pc, json_object_get_string_member(message, "steamid_from"), 20, PURPLE_TYPING);
		} else if (g_str_equal(type, "saytext") || g_str_equal(type, "emote") || g_str_equal(type, "my_saytext") || g_str_equal(type, "my_emote"))
		{
			if (json_object_has_member(message, "secure_message_id"))
			{
				guint secure_message_id = (guint) json_object_get_int_member(message, "secure_message_id");
				steam_poll(sa, TRUE, secure_message_id);
				sa->message = MAX(sa->message, secure_message_id);
			} else {
				guint new_timestamp = (guint) json_object_get_int_member(message, "timestamp");
				if (new_timestamp > sa->last_message_timestamp)
				{
					gchar *text, *html;
					const gchar *from;
					if (g_str_equal(type, "emote") || g_str_equal(type, "my_emote"))
					{
						text = g_strconcat("/me ", json_object_get_string_member(message, "text"), NULL);
					} else {
						text = g_strdup(json_object_get_string_member(message, "text"));
					}
					html = purple_markup_escape_text(text, -1);
					from = json_object_get_string_member(message, "steamid_from");
					if (g_str_has_prefix(type, "my_")) {
						PurpleConversation *conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, from, sa->account);
						if (conv == NULL)
						{
							conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, sa->account, from);
						}
						purple_conversation_write(conv, from, html, PURPLE_MESSAGE_SEND, local_timestamp - ((server_timestamp - new_timestamp) / 1000));
					} else {
						serv_got_im(sa->pc, from, html, PURPLE_MESSAGE_RECV, local_timestamp - ((server_timestamp - new_timestamp) / 1000));
					}
					g_free(html);
					g_free(text);
					
					sa->last_message_timestamp = new_timestamp;
				}
			}
		} else if (g_str_equal(type, "personastate"))
		{
			gint64 personastate = json_object_get_int_member(message, "persona_state");
			const gchar *steamid = json_object_get_string_member(message, "steamid_from");
			purple_prpl_got_user_status(sa->account, steamid, steam_personastate_to_statustype(personastate), NULL);
			serv_got_alias(sa->pc, steamid, json_object_get_string_member(message, "persona_name"));
			
			g_string_append_c(users_to_update, ',');
			g_string_append(users_to_update, steamid);
		} else if (g_str_equal(type, "personarelationship"))
		{
			const gchar *steamid = json_object_get_string_member(message, "steamid_from");
			gint64 persona_state = json_object_get_int_member(message, "persona_state");
			if (persona_state == 0)
				purple_blist_remove_buddy(purple_find_buddy(sa->account, steamid));
			else if (persona_state == 2)
				purple_account_request_authorization(
					sa->account, steamid, NULL,
					NULL, NULL, TRUE,
					steam_auth_accept_cb, steam_auth_reject_cb, purple_buddy_new(sa->account, steamid, NULL));
			else if (persona_state == 3)
				if (!purple_find_buddy(sa->account, steamid))
					purple_blist_add_buddy(purple_buddy_new(sa->account, steamid, NULL), NULL, purple_find_group("Steam"), NULL);
		} else if (g_str_equal(type, "leftconversation"))
		{
			const gchar *steamid = json_object_get_string_member(message, "steamid_from");
			PurpleConversation *conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, steamid, sa->account);
			const gchar *alias = purple_buddy_get_alias(purple_find_buddy(sa->account, steamid));
			gchar *has_left_msg = g_strdup_printf("%s has left the conversation", alias ? alias : "User");
			purple_conversation_write(conv, "", has_left_msg, PURPLE_MESSAGE_SYSTEM, time(NULL));
			g_free(has_left_msg);
		}
	}
	
	if (json_object_has_member(obj, "messagelast"))
		sa->message = MAX(sa->message, (guint) json_object_get_int_member(obj, "messagelast"));
	
	if (json_object_has_member(obj, "error") && g_str_equal(json_object_get_string_member(obj, "error"), "Not Logged On"))
	{
		purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Reconnect needed"));
	}
	
	if (!secure)
	{
		sa->poll_timeout = purple_timeout_add_seconds(1, steam_timeout, sa);
	}
	
	if (users_to_update && users_to_update->len) {
		steam_get_friend_summaries(sa, users_to_update->str);
	}
	g_string_free(users_to_update, TRUE);
			
}

static void
sevencup_check_conversations(SevenCupAccount *sa)
{
	sevencup_post_or_get(sa, 7CUP_METHOD_POST | 7CUP_METHOD_SSL, NULL, "/connect/checkConversations.php", "md5=0", sevencup_conversations_cb, NULL, TRUE);
}

/******************************************************************************/
/* PRPL functions */
/******************************************************************************/

static const char *sevencup_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return "7cup";
}

static gchar *sevencup_status_text(PurpleBuddy *buddy)
{
	SevenCupBuddy *sbuddy = buddy->proto_data;

	if (sbuddy && sbuddy->gameextrainfo)
	{
		if (sbuddy->gameid)
		{
			return g_markup_printf_escaped("In game %s", sbuddy->gameextrainfo);
		} else {
			return g_markup_printf_escaped("In non-Steam game %s", sbuddy->gameextrainfo);
		}
	}

	return NULL;
}

void
steam_tooltip_text(PurpleBuddy *buddy, PurpleNotifyUserInfo *user_info, gboolean full)
{
	SevenCupBuddy *sbuddy = buddy->proto_data;
	
	if (sbuddy)
	{
		purple_notify_user_info_add_pair_html(user_info, "Name", sbuddy->personaname);
		purple_notify_user_info_add_pair_html(user_info, "Real Name", sbuddy->realname);
		if (sbuddy->gameextrainfo)
		{
			gchar *gamename = purple_strdup_withhtml(sbuddy->gameextrainfo);
			if (sbuddy->gameid)
			{
				purple_notify_user_info_add_pair_html(user_info, "In game", gamename);
			} else {
				purple_notify_user_info_add_pair_html(user_info, "In non-Steam game", gamename);
			}
			g_free(gamename);
		}
	}
}

const gchar *
steam_list_emblem(PurpleBuddy *buddy)
{
	SevenCupBuddy *sbuddy = buddy->proto_data;
	
	if (sbuddy)
	{
		
	}
		
	return NULL;
}

GList *
steam_status_types(PurpleAccount *account)
{
	GList *types = NULL;
	PurpleStatusType *status;
	
	status = purple_status_type_new_full(PURPLE_STATUS_AVAILABLE, NULL, "Online", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);
	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, NULL, "Offline", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);
	status = purple_status_type_new_full(PURPLE_STATUS_UNAVAILABLE, NULL, "Busy", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);
	status = purple_status_type_new_full(PURPLE_STATUS_AWAY, NULL, "Away", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);
	status = purple_status_type_new_full(PURPLE_STATUS_EXTENDED_AWAY, NULL, "Snoozing", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);
	
	return types;
}

static void
sevencup_login_cb(SevenCupAccount *sa, JsonObject *obj, gpointer user_data)
{
	if (g_hash_table_lookup(sa->cookie_table, "mauth") == NULL) {
		purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, "Bad username/password");
	} else {
		sevencup_check_conversations(sa);
	}
}

static void
steam_login(PurpleAccount *account)
{
	PurpleConnection *pc = purple_account_get_connection(account);
	SevenCupAccount *sa = g_new0(SevenCupAccount, 1);
	GString *post;
	
	pc->proto_data = sa;
	
	if (!purple_ssl_is_supported()) {
		purple_connection_error (pc,
								PURPLE_CONNECTION_ERROR_NO_SSL_SUPPORT,
								_("Server requires TLS/SSL for login.  No TLS/SSL support found."));
		return;
	}
	
	sa->account = account;
	sa->pc = pc;
	sa->cookie_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	sa->hostname_ip_cache = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	sa->sent_messages_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	sa->waiting_conns = g_queue_new();
	
	purple_connection_set_state(pc, PURPLE_CONNECTING);
	purple_connection_update_progress(pc, _("Connecting"), 1, 3);
	
	post = g_string_new(NULL);
	g_string_append_printf(post, "uName=%s&", purple_url_encode(account->username));
	g_string_append_printf(post, "passwd=%s&", purple_url_encode(account->password));
	g_string_append(post, "save=Login&");
	sevencup_post_or_get(sa, 7CUP_METHOD_POST | 7CUP_METHOD_SSL, NULL, "/login.php", post->str, sevencup_login_cb, NULL, TRUE);
	g_string_free(post, TRUE);
}

static void steam_close(PurpleConnection *pc)
{
	SevenCupAccount *sa;
	GString *post;
	
	g_return_if_fail(pc != NULL);
	g_return_if_fail(pc->proto_data != NULL);
	
	sa = pc->proto_data;
	
	// Go offline on the website
	post = g_string_new(NULL);
	g_string_append_printf(post, "access_token=%s&", purple_url_encode(steam_account_get_access_token(sa)));
	g_string_append_printf(post, "umqid=%s&", purple_url_encode(sa->umqid));
	sevencup_post_or_get(sa, 7CUP_METHOD_POST | 7CUP_METHOD_SSL, NULL, "/ISteamWebUserPresenceOAuth/Logoff/v0001", post->str, NULL, NULL, TRUE);
	g_string_free(post, TRUE);
	
	purple_timeout_remove(sa->poll_timeout);
	purple_timeout_remove(sa->watchdog_timeout);
	
	purple_debug_info("steam", "destroying %d waiting connections\n",
					  g_queue_get_length(sa->waiting_conns));
	
	while (!g_queue_is_empty(sa->waiting_conns))
		steam_connection_destroy(g_queue_pop_tail(sa->waiting_conns));
	g_queue_free(sa->waiting_conns);
	
	purple_debug_info("steam", "destroying %d incomplete connections\n",
			g_slist_length(sa->conns));

	while (sa->conns != NULL)
		steam_connection_destroy(sa->conns->data);

	while (sa->dns_queries != NULL) {
		PurpleDnsQueryData *dns_query = sa->dns_queries->data;
		purple_debug_info("steam", "canceling dns query for %s\n",
					purple_dnsquery_get_host(dns_query));
		sa->dns_queries = g_slist_remove(sa->dns_queries, dns_query);
		purple_dnsquery_destroy(dns_query);
	}
	
	g_hash_table_destroy(sa->sent_messages_hash);
	g_hash_table_destroy(sa->cookie_table);
	g_hash_table_destroy(sa->hostname_ip_cache);
	
	g_free(sa->captcha_gid);
	g_free(sa->captcha_text);
	g_free(sa->twofactorcode);
	
	g_free(sa->cached_access_token);
	g_free(sa->umqid);
	g_free(sa);
}

static unsigned int
steam_send_typing(PurpleConnection *pc, const gchar *name, PurpleTypingState state)
{
	SevenCupAccount *sa = pc->proto_data;
	if (state == PURPLE_TYPING)
	{
		GString *post = g_string_new(NULL);
		
		g_string_append_printf(post, "access_token=%s&", purple_url_encode(steam_account_get_access_token(sa)));
		g_string_append_printf(post, "umqid=%s&", purple_url_encode(sa->umqid));
		g_string_append(post, "type=typing&");
		g_string_append_printf(post, "steamid_dst=%s", name);
		
		sevencup_post_or_get(sa, 7CUP_METHOD_POST | 7CUP_METHOD_SSL, NULL, "/ISteamWebUserPresenceOAuth/Message/v0001", post->str, NULL, NULL, TRUE);
		
		g_string_free(post, TRUE);
	}
	
	return 20;
}

static void
steam_set_status(PurpleAccount *account, PurpleStatus *status)
{
	PurpleConnection *pc = purple_account_get_connection(account);
	SevenCupAccount *sa = pc->proto_data;
	PurpleStatusPrimitive prim = purple_status_type_get_primitive(purple_status_get_type(status));
	guint state_id;
	GString *post = NULL;
	
	switch(prim)
	{
		default:
		case PURPLE_STATUS_OFFLINE:
			state_id = 0;
			break;
		case PURPLE_STATUS_AVAILABLE:
			state_id = 1;
			break;
		case PURPLE_STATUS_UNAVAILABLE:
			state_id = 2;
			break;
		case PURPLE_STATUS_AWAY:
			state_id = 3;
			break;
		case PURPLE_STATUS_EXTENDED_AWAY:
			state_id = 4;
			break;
	}
	
	post = g_string_new(NULL);
	
	g_string_append_printf(post, "access_token=%s&", purple_url_encode(steam_account_get_access_token(sa)));
	g_string_append_printf(post, "umqid=%s&", purple_url_encode(sa->umqid));
	g_string_append(post, "type=personastate&");
	g_string_append_printf(post, "persona_state=%u", state_id);
	
	sevencup_post_or_get(sa, 7CUP_METHOD_POST | 7CUP_METHOD_SSL, NULL, "/ISteamWebUserPresenceOAuth/Message/v0001", post->str, NULL, NULL, TRUE);
	
	g_string_free(post, TRUE);
}

static void
steam_set_idle(PurpleConnection *pc, int time)
{
	SevenCupAccount *sa = pc->proto_data;
	sa->idletime = time;
}

static gint steam_send_im(PurpleConnection *pc, const gchar *who, const gchar *msg,
		PurpleMessageFlags flags)
{
	SevenCupAccount *sa = pc->proto_data;
	GString *post = g_string_new(NULL);
	gchar *stripped;
	
	g_string_append_printf(post, "access_token=%s&", purple_url_encode(steam_account_get_access_token(sa)));
	g_string_append_printf(post, "umqid=%s&", purple_url_encode(sa->umqid));
	
	stripped = purple_unescape_html(msg);
	g_string_append(post, "type=saytext&");
	g_string_append_printf(post, "text=%s&", purple_url_encode(stripped));
	g_string_append_printf(post, "steamid_dst=%s", who);
	
	sevencup_post_or_get(sa, 7CUP_METHOD_POST | 7CUP_METHOD_SSL, NULL, "/ISteamWebUserPresenceOAuth/Message/v0001", post->str, NULL, NULL, TRUE);
	
	g_string_free(post, TRUE);
	g_free(stripped);
	
	return 1;
}

static void steam_buddy_free(PurpleBuddy *buddy)
{
	SevenCupBuddy *sbuddy = buddy->proto_data;
	if (sbuddy != NULL)
	{
		buddy->proto_data = NULL;

		g_free(sbuddy->steamid);
		g_free(sbuddy->personaname);
		g_free(sbuddy->realname);
		g_free(sbuddy->profileurl);
		g_free(sbuddy->avatar);
		g_free(sbuddy->gameid);
		g_free(sbuddy->gameextrainfo);
		g_free(sbuddy->gameserversteamid);
		g_free(sbuddy->lobbysteamid);
		g_free(sbuddy->gameserverip);
		
		g_free(sbuddy);
	}
}

void
steam_fake_group_buddy(PurpleConnection *pc, const char *who, const char *old_group, const char *new_group)
{
	// Do nothing to stop the remove+add behaviour
}
void
steam_fake_group_rename(PurpleConnection *pc, const char *old_name, PurpleGroup *group, GList *moved_buddies)
{
	// Do nothing to stop the remove+add behaviour
}

void
#if PURPLE_VERSION_CHECK(3, 0, 0)
steam_add_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group, const char* message)
#else
steam_add_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group)
#endif
{
	SevenCupAccount *sa = pc->proto_data;
	
	if (g_ascii_strtoull(buddy->name, NULL, 10))
	{
		steam_friend_action(sa, buddy->name, "add");
	} else {
		purple_blist_remove_buddy(buddy);
		purple_notify_warning(pc, "Invalid friend id", "Invalid friend id", "Friend ID's must be numeric.\nTry searching from the account menu.");
	}
}

void
steam_buddy_remove(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group)
{
	SevenCupAccount *sa = pc->proto_data;
	
	steam_friend_action(sa, buddy->name, "remove");
}

/******************************************************************************/
/* Plugin functions */
/******************************************************************************/

static gboolean plugin_load(PurplePlugin *plugin)
{
	purple_debug_info("steam", "Purple core UI name: %s\n", purple_core_get_ui());
	
#ifdef G_OS_UNIX
	core_is_haze = g_str_equal(purple_core_get_ui(), "haze");
	
	if (core_is_haze && gnome_keyring_lib == NULL) {
		purple_debug_info("steam", "UI Core is Telepathy-Haze, attempting to load Gnome-Keyring\n");
		
		gnome_keyring_lib = dlopen("libgnome-keyring.so", RTLD_NOW | RTLD_GLOBAL);
		if (!gnome_keyring_lib) {
			purple_debug_error("steam", "Could not load Gnome-Keyring library.  This plugin requires Gnome-Keyring when used with Telepathy-Haze\n");
			return FALSE;
		}
		
		my_gnome_keyring_store_password = (gnome_keyring_store_password_type) dlsym(gnome_keyring_lib, "gnome_keyring_store_password");
		my_gnome_keyring_delete_password = (gnome_keyring_delete_password_type) dlsym(gnome_keyring_lib, "gnome_keyring_delete_password");
		my_gnome_keyring_find_password = (gnome_keyring_find_password_type) dlsym(gnome_keyring_lib, "gnome_keyring_find_password");
		
		if (!my_gnome_keyring_store_password || !my_gnome_keyring_delete_password || !my_gnome_keyring_find_password) {
			dlclose(gnome_keyring_lib);
			gnome_keyring_lib = NULL;
			purple_debug_error("steam", "Could not load Gnome-Keyring functions.  This plugin requires Gnome-Keyring when used with Telepathy-Haze\n");
			return FALSE;
		}
	}
#endif
	
	return TRUE;
}

static gboolean plugin_unload(PurplePlugin *plugin)
{
#ifdef G_OS_UNIX
	if (gnome_keyring_lib) {
		dlclose(gnome_keyring_lib);
		gnome_keyring_lib = NULL;
	}
#endif
	return TRUE;
}

static GList *steam_actions(PurplePlugin *plugin, gpointer context)
{
	GList *m = NULL;
	PurplePluginAction *act;

	act = purple_plugin_action_new(_("Search for friends..."),
			steam_search_users);
	m = g_list_append(m, act);

	return m;
}

void
steam_blist_launch_game(PurpleBlistNode *node, gpointer data)
{
	PurpleBuddy *buddy;
	SevenCupBuddy *sbuddy;
	PurplePlugin *handle = purple_find_prpl(STEAM_PLUGIN_ID);
	
	if(!PURPLE_BLIST_NODE_IS_BUDDY(node))
		return;
	buddy = (PurpleBuddy *) node;
	if (!buddy)
		return;
	sbuddy = buddy->proto_data;
	if (sbuddy && sbuddy->gameid) 
	{
		gchar *runurl = g_strdup_printf("steam://rungameid/%s", sbuddy->gameid);
		purple_notify_uri(handle, runurl);
		g_free(runurl);
	}
}

void
steam_blist_join_game(PurpleBlistNode *node, gpointer data)
{
	PurpleBuddy *buddy;
	SevenCupBuddy *sbuddy;
	PurplePlugin *handle = purple_find_prpl(STEAM_PLUGIN_ID);
	
	if(!PURPLE_BLIST_NODE_IS_BUDDY(node))
		return;
	buddy = (PurpleBuddy *) node;
	if (!buddy)
		return;
	sbuddy = buddy->proto_data;
	if (sbuddy) {
		if (sbuddy->gameserverip && (!sbuddy->gameserversteamid || !g_str_equal(sbuddy->gameserversteamid, "1"))) 
		{
			gchar *joinurl = g_strdup_printf("steam://connect/%s", sbuddy->gameserverip);
			purple_notify_uri(handle, joinurl);
			g_free(joinurl);
		} else if (sbuddy->lobbysteamid) {
			gchar *joinurl = g_strdup_printf("steam://joinlobby/%s/%s/%s", sbuddy->gameid, sbuddy->lobbysteamid, sbuddy->steamid);
			purple_notify_uri(handle, joinurl);
			g_free(joinurl);
		}
	}
}

void
steam_blist_view_profile(PurpleBlistNode *node, gpointer data)
{
	PurpleBuddy *buddy;
	SevenCupBuddy *sbuddy;
	PurplePlugin *handle = purple_find_prpl(STEAM_PLUGIN_ID);
	
	if(!PURPLE_BLIST_NODE_IS_BUDDY(node))
		return;
	buddy = (PurpleBuddy *) node;
	if (!buddy)
		return;
	sbuddy = buddy->proto_data;
	if (sbuddy && sbuddy->profileurl) {
		purple_notify_uri(handle, sbuddy->profileurl);
	} else {
		gchar *profileurl = g_strdup_printf("http://steamcommunity.com/profiles/%s", buddy->name);
		purple_notify_uri(handle, profileurl);
		g_free(profileurl);
	}
}

static GList *
steam_node_menu(PurpleBlistNode *node)
{
	GList *m = NULL;
	PurpleMenuAction *act;
	PurpleBuddy *buddy;
	SevenCupBuddy *sbuddy;
	
	if(PURPLE_BLIST_NODE_IS_BUDDY(node))
	{
		buddy = (PurpleBuddy *)node;
		
		act = purple_menu_action_new("View online Profile",
				PURPLE_CALLBACK(steam_blist_view_profile),
				NULL, NULL);
		m = g_list_append(m, act);
		
		sbuddy = buddy->proto_data;
		if (sbuddy && sbuddy->gameid)
		{
			act = purple_menu_action_new("Launch Game",
					PURPLE_CALLBACK(steam_blist_launch_game),
					NULL, NULL);
			m = g_list_append(m, act);
			
			if (sbuddy->lobbysteamid || 
				(sbuddy->gameserverip && (!sbuddy->gameserversteamid || !g_str_equal(sbuddy->gameserversteamid, "1")))) 
			{
				act = purple_menu_action_new("Join Game",
						PURPLE_CALLBACK(steam_blist_join_game),
						NULL, NULL);
				m = g_list_append(m, act);
			}
		}
	}
	return m;
}

static void plugin_init(PurplePlugin *plugin)
{
	PurpleAccountOption *option;
	PurplePluginInfo *info = plugin->info;
	PurplePluginProtocolInfo *prpl_info = info->extra_info;

	option = purple_account_option_string_new(
		_("Steam Guard Code"),
		"steam_guard_code", "");
	prpl_info->protocol_options = g_list_append(
		prpl_info->protocol_options, option);

	option = purple_account_option_bool_new(
		_("Always use HTTPS"),
		"always_use_https", FALSE);
	prpl_info->protocol_options = g_list_append(
		prpl_info->protocol_options, option);

	option = purple_account_option_bool_new(
		_("Change status when in-game"),
		"change_status_to_game", FALSE);
	prpl_info->protocol_options = g_list_append(
		prpl_info->protocol_options, option);

}

static PurplePluginProtocolInfo prpl_info = {
#if PURPLE_VERSION_CHECK(3, 0, 0)
	sizeof(PurplePluginProtocolInfo),	/* struct_size */
#endif

	/* options */
	OPT_PROTO_MAIL_CHECK,

	NULL,                   /* user_splits */
	NULL,                   /* protocol_options */
	/* NO_BUDDY_ICONS */    /* icon_spec */
	{"png,jpeg", 0, 0, 64, 64, 0, PURPLE_ICON_SCALE_DISPLAY}, /* icon_spec */
	steam_list_icon,           /* list_icon */
	steam_list_emblem,         /* list_emblems */
	steam_status_text,         /* status_text */
	steam_tooltip_text,        /* tooltip_text */
	steam_status_types,        /* status_types */
	steam_node_menu,           /* blist_node_menu */
	NULL,//steam_chat_info,           /* chat_info */
	NULL,//steam_chat_info_defaults,  /* chat_info_defaults */
	steam_login,               /* login */
	steam_close,               /* close */
	steam_send_im,             /* send_im */
	NULL,                      /* set_info */
	steam_send_typing,         /* send_typing */
	NULL,//steam_get_info,            /* get_info */
	steam_set_status,          /* set_status */
	steam_set_idle,            /* set_idle */
	NULL,                   /* change_passwd */
	steam_add_buddy,           /* add_buddy */
	NULL,                   /* add_buddies */
	steam_buddy_remove,        /* remove_buddy */
	NULL,                   /* remove_buddies */
	NULL,                   /* add_permit */
	NULL,                   /* add_deny */
	NULL,                   /* rem_permit */
	NULL,                   /* rem_deny */
	NULL,                   /* set_permit_deny */
	NULL,//steam_fake_join_chat,      /* join_chat */
	NULL,                   /* reject chat invite */
	NULL,//steam_get_chat_name,       /* get_chat_name */
	NULL,                   /* chat_invite */
	NULL,//steam_chat_fake_leave,     /* chat_leave */
	NULL,                   /* chat_whisper */
	NULL,//steam_chat_send,           /* chat_send */
	NULL,                   /* keepalive */
	NULL,                   /* register_user */
	NULL,                   /* get_cb_info */
#if !PURPLE_VERSION_CHECK(3, 0, 0)
	NULL,                   /* get_cb_away */
#endif
	NULL,                   /* alias_buddy */
	steam_fake_group_buddy,    /* group_buddy */
	steam_fake_group_rename,   /* rename_group */
	steam_buddy_free,          /* buddy_free */
	NULL,//steam_conversation_closed, /* convo_closed */
	purple_normalize_nocase,/* normalize */
	NULL,                   /* set_buddy_icon */
	NULL,//steam_group_remove,        /* remove_group */
	NULL,                   /* get_cb_real_name */
	NULL,                   /* set_chat_topic */
	NULL,                   /* find_blist_chat */
	NULL,                   /* roomlist_get_list */
	NULL,                   /* roomlist_cancel */
	NULL,                   /* roomlist_expand_category */
	NULL,                   /* can_receive_file */
	NULL,                   /* send_file */
	NULL,                   /* new_xfer */
	NULL,                   /* offline_message */
	NULL,                   /* whiteboard_prpl_ops */
	NULL,                   /* send_raw */
	NULL,                   /* roomlist_room_serialize */
	NULL,                   /* unregister_user */
	NULL,                   /* send_attention */
	NULL,                   /* attention_types */
#if (PURPLE_MAJOR_VERSION == 2 && PURPLE_MINOR_VERSION >= 5) || PURPLE_MAJOR_VERSION > 2
#if PURPLE_MAJOR_VERSION == 2 && PURPLE_MINOR_VERSION >= 5
	sizeof(PurplePluginProtocolInfo), /* struct_size */
#endif
	NULL, // steam_get_account_text_table, /* get_account_text_table */
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
#else
	(gpointer) sizeof(PurplePluginProtocolInfo)
#endif
};

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,				/* major_version */
	PURPLE_MINOR_VERSION, 				/* minor version */
	PURPLE_PLUGIN_PROTOCOL, 			/* type */
	NULL, 						/* ui_requirement */
	0, 						/* flags */
	NULL, 						/* dependencies */
	PURPLE_PRIORITY_DEFAULT, 			/* priority */
	STEAM_PLUGIN_ID,				/* id */
	"Steam", 					/* name */
	STEAM_PLUGIN_VERSION, 			/* version */
	N_("Steam Protocol Plugin"), 		/* summary */
	N_("Steam Protocol Plugin"), 		/* description */
	"Eion Robb <eionrobb@gmail.com>", 		/* author */
	"http://pidgin-opensteamworks.googlecode.com/",	/* homepage */
	plugin_load, 					/* load */
	plugin_unload, 					/* unload */
	NULL, 						/* destroy */
	NULL, 						/* ui_info */
	&prpl_info, 					/* extra_info */
	NULL, 						/* prefs_info */
	steam_actions, 					/* actions */

							/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

PURPLE_INIT_PLUGIN(steam, plugin_init, info);
