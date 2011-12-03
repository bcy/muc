/*
 * MU-Conference - Multi-User Conference Service
 * Copyright (c) 2002-2005 David Sutton
 *
 *
 * This program is free software; you can redistribute it and/or drvify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307USA
 */

#define _GNU_SOURCE
#include <jabberd.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <time.h>
#include <poll.h>
#include "hash.h"
#include "ns.h"

#include <ccn/ccn.h>
#include <ccn/uri.h>
#include <ccn/bloom.h>
#include <ccn/keystore.h>
#include <ccn/signing.h>
#include <ccn/charbuf.h>

#define NAME			"MU-Conference"
#undef VERSION
#define VERSION 		"0.8"

#define FZONE funcstr(__FILE__,__FUNCTION__,__LINE__)

/* Status code defines */
#define STATUS_MUC_SHOWN_JID	"100"
#define STATUS_MUC_AFFCHANGE	"101"
#define STATUS_MUC_SHOW_MEMBER	"102"
#define STATUS_MUC_HIDE_MEMBER  "103"
#define STATUS_MUC_CONF_CHANGE  "104"
#define STATUS_MUC_HIDDEN_JID	"109"
#define STATUS_MUC_OWN_PRESENCE	"110"
#define STATUS_MUC_LOGGING_ON "170"
#define STATUS_MUC_LOGGING_OFF "171"
#define STATUS_MUC_NON_ANONYM "172"
#define STATUS_MUC_SEMI_ANONYM "173"
#define STATUS_MUC_CREATED	"201"
#define STATUS_MUC_BANNED	"301"
#define STATUS_MUC_NICKCHANGE	"303"
#define STATUS_MUC_KICKED	"307"
#define STATUS_MUC_REM_AFFCHG	"321"
#define STATUS_MUC_REM_NONMEM	"322"
#define STATUS_MUC_REM_SHUTDOWN "332"

/* Error message defines */
#define TERROR_MUC_PASSWORD	(terror){401, "Password required to join this room.", "auth", "not-authorized"}
#define TERROR_MUC_BANNED	(terror){403, "You have been banned from this room.", "auth", "forbidden"}
#define TERROR_MUC_VOICE	(terror){403, "You do not have permission to talk in this room.", "auth", "forbidden"}
#define TERROR_MUC_PRIVMSG	(terror){403, "Private messages are not allowed in this room.", "auth", "forbidden"}
#define TERROR_MUC_ROOM		(terror){403, "Room creation is disabled.", "auth", "forbidden"}
#define TERROR_MUC_CONFIG	(terror){405, "You are disallowed access to room configuration", "cancel", "not-allowed"}
#define TERROR_MUC_OUTSIDE	(terror){405, "You are not in this room", "cancel", "not-allowed"}
#define TERROR_MUC_INVITED	(terror){407, "Invitation required to join this room.", "auth", "registration-required"}
#define TERROR_MUC_FULL		(terror){503, "Room is full.", "wait", "service-unavailable"}
#define TERROR_MUC_NICK		(terror){409, "Please choose a different nickname.", "cancel", "conflict"}
#define TERROR_MUC_NICKREG	(terror){409, "Reserved Nick - Please choose a different nickname.", "cancel", "conflict"}
#define TERROR_MUC_NICKLOCKED	(terror){406, "Nicknames locked: please use your username instead.", "cancel", "conflict"}

#define SEND_ALL		0
#define SEND_LEGACY		1

/* Log Types */
#define LOG_TEXT		0
#define LOG_XML			1
#define LOG_XHTML		2


/* Role List */


typedef struct cnu_struct *cnu, _cnu;
typedef struct cnh_struct *cnh, _cnh;

/* mysql instance */
#ifdef HAVE_MYSQL
#include <mysql/mysql.h>
typedef struct mysql_struct {
  MYSQL* mysql;
  char* host;
  char* user;
  char* pass;
  char* database;
  unsigned int port;
  char* socket;
  unsigned long flag;
  pool p;
} *mysql, _mysql;
#endif


/* conference instance */
typedef struct cni_struct
{
    instance i;
    void *xdbc;
    GHashTable *rooms;		/* Hash of all rooms available */
    GHashTable *extbrowse;	/* Hash of external rooms to report via server browse */
    xmlnode config; 		/* config data, mostly for public right now */
    int public; 		/* if we're public or not */
    int history; 		/* max history items */
    int start; 			/* startup time */
    char *day;			/* To keep track of log rotation information */
    GHashTable *sadmin;		/* Server admin, able to override admin locks */
    char *logdir;		/* Directory where to store logs */
    char *stylesheet;		/* URL of the log stylesheet */
    int loader;			/* Used to delay loading from xdb */
    int roomlock;		/* Stop dynamic room creation */
    int dynamic;		/* If dynamic is -1 then all rooms are persistent.  If dynamic is 0 then implicitly created rooms are temporary and reserved rooms are persistent.  If dynamic is 1 then all rooms are temporary.*/
    int locknicks;		/* All rooms have locked nicknames */
    int hideempty;		/* Empty rooms are not shown on disco/browse */
    int shutdown;		/* Service shutting down */
    GMutex *lock;		/* Used for hasGHashTable *locking */
    GQueue *queue;		/* used to remove zombie rooms  */
    int flatLogs;   /* tell if the logs must be in one dir per room or one dir per day and room */
    int logsEnabled; /* tell if the logs are enabled */
#ifdef HAVE_MYSQL
    mysql sql; /* sql struct */
#endif
} *cni, _cni;

/* conference room */
typedef struct cnr_struct
{
    pool p;
    cni master;			/* Reference to cni struct for service */
    jid id; 			/* room id */
    jid creator;		/* room creator */
    char *name; 		/* friendly name of the room */
    char *description;		/* Short description of the room */
    char *secret; 		/* if there's a secret */
    GHashTable *owner; 		/* Owners of the room */
    GHashTable *remote; 	/* users associated w/ the room, key is remote jid */
    GHashTable *local; 		/* users associated w/ the room, key is local jid */
    GHashTable *roster;		/* room roster, key is bare remote jid */
    GHashTable *admin; 		/* users associated w/ the room, key is remote jid */
    GHashTable *member; 	/* members invited, key is remote jid */
    GHashTable *outcast; 	/* users banned, key is remote jid */
    GHashTable *moderator;	/* users with voice ability, key is local jid */
    GHashTable *participant;	/* users with voice ability, key is local jid */
    int start;			/* Time room was started */
    int created;		/* Time room was created */
    int last; 			/* last time there was any traffic to the room */
    int private; 		/* if private is allowed in this room */
    int public;			/* Is this room publicly searchable */
    int subjectlock;		/* Is changing subject locked to admins? */
    int maxusers;		/* Maximum allowed users, 0 = unlimited */
    int locknicks;		/* Nicknames locked to JID usernames */
    int persistent;		/* Will this room avoid autocleanup */
    int moderated;		/* Is this room moderated */
    int defaulttype;		/* Do users default to members in moderated rooms? */
    int visible;		/* Are real jid's visible to non-admins */
    int invitation;		/* Do users require an invite to enter */
    int invites;		/* Can users send invitations in an invitation-only room */
    int locked;			/* Stops any users connecting - used for create+config (Creation via IQ) */
    int privmsg;		/* Are private messages between users forbidden? */
    int legacy;			/* Are all clients considered legacy? */
    int count; 			/* # of users in the room */
    int hlast; 			/* last history message */
    int packets; 		/* total packets to this room */
    xmlnode topic; 		/* <t i='time(NULL)' from='nick' subject='room subject'>Some Intro Text: room subject</t> */
    cnh *history;               /* an array of history messages (vattrib cnu='') */
    char *note_leave, *note_join, *note_rename; 
    				/* notices */
    FILE *logfile; 		/* for logging of this room */
    int logformat;		/* For log format */
    GQueue *queue;		/* used to remove zombie users  */
    
    GHashTable *presence;	/* bcy: storage of generated presence packets */
    GHashTable *remote_users;	/* bcy: storage of remote users, key is user@server string */

    /* bcy: ccn closures */
    struct ccn_closure *in_interest_message;
    struct ccn_closure *in_content_presence;
    
    GQueue *exclusion_list;	/* bcy: exclusion list for presence interest */
    int local_count;		/* bcy: # of local users in the room */
    int zapping;		/* bcy: to flag room is being zapped */
    int stale;			/* bcy: to flag interest is set stale flag */
    int cleaning;		/* bcy: to flag remote users are being cleaned */
} *cnr, _cnr;

/* conference user */
struct cnu_struct
{
    cnr room;
    pool p;
    jid realid, localid;	/* remote and local jids */
    xmlnode nick; 		/* <n>nickname</n> */
    xmlnode presence; 		/* cached presence */
    int last; 			/* last activity to/from user */
    int private; 		/* private flag */
    int packets; 		/* number of packets from this user */
    int legacy;			/* To denote gc clients */
    int leaving;		/* To flag user is leaving the room */
    
    char *name_prefix;		/* bcy: name prefix */
    int message_seq;		/* bcy: message sequence number */
    int remote;			/* bcy: remote flag */
    char *status;		/* bcy: current status */
    int last_presence;		/* bcy: last presence from user */
    int last_message;		/* bcy: last message from user */
    int last_seq;		/* bcy: last message sequence from user */
    
    /* bcy: ccn closure */
    struct ccn_closure *in_content_message;
};

/* bcy: element struct in exclusion list */
struct exclusion_element
{
    char *name;		/* exclusion name */
    GTimer *timer;	/* exclusion timer, remove element when outdated */
};

/* conference room history */
struct cnh_struct
{
	pool p;
	int content_length;
	int timestamp;
	xmlnode x;
};

/* Roles and Associations */
typedef struct trole_struct
{
    int  code;
    char msg[64];
} trole;

typedef struct taffil_struct
{
    int  code;
    char msg[64];
} taffil;

#define TAFFIL_OWNER		(taffil){3, "owner"}
#define TAFFIL_ADMIN		(taffil){2, "admin"}
#define TAFFIL_MEMBER		(taffil){1, "member"}
#define TAFFIL_NONE		(taffil){0, "none"}
#define TAFFIL_OUTCAST		(taffil){-1, "outcast"}

#define TROLE_MODERATOR		(trole){3, "moderator"}
#define TROLE_PARTICIPANT	(trole){2, "participant"}
#define TROLE_VISITOR		(trole){1, "visitor"}
#define TROLE_NONE		(trole){0, "none"}

/* Functions in conference_room.c */
void con_room_log(cnr room, char *nick, char *message);	/* Log messages */
void con_room_log_new(cnr room);			/* New Log */
void con_room_log_close(cnr room);			/* Close logfile */
void con_room_send_invite(cnu sender, xmlnode node);	/* Send invites */
void con_room_forward_decline(cnr room, jpacket jp, xmlnode decline); /* Forward declines */
cnr con_room_new(cni c, jid roomid, jid owner, char *name, char *secret, int private, int persist, char *name_prefix, int external);
							/* Set up a new room */
void con_room_sendwalk(gpointer key, gpointer data, gpointer arg);
							/* Used to send to all members of a room */
void con_room_leaveall(gpointer key, gpointer data, gpointer arg);
							/* used to send destroyed presence to users */
void con_room_process(cnr room, cnu from, jpacket jp); 	/* process a packet to a room from a participant */
void con_room_outsider(cnr room, cnu from, jpacket jp); /* process a packet to a room from a non-participant */
void con_room_show_config(cnr room, xmlnode msg);	/* Results for iq:negotiate request */
void con_room_send(cnr room, xmlnode x, int legacy);	/* sends a raw packet from="room@host" to all participants */
void con_room_cleanup(cnr room);			/* Clean up room hashes */
void con_room_zap(cnr room); 				/* kills a room */
void con_room_history_clear(cnr room);			/* Wipes a room history */

/* Functions in conference_user.c */
cnu con_user_new(cnr room, jid id, char *name_prefix, int external);	/* new generic user */
void con_user_nick(cnu user, char *nick, xmlnode data); 		/* broadcast nick change */
void con_user_enter(cnu user, char *nick, int created); 		/* put user in room and announce */
void con_user_send(cnu to, cnu from, xmlnode x); 			/* send a packet to a user from other user */
void con_user_zap(cnu user, xmlnode data);				/* clean up the user */
void con_user_process(cnu to, cnu from, jpacket jp); 			/* process packets betweeen users */

/* Functions in utils.c */
xmlnode add_extended_presence(cnu from, cnu to, xmlnode presence, char *status, char *reason, char *actor);
							/* Adds extended presence info to a presence packet */
void add_status_code(xmlnode presence, char *status); /* add a muc status code to a presence stanza */
void add_room_status_codes(xmlnode presence, cnr room); /* add room specific status codes (logging, anonymous, ...) */ 
int is_sadmin(cni master, jid user);			/* Check if user is server admin */
int is_owner(cnr room, jid user);			/* Check if user is room owner */
int is_admin(cnr room, jid user);			/* Check if user is room admin */
int is_member(cnr room, jid user);			/* Check if user is invited to the room */
int is_outcast(cnr room, jid user);			/* Check if user is banned from the room */
int is_moderator(cnr room, jid user);			/* Check if user is room admin */
int is_participant(cnr room, jid user);			/* Check if user has voice  */
int is_visitor(cnr room, jid user);			/* Check if user is a visitor  */
int in_room(cnr room, jid user);			/* Check if user in the room  */
int is_legacy(cnu user);				/* Check if user is using a legacy client */
int is_leaving(cnr room, jid user);			/* Check if user is leaving */
int is_registered(cni master, char *user, char *nick);	/* Check if the nick has been reserved */
void con_send_alert(cnu user, char *text, char *subject, const char *status);
							/* Sends alert message to user */
void con_send_room_status(cnr room, char *status);	/* For sending status messages */
char *funcstr(const char *file, const char *function, int line);	/* Custom log_debug define */
char *itoa(int number, char *result);			/* Reverse of atoi command */
int minuteget(time_t tin);				/* Get current minute */
char *timeget(time_t tin);				/* Get current time */
char *dateget(time_t tin);				/* Get current date */
void update_presence(cnu user);				/* Send presence update for a user */
void insert_item_error(xmlnode node, char *code, char *msg);
							/* Insert error message into item */
int add_roster(cnr room, jid userid);			/* Add full jid to room roster */
int remove_roster(cnr room, jid userid);		/* Remove full jid from room roster */
xmlnode get_roster(cnr room, jid userid);		/* Get all full jids for a user */
char *extractAction(char *origin, pool p);		/* extract action from /me string */
jid jid_fix(jid id);					/* Check and fix case of jids */

/* Functions in xdata.c */
int xdata_handler(cnr room, cnu user, jpacket packet);
void xdata_room_config(cnr room, cnu user, int new, xmlnode query);	
							/* Sends room configuration details */

/* Functions in admin.c */
void con_get_banlist(gpointer key, gpointer data, gpointer arg);
void adm_user_kick(cnu user, cnu target, char *reason);
void con_parse_item(cnu sender, jpacket jp);

/* Functions in roles.c */
taffil affiliation_level(cnr room, jid user);		/* Returns current role level */
trole role_level(cnr room, jid user);			/* Returns current role level */
int add_affiliate(GHashTable *hash, jid userid, xmlnode details);
int remove_affiliate(GHashTable *hash, jid userid);
void revoke_affiliate(cnr room, GHashTable *hash, jid userid);
void change_affiliate(char *role, cnu sender, jid user, char *reason, jid by);
void add_role(GHashTable *hash, cnu user);
void revoke_role(GHashTable *hash, cnu user);
void change_role(char *role, cnu sender, jid user, char *reason);

/* Functions in xdb.c */
int xdb_room_lists_set(cnr room);			/* Save room lists */
void xdb_room_set(cnr room);				/* Set room config to xdb */
void xdb_rooms_get(cni master);				/* Get room config from xdb */
void xdb_room_clear(cnr room);				/* Clear room config from xdb */
int set_data(cni master, char *nick, char *jabberid, xmlnode node, int remove);
							/* Store data */
xmlnode get_data_bynick(cni master, char *nick);	/* Retrieved stored data */
xmlnode get_data_byjid(cni master, char *jabberid);	/* Retrieved stored data */

/* Functions in iq.c */
void iq_get_version(jpacket jp);
void iq_get_time(jpacket jp);
void iq_populate_browse(xmlnode item);

#ifdef HAVE_MYSQL
/* Functions in mysql.c */
mysql sql_mysql_init(cni master, xmlnode config);
int sql_mysql_connect(mysql mysql);
void sql_mysql_close(mysql mysql);deliver(dpacket_new(node), NULL);
void sql_clear_all(mysql sql);
void sql_update_nb_users(mysql sql, cnr room);
void sql_update_field(mysql sql, const char * roomId, const char* field, const char * value);
void sql_update_room_config(mysql sql, cnr room);
void sql_insert_all(mysql sql, GHashTable * rooms);
void sql_insert_room_config(mysql sql, cnr room); 
void sql_insert_lists(mysql sql, GHashTable * rooms);
void sql_add_room_lists(mysql sql, cnr room);
void sql_destroy_room(mysql sql, char * room_jid);
void sql_add_affiliate(mysql sql, cnr room, char * userid, int affil);
void sql_remove_affiliate(mysql sql, cnr room, jid userid);
#endif

/* bcy: ndn_thread struct */
struct ndn_thread
{
  struct ccn *ccn;	// ccn
  GThread *thread;	// thread for running ccn
  int bRunning;		// running flag
};

struct presence
{
  cnu user;
  xmlnode x;
};

/* bcy: upcall functions for incoming interest/content */
enum ccn_upcall_res incoming_content_message(struct ccn_closure *selfp, enum ccn_upcall_kind kind, struct ccn_upcall_info *info);
enum ccn_upcall_res incoming_content_presence(struct ccn_closure *selfp, enum ccn_upcall_kind kind, struct ccn_upcall_info *info);

/* bcy: functions related to ccn operation, defined in ndn.c */
int init_ndn_thread();
int stop_ndn_thread();
int create_presence_interest(cnr room);
int create_message_interest(cnu user, unsigned int seq);
int create_presence_content(cnu user, xmlnode x);
int create_message_content(cnu user, char *data);
void generate_presence_name(char *name, cnu user);