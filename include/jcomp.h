/*
    JCR - Jabber Component Runtime
    Copyright (C) 2003 Paul Curtis

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

$Id: jcomp.h,v 1.2 2005/12/15 07:48:11 peregrine Exp $

*/

/* A global define for a jcomp component */
#ifndef _JCOMP
#define _JCOMP
#endif

#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>

#include "glib.h"
#include "lib.h"  /* jabberd/jcomp library */

#include "jcomp-compat.h"

#define _JCOMP_NAME	"Jabber Component Runtime"
#define _JCOMP_COPY	"(c) 2003-2004 Paul Curtis"
#define _JCOMP_VERS	"0.2.4"

char *jcr_debug_msg(const char *, const char *, int);
#define JDBG jcr_debug_msg(__FILE__,__FUNCTION__,__LINE__)

/* The JCR instance structure */
typedef struct jcr_instance_struct {

  GAsyncQueue *dqueue;  /* the packet delivery queue */
  GIOChannel    *gio;     /* the base connect/bind channel */
  GMainLoop   *gmain;
  GThread   *dthread;
  guint gmain_watch_source;
  int in_shutdown;	/* A shutdown is in progress */

  char *recv_buffer;	/* buffer for read off the socket */
  int recv_buffer_size;

  xmlnode config; /* The configuration file xmlnode */

  char *spool_dir; /* The spool directory */
  char *pid_file; /* The pid file */

  char *log_dir; /* The log directory */
  FILE *log_stream; /* The log file */

  /* The socket connection to the router/server */
  int fd;

  /* This is the GError bit mask for error logging */
  int message_mask;
  /* == 1,  Forces stderr for all error logging */
  int message_stderr;

  /* These are the base connect/router nodes and parser */
  xmlnode current;
  XML_Parser parser;
  int stream_state;

  /* These are left overs from jabberd 1.4.x  */
  instance jcr_i;

  /* The components packet handler and data */
  phandler handler;
  void *pdata;

  /* The components shutdown handler and data */
  shutdown_func shandler;
  void *sdata;

} _jcr_instance, *jcr_instance;

#define _STREAM_INIT_STATE 0
#define _STREAM_AUTH_SENT  1
#define _STREAM_AUTH_RCVD  2
#define _STREAM_CONNECTED  3
#define _STREAM_ERROR	   4
#define _STREAM_SHUTDOWN   5

jcr_instance jcr;

void log_debug(char *, const char *, ...) G_GNUC_PRINTF(2, 3);
void log_warn(char *, const char *, ...) G_GNUC_PRINTF(2, 3);
void log_error(char *, const char *, ...) G_GNUC_PRINTF(2, 3);
void log_alert(char *, const char *, ...) G_GNUC_PRINTF(2, 3);
void log_notice(char *, const char *, ...) G_GNUC_PRINTF(2, 3);

void jcr_log_handler(const gchar *, GLogLevelFlags, const gchar *, gpointer);
void jcr_log_close(void);
int jcr_socket_connect(void);
void jcr_main_close_stream(void);
void jcr_start_element(void *, const char *, const char **);
void jcr_end_element(void *, const char *);
void jcr_cdata(void *, const char *, int);
gboolean jcr_read_data(GIOChannel *, GIOCondition, gpointer *);
void jcr_send_start_stream(void);
void deliver(dpacket, void *);
void deliver_fail(dpacket, char *);
void jcr_queue_deliver(void *);
int xdb_set(void *, jid, char *, xmlnode);
xmlnode xdb_get(void *, jid, char *);
dpacket dpacket_new(xmlnode);
void register_phandler(void *, int, void *, void *);
void register_shutdown(void *, void *);
void jcr_server_shutdown(int);
void jcr_server_hangup(int);
void jcr_main_new_stream(void);
void jcr_error_data(GIOChannel *, GIOCondition, gpointer *);

void conference(instance i, xmlnode x);
