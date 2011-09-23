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

$Id: jcr_log.c,v 1.1 2005/12/06 14:48:49 peregrine Exp $

*/

#include "jcomp.h"

static GStaticMutex _jcr_log_lock = G_STATIC_MUTEX_INIT;


void jcr_log_handler(const gchar *log_domain, GLogLevelFlags log_level,
                     const gchar *message, gpointer user_data) {
  extern jcr_instance jcr;
  char log_str[512];

  char *pos;
  int sz;
  time_t t;

  /* timestamp */
  t = time(NULL);
  pos = ctime(&t);
  sz = strlen(pos);
  /* chop off the \n */
  pos[sz-1]='\0';

  if (log_level & jcr->message_mask) {
    if (jcr->message_stderr == 1) {
      fprintf(stderr, "%s\n", message);
      fflush(stderr);
    } else {
      if (jcr->log_stream == NULL) {
        snprintf(log_str, 512, "%s/mu-conference.log", jcr->log_dir);
        jcr->log_stream = fopen(log_str, "a+");
      }
      if (jcr->log_stream == NULL) {
        fprintf(stderr, "Unable to open log file %s/mu-conference.log\n",jcr->log_dir);
        return;
      }

      fprintf(jcr->log_stream, "%s %s\n", pos, message);
      fflush(jcr->log_stream);
    }

  }
}

void jcr_log_close(void) {
  extern jcr_instance jcr;

  if (jcr->log_stream != NULL) {
     fclose(jcr->log_stream);
     jcr->log_stream = NULL;
  }

}

void log_alert(char *zone, const char *fmt, ...) {
  va_list ap;
  char logmsg[512] = "";

  g_static_mutex_lock(&_jcr_log_lock);
  va_start(ap, fmt);
  vsnprintf(logmsg, 512, fmt, ap);
  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL, "%s: %s", zone, logmsg);
  va_end(ap);
  g_static_mutex_unlock(&_jcr_log_lock);
}

void log_error(char *zone, const char *fmt, ...) {
  va_list ap;
  char logmsg[512] = "";


  g_static_mutex_lock(&_jcr_log_lock);
  va_start(ap, fmt);
  vsnprintf(logmsg, 512, fmt, ap);
  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_ERROR, "%s: %s", zone, logmsg);
  va_end(ap);
  g_static_mutex_unlock(&_jcr_log_lock);
}

void log_notice(char *zone, const char *fmt, ...) {
  va_list ap;
  char logmsg[512] = "";


  g_static_mutex_lock(&_jcr_log_lock);
  va_start(ap, fmt);
  vsnprintf(logmsg, 512, fmt, ap);
  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE, "%s: %s", zone, logmsg);
  va_end(ap);
  g_static_mutex_unlock(&_jcr_log_lock);
}

void log_warn(char *zone, const char *fmt, ...) {
  va_list ap;
  char logmsg[512] = "";


  g_static_mutex_lock(&_jcr_log_lock);
  va_start(ap, fmt);
  vsnprintf(logmsg, 512, fmt, ap);
  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "%s: %s", zone, logmsg);
  va_end(ap);
  g_static_mutex_unlock(&_jcr_log_lock);
}

void log_debug(char *zone, const char *fmt, ...) {
  va_list ap;
  char logmsg[512] = "";


  g_static_mutex_lock(&_jcr_log_lock);
  va_start(ap, fmt);
  vsnprintf(logmsg, 512, fmt, ap);
  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "%s: %s", zone, logmsg);
  va_end(ap);
  g_static_mutex_unlock(&_jcr_log_lock);
}
