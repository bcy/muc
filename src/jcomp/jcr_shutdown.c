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

$Id: jcr_shutdown.c,v 1.2 2005/12/15 07:48:11 peregrine Exp $

*/

#include "jcomp.h"


void jcr_error_data(GIOChannel *src, GIOCondition cond, gpointer *data) {
  extern jcr_instance jcr;

  log_warn(JDBG, "I/O Channel Error");
  g_io_channel_shutdown(jcr->gio, TRUE, NULL);
  g_main_loop_quit(jcr->gmain);

}

void jcr_server_shutdown(int signum) {
  extern jcr_instance jcr;

  if (!(jcr->in_shutdown))
    jcr->in_shutdown = 1;
  else
    return;

  log_warn(JDBG, "Server shutting down");
  if (jcr->shandler != NULL)
    (jcr->shandler)((void *)jcr->sdata);

  jcr->stream_state = _STREAM_SHUTDOWN;
  g_thread_join(jcr->dthread);

  g_io_channel_shutdown(jcr->gio, TRUE, NULL);
  g_main_loop_quit(jcr->gmain);
  pool_free(jcr->jcr_i->p);
  free(jcr->spool_dir);
  free(jcr->log_dir);
  free(jcr->recv_buffer);
  xmlnode_free(jcr->config);
  XML_ParserFree(jcr->parser);

  if (jcr->pid_file)
  {
    unlink(jcr->pid_file);
    free(jcr->pid_file);
  }

  exit(0); 
}

void jcr_server_hangup(int signum) {

  log_warn(JDBG, "server received hangup signal, reopening logs");
  jcr_log_close();
  log_warn(JDBG, "started new log");

  return;
}
