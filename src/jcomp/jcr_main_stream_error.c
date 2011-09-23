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

$Id: jcr_main_stream_error.c,v 1.1 2005/12/06 14:48:49 peregrine Exp $

*/

#include "jcomp.h"

void jcr_main_new_stream(void) {
 
  jcr->current = NULL;
  if (jcr->parser)
    XML_ParserFree(jcr->parser);
  jcr->fd = -1;

  jcr->stream_state = _STREAM_INIT_STATE;
  jcr->parser = XML_ParserCreate(NULL);
  XML_SetElementHandler(jcr->parser, (void *)jcr_start_element, (void *)jcr_end_element);
  XML_SetCharacterDataHandler(jcr->parser, (void *)jcr_cdata);
  XML_SetUserData(jcr->parser, NULL);

  while (jcr_socket_connect()) {
    sleep(2);
  }

  jcr->gio = g_io_channel_unix_new(jcr->fd);
  g_io_channel_set_encoding(jcr->gio, NULL, NULL);
  g_io_channel_set_buffered(jcr->gio, FALSE);

  jcr->dthread = g_thread_create((void *)jcr_queue_deliver, NULL, TRUE, NULL);

  jcr->gmain_watch_source = g_io_add_watch_full(jcr->gio, G_PRIORITY_HIGH, (G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL), (void *)jcr_read_data, NULL, NULL);
  jcr_send_start_stream();
  log_notice(JDBG, "Server stream connected.");
}

void jcr_main_close_stream(void) {
  extern jcr_instance jcr;

  log_warn(JDBG, "Server stream error, resetting");
  jcr->stream_state = _STREAM_ERROR;
  g_thread_join(jcr->dthread);

  g_source_remove(jcr->gmain_watch_source);
  g_io_channel_shutdown(jcr->gio, TRUE, NULL);
  g_io_channel_unref(jcr->gio);
  g_io_channel_unref(jcr->gio);
  close(jcr->fd);
  

  sleep(2);
  jcr_main_new_stream();
}
