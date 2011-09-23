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

$Id: jcr_deliver.c,v 1.1 2005/12/06 14:48:49 peregrine Exp $

*/

#include "jcomp.h"

void deliver(dpacket d, void *a) {
  extern jcr_instance jcr;

  if (d == NULL)
    return;

  while (jcr->stream_state != _STREAM_CONNECTED) {
    log_debug(JDBG, "Stream not ready ... waiting to queue pkts");
    sleep(1);
  }

  log_debug(JDBG, "queued %d bytes : >>> %s <<<", strlen(xmlnode2str(d->x)), xmlnode2str(d->x));
  g_async_queue_push(jcr->dqueue, d);
}

void jcr_queue_deliver(void *a) {
  extern jcr_instance jcr;
  GIOStatus rc = G_IO_STATUS_NORMAL;
  GString *buffer;
  gsize bytes;
  int left, len, pkts;
  dpacket d;
  GTimeVal timeout;

  int buf_size = j_atoi(xmlnode_get_data(xmlnode_get_tag(jcr->config,"send-buffer")), 8192);

  log_warn(JDBG, "packet delivery thread starting.");
  buffer = g_string_new(NULL);
  while(TRUE) {

    g_string_set_size(buffer, 0);
    pkts = 0;
    g_get_current_time(&timeout);
    g_time_val_add(&timeout, (5 * G_USEC_PER_SEC));
    d = (dpacket)g_async_queue_timed_pop(jcr->dqueue, &timeout);

    if (d == NULL) {
      if (jcr->stream_state == _STREAM_CONNECTED)
         continue;
      else
         break;
    }

    g_string_append(buffer, xmlnode2str(d->x));
    xmlnode_free(d->x);
    d = NULL;
    left = len = buffer->len;
    pkts++;

    while ((g_async_queue_length(jcr->dqueue) > 0) && (buffer->len < buf_size)) {
      d = (dpacket)g_async_queue_pop(jcr->dqueue);
      g_string_append(buffer, xmlnode2str(d->x));
      xmlnode_free(d->x);
      d = NULL;
      left = len = buffer->len;
      pkts++;
    }

    //   log_debug(JDBG, "%d '%s'", len, buf);

    while ((left > 0) && (rc == G_IO_STATUS_NORMAL)) {
      rc = g_io_channel_write_chars(jcr->gio, (buffer->str+(len - left)), left, &bytes, NULL);
      left = left - bytes;

      if (rc != G_IO_STATUS_NORMAL) {
        log_warn(JDBG, "Send packet failed, dropping packet");
      }

      log_debug(JDBG, "wrote %d packets of %d bytes", pkts, bytes);
      //    fprintf(stderr, "wrote %d packets of %d bytes\n", pkts, bytes);
      if (left==0){
        //queue is empty, flushing the socket
        g_io_channel_flush(jcr->gio, NULL);
      }
    }
  }
  log_warn(JDBG, "packet delivery thread exiting.");
  log_warn(JDBG, "  Last DvryQ Buffer='%.*s'", buffer->len, buffer->str);
  g_string_free(buffer, TRUE);
}

void deliver_fail(dpacket p, char *err) {
  terror t;

  /* normal packet bounce */
  if(j_strcmp(xmlnode_get_attrib(p->x,"type"),"error") == 0) { /* can't bounce an error */
    log_warn(p->host,"dropping a packet to %s from %s: %s",xmlnode_get_attrib(p->x,"to"),xmlnode_get_attrib(p->x,"from"),err);
    pool_free(p->p);
  } else {
    log_warn(p->host,"bouncing a packet to %s from %s: %s",xmlnode_get_attrib(p->x,"to"),xmlnode_get_attrib(p->x,"from"),err);

    /* turn into an error */
    if(err == NULL) {
      jutil_error(p->x,TERROR_EXTERNAL);
    } else {
      t.code = 502;
      strcpy(t.msg,err);
      strcpy(t.condition, "service-unavailable");
      strcpy(t.type, "wait");
      jutil_error(p->x,t);
    }
    deliver(dpacket_new(p->x),NULL);
  }
}
