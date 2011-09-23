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

$Id: jcr_elements.c,v 1.2 2005/12/15 07:48:11 peregrine Exp $

*/

#include "jcomp.h"

void jcr_start_element(void *m, const char *name, const char **attrib) {
  extern jcr_instance jcr;
  pool p;
  char hashbuf[41];
  xmlnode cur;

  switch (jcr->stream_state) {

  case _STREAM_INIT_STATE:
    if (strncasecmp(name, "stream:stream", 13) == 0) {
      char *pass = xmlnode_get_data(xmlnode_get_tag(jcr->config,"secret"));
      int i = 0;
      if (attrib == NULL) return;
      while (attrib[i] != '\0') {
        if (strncasecmp(attrib[i], "id", 2) == 0)
          break;
        i += 2;
      }
      p = pool_new();
      //    log_debug(JDBG, "%s = '%s'", attrib[i], attrib[i+1]);
      shahash_r(spools(p, attrib[i + 1], pass, p), hashbuf);

      /* Build a handshake packet */
      cur = xmlnode_new_tag("handshake");
      xmlnode_insert_cdata(cur, hashbuf, -1);

      /* Transmit handshake */
      g_async_queue_push(jcr->dqueue, dpacket_new(cur));
//    deliver(dpacket_new(cur), NULL);
      jcr->stream_state = _STREAM_AUTH_SENT;
      pool_free(p);
      break;
    }

  case _STREAM_CONNECTED:
//  if (strncasecmp(name, "stream:error", 12) == 0) {
//    log_warn(JDBG, "'stream:error' in connected server stream: '%s'", xmlnode2str(jcr->current));
//    jcr_main_close_stream();
//    return;
//  }

    if (jcr->current == NULL) {
      p = pool_heap(5 * 1024); /* Jer's sizing */
      jcr->current = xmlnode_new_tag_pool(p, name);
      //    jcr->current = xmlnode_new_tag(name);
      xmlnode_put_expat_attribs(jcr->current, attrib);

    } else {
      jcr->current = xmlnode_insert_tag(jcr->current, name);
      xmlnode_put_expat_attribs(jcr->current, attrib);
    }

    break;
  }
  return;
}

void jcr_end_element(void *m, const char *name) {
  extern jcr_instance jcr;
  xmlnode parent;
  jid to;
  dpacket d;

  switch (jcr->stream_state) {

  case _STREAM_INIT_STATE:
  case _STREAM_AUTH_SENT:
    if (strncasecmp(name, "handshake", 10) == 0) {
      jcr->stream_state = _STREAM_CONNECTED;
      log_debug(JDBG, "<handshake> received");
    }
    break;
  case _STREAM_CONNECTED:
    if (jcr->current == NULL) {
      log_warn(JDBG, "jcr->current == NULL, closing stream");
      jcr_main_close_stream();
    } else {
      if (strncasecmp(name, "stream:error", 13) == 0) {
        log_warn(JDBG, "'stream:error' on server stream: '%s'", xmlnode2str(jcr->current));
//      jcr_main_close_stream();
        return;
      }

      if (strncasecmp(name, "stream", 7) == 0) {
        log_warn(JDBG, "End of Stream from server: '%s'", xmlnode2str(jcr->current));
        jcr_main_close_stream();
        return;
      }

      if (strncasecmp(name, "stream:stream", 14) == 0) {
        log_warn(JDBG, "End of Stream from server: '%s'", xmlnode2str(jcr->current));
        jcr_main_close_stream();
        return;
      }

      parent = xmlnode_get_parent(jcr->current);
      if (parent == NULL) {
        to = jid_new(jcr->current->p, xmlnode_get_attrib(jcr->current, "to"));
        if (!to || strncasecmp(jcr->jcr_i->id, to->server, strlen(jcr->jcr_i->id)) == 0) {
          d = dpacket_new(jcr->current);
          if (d)
            (jcr->handler)(jcr->jcr_i, d, (void *)jcr->pdata);
          else
            xmlnode_free(jcr->current);
        } else {
          log_debug(JDBG, "Dropping to '%s'",  xmlnode_get_attrib(jcr->current, "to"));
          xmlnode_free(jcr->current);
        }
        jcr->current = NULL;
      } else {
        jcr->current = parent;
      }
    }
    break;
  }
}

void jcr_cdata(void *m, const char *cdata, int len) {
  if (jcr->current != NULL)
    xmlnode_insert_cdata(jcr->current, cdata, len);
}

gboolean jcr_read_data(GIOChannel *src, GIOCondition cond, gpointer *data) {
  gsize bytes_read;
  extern jcr_instance jcr;
  GError *gerr = NULL;
  GIOStatus rc;

  if (cond & G_IO_ERR) {
    log_warn(JDBG, "Main Channel Error: G_IO_ERR");
    return FALSE;
  }

  if (cond & G_IO_HUP) {
    log_warn(JDBG, "Main Channel Error: G_IO_HUP");
    return FALSE;
  }

  if (cond & G_IO_NVAL) {
    log_warn(JDBG, "Main Channel Error: G_IO_NVAL");
    return FALSE;
  }

  if (cond & G_IO_IN) {
    memset(jcr->recv_buffer, 0, jcr->recv_buffer_size);
    bytes_read = 0;
    rc = g_io_channel_read_chars(src, jcr->recv_buffer, (jcr->recv_buffer_size - 1), &bytes_read, &gerr);
    if (rc != G_IO_STATUS_NORMAL) {
      if (gerr != NULL) {
        log_warn(JDBG, "Main Channel Error: rc=%d, %d '%s' '%s'", rc,
          gerr->code, gerr->domain, gerr->message);
        g_error_free(gerr);
      } else {
        log_warn(JDBG, "Main Channel Error: rc=%d", rc);
      }
      jcr_main_close_stream();
      return FALSE;
    }

//  if (bytes_read == 0)
//    jcr_error_data(jcr->gio, G_IO_ERR, NULL);

    if (XML_Parse(jcr->parser, jcr->recv_buffer, bytes_read, 0) == 0) {
      log_warn(JDBG, "XML Parsing Error: '%s'", (char *)XML_ErrorString(XML_GetErrorCode(jcr->parser)));
      log_warn(JDBG, "   Last Rcvd Buffer='%.*s'", bytes_read, jcr->recv_buffer);
      jcr_main_close_stream();
      return FALSE;
    }
  }
  return TRUE;
}
