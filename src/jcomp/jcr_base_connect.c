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

$Id: jcr_base_connect.c,v 1.1 2005/12/06 14:48:49 peregrine Exp $

*/

#include "jcomp.h"

int jcr_socket_connect(void) {
  int rc;
  struct sockaddr_in from;
  struct hostent *hp;
  extern jcr_instance jcr;

  char *host = xmlnode_get_data(xmlnode_get_tag(jcr->config,"ip"));
  int port = j_atoi(xmlnode_get_data(xmlnode_get_tag(jcr->config,"port")), 5347);

  log_debug(JDBG, "Attempting connection to %s:%d", host, port);
  memset(&from, 0, sizeof(from));
  from.sin_family = AF_INET;
  from.sin_port = htons(port);

  from.sin_addr.s_addr = inet_addr(host);
  if (from.sin_addr.s_addr == (u_int) - 1) {
    hp = gethostbyname(host);
    if (!hp) {
      log_debug(JDBG, "unknown host \"%s\"\n", host);
      return (1);
    }
    from.sin_family = hp->h_addrtype;
#ifdef _WIN32
    memcpy(&from.sin_addr, hp->h_addr, hp->h_length);
#else
    memcpy((caddr_t) &from.sin_addr, hp->h_addr, hp->h_length);
#endif
  }
  jcr->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (jcr->fd == -1) {
    log_debug(JDBG, "unable to create socket, errno=%d\n",errno);
    return 1;
  }

  rc = connect(jcr->fd, (struct sockaddr *) &from, sizeof(from));

  if (rc < 0) {
    log_debug(JDBG, "connect failed with %d\n", rc);
    close(jcr->fd);
    return(1);
  }

  return 0;
}

void jcr_send_start_stream(void) {
  extern jcr_instance jcr;
  char buf[512];
  char *name = xmlnode_get_data(xmlnode_get_tag(jcr->config,"name"));
  char *host = xmlnode_get_data(xmlnode_get_tag(jcr->config,"host"));
  gsize bytes;
  GError *error = NULL;
  GIOStatus rc;

  memset(buf, 0, 512);
  snprintf(buf, 511, "<?xml version='1.0'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:component:accept' to='%s' from='%s'>\n", name, host);

  rc = g_io_channel_write_chars(jcr->gio, buf, strlen(buf), &bytes, &error);
  if (rc != G_IO_STATUS_NORMAL) {
    log_warn(JDBG, "Opening XML stream failed, rc=%d", rc);
  } else {
    log_debug(JDBG, "Opening XML stream: sent %d bytes", bytes);
  }

}
