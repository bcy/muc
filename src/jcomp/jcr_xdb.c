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

$Id: jcr_xdb.c,v 1.1 2005/12/06 14:48:49 peregrine Exp $

*/

#include "jcomp.h"

/**
 * A replacement for xdb_set
 * returns 0 if the set succeeded, 1 if not
*/
int xdb_set(void *noop, jid fn, char *ns, xmlnode x) {
  extern jcr_instance jcr;
  char buf[512];
  xmlnode n, s, xdb;
  int rc;

  n = xdb_get(noop, fn, NULL);

  if (n == NULL) {
    memset(buf, 0, 512);
    snprintf(buf, 511, "%s/%s.xml", jcr->spool_dir, fn->user);
    xdb = xmlnode_new_tag("xdb");
    if (ns != NULL)
      xmlnode_put_attrib(x, "xdbns", ns);
//  log_debug(JDBG, "node not found, creating %s", xmlnode2str(x));
    xmlnode_insert_node(xdb, x);
//  log_debug(JDBG, "\nwriting '%s'\n\n", xmlnode2str(xdb));
    rc = xmlnode2file(buf, xdb);
    xmlnode_free(xdb);
    return rc;
  } else {
    s = NULL;
//  log_debug(JDBG, "node found '%s'", xmlnode2str(n));
    if (ns == NULL) {
      s = xmlnode_get_tag(n, xmlnode_get_name(x));
    } else {
      memset(buf, 0, 512);
      snprintf(buf, 511, "%s?xdbns=%s", xmlnode_get_name(x), ns);
//    log_debug(JDBG, "search for '%s'", buf);
      s = xmlnode_get_tag(n, buf);
    }
//  log_debug(JDBG, "removing '%s'", xmlnode2str(s));
    xmlnode_hide(s);
    if (ns != NULL)
      xmlnode_put_attrib(x, "xdbns", ns);
    xmlnode_insert_tag_node(n, x);
  }
  snprintf(buf, 511, "%s/%s.xml", jcr->spool_dir, fn->user);
  rc = xmlnode2file(buf, n);
  xmlnode_free(n);
  log_debug(JDBG, "xdb_set: rc == %d", rc);
  return 0;
}


/**
 * A replacement for xdb_set
 * returns 0 if the set succeeded, 1 if not
*/
xmlnode xdb_get(void *noop, jid fn, char *ns) {
  extern jcr_instance jcr;
  char buf[512];
  xmlnode x, child;

  memset(buf, 0, 512);
  snprintf(buf, 511, "%s/%s.xml", jcr->spool_dir, fn->user);

  x = xmlnode_file(buf);

  if (x == NULL)
    return NULL;

  if (ns != NULL) {
    memset(buf, 0, 512);
    snprintf(buf, 511, "?xdbns=%s", ns);
    child = xmlnode_get_tag(x, buf);
    if (child == NULL)
      xmlnode_free(x);
    return child;
  } else {
    return x;
  }
}
