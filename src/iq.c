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

/* Functions used be both conference.c and conference_room.c to respond to IQ requests */
#include "conference.h"
#include <sys/utsname.h>

/* Take an iq request for version and send the response directly */
void iq_get_version(jpacket jp){
  struct utsname un;
  xmlnode x;
  jutil_iqresult(jp->x);
  xmlnode_put_attrib(xmlnode_insert_tag(jp->x, "query"), "xmlns", NS_VERSION);
  jpacket_reset(jp);

  xmlnode_insert_cdata(xmlnode_insert_tag(jp->iq, "name"), NAME, -1);
  xmlnode_insert_cdata(xmlnode_insert_tag(jp->iq, "version"), VERSION, -1);

  uname(&un);
  x = xmlnode_insert_tag(jp->iq,"os");
  xmlnode_insert_cdata(x, pstrdup(jp->p, un.sysname),-1);
  xmlnode_insert_cdata(x," ",1);
  xmlnode_insert_cdata(x,pstrdup(jp->p, un.release),-1);

  deliver(dpacket_new(jp->x),NULL);
  return;
}

/* send a response to a iq:time request */
void iq_get_time(jpacket jp){
  time_t t;
  char *str;
  jutil_iqresult(jp->x);
  xmlnode_put_attrib(xmlnode_insert_tag(jp->x, "query"), "xmlns", NS_TIME);
  jpacket_reset(jp);
  xmlnode_insert_cdata(xmlnode_insert_tag(jp->iq, "utc"), jutil_timestamp(), -1);
  xmlnode_insert_cdata(xmlnode_insert_tag(jp->iq, "tz"), tzname[0], -1);

  /* create nice display time */
  t = time(NULL);
  str = ctime(&t);

  str[strlen(str) - 1] = '\0'; /* cut off newline */
  xmlnode_insert_cdata(xmlnode_insert_tag(jp->iq, "display"), pstrdup(jp->p, str), -1);

  deliver(dpacket_new(jp->x),NULL);
}

/* Add commons features ns to the item node of a browse reply 
 * Take the item node in argument */
void iq_populate_browse(xmlnode item){
  xmlnode_insert_cdata(xmlnode_insert_tag(item, "ns"), NS_MUC, -1);
  xmlnode_insert_cdata(xmlnode_insert_tag(item, "ns"), NS_DISCO, -1);
  xmlnode_insert_cdata(xmlnode_insert_tag(item, "ns"), NS_BROWSE, -1);
  xmlnode_insert_cdata(xmlnode_insert_tag(item, "ns"), NS_REGISTER, -1);
  xmlnode_insert_cdata(xmlnode_insert_tag(item, "ns"), NS_VERSION, -1);
  xmlnode_insert_cdata(xmlnode_insert_tag(item, "ns"), NS_TIME, -1);
  xmlnode_insert_cdata(xmlnode_insert_tag(item, "ns"), NS_LAST, -1);
  xmlnode_insert_cdata(xmlnode_insert_tag(item, "ns"), NS_VCARD, -1);
}

