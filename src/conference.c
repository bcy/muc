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

#include "conference.h"

void con_server_browsewalk(gpointer key, gpointer data, gpointer arg)
{
  cnr room = (cnr)data;
  jpacket jp = (jpacket)arg;
  char users[10];
  char maxu[10];
  xmlnode x;

  if(room == NULL)
  {
    log_warn(NAME, "[%s] Aborting: NULL room %s", FZONE, (char *) key);
    return;
  }

  /* We can only show the private rooms that the user already knows about */
  if(room->public == 0 && !in_room(room, jp->to) && !is_admin(room, jp->to) && !is_member(room, jp->to))
    return;

  /* Unconfigured rooms don't exist either */
  if(room->locked == 1)
    return;

  /* Hide empty rooms when requested */
  if(room->master->hideempty && room->count < 1)
    return;

  x = xmlnode_insert_tag(jp->iq, "item");

  xmlnode_put_attrib(x, "category", "conference");

  if(room->public == 0)
    xmlnode_put_attrib(x, "type", "private");
  else
    xmlnode_put_attrib(x, "type", "public");

  xmlnode_put_attrib(x, "jid", jid_full(room->id));

  if(room->maxusers > 0)
    xmlnode_put_attrib(x, "name", spools(jp->p, room->name, " (", itoa(room->count, users), "/", itoa(room->maxusers, maxu), ")", jp->p));
  else
    xmlnode_put_attrib(x, "name", spools(jp->p, room->name, " (", itoa(room->count, users), ")", jp->p));

}

void _server_discowalk(gpointer key, gpointer data, gpointer arg)
{
  cnr room = (cnr)data;
  jpacket jp = (jpacket)arg;
  char users[10];
  char maxu[10];
  xmlnode x;

  if(room == NULL)
  {
    log_warn(NAME, "[%s] Aborting: NULL room %s", FZONE, (char *) key);
    return;
  }

  /* if we're a private server, we can only show the rooms the user already knows about */
  if(room->public == 0 && !in_room(room, jp->to) && !is_admin(room, jp->to) && !is_member(room, jp->to))
    return;

  /* Unconfigured rooms don't exist either */
  if(room->locked == 1)
    return;

  /* Hide empty rooms when requested */
  if(room->master->hideempty && room->count < 1)
    return;

  x = xmlnode_insert_tag(jp->iq, "item");

  xmlnode_put_attrib(x, "jid", jid_full(room->id));

  if(room->maxusers > 0)
    xmlnode_put_attrib(x, "name", spools(jp->p, room->name, " (", itoa(room->count, users), "/", itoa(room->maxusers, maxu), ")", jp->p));
  else
    xmlnode_put_attrib(x, "name", spools(jp->p, room->name, " (", itoa(room->count, users), ")", jp->p));
}

char* _generate_unique_id(jid jid) {
  time_t current_time;
  char buffer[150];
  char jid_node[21];//not the full jid, just a part of the node
  char* ret;
  strncpy(jid_node,jid->user,21);
  if (jid_node[20]!='\0') {
    jid_node[20]='\0';
  }
  current_time = time(NULL);
  sprintf(buffer,"%s%i%i",jid_node,(int)current_time,rand());
  ret=malloc((strlen(buffer)+1)*sizeof(char));
  sprintf(ret,"%s",buffer);
  printf("Generating : %s\n",ret);
  return ret;
}


/* Handle packects send directly to the server (jid with no username) */
void con_server(cni master, jpacket jp)
{
  char *str;
  xmlnode x;
  int start, status;
  char *from;
  char nstr[10];
  jid user;

  log_debug(NAME, "[%s] server packet", FZONE);

  if(jp->type == JPACKET_PRESENCE)
  {
    log_debug(NAME, "[%s] Server packet: Presence - Not Implemented", FZONE);
    jutil_error(jp->x, TERROR_NOTIMPL);
    deliver(dpacket_new(jp->x),NULL);
    return;
  }

  if(jp->type != JPACKET_IQ)
  {
    log_debug(NAME, "[%s] Server packet: Dropping non-IQ packet", FZONE);
    xmlnode_free(jp->x);
    return;
  }

  /* Action by subpacket type */
  if(jpacket_subtype(jp) == JPACKET__SET)
  {
    log_debug(NAME, "[%s] Server packet - IQ Set", FZONE);

    if(NSCHECK(jp->iq,NS_REGISTER))
    {
      log_debug(NAME, "[%s] Server packet - Registration Handler", FZONE);
      str = xmlnode_get_tag_data(jp->iq, "name");
      x = xmlnode_get_tag(jp->iq, "remove");

      from = xmlnode_get_attrib(jp->x, "from");

      user = jid_new(jp->p, from);
      status = is_registered(master, jid_full(jid_user(user)), str);

      if(x)
      {
        log_debug(NAME, "[%s] Server packet - UnReg Submission", FZONE);
        set_data(master, str, from, NULL, 1);
        jutil_iqresult(jp->x);
      }
      else if(status == -1)
      {
        log_debug(NAME, "[%s] Server packet - Registration Submission : Already taken", FZONE);
        jutil_error(jp->x, TERROR_MUC_NICKREG);
      }
      else if(status == 0)
      {
        log_debug(NAME, "[%s] Server packet - Registration Submission", FZONE);
        set_data(master, str, from, NULL, 0);
        jutil_iqresult(jp->x);
      }
      else
      {
        log_debug(NAME, "[%s] Server packet - Registration Submission : already set", FZONE);
        jutil_iqresult(jp->x);
      }

      deliver(dpacket_new(jp->x), NULL);
      return;
    }

  }
  else if(jpacket_subtype(jp) == JPACKET__GET)
  {
    /* now we're all set */

    if(NSCHECK(jp->iq,NS_REGISTER))
    {
      log_debug(NAME, "[%s] Server packet - Registration Request", FZONE);

      x = get_data_byjid(master, xmlnode_get_attrib(jp->x, "from"));
      str = xmlnode_get_attrib(x, "nick") ? xmlnode_get_attrib(x, "nick") : "";

      jutil_iqresult(jp->x);
      xmlnode_put_attrib(xmlnode_insert_tag(jp->x, "query"), "xmlns", NS_REGISTER);
      jpacket_reset(jp);

      xmlnode_insert_cdata(xmlnode_insert_tag(jp->iq, "instructions"), "Enter the nickname you wish to reserve for this conference service", -1);
      xmlnode_insert_cdata(xmlnode_insert_tag(jp->iq, "name"), str, -1);
      xmlnode_insert_cdata(xmlnode_insert_tag(jp->iq, "key"), jutil_regkey(NULL, jid_full(jp->to)), -1);

      if(x != NULL) 
        xmlnode_insert_tag(jp->iq, "registered");

      deliver(dpacket_new(jp->x), NULL);
      return;
    }
    else if(NSCHECK(jp->iq,NS_TIME))
    {
      /* Compliant with JEP-0090 */ 

      log_debug(NAME, "[%s] Server packet - Time Request", FZONE);
      
      iq_get_time(jp);
      return;
    }
    else if(NSCHECK(jp->iq,NS_VERSION))
    {
      /* Compliant with JEP-0092 */

      log_debug(NAME, "[%s] Server packet - Version Request", FZONE);
      
      iq_get_version(jp);
      return;
    }
    else if(NSCHECK(jp->iq,NS_BROWSE))
    {
      /* Compliant with JEP-0011 */

      log_debug(NAME, "[%s] Server packet - Browse Request", FZONE);

      jutil_iqresult(jp->x);
      xmlnode_put_attrib(xmlnode_insert_tag(jp->x, "item"), "xmlns", NS_BROWSE);
      jpacket_reset(jp);

      xmlnode_put_attrib(jp->iq, "category", "conference");
      xmlnode_put_attrib(jp->iq, "type", "public");
      xmlnode_put_attrib(jp->iq, "jid", master->i->id);

      /* pull name from the server vCard */
      xmlnode_put_attrib(jp->iq, "name", xmlnode_get_tag_data(master->config, "vCard/FN"));
      iq_populate_browse(jp->iq);

      /* Walk room hashtable and report available rooms */
      g_hash_table_foreach(master->rooms, con_server_browsewalk, (void*)jp);

      deliver(dpacket_new(jp->x), NULL);
      return;
    }
    else if(NSCHECK(jp->iq, NS_DISCO_INFO))
    {
      log_debug(NAME, "[%s] Server packet - Disco Info Request", FZONE);
      if (xmlnode_get_attrib(jp->iq,"node")!= NULL){
        jutil_error(jp->x, TERROR_UNAVAIL);
        deliver(dpacket_new(jp->x),NULL);
        return;
      }

      jutil_iqresult(jp->x);
      xmlnode_put_attrib(xmlnode_insert_tag(jp->x,"query"), "xmlns", NS_DISCO_INFO);
      jpacket_reset(jp);

      x = xmlnode_insert_tag(jp->iq,"identity");
      xmlnode_put_attrib(x, "category", "conference");
      xmlnode_put_attrib(x, "type", "text");
      xmlnode_put_attrib(x, "name", xmlnode_get_tag_data(master->config, "vCard/FN"));

      xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", NS_MUC);
      xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", NS_MUC_UNIQUE);
      xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", NS_DISCO);
      xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", NS_BROWSE);
      xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", NS_REGISTER);
      xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", NS_VERSION);
      xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", NS_TIME);
      xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", NS_LAST);
      xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", NS_VCARD);
      xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", NS_PING);

      deliver(dpacket_new(jp->x),NULL);
      return;
    }
    else if(NSCHECK(jp->iq, NS_DISCO_ITEMS))
    { 
      log_debug(NAME, "[%s] Server packet - Disco Items Request", FZONE);
      
      if (xmlnode_get_attrib(jp->iq,"node")!= NULL){
        jutil_error(jp->x, TERROR_UNAVAIL);
        deliver(dpacket_new(jp->x),NULL);
        return;
      }

      jutil_iqresult(jp->x);
      xmlnode_put_attrib(xmlnode_insert_tag(jp->x,"query"),"xmlns", NS_DISCO_ITEMS);
      jpacket_reset(jp);

      g_hash_table_foreach(master->rooms,_server_discowalk, (void*)jp);

      deliver(dpacket_new(jp->x),NULL);
      return;
    }
    else if(NSCHECK(jp->iq, NS_LAST))
    {
      log_debug(NAME, "[%s] Server packet - Last Request", FZONE);

      jutil_iqresult(jp->x);
      xmlnode_put_attrib(xmlnode_insert_tag(jp->x,"query"),"xmlns",NS_LAST);
      jpacket_reset(jp);

      start = time(NULL) - master->start;
      sprintf(nstr,"%d",start);
      xmlnode_put_attrib(jp->iq,"seconds", pstrdup(jp->p, nstr));

      deliver(dpacket_new(jp->x),NULL);
      return;
    }
    else if(NSCHECK(jp->iq,NS_VCARD))
    { 
      log_debug(NAME, "[%s] Server packet - VCard Request", FZONE);

      jutil_iqresult(jp->x);
      xmlnode_put_attrib(xmlnode_insert_tag(jp->x,"vCard"),"xmlns",NS_VCARD);
      jpacket_reset(jp);

      xmlnode_insert_node(jp->iq,xmlnode_get_firstchild(xmlnode_get_tag(master->config,"vCard")));

      deliver(dpacket_new(jp->x),NULL);
      return;
    }
    else if(NSCHECK(jp->iq,NS_MUC_UNIQUE)) 
    {
      //generate a unique identifier and send it back
      log_debug(NAME, "[%s] Server packet - Unique Request", FZONE);
      str=_generate_unique_id(jp->from);
      jutil_iqresult(jp->x);
      xmlnode_put_attrib(xmlnode_insert_tag(jp->x,"unique"),"xmlns",NS_MUC_UNIQUE);
      jpacket_reset(jp);

      xmlnode_insert_cdata(jp->iq,str,strlen(str));
      free(str);
      deliver(dpacket_new(jp->x),NULL);
      return;
    }
    else if(NSCHECK(jp->iq,NS_PING)) 
    {
      log_debug(NAME, "[%s] Server packet - Ping", FZONE);
      jutil_iqresult(jp->x);
      deliver(dpacket_new(jp->x),NULL);
      return;
    }

  }

  //if we're here, it's because we don't know this packet
  log_debug(NAME, "[%s] TERROR_NOTIMPL", FZONE);
  jutil_error(jp->x, TERROR_NOTIMPL);
  deliver(dpacket_new(jp->x),NULL);

  return;
}


void _con_packets(void *arg)
{
  jpacket jp = (jpacket)arg;
  cni master = (cni)jp->aux1;
  cnr room;
  cnu u, u2;
  char *s, *reason;
  xmlnode node;
  int priority = -1;
  int created = 0;
  time_t now = time(NULL);

  if((jid_fix(jp->from) == NULL) || (jid_fix(jp->to) == NULL))
  {
    log_debug(NAME, "[%s] ignoring packets, invalid to or from", FZONE);
    return;
  }



  g_mutex_lock(master->lock);

  /* first, handle all packets just to the server (browse, vcard, ping, etc) */
  if(jp->to->user == NULL)
  {
    con_server(master, jp);
    g_mutex_unlock(master->lock);
    return;
  }

  log_debug(NAME, "[%s] processing packet %s", FZONE, xmlnode2str(jp->x));

  /* any other packets must have an associated room */
  for(s = jp->to->user; *s != '\0'; s++) 
    *s = tolower(*s); /* lowercase the group name */

  if((room = g_hash_table_lookup(master->rooms, jid_full(jid_user(jid_fix(jp->to))))) == NULL)
  {
    log_debug(NAME, "[%s] Room not found (%s)", FZONE, jid_full(jid_user(jp->to)));

    if((master->roomlock == 1 && !is_sadmin(master, jp->from)) || master->loader == 0)
    {
      log_debug(NAME, "[%s] Room building request denied", FZONE);
      jutil_error(jp->x, TERROR_MUC_ROOM);

      g_mutex_unlock(master->lock);
      deliver(dpacket_new(jp->x),NULL);
      return;
    }
    else if(jp->type == JPACKET_IQ && jpacket_subtype(jp) == JPACKET__GET && NSCHECK(jp->iq, NS_MUC_OWNER))
    {
      room = con_room_new(master, jid_user(jp->to), jp->from, NULL, NULL, 1, 0);

      xdata_room_config(room,g_hash_table_lookup(room->remote, jid_full(jid_fix(jp->from))),1,jp->x);

      g_mutex_unlock(master->lock);
      xmlnode_free(jp->x);
      return;
    }
    else if(jp->type == JPACKET_IQ && jpacket_subtype(jp) == JPACKET__SET && NSCHECK(jp->iq, NS_MUC_OWNER) && xmlnode_get_tag(jp->iq,"x?xmlns=jabber:x:data"))
    {
      //create instant room
      room = con_room_new(master, jid_user(jp->to), jp->from, NULL, NULL, 1, 0);
      //instant room are always non browsable
      room->public=0;
     
      jutil_iqresult(jp->x);
      deliver(dpacket_new(jp->x),NULL);
      g_mutex_unlock(master->lock);
      return;
    }
    else if(jp->to->resource == NULL)
    {
      log_debug(NAME, "[%s] Room %s doesn't exist: Returning Bad Request", FZONE, jp->to->user);
      jutil_error(jp->x, TERROR_BAD);
      g_mutex_unlock(master->lock);
      deliver(dpacket_new(jp->x),NULL);
      return;
    }
    else if(jpacket_subtype(jp) == JPACKET__UNAVAILABLE)
    {
      log_debug(NAME, "[%s] Room %s doesn't exist: dropping unavailable presence", FZONE, jp->to->user);
      g_mutex_unlock(master->lock);
      xmlnode_free(jp->x);
      return;
    }
    else
    {
      if(master->dynamic == -1)
        room = con_room_new(master, jid_user(jp->to), jp->from, NULL, NULL, 1, 1);
      else
        room = con_room_new(master, jid_user(jp->to), jp->from, NULL, NULL, 1, 0);

      /* fall through, so the presence goes to the room like normal */
      created = 1;
    }
  }

  /* get the sending user entry, if any */
  log_debug(NAME, "[%s] %s", FZONE, jid_full(jid_fix(jp->from)));
  u = g_hash_table_lookup(room->remote, jid_full(jid_fix(jp->from)));

  /* handle errors */
  if(jpacket_subtype(jp) == JPACKET__ERROR)
  {
    log_debug(NAME, "[%s] Error Handler: init", FZONE);

    /* only allow iq errors that are to a resource (direct-chat) */
    if(jp->to->resource == NULL || jp->type != JPACKET_IQ)
    {
      if(u != NULL && u->localid != NULL)
      {
        /* allow errors if they aren't delivery related errors */
        node = xmlnode_get_tag(jp->x, "error");
        for((node != NULL) && (node = xmlnode_get_firstchild(node)); node != NULL; node = xmlnode_get_nextsibling(node)) {
          if(!NSCHECK(node, NS_STANZA))
            continue;
          s = xmlnode_get_name(node);
          if ((j_strcmp(s, "gone") == 0) || (j_strcmp(s, "item-not-found") == 0) || (j_strcmp(s, "recipient-unavailable") == 0) || (j_strcmp(s, "redirect") == 0) || (j_strcmp(s, "remote-server-not-found") == 0) || (j_strcmp(s, "remote-server-timeout") == 0) || (j_strcmp(s, "service-unavailable")) || (j_strcmp(s, "jid-malformed")))
          {
            log_debug(NAME, "[%s] Error Handler: Zapping user", FZONE);
            node = xmlnode_new_tag("reason");
            xmlnode_insert_cdata(node, "Lost connection", -1);

            con_user_zap(u, node);

            xmlnode_free(jp->x);
            g_mutex_unlock(master->lock);
            return;
          }
        }
      }
      else
      {
        log_debug(NAME, "[%s] Error Handler: No cnu/lid found for user", FZONE);

        xmlnode_free(jp->x);
        g_mutex_unlock(master->lock);
        return;
      }
    }

  }

  /* Block message from users not already in the room */
  if(jp->type == JPACKET_MESSAGE && u == NULL)
  {
    //check if this is a decline to an invitation
    if (( node = xmlnode_get_tag(xmlnode_get_tag(jp->x,"x?xmlns=http://jabber.org/protocol/muc#user"),"decline")) != NULL);
    if (node!=NULL)
    {
      con_room_forward_decline(room,jp,node);
      g_mutex_unlock(master->lock);
      return;
    }

    log_debug(NAME, "[%s] Blocking message from outsider (%s)", FZONE, jid_full(jp->to));

    jutil_error(jp->x, TERROR_MUC_OUTSIDE);
    g_mutex_unlock(master->lock);
    deliver(dpacket_new(jp->x),NULL);
    return;
  }

  /* several things use this field below as a flag */
  if(jp->type == JPACKET_PRESENCE) {
    if(jpacket_subtype(jp) == JPACKET__INVISIBLE) {
      xmlnode_hide_attrib(jp->x, "type");
    }

    priority = jutil_priority(jp->x);
  }

  /* sending available presence will automatically get you a generic user, if you don't have one */
  if(u == NULL && priority >= 0)
    u = con_user_new(room, jp->from);

  /* update tracking stuff */
  room->last = now;
  room->packets++;

  if(u != NULL)
  {
    u->last = now;
    u->packets++;
  }

  /* handle join/rename */
  if(priority >= 0 && jp->to->resource != NULL)
  {
    u2 = g_hash_table_lookup(room->local, jp->to->resource); /* existing user w/ this nick? */

    /* it's just us updating our presence */
    if(u2 == u)
    {
      jp->to = jid_user(jp->to);
      xmlnode_put_attrib(jp->x, "to", jid_full(jp->to));

      if(u)
      {
        xmlnode_free(u->presence);
        u->presence = xmlnode_dup(jp->x);
      }

      con_room_process(room, u, jp);
      g_mutex_unlock(master->lock);
      return;
    }

    /* Don't allow user if locknicks is set and resource != JID user */
    if ( ((master->locknicks || room->locknicks) && (j_strcmp(jp->to->resource, jp->from->user) != 0)) && !is_sadmin(master, jp->from) ) {
      log_debug(NAME, "[%s] Nicknames locked - Requested nick %s doesn't match required username %s",
          FZONE, jp->to->resource, jp->from->user);

      /* Send a nickname refused error message */
      jutil_error(jp->x, TERROR_MUC_NICKLOCKED);
      g_mutex_unlock(master->lock);
      deliver(dpacket_new(jp->x),NULL);
      return;
    }

    /* User already exists, return conflict Error */
    if(u2 != NULL)
    {
      log_debug(NAME, "[%s] Nick Conflict (%s)", FZONE, jid_full(jid_user(jp->to)));

      jutil_error(jp->x, TERROR_MUC_NICK);
      g_mutex_unlock(master->lock);
      deliver(dpacket_new(jp->x),NULL);
      return;
    }

    /* Nick already registered, return conflict Error */
    if(is_registered(master, jid_full(jid_user(u->realid)), jp->to->resource) == -1)
    {
      log_debug(NAME, "[%s] Nick Conflict with registered nick (%s)", FZONE, jid_full(jid_fix(jp->to)));

      jutil_error(jp->x, TERROR_MUC_NICKREG);
      g_mutex_unlock(master->lock);
      deliver(dpacket_new(jp->x),NULL);
      return;
    }

    if(is_outcast(room, u->realid) && !is_admin(room, u->realid))
    {
      log_debug(NAME, "[%s] Blocking Banned user (%s)", FZONE, jid_full(jid_user(jid_fix(jp->to))));

      jutil_error(jp->x, TERROR_MUC_BANNED);
      g_mutex_unlock(master->lock);
      deliver(dpacket_new(jp->x),NULL);
      return;
    }

    /* User is not invited, return invitation error */
    if(room->invitation == 1 && !is_member(room, u->realid) && !is_owner(room, u->realid))
    {
      jutil_error(jp->x, TERROR_MUC_INVITED);
      g_mutex_unlock(master->lock);
      deliver(dpacket_new(jp->x),NULL);
      return;
    }

    /* Room is full, return full room error */
    if(room->count >= room->maxusers && room->maxusers != 0 && !is_admin(room, u->realid))
    {
      log_debug(NAME, "[%s] Room over quota - disallowing entry", FZONE);

      jutil_error(jp->x, TERROR_MUC_FULL);
      g_mutex_unlock(master->lock);
      deliver(dpacket_new(jp->x),NULL);
      return;
    }

    /* Room has been locked against entry */
    if(room->locked && !is_owner(room, u->realid))
    {
      log_debug(NAME, "[%s] Room has been locked", FZONE);

      jutil_error(jp->x, TERROR_NOTFOUND);
      g_mutex_unlock(master->lock);
      deliver(dpacket_new(jp->x),NULL);
      return;
    }

    /* User already in room, simply a nick change */
    if(u->localid != NULL)
    {
      g_hash_table_remove(u->room->local, u->localid->resource);
      jid_set(u->localid, jp->to->resource, JID_RESOURCE);
      g_hash_table_insert(u->room->local, u->localid->resource, u);
      xmlnode_free(u->presence);
      u->presence = xmlnode_dup(jp->x);
      con_user_nick(u, jp->to->resource, NULL); /* broadcast nick rename */
      xmlnode_free(jp->x);
      g_mutex_unlock(master->lock);
      return;

    }
    else if(room->secret == NULL || is_sadmin(master, jp->from)) /* No password required, just go right in, or you're an sadmin */
    {

      //the client is legacy unless we're told otherwise
      u->legacy = 1;
      for( node = xmlnode_get_firstchild(jp->x); node != NULL; node = xmlnode_get_nextsibling(node)) {
        if (xmlnode_get_name(node)==NULL || strcmp("x",xmlnode_get_name(node))!=0) continue; // check if the node is a "x" node

        if(NSCHECK(node, NS_MUC))
        {
          /* Set legacy value to room value */
          u->legacy = 0;
          //	xmlnode_hide(node);

          /* Enable room defaults automatically */ 
          if(master->roomlock == -1)
          {
            created = 0;
          }

        }
      }
      if (u->legacy == 1) {
        created = 0; //override created flag for non MUC compliant clients
      }
      xmlnode_free(u->presence);
      u->presence = xmlnode_dup(jp->x);
      jutil_delay(u->presence, NULL);

      log_debug(NAME, "[%s] About to enter room, legacy<%d>, presence [%s]", FZONE, u->legacy, xmlnode2str(u->presence));
      con_user_enter(u, jp->to->resource, created); /* join the room */

      xmlnode_free(jp->x);
      g_mutex_unlock(master->lock);
      return;

    }
    else if(jp->type == JPACKET_PRESENCE) /* Hopefully you are including a password, this room is locked */
    {
      for( node = xmlnode_get_firstchild(jp->x); node != NULL; node = xmlnode_get_nextsibling(node)) {
        if (xmlnode_get_name(node)==NULL || strcmp("x",xmlnode_get_name(node))!=0) continue; // check if the node is a "x" node

        if(NSCHECK(node, NS_MUC))
        {
          log_debug(NAME, "[%s] Password?", FZONE);
          if(j_strcmp(room->secret, xmlnode_get_tag_data(node, "password")) == 0)
          {
            /* Set legacy value to room value */
            u->legacy = 0;
            node = xmlnode_get_tag(jp->x,"x");
            xmlnode_hide(node);

            xmlnode_free(u->presence);
            u->presence = xmlnode_dup(jp->x);

            jutil_delay(u->presence, NULL);
            con_user_enter(u, jp->to->resource, created); /* join the room */

            xmlnode_free(jp->x);
            g_mutex_unlock(master->lock);
            return;
          }
        }
      }
    }

    /* No password found, room is password protected. Return password error */
    jutil_error(jp->x, TERROR_MUC_PASSWORD);
    deliver(dpacket_new(jp->x), NULL);
    g_mutex_unlock(master->lock);
    return;
  }

  /* kill any user sending unavailable presence */
  if(jpacket_subtype(jp) == JPACKET__UNAVAILABLE)
  {
    log_debug(NAME, "[%s] Calling user zap", FZONE);

    if(u != NULL) 
    {
      reason = xmlnode_get_tag_data(jp->x, "status");

      xmlnode_free(u->presence);
      u->presence = xmlnode_dup(jp->x);

      node = xmlnode_new_tag("reason");
      if (reason)
        xmlnode_insert_cdata(node, reason, -1);

      con_user_zap(u, node);
    }

    xmlnode_free(jp->x);
    g_mutex_unlock(master->lock);
    return;
  }

  /* not in the room yet? foo */
  if(u == NULL || u->localid == NULL)
  {
    if(u == NULL)
    {
      log_debug(NAME, "[%s] No cnu found for user", FZONE);
    }
    else
    {
      log_debug(NAME, "[%s] No lid found for %s", FZONE, jid_full(u->realid));
    }

    if(jp->to->resource != NULL)
    {
      jutil_error(jp->x, TERROR_NOTFOUND);
      deliver(dpacket_new(jp->x),NULL);
    }
    else
    {
      con_room_outsider(room, u, jp); /* non-participants get special treatment */
    }

    g_mutex_unlock(master->lock);
    return;
  }

  /* packets to a specific resource?  one on one chats, browse lookups, etc */
  if(jp->to->resource != NULL)
  {
    if((u2 = g_hash_table_lookup(room->local, jp->to->resource)) == NULL) /* gotta have a recipient */
    {
      jutil_error(jp->x, TERROR_NOTFOUND);
      deliver(dpacket_new(jp->x),NULL);
    }
    else
    {
      con_user_process(u2, u, jp);
    }

    g_mutex_unlock(master->lock);
    return;
  }

  /* finally, handle packets just to a room from a participant, msgs, pres, iq browse/conferencing, etc */
  con_room_process(room, u, jp);

  g_mutex_unlock(master->lock);

}

/* phandler callback, send packets to another server */
result con_packets(instance i, dpacket dp, void *arg)
{
  cni master = (cni)arg;
  jpacket jp;

  if(dp == NULL)
  {
    log_warn(NAME, "[%s] Err: Sent a NULL dpacket!", FZONE);
    return r_DONE;
  }

  /* routes are from dnsrv w/ the needed ip */
  if(dp->type == p_ROUTE)
  {
    log_debug(NAME, "[%s] Rejecting ROUTE packet", FZONE);
    deliver_fail(dp,"Illegal Packet");
    return r_DONE;
  }
  jp = jpacket_new(dp->x);

  /* if the delivery failed */
  if(jp == NULL || jp->to == NULL || jp->from == NULL)
  {
    log_warn(NAME, "[%s] Rejecting Illegal Packet", FZONE);
    deliver_fail(dp,"Illegal Packet");
    return r_DONE;
  }

  /* bad packet??? ick */
  if(jp->type == JPACKET_UNKNOWN || jp->to == NULL)
  {
    log_warn(NAME, "[%s] Bouncing Bad Packet", FZONE);
    jutil_error(jp->x, TERROR_BAD);
    deliver(dpacket_new(jp->x),NULL);
    return r_DONE;
  }

  /* we want things processed in order, and don't like re-entrancy! */
  jp->aux1 = (void*)master;
  _con_packets((void *)jp);

  return r_DONE;
}

/** Save and clean out every room on shutdown */
void _con_shutdown_rooms(gpointer key, gpointer data, gpointer arg)
{
  cnr room = (cnr)data;
  xmlnode destroy;

  if(room == NULL)
  {
    log_warn(NAME, "[%s] SHUTDOWN: Aborting attempt to clear %s", FZONE, (char *) key);
    return;
  }

  if(room->persistent == 1)
    xdb_room_set(room);

  destroy=xmlnode_new_tag("destroy");
  xmlnode_insert_cdata(xmlnode_insert_tag(destroy,"reason"),"The conference component is shutting down",-1);
  g_hash_table_foreach(room->remote, con_room_leaveall, destroy);
  xmlnode_free(destroy);

  con_room_cleanup(room);
}

/** Called to clean up system on shutdown */
void con_shutdown(void *arg)
{
  cni master = (cni)arg;

  if(master->shutdown == 1)
  {
    log_debug(NAME, "[%s] SHUTDOWN: Already commencing. Aborting attempt", FZONE);
    return;
  }
  else
  {
    master->shutdown = 1;
  }

  log_debug(NAME, "[%s] SHUTDOWN: Clearing configuration", FZONE);
  xmlnode_free(master->config);

  log_debug(NAME, "[%s] SHUTDOWN: Zapping sadmin table", FZONE);
  g_hash_table_destroy(master->sadmin);

  log_debug(NAME, "[%s] SHUTDOWN: Clear users from rooms", FZONE);
  g_hash_table_foreach(master->rooms, _con_shutdown_rooms, NULL);

  log_debug(NAME, "[%s] SHUTDOWN: Zapping rooms", FZONE);
  g_hash_table_destroy(master->rooms);

  free(master->day);

  g_mutex_free(master->lock);

#ifdef HAVE_MYSQL
  if (master->sql != NULL)
  {
    sql_clear_all(master->sql);
    sql_mysql_close(master->sql);
  }
#endif

  log_debug(NAME, "[%s] SHUTDOWN: Sequence completed", FZONE);
}

/** Function called for walking each user in a room */
void _con_beat_user(gpointer key, gpointer data, gpointer arg)
{
  cnu user = (cnu)data;
  time_t t = *(time_t *)arg;

  if(user == NULL)
  {
    log_warn(NAME, "[%s] Aborting : NULL cnu for %s", FZONE, (char *) key);
    return;
  }

  if(user->localid == NULL && (t - user->last) > 120)
  {
    log_debug(NAME, "[%s] Marking zombie", FZONE);

    g_queue_push_tail(user->room->queue, g_strdup(jid_full(user->realid)));
  }
}

/* callback for walking each room */
void _con_beat_idle(gpointer key, gpointer data, gpointer arg)
{
  cnr room = (cnr)data;
  time_t t = *(time_t *)arg;
  xmlnode node;
  char *user_name;

  log_debug(NAME, "[%s] HBTICK: Idle check for >%s<", FZONE, (char*) key);

  if(room == NULL)
  {
    log_warn(NAME, "[%s] Aborting : NULL cnr for %s", FZONE, (char*) key);
    return;
  }

  /* Perform zombie user clearout */
  room->queue = g_queue_new();
  g_hash_table_foreach(room->remote, _con_beat_user, &t); /* makes sure nothing stale is in the room */

  while ((user_name = (char *)g_queue_pop_head(room->queue)) != NULL) 
  {
    node = xmlnode_new_tag("reason");
    xmlnode_insert_cdata(node, "Clearing zombie", -1);

    con_user_zap(g_hash_table_lookup(room->remote, user_name), node);

    log_debug(NAME, "[%s] HBTICK: removed zombie '%s' in the queue", FZONE, user_name);
    g_free(user_name);
  }
  g_queue_free(room->queue);

  /* Destroy timed-out dynamic room */
  if(room->persistent == 0 && room->count == 0 && (t - room->last) > 240)
  {
    log_debug(NAME, "[%s] HBTICK: Locking room and adding %s to remove queue", FZONE, (char*) key);
    room->locked = 1;
    g_queue_push_tail(room->master->queue, g_strdup(jid_full(room->id)));
  }
}

/* heartbeat checker for timed out idle rooms */
void _con_beat_logrotate(gpointer key, gpointer data, gpointer arg)
{
  cnr room = (cnr)data;

  if(room == NULL)
  {
    log_warn(NAME, "[%s] Aborting : NULL cnr for %s", FZONE, (char*) key);
    return;
  }

  if(room->logfile)
  {
    log_debug(NAME, "[%s] Rotating log for room %s", FZONE, jid_full(room->id));

    con_room_log_close(room);
    con_room_log_new(room);
  }
}

/* heartbeat checker for maintainance */
result con_beat_update(void *arg)
{
  cni master = (cni)arg;
  time_t t = time(NULL);
  int mins = minuteget(t);
  char *tstamp = timeget(t);
  char *dstamp = dateget(t);
  char *room_name;

  log_debug(NAME, "[%s] HBTICK", FZONE);

  /* Clean the jid cache */
  jid_clean_cache();

  /* Check for timed out idle rooms */
  if(mins % 2 == 0)
  {
    g_mutex_lock(master->lock);
    log_debug(NAME, "[%s] HBTICK: Idle check started", FZONE);

    master->queue = g_queue_new();

    g_hash_table_foreach(master->rooms, _con_beat_idle, &t);

    while ((room_name = (char *)g_queue_pop_head(master->queue)) != NULL) 
    {
      log_debug(NAME, "[%s] HBTICK: removed room '%s' in the queue", FZONE, room_name);
      con_room_zap(g_hash_table_lookup(master->rooms, room_name));
      log_debug(NAME, "[%s] HBTICK: removed room '%s' in the queue", FZONE, room_name);
      g_free(room_name);
    }
    g_queue_free(master->queue);
    log_debug(NAME, "[%s] HBTICK: Idle check complete", FZONE);
    g_mutex_unlock(master->lock);
  }

  /* Release malloc for tstamp */
  free(tstamp);

  if(j_strcmp(master->day, dstamp) == 0)
  {
    free(dstamp);
    return r_DONE;
  }

  free(master->day);
  master->day = j_strdup(dstamp);
  free(dstamp);

  g_mutex_lock(master->lock);
  g_hash_table_foreach(master->rooms, _con_beat_logrotate, NULL);
  g_mutex_unlock(master->lock);

  return r_DONE;
}

/*** everything starts here ***/
void conference(instance i, xmlnode x)
{
  extern jcr_instance jcr;
  cni master;
  xmlnode cfg;
  jid sadmin;
  xmlnode current;
  xmlnode node;
  pool tp;
  time_t now = time(NULL);

  log_debug(NAME, "[%s] mu-conference loading  - Service ID: %s", FZONE, i->id);

  /* Temporary pool for temporary jid creation */
  tp = pool_new();

  /* Allocate space for cni struct and link to instance */
  log_debug(NAME, "[%s] Malloc: _cni=%d", FZONE, sizeof(_cni));
  master = pmalloco(i->p, sizeof(_cni));

  master->i = i;
  /* get the config */
  cfg = xmlnode_get_tag(jcr->config, "conference");

  master->loader = 0;
  master->start = now;

  master->rooms = g_hash_table_new_full(g_str_hash, g_str_equal, ght_remove_key, ght_remove_cnr);

  master->history = j_atoi(xmlnode_get_tag_data(cfg,"history"),20);
  master->config = xmlnode_dup(cfg);					/* Store a copy of the config for later usage */
  master->day = dateget(now); 				/* Used to determine when to rotate logs */
  if (xmlnode_get_tag(cfg, "logdir") == NULL) {
    master->logsEnabled = 0;
    master->logdir = NULL;
  }
  else {
    master->logsEnabled = 1;
    master->logdir = xmlnode_get_tag_data(cfg, "logdir");	/* Directory where to store logs */
  }
  master->stylesheet = xmlnode_get_tag_data(cfg, "stylesheet");	/* Stylesheet of log files */
  if (xmlnode_get_tag(cfg, "logsubdirs") == NULL) {
    master->flatLogs = 1;
  }
  else {
    master->flatLogs = 0;
  }

  /* If requested, set default room state to 'public', otherwise will default to 'private */
  if(xmlnode_get_tag(cfg,"public"))
    master->public = 1;

  /* If requested, rooms are given a default configuration */
  if(xmlnode_get_tag(cfg,"defaults"))
    master->roomlock = -1;

  /* If requested, stop any new rooms being created */
  if(xmlnode_get_tag(cfg,"roomlock"))
    master->roomlock = 1;

  /* If requested, stop any new rooms being created */
  if(xmlnode_get_tag(cfg,"dynamic"))
    master->dynamic = 1;

  /* If requested, stop any new rooms being created */
  if(xmlnode_get_tag(cfg,"persistent"))
    master->dynamic = -1;

  /* If requested, make room nicknames locked by default */
  if(xmlnode_get_tag(cfg,"locknicks"))
    master->locknicks = 1;
  else
    master->locknicks = 0;

  /* If requested, hide rooms with no participants */
  if(xmlnode_get_tag(cfg,"hideempty"))
    master->hideempty = 1;
  else
    master->hideempty = 0;

  master->sadmin = g_hash_table_new_full(g_str_hash,g_str_equal, ght_remove_key, NULL);

  /* sadmin code */
  if(xmlnode_get_tag(cfg, "sadmin"))
  {
    node = xmlnode_get_tag(cfg, "sadmin");
    for(current = xmlnode_get_firstchild(node); current != NULL; current = xmlnode_get_nextsibling(current))
    {
      sadmin = jid_new(tp, xmlnode_get_data(current));

      if(sadmin != NULL)
      {
        log_debug(NAME, "[%s] Adding sadmin %s", FZONE, jid_full(sadmin));
        g_hash_table_insert(master->sadmin, j_strdup(jid_full(jid_user(jid_fix(sadmin)))), GINT_TO_POINTER(1));
      }
    }
  }

  master->lock = g_mutex_new();
  master->loader = 1;
  xdb_rooms_get(master);
#ifdef HAVE_MYSQL
  if ((node = xmlnode_get_tag(cfg, "mysql")))
  {
    master->sql=sql_mysql_init(master,node);
    sql_clear_all(master->sql);
    sql_insert_all(master->sql, master->rooms);
    sql_insert_lists(master->sql, master->rooms);
  }
#endif

  register_phandler(i, o_DELIVER, con_packets, (void*)master);
  register_shutdown(con_shutdown,(void *) master);
  g_timeout_add(60000, (GSourceFunc)con_beat_update, (void *)master);

  pool_free(tp);
}
