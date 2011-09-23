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
extern int deliver__flag;

cnu con_user_new(cnr room, jid id)
{
  pool p;
  cnu user;
  char *key;

  log_debug(NAME, "[%s] adding user %s to room %s", FZONE, jid_full(jid_fix(id)), jid_full(room->id));

  p = pool_new(); /* Create pool for user struct */
  user = pmalloco(p, sizeof(_cnu));

  user->p = p;
  user->realid = jid_new(user->p, jid_full(jid_fix(id)));
  user->room = room;
  user->presence = jutil_presnew(JPACKET__AVAILABLE, NULL, NULL);

  key = j_strdup(jid_full(user->realid));
  g_hash_table_insert(room->remote, key, (void*)user);

  /* Add this user to the room roster */
  add_roster(room, user->realid);

  /* If admin, switch */
  if(is_admin(room, user->realid) && !is_moderator(room, user->realid))
  {
    log_debug(NAME, "[%s] Adding %s to moderator list", FZONE, jid_full(user->realid));

    /* Update affiliate info */
    #ifdef HAVE_MYSQL
    sql_add_affiliate(room->master->sql, room,jid_full(user->realid),TAFFIL_ADMIN.code);
    #endif
    add_affiliate(room->admin, user->realid, NULL);
    add_role(room->moderator, user);
  }
  else if(is_member(room, user->realid) && !is_admin(room, user->realid))
  {
    /* Update affiliate information */
    log_debug(NAME, "[%s] Updating %s in the member list", FZONE, jid_full(user->realid));

    #ifdef HAVE_MYSQL
    sql_add_affiliate(room->master->sql, room,jid_full(user->realid),TAFFIL_MEMBER.code);
    #endif
    add_affiliate(room->member, user->realid, NULL);
    add_role(room->participant, user);
  }
  else if(room->moderated == 1 && room->defaulttype == 1)
  {
    /* Auto-add to participant list if moderated and participant type is default */
    add_role(room->participant, user);
  }

  return user;
}

int _con_user_history_send(cnu to, xmlnode node)
{

  if(to == NULL || node == NULL)
  {
    return 0;
  }

  xmlnode_put_attrib(node, "to", jid_full(to->realid));
  deliver(dpacket_new(node), NULL);
  return 1;
}

void _con_user_nick(gpointer key, gpointer data, gpointer arg)
{
  cnu to = (cnu)data;
  cnu from = (cnu)arg;
  char *old, *status, *reason, *actor;
  xmlnode node;
  xmlnode result;
  xmlnode element;
  jid fullid;

  /* send unavail pres w/ old nick */
  if((old = xmlnode_get_attrib(from->nick,"old")) != NULL)
  {

    if((from->localid->resource != NULL) ||
      (j_strcmp(xmlnode_get_attrib(from->presence,"type"),"unavailable") != 0)) //when the last presence received is not of type unavailable, the users didn't ask to leave, so we must create a new presence packet
    {
      node = jutil_presnew(JPACKET__UNAVAILABLE, jid_full(to->realid), NULL);
    }
    else
    {
      node = xmlnode_dup(from->presence);
      xmlnode_put_attrib(node, "to", jid_full(to->realid));
    }

    fullid = jid_new(xmlnode_pool(node), jid_full(from->localid));
    jid_set(fullid, old, JID_RESOURCE);
    xmlnode_put_attrib(node, "from", jid_full(fullid));

    status = xmlnode_get_attrib(from->nick,"status");
    log_debug(NAME, "[%s] status = %s", FZONE, status);

    reason = xmlnode_get_attrib(from->nick,"reason");
    actor = xmlnode_get_attrib(from->nick,"actor");

    if(from->localid->resource != NULL)
    { 
      log_debug(NAME, "[%s] Extended presence - Nick Change", FZONE);
      result = add_extended_presence(from, to, node, STATUS_MUC_NICKCHANGE, NULL, NULL);
    }
    else
    {
      log_debug(NAME, "[%s] Extended presence", FZONE);

      result = add_extended_presence(from, to, node, status, reason, actor);
    }
    
    if(jid_cmp(to->realid,from->realid)==0) //own presence
    {
      add_status_code(result, STATUS_MUC_OWN_PRESENCE);
    }

    deliver(dpacket_new(result), NULL);
    xmlnode_free(node);
  }

  /* if there's a new nick, broadcast that too */
  if(from->localid->resource != NULL)
  {
    status = xmlnode_get_attrib(from->nick,"status");
    log_debug(NAME, "[%s] status = %s/%s", FZONE, status, STATUS_MUC_CREATED);

    if(j_strcmp(status, STATUS_MUC_CREATED) == 0)
      node = add_extended_presence(from, to, NULL, status, NULL, NULL);
    else
      node = add_extended_presence(from, to, NULL, NULL, NULL, NULL);

    if((jid_cmp(to->realid,from->realid)==0) && (xmlnode_get_attrib(from->nick,"old")==NULL)) //own presence to a joining user
    {
      //we must add the other status codes
      add_room_status_codes(node,from->room);
    }

    /* Hide x:delay, not needed */
    element = xmlnode_get_tag(node, "x?xmlns=jabber:x:delay");
    if(element)
      xmlnode_hide(element);

    /* Hide urn:xmpp:delay, not needed */
    element = xmlnode_get_tag(node, "delay?xmlns=urn:xmpp:delay");
    if(element)
      xmlnode_hide(element);

    xmlnode_put_attrib(node, "to", jid_full(to->realid));
    xmlnode_put_attrib(node, "from", jid_full(from->localid));

    if(jid_cmp(to->realid,from->realid)==0) //own presence
    {
      add_status_code(node, STATUS_MUC_OWN_PRESENCE);
    }

    deliver(dpacket_new(node), NULL);
  }
}

void con_user_nick(cnu user, char *nick, xmlnode data)
{
  xmlnode node;
  char *status, *reason, *actor, *resource;
  cnr room = user->room;

  log_debug(NAME, "[%s] in room %s changing nick for user %s to %s from %s", FZONE, jid_full(room->id), jid_full(user->realid), nick, xmlnode_get_data(user->nick));

  node = xmlnode_new_tag("n");
  xmlnode_put_attrib(node, "old", xmlnode_get_data(user->nick));

  if (data)
  {
    status = xmlnode_get_attrib(data, "status");
    reason = xmlnode_get_data(data);
    actor = xmlnode_get_attrib(data, "actor");

    if(status)
      xmlnode_put_attrib(node, "status", status);

    if(reason)
      xmlnode_put_attrib(node, "reason", reason);

    if(actor)
      xmlnode_put_attrib(node, "actor", actor);

    log_debug(NAME, "[%s] status = %s", FZONE, status);
  }

  xmlnode_insert_cdata(node,nick,-1);

  xmlnode_free(user->nick);
  user->nick = node;

  resource = user->localid->resource;
  jid_set(user->localid, nick, JID_RESOURCE);

  if (nick != NULL) // if this is not a leave, we update the hash_table with the new nick as the key before sending the presence to everyone
  {
      g_hash_table_remove(user->room->local, resource);
      g_hash_table_insert(user->room->local, user->localid->resource, (void*)user);
  }

  deliver__flag = 0;
  g_hash_table_foreach(room->local, _con_user_nick, (void*)user);
  deliver__flag = 1;

  if (nick == NULL) //if this is a leave, we just remove the nick from the hashtable, we must do this after sending the presence to everyone (otherwise this user won't be notified that he has left the room)
  {
      g_hash_table_remove(user->room->local, resource);
  }

  deliver(NULL, NULL);

  /* send nick change notice if available */
  if(room->note_rename != NULL && nick != NULL && xmlnode_get_attrib(node, "old") != NULL && *room->note_rename != '\0')
    con_room_send(room, jutil_msgnew("groupchat", NULL, NULL, spools(xmlnode_pool(node), xmlnode_get_attrib(node, "old"), " ", room->note_rename, " ", nick, xmlnode_pool(node))), SEND_LEGACY);
}

void _con_user_enter(gpointer key, gpointer data, gpointer arg)
{
  cnu from = (cnu)data;
  cnu to = (cnu)arg;
  xmlnode node;
  xmlnode element;

  /* mirror */
  if(from == to)
    return;

  node = add_extended_presence(from, to, NULL, NULL, NULL, NULL);

  xmlnode_put_attrib(node, "to", jid_full(to->realid));

  xmlnode_put_attrib(node, "from", jid_full(from->localid));

  /* Hide x:delay, not needed */
  element = xmlnode_get_tag(node, "x?xmlns=jabber:x:delay");
  if(element)
    xmlnode_hide(element);
    
  /* Hide urn:xmpp:delay, not needed */
  element = xmlnode_get_tag(node, "delay?xmlns=urn:xmpp:delay");
  if(element)
    xmlnode_hide(element);

  deliver(dpacket_new(node), NULL);
}

void con_user_enter(cnu user, char *nick, int created)
{
  xmlnode node;
  xmlnode message;
  xmlnode p_x_history;
  int h, tflag = 0;
  cnr room = user->room;

  int num_stanzas = 0;
  int max_stanzas;
  int max_chars;
  int max_chars_stanzas = 0;
  int seconds;
  int since = -1;
  char *since_str;

  struct tm *since_tm;

  int num_chars = 0;

  user->localid = jid_new(user->p, jid_full(room->id));
  jid_set(user->localid, nick, JID_RESOURCE);

  room->count++;

#ifdef HAVE_MYSQL
  sql_update_nb_users(room->master->sql, room);
#endif

  log_debug(NAME, "[%s] officiating user %s in room (created = %d) %s as %s", FZONE, jid_full(user->realid), created, jid_full(room->id), nick);

  /* Update my roster with current users */
  g_hash_table_foreach(room->local, _con_user_enter, (void*)user);

  /* Send presence back to user to confirm presence received */
  if(created == 1)
  {
    /* Inform if room just created */
    node = xmlnode_new_tag("reason");
    xmlnode_put_attrib(node, "status", STATUS_MUC_CREATED);
    con_user_nick(user, nick, node); /* pushes to everyone (including ourselves) our entrance */
    xmlnode_free(node);
  }
  else
  {
    con_user_nick(user, nick, NULL); /* pushes to everyone (including ourselves) our entrance */
  }

  /* Send Room MOTD */
  if(room->description != NULL && *room->description != '\0')
  {
    message = jutil_msgnew("groupchat", jid_full(user->realid), NULL, room->description);
    xmlnode_put_attrib(message,"from", jid_full(room->id));
    deliver(dpacket_new(message), NULL);
  }

  /* Send Room protocol message to legacy clients */
  if(is_legacy(user))
  {
    message = jutil_msgnew("groupchat", jid_full(user->realid), NULL, spools(user->p, "This room supports the MUC protocol.", user->p));
    xmlnode_put_attrib(message,"from", jid_full(room->id));
    deliver(dpacket_new(message), NULL);
  }

  /* Send Room Lock warning if necessary */
  if(room->locked > 0)
  {
    message = jutil_msgnew("groupchat", jid_full(user->realid), NULL, spools(user->p, "This room is locked from entry until configuration is confirmed.", user->p));
    xmlnode_put_attrib(message,"from", jid_full(room->id));
    deliver(dpacket_new(message), NULL);
  }

  /* Switch to queue mode */
  deliver__flag = 0;

  p_x_history = xmlnode_get_tag(user->presence,"x/history");
  log_debug(NAME,"x->maxstanzas: %i",j_atoi(xmlnode_get_attrib(p_x_history,"maxstanzas"),-1));
  log_debug(NAME,"x->maxchars: %i",j_atoi(xmlnode_get_attrib(p_x_history,"maxchars"),-1));

  /* loop through history and send back */
  if(room->master->history > 0)
  {
    max_stanzas = j_atoi(xmlnode_get_attrib(p_x_history,"maxstanzas"),room->master->history);
    max_chars = j_atoi(xmlnode_get_attrib(p_x_history,"maxchars"),-1);
    seconds = j_atoi(xmlnode_get_attrib(p_x_history,"seconds"),-1);
    since_str = xmlnode_get_attrib(p_x_history,"since");
    if (since_str != NULL) {
      since_tm = malloc(sizeof(struct tm));
      bzero(since_tm,sizeof(struct tm));

      /* calc unix time */
      strptime(since_str,"%Y-%m-%dT%T%z",since_tm);
      since = mktime(since_tm);
      free(since_tm);
    }


    if (max_stanzas > room->master->history)
      max_stanzas = room->master->history;

    if (max_chars>0) {
      /* loop (backwards) through history to get num of stanzas to reach num_chars */
      h = (room->hlast + room->master->history - max_stanzas) % room->master->history;
      while(1) {
        if (room->history[h] != NULL)
          num_chars += room->history[h]->content_length;
        if (num_chars <= max_chars)
          max_chars_stanzas++;
        else
          break;
        if (h==0)
          h = room->master->history;
        h--;
        if (h == room->hlast)
          break;
      }

      if (max_chars_stanzas < max_stanzas) // choose the smaller one
        max_stanzas = max_chars_stanzas;
    }
    if (max_chars == 0)
      max_stanzas = 0;

    log_debug(NAME, "room->hlast: %i, room->master->history: %i, maxstanzas: %i", room->hlast, room->master->history, max_stanzas);
    h = (room->hlast + room->master->history - max_stanzas) % room->master->history;
    while(1)
    {
      log_debug(NAME, "h: %i",h);
      if (num_stanzas >= max_stanzas)
        break;

      h++;

      if(h == room->master->history)
        h = 0;
      if (room->history[h] != NULL) {
        /* skip messages that older than requested */
        if (!(seconds >= 0 && (time(NULL) - room->history[h]->timestamp) > seconds) && 
            !(since >= 0 && room->history[h]->timestamp < since)) {

          num_stanzas +=_con_user_history_send(user, xmlnode_dup(room->history[h]->x));

          if(xmlnode_get_tag(room->history[h]->x,"subject") != NULL)
            tflag = 1;
        }
      }

      if(h == room->hlast)
        break;
    }
  }

  /* Re-enable delivery */
  deliver__flag = 1;
  /* Send queued messages */
  deliver(NULL, NULL);

  /* send last know topic */
  if(tflag == 0 && room->topic != NULL)
  {
    node = jutil_msgnew("groupchat", jid_full(user->realid), xmlnode_get_attrib(room->topic,"subject"), xmlnode_get_data(room->topic));
    xmlnode_put_attrib(node, "from", jid_full(room->id));
    deliver(dpacket_new(node), NULL);
  }

  /* send entrance notice if available */
  if(room->note_join != NULL && *room->note_join != '\0')
    con_room_send(room, jutil_msgnew("groupchat", NULL, NULL, spools(user->p, nick, " ", room->note_join, user->p)), SEND_LEGACY);

  /* Send 'non-anonymous' message if necessary */
  if(room->visible == 1)
    con_send_alert(user, NULL, NULL, STATUS_MUC_SHOWN_JID);
}

void con_user_process(cnu to, cnu from, jpacket jp)
{
  xmlnode node, element;
  cnr room = to->room;
  char str[10];
  int t;

  /* we handle all iq's for this id, it's *our* id */
  if(jp->type == JPACKET_IQ)
  {
    if(NSCHECK(jp->iq,NS_BROWSE))
    {
      jutil_iqresult(jp->x);
      node = xmlnode_insert_tag(jp->x, "item");

      xmlnode_put_attrib(node, "category", "user");
      xmlnode_put_attrib(node, "xmlns", NS_BROWSE);
      xmlnode_put_attrib(node, "name", to->localid->resource);

      element = xmlnode_insert_tag(node, "item");
      xmlnode_put_attrib(element, "category", "user");

      if(room->visible == 1 || is_moderator(room, from->realid))
        xmlnode_put_attrib(element, "jid", jid_full(to->realid));
      else
        xmlnode_put_attrib(element, "jid", jid_full(to->localid));

      if(is_legacy(to))
        xmlnode_insert_cdata(xmlnode_insert_tag(node, "ns"), NS_GROUPCHAT, -1);
      else
        xmlnode_insert_cdata(xmlnode_insert_tag(node, "ns"), NS_MUC, -1);

      deliver(dpacket_new(jp->x), NULL);
      return;
    }

    if(NSCHECK(jp->iq,NS_LAST))
    {
      jutil_iqresult(jp->x);

      node = xmlnode_insert_tag(jp->x, "query");
      xmlnode_put_attrib(node, "xmlns", NS_LAST);

      t = time(NULL) - to->last;
      sprintf(str,"%d",t);

      xmlnode_put_attrib(node ,"seconds", str);

      deliver(dpacket_new(jp->x), NULL);
      return;
    }

    /* deny any other iq's if it's private */
    if(to->private == 1)
    {
      jutil_error(jp->x, TERROR_FORBIDDEN);
      deliver(dpacket_new(jp->x), NULL);
      return;
    }

    /* if not, fall through and just forward em on I guess! */
  }

  /* Block possibly faked groupchat messages - groupchat is not meant for p2p chats */
  if(jp->type == JPACKET_MESSAGE)
  {
    if(jp->subtype == JPACKET__GROUPCHAT)
    {
      jutil_error(jp->x, TERROR_BAD);
      deliver(dpacket_new(jp->x), NULL);
      return;
    }

    if(room->privmsg == 1 && !is_admin(room, from->realid))
    {
      /* Only error on messages with body, otherwise just drop */
      if(xmlnode_get_tag(jp->x, "body") != NULL)
      {	
        jutil_error(jp->x, TERROR_MUC_PRIVMSG);
        deliver(dpacket_new(jp->x), NULL);
        return;
      }
      else
      {
        xmlnode_free(jp->x);
        return;
      }
    }

  }

  con_user_send(to, from, jp->x);
}

void con_user_send(cnu to, cnu from, xmlnode node)
{
  if(to == NULL || from == NULL || node == NULL)
  {
    return;
  }

  xmlnode_put_attrib(node, "to", jid_full(to->realid));

  if(xmlnode_get_attrib(node, "cnu") != NULL)
    xmlnode_hide_attrib(node, "cnu");

  xmlnode_put_attrib(node, "from", jid_full(from->localid));
  deliver(dpacket_new(node), NULL);
}

void con_user_zap(cnu user, xmlnode data)
{
  cnr room;
  char *reason;
  char *status;
  char *nick;
  char *key;

  if(user == NULL || data == NULL)
  {
    log_warn(NAME, "[%s]: Aborting: NULL attribute found", FZONE);

    if(data != NULL)
      xmlnode_free(data);

    return;
  }

  user->leaving = 1;

  key = pstrdup(user->p, jid_full(user->realid));

  status = xmlnode_get_attrib(data, "status");
  nick = xmlnode_get_attrib(data, "actnick");

  reason = xmlnode_get_data(data);

  room = user->room;

  if(room == NULL)
  {
    log_warn(NAME, "[%s] Unable to zap user %s <%s-%s> : Room does not exist", FZONE, jid_full(user->realid), status, reason);
    xmlnode_free(data);
    return;
  }

  log_debug(NAME, "[%s] zapping user %s <%s-%s>", FZONE, jid_full(user->realid), status, reason);

  if(user->localid != NULL)
  {
    log_debug(NAME, "[%s] Removing entry from local list, and sending unavailable presence", FZONE);
    con_user_nick(user, NULL, data); /* sends unavailable */

    room->count--;
#ifdef HAVE_MYSQL
    sql_update_nb_users(room->master->sql, room);
#endif

    /* send departure notice if available*/
    if(room->note_leave != NULL && *room->note_leave != '\0')
    {
      if(reason != NULL)
      {
        if(j_strcmp(status, STATUS_MUC_KICKED) == 0)
        {
          if(nick != NULL)
          {
            con_room_send(room,jutil_msgnew("groupchat",NULL,NULL,spools(user->p, xmlnode_get_attrib(user->nick,"old")," ",room->note_leave,": [Kicked by ", nick, "] ", reason, user->p)), SEND_LEGACY);
          }
          else
          {
            con_room_send(room,jutil_msgnew("groupchat",NULL,NULL,spools(user->p, xmlnode_get_attrib(user->nick,"old")," ",room->note_leave,": [Kicked by a user] ", reason, user->p)), SEND_LEGACY);
          }
        }
        else if(j_strcmp(status, STATUS_MUC_BANNED) == 0)
        {
          if(nick != NULL)
          {
            con_room_send(room,jutil_msgnew("groupchat",NULL,NULL,spools(user->p,xmlnode_get_attrib(user->nick,"old")," ",room->note_leave,": [Banned by ", nick ,"] ", reason, user->p)), SEND_LEGACY);
          }
          else
          {
            con_room_send(room,jutil_msgnew("groupchat",NULL,NULL,spools(user->p,xmlnode_get_attrib(user->nick,"old")," ",room->note_leave,": [Banned by a user] ", reason, user->p)), SEND_LEGACY);
          }
        }
        else
        {
          con_room_send(room,jutil_msgnew("groupchat",NULL,NULL,spools(user->p,xmlnode_get_attrib(user->nick,"old")," ",room->note_leave,": ", reason, user->p)), SEND_LEGACY);
        }
      }
      else 
      {
        con_room_send(room,jutil_msgnew("groupchat",NULL,NULL,spools(user->p,xmlnode_get_attrib(user->nick,"old")," ",room->note_leave,user->p)), SEND_LEGACY);
      }
    }
  }

  xmlnode_free(data);

  log_debug(NAME, "[%s] Removing any affiliate info from admin list", FZONE);
  log_debug(NAME, "[%s] admin list size [%d]", FZONE, g_hash_table_size(room->admin));
  remove_affiliate(room->admin, user->realid);

  log_debug(NAME, "[%s] Removing any affiliate info from member list", FZONE);
  log_debug(NAME, "[%s] member list size [%d]", FZONE, g_hash_table_size(room->member));
  remove_affiliate(room->member, user->realid);

  log_debug(NAME, "[%s] Removing any role info from moderator list", FZONE);
  log_debug(NAME, "[%s] moderator list size [%d]", FZONE, g_hash_table_size(room->moderator));
  revoke_role(room->moderator, user);
  log_debug(NAME, "[%s] Removing any role info from participant list", FZONE);
  log_debug(NAME, "[%s] participant list size [%d]", FZONE, g_hash_table_size(room->participant));
  revoke_role(room->participant, user);

  log_debug(NAME, "[%s] Removing any roster info from roster list", FZONE);
  remove_roster(room, user->realid);

  log_debug(NAME, "[%s] Un-alloc presence xmlnode", FZONE);
  xmlnode_free(user->presence);
  log_debug(NAME, "[%s] Un-alloc nick xmlnode", FZONE);
  xmlnode_free(user->nick);

  log_debug(NAME, "[%s] Removing from remote list and un-alloc cnu", FZONE);
  g_hash_table_remove(room->remote, jid_full(user->realid));
}

