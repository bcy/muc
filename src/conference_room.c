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

/* call strescape on a string and xhtmlize the string (\n-><br/>) */
char * _con_room_xhtml_strescape(pool p, char * buf) {
  char *result,*temp;
  int i,j;
  int oldlen, newlen;
  result = strescape(p, buf);
  oldlen = newlen=strlen(result);
  for (i=0; i<oldlen;i++) {
    if (result[i]=='\n') {
      newlen += 6;
    }
  }

  if(oldlen == newlen) return result;

  temp = pmalloc(p,newlen+1);
  if (temp == NULL) return NULL;

  for (i=j=0;i<oldlen;i++) {
    if (result[i]== '\n') {
      memcpy(&temp[j], "<br />", 6);
      j+=6;
    }
    else temp[j++] = result[i];
  }
  temp[j]='\0';
  return temp;
}



/* Handles logging for each room, simply returning if logfile is not defined */
void con_room_log(cnr room, char *nick, char *message)
{
  time_t t;
  xmlnode xml;
  jid user;
  char *output;
  char timestr[80];
  size_t timelen = 79;
  FILE *logfile;
  pool p;

  if(message == NULL || room == NULL) 
  {
    log_warn(NAME, "[%s] ERR: Aborting - NULL reference found - ", FZONE);
    return;
  }

  logfile = room->logfile;

  if(logfile == NULL) 
  {
    log_debug(NAME, "[%s] Logging not enabled for this room", FZONE);
    return;
  }

  p = pool_heap(1024);

  /* nicked from mod_time */
  t = time(NULL);
  
  if(room->logformat == LOG_XHTML)
    strftime(timestr, timelen, "<a name=\"t%H:%M:%S\" href=\"#t%H:%M:%S\">[%H:%M:%S]</a>", localtime(&t));
  else
    strftime(timestr, timelen, "[%H:%M:%S]", localtime(&t));

  if(room->logformat == LOG_XML)
  {
    xml = jutil_msgnew("groupchat", jid_full(room->id) , NULL, strescape(p, message));

    user = jid_new(xmlnode_pool(xml), jid_full(room->id));
    jid_set(user, strescape(p, nick), JID_RESOURCE);
    xmlnode_put_attrib(xml, "from", jid_full(user));

    jutil_delay(xml, NULL);

    fprintf(logfile, "%s\n", xmlnode2str(xml));

    xmlnode_free(xml);
  }
  else if(room->logformat == LOG_XHTML)
  {
    if(nick)
    {
      if(j_strncmp(message, "/me ", 4) == 0)
      {
        output = extractAction(_con_room_xhtml_strescape(p, message), p);
        fprintf(logfile, "<span class=\"time\">%s</span> * <span class=\"nick\">%s</span>%s<br />\n", timestr, strescape(p, nick), output);

      }
      else
      {
        fprintf(logfile, "<span class=\"time\">%s</span> &lt;<span class=\"nick\">%s</span>&gt; %s<br />\n", timestr, strescape(p, nick), _con_room_xhtml_strescape(p, message));
      }
    }
    else
    {
      fprintf(logfile, "<span class=\"time\">%s</span> --- %s<br />\n", timestr, message);
    }
  }
  else
  {
    if(nick)
    {
      if(j_strncmp(message, "/me ", 4) == 0)
      {
        output = extractAction(message, p);
        fprintf(logfile, "%s * %s%s\n", timestr, nick, output);
      }
      else
      {
        fprintf(logfile, "%s <%s> %s\n", timestr, nick, message);
      }
    }
    else
    {
      fprintf(logfile, "%s --- %s\n", timestr, message);
    }
  }

  fflush(logfile);
  pool_free(p);
  return;
}

void con_room_log_new(cnr room)
{
  char *filename;
  char *curdate;
  char *dirname;
  char datePart[5];
  struct stat fileinfo;
  time_t now = time(NULL);
  int type;
  pool p;
  spool sp;

  if(room == NULL || !room->master->logsEnabled) 
  {
    log_warn(NAME, "[%s] Aborting - NULL room", FZONE);
    return;
  }

  p = pool_heap(1024);
  type = room->logformat;
  dirname = jid_full(room->id);
  sp = spool_new(p);

  if(room->master->logdir)
  {
    spooler(sp, room->master->logdir, "/", dirname, sp);
  }
  else
  {
    spooler(sp, "./", dirname, sp);
  }

  filename = spool_print(sp);

  if(stat(filename,&fileinfo) < 0 && mkdir(filename, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0)
  {
    log_warn(NAME, "[%s] ERR: unable to open log directory >%s<", FZONE, filename);
    return;
  }

  curdate = dateget(now);

  if (room->master->flatLogs) {

    spooler(sp, "/", curdate, sp);

  }
  else {

    strftime(datePart, 5, "%Y", localtime(&now));
    
    spooler(sp, "/", datePart, sp);
    filename = spool_print(sp);
    if(stat(filename,&fileinfo) < 0 && mkdir(filename, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0)
    {
      log_warn(NAME, "[%s] ERR: unable to open log directory >%s<", FZONE, filename);
      return;
    }

    strftime(datePart, 5, "%m", localtime(&now));
    
    spooler(sp, "/", datePart, sp);
    filename = spool_print(sp);
    if(stat(filename,&fileinfo) < 0 && mkdir(filename, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0)
    {
      log_warn(NAME, "[%s] ERR: unable to open log directory >%s<", FZONE, filename);
      return;
    }

    strftime(datePart, 5, "%d", localtime(&now));
    
    spooler(sp, "/", datePart, sp);


  }

  if(type == LOG_XML)
    spool_add(sp, ".xml");
  else if(type == LOG_XHTML)
    spool_add(sp, ".html");
  else
    spool_add(sp, ".txt");


  filename = spool_print(sp);

  if(stat(filename,&fileinfo) < 0)
  {
    log_debug(NAME, "[%s] New logfile >%s<", FZONE, filename);

    room->logfile = fopen(filename, "a");

    if(type == LOG_XHTML && room->logfile != NULL)
    {
      fprintf(room->logfile, "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">\n<head>\n<title>Logs for %s, %s</title>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/>\n", jid_full(room->id), curdate);
     if (room->master->stylesheet!=NULL)
       fprintf(room->logfile, "<link rel=\"stylesheet\" type=\"text/css\" href=\"%s\" />\n",room->master->stylesheet);
     fprintf(room->logfile, "</head><body>\n<p class=\"logs\">\n");

      fflush(room->logfile);
    }
  }
  else
  {
    room->logfile = fopen(filename, "a");
  }


  if(room->logfile == NULL)
    log_warn(NAME, "[%s] ERR: unable to open log file >%s<", FZONE, filename);
  else
    log_debug(NAME, "[%s] Opened logfile >%s<", FZONE, filename);

  pool_free(p);
  free(curdate);
  return;
}

void con_room_log_close(cnr room)
{
  int type;
  FILE *logfile;

  if(room == NULL) 
  {
    log_warn(NAME, "[%s] Aborting - NULL room", FZONE);
    return;
  }

  type = room->logformat;
  logfile = room->logfile;

  if(logfile == NULL)
  {
    log_warn(NAME, "[%s] Aborting - NULL logfile", FZONE);
    return;
  }

  log_debug(NAME, "[%s] Closing logfile for room >%s<", FZONE, jid_full(room->id));

  if(type == LOG_XHTML)
  {
    fprintf(logfile, "</p>\n</body>\n</html>\n");
    fflush(logfile);
  }

  fclose(room->logfile);
  room->logfile = NULL;
}

void con_room_send_invite(cnu sender, xmlnode node)
{
  xmlnode result;
  xmlnode element;
  xmlnode invite;
  xmlnode pass;
  char *body, *user, *reason, *inviter;
  cnr room;
  pool p;

  if(sender == NULL || node == NULL) 
  {
    log_warn(NAME, "[%s] Aborting - NULL attribute found", FZONE);
    return;
  }

  log_debug(NAME, "[%s] Sending room invite", FZONE);

  room = sender->room;

  invite = xmlnode_get_tag(node, "invite");
  user = xmlnode_get_attrib(invite, "to");
  reason = xmlnode_get_tag_data(invite, "reason");

  p = xmlnode_pool(node);

  if(room->visible == 1)
  {
    inviter = jid_full(sender->realid);
  }
  else
  {
    inviter = jid_full(sender->localid);
  }

  xmlnode_put_attrib(invite, "from", inviter);
  xmlnode_hide_attrib(invite, "to");

  if(reason == NULL)
  {
    reason = spools(p, "None given", p);
  }

  body = spools(p, "You have been invited to the ", jid_full(room->id), " room by ", inviter, "\nReason: ", reason, p);

  result = jutil_msgnew("normal", user , "Invitation", body);
  xmlnode_put_attrib(result, "from", jid_full(room->id));

  xmlnode_insert_node(result, node);

  if(room->secret != NULL)
  {
    pass = xmlnode_get_tag(result, "x");
    xmlnode_insert_cdata(xmlnode_insert_tag(pass, "password"), room->secret, -1);
  }

  element = xmlnode_insert_tag(result, "x");
  xmlnode_put_attrib(element, "jid", jid_full(room->id));
  xmlnode_put_attrib(element, "xmlns", NS_X_CONFERENCE);
  xmlnode_insert_cdata(element, reason, -1);

  log_debug(NAME, "[%s] >>>%s<<<", FZONE, xmlnode2str(result));

  deliver(dpacket_new(result), NULL);
  return;

}    

void con_room_forward_decline(cnr room, jpacket jp, xmlnode decline)
{
  cnu user;
  jid user_jid;
  if (room == NULL || decline == NULL || jp == NULL)
  {
    log_warn(NAME, "[%s] Aborting - NULL attribute found", FZONE);
    xmlnode_free(jp->x);
    return;
  }
  user_jid=jid_new(decline->p,xmlnode_get_attrib(decline,"to"));
  if ((room->invitation == 1 && !is_member(room, jp->from) && !is_owner(room, jp->from)) || user_jid == NULL)
  {
    log_warn(NAME, "[%s] Aborting - User is not allowed to send a decline", FZONE);
    jutil_error(jp->x, TERROR_MUC_OUTSIDE);
    deliver(dpacket_new(jp->x), NULL);
    return;
  }
  if (user_jid->resource == NULL) {
    log_warn(NAME, "[%s] Aborting - cannot send back decline, bare jid found", FZONE);
    return;
  }
  if (room->visible == 1)
  {
    user = g_hash_table_lookup(room->remote, jid_full(jid_fix(user_jid)));
  }
  else
  {
    user = g_hash_table_lookup(room->local, user_jid->resource);
  }

  if (user == NULL){
    log_warn(NAME, "[%s] Aborting - Decline recipient is not in the room", FZONE);
    jutil_error(jp->x, TERROR_MUC_OUTSIDE);
    deliver(dpacket_new(jp->x), NULL);
    return;
  }
  log_debug(NAME, "[%s] Sending invitation decline", FZONE);
  xmlnode_put_attrib(decline, "from", jid_full(jp->from));
  xmlnode_hide_attrib(decline, "to");
  xmlnode_put_attrib(jp->x, "to", jid_full(user->realid));
  xmlnode_put_attrib(jp->x, "from", jid_full(room->id));

  log_debug(NAME, "[%s] >>>%s<<<", FZONE, xmlnode2str(jp->x));

  deliver(dpacket_new(jp->x), NULL);
  return;
}


void con_room_leaveall(gpointer key, gpointer data, gpointer arg)
{
  cnu user = (cnu)data;
  xmlnode info = (xmlnode)arg;
  char *alt, *reason;
  xmlnode presence;
  xmlnode tag;
  xmlnode element;
  xmlnode node;
  xmlnode destroy;

  log_debug(NAME, "[%s] reason :  %s", FZONE, xmlnode2str(info));
  if(user == NULL) 
  {
    log_warn(NAME, "[%s] Aborting - NULL user attribute found", FZONE);
    return;
  }

  presence = jutil_presnew(JPACKET__UNAVAILABLE, NULL, NULL);
  tag = xmlnode_insert_tag(presence,"x");
  xmlnode_put_attrib(tag, "xmlns", NS_MUC_USER);

  element = xmlnode_insert_tag(tag, "item");
  xmlnode_put_attrib(element, "role", "none");
  xmlnode_put_attrib(element, "affiliation", "none");

  if (info != NULL)
  {
    destroy = xmlnode_insert_tag(tag, "destroy");
    reason = xmlnode_get_tag_data(info, "reason");
    node = xmlnode_insert_tag(destroy, "reason");

    if(reason != NULL)
    {
      xmlnode_insert_cdata(node, reason, -1);
    }

    alt = xmlnode_get_attrib(info, "jid");

    if (alt != NULL)
    {
      xmlnode_put_attrib(destroy, "jid", alt);
    }
  }

  con_user_send(user, user, presence);
}

/* returns a valid nick from the list, x is the first <nick>foo</nick> xmlnode, checks siblings */
char *con_room_nick(cnr room, cnu user, xmlnode x)
{
  char *nick = NULL;
  xmlnode cur;
  int count = 1;

  if(room == NULL || user == NULL) 
  {
    log_warn(NAME, "[%s] Aborting - NULL attribute found", FZONE);
    return NULL;
  }

  log_debug(NAME, "[%s] looking for valid nick in room %s from starter %s", FZONE, jid_full(room->id), xmlnode2str(x));

  /* make-up-a-nick phase */
  if(x == NULL)
  {
    nick = pmalloco(user->p, j_strlen(user->realid->user) + 10);
    log_debug(NAME, "[%s] Malloc: Nick = %d", FZONE, j_strlen(user->realid->user) + 10);

    sprintf(nick, "%s", user->realid->user);
    while(g_hash_table_lookup(room->local, nick) != NULL)
      sprintf(nick, "%s%d", user->realid->user,count++);
    return nick;
  }

  /* scan the list */
  for(cur = x; cur != NULL; cur = xmlnode_get_nextsibling(cur))
  {
    if(j_strcmp(xmlnode_get_name(cur),"nick") == 0 && (nick = xmlnode_get_data(cur)) != NULL)
      if(g_hash_table_lookup(room->local, nick) == NULL)
        break;
  }

  if(is_registered(room->master, jid_full(jid_user(user->realid)), nick) == -1)
    nick = NULL;

  return nick;
}

void con_room_sendwalk(gpointer key, gpointer data, gpointer arg)
{
  xmlnode x = (xmlnode)arg;
  cnu to = (cnu)data;
  cnu from;
  xmlnode output;

  if(x == NULL || to == NULL) 
  {
    log_warn(NAME, "[%s] Aborting - NULL attribute found", FZONE);
    return;
  }

  from = (cnu)xmlnode_get_vattrib(x,"cnu");

  if(j_strcmp(xmlnode_get_name(x),"presence") == 0)
  {
    output = add_extended_presence(from, to, x, NULL, NULL, NULL);
    if(jid_cmp(to->realid,from->realid)==0) //own presence
    {
      add_status_code(output, STATUS_MUC_OWN_PRESENCE);
    }
    con_user_send(to, from, output); 
  }
  else
  {
    con_user_send(to, from, xmlnode_dup(x)); /* Need to send duplicate */
  }
}

/* Browse for members of a room */
void con_room_browsewalk(gpointer key, gpointer data, gpointer arg)
{
  jid userjid;
  cnu user = (cnu)data;
  xmlnode q = (xmlnode)arg;
  xmlnode xml;

  if(user == NULL || q == NULL) 
  {
    log_warn(NAME, "[%s] Aborting - NULL attribute found", FZONE);
    return;
  }

  xml = xmlnode_insert_tag(q, "item");
  userjid = jid_new(xmlnode_pool(xml), jid_full(user->room->id));
  jid_set(userjid, user->localid->resource, JID_RESOURCE);

  xmlnode_put_attrib(xml, "category", "user");
  xmlnode_put_attrib(xml, "type", "client");
  xmlnode_put_attrib(xml, "name", user->localid->resource);
  xmlnode_put_attrib(xml, "jid", jid_full(userjid));
}

void _con_room_discoinfo(cnr room, jpacket jp)
{
  xmlnode result;
  xmlnode xdata, field;
  char *topic;
  char buf[32];

  if(room == NULL) 
  {
    log_warn(NAME, "[%s] Aborting - NULL room attribute found", FZONE);
    return;
  }

  jutil_iqresult(jp->x);
  xmlnode_put_attrib(xmlnode_insert_tag(jp->x,"query"), "xmlns", NS_DISCO_INFO);
  jpacket_reset(jp);

  result = xmlnode_insert_tag(jp->iq,"identity");
  xmlnode_put_attrib(result, "category", "conference");
  xmlnode_put_attrib(result, "type", "text");
  xmlnode_put_attrib(result, "name", room->name);

  xmlnode_put_attrib(xmlnode_insert_tag(jp->iq, "feature"), "var", NS_MUC);
  xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", NS_DISCO);
  xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", NS_BROWSE);
  xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", NS_VERSION);
  xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", NS_LAST);
  xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", NS_TIME);
  xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", NS_VCARD);

  if(room->secret != NULL && *room->secret != '\0')
    xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", "muc_passwordprotected");
  else
    xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", "muc_unsecure");

  if(room->public == 1)
    xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", "muc_public");
  else
    xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", "muc_hidden");

  if(room->persistent == 1)
    xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", "muc_persistent");
  else
    xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", "muc_temporary");

  if(room->invitation == 1)
    xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", "muc_membersonly");
  else
    xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", "muc_open");

  if(room->moderated == 1)
    xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", "muc_moderated");
  else
    xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", "muc_unmoderated");

  if(room->visible == 1)
    xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", "muc_nonanonymous");
  else
    xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", "muc_semianonymous");

  if(room->legacy == 1)
    xmlnode_put_attrib(xmlnode_insert_tag(jp->iq,"feature"), "var", "muc-legacy");

  /* return extended disco info per JEP-0128 */
  xdata = xmlnode_insert_tag(jp->iq, "x");
  xmlnode_put_attrib(xdata, "xmlns", NS_DATA);
  xmlnode_put_attrib(xdata, "type", "result");

  /* FORM_TYPE field */
  field = xmlnode_insert_tag(xdata, "field");
  xmlnode_put_attrib(field, "var", "FORM_TYPE");
  xmlnode_put_attrib(field, "type", "hidden");
  xmlnode_insert_cdata(xmlnode_insert_tag(field, "value"), "http://jabber.org/protocol/muc#roominfo", -1);

  /* muc#roominfo_description field */
  if (room->description != NULL && *room->description != '\0') {
    field = xmlnode_insert_tag(xdata, "field");
    xmlnode_put_attrib(field, "var", "muc#roominfo_description");
    xmlnode_put_attrib(field, "label", "Description");
    xmlnode_insert_cdata(xmlnode_insert_tag(field, "value"),
        room->description, -1);
  }

  /* muc#roominfo_subject field */
  topic = xmlnode_get_attrib(room->topic, "subject");
  if (topic != NULL && *topic != '\0') {
    field = xmlnode_insert_tag(xdata, "field");
    xmlnode_put_attrib(field, "var", "muc#roominfo_subject");
    xmlnode_put_attrib(field, "label", "Subject");
    xmlnode_insert_cdata(xmlnode_insert_tag(field, "value"),
        topic, -1);
  }

  /* muc#roominfo_occupants field */
  snprintf(buf, 32, "%d", room->count);
  field = xmlnode_insert_tag(xdata, "field");
  xmlnode_put_attrib(field, "var", "muc#roominfo_occupants");
  xmlnode_put_attrib(field, "label", "Number of occupants");
  xmlnode_insert_cdata(xmlnode_insert_tag(field, "value"),
      buf, -1);

  /* FIXME: do something about muc#roominfo_lang field */

  deliver(dpacket_new(jp->x), NULL);
  return;
}

void _con_room_discoitem(gpointer key, gpointer data, gpointer arg)
{
  jid userjid;
  cnu user = (cnu)data;
  xmlnode query = (xmlnode)arg;
  xmlnode xml;

  if(user == NULL || query == NULL) 
  {
    log_warn(NAME, "[%s] Aborting - NULL attribute found", FZONE);
    return;
  }

  xml = xmlnode_insert_tag(query, "item");

  userjid = jid_new(xmlnode_pool(xml), jid_full(user->room->id));
  jid_set(userjid, user->localid->resource, JID_RESOURCE);

  xmlnode_put_attrib(xml, "jid", jid_full(userjid));
}

void _con_room_disconick(cnr room, jpacket jp){
  char* str;
  xmlnode x;

  if (room->locknicks) {
    str=jp->from->user;
  }
  else {
    x = get_data_byjid(room->master, xmlnode_get_attrib(jp->x, "from"));
    str = xmlnode_get_attrib(x, "nick") ? xmlnode_get_attrib(x, "nick") : NULL;
  }
  jutil_iqresult(jp->x);
  x = xmlnode_insert_tag(jp->x,"query");
  xmlnode_put_attrib(x,"xmlns",NS_DISCO_INFO);
  xmlnode_put_attrib(x,"node","x-roomuser-item");
  jpacket_reset(jp);

  if (str) {
    x = xmlnode_insert_tag(jp->x,"identity");
    xmlnode_put_attrib(x,"category","conference");
    xmlnode_put_attrib(x,"name",str);
    xmlnode_put_attrib(x,"type","text");
  }
  deliver(dpacket_new(jp->x), NULL);

}

/* send disco items reply */
void _con_room_discoitems(cnr room, jpacket jp, int in_room){
  xmlnode result;
  if (xmlnode_get_attrib(jp->iq,"node")!= NULL){
    //unknow node
    jutil_error(jp->x, TERROR_UNAVAIL);
    deliver(dpacket_new(jp->x),NULL);
    return;
  }

  jutil_iqresult(jp->x);
  result = xmlnode_insert_tag(jp->x, "query");
  xmlnode_put_attrib(result, "xmlns", NS_DISCO_ITEMS);

  if ((in_room == 1) || (is_sadmin(room->master, jp->from))) {
    g_hash_table_foreach(room->local, _con_room_discoitem, (void*)result);
  }

  deliver(dpacket_new(jp->x), NULL);


}

/* send browse reply */
void _con_room_send_browse_reply(jpacket iq, cnr room, int in_room){
  xmlnode node;
      jutil_iqresult(iq->x);
      node = xmlnode_insert_tag(iq->x,"item");
      xmlnode_put_attrib(node,"category","conference");

      if((room->public && room->invitation == 0) || (room->public && is_member(room, iq->from)))
      {
        xmlnode_put_attrib(node,"type","public");
        if (in_room || (is_sadmin(room->master, iq->from))){
          g_hash_table_foreach(room->local, con_room_browsewalk, (void*)node);
        }
      }
      else
      {
        xmlnode_put_attrib(node,"type","private");
        if (in_room || (is_sadmin(room->master, iq->from))){
          g_hash_table_foreach(room->local, con_room_browsewalk, (void*)node);
        }

      }

      xmlnode_put_attrib(node,"xmlns",NS_BROWSE);
      xmlnode_put_attrib(node,"name",room->name);
      xmlnode_put_attrib(node,"version",VERSION);

      iq_populate_browse(node);

      deliver(dpacket_new(iq->x), NULL);
}

/* send a response to a iq:last request */
void _con_room_send_last(jpacket jp,cnr room){
  int start;
  char nstr[10];
  jutil_iqresult(jp->x);
  xmlnode_put_attrib(xmlnode_insert_tag(jp->x,"query"),"xmlns",NS_LAST);
  jpacket_reset(jp);

  start = time(NULL) - room->start;
  sprintf(nstr,"%d",start);
  xmlnode_put_attrib(jp->iq,"seconds", pstrdup(jp->p, nstr));

  deliver(dpacket_new(jp->x),NULL);
}


void con_room_outsider(cnr room, cnu from, jpacket jp)
{


  if(room == NULL) 
  {
    log_warn(NAME, "[%s] Aborting - NULL attribute found", FZONE);
    return;
  }

  log_debug(NAME, "[%s] handling request from outsider %s to room %s", FZONE, jid_full(jp->from), jid_full(room->id));

  /* any presence here is just fluff */
  if(jp->type == JPACKET_PRESENCE)
  {
    log_debug(NAME, "[%s] Dropping presence from outsider", FZONE);
    xmlnode_free(jp->x);
    return;
  }

  if(jp->type == JPACKET_MESSAGE)
  {
    log_debug(NAME, "[%s] Bouncing message from outsider", FZONE);
    jutil_error(jp->x, TERROR_FORBIDDEN);
    deliver(dpacket_new(jp->x), NULL);
    return;
  }

  /* public iq requests */
  if(jpacket_subtype(jp) == JPACKET__SET)
  {
    if(NSCHECK(jp->iq, NS_MUC_OWNER))
    {
      log_debug(NAME, "[%s] IQ Set for owner function", FZONE);

      if(from && is_owner(room, jp->from))
      {       
        xdata_room_config(room, from, room->locked, jp->x);

        jutil_iqresult(jp->x);
        deliver(dpacket_new(jp->x), NULL);
        return;
      }   
      else
      {
        log_debug(NAME, "[%s] IQ Set for owner disallowed", FZONE);
        jutil_error(jp->x, TERROR_NOTALLOWED);
        deliver(dpacket_new(jp->x), NULL);
        return;
      }
    }
    else if(NSCHECK(jp->iq, NS_REGISTER))
    {
      log_debug(NAME, "[%s] IQ Set for Registration function", FZONE);

      jutil_error(jp->x, TERROR_NOTALLOWED);
      deliver(dpacket_new(jp->x), NULL);
      return;
    }
  }

  if(jpacket_subtype(jp) == JPACKET__GET)
  {
    if(NSCHECK(jp->iq,NS_VERSION))
    {
      iq_get_version(jp);
      return;
    }
    else if(NSCHECK(jp->iq, NS_BROWSE))
    {
      _con_room_send_browse_reply(jp,room,0);
      return;
    }
    else if(NSCHECK(jp->iq, NS_DISCO_INFO))
    {
      if (xmlnode_get_attrib(jp->iq,"node")== NULL){
        log_debug(NAME, "[%s] Outside room packet - Disco Info Request", FZONE);
        _con_room_discoinfo(room, jp);
        return;
      }
      else {
        if (j_strcmp(xmlnode_get_attrib(jp->iq,"node"),"x-roomuser-item")==0)
        {
          log_debug(NAME, "[%s] Outside room packet - Nickname Discovery Request", FZONE);
          _con_room_disconick(room,jp);
          return;

        }
        else {
          //unknow node
          jutil_error(jp->x, TERROR_UNAVAIL);
          deliver(dpacket_new(jp->x),NULL);
          return;
        }
      }
    }
    else if(NSCHECK(jp->iq, NS_DISCO_ITEMS))
    {
      log_debug(NAME, "[%s] Outside room packet - Disco Items Request", FZONE);
      _con_room_discoitems(room, jp, 0);
      return;
    }
    else if(NSCHECK(jp->iq, NS_LAST))
    {
      log_debug(NAME, "[%s] Outside room packet - Last Request", FZONE);

      _con_room_send_last(jp,room);
      return;
    }
    else if(NSCHECK(jp->iq,NS_TIME))
    {
      /* Compliant with JEP-0090 */

      log_debug(NAME, "[%s] Server packet - Time Request", FZONE);

      iq_get_time(jp);
      return;
    }
    else if(NSCHECK(jp->iq, NS_MUC_OWNER))
    {
      if(j_strcmp(xmlnode_get_name(jp->iq),"query") == 0)
      {
        log_debug(NAME, "[%s] IQ Get for owner: configuration", FZONE);

        if(!from || !is_owner(room, from->realid))
        {
          jutil_error(jp->x, TERROR_BAD);
          deliver(dpacket_new(jp->x), NULL);
          return;
        }

        xdata_room_config(room, from, 0, jp->x);

        xmlnode_free(jp->x);
        return;
      }
    }
    else if(NSCHECK(jp->iq, NS_REGISTER))
    {
      log_debug(NAME, "[%s] IQ Get for Registration function", FZONE);

      jutil_error(jp->x, TERROR_NOTALLOWED);
      deliver(dpacket_new(jp->x), NULL);
      return;
    }
    else if(NSCHECK(jp->iq,NS_VCARD))
    {
      log_debug(NAME, "[%s] Outside room packet - VCard Request", FZONE);

      jutil_iqresult(jp->x);
      xmlnode_put_attrib(xmlnode_insert_tag(jp->x,"vCard"),"xmlns",NS_VCARD);
      jpacket_reset(jp);

      xmlnode_insert_cdata(xmlnode_insert_tag(jp->iq, "DESC"), room->description, -1);
      deliver(dpacket_new(jp->x),NULL);
      return;
    }
  }

  //if this is a subscription packet, drop silently
  if((jpacket_subtype(jp) == JPACKET__SUBSCRIBE) ||
      (jpacket_subtype(jp) == JPACKET__SUBSCRIBED) ||
      (jpacket_subtype(jp) == JPACKET__UNSUBSCRIBE) ||
      (jpacket_subtype(jp) == JPACKET__UNSUBSCRIBED) 
    )
  {
    log_debug(NAME,"[%s] dropping subscription packet", FZONE);
    xmlnode_free(jp->x);
    return;
  }

  log_debug(NAME, "[%s] Sending Not Implemented", FZONE);
  jutil_error(jp->x, TERROR_NOTIMPL);
  deliver(dpacket_new(jp->x), NULL);
  return;

}

void con_room_process(cnr room, cnu from, jpacket jp)
{
  char *nick = NULL;
  char *key;
  xmlnode result, item, x, node;
  jid id;
  int cont;

  pool hist_p;
  cnh hist;


  if(room == NULL || from == NULL) 
  {
    log_warn(NAME, "[%s] Aborting - NULL attribute found", FZONE);
    return;
  }

  log_debug(NAME, "[%s] handling request from participant %s (%s) to room %s", FZONE, jid_full(from->realid), from->localid->resource, jid_full(room->id));

  /* presence is just stored and forwarded */
  if(jp->type == JPACKET_PRESENCE)
  {
    xmlnode_free(from->presence);
    from->presence = xmlnode_dup(jp->x);

    jutil_delay(from->presence, NULL);

    xmlnode_put_vattrib(jp->x, "cnu", (void*)from);
    g_hash_table_foreach(room->local, con_room_sendwalk, (void*)jp->x);

    xmlnode_free(jp->x);
    return;
  }

  if(jp->type == JPACKET_MESSAGE)
  {
    if(NSCHECK(xmlnode_get_tag(jp->x,"x"),NS_MUC_USER))
    {
      /* Invite */
      log_debug(NAME, "[%s] Found invite request", FZONE);

      if(room->invitation == 1 && room->invites == 0 && !is_admin(room, from->realid))
      {
        log_debug(NAME, "[%s] Forbidden invitation request, returning error", FZONE);

        jutil_error(jp->x,TERROR_FORBIDDEN);
        deliver(dpacket_new(jp->x),NULL);
        return;
      }

      item = xmlnode_dup(xmlnode_get_tag(jp->x,"x"));
      nick = xmlnode_get_attrib(xmlnode_get_tag(item, "invite"), "to");

      if( nick == NULL)
      {
        log_debug(NAME, "[%s] No receipient, returning error", FZONE);

        jutil_error(jp->x,TERROR_BAD);
        deliver(dpacket_new(jp->x),NULL);

        xmlnode_free(item);
        return;
      }

      if(room->invitation == 1)
      {
        id = jid_new(xmlnode_pool(item), nick);

        key = j_strdup(jid_full(jid_user(jid_fix(id))));
        g_hash_table_insert(room->member, key, (void*)item);
      }
      else
      {
        xmlnode_free(item);
      }

      con_room_send_invite(from, xmlnode_get_tag(jp->x,"x"));
      return;
    }

    /* if topic, store it */
    if((x = xmlnode_get_tag(jp->x,"subject")) != NULL )
    {

      /* catch the invite hack */
      if((nick = xmlnode_get_data(x)) != NULL && j_strncasecmp(nick,"invite:",7) == 0)
      {
        nick += 7;
        if((jp->to = jid_new(jp->p, nick)) == NULL)
        {
          jutil_error(jp->x,TERROR_BAD);
        }else{
          xmlnode_put_attrib(jp->x, "to", jid_full(jp->to));
          jp->from = jid_new(jp->p, jid_full(from->localid));
          xmlnode_put_attrib(jp->x, "from", jid_full(jp->from));
        }
        deliver(dpacket_new(jp->x), NULL);
        return;
      }

      /* Disallow subject change if user does not have high enough level */
      if((!is_admin(room, from->realid) && room->subjectlock == 0) || is_visitor(room, from->realid) )
      {
        jutil_error(jp->x,TERROR_FORBIDDEN);
        deliver(dpacket_new(jp->x),NULL);
        return;
      }

      /* Save room topic for new users */
      xmlnode_free(room->topic);
      room->topic = xmlnode_new_tag("topic");
      xmlnode_put_attrib(room->topic, "subject", xmlnode_get_data(x));
      xmlnode_insert_cdata(room->topic, from->localid->resource, -1);
      xmlnode_insert_cdata(room->topic, " has set the topic to: ", -1);
      xmlnode_insert_cdata(room->topic, xmlnode_get_data(x), -1);

#ifdef HAVE_MYSQL
      sql_update_field(room->master->sql, jid_full(room->id), "topic", xmlnode_get_attrib(room->topic,"subject"));
#endif

      /* Save the room topic if room is persistent */
      if(room->persistent == 1)
      {
        xdb_room_set(room);
      }
    }

    /* Check if allowed to talk */
    if(room->moderated == 1 && !is_participant(room, from->realid))
    {
      /* Attempting to talk in a moderated room without voice intrinsic */
      jutil_error(jp->x,TERROR_MUC_VOICE);
      deliver(dpacket_new(jp->x),NULL);
      return;
    }

    if(jp->subtype != JPACKET__GROUPCHAT)
    {                                   
      jutil_error(jp->x, TERROR_BAD);                                    
      deliver(dpacket_new(jp->x), NULL);                                 
      return;                            
    }                                                                     

    /* ensure type="groupchat" */
    xmlnode_put_attrib(jp->x,"type","groupchat");

    /* check is the message is a discussion history */
    cont = 0;
    for( node = xmlnode_get_firstchild(jp->x); node != NULL; node = xmlnode_get_nextsibling(node)) {
      if (xmlnode_get_name(node)==NULL || strcmp("x",xmlnode_get_name(node))!=0) continue; // check if the node is a "x" node
      if(!NSCHECK(node, NS_DELAY)) continue;
      if ((xmlnode_get_attrib(node, "from")!= NULL) && (xmlnode_get_attrib(node, "stamp")) && (is_owner(room,from->realid))) {
        cont = 1;
        break;
      }

    }

    /* Save copy of packet for history */
    node = xmlnode_dup(jp->x);

    /* broadcast */
    xmlnode_put_vattrib(jp->x,"cnu",(void*)from);
    g_hash_table_foreach(room->local, con_room_sendwalk, (void*)jp->x);

    /* log */
    con_room_log(room, from->localid->resource, xmlnode_get_tag_data(jp->x, "body"));

    /* Save from address */
    if (cont == 0) {
      xmlnode_put_attrib(node, "from", jid_full(from->localid));
    }
    else {
      xmlnode_put_attrib(node, "from", jid_full(jid_user(from->localid)));
    }

    /* store in history */
    if (cont == 0)
      jutil_delay(node, jid_full(room->id));

    if(room->master->history > 0)
    {

      hist_p = pool_new();
      hist = pmalloco(hist_p, sizeof(_cnh));
      hist->p = hist_p;
      hist->x = node;
      hist->content_length = j_strlen(xmlnode_get_tag_data(node,"body"));
      hist->timestamp = time(NULL);

      if(++room->hlast == room->master->history)
        room->hlast = 0;

      if (room->history[room->hlast] != NULL)
      {
        log_debug(NAME, "[%s] clearing old history entry %d", FZONE, room->hlast);
        xmlnode_free(room->history[room->hlast]->x);
        pool_free(room->history[room->hlast]->p);
      }

      log_debug(NAME, "[%s] adding history entry %d", FZONE, room->hlast);
      room->history[room->hlast] = hist;
    }
    else
    {
      xmlnode_free(node);
    }

    xmlnode_free(jp->x);
    return;
  }

  /* public iq requests */

  if(jpacket_subtype(jp) == JPACKET__SET)
  {
    if(NSCHECK(jp->iq, NS_MUC_ADMIN))
    { 
      log_debug(NAME, "[%s] IQ Set for admin function: >%s<", FZONE, xmlnode_get_name(jp->iq));

      if(!is_moderator(room, from->realid))
      {
        jutil_error(jp->x, TERROR_FORBIDDEN);
        deliver(dpacket_new(jp->x), NULL);
        return;
      }

      if(j_strcmp(xmlnode_get_name(jp->iq), "query") == 0)
      {
        log_debug(NAME, "[%s] List set requested by admin...", FZONE);

        result = xmlnode_get_tag(jp->x, "query");

        if(NSCHECK(xmlnode_get_tag(result,"x"),NS_DATA))
        {
          log_debug(NAME, "[%s] Received x:data", FZONE);
          jutil_error(jp->x, TERROR_BAD);
          deliver(dpacket_new(jp->x), NULL);
          return;
        }
        else
        {
          con_parse_item(from, jp);
          return;
        }
      }
    }
    else if(NSCHECK(jp->iq, NS_MUC_OWNER))
    {
      if(!is_owner(room, from->realid))
      {   
        jutil_error(jp->x, TERROR_NOTALLOWED);
        deliver(dpacket_new(jp->x), NULL);
        return;
      }

      if(j_strcmp(xmlnode_get_name(jp->iq),"query") == 0)
      {

        result = xmlnode_get_tag(jp->x, "query");
        node = xmlnode_get_tag(result, "destroy");

        if(node)
        {
          log_debug(NAME, "[%s] IQ Set for owner: destroy requested", FZONE);
          /* Remove old xdb registration */
          if(room->persistent == 1)
          {
            xdb_room_clear(room);
          }

          /* inform everyone they have left the room */
          g_hash_table_foreach(room->remote, con_room_leaveall, node);

          con_room_zap(room);
          jutil_iqresult(jp->x);
          deliver(dpacket_new(jp->x), NULL);
          return;
        }
        else if(NSCHECK(xmlnode_get_tag(result,"x"),NS_DATA))
        {
          log_debug(NAME, "[%s] Received x:data", FZONE);
          #ifdef HAVE_MYSQL
          if (xdata_handler(room, from, jp)>0)
            sql_update_room_config(room->master->sql,room);
          #else
          xdata_handler(room, from, jp);
          #endif

          jutil_iqresult(jp->x);
          deliver(dpacket_new(jp->x), NULL);
          return;
        }
        else
        {
          log_debug(NAME, "[%s] IQ Set for owner: configuration set", FZONE);
          con_parse_item(from, jp);
          return;
        }
      }
      else
      {
        jutil_error(jp->x, TERROR_BAD);
        deliver(dpacket_new(jp->x), NULL);
        return;
      }
    }
    else if(NSCHECK(jp->iq, NS_REGISTER))
    {
      log_debug(NAME, "[%s] IQ Set for Registration function", FZONE);

      jutil_error(jp->x, TERROR_NOTALLOWED);
      deliver(dpacket_new(jp->x), NULL);
      return;
    }

    jutil_error(jp->x, TERROR_BAD);
    deliver(dpacket_new(jp->x), NULL);
    return;
  }

  if(jpacket_subtype(jp) == JPACKET__GET)
  {
    if(NSCHECK(jp->iq,NS_VERSION))
    {
      iq_get_version(jp);
      return;
    }
    else if(NSCHECK(jp->iq, NS_BROWSE))
    {
      _con_room_send_browse_reply(jp,room,1);
      return;
    }
    else if(NSCHECK(jp->iq, NS_DISCO_INFO))
    {
      if (xmlnode_get_attrib(jp->iq,"node")==NULL) {
        log_debug(NAME, "[%s] room packet - Disco Info Request", FZONE);

        _con_room_discoinfo(room, jp);
        return;
      }
      else {
        if (j_strcmp(xmlnode_get_attrib(jp->iq,"node"),"x-roomuser-item")==0)
        {
          log_debug(NAME, "[%s] room packet - Nickname Discovery Request", FZONE);
          _con_room_disconick(room,jp);
          return;

        }
        else {
          jutil_error(jp->x, TERROR_UNAVAIL);
          deliver(dpacket_new(jp->x),NULL);
          return;  
        }
      }
    }
    else if(NSCHECK(jp->iq, NS_DISCO_ITEMS))
    {
      log_debug(NAME, "[%s] room packet - Disco Items Request", FZONE);
      _con_room_discoitems(room, jp, 1);
      return;
    }
    else if(NSCHECK(jp->iq, NS_LAST))
    {
      log_debug(NAME, "[%s] room packet - Last Request", FZONE);

      _con_room_send_last(jp,room);
      return;
    }
    else if(NSCHECK(jp->iq,NS_TIME))
    {
      /* Compliant with JEP-0090 */

      log_debug(NAME, "[%s] Server packet - Time Request", FZONE);

      iq_get_time(jp);
      return;
    }
    else if(NSCHECK(jp->iq, NS_MUC_ADMIN))
    {
      log_debug(NAME, "[%s] IQ Get for admin function, %s", FZONE, xmlnode_get_name(jp->iq));

      if(!is_moderator(room, from->realid))
      {
        jutil_error(jp->x, TERROR_FORBIDDEN);
        deliver(dpacket_new(jp->x), NULL);
        return;
      }

      if(j_strcmp(xmlnode_get_name(jp->iq),"query") == 0)
      {
        con_parse_item(from, jp);
        return;
      }
    }
    else if(NSCHECK(jp->iq, NS_MUC_OWNER))
    {
      log_debug(NAME, "[%s] IQ Get for owner function, %s", FZONE, xmlnode_get_name(jp->iq));

      if(!is_owner(room, from->realid))
      {
        jutil_error(jp->x, TERROR_FORBIDDEN);
        deliver(dpacket_new(jp->x), NULL);
        return;
      }

      if(j_strcmp(xmlnode_get_name(jp->iq),"query") == 0)
      {
        con_parse_item(from, jp);
        return;
      }
    }
    else if(NSCHECK(jp->iq, NS_REGISTER))
    {
      log_debug(NAME, "[%s] IQ Get for Registration function", FZONE);

      jutil_error(jp->x, TERROR_NOTALLOWED);
      deliver(dpacket_new(jp->x), NULL);
      return;
    }
    else if(NSCHECK(jp->iq,NS_VCARD))
    {
      log_debug(NAME, "[%s] room packet - VCard Request", FZONE);

      jutil_iqresult(jp->x);
      xmlnode_put_attrib(xmlnode_insert_tag(jp->x, "vCard"), "xmlns", NS_VCARD);
      jpacket_reset(jp);

      xmlnode_insert_cdata(xmlnode_insert_tag(jp->iq, "DESC"), room->description, -1);
      deliver(dpacket_new(jp->x),NULL);
      return;
    }
  }
  //if this is a subscription packet, drop silently
  if((jpacket_subtype(jp) == JPACKET__SUBSCRIBE) ||
      (jpacket_subtype(jp) == JPACKET__SUBSCRIBED) ||
      (jpacket_subtype(jp) == JPACKET__UNSUBSCRIBE) ||
      (jpacket_subtype(jp) == JPACKET__UNSUBSCRIBED) 
    )
  {
    log_debug(NAME,"[%s] dropping subscription packet", FZONE);
    xmlnode_free(jp->x);
    return;
  }

  log_debug(NAME, "[%s] Sending Bad Request", FZONE);
  jutil_error(jp->x, TERROR_BAD);
  deliver(dpacket_new(jp->x), NULL);
  return;

}

cnr con_room_new(cni master, jid roomid, jid owner, char *name, char *secret, int private, int persist)
{
  cnr room;
  pool p;
  cnu admin;
  char *key;
  time_t now = time(NULL);

  /* Create pool for room struct */
  p = pool_new(); 
  room = pmalloco(p, sizeof(_cnr));
  log_debug(NAME, "[%s] Malloc: _cnr = %d", FZONE, sizeof(_cnr));
  room->p = p;
  room->master = master;

  /* room jid */
  room->id = jid_new(p, jid_full(jid_fix(roomid)));

  /* room natural language name for browse/disco */
  if(name)
    room->name = j_strdup(name);
  else
    room->name = j_strdup(room->id->user);

  /* room password */
  room->secret = j_strdup(secret);
  room->private = private;

  /* lock nicknames - defaults to off (unless overridden by master setting) */
  room->locknicks = 0;

  /* Initialise room history */
  room->history = pmalloco(p, sizeof(_cnh) * master->history); /* make array of xmlnodes */
  log_debug(NAME, "[%s] Malloc: history = %d", FZONE, sizeof(_cnh) * master->history);

  /* Room time */
  room->start = now;
  room->created = now;

  /* user hashes */
  room->remote = g_hash_table_new_full(g_str_hash,g_str_equal, ght_remove_key, ght_remove_cnu);
  room->local = g_hash_table_new_full(g_str_hash,g_str_equal, NULL, NULL);
  room->roster = g_hash_table_new_full(g_str_hash,g_str_equal, ght_remove_key, ght_remove_xmlnode);

  /* Affiliated hashes */
  room->owner = g_hash_table_new_full(g_str_hash,g_str_equal, ght_remove_key, ght_remove_xmlnode);
  room->admin = g_hash_table_new_full(g_str_hash,g_str_equal, ght_remove_key, ght_remove_xmlnode);
  room->member = g_hash_table_new_full(g_str_hash,g_str_equal, ght_remove_key, ght_remove_xmlnode);
  room->outcast = g_hash_table_new_full(g_str_hash,g_str_equal, ght_remove_key, ght_remove_xmlnode);

  /* Role hashes */
  room->moderator = g_hash_table_new_full(g_str_hash,g_str_equal, ght_remove_key, NULL);
  room->participant = g_hash_table_new_full(g_str_hash,g_str_equal, ght_remove_key, NULL);

  /* Room messages */
  room->note_leave = j_strdup(xmlnode_get_tag_data(master->config,"notice/leave"));
  room->note_join = j_strdup(xmlnode_get_tag_data(master->config,"notice/join"));
  room->note_rename = j_strdup(xmlnode_get_tag_data(master->config,"notice/rename"));

  /* Room Defaults */
  room->public = master->public;
  room->subjectlock = 0;
  room->maxusers = 30;
  room->persistent = persist;
  room->moderated = 0;
  room->defaulttype = 0;
  room->privmsg = 0;
  room->invitation = 0;
  room->invites = 0;
  room->legacy = 0;
  room->visible = 0;
  room->logfile = NULL;
  room->logformat = LOG_TEXT;
  room->description = j_strdup(room->name);

  /* Assign owner to room */
  if(owner != NULL)
  {
    admin = (void*)con_user_new(room, owner);
    add_roster(room, admin->realid);

    room->creator = jid_new(room->p, jid_full(jid_user(admin->realid)));

    add_affiliate(room->owner, admin->realid, NULL);

    log_debug(NAME, "[%s] Added new admin: %s to room %s", FZONE, jid_full(jid_fix(owner)), jid_full(room->id));
  }

  key = j_strdup(jid_full(room->id));
  g_hash_table_insert(master->rooms, key, (void*)room);

  log_debug(NAME,"[%s] new room %s (%s/%s/%d)", FZONE, jid_full(room->id),name,secret,private);

  /* Save room configuration if persistent */
  if(room->persistent == 1)
  {
    xdb_room_set(room);
  }

#ifdef HAVE_MYSQL
  sql_insert_room_config(master->sql, room);
  sql_add_room_lists(master->sql, room);
#endif

  return room;
}

void _con_room_send(gpointer key, gpointer data, gpointer arg)
{
  cnu user = (cnu)data;
  xmlnode x = (xmlnode)arg;
  xmlnode output;

  if(user == NULL || x == NULL) 
  {
    log_warn(NAME, "[%s] Aborting - NULL attribute found", FZONE);
    return;
  }

  output = xmlnode_dup((xmlnode)x);

  xmlnode_put_attrib(output, "to", jid_full(user->realid));
  deliver(dpacket_new(output), NULL);
  return;
}

void _con_room_send_legacy(gpointer key, gpointer data, gpointer arg)
{
  cnu user = (cnu)data;
  xmlnode x = (xmlnode)arg;
  xmlnode output;

  if(user == NULL || x == NULL) 
  {
    log_warn(NAME, "[%s] Aborting - NULL attribute found", FZONE);
    return;
  }

  if(!is_legacy(user))
    return;

  output = xmlnode_dup((xmlnode)x);

  xmlnode_put_attrib(output, "to", jid_full(user->realid));
  deliver(dpacket_new(output), NULL);
  return;
}


void con_room_send(cnr room, xmlnode x, int legacy)
{
  if(room == NULL || x == NULL) 
  {
    log_warn(NAME, "[%s] Aborting - NULL attribute found", FZONE);
    return;
  }

  log_debug(NAME,"[%s] Sending packet from room %s: %s", FZONE, jid_full(room->id), xmlnode2str(x));

  /* log */
  con_room_log(room, NULL, xmlnode_get_tag_data(x, "body"));

  xmlnode_put_attrib(x, "from", jid_full(room->id));

  deliver__flag = 0;

  if(legacy)
    g_hash_table_foreach(room->local, _con_room_send_legacy, (void*)x);
  else
    g_hash_table_foreach(room->local, _con_room_send, (void*)x);
  deliver__flag = 1;
  deliver(NULL, NULL);

  xmlnode_free(x);
  return;
}

/* Clear up room hashes */
void con_room_cleanup(cnr room)
{
  char *roomid;

  if(room == NULL) 
  {
    log_warn(NAME, "[%s] Aborting - NULL room attribute found", FZONE);
    return;
  }

  roomid = j_strdup(jid_full(room->id));

  log_debug(NAME, "[%s] cleaning room %s", FZONE, roomid);

  /* Clear old hashes */
  log_debug(NAME, "[%s] zapping list remote in room %s", FZONE, roomid);
  g_hash_table_destroy(room->remote);

  log_debug(NAME, "[%s] zapping list local in room %s", FZONE, roomid);
  g_hash_table_destroy(room->local);

  log_debug(NAME, "[%s] zapping list roster in room %s", FZONE, roomid);
  g_hash_table_destroy(room->roster);

  log_debug(NAME, "[%s] zapping list owner in room %s", FZONE, roomid);
  g_hash_table_destroy(room->owner);

  log_debug(NAME, "[%s] zapping list admin in room %s", FZONE, roomid);
  g_hash_table_destroy(room->admin);

  log_debug(NAME, "[%s] zapping list member in room %s", FZONE, roomid);
  g_hash_table_destroy(room->member);

  log_debug(NAME, "[%s] zapping list outcast in room %s", FZONE, roomid);
  g_hash_table_destroy(room->outcast);

  log_debug(NAME, "[%s] zapping list moderator in room %s", FZONE, roomid);
  g_hash_table_destroy(room->moderator);

  log_debug(NAME, "[%s] zapping list participant in room %s", FZONE, roomid);
  g_hash_table_destroy(room->participant);

  log_debug(NAME, "[%s] closing room log in room %s", FZONE, roomid);
  if(room->logfile && room->logfile != NULL)
    fclose(room->logfile);

  log_debug(NAME, "[%s] Clearing any history in room %s", FZONE, roomid);
  con_room_history_clear(room);

  log_debug(NAME, "[%s] Clearing topic in room %s", FZONE, roomid);
  xmlnode_free(room->topic);

  log_debug(NAME, "[%s] Clearing strings and legacy messages in room %s", FZONE, roomid);
  free(room->name);
  free(room->description);
  free(room->secret);
  free(room->note_join);
  free(room->note_rename);
  free(room->note_leave);

  free(roomid);
  return;
}

/* Zap room entry */
void con_room_zap(cnr room)
{
  if(room == NULL) 
  {
    log_warn(NAME, "[%s] Aborting - NULL room attribute found", FZONE);
    return;
  }

  log_debug(NAME, "[%s] cleaning up room %s", FZONE, jid_full(room->id));

  con_room_cleanup(room);

#ifdef HAVE_MYSQL
  sql_destroy_room(room->master->sql, jid_full(room->id));
#endif

  log_debug(NAME, "[%s] zapping room %s from list and freeing pool", FZONE, jid_full(room->id));

  g_hash_table_remove(room->master->rooms, jid_full(room->id));
  return;
}

void con_room_history_clear(cnr room)
{
  int h;

  if(room->master->history > 0)
  {

    h = room->hlast;

    while(1)
    {
      h++;

      if(h == room->master->history)
        h = 0;

      if (room->history[h] != NULL)
      {
        log_debug(NAME, "[%s] Clearing history entry %d", FZONE, h);
        xmlnode_free(room->history[h]->x);
        pool_free(room->history[h]->p);
      }
      else
      {
        log_debug(NAME, "[%s] skipping history entry %d", FZONE, h);
      }

      if(h == room->hlast)
        break;
    }
  }

}
