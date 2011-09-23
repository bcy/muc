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
#include "fields.h"

static void add_xdata_boolean(xmlnode parent, char *label, char *var, int data)
{
  xmlnode node;
  char value[4];

  snprintf(value, 4, "%i", data);
  node = xmlnode_insert_tag(parent, "field");
  xmlnode_put_attrib(node,"type","boolean");
  xmlnode_put_attrib(node,"label", label);
  xmlnode_put_attrib(node,"var", var);
  xmlnode_insert_cdata(xmlnode_insert_tag(node,"value"), value, -1);
}

static void add_xdata_text(xmlnode parent, char *label, int type, char *var, char *data)
{
  xmlnode node;

  node = xmlnode_insert_tag(parent, "field");

  if(type > 1)
    xmlnode_put_attrib(node,"type","text-multi");
  else if(type == 1)
    xmlnode_put_attrib(node,"type","text-single");
  else if(type == -1)
    xmlnode_put_attrib(node,"type","text-private");
  else
    xmlnode_put_attrib(node,"type","hidden");

  if(label != NULL)
    xmlnode_put_attrib(node,"label", label);

  xmlnode_put_attrib(node,"var", var);
  xmlnode_insert_cdata(xmlnode_insert_tag(node,"value"), data, -1);
}

static void add_xdata_desc(xmlnode parent, char *label)
{
  xmlnode node;

  node = xmlnode_insert_tag(parent, "field");
  xmlnode_put_attrib(node,"type","fixed");
  xmlnode_insert_cdata(xmlnode_insert_tag(node,"value"), label, -1);
}

//return 1 if configuration may have changed
int xdata_handler(cnr room, cnu user, jpacket packet)
{
  xmlnode results, element, value, current, node, message;

  pool tp = pool_new();
  spool sp = spool_new(tp);
  int visible = room->visible;
  char namespace[100];
  char var[100];
  char var_secret[100];
  char var_protected[100];

  log_debug(NAME, "[%s] xdata handler", FZONE);
  results = xmlnode_get_tag(packet->x,"x");

  /* Can't find xdata - trying NS_MUC_ADMIN namespace */
  if(results == NULL)
  {
    snprintf(namespace, 100, "?xmlns=%s", NS_MUC_ADMIN);
    element = xmlnode_get_tag(packet->x, namespace);
    results = xmlnode_get_tag(element,"x");
  }

  /* Still no data, try NS_MUC_OWNER namespace */
  if(results == NULL)
  {
    snprintf(namespace, 100, "?xmlns=%s", NS_MUC_OWNER);
    element = xmlnode_get_tag(packet->x, namespace);
    results = xmlnode_get_tag(element,"x");
  }

  /* Still no data, try NS_MUC_USER namespace */
  if(results == NULL)
  {
    snprintf(namespace, 100, "?xmlns=%s", NS_MUC_USER);
    element = xmlnode_get_tag(packet->x, namespace);
    results = xmlnode_get_tag(element,"x");
  }

  /* Still no xdata, just leave */
  if(results == NULL)
  {
    log_debug(NAME, "[%s] No xdata results found", FZONE);
    pool_free(tp);
    return 0;
  }

  if(j_strcmp(xmlnode_get_attrib(results, "type"), "cancel") == 0)
  {
    log_debug(NAME, "[%s] xdata form was cancelled", FZONE);

    /* If form cancelled and room locked, this is declaration of room destroy request */
    if(room->locked == 1)
    {
      if(room->persistent == 1)
        xdb_room_clear(room);

      g_hash_table_foreach(room->remote, con_room_leaveall, (void*)NULL);
      con_room_zap(room);
    }
    pool_free(tp);
    return 0;
  }

  value = xmlnode_get_tag(results,"?var=form");
  log_debug(NAME, "[%s] Form type: %s", FZONE, xmlnode_get_tag_data(value,"value"));

  if(is_admin(room, user->realid))
  {
    log_debug(NAME, "[%s] Processing configuration form", FZONE);

    /* Clear any room locks */
    if(room->locked == 1)
    {
      message = jutil_msgnew("groupchat", jid_full(user->realid), NULL, spools(packet->p, "Configuration confirmed: This room is now unlocked.", packet->p));
      xmlnode_put_attrib(message,"from", jid_full(room->id));
      deliver(dpacket_new(message), NULL);

      room->locked = 0;
    }

    /* Protect text forms from broken clients */
    snprintf(var, 100, "?var=%s", FIELD_NAME);
    if(xmlnode_get_tag(results,var) != NULL)
    {
      free(room->name);
      room->name = j_strdup(xmlnode_get_tag_data(xmlnode_get_tag(results,var),"value"));
    }
    snprintf(var, 100, "?var=%s", FIELD_LEAVE);
    if(xmlnode_get_tag(results,var) != NULL)
    {
      free(room->note_leave);
      room->note_leave = j_strdup(xmlnode_get_tag_data(xmlnode_get_tag(results,var),"value"));
    }
    snprintf(var, 100, "?var=%s", FIELD_JOIN);
    if(xmlnode_get_tag(results,var) != NULL)
    {
      free(room->note_join);
      room->note_join = j_strdup(xmlnode_get_tag_data(xmlnode_get_tag(results,var),"value"));
    }
    snprintf(var, 100, "?var=%s", FIELD_RENAME);
    if(xmlnode_get_tag(results,var) != NULL)
    {
      free(room->note_rename);
      room->note_rename = j_strdup(xmlnode_get_tag_data(xmlnode_get_tag(results,var),"value"));
    }

    /* Handle text-multi */
    snprintf(var, 100, "?var=%s", FIELD_DESC);
    if((node = xmlnode_get_tag(results,var)) != NULL)
    {
      for(current = xmlnode_get_firstchild(node); current != NULL; current = xmlnode_get_nextsibling(current))
      {
        //We don't want blank line at end or begining of the field. It's in fact just an hack to avoid that mu-conference add blank line at the begining and the end of the field.
        if (((xmlnode_get_nextsibling(current) == NULL) || (xmlnode_get_prevsibling(current) == NULL)) && current->type != NTYPE_TAG) continue;
        spooler(sp, xmlnode_get_data(current), sp);
      }

      free(room->description);
      room->description = j_strdup(spool_print(sp));
    }

    /* Update with results from form if available. If unable, simply use the original value */
    snprintf(var, 100, "?var=%s", FIELD_ALLOW_SUBJECT);
    room->subjectlock = j_atoi(xmlnode_get_tag_data(xmlnode_get_tag(results,var),"value"), room->subjectlock);
    snprintf(var, 100, "?var=%s", FIELD_PRIVACY);
    room->private = j_atoi(xmlnode_get_tag_data(xmlnode_get_tag(results,var),"value"),room->private);
    snprintf(var, 100, "?var=%s", FIELD_PUBLIC);
    room->public = j_atoi(xmlnode_get_tag_data(xmlnode_get_tag(results,var),"value"),room->public);
    snprintf(var, 100, "?var=%s", FIELD_MAX_USERS);
    room->maxusers = j_atoi(xmlnode_get_tag_data(xmlnode_get_tag(results,var),"value"),room->maxusers);

    if(room->master->dynamic == 0 || is_sadmin(room->master, user->realid))
    {
      snprintf(var, 100, "?var=%s", FIELD_PERSISTENT);
      room->persistent = j_atoi(xmlnode_get_tag_data(xmlnode_get_tag(results,var),"value"),room->persistent);
    }
    
    snprintf(var, 100, "?var=%s", FIELD_MODERATED);
    room->moderated = j_atoi(xmlnode_get_tag_data(xmlnode_get_tag(results,var),"value"),room->moderated);
    snprintf(var, 100, "?var=%s", FIELD_DEFAULT_TYPE);
    room->defaulttype = j_atoi(xmlnode_get_tag_data(xmlnode_get_tag(results,var),"value"),room->defaulttype);
    snprintf(var, 100, "?var=%s", FIELD_PRIVATE_MSG);
    room->privmsg = j_atoi(xmlnode_get_tag_data(xmlnode_get_tag(results,var),"value"),room->privmsg);

    /* Nicknames locked ? Allow owner to choose if master->locknicks != 0 */
    if (!room->master->locknicks) 
    {
      snprintf(var, 100, "?var=%s", FIELD_LOCK_NICK);
      room->locknicks = j_atoi(xmlnode_get_tag_data(xmlnode_get_tag(results,var),"value"),room->locknicks);
    }
    snprintf(var, 100, "?var=%s", FIELD_MEMBERS_ONLY);
    room->invitation = j_atoi(xmlnode_get_tag_data(xmlnode_get_tag(results,var),"value"),room->invitation);
    snprintf(var, 100, "?var=%s", FIELD_ALLOW_INVITE);
    room->invites = j_atoi(xmlnode_get_tag_data(xmlnode_get_tag(results,var),"value"),room->invites);
    snprintf(var, 100, "?var=%s", FIELD_LEGACY);
    room->legacy = j_atoi(xmlnode_get_tag_data(xmlnode_get_tag(results,var),"value"),room->legacy);

    /* Protection against broken clients */
    snprintf(var_protected, 100, "?var=%s", FIELD_PASS_PROTECTED);
    snprintf(var_secret, 100, "?var=%s", FIELD_PASS);
    if(xmlnode_get_tag(results,var_protected) != NULL && xmlnode_get_tag(results, var_secret) != NULL)
    {
      /* Is both password set and active? */
      if(j_strcmp(xmlnode_get_tag_data(xmlnode_get_tag(results,var_protected),"value"), "1") == 0 && xmlnode_get_tag_data(xmlnode_get_tag(results,var_secret),"value") != NULL)
      {
        free(room->secret);
        room->secret = j_strdup(xmlnode_get_tag_data(xmlnode_get_tag(results,var_secret),"value"));
        log_debug(NAME ,"[%s] Switching on room password: %s", FZONE, room->secret);
      }
      else 
      {
        log_debug(NAME, "[%s] Deactivating room password: %s %s", FZONE, xmlnode_get_tag_data(xmlnode_get_tag(results,var_protected),"value"), xmlnode_get_tag_data(xmlnode_get_tag(results,var_secret),"value"));
        free(room->secret);
        room->secret = NULL;
      }
    }

    snprintf(var, 100, "?var=%s", FIELD_WHOIS);
    if(j_strcmp(xmlnode_get_tag_data(xmlnode_get_tag(results,var),"value"), "anyone") == 0)
      room->visible = 1;
    else
      room->visible = 0;

    /* Send Status Alert */
    if(room->visible == 1 && room->visible != visible)
      con_send_room_status(room, STATUS_MUC_NON_ANONYM);
    else if(room->visible == 0 && room->visible != visible)
      con_send_room_status(room, STATUS_MUC_SEMI_ANONYM);

    /* Set up log format and restart logging if necessary */
    if (room->master->logsEnabled) {
      snprintf(var, 100, "?var=%s", FIELD_LOG_FORMAT);
      if(xmlnode_get_tag(results,var))
      {
        if(j_strcmp(xmlnode_get_tag_data(xmlnode_get_tag(results,var),"value"), "xml") == 0)
        {
          if(room->logfile != NULL && room->logformat != LOG_XML)
          {
            fclose(room->logfile);
            room->logformat = LOG_XML;
            con_room_log_new(room);
          }
          else
          {
            room->logformat = LOG_XML;
          }
        }
        else if(j_strcmp(xmlnode_get_tag_data(xmlnode_get_tag(results,var),"value"), "xhtml") == 0)
        {
          if(room->logfile != NULL && room->logformat != LOG_XHTML)
          {
            fclose(room->logfile);
            room->logformat = LOG_XHTML;
            con_room_log_new(room);
          }
          else
          {
            room->logformat = LOG_XHTML;
          }
        }
        else
        {
          if(room->logfile != NULL && room->logformat != LOG_TEXT)
          {
            fclose(room->logfile);
            room->logformat = LOG_TEXT;
            con_room_log_new(room);
          }
          else
          {
            room->logformat = LOG_TEXT;
          }
        }
      }

      /* Set up room logging */
      snprintf(var, 100, "?var=%s", FIELD_ENABLE_LOGGING);
      if(room->logfile == NULL && j_strcmp(xmlnode_get_tag_data(xmlnode_get_tag(results,var),"value"),"1") == 0)
      {

        con_room_log_new(room);

        if (room->logfile == NULL)
          log_alert(NULL, "cannot open log file for room %s", jid_full(room->id));
        else
        {
          con_room_log(room, NULL, "LOGGING STARTED");
          con_send_room_status(room, STATUS_MUC_LOGGING_ON);
        }
      }

      if(room->logfile != NULL && j_strcmp(xmlnode_get_tag_data(xmlnode_get_tag(results,var),"value"),"0") == 0)
      {
        con_room_log(room, NULL, "LOGGING STOPPED");
        con_room_log_close(room);
        con_send_room_status(room, STATUS_MUC_LOGGING_OFF);
      }
    }

    if(room->persistent == 1)
    {
      xdb_room_set(room);
    }
    else
    {
      xdb_room_clear(room);
    }
  }
  pool_free(tp);
  return 1;
}

void xdata_room_config(cnr room, cnu user, int new, xmlnode query)
{
  xmlnode msg, iq, element, field, x;
  char value[4];

  if(user == NULL)
  {
    log_warn(NAME, "[%s] NULL attribute found", FZONE);
    return;
  }

  log_debug(NAME, "[%s] Configuration form requested by %s", FZONE, jid_full(user->realid));

  if(!is_owner(room, user->realid))
  {
    log_debug(NAME, "[%s] Configuration form request denied", FZONE);

    if(query != NULL)
    {
      jutil_error(query,TERROR_MUC_CONFIG);
      deliver(dpacket_new(query),NULL);
    }   

    return;
  }   

  /* Lock room for IQ Registration method. Will release lock when config received */
  if(new == 1)
    room->locked = 1;

  /* Catchall code, for creating a standalone form */
  if( query == NULL )
  {
    msg = xmlnode_new_tag("message");
    xmlnode_put_attrib(msg, "to", jid_full(user->realid));
    xmlnode_put_attrib(msg,"from",jid_full(room->id));
    xmlnode_put_attrib(msg,"type","normal");

    xmlnode_insert_cdata(xmlnode_insert_tag(msg,"subject"),"Please setup your room",-1);

    element = xmlnode_insert_tag(msg,"body");
    xmlnode_insert_cdata(element,"Channel ",-1);
    xmlnode_insert_cdata(element,room->id->user,-1);

    if(new == 1)
      xmlnode_insert_cdata(element," has been created",-1);
    else    
      xmlnode_insert_cdata(element," configuration setting",-1);

    x = xmlnode_insert_tag(msg,"x");
  }           
  else
  {
    msg = xmlnode_dup(query);
    jutil_iqresult(msg);
    iq = xmlnode_insert_tag(msg,"query");
    xmlnode_put_attrib(iq, "xmlns", NS_MUC_OWNER);

    x = xmlnode_insert_tag(iq,"x");
  }

  xmlnode_put_attrib(x,"xmlns",NS_DATA);
  xmlnode_put_attrib(x,"type","form");
  xmlnode_insert_cdata(xmlnode_insert_tag(x,"title"),"Room configuration",-1);

  if(new == 1)
  {
    field = xmlnode_insert_tag(x,"instructions");
    xmlnode_insert_cdata(field,"Your room \"",-1);
    xmlnode_insert_cdata(field,room->id->user,-1);
    xmlnode_insert_cdata(field,"\" has been created! The default configuration is as follows:\n", -1);

    if(room->logfile == NULL)
      xmlnode_insert_cdata(field,"- No logging\n", -1);
    else
      xmlnode_insert_cdata(field,"- logging\n", -1);

    if(room->moderated == 1)
      xmlnode_insert_cdata(field,"- Room moderation\n", -1);
    else
      xmlnode_insert_cdata(field,"- No moderation\n", -1);

    if(room->maxusers > 0)
    {
      snprintf(value, 4, "%i", room->maxusers);
      xmlnode_insert_cdata(field,"- Up to ", -1);
      xmlnode_insert_cdata(field, value, -1); 
      xmlnode_insert_cdata(field, " participants\n", -1);
    }
    else
    {
      xmlnode_insert_cdata(field,"- Unlimited room size\n", -1);
    }

    if(room->secret == NULL)
      xmlnode_insert_cdata(field,"- No password required\n", -1);
    else
      xmlnode_insert_cdata(field,"- Password required\n", -1);

    if(room->invitation == 0)
      xmlnode_insert_cdata(field,"- No invitation required\n", -1);
    else
      xmlnode_insert_cdata(field,"- Invitation required\n", -1);

    if(room->persistent == 0)
      xmlnode_insert_cdata(field,"- Room is not persistent\n", -1);
    else
      xmlnode_insert_cdata(field,"- Room is persistent\n", -1);

    if(room->subjectlock == 0)
      xmlnode_insert_cdata(field,"- Only admins may change the subject\n", -1);
    else
      xmlnode_insert_cdata(field,"- Anyone may change the subject\n", -1);

    xmlnode_insert_cdata(field,"To accept the default configuration, click OK. To select a different configuration, please complete this form", -1);
  }
  else
    xmlnode_insert_cdata(xmlnode_insert_tag(x,"instructions"),"Complete this form to make changes to the configuration of your room.",-1);

  add_xdata_text(x, NULL, 0, "FORM_TYPE", NS_MUC_ROOMCONFIG);
  add_xdata_text(x, "Natural-Language Room Name", 1, FIELD_NAME, room->name);
  add_xdata_text(x, "Short Description of Room", 2, FIELD_DESC, room->description);

  add_xdata_desc(x, "The following messages are sent to legacy clients.");
  add_xdata_text(x, "Message for user leaving room", 1, FIELD_LEAVE, room->note_leave);
  add_xdata_text(x, "Message for user joining room", 1, FIELD_JOIN, room->note_join);
  add_xdata_text(x, "Message for user renaming nickname in room", 1, FIELD_RENAME, room->note_rename);

  add_xdata_boolean(x, "Allow Occupants to Change Subject", FIELD_ALLOW_SUBJECT, room->subjectlock);

  field = xmlnode_insert_tag(x,"field");
  xmlnode_put_attrib(field,"type","list-single");
  xmlnode_put_attrib(field,"label","Maximum Number of Room Occupants");
  xmlnode_put_attrib(field,"var", FIELD_MAX_USERS);
  snprintf(value, 4, "%i", room->maxusers);
  xmlnode_insert_cdata(xmlnode_insert_tag(field, "value"), value, -1);

  element = xmlnode_insert_tag(field, "option");
  xmlnode_put_attrib(element, "label", "1");
  xmlnode_insert_cdata(xmlnode_insert_tag(element, "value"), "1", -1);
  element = xmlnode_insert_tag(field, "option");
  xmlnode_put_attrib(element, "label", "10");
  xmlnode_insert_cdata(xmlnode_insert_tag(element, "value"), "10", -1);
  element = xmlnode_insert_tag(field, "option");
  xmlnode_put_attrib(element, "label", "20");
  xmlnode_insert_cdata(xmlnode_insert_tag(element, "value"), "20", -1);
  element = xmlnode_insert_tag(field, "option");
  xmlnode_put_attrib(element, "label", "30");
  xmlnode_insert_cdata(xmlnode_insert_tag(element, "value"), "30", -1);
  element = xmlnode_insert_tag(field, "option");
  xmlnode_put_attrib(element, "label", "40");
  xmlnode_insert_cdata(xmlnode_insert_tag(element, "value"), "40", -1);
  element = xmlnode_insert_tag(field, "option");
  xmlnode_put_attrib(element, "label", "50");
  xmlnode_insert_cdata(xmlnode_insert_tag(element, "value"), "50", -1);
  element = xmlnode_insert_tag(field, "option");
  xmlnode_put_attrib(element, "label", "None");
  xmlnode_insert_cdata(xmlnode_insert_tag(element, "value"), "0", -1);

  if (!room->master->locknicks)
    add_xdata_boolean(x, "Lock nicknames to JID usernames?", FIELD_LOCK_NICK, room->locknicks);

  add_xdata_boolean(x, "Allow Occupants to query other Occupants?", FIELD_PRIVACY, room->private);
  add_xdata_boolean(x, "Allow Public Searching for Room", FIELD_PUBLIC, room->public);

  if(room->master->dynamic == 0 || is_sadmin(room->master, user->realid))
    add_xdata_boolean(x, "Make Room Persistent", FIELD_PERSISTENT, room->persistent);

  add_xdata_boolean(x, "Consider all Clients as Legacy (shown messages)", FIELD_LEGACY, room->legacy);
  add_xdata_boolean(x, "Make Room Moderated", FIELD_MODERATED, room->moderated);
  add_xdata_desc(x, "By default, new users entering a moderated room are only visitors");
  add_xdata_boolean(x, "Make Occupants in a Moderated Room Default to Participant", FIELD_DEFAULT_TYPE, room->defaulttype);
  add_xdata_boolean(x, "Ban Private Messages between Occupants", FIELD_PRIVATE_MSG, room->privmsg);
  add_xdata_boolean(x, "An Invitation is Required to Enter", FIELD_MEMBERS_ONLY, room->invitation);
  add_xdata_desc(x, "By default, only admins can send invites in an invite-only room");
  add_xdata_boolean(x, "Allow Occupants to Invite Others", FIELD_ALLOW_INVITE, room->invites);

  if(room->secret == NULL)
    add_xdata_boolean(x, "A Password is required to enter", FIELD_PASS_PROTECTED, 0);
  else
    add_xdata_boolean(x, "A Password is required to enter", FIELD_PASS_PROTECTED, 1);

  add_xdata_desc(x, "If a password is required to enter this room, you must specify the password below.");
  add_xdata_text(x, "The Room Password", -1, FIELD_PASS, room->secret);

  field = xmlnode_insert_tag(x,"field");
  xmlnode_put_attrib(field,"type","list-single");
  xmlnode_put_attrib(field,"label","Affiliations that May Discover Real JIDs of Occupants");
  xmlnode_put_attrib(field,"var",FIELD_WHOIS);
  if(room->visible == 0)
    xmlnode_insert_cdata(xmlnode_insert_tag(field, "value"),"admins", -1);
  else
    xmlnode_insert_cdata(xmlnode_insert_tag(field, "value"),"anyone", -1);

  element = xmlnode_insert_tag(field, "option");
  xmlnode_put_attrib(element, "label", "Room Owner and Admins Only");
  xmlnode_insert_cdata(xmlnode_insert_tag(element, "value"), "admins", -1);
  element = xmlnode_insert_tag(field, "option");
  xmlnode_put_attrib(element, "label", "Anyone");
  xmlnode_insert_cdata(xmlnode_insert_tag(element, "value"), "anyone", -1);
  
  if (room->master->logsEnabled) {
    if(room->logfile == NULL)
      add_xdata_boolean(x, "Enable Logging of Room Conversations", FIELD_ENABLE_LOGGING, 0);
    else
      add_xdata_boolean(x, "Enable Logging of Room Conversations", FIELD_ENABLE_LOGGING, 1);

    field = xmlnode_insert_tag(x,"field");
    xmlnode_put_attrib(field,"type","list-single");
    xmlnode_put_attrib(field,"label","Logfile format");
    xmlnode_put_attrib(field,"var",FIELD_LOG_FORMAT);

    if(room->logformat == LOG_XML)
      xmlnode_insert_cdata(xmlnode_insert_tag(field, "value"),"xml", -1);
    else if(room->logformat == LOG_XHTML)
      xmlnode_insert_cdata(xmlnode_insert_tag(field, "value"),"xhtml", -1);
    else
      xmlnode_insert_cdata(xmlnode_insert_tag(field, "value"),"text", -1);

    element = xmlnode_insert_tag(field, "option");
    xmlnode_put_attrib(element, "label", "XML");
    xmlnode_insert_cdata(xmlnode_insert_tag(element, "value"), "xml", -1);
    element = xmlnode_insert_tag(field, "option");
    xmlnode_put_attrib(element, "label", "XHTML");
    xmlnode_insert_cdata(xmlnode_insert_tag(element, "value"), "xhtml", -1);
    element = xmlnode_insert_tag(field, "option");
    xmlnode_put_attrib(element, "label", "Plain Text");
    xmlnode_insert_cdata(xmlnode_insert_tag(element, "value"), "text", -1);
  }

  deliver(dpacket_new(msg),NULL);
}   

