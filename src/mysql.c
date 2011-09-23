/*
 * MU-Conference - Multi-User Conference Service
 * Copyright (c) 2007 Gregoire Menuel
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

#ifdef HAVE_MYSQL
#  include <mysql/mysql.h>
#  include <mysql/errmsg.h>

//Size of the buffer used to escape characters
#define BUFFER_SIZE 2049
//Size given to mysql_real_escape_char, BUFFER_SIZE must be at least BUFFER_CHAR_SIZE*2+1
#define BUFFER_CHAR_SIZE 1024  

static char escaped[BUFFER_SIZE] = "";


/* Initialize a mysql instance */
mysql sql_mysql_init(cni master, xmlnode config){
  xmlnode node;
  mysql mysql = malloc(sizeof(_mysql));
  mysql->mysql=mysql_init(NULL);
  mysql->host = NULL;
  mysql->user = NULL;
  mysql->pass = NULL;
  mysql->database = NULL;
  if ((node = xmlnode_get_tag(config, "host")) != NULL) {
    mysql->host = xmlnode_get_data(node);
  }
  if ((node = xmlnode_get_tag(config, "user")) != NULL) {
    mysql->user = xmlnode_get_data(node);
  }
  if ((node = xmlnode_get_tag(config, "pass")) != NULL) {
    mysql->pass = xmlnode_get_data(node);
  }
  if ((node = xmlnode_get_tag(config, "database")) != NULL) {
    mysql->database = xmlnode_get_data(node);
  }
  mysql->port=0;
  mysql->flag=0;
  mysql->socket=NULL;
  if (sql_mysql_connect(mysql)==0) {
    mysql_close(mysql->mysql);
    free(mysql);
    return NULL;
  }
  return mysql;
}
  
/* establishe a connection with a mysql server */
int sql_mysql_connect(mysql mysql)
{
  if (mysql == NULL) return 0;
  if (mysql_real_connect(mysql->mysql,mysql->host,mysql->user,mysql->pass,mysql->database,mysql->port,mysql->socket,mysql->flag)==NULL){
    log_warn(NAME, "[%s] ERR: Unable to connect to the database", FZONE);
    return 0;
  }
  return 1;
}

/* close the connection with the server and destroy the mysql object */
void sql_mysql_close(mysql sql)
{
  if (sql == NULL) return;
  mysql_close(sql->mysql);
  free(sql);
  sql = NULL;
}

/* execute a sql query */
static int sql_mysql_execute(mysql sql, char* query) {
  int ret = 0;
  unsigned int query_err=0;
  if (sql == NULL) return 1;
  log_debug(NAME,"[%s] Trying to execute query : %s", FZONE, query);
  ret = mysql_query(sql->mysql,query);
  if (ret) {
    query_err = mysql_errno(sql->mysql);
    if (query_err == CR_SERVER_LOST || query_err == CR_SERVER_GONE_ERROR) {
      log_warn(NAME, "[%s] ERR: sql connection lost, trying to reconnect", FZONE);
      sql_mysql_connect(sql);
      ret = mysql_query(sql->mysql, query);
      if (ret == 0){
        log_warn(NAME, "[%s] sql connection has been lost and reestablished", FZONE);
      }
    }
  }

  if (ret != 0){
    //an error occured
    log_warn(NAME, "[%s] ERR: mysql query (%s) failed: %s", FZONE, query, mysql_error(sql->mysql));
    return 1;
  }
  return 0;
}

/* escape a string using mysql_real_escape. str is the string to escape, buffer is a previously created buffer, limit is the size of the buffer.
 * Return: the buffer */
char * _sql_escape_string(MYSQL * mysql, char * str, char * buffer, int limit) {
  int len;
  if (str == NULL) return NULL;
  len = strlen(str);
  if (len > limit) {
    len = limit;
  }
  mysql_real_escape_string(mysql, buffer, str, len);
  return buffer;
}

/* clear both tables (rooms and rooms_lists) */
void sql_clear_all(mysql sql) {
  if (sql == NULL) return;
  sql_mysql_execute(sql,"DELETE FROM rooms");
  sql_mysql_execute(sql,"DELETE FROM rooms_lists");
}

/* update a field in the rooms table */
void sql_update_field(mysql sql, const char * roomId,const char* field, const char * value){
  pool p=NULL;
  spool s=NULL;
  if (sql == NULL) return;
  p = pool_new();
  s = spool_new(p);
  spool_add(s, "UPDATE rooms SET ");
  spool_add(s, (char*)field);
  spool_add(s, "='");
  spool_add(s, _sql_escape_string(sql->mysql, (char*)value, escaped, BUFFER_CHAR_SIZE));
  spool_add(s, "' WHERE jid='");
  spool_add(s, _sql_escape_string(sql->mysql, (char*)roomId, escaped, BUFFER_CHAR_SIZE));
  spool_add(s, "'");
  sql_mysql_execute(sql,spool_print(s));
  pool_free(p);
}

/* update the users number of a room */
void sql_update_nb_users(mysql sql, cnr room){
  if (sql == NULL) return;
  char users[10]="";
  sprintf(users,"%d",room->count);
  sql_update_field(sql,  jid_full(room->id), "users", users);
}

/* insert a room config in the rooms table */
void sql_insert_room_config(mysql sql, cnr room) {
  char * x=NULL;
  char buffer[10]="";
  pool p = NULL;
  spool s = NULL;
  if ((room == NULL) || (room->id == NULL) || (sql == NULL)) {
    return;
  }
  log_debug(NAME, "[%s] Inserting SQL record for room %s", FZONE, jid_full(room->id));
  p = pool_new();
  s = spool_new(p);
  spool_add(s, "INSERT INTO rooms (`jid`, `name`, `desc`, `topic`, `users`, `public`, `open`, `secret`) VALUES ('");
  spool_add(s, _sql_escape_string(sql->mysql, jid_full(room->id), escaped, BUFFER_CHAR_SIZE));
  spool_add(s, "', '");
  spool_add(s, _sql_escape_string(sql->mysql, room->name, escaped, BUFFER_CHAR_SIZE));
  spool_add(s, "', '");
  spool_add(s, _sql_escape_string(sql->mysql, room->description, escaped, BUFFER_CHAR_SIZE));
  spool_add(s, "', '");
  if ((x=xmlnode_get_attrib(room->topic,"subject")) != NULL) {
    spool_add(s, _sql_escape_string(sql->mysql, x, escaped, BUFFER_CHAR_SIZE));
  }
  spooler(s, "', '0', '", itoa(room->public, buffer), "', '",s);
  if (room->invitation || room->locked){
    spool_add(s, "0");
  }
  else {
    spool_add(s, "1");
  }
  spool_add(s, "', '");
  if (room->secret!=NULL){
    spool_add(s, _sql_escape_string(sql->mysql, room->secret, escaped, BUFFER_CHAR_SIZE));
  }
  spool_add(s, "')");
  sql_mysql_execute(sql,spool_print(s));
  pool_free(p);
}

/* callback of the hash table lookup of the function sql_insert_all */
void _sql_insert_room_config(gpointer key, gpointer data, gpointer arg) {
  cnr room=(cnr) data;
  mysql sql = (mysql) arg;
  sql_insert_room_config(sql,room);
}

/* insert all rooms config in the db */
void sql_insert_all(mysql sql, GHashTable * rooms) {
  if (sql == NULL) return;
  g_hash_table_foreach(rooms, _sql_insert_room_config, (void*)sql);

}

/* update a room config (all fields) */
void sql_update_room_config(mysql sql, cnr room) {
  char buffer[10]="";
  pool p = NULL;
  spool s = NULL;
  if (sql == NULL) return;
  log_debug(NAME, "[%s] Updating SQL record for room %s", FZONE, jid_full(room->id));
  p = pool_new();
  s = spool_new(p);
  spool_add(s, "UPDATE rooms SET `name`='");
  spool_add(s, _sql_escape_string(sql->mysql, room->name, escaped, BUFFER_CHAR_SIZE));

  spool_add(s, "', `desc`='");
  spool_add(s, _sql_escape_string(sql->mysql, room->description, escaped, BUFFER_CHAR_SIZE));


  spooler(s, "', `public`='", itoa(room->public, buffer), "', `open`='",s);

  //check if anyone can enter the room
  if (room->invitation || room->locked){
    spool_add(s, "0");
  }
  else {
    spool_add(s, "1");
  }
    
  spool_add(s, "', secret='");
  if (room->secret!=NULL){
    spool_add(s, _sql_escape_string(sql->mysql, room->secret, escaped, BUFFER_CHAR_SIZE));
  }

  spool_add(s, "' WHERE `jid`='");
  spool_add(s, _sql_escape_string(sql->mysql, jid_full(room->id), escaped, BUFFER_CHAR_SIZE));

  spool_add(s, "'");
  
  sql_mysql_execute(sql,spool_print(s));
  pool_free(p);
}

/* destroy a room */
void sql_destroy_room(mysql sql, char * room_jid) {
  pool p = NULL;
  static char eroom[1025] = "";
  if (sql == NULL) return;
  p = pool_new();
  _sql_escape_string(sql->mysql, room_jid, eroom, 1025);
  sql_mysql_execute(sql,spools(p, "DELETE FROM rooms WHERE jid='", eroom, "' LIMIT 1",p));
  sql_mysql_execute(sql,spools(p, "DELETE FROM rooms_lists WHERE jid_room='", eroom, "'",p));
  pool_free(p);

}

/* struct used to pass arguments to the functions (for the owner, admin, member and outcast lists) */
typedef struct s_lists {
  int affil;
  cnr room;
  mysql sql;
  pool p;
} *lists, _lists;

/* return the string associated with an affiliation code */
char * _sql_affil_string(int affil) {
  if (affil==TAFFIL_OWNER.code) {
    return "owner";
  }
  else if (affil==TAFFIL_ADMIN.code) {
    return "administrator";
  }
  else if (affil == TAFFIL_MEMBER.code) {
    return "member";
  }
  else if (affil == TAFFIL_OUTCAST.code) {
    return "outcast";
  }

  return NULL;
}

/* add a user to the list in the db */
void sql_add_affiliate(mysql sql,cnr room,char * userid,int affil) {
  pool p = NULL;
  static char euser[1025] = "";
  static char eroom[1025] = "";
  char * affil_s = NULL;

  if (sql == NULL) return;
  affil_s = _sql_affil_string(affil);
  if (affil_s == NULL) {
    return;
  }

  _sql_escape_string(sql->mysql, userid, euser, 1025);
  _sql_escape_string(sql->mysql, jid_full(room->id), eroom, 1025);
  log_debug(NAME, "[%s] Add affiliation in db for user %s in room %s", FZONE, userid,jid_full(room->id));
  p = pool_new();


  sql_mysql_execute(sql, spools(p, "INSERT INTO rooms_lists (jid_room, jid_user, affil) VALUES ('",eroom, "', '", euser, "', '", affil_s, "')", p));

  pool_free(p);

} 

void _sql_add_list(gpointer key, gpointer data, gpointer arg) {
  lists list = (lists) arg;
  sql_add_affiliate(list->sql, list->room,(char *) key, list->affil);
}

/* insert an affiliation list in the db */
void _sql_add_lists(mysql sql, cnr room, GHashTable * list_users, int affil) {
  log_debug(NAME, "[%s] Inserting users for room %s and affiliation %s", FZONE, jid_full(room->id), _sql_affil_string(affil));
  lists list = (lists)malloc(sizeof(_lists));
  list->affil=affil;
  list->sql=sql;
  list->p = pool_new();
  list->room=room;
  g_hash_table_foreach(list_users, _sql_add_list, (void*)list);
  pool_free(list->p);
  free(list);
}

/* add all lists of a room in the db */
void sql_add_room_lists(mysql sql, cnr room) {
  if (sql == NULL) return;
  _sql_add_lists(sql, room, room->owner, TAFFIL_OWNER.code);
  _sql_add_lists(sql, room, room->member, TAFFIL_MEMBER.code);
  _sql_add_lists(sql, room, room->admin, TAFFIL_ADMIN.code);
  _sql_add_lists(sql, room, room->outcast, TAFFIL_OUTCAST.code);
}

void _sql_add_all_lists(gpointer key, gpointer data, gpointer arg) {
  sql_add_room_lists((mysql) arg, (cnr) data);
}

/* insert all lists of all rooms in the db */
void sql_insert_lists(mysql sql, GHashTable * rooms) {
  if (sql == NULL) return;
  sql_mysql_execute(sql, "DELETE FROM rooms_lists");
  g_hash_table_foreach(rooms, _sql_add_all_lists, (void*)sql);
}

/* remove the bd entry of an affiliated user */
void sql_remove_affiliate(mysql sql,cnr room,jid userid) {
  pool p = NULL;
  static char euser[1025] = "";
  static char eroom[1025] = "";

  if (sql == NULL) return;

  _sql_escape_string(sql->mysql, jid_full(userid), euser, 1025);
  _sql_escape_string(sql->mysql, jid_full(room->id), eroom, 1025);
  log_debug(NAME, "[%s] Remove affiliation in db for user %s in room %s", FZONE, jid_full(userid),jid_full(room->id));
  p = pool_new();


  sql_mysql_execute(sql, spools(p, "DELETE FROM rooms_lists WHERE jid_room='",eroom,"' AND  jid_user='", euser,"'", p));

  pool_free(p);

} 

#endif
