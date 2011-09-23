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

$Id: jcomp-compat.h,v 1.1 2005/12/06 14:48:49 peregrine Exp $

*/

/* The following are Compatibility Definitions from jabberd 1.4.x  */

/* packet types */
typedef enum { p_NONE, p_NORM, p_XDB, p_LOG, p_ROUTE } ptype;

/* ordering types, me first me first, managerial, engineer, grunt */
typedef enum { o_PRECOND, o_COND, o_PREDELIVER, o_DELIVER } order;

/* result types, unregister me, I pass, I should be last, I suck, I rock */
typedef enum { r_UNREG, r_NONE, r_PASS, r_LAST, r_ERR, r_DONE } result;

typedef struct instance_struct *instance, _instance;

/* packet wrapper, d as in delivery or daemon, whichever pleases you */
typedef struct dpacket_struct
{
    char *host;
    jid id;
    ptype type;
    pool p;
    xmlnode x;
} *dpacket, _dpacket;

/* delivery handler function callback definition */
typedef result (*phandler)(instance id, dpacket p, void *arg);

/* delivery handler list */
typedef struct handel_struct
{
    pool p;
    phandler f;
    void *arg;
    order o; /* for sorting new handlers as they're inserted */
    struct handel_struct *next;
} *handel, _handel;

/* wrapper around top-level config file sections */
struct instance_struct
{
    char *id;
    pool p;
    xmlnode x;
    ptype type;
    handel hds;
};

int deliver__flag;

typedef void(*shutdown_func)(void *arg);
