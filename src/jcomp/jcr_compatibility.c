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

$Id: jcr_compatibility.c,v 1.2 2005/12/15 07:48:11 peregrine Exp $

*/

#include "jcomp.h"

dpacket dpacket_new(xmlnode x) {
  dpacket p;

  if(x == NULL)
    return NULL;

  /* create the new packet */
  p = pmalloco(xmlnode_pool(x),sizeof(_dpacket));
  p->x = x;
  p->p = xmlnode_pool(x);
  p->type = p_NORM;

  return p;
}

void register_phandler(void *i, int d, void *phandler, void* pdata) {
  extern jcr_instance jcr;

  jcr->handler = phandler;
  jcr->pdata = pdata;
}

void register_shutdown(void *shandler, void *sdata) {
  extern jcr_instance jcr;
  
  jcr->shandler = shandler;
  jcr->sdata = sdata;
}

/* Custom Debug message */
char *jcr_debug_msg(const char *file, const char *function, int line) {           
    static char buff[128];
    int i;
		            
    i = snprintf(buff,127,"%s:%d (%s)",file,line,function);
    buff[i] = '\0';
		            
    return buff;
}
