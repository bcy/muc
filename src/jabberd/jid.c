/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "JOSL").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the JOSL. You
 * may obtain a copy of the JOSL at http://www.jabber.org/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the JOSL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the JOSL
 * for the specific language governing rights and limitations under the
 * JOSL.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 or later (the "GPL"), in which case
 * the provisions of the GPL are applicable instead of those above.  If you
 * wish to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the JOSL,
 * indicate your decision by deleting the provisions above and replace them
 * with the notice and other provisions required by the GPL.  If you do not
 * delete the provisions above, a recipient may use your version of this file
 * under either the JOSL or the GPL. 
 * 
 * --------------------------------------------------------------------------*/

/**
 * @file jid.c
 * @brief representation and normalization of JabberIDs
 */

#include "lib.h"

#ifdef LIBIDN

#  include <glib.h>
#  include <stringprep.h>
#  include "hash.h"


/**
 * @brief datastructure to build the stringprep caches
 */
typedef struct _jid_prep_entry_st {
    char *preped;	/**< the result of the preparation, NULL if unchanged */
    time_t last_used;	/**< when this result has last been successfully used */
    unsigned int used_count; /**< how often this result has been successfully used */
    int size;		/**< the min buffer size needed to hold the result (strlen+1) */
} *_jid_prep_entry_t;

/**
 * @brief string preparation cache
 */
typedef struct _jid_prep_cache_st {
    GHashTable *hashtable;	/**< the hash table containing the preped strings */
    GMutex *mutex;	/**< mutex controling the access to the hashtable */
    const Stringprep_profile *profile;
    			/**< the stringprep profile used for this cache */
} *_jid_prep_cache_t;

/**
 * stringprep cache containging already preped nodes
 *
 * we are using global caches here for two reasons:
 * - I do not see why different instances would want
 *   to have different caches as we are always doing
 *   the same
 * - For per instance caches I would have to modify the
 *   interface of the jid_*() functions which would break
 *   compatibility with transports
 */
static _jid_prep_cache_t _jid_prep_cache_node = NULL;

/**
 * stringprep cache containing already preped domains
 */
static _jid_prep_cache_t _jid_prep_cache_domain = NULL;

/**
 * stringprep cache containing already preped resources
 */
static _jid_prep_cache_t _jid_prep_cache_resource = NULL;

/**
 * walker for cleaning up stringprep caches
 *
 * @param h the hash we are walking through
 * @param key the key of this item
 * @param val the value of this item
 * @param arg delete entries older as this unix timestamp
 */
static gboolean _jid_clean_walker(gpointer key, gpointer val, gpointer arg) {
    time_t *keep_newer_as = (time_t*)arg;
    _jid_prep_entry_t entry = (_jid_prep_entry_t)val;

    if (entry == NULL)
	return FALSE;

    if (entry->last_used <= *keep_newer_as) {
	if (entry->preped != NULL)
	    free(entry->preped);
	free(entry);

        return TRUE;
    }

    return FALSE;
}

/**
 * walk through a single stringprep cache and check which entries have expired
 */
static void _jid_clean_single_cache(_jid_prep_cache_t cache, time_t keep_newer_as) {
    /* acquire the lock on the cache */
    g_mutex_lock(cache->mutex);

    /* walk over all entries */
    g_hash_table_foreach_remove(cache->hashtable, _jid_clean_walker, (void*)&keep_newer_as);

    /* we're done, release the lock on the cache */
    g_mutex_unlock(cache->mutex);
}

/**
 * walk through the stringprep caches and check which entries have expired
 */
void jid_clean_cache(void) {
    /* XXX make this configurable? */
    time_t keep_newer_as = time(NULL) - 900;

    /* cleanup the nodeprep cache */
    _jid_clean_single_cache(_jid_prep_cache_node, keep_newer_as);
    
    /* cleanup the domain preparation cache */
    _jid_clean_single_cache(_jid_prep_cache_domain, keep_newer_as);
    
    /* cleanup the resourceprep cache */
    _jid_clean_single_cache(_jid_prep_cache_resource, keep_newer_as);
}

/**
 * caching wrapper around a stringprep function
 *
 * @param in_out_buffer buffer containing what has to be stringpreped and that gets the result
 * @param max_len size of the buffer
 * @param cache the used cache, defining also the used stringprep profile
 * @return the return code of the stringprep call
 */
static int _jid_cached_stringprep(char *in_out_buffer, int max_len, _jid_prep_cache_t cache) {
    _jid_prep_entry_t preped;
    int result = STRINGPREP_OK;

    /* check that the cache already exists
     * we can not do anything as we don't know which profile has to be used */
    if (cache == NULL) {
	return STRINGPREP_UNKNOWN_PROFILE;
    }

    /* is there something that has to be stringpreped? */
    if (in_out_buffer == NULL) {
	return STRINGPREP_OK;
    }

    /* acquire the lock on the cache */
    g_mutex_lock(cache->mutex);

    /* check if the requested preparation has already been done */
    preped = (_jid_prep_entry_t)g_hash_table_lookup(cache->hashtable, in_out_buffer);
    if (preped != NULL) {
	/* we already prepared this argument */
	if (preped->size <= max_len) {
	    /* we can use the result */

	    /* update the statistic */
	    preped->used_count++;
	    preped->last_used = time(NULL);

	    /* do we need to copy the result? */
	    if (preped->preped != NULL) {
		/* copy the result */
		strcpy(in_out_buffer, preped->preped);
	    }

	    result = STRINGPREP_OK;
	} else {
	    /* we need a bigger buffer */
	    result = STRINGPREP_TOO_SMALL_BUFFER;
	}
	
	/* we're done, release the lock on the cache */
	g_mutex_unlock(cache->mutex);
    } else {
	char *original;

	/* stringprep needs time, release the lock on the cache for the meantime */
	g_mutex_unlock(cache->mutex);

	/* we have to keep the key */
	original = strdup(in_out_buffer);
	
	/* try to prepare the string */
	result = stringprep(in_out_buffer, max_len, STRINGPREP_NO_UNASSIGNED, cache->profile);

	/* did we manage to prepare the string? */
	if (result == STRINGPREP_OK && original != NULL) {
	    /* generate an entry for the cache */
	    preped = (_jid_prep_entry_t)malloc(sizeof(struct _jid_prep_entry_st));
	    if (preped != NULL) {
		/* has there been modified something? */
		if (j_strcmp(in_out_buffer, original) == 0) {
		    /* no, we don't need to store a copy of the original string */
		    preped->preped = NULL;
		} else {
		    /* yes, store the stringpreped string */
		    preped->preped = strdup(in_out_buffer);
		}
		preped->last_used = time(NULL);
		preped->used_count = 1;
		preped->size = strlen(in_out_buffer)+1;

		/* acquire the lock on the cache again */
		g_mutex_lock(cache->mutex);

		/* store the entry in the cache */
		g_hash_table_insert(cache->hashtable, original, preped);

		/* we're done, release the lock on the cache */
		g_mutex_unlock(cache->mutex);
	    } else {
		/* we don't need the copy of the key, if there is no memory to store it */
		free(original);
	    }
	} else {
	    /* we don't need the copy of the original value */
	    if (original != NULL)
		free(original);
	}
    }

    return result;
}

/**
 * free a single stringprep cache
 *
 * @param cache the cache to free
 */
static void _jid_stop_single_cache(_jid_prep_cache_t *cache) {
    if (*cache == NULL)
	return;

    _jid_clean_single_cache(*cache, time(NULL));
    
    g_mutex_lock((*cache)->mutex);
    g_hash_table_destroy((*cache)->hashtable);
    g_mutex_free((*cache)->mutex);

    free(*cache);

    *cache = NULL;
}

/**
 * init a single stringprep cache
 *
 * @param cache the cache to init
 * @param profile profile used to prepare the strings
 */
static void _jid_init_single_cache(_jid_prep_cache_t *cache, const Stringprep_profile *profile) {
    /* do not init a cache twice */
    if (*cache == NULL) {
	*cache = (_jid_prep_cache_t)malloc(sizeof(struct _jid_prep_cache_st));
	(*cache)->mutex = g_mutex_new();
	(*cache)->hashtable = g_hash_table_new_full(g_str_hash,g_str_equal, ght_remove_key, NULL);
	(*cache)->profile = profile;
    }
}

/**
 * free the stringprep caches
 */
void jid_stop_caching(void) {
    _jid_stop_single_cache(&_jid_prep_cache_node);
    _jid_stop_single_cache(&_jid_prep_cache_domain);
    _jid_stop_single_cache(&_jid_prep_cache_resource);
}

/**
 * init the stringprep caches
 * (do not call this twice at the same time, we do not have the mutexes yet)
 */
void jid_init_cache(void) {
    /* init the nodeprep cache */
    _jid_init_single_cache(&_jid_prep_cache_node, stringprep_xmpp_nodeprep);

    /* init the nameprep cache (domains) */
    _jid_init_single_cache(&_jid_prep_cache_domain, stringprep_nameprep);

    /* init the resourceprep cache */
    _jid_init_single_cache(&_jid_prep_cache_resource, stringprep_xmpp_resourceprep);
}

/**
 * nameprep the domain identifier in a JID and check if it is valid
 *
 * @param jid data structure holding the JID
 * @return 0 if JID is valid, non zero otherwise
 */
static int _jid_safe_domain(jid id) {
    int result=0;

    /* there must be a domain identifier */
    if (id->server == NULL || *id->server == '\0')
	return 1;

    /* nameprep the domain identifier */
    result = _jid_cached_stringprep(id->server, strlen(id->server)+1, _jid_prep_cache_domain);
    if (result == STRINGPREP_TOO_SMALL_BUFFER) {
	/* nameprep wants to expand the string, e.g. conversion from &szlig; to ss */
	size_t biggerbuffersize = 1024;
	char *biggerbuffer = pmalloc(id->p, biggerbuffersize);
	if (biggerbuffer == NULL)
	    return 1;
	strcpy(biggerbuffer, id->server);
	result = _jid_cached_stringprep(biggerbuffer, biggerbuffersize, _jid_prep_cache_domain);
	id->server = biggerbuffer;
    }
    if (result != STRINGPREP_OK)
	return 1;

    /* the namepreped domain must not be longer than 1023 bytes */
    if (j_strlen(id->server) > 1023)
	return 1;

    /* if nothing failed, the domain is valid */
    return 0;
}

/**
 * nodeprep the node identifier in a JID and check if it is valid
 *
 * @param jid data structure holding the JID
 * @return 0 if JID is valid, non zero otherwise
 */
static int _jid_safe_node(jid id) {
    int result=0;

    /* it is valid to have no node identifier in the JID */
    if (id->user == NULL)
	return 0;

    /* nodeprep */
    result = _jid_cached_stringprep(id->user, strlen(id->user)+1, _jid_prep_cache_node);
    if (result == STRINGPREP_TOO_SMALL_BUFFER) {
	/* nodeprep wants to expand the string, e.g. conversion from &szlig; to ss */
	size_t biggerbuffersize = 1024;
	char *biggerbuffer = pmalloc(id->p, biggerbuffersize);
	if (biggerbuffer == NULL)
	    return 1;
	strcpy(biggerbuffer, id->user);
	result = _jid_cached_stringprep(biggerbuffer, biggerbuffersize, _jid_prep_cache_node);
	id->user = biggerbuffer;
    }
    if (result != STRINGPREP_OK)
	return 1;

    /* the nodepreped node must not be longer than 1023 bytes */
    if (j_strlen(id->user) > 1023)
	return 1;

    /* check if node was zeroed by stringprep */
    if (*id->user == '\0')
	id->user = NULL;

    /* if nothing failed, the node is valid */
    return 0;
}

/**
 * resourceprep the resource identifier in a JID and check if it is valid
 *
 * @param jid data structure holding the JID
 * @return 0 if JID is valid, non zero otherwise
 */
static int _jid_safe_resource(jid id) {
    int result=0;

    /* it is valid to have no resource identifier in the JID */
    if (id->resource == NULL)
	return 0;

    /* resource prep the resource identifier */
    result = _jid_cached_stringprep(id->resource, strlen(id->resource)+1, _jid_prep_cache_resource);
    if (result == STRINGPREP_TOO_SMALL_BUFFER) {
	/* resourceprep wants to expand the string, e.g. conversion from &szlig; to ss */
	size_t biggerbuffersize = 1024;
	char *biggerbuffer = pmalloc(id->p, biggerbuffersize);
	if (biggerbuffer == NULL)
	    return 1;
	strcpy(biggerbuffer, id->resource);
	result = _jid_cached_stringprep(id->resource, strlen(id->resource)+1, _jid_prep_cache_resource);
	id->resource = biggerbuffer;
    }
    if (result != STRINGPREP_OK)
	return 1;

    /* the resourcepreped resource must not be longer than 1023 bytes */
    if (j_strlen(id->resource) > 1023)
	return 1;

    /* check if resource was zeroed by stringprep */
    if (*id->resource == '\0')
	id->resource = NULL;

    /* if nothing failed, the resource is valid */
    return 0;

}

#else /* no LIBIDN */

/**
 * check if the domain identifier in a JID is valid
 *
 * @param jid data structure holding the JID
 * @return 0 if domain is valid, non zero otherwise
 */
static int _jid_safe_domain(jid id) {
    char *str;

    /* there must be a domain identifier */
    if (id->server == NULL || *id->server == '\0')
	return 1;

    /* and it must not be longer than 1023 bytes */
    if (strlen(id->server) > 1023)
	return 1;

    /* lowercase the hostname, make sure it's valid characters */
    for(str = id->server; *str != '\0'; str++)
    {
        *str = tolower(*str);
        if(!(isalnum(*str) || *str == '.' || *str == '-' || *str == '_')) return 1;
    }

    /* otherwise it's okay as far as we can tell without LIBIDN */
    return 0;
}

/**
 * check if the node identifier in a JID is valid
 *
 * @param jid data structure holding the JID
 * @return 0 if node is valid, non zero otherwise
 */
static int _jid_safe_node(jid id) {
    char *str;

    /* node identifiers may not be longer than 1023 bytes */
    if (j_strlen(id->user) > 1023)
	return 1;

    /* check for low and invalid ascii characters in the username */
    if(id->user != NULL)
        for(str = id->user; *str != '\0'; str++)
            if(*str <= 32 || *str == ':' || *str == '@' || *str == '<' || *str == '>' || *str == '\'' || *str == '"' || *str == '&' || *str == '/') return 1;

    /* otherwise it's okay as far as we can tell without LIBIDN */
    return 0;
}

/**
 * check if the resource identifier in a JID is valid
 *
 * @param jid data structure holding the JID
 * @return 0 if resource is valid, non zero otherwise
 */
static int _jid_safe_resource(jid id) {
    /* resources may not be longer than 1023 bytes */
    if (j_strlen(id->resource) > 1023)
	return 1;

    /* otherwise it's okay as far as we can tell without LIBIDN */
    return 0;
}

#endif

/**
 * nodeprep/nameprep/resourceprep the JID and check if it is valid
 *
 * @param jid data structure holding the JID
 * @return NULL if the JID is invalid, pointer to the jid otherwise
 */
jid jid_safe(jid id)
{
    if (_jid_safe_domain(id))
	return NULL;
    if (_jid_safe_node(id))
	return NULL;
    if (_jid_safe_resource(id))
	return NULL;

    return id;
}

jid jid_new(pool p, const char *idstr)
{
    char *server, *resource, *type, *str;
    jid id;

    if(p == NULL || idstr == NULL || *idstr == '\0')
        return NULL;

    /* user@server/resource */

    str = pstrdup(p, idstr);

    id = pmalloco(p,sizeof(struct jid_struct));
    id->p = p;

    resource = strstr(str,"/");
    if(resource != NULL)
    {
        *resource = '\0';
        ++resource;
        if(*resource != '\0')
            id->resource = resource;
    }else{
        resource = str + strlen(str); /* point to end */
    }

    type = strstr(str,":");
    if(type != NULL && type < resource)
    {
        *type = '\0';
        ++type;
        str = type; /* ignore the type: prefix */
    }

    server = strstr(str,"@");
    if(server == NULL || server > resource)
    { /* if there's no @, it's just the server address */
        id->server = str;
    }else{
        *server = '\0';
        ++server;
        id->server = server;
        if(*str != '\0')
            id->user = str;
    }

    return jid_safe(id);
}

void jid_set(jid id, char *str, int item)
{
    char *old;

    if(id == NULL)
        return;

    /* invalidate the cached copy */
    id->full = NULL;

    switch(item)
    {
    case JID_RESOURCE:
	old = id->resource;
        if(str != NULL && *str != '\0')
            id->resource = pstrdup(id->p, str);
        else
            id->resource = NULL;
        if(_jid_safe_resource(id))
            id->resource = old; /* revert if invalid */
        break;
    case JID_USER:
        old = id->user;
        if(str != NULL && *str != '\0')
            id->user = pstrdup(id->p, str);
        else
            id->user = NULL;
        if(_jid_safe_node(id))
            id->user = old; /* revert if invalid */
        break;
    case JID_SERVER:
        old = id->server;
        id->server = pstrdup(id->p, str);
        if(_jid_safe_domain(id))
            id->server = old; /* revert if invalid */
        break;
    }

}

char *jid_full(jid id)
{
    spool s;

    if(id == NULL)
        return NULL;

    /* use cached copy */
    if(id->full != NULL)
        return id->full;

    s = spool_new(id->p);

    if(id->user != NULL)
        spooler(s, id->user,"@",s);

    spool_add(s, id->server);

    if(id->resource != NULL)
        spooler(s, "/",id->resource,s);

    id->full = spool_print(s);
    return id->full;
}

/* local utils */
static int _jid_nullstrcmp(char *a, char *b)
{
    if(a == NULL && b == NULL) return 0;
    if(a == NULL || b == NULL) return -1;
    return strcmp(a,b);
}
static int _jid_nullstrcasecmp(char *a, char *b)
{
    if(a == NULL && b == NULL) return 0;
    if(a == NULL || b == NULL) return -1;
    return strcasecmp(a,b);
}

int jid_cmp(jid a, jid b)
{
    return jid_cmpx(a, b, JID_RESOURCE | JID_USER | JID_SERVER);
}

/* suggested by Anders Qvist <quest@valdez.netg.se> */
int jid_cmpx(jid a, jid b, int parts)
{
    if(a == NULL || b == NULL)
        return -1;

    if(parts & JID_RESOURCE && _jid_nullstrcmp(a->resource, b->resource) != 0) return -1;
    if(parts & JID_USER && _jid_nullstrcasecmp(a->user, b->user) != 0) return -1;
    if(parts & JID_SERVER && _jid_nullstrcmp(a->server, b->server) != 0) return -1;

    return 0;
}

jid jid_user(jid a)
{
    jid ret;

    if(a == NULL || a->resource == NULL) return a;

    ret = pmalloco(a->p,sizeof(struct jid_struct));
    ret->p = a->p;
    ret->user = a->user;
    ret->server = a->server;

    return ret;
}
