/* bcy: NDN related operations */
#include "conference.h"

#define PRESENCE_FRESHNESS 2
#define MESSAGE_FRESHNESS 10
#define EXCLUSION_TIMEOUT 2
#define UNAVAILABLE_FRESHNESS 30
#define SEND_PRESENCE_INTERVAL 600

struct ndn_thread *nthread;			// ndn thread struct
static struct pollfd pfds[1];
static struct ccn_keystore *keystore;		// ccn keystore struct
static GMutex *ccn_mutex;
extern jcr_instance jcr;

/*
 * This appends a tagged, valid, fully-saturated Bloom filter, useful for
 * excluding everything between two 'fenceposts' in an Exclude construct.
 */
static void
append_bf_all(struct ccn_charbuf *c)
{
  unsigned char bf_all[9] = { 3, 1, 'A', 0, 0, 0, 0, 0, 0xFF };
  const struct ccn_bloom_wire *b = ccn_bloom_validate_wire(bf_all, sizeof(bf_all));
  if (b == NULL)
    abort();
  ccn_charbuf_append_tt(c, CCN_DTAG_Bloom, CCN_DTAG);
  ccn_charbuf_append_tt(c, sizeof(bf_all), CCN_BLOB);
  ccn_charbuf_append(c, bf_all, sizeof(bf_all));
  ccn_charbuf_append_closer(c);
}

/* fetch content name from content_ccnb structure */
static void
fetch_name_from_ccnb(char *name, const unsigned char *ccnb, struct ccn_indexbuf *comps)
{
  char *comp_str;
  size_t size;
  int n = comps->n;
  int i;
  
  name[0] = '\0';
  for (i = 0; i < n - 1; i++)
  {
    strcat(name, "/");
    if (ccn_name_comp_get(ccnb, comps, i, (const unsigned char **)&comp_str, &size) == 0)
    {
      strncat(name, comp_str, size);
    }
  }
}

/* create keylocator */
static int
ccn_create_keylocator(struct ccn_charbuf *c, const struct ccn_pkey *k)
{
  int res;
  ccn_charbuf_append_tt(c, CCN_DTAG_KeyLocator, CCN_DTAG);
  ccn_charbuf_append_tt(c, CCN_DTAG_Key, CCN_DTAG);
  res = ccn_append_pubkey_blob(c, k);
  if (res < 0)
    return (res);
  else
  {
    ccn_charbuf_append_closer(c); /* </Key> */
    ccn_charbuf_append_closer(c); /* </KeyLocator> */
  }
  return (0);
}

static void
send_presence(gpointer key, gpointer value, gpointer user_data)
{
  struct ccn *ccn = (struct ccn*) user_data;
  struct ccn_charbuf *content = (struct ccn_charbuf*) value;
  
  g_mutex_lock(ccn_mutex);
  ccn_put(ccn, content->buf, content->length);
  g_mutex_unlock(ccn_mutex);
}

/* find a specific name from a list */
static int
list_find(GQueue *list, char *name)
{
  GList *iterator = list->head;
  for (; iterator != NULL; iterator = iterator->next)
  {
    struct exclusion_element *element = (struct exclusion_element *) iterator->data;
    if (strcmp(name, element->name) == 0)
      return 1;
  }
  return 0;
}

enum ccn_upcall_res
incoming_interest_message(
  struct ccn_closure *selfp,
  enum ccn_upcall_kind kind,
  struct ccn_upcall_info *info)
{
  cnr room = (cnr) selfp->data;
  char *name;
  struct ccn_charbuf *content = NULL;
  
  switch (kind)
  {
    case CCN_UPCALL_FINAL:
      if (room != NULL)
	free(room);
      free(selfp);
      return CCN_UPCALL_RESULT_OK;
      
    case CCN_UPCALL_INTEREST:
      break;
      
    default:
      return CCN_UPCALL_RESULT_OK;
  }
  
  if (room == NULL) // room has been zapped
    return CCN_UPCALL_RESULT_OK;

  name = calloc(1, sizeof(char) * info->interest_comps->buf[info->interest_comps->n - 1]);
  fetch_name_from_ccnb(name, info->interest_ccnb, info->interest_comps);
  
  // find corresponding messages in local storage and put to ccnd
  if ((content = g_hash_table_lookup(room->message, name)) != NULL)
  {
    g_mutex_lock(ccn_mutex);
    ccn_put(info->h, content->buf, content->length);
    g_mutex_unlock(ccn_mutex);
    free(name);
    return CCN_UPCALL_RESULT_INTEREST_CONSUMED;
  }
  else if ((content = g_hash_table_lookup(room->message_latest, name)) != NULL)
  {
    g_mutex_lock(ccn_mutex);
    ccn_put(info->h, content->buf, content->length);
    g_mutex_unlock(ccn_mutex);
    free(name);
    return CCN_UPCALL_RESULT_INTEREST_CONSUMED;
  }
  else
    free(name);
    return CCN_UPCALL_RESULT_OK;
}

enum ccn_upcall_res
incoming_interest_presence(
  struct ccn_closure *selfp,
  enum ccn_upcall_kind kind,
  struct ccn_upcall_info *info)
{
  cnr room = (cnr) selfp->data;
  
  switch (kind)
  {
    case CCN_UPCALL_FINAL:
      if (room != NULL)
	free(room);
      free(selfp);
      return CCN_UPCALL_RESULT_OK;
    
    case CCN_UPCALL_INTEREST:
      break;
    
    default:
      return CCN_UPCALL_RESULT_OK;
  }
  
  if (room == NULL) // room has been zapped
    return CCN_UPCALL_RESULT_OK;
  
  // put all presence in local storage to ccnd
  g_hash_table_foreach(room->presence, send_presence, info->h);
  
  return CCN_UPCALL_RESULT_OK;
}

enum ccn_upcall_res
incoming_content_message(
  struct ccn_closure *selfp,
  enum ccn_upcall_kind kind,
  struct ccn_upcall_info *info)
{
  cnu user = (cnu) selfp->data;  
  char *name, *seq_str;
  char *pcontent = NULL;
  int seq;
  size_t len, size;
  char *changed;
  xmlnode x;
  
  switch (kind)
  {
    case CCN_UPCALL_FINAL:
      if (user != NULL)
	free(user);
      free(selfp);
      return CCN_UPCALL_RESULT_OK;
    
    case CCN_UPCALL_INTEREST_TIMED_OUT:
      if (user != NULL) // interest timed out, re-express it
	return CCN_UPCALL_RESULT_REEXPRESS;
      else
	return CCN_UPCALL_RESULT_OK;
    
    case CCN_UPCALL_CONTENT_UNVERIFIED:
      log_warn(NAME, "[%s] Unverified message content received", FZONE);
      return CCN_UPCALL_RESULT_OK;
    
    case CCN_UPCALL_CONTENT:
      break;
    
    default:
      return CCN_UPCALL_RESULT_OK;
  }
  
  if (user == NULL) // user has been zapped
    return CCN_UPCALL_RESULT_OK;
  
  // extract sequence number from content name, increase one and send new interest
  name = calloc(1, sizeof(char) * info->content_comps->buf[info->content_comps->n - 1]);
  fetch_name_from_ccnb(name, info->content_ccnb, info->content_comps);
  *strrchr(name, '/') = '\0';
  ccn_name_comp_get(info->content_ccnb, info->content_comps, info->content_comps->n - 2, (const unsigned char **)&seq_str, &size);
  seq = atoi(seq_str);
  seq++;
  create_message_interest(user, name, seq);
  free(name);

  ccn_content_get_value(info->content_ccnb, info->pco->offset[CCN_PCO_E], info->pco, (const unsigned char **)&pcontent, &len);
  x = xmlnode_str(pcontent, len); // translate a XML string into a xmlnode
  
  // judge whether this message should be delivered to local MUC server
  if (j_strcmp(xmlnode_get_attrib(x, "type"), "groupchat") != 0) // if it's groupchat, go through check directly; else we need to check the destination user
  {
    char *to = xmlnode_get_attrib(x, "to");
    if (strstr(to, jid_full(user->room->id)) == NULL) // "to" field should be in the form of <roomID>/<nick>
    {
      xmlnode_free(x);
      return CCN_UPCALL_RESULT_OK;
    }
    else
    {
      char *nick = to + strlen(jid_full(user->room->id)) + 1;
      cnu u = g_hash_table_lookup(user->room->local, nick);
      if (u == NULL || u->remote == 1) // the destination user should be local
      {
	xmlnode_free(x);
	return CCN_UPCALL_RESULT_OK;
      }
    }
  }
  
  // add external field to indicate the message comes from outside
  xmlnode_put_attrib(x, "external", "1");
  changed = xmlnode2str(x);
  if (XML_Parse(jcr->parser, changed, strlen(changed), 0) == 0) // deliver the message to MUC
  {
    log_warn(JDBG, "XML Parsing Error: '%s'", (char *)XML_ErrorString(XML_GetErrorCode(jcr->parser)));
  }
  xmlnode_free(x);
  return CCN_UPCALL_RESULT_OK;
}

enum ccn_upcall_res
incoming_content_presence(
  struct ccn_closure *selfp,
  enum ccn_upcall_kind kind,
  struct ccn_upcall_info *info)
{
  cnr room = (cnr) selfp->data;
  size_t len, size;
  char *pcontent = NULL;
  struct exclusion_element *element;
  char *name;
  char *hostname;
  cnu user;
  xmlnode x;
  char *status;
  
  switch (kind)
  {
    case CCN_UPCALL_FINAL:
      if (room != NULL)
	free(room);
      free(selfp);
      return CCN_UPCALL_RESULT_OK;
    
    case CCN_UPCALL_INTEREST_TIMED_OUT:
      if (room != NULL)
	create_presence_interest(room, 0); // interest timed out, re-express using new exclusion_list
      return CCN_UPCALL_RESULT_OK;
    
    case CCN_UPCALL_CONTENT_UNVERIFIED:
      log_warn(NAME, "[%s] Unverified presence content received", FZONE);
      return CCN_UPCALL_RESULT_OK;
    
    case CCN_UPCALL_CONTENT:
      break;
    
    default:
      return CCN_UPCALL_RESULT_OK;
  }
  
  if (room == NULL) // room has been zapped
    return CCN_UPCALL_RESULT_OK;
  
  // extract user name and insert it into exclusion_list
  ccn_name_comp_get(info->content_ccnb, info->content_comps, info->content_comps->n - 2, (const unsigned char **)&name, &size);
  element = (struct exclusion_element *) calloc(1, sizeof(struct exclusion_element));
  element->name = strndup(name, size);
  if (list_find(room->exclusion_list, element->name) == 0)
  {
    element->timer = g_timer_new();
    g_queue_push_head(room->exclusion_list, element);
  }
  else
  {
    free(element->name);
    free(element);
  }
  
  create_presence_interest(room, 0); // generate new presence interest
  
  ccn_content_get_value(info->content_ccnb, info->pco->offset[CCN_PCO_E], info->pco, (const unsigned char **)&pcontent, &len);
  user = g_hash_table_lookup(room->remote_users, name);
  x = xmlnode_str(pcontent, len); // translate XML string into xmlnode
  
  // extract status from presence message to check if it's the same as the previous one
  // the "type" field can show "unavailable", and "show", "status" fields together forms the complete status
  status = calloc(1, sizeof(char) * 100);
  status[0] = '\0';
  j_strcat(status, xmlnode_get_attrib(x, "type"));
  if (strlen(status) == 0)
    j_strcat(status, xmlnode_get_tag_data(x, "show"));
  if (strlen(status) == 0)
    j_strcat(status, "available");
  j_strcat(status, xmlnode_get_tag_data(x, "status"));
  if ((user != NULL && j_strcmp(status, user->status) == 0) || (user == NULL && j_strcmp(status, "unavailable") == 0))
  {
    if (user != NULL)
      user->last = time(NULL);
    free(status);
    xmlnode_free(x);
    return CCN_UPCALL_RESULT_OK;
  }
  
  // check hostname to determine whether the presence is from outside
  hostname = calloc(1, sizeof(char) * 50);
  gethostname(hostname, 50);
  if (j_strcmp(xmlnode_get_attrib(x, "hostname"), hostname) != 0)
  {
    char *changed;
    // insert external field to show it's from outside and then deliver it to MUC
    xmlnode_put_attrib(x, "external", "1");
    changed = xmlnode2str(x);
    if (XML_Parse(jcr->parser, changed, strlen(changed), 0) == 0)
    {
      log_warn(JDBG, "XML Parsing Error: '%s'", (char *)XML_ErrorString(XML_GetErrorCode(jcr->parser)));
    }
  }
  free(status);
  free(hostname);
  xmlnode_free(x);
  return CCN_UPCALL_RESULT_OK;
}

/* NDN thread function */
gpointer
ndn_run(gpointer data)
{
  struct ccn *ccn = nthread->ccn;
  int res = ccn_run(ccn, 0);
  
  while (nthread->bRunning)
  {
    if (res >= 0)
    {
      int ret = poll(pfds, 1, 100);
      if (ret >= 0)
      {
	res = ccn_run(ccn, 0);
      }
    }
  }
  
  return NULL;
}

static int /* for qsort */
namecompare(const void *a, const void *b)
{
  const struct ccn_charbuf *aa = *(const struct ccn_charbuf **)a;
  const struct ccn_charbuf *bb = *(const struct ccn_charbuf **)b;
  int ans = ccn_compare_names(aa->buf, aa->length, bb->buf, bb->length);
  return ans;
}

/* copy names from a list */
static int
copy_from_list(struct ccn_charbuf **res, GQueue *list)
{
  GList *iterator = list->head;
  int idx = 0;
  while (iterator != NULL)
  {
    struct exclusion_element *element = (struct exclusion_element *) iterator->data;
    struct ccn_charbuf *temp = ccn_charbuf_create();
    ccn_name_init(temp);
    ccn_name_append_str(temp, element->name);
    res[idx++] = temp;
    iterator = iterator->next;
  }
  return idx;
}

/* check exclusion element and remove the outdated ones */
static void
check_delete(gpointer data, gpointer user_data)
{
  struct exclusion_element *element = (struct exclusion_element*) data;
  GQueue *list = (GQueue*) user_data;
  gdouble duration;
  gulong useless;
  
  duration = g_timer_elapsed(element->timer, &useless);
  if (duration >= 2)
  {
    g_queue_remove(list, data);
    g_timer_destroy(element->timer);
    free(element->name);
    free(element);
  }
}

/* create interest for presence */
int
create_presence_interest(cnr room, int allow_stale)
{
  GQueue *exclusion_list = room->exclusion_list;
  struct ccn_charbuf *interest;
  struct ccn_charbuf **excl = NULL;
  int begin, i, length;
  gboolean excludeLow, excludeHigh;
  char *interest_name = calloc(1, sizeof(char) * 50);
  
  g_mutex_lock(ccn_mutex);
  
  // the interest name has the form of "/ndn/broadcast/xmpp-muc/<roomID>"
  interest = ccn_charbuf_create();
  strcpy(interest_name, "/ndn/broadcast/xmpp-muc/");
  strcat(interest_name, room->id->user);
  ccn_name_from_uri(interest, interest_name);
  free(interest_name);
  
  g_queue_foreach(exclusion_list, check_delete, exclusion_list); // delete outdated exclusion elements
  
  if (g_queue_is_empty(exclusion_list)) // empty exclusion list, directly express interest
  {
    int res;
    struct ccn_charbuf *templ = NULL;
    
    if (allow_stale)
    {
      templ = ccn_charbuf_create();
      ccn_charbuf_append_tt(templ, CCN_DTAG_Interest, CCN_DTAG);
      ccn_charbuf_append_tt(templ, CCN_DTAG_Name, CCN_DTAG);
      ccn_charbuf_append_closer(templ); // </Name>
      ccn_charbuf_append_tt(templ, CCN_DTAG_AnswerOriginKind, CCN_DTAG);
      ccnb_append_number(templ, CCN_AOK_DEFAULT | CCN_AOK_STALE);
      ccn_charbuf_append_closer(templ); // </AnswerOriginKind>
      ccn_charbuf_append_closer(templ); // </Interest>
    }
    res = ccn_express_interest(nthread->ccn, interest, room->in_content_presence, templ);
    g_mutex_unlock(ccn_mutex);
    if (res < 0)
    {
      log_warn(NAME, "[%s] ccn_express_interest failed", FZONE);
      ccn_charbuf_destroy(&interest);
      if (templ != NULL)
	ccn_charbuf_destroy(&templ);
      return 1;
    }
    ccn_charbuf_destroy(&interest);
    if (templ != NULL)
      ccn_charbuf_destroy(&templ);
    return 0;
  }

  excl = calloc(1, sizeof(struct ccn_charbuf) * g_queue_get_length(exclusion_list));
  length = copy_from_list(excl, exclusion_list);
  qsort(&excl[0], length, sizeof(excl[0]), &namecompare); // sort the exclusion list, necessary for CCNx
  
  begin = 0;
  excludeLow = FALSE;
  excludeHigh = TRUE;
  while (begin < length)
  {
    if (begin != 0)
      excludeLow = TRUE;
    
    struct ccn_charbuf *templ = ccn_charbuf_create();
    ccn_charbuf_append_tt(templ, CCN_DTAG_Interest, CCN_DTAG); // <Interest>
    ccn_charbuf_append_tt(templ, CCN_DTAG_Name, CCN_DTAG); // <Name>
    ccn_charbuf_append_closer(templ); // </Name>
    if (allow_stale)
    {
      ccn_charbuf_append_tt(templ, CCN_DTAG_AnswerOriginKind, CCN_DTAG);
      ccnb_append_number(templ, CCN_AOK_DEFAULT | CCN_AOK_STALE);
      ccn_charbuf_append_closer(templ); // </AndswerOriginKind>
    }
    ccn_charbuf_append_tt(templ, CCN_DTAG_Exclude, CCN_DTAG); // <Exclude>
    
    if (excludeLow)
      append_bf_all(templ);
    
    for (; begin < length; begin++)
    {
      struct ccn_charbuf *comp = excl[begin];
      if (comp->length < 4)
	abort();
      
      // we are being conservative here
      if (interest->length + templ->length + comp->length > 1350)
	break;
      
      ccn_charbuf_append(templ, comp->buf + 1, comp->length - 2);
    }
    
    if (begin == length)
      excludeHigh = FALSE;

    if (excludeHigh)
      append_bf_all(templ);
    
    ccn_charbuf_append_closer(templ); // </Exclude>
    ccn_charbuf_append_closer(templ); // </Interest>
    int res = ccn_express_interest(nthread->ccn, interest, room->in_content_presence, templ);
    if (res < 0)
    {
      log_warn(NAME, "[%s] ccn_express_interest failed!", FZONE);
      g_mutex_unlock(ccn_mutex);
      ccn_charbuf_destroy(&interest);
      ccn_charbuf_destroy(&templ);
      for (i = 0; i < length; i++)
	ccn_charbuf_destroy(&excl[i]);
      free(excl);
      return 1;
    }
    
    ccn_charbuf_destroy(&templ);
  }
  
  g_mutex_unlock(ccn_mutex);
  
  ccn_charbuf_destroy(&interest);
  for (i = 0; i < length; i++)
    ccn_charbuf_destroy(&excl[i]);
  free(excl);
  return 0;
}

gboolean send_again(gpointer data)
{
  struct ccn_charbuf *content = (struct ccn_charbuf *) data;

  if (content != NULL)
  {
    g_mutex_lock(ccn_mutex);
    ccn_put(nthread->ccn, content->buf, content->length);
    g_mutex_unlock(ccn_mutex);
    return TRUE;
  }
  return FALSE;
}

/* create content packet for presence */
int
create_presence_content(cnu user, xmlnode x)
{
  struct ccn_charbuf *pname;
  struct ccn_charbuf *interest_filter;
  struct ccn_charbuf *keylocator;
  struct ccn_charbuf *content;
  struct ccn_charbuf *signed_info;
  int res;
  char *content_name = calloc(1, sizeof(char) * 100);
  char *hostname;
  char *data;
  xmlnode dup_x;
  int freshness;
  
  g_mutex_lock(ccn_mutex);
  
  // the presence content name is in the form of "/ndn/broadcast/xmpp-muc/<roomID>/<userID>"
  strcpy(content_name, "/ndn/broadcast/xmpp-muc/");
  strcat(content_name, user->room->id->user);
  interest_filter = ccn_charbuf_create();
  ccn_name_from_uri(interest_filter, content_name);
  strcat(content_name, "/");
  strcat(content_name, jid_ns(user->realid));
  pname = ccn_charbuf_create();
  ccn_name_from_uri(pname, content_name);
  
  // create signed_info for presence content
  signed_info = ccn_charbuf_create();
  keylocator = ccn_charbuf_create();
  ccn_create_keylocator(keylocator, ccn_keystore_public_key(keystore));
  if (j_strcmp(xmlnode_get_attrib(x, "type"), "unavailable") == 0)
    freshness = UNAVAILABLE_FRESHNESS;
  else
    freshness = PRESENCE_FRESHNESS;
  res = ccn_signed_info_create(signed_info,
		/*pubkeyid*/ ccn_keystore_public_key_digest(keystore),
		/*publisher_key_id_size*/ ccn_keystore_public_key_digest_length(keystore),
		/*datetime*/ NULL,
		/*type*/ CCN_CONTENT_DATA,
		/*freshness*/ freshness,
		/*finalblockid*/ NULL,
		/*keylocator*/ keylocator);
  if (res < 0)
  {
    log_warn(NAME, "[%s]: Failed to create signed_info (res == %d)", FZONE, res);
    g_mutex_unlock(ccn_mutex);
    free(content_name);
    ccn_charbuf_destroy(&signed_info);
    ccn_charbuf_destroy(&keylocator);
    ccn_charbuf_destroy(&interest_filter);
    ccn_charbuf_destroy(&pname);
    return 1;
  }

  // add hostname field and encode the content
  dup_x = xmlnode_dup(x);
  hostname = calloc(1, sizeof(char) * 50);
  gethostname(hostname, 50);
  xmlnode_put_attrib(dup_x, "hostname", hostname);
  data = xmlnode2str(dup_x);
  log_debug(NAME, "[%s]: encoding content %s", FZONE, data);
  content = ccn_charbuf_create();
  ccn_encode_ContentObject(content, pname, signed_info,
			data, strlen(data), 
			NULL, ccn_keystore_private_key(keystore));
  g_hash_table_insert(user->room->presence, content_name, content); // insert into presence table for local storage
  ccn_put(nthread->ccn, content->buf, content->length);
  g_timeout_add_seconds(SEND_PRESENCE_INTERVAL, send_again, content);

  // set interest filter for incoming interest
  // ccn_set_interest_filter(nthread->ccn, interest_filter, user->room->in_interest_presence);
  
  g_mutex_unlock(ccn_mutex);

  ccn_charbuf_destroy(&keylocator);
  ccn_charbuf_destroy(&signed_info);
  ccn_charbuf_destroy(&interest_filter);
  ccn_charbuf_destroy(&pname);
  free(hostname);
  xmlnode_free(dup_x);
  return 0;
}

/* create interest for message */
int
create_message_interest(cnu user, char *name, int seq)
{
  struct ccn_charbuf *interest;
  int res;
  char *str_seq = calloc(1, sizeof(char) * 10);
  
  g_mutex_lock(ccn_mutex);
  
  // append sequence number to the name
  interest = ccn_charbuf_create();
  ccn_name_from_uri(interest, name);
  if (seq > 0)
  {
    itoa(seq, str_seq);
    ccn_name_append_str(interest, str_seq);
  }
  
  // express interest
  res = ccn_express_interest(nthread->ccn, interest, user->in_content_message, NULL);
  if (res < 0)
  {
    log_warn(NAME, "[%s] ccn_express_interest %s failed", FZONE, name);
    g_mutex_unlock(ccn_mutex);
    free(str_seq);
    ccn_charbuf_destroy(&interest);
    return 1;
  }
  
  g_mutex_unlock(ccn_mutex);
  
  free(str_seq);
  ccn_charbuf_destroy(&interest);
  return 0;
}

/* create content for message */
int
create_message_content(cnu user, char *data)
{
  struct ccn_charbuf *pname;
  struct ccn_charbuf *interest_filter;
  struct ccn_charbuf *signed_info;
  struct ccn_charbuf *keylocator;
  struct ccn_charbuf *content, *dup_content;
  int res;
  char *content_name = calloc(1, sizeof(char) * 100);
  char *name_without_seq;
  char *seq_char = calloc(1, sizeof(char) * 10);
  
  g_mutex_lock(ccn_mutex);
  
  // content name has the form of "<name_prefix>/<userID>/<roomID>/<seq>"
  strcpy(content_name, user->name_prefix);
  strcat(content_name, "/");
  strcat(content_name, jid_ns(user->realid));
  strcat(content_name, "/");
  strcat(content_name, user->room->id->user);
  interest_filter = ccn_charbuf_create();
  ccn_name_from_uri(interest_filter, content_name);  
  name_without_seq = strdup(content_name);
  strcat(content_name, "/");
  itoa(user->message_seq, seq_char);
  strcat(content_name, seq_char);
  pname = ccn_charbuf_create();
  ccn_name_from_uri(pname, content_name);
  
  // create keylocator and signed_info for content
  keylocator = ccn_charbuf_create();
  ccn_create_keylocator(keylocator, ccn_keystore_public_key(keystore));
  signed_info = ccn_charbuf_create();
  res = ccn_signed_info_create(signed_info,
		/*pubkeyid*/ ccn_keystore_public_key_digest(keystore),
		/*publisher_key_id_size*/ ccn_keystore_public_key_digest_length(keystore),
		/*datetime*/ NULL,
		/*type*/ CCN_CONTENT_DATA,
		/*freshness*/ MESSAGE_FRESHNESS,
		/*finalblockid*/ NULL,
		/*keylocator*/ keylocator);
  if (res < 0)
  {
    log_warn(NAME, "[%s] failed to create signed_info (res == %d)", FZONE, res);
    g_mutex_unlock(ccn_mutex);
    ccn_charbuf_destroy(&keylocator);
    ccn_charbuf_destroy(&signed_info);
    ccn_charbuf_destroy(&pname);
    ccn_charbuf_destroy(&interest_filter);
    return 1;
  }
  
  // encode content packet
  content = ccn_charbuf_create();
  ccn_encode_ContentObject(content, pname, signed_info,
			data, strlen(data), 
			NULL, ccn_keystore_private_key(keystore));
  
  dup_content = ccn_charbuf_create();
  ccn_charbuf_reset(dup_content);
  ccn_charbuf_append_charbuf(dup_content, content);

  // insert into message tables for local storage
  g_hash_table_insert(user->room->message, content_name, content);
  g_hash_table_insert(user->room->message_latest, name_without_seq, dup_content);
  
  ccn_put(nthread->ccn, content->buf, content->length);
  // set interest filter for incoming message
  //ccn_set_interest_filter(nthread->ccn, interest_filter, user->room->in_interest_message);
  user->message_seq++;
  
  g_mutex_unlock(ccn_mutex);

  ccn_charbuf_destroy(&keylocator);
  ccn_charbuf_destroy(&signed_info);
  ccn_charbuf_destroy(&pname);
  ccn_charbuf_destroy(&interest_filter);
  free(seq_char);
  return 0;
}

/* initialize NDN thread */
int
init_ndn_thread()
{
  GError *err;
  struct ccn_charbuf *temp;
  int res;
  
  nthread = (struct ndn_thread*) calloc(1, sizeof(struct ndn_thread));
  if (nthread == NULL)
  {
    log_error(NAME, "[%s] Memory allocation error!", FZONE);
    return 1;
  }
  
  nthread->ccn = NULL;
  nthread->ccn = ccn_create();
  if (nthread->ccn == NULL || ccn_connect(nthread->ccn, NULL) == -1)
  {
    log_error(NAME, "[%s] Failed to initialize ccn agent connection", FZONE);
    return 1;
  }
  
  ccn_mutex = g_mutex_new();

  // initialize ccn_keystore
  temp = ccn_charbuf_create();
  keystore = ccn_keystore_create();
  ccn_charbuf_putf(temp, "%s/.ccnx/.ccnx_keystore", getenv("HOME"));
  res = ccn_keystore_init(keystore, ccn_charbuf_as_string(temp), "Th1s1sn0t8g00dp8ssw0rd.");
  if (res != 0)
  {
    log_error(NAME, "[%s] Failed to initialize keystore %s", FZONE, ccn_charbuf_as_string(temp));
    return 1;
  }
  ccn_charbuf_destroy(&temp);
  
  // create NDN thread
  nthread->bRunning = 1;
  pfds[0].fd = ccn_get_connection_fd(nthread->ccn);
  pfds[0].events = POLLIN;
  if ((nthread->thread = g_thread_create(&ndn_run, NULL, TRUE, &err)) == NULL)
  {
    log_error(NAME, "[%s] NDN thread create failed: %s", FZONE, err->message);
    g_error_free(err);
  }
  log_debug(NAME, "[%s] NDN thread created", FZONE);

  return 0;
}

/* stop NDN thread */
int
stop_ndn_thread()
{
  nthread->bRunning = 0;
  g_thread_join(nthread->thread);
  ccn_disconnect(nthread->ccn);
  ccn_destroy(&nthread->ccn);
  ccn_keystore_destroy(&keystore);
  g_mutex_free(ccn_mutex);
  free(nthread);
  return 0;
}
