/* bcy: NDN related operations */
#include "conference.h"

struct ndn_thread *nthread;
static struct pollfd pfds[1];
static struct ccn_keystore *keystore;
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
    if (ccn_name_comp_get(ccnb, comps, i, &comp_str, &size) == 0)
    {
      comp_str[size] = '\0';
      strcat(name, comp_str);
    }
  }
}

static int
ccn_create_keylocator(struct ccn_charbuf *c, const struct ccn_pkey *k)
{
    int res;
    ccn_charbuf_append_tt(c, CCN_DTAG_KeyLocator, CCN_DTAG);
    ccn_charbuf_append_tt(c, CCN_DTAG_Key, CCN_DTAG);
    res = ccn_append_pubkey_blob(c, k);
    if (res < 0)
        return (res);
    else {
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
  
  ccn_put(ccn, content->buf, content->length);
}

enum ccn_upcall_res
incoming_interest_meesage(
  struct ccn_closure *selfp,
  enum ccn_upcall_kind kind,
  struct ccn_upcall_info *info)
{
  cnu user = (cnu) selfp->data;
  cnr room = user->room;
  char *name;
  struct ccn_charbuf *content = NULL;
  
  switch (kind) {
    case CCN_UPCALL_FINAL:
      return CCN_UPCALL_RESULT_OK;
      
    case CCN_UPCALL_INTEREST:
      break;
      
    default:
      return CCN_UPCALL_RESULT_OK;
  }
  
  name = calloc(1, sizeof(char) * info->interest_comps->buf[info->interest_comps->n - 1]);
  
  fetch_name_from_ccnb(name, info->interest_ccnb, info->interest_comps);
  
  if ((content = g_hash_table_lookup(room->message, name)) != NULL)
  {
    ccn_put(info->h, content->buf, content->length);
    return CCN_UPCALL_RESULT_INTEREST_CONSUMED;
  }
  else if ((content = g_hash_table_lookup(room->message_latest, name)) != NULL)
  {
    ccn_put(info->h, content->buf, content->length);
    return CCN_UPCALL_RESULT_INTEREST_CONSUMED;
  }
  else
    return CCN_UPCALL_RESULT_OK;
}

enum ccn_upcall_res
incoming_interest_presence(
  struct ccn_closure *selfp,
  enum ccn_upcall_kind kind,
  struct ccn_upcall_info *info)
{
  cnu user = (cnu) selfp->data;
  cnr room = (cnr) user->room;
  char *name;
  char *roomname;
  
  switch (kind) {
    case CCN_UPCALL_FINAL:
      return CCN_UPCALL_RESULT_OK;
      
    case CCN_UPCALL_INTEREST:
      break;
            
    default:
      return CCN_UPCALL_RESULT_OK;
  }
  
  name = calloc(1, sizeof(char) * info->interest_comps->buf[info->interest_comps->n - 1]);
  fetch_name_from_ccnb(name, info->interest_ccnb, info->interest_comps);
  
  roomname = calloc(1, sizeof(char) * 100);
  strcpy(roomname, "/ndn/broadcast/xmpp-muc/");
  strcat(roomname, jid_ns(room->id));
  
  if (strcmp(roomname, name) == 0)
  {
    g_hash_table_foreach(room->presence, send_presence, info->h);
  }
    
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
  unsigned char *pcontent = NULL;
  int seq;
  size_t len, size;
  
  switch (kind) {
    case CCN_UPCALL_FINAL:
      return CCN_UPCALL_RESULT_OK;
      
    case CCN_UPCALL_INTEREST_TIMED_OUT:
      return CCN_UPCALL_RESULT_REEXPRESS;
      
    case CCN_UPCALL_CONTENT_UNVERIFIED:
      log_warn(NAME, "[%s] Unverified message content received", FZONE);
      return CCN_UPCALL_RESULT_OK;
      
    case CCN_UPCALL_CONTENT:
      break;
      
    default:
      return CCN_UPCALL_RESULT_OK;
  }

  ccn_content_get_value(info->content_ccnb, info->pco->offset[CCN_PCO_E], info->pco, &pcontent, &len);
  XML_Parse(jcr->parser, pcontent, len, 0);
  
  name = calloc(1, sizeof(char) * info->content_comps->buf[info->content_comps->n - 1]);
  fetch_name_from_ccnb(name, info->content_ccnb, info->content_comps);
  
  seq_str = calloc(1, sizeof(char) * 10);
  ccn_name_comp_get(info->content_ccnb, info->content_comps, info->content_comps->n - 2, &seq_str, &size);
  seq = atoi(seq_str);
  seq++;
  
  create_message_interest(user, name, seq);
  
  return CCN_UPCALL_RESULT_OK;
}

enum ccn_upcall_res
incoming_content_presence(
  struct ccn_closure *selfp,
  enum ccn_upcall_kind kind,
  struct ccn_upcall_info *info)
{
  cnu user = (cnu) selfp->data;
  size_t len, size;
  unsigned char *pcontent = NULL;
  
  switch (kind) {
    case CCN_UPCALL_FINAL:
      return CCN_UPCALL_RESULT_OK;
      
    case CCN_UPCALL_INTEREST_TIMED_OUT:
      create_presence_interest(user);
      return CCN_UPCALL_RESULT_OK;
      
    case CCN_UPCALL_CONTENT_UNVERIFIED:
      log_warn(NAME, "[%s] Unverified presence content received", FZONE);
      return CCN_UPCALL_RESULT_OK;
      
    case CCN_UPCALL_CONTENT:
      break;
      
    default:
      return CCN_UPCALL_RESULT_OK;
  }
  
  struct exclusion_element *element = (struct exclusion_element *) calloc(1, sizeof(struct exclusion_element));
  
  element->name = calloc(1, sizeof(char) * 100);
  ccn_name_comp_get(info->content_ccnb, info->content_comps, info->content_comps->n - 2, &element->name, &size);
  
  element->timer = g_timer_new();
  g_queue_push_head(user->exclusion_list, element);
  
  create_presence_interest(user);
  
  ccn_content_get_value(info->content_ccnb, info->pco->offset[CCN_PCO_E], info->pco, &pcontent, &len);
  XML_Parse(jcr->parser, pcontent, len, 0);
    
  return CCN_UPCALL_RESULT_OK;
}

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

static void
check_delete(gpointer data, gpointer user_data)
{
  struct exclusion_element *element = (struct exclusion_element*) data;
  GQueue *list = (GQueue*) user_data;
  gulong duration;
  
  g_timer_elapsed(element->timer, &duration);
  if (duration >= 2000000)
  {
    g_queue_remove(list, data);
    g_timer_destroy(element->timer);
    free(element->name);
    free(element);
  }    
}
  
int
create_presence_interest(cnu user)
{
  GQueue *exclusion_list = user->exclusion_list;
  struct ccn_charbuf *interest;
  struct ccn_charbuf **excl = NULL;
  int begin, i, length;
  gboolean excludeLow, excludeHigh;
  
  interest = ccn_charbuf_create();
  if (interest == NULL)
  {
    log_error(NAME, "ccn_charbuf_create failed");
    return 1;
  }
  ccn_name_from_uri(interest, "/ndn/broadcast/xmpp-muc");
  ccn_name_append_str(interest, jid_ns(user->room->id));
  
  if (g_queue_is_empty(exclusion_list))
  {
    int res = ccn_express_interest(nthread->ccn, interest, user->in_content_presence, NULL);
    if (res < 0)
    {
      log_error(NAME, "ccn_express_interest failed");
      return 1;
    }
    ccn_charbuf_destroy(&interest);
    return 0;
  }
  
  g_queue_foreach(exclusion_list, check_delete, exclusion_list);
  
  excl = calloc(1, sizeof(struct ccn_charbuf) * g_queue_get_length(exclusion_list));
  length = copy_from_list(excl, exclusion_list);
  qsort(&excl[0], length, sizeof(excl[0]), &namecompare);
  
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
    int res = ccn_express_interest(nthread->ccn, interest, user->in_content_presence, templ);
    if (res < 0)
    {
      log_error(NAME, "ccn_express_interest failed!");
      return 1;
    }
    
    ccn_charbuf_destroy(&templ);
  }
  
  ccn_charbuf_destroy(&interest);
  for (i = 0; i < length; i++)
    ccn_charbuf_destroy(&excl[i]); 

  free(excl);
  
  return 0;
}

int
create_presence_content(cnu user, char *data)
{
  struct ccn_charbuf *pname;
  struct ccn_charbuf *keylocator;
  struct ccn_charbuf *content;
  struct ccn_charbuf *signed_info;
  int res;
  char *content_name = calloc(1, sizeof(char) * 100);
  
  strcpy(content_name, "/ndn/broadcast/xmpp-muc/");
  strcat(content_name, jid_ns(user->room->id));
  strcat(content_name, "/");
  strcat(content_name, jid_ns(user->realid));
  pname = ccn_charbuf_create();
  ccn_name_from_uri(pname, content_name);

  /*
  struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
  struct ccn_charbuf *temp;
  
  sp.type = CCN_CONTENT_DATA;  
  if (sp.template_ccnb == NULL)
  {
    sp.template_ccnb = ccn_charbuf_create();
    ccn_charbuf_append_tt(sp.template_ccnb, CCN_DTAG_SignedInfo, CCN_DTAG);
  }
  else if (sp.template_ccnb->length > 0)
  {
    sp.template_ccnb->length--;
  }
  
  ccnb_tagged_putf(sp.template_ccnb, CCN_DTAG_FreshnessSeconds, "%d", 10);
  sp.sp_flags |= CCN_SP_TEMPL_FRESHNESS;
  ccn_charbuf_append_closer(sp.template_ccnb);
  
  temp = ccn_charbuf_create();
  temp->length = 0;
  res = ccn_sign_content(nthread->ccn, temp, pname, &sp, data, strlen(data));
  if (res != 0)
  {
    log_error(NAME, "ccn_sign_content failed");
    return 1;
  }
    
  res = ccn_put(nthread->ccn, temp->buf, temp->length);
  if (res < 0)
  {
    log_error(NAME, "ccn_put failed");
    return 1;
  }
  
  ccn_charbuf_destroy(&pname);
  ccn_charbuf_destroy(&temp);
  ccn_charbuf_destroy(&sp.template_ccnb);
  
  */
  
  signed_info = ccn_charbuf_create();
  keylocator = ccn_charbuf_create();
  ccn_create_keylocator(keylocator, ccn_keystore_public_key(keystore));
  res = ccn_signed_info_create(signed_info,
		/*pubkeyid*/ ccn_keystore_public_key_digest(keystore),
		/*publisher_key_id_size*/ ccn_keystore_public_key_digest_length(keystore),
		/*datetime*/ NULL,
		/*type*/ CCN_CONTENT_DATA,
		/*freshness*/ 10,
		/*finalblockid*/ NULL,
		/*keylocator*/ keylocator);
	
  if (res < 0)
  {
    log_error(NAME, "[%s]: Failed to create signed_info (res == %d)", FZONE, res);
    return 1;
  }
  
  log_debug(NAME, "[%s]: encoding content %s", FZONE, data);
  content = ccn_charbuf_create();
  ccn_encode_ContentObject(content, pname, signed_info,
			data, strlen(data), 
			NULL, ccn_keystore_private_key(keystore));
  ccn_put(nthread->ccn, content->buf, content->length);
  
  g_hash_table_insert(user->room->presence, content_name, content);
  
  ccn_charbuf_destroy(&signed_info);
  ccn_charbuf_destroy(&pname);
  //ccn_charbuf_destroy(&content);
  
  //free(content_name);
  
  return 0;
}

int
create_message_interest(cnu user, char *name, int seq)
{
  struct ccn_charbuf *interest;
  int res;
  char str_seq[10];
  
  interest = ccn_charbuf_create();
  if (interest == NULL)
  {
    log_error(NAME, "ccn_charbuf_create failed");
    return 1;
  }
  ccn_name_from_uri(interest, name);
  if (seq > 0)
  {
    itoa(seq, str_seq);
    ccn_name_append_str(interest, str_seq);
  }
  
  res = ccn_express_interest(nthread->ccn, interest, user->in_content_presence, NULL);
  if (res < 0)
  {
    log_error(NAME, "ccn_express_interest %s failed", name);
    return 1;
  }
  
  ccn_charbuf_destroy(&interest);
  return 0;
}

int
create_message_content(cnu user, char *data)
{
  struct ccn_charbuf *pname;
  struct ccn_charbuf *signed_info;
  struct ccn_charbuf *keylocator;
  struct ccn_charbuf *content, *dup_content;
  int res;
  char *content_name = calloc(1, sizeof(char) * 100);
  char *name_without_seq;
  char *seq_char = calloc(1, sizeof(char) * 10);
  
  strcpy(content_name, user->name_prefix);
  strcat(content_name, "/");
  strcat(content_name, jid_ns(user->realid));
  name_without_seq = j_strdup(content_name);
  strcat(content_name, "/");
  itoa(user->message_seq, seq_char);
  strcat(content_name, seq_char);
  pname = ccn_charbuf_create();
  ccn_name_from_uri(pname, content_name);
  
  /*
  struct ccn_charbuf *temp;
  
  sp.type = CCN_CONTENT_DATA;
  struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
  
  if (sp.template_ccnb == NULL)
  {
    sp.template_ccnb = ccn_charbuf_create();
    ccn_charbuf_append_tt(sp.template_ccnb, CCN_DTAG_SignedInfo, CCN_DTAG);
  }
  else if (sp.template_ccnb->length > 0)
  {
    sp.template_ccnb->length--;
  }
  
  ccnb_tagged_putf(sp.template_ccnb, CCN_DTAG_FreshnessSeconds, "%d", 10);
  sp.sp_flags |= CCN_SP_TEMPL_FRESHNESS;
  ccn_charbuf_append_closer(sp.template_ccnb);
  
  temp = ccn_charbuf_create();
  temp->length = 0;
  res = ccn_sign_content(nthread->ccn, temp, pname, &sp, data, strlen(data));
  if (res != 0)
  {
    log_error(NAME, "ccn_sign_content failed");
    return 1;
  }
  
  res = ccn_put(nthread->ccn, temp->buf, temp->length);
  if (res < 0)
  {
    log_error(NAME, "ccn_put failed");
    return 1;
  }
  
  ccn_charbuf_destroy(&pname);
  ccn_charbuf_destroy(&temp);
  ccn_charbuf_destroy(&sp.template_ccnb);
  */
  
  keylocator = ccn_charbuf_create();
  ccn_create_keylocator(keylocator, ccn_keystore_public_key(keystore));
  signed_info = ccn_charbuf_create();
  res = ccn_signed_info_create(signed_info,
		/*pubkeyid*/ ccn_keystore_public_key_digest(keystore),
		/*publisher_key_id_size*/ ccn_keystore_public_key_digest_length(keystore),
		/*datetime*/ NULL,
		/*type*/ CCN_CONTENT_DATA,
		/*freshness*/ 10,
		/*finalblockid*/ NULL,
		/*keylocator*/ keylocator);
	
  if (res < 0)
  {
    log_error(NAME, "FAILED TO CREATE signed_info (res == %d)", res);
    return 1;
  }
  
  content = ccn_charbuf_create();
  ccn_encode_ContentObject(content, pname, signed_info,
			data, strlen(data), 
			NULL, ccn_keystore_private_key(keystore));
  ccn_put(nthread->ccn, content->buf, content->length);
  
  dup_content = ccn_charbuf_create();
  ccn_charbuf_reset(dup_content);
  ccn_charbuf_append_charbuf(dup_content, content);
  
  g_hash_table_insert(user->room->message, content_name, content);
  g_hash_table_insert(user->room->message_latest, name_without_seq, dup_content);
    
  ccn_charbuf_destroy(&signed_info);
  ccn_charbuf_destroy(&pname);
  //ccn_charbuf_destroy(&content);
  //free(content_name);
  free(seq_char);
  
  return 0;
}

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

int
stop_ndn_thread()
{
  nthread->bRunning = 0;
  g_thread_join(nthread->thread);
  ccn_disconnect(nthread->ccn);
  ccn_destroy(&nthread->ccn);
  ccn_keystore_destroy(&keystore);
  free(nthread);
  
  return 0;
}