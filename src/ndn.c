/* bcy: NDN related operations */
#include "conference.h"

struct ndn_thread *nthread;

enum ccn_upcall_res
incoming_interest_meesage(
  struct ccn_closure *selfp,
  enum ccn_upcall_kind kind,
  struct ccn_upcall_info *info)
{
  switch (kind) {
    case CCN_UPCALL_FINAL:
      break;
      
    case CCN_UPCALL_INTEREST:
      break;
      
    default:
      break;
  }
  
  return CCN_UPCALL_RESULT_OK;
}

enum ccn_upcall_res
incoming_interest_presence(
  struct ccn_closure *selfp,
  enum ccn_upcall_kind kind,
  struct ccn_upcall_info *info)
{
  switch (kind) {
    case CCN_UPCALL_FINAL:
      break;
      
    case CCN_UPCALL_INTEREST:
      break;
      
    default:
      break;
  }
  
  return CCN_UPCALL_RESULT_OK;
}

enum ccn_upcall_res
incoming_content_message(
  struct ccn_closure *selfp,
  enum ccn_upcall_kind kind,
  struct ccn_upcall_info *info)
{
  switch (kind) {
    case CCN_UPCALL_FINAL:
      break;
      
    case CCN_UPCALL_INTEREST_TIMED_OUT:
      break;
      
    case CCN_UPCALL_CONTENT_UNVERIFIED:
      break;
      
    case CCN_UPCALL_CONTENT:
      break;
      
    default:
      break;
  }
  
  return CCN_UPCALL_RESULT_OK;
}

enum ccn_upcall_res
incoming_content_presence(
  struct ccn_closure *selfp,
  enum ccn_upcall_kind kind,
  struct ccn_upcall_info *info)
{
  switch (kind) {
    case CCN_UPCALL_FINAL:
      break;
      
    case CCN_UPCALL_INTEREST_TIMED_OUT:
      break;
      
    case CCN_UPCALL_CONTENT_UNVERIFIED:
      break;
      
    case CCN_UPCALL_CONTENT:
      break;
      
    default:
      break;
  }
  
  return CCN_UPCALL_RESULT_OK;
}

static gpointer
ndn_run(gpointer data)
{
  struct ccn *ccn = (struct ccn*) data;
  int res = ccn_run(ccn, 0);
  return res;
}

static int /* for qsort */
namecompare(const void *a, const void *b)
{
    const struct ccn_charbuf *aa = *(const struct ccn_charbuf **)a;
    const struct ccn_charbuf *bb = *(const struct ccn_charbuf **)b;
    int ans = ccn_compare_names(aa->buf, aa->length, bb->buf, bb->length);
    return ans;
}

static void
copy_from_list(struct ccn_charbuf **res, GQueue *list)
{
  GQueue *duplica = g_queue_copy(list);
  char *element;
  int idx = 0;
  while ((element = g_queue_pop_head(duplica)) != NULL)
  {
    struct ccn_charbuf *temp = ccn_charbuf_create();
    ccn_name_init(temp);
    ccn_name_append_str(temp, element);
    res[idx++] = temp;
  }
}

static int
create_presence_interest(char *roomid, GQueue *exclusion_list)
{
  struct ccn_charbuf *interest;
  struct ccn_charbuf **excl = NULL;
  
  interest = ccn_charbuf_create();
  if (interest == NULL)
  {
    log_error(NAME, "ccn_charbuf_create failed");
    return 1;
  }
  ccn_name_from_uri(interest, "/ndn/xmpp/muc/");
  ccn_name_append_str(interest, roomid);
  ccn_name_append_str(interest, "presence");
  
  if (g_queue_is_empty(exclusion_list))
  {
    int res = ccn_express_interest(nthread->ccn, interest, nthread->in_content_presence, NULL);
    if (res < 0)
    {
      log_error(NAME, "ccn_express_interest failed");
      return 1;
    }
    ccn_charbuf_destroy(&interest);
    return 0;
  }
  
  excl = calloc(sizeof(struct ccn_charbuf) * g_queue_get_length(exclusion_list));
  copy_from_list(excl, exclusion_list);
  qsort(excl, g_queue_get_length(exclusion_list), sizeof(struct ccn_charbuf), &namecompare);
  
  int begin = 0;
  bool excludeLow = false;
  bool excludeHigh = true;
  while (begin < g_queue_get_length(exclusion_list))
  {
    if (begin != 0)
      excludeLow = true;
    
    struct ccn_charbuf *templ = ccn_charbuf_create();
    ccn_charbuf_append_tt(templ, CCN_DTAG_Interest, CCN_DTAG); // <Interest>
    ccn_charbuf_append_tt(templ, CCN_DTAG_Name, CCN_DTAG); // <Name>
    ccn_charbuf_append_closer(templ); // </Name> 
    ccn_charbuf_append_tt(templ, CCN_DTAG_Exclude, CCN_DTAG); // <Exclude>
    
    if (excludeLow)
      append_bf_all(templ);
    
    for (; begin < g_queue_get_length(exclusion_list); begin++)
    {
      struct ccn_charbuf *comp = excl[begin];
      if (comp->length < 4)
	abort();
      
      // we are being conservative here
      if (interest->length + templ->length + comp->length > 1350)
	break;
      
      ccn_charbuf_append(templ, comp->buf + 1, comp->length - 2);
    }
    
    if (begin == g_queue_get_length(exclusion_list))
      excludeHigh = false;

    if (excludeHigh)
      append_bf_all(templ);
    
    ccn_charbuf_append_closer(templ); // </Exclude>
    ccn_charbuf_append_closer(templ); // </Interest> 
    int res = ccn_express_interest(ccn, interest, nthread->in_content_presence, templ);
    if (res < 0)
    {
      log_error(NAME, "ccn_express_interest failed!");
      return 1;
    }
    
    ccn_charbuf_destroy(&templ);
  }
  
  ccn_charbuf_destroy(&interest);
  for (int i = 0; i < g_queue_get_length(exclusion_list); i++)
    ccn_charbuf_destroy(&excl[i]); 

  free(excl);
  
  return 0;
}

static int
create_presence_content(char *name, char *data)
{
  struct ccn_charbuf *pname, *temp;
  struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
  int res;
  char *content_name = calloc(1, sizeof(char) * 50);
  
  strcpy(content_name, "/ndn/xmpp/muc/");
  strcat(content_name, name);
  strcat(content_name, "/presence");
  pname = ccn_charbuf_create();
  ccn_name_from_uri(pname, content_name);
  
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
  
  ccnb_tagged_putf(sp.template_ccnb, CCN_DTAG_FreshnessSeconds, 10);
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
  
  g_hash_table_insert(nthread->content_table, content_name, data);
  
  res = ccn_put(ccn, temp->buf, temp->length);
  if (res < 0)
  {
    log_error(NAME, "ccn_put failed");
    return 1;
  }
  
  ccn_charbuf_destroy(&pname);
  ccn_charbuf_destroy(&temp);
  ccn_charbuf_destroy(&sp.template_ccnb);
  free(content_name);
  
  return 0;
}

static int
create_message_interest(char *name, int seq)
{
  struct ccn_charbuf *interest;
  int res;
  
  interest = ccn_charbuf_create();
  if (interest == NULL)
  {
    log_error(NAME, "ccn_charbuf_create failed");
    return 1;
  }
  ccn_name_from_uri(interest, "/ndn/xmpp/muc/");
  ccn_name_append_str(interest, roomid);
  ccn_name_append_str(interest, "message");
  ccn_name_append_numeric(interest, seq);
  
  res = ccn_express_interest(nthread->ccn, interest, nthread->in_content_presence, NULL);
  if (res < 0)
  {
    log_error(NAME, "ccn_express_interest failed");
    return 1;
  }
  
  ccn_charbuf_destroy(&interest);
  return 0;
}

static int
create_message_content(char *name, int seq, char *data)
{
  struct ccn_charbuf *pname, *temp;
  struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
  int res;
  char *content_name = calloc(1, sizeof(char) * 50);
  char *seq_char = calloc(1, sizeof(char) * 10);
  
  strcpy(content_name, "/ndn/xmpp/muc/");
  strcat(content_name, name);
  strcat(content_name, "/message/");
  itoa(seq, seq_char);
  strcat(content_name, seq_char);
  pname = ccn_charbuf_create();
  ccn_name_from_uri(pname, content_name);
  
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
  
  ccnb_tagged_putf(sp.template_ccnb, CCN_DTAG_FreshnessSeconds, 10);
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
  
  g_hash_table_lookup(nthread->room_table, name);
  
  res = ccn_put(ccn, temp->buf, temp->length);
  if (res < 0)
  {
    log_error(NAME, "ccn_put failed");
    return 1;
  }
  
  ccn_charbuf_destroy(&pname);
  ccn_charbuf_destroy(&temp);
  ccn_charbuf_destroy(&sp.template_ccnb);
  free(content_name);
  free(seq_char);
  
  return 0;
}

static int
parse_ndn_packet()
{
  return 0;
}

int
init_ndn_thread(struct ndn_thread *pthread)
{
  pthread = (struct ndn_thread*) calloc(1, sizeof(struct ndn_thread));
  if (pthread == NULL)
  {
    log_error(NAME, "Memory allocation error!");
    return 1;
  }
    
  pthread->room_table = g_hash_table_new(NULL, NULL);
  pthread->nthread = g_thread_create(&ndn_run, (gpointer)ccn, TRUE, NULL);
  
  pthread->create_message_content = &create_message_content;
  pthread->create_presence_content = &create_presence_content;
  pthread->create_presence_interest = &create_presence_interest;
  pthread->create_message_interest = &create_message_interest;
  
  pthread->parse_ndn_packet = &parse_ndn_packet;
  
  return 0;
}