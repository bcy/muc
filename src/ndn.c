/* bcy: NDN related operations */
#include "ndn.h"
#include <../../ccnx-0.4.1/apps/wireshark/ccn/Makefile.in>

struct ndn_thread *nthread;

static enum ccn_upcall_res
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

static enum ccn_upcall_res
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

static enum ccn_upcall_res
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

static enum ccn_upcall_res
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
    ccn_destroy(&interest);
    return 0;
  }
  
  excl = calloc(sizeof(struct ccn_charbuf) * g_queue_get_length(exclusion_list));
  return 0;
}

static int
create_presence_content(char *name, char *data)
{
  return 0;
}

static int
create_message_interest(char *name, int seq)
{
  return 0;
}

static int
create_message_content(char *name, char *data)
{
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
  
  pthread->in_content_presence = (struct ccn_closure*) calloc(1, sizeof(struct ccn_closure));
  pthread->in_content_presence->p = &incoming_content_presence;
  pthread->in_interest_presence = (struct ccn_closure*) calloc(1, sizeof(struct ccn_closure));
  pthread->in_interest_presence->p = &incoming_interest_presence;
  pthread->in_content_message = (struct ccn_closure*) calloc(1, sizeof(struct ccn_closure));
  pthread->in_content_message->p = &incoming_content_message;
  pthread->in_interest_message = (struct ccn_closure*) calloc(1, sizeof(struct ccn_closure));
  pthread->in_interest_message->p = &incoming_interest_meesage;
  
  pthread->content_table = g_hashtable_new(NULL, NULL);
  pthread->nthread = g_thread_create(&ndn_run, (gpointer)ccn, TRUE, NULL);
  
  pthread->create_message_content = &create_message_content;
  pthread->create_presence_content = &create_presence_content;
  pthread->create_presence_interest = &create_presence_interest;
  pthread->create_message_interest = &create_message_interest;
  
  pthread->parse_ndn_packet = &parse_ndn_packet;
  
  return 0;
}