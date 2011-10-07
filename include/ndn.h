/* bcy: ndn.h */

#include <glib.h>
#include <ccn/ccn.h>

struct ndn_thread {
  GThread *nthread;
  struct ccn *ccn;
  struct ccn_closure *in_interest_presence, *in_interest_message, *in_content_presence, *in_content_message;
  GHashtable *room_table;
  
  int (*parse_ndn_packet());
  int (*create_presence_interest());
  int (*create_message_interest());
  int (*create_presence_content());
  int (*create_message_content());
};