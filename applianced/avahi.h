#ifndef __appliance_avahi_H__
#define __appliance_avahi_H__

#include "util.h"
#include "event.h"
#include "pconn.h"

#define DNS_DOMAIN_MAXLEN 253
#define AVAHI_RESPONSE_MAXLEN 256

#define AVAHI_RESOLVE_IPV6 4
#define AVAHI_RESOLVE_IPV4 3
#define AVAHI_IN_PROGRESS 2
#define AVAHI_UNSTARTED 1
#define AVAHI_SUCCESS 0
#define AVAHI_UNAVAILABLE (-1)
#define AVAHI_NOT_RESPONDING (-2)
#define AVAHI_INVALID_RESPONSE (-3)
#define AVAHI_RESPONSE_OVERFLOW (-4)
#define AVAHI_NOT_FOUND (-5)

#define AVAHIREQUEST_FROM_FINISH_EVT(evt) STRUCT_FROM_BASE(struct avahirequest, ar_finished_evt, (evt)->qde_sub)

#define AVAHIREQUEST_REF(ar) SHARED_REF(&(ar)->ar_shared)
#define AVAHIREQUEST_UNREF(ar) SHARED_UNREF(&(ar)->ar_shared)
#define AVAHIREQUEST_WREF(ar) SHARED_WREF(&(ar)->ar_shared)
#define AVAHIREQUEST_WUNREF(ar) SHARED_WUNREF(&(ar)->ar_shared)
#define AVAHIREQUEST_LOCK(ar) SHARED_LOCK(&(ar)->ar_shared)

struct avahirequest {
  struct shared ar_shared;

  pthread_mutex_t ar_mutex;

  char ar_domain[DNS_DOMAIN_MAXLEN + 1];

  char ar_response[AVAHI_RESPONSE_MAXLEN];
  int ar_response_len;

  struct eventloop *ar_eventloop;

  struct qdevtsub ar_finished_evt;
  struct qdevtsub ar_start_evt;
  struct fdsub ar_sock_evt;
  struct timersub ar_timeout_evt;

  int ar_fd;

  int ar_status;

  intrustd_sock_addr ar_resolved_addr;
  uint16_t ar_port;

  char ar_data[];
};

/*
 * Returns 1 if the given address is a .local address, 0 otherwise
 */
int is_local_address(char *addr, size_t addr_sz);

/*
 * Allocate an avahi request for the given domain and pconn. Allocates user data of size data_sz.
 *
 * The given op fn is called on completion. Ar_status will be set.
 */
struct avahirequest *avahirequest_alloc(const char *domain, size_t domain_sz, uint16_t port,
                                        size_t data_sz, int finish_op, evtctlfn finish_fn);

/*
 * Start the avahi request in the given event loop
 */
void avahirequest_start(struct avahirequest *ar, struct eventloop *el);

/*
 * Get the status, and the resolved address, if any, from the avahi request
 */
int avahirequest_get_status(struct avahirequest *ar, int *sts, intrustd_sock_addr *addr);

/*
 * Get a string corresponding to the avahi status
 */
const char *avahi_error_string(int sts);

#endif
