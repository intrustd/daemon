#ifndef __flock_appliance_H__
#define __flock_appliance_H__

#include <sys/socket.h>
#include <netinet/ip.h>
#include <uthash.h>

#include "client.h"
#include "util.h"
#include "connection.h"
#include "personas.h"
#include "stun.h"

struct applianceinfo;
struct flockservice;

// Whenever this is called, ai_mutex is locked independently
typedef int (*appliancefn)(struct applianceinfo *, int, void *);
#define AI_OP_RECONCILE        1
#define AI_OP_GET_PEER_ADDR    2
#define AI_OP_SEND_PACKET      3
#define AI_OP_GET_CERTIFICATE  4

// Keep at most the last 3 persona sets
#define AI_MAX_PERSONAS        3
// The maximum size of a persona set. Currently 64 kb
#define AI_MAX_PERSONASET_SIZE 65536
#define AI_PERSONAS_FETCH_RETRY_INTERVAL 100
#define AI_PERSONAS_FETCH_MAX_RETRIES 7

#define applianceinfo_ctl(ai, op, r) ((ai)->ai_appliance_fn((ai), op, r))
#define applianceinfo_get_peer_addr(ai, app_addr) applianceinfo_ctl(ai, AI_OP_GET_PEER_ADDR, app_addr)

struct aireconcile {
  struct applianceinfo *air_old, *air_new;
};

struct aipersonasfetcher {
  struct personasfetcher aipf_fetcher;

  struct eventloop *aipf_el;
  struct flockservice *aipf_service;
  struct applianceinfo *aipf_appliance;

  struct stuntxid aipf_tx_id;

  // The size of the persona set. Less than or equal to AI_MAX_PERSONASET_SIZE
  uint32_t aipf_personaset_size;
  // The current offset we are writing data to. If less than
  // aipf_personaset_size, then we are still transferring. If equal ( and the size > 0 ),
  // we are done. pf_is_complete will be marked appropriately
  uint32_t aipf_offset;

  // This timer rings when we have to retransmit a request
  struct timersub aipf_req_timeout;
  // The number of times we've retransmitted an request without any
  // intervening responses
  int aipf_req_retries;

  struct fcspktwriter aipf_pkt_writer;
};

#define AIPF_REF(a) PERSONASFETCHER_REF(&(a)->aipf_fetcher)
#define AIPF_WREF(a) PERSONASFETCHER_WREF(&(a)->aipf_fetcher)
#define AIPF_UNREF(a) PERSONASFETCHER_UNREF(&(a)->aipf_fetcher)
#define AIPF_WUNREF(a) PERSONASFETCHER_WUNREF(&(a)->aipf_fetcher)
#define AIPF_LOCK(a) PERSONASFETCHER_LOCK(&(a)->aipf_fetcher)

struct applianceinfo {
  // Must be the first field, because it's cast directly to aih_name in appinfo hash
  char               ai_name[KITE_APPLIANCE_NAME_MAX];
  struct shared      ai_shared;

  appliancefn        ai_appliance_fn;
  uint32_t           ai_flags;

  pthread_mutex_t    ai_mutex;

  UT_hash_handle     ai_hash_ent;

  struct personasfetcher *ai_personas[AI_MAX_PERSONAS];

  // Managed by connection_connect_appliance and connection_disconnect_appliance

  // A hash table (by connection id) of all connections currently
  // being established with this device
  struct connection *ai_connections;
};

#define AI_FLAG_SECURE      0x1
#define AI_FLAG_ACTIVE      0x2
#define AI_FLAG_INITIALIZED 0x4

#define AI_REF(ai)   SHARED_REF(&(ai)->ai_shared)
#define AI_UNREF(ai) SHARED_UNREF(&(ai)->ai_shared)
#define AI_WREF(ai)   SHARED_WREF(&(ai)->ai_shared)
#define AI_WUNREF(ai) SHARED_WUNREF(&(ai)->ai_shared)
#define APPLIANCEINFO_FROM_SHARED(sh) STRUCT_FROM_BASE(struct applianceinfo, ai_shared, sh)

int applianceinfo_init(struct applianceinfo *info, shfreefn free);
void applianceinfo_clear(struct applianceinfo *info);
void applianceinfo_release(struct applianceinfo *info);

X509 *applianceinfo_get_peer_certificate(struct applianceinfo *info);

struct personasfetcher *applianceinfo_lookup_personas(struct applianceinfo *info,
                                                      struct eventloop *el,
                                                      struct flockservice *svc,
                                                      const unsigned char *hash);

int applianceinfo_receive_persona_response(struct applianceinfo *info,
                                           const struct stunmsg *msg,
                                           int buf_sz);

#endif
