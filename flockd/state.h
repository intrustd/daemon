#ifndef __flock_state_H__
#define __flock_state_H__

#include <openssl/x509.h>
#include <pthread.h>

#include "configuration.h"
#include "event.h"
#include "service.h"

struct flockstate {
  X509     *fs_flock_cert;
  EVP_PKEY *fs_flock_privkey;

  // Shards
  struct {
    int fs_shard_count, fs_our_shard_index;
    struct sockaddr_in *fs_shards;
  } fs_shards;

  struct flockservice fs_service;

  int fs_websocket_sk;
  struct fdsub fs_websocket_sub;

  struct eventloop fs_eventloop;
};

#define FLOCKSTATE_FROM_SERVICE(svc) STRUCT_FROM_BASE(struct flockstate, fs_service, svc)
#define FLOCKSTATE_FROM_EVENTLOOP(el) STRUCT_FROM_BASE(struct flockstate, fs_eventloop, el)

int flockstate_init(struct flockstate *st, struct flockconf *conf);
void flockstate_release(struct flockstate *st);

int flockstate_set_conf(struct flockstate *st, struct flockconf *conf);

void flockstate_start_services(struct flockstate *st);

#endif
