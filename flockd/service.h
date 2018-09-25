#ifndef __flock_service_H__
#define __flock_service_H__

#include <pthread.h>
#include <openssl/ssl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "connection.h"
#include "appliance.h"
#include "event.h"
#include "util.h"
#include "stun.h"
#include "dtls.h"

#define PKT_BUF_SZ 2048

struct flocksvcclientstate;
struct flockservice {
  uint8_t fs_mutexes_initialized;

  pthread_mutex_t fs_service_mutex;   // Mutex for write operations on this socket
  struct flocksvcclientstate *fs_first_outgoing, *fs_last_outgoing;
  int fs_service_sk;
  struct fdsub fs_service_sub;
  struct BIO_static fs_sk_incoming;
  BIO_ADDR *fs_incoming_addr;

  pthread_rwlock_t fs_clients_mutex;  // Mutex for client hash table
  struct flocksvcclientstate *fs_clients_hash;

  pthread_rwlock_t fs_appliances_mutex;
  struct applianceinfo *fs_appliances;

  pthread_rwlock_t fs_connections_mutex;
  struct connection *fs_connections;

  pthread_mutex_t fs_dtls_cookies_mutex;
  struct dtlscookies fs_dtls_cookies;

  // We keep an on-disk cache of personsas. The cache is cleaned out periodically

  SSL_CTX *fs_ssl_ctx;

  char fs_incoming_packet[PKT_BUF_SZ];
};

#define FS_SERVICE_MUTEX      0x1
#define FS_CLIENTS_MUTEX      0x2
#define FS_APPLIANCES_MUTEX   0x4
#define FS_CONNECTIONS_MUTEX  0x8
#define FS_DTLS_COOKIES_MUTEX 0x10

int flockservice_init(struct flockservice *svc, X509 *cert, EVP_PKEY *pkey, struct eventloop *el, uint16_t port);
void flockservice_clear(struct flockservice *svc);
void flockservice_release(struct flockservice *svc);
void flockservice_start(struct flockservice *svc, struct eventloop *el);

int flockservice_new_connection(struct flockservice *svc, struct connection *conn);
int flockservice_finish_connection(struct flockservice *svc, struct connection *conn);

// Attempts to register the appliance provided in the message.
//
// app is assumed to be a pointer to an appliance info struct that
// will be included in the hash table.
//
// Returns 0 if a response should be sent. rsp_sz is set to the total
// size of the response.
//
// Returns a positive number if no response should be sent, but there is no error.
//
// If the return value is >= 0 and app is not NULL, appliance should be kept around
//
// If the return value is less than 0, appliance was not added to the appliances hash table.
int flockservice_handle_appliance_registration(struct flockservice *svc,
                                               struct applianceinfo *app,
                                               const struct stunmsg *msg, int msg_sz,
                                               char *rsp_buf, size_t *rsp_sz);

void flock_service_fn(int op, void *arg);

// Lookup the appliance with the given name. The fs_appliances_mutex
// must be held for reading at least.
//
// Returns -1 on error, 0 otherwise. On success, ai is filled in with
// a new reference to the appliance.
int flockservice_lookup_appliance(struct flockservice *f, const char *name,
                                  struct applianceinfo **ai);

// Like flockservice_lookup_appliance, but lets you specify the length of name
int flockservice_lookup_appliance_ex(struct flockservice *f,
                                     const char *name, int name_sz,
                                     struct applianceinfo **ai);

// Lookup the given connection returning a new reference. Returns -1
// on error, 0 on success.
//
// fs_connections_mutex must be held for reading
int flockservice_lookup_connection(struct flockservice *f, uint64_t conn_id,
                                   struct connection **c);

struct cpersonaset;
#define FLOCKSERVICE_CACHED_PERSONASET_FOUND 0
#define FLOCKSERVICE_CACHED_PERSONASET_NEW   1
int flockservice_open_cached_personaset(struct flockservice *svc,
                                        const char *appliance_name, const unsigned char *ps_hash,
                                        int ps_hash_sz, struct cpersonaset **cps);

#define FLOCKSERVICE_REMOVE_REASON_APPLIANCE_EXPIRED 1
void flockservice_remove_appliance(struct flockservice *f, struct applianceinfo *ai, int reason);

#endif
