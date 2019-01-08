#ifndef __appliance_flock_H__
#define __appliance_flock_H__

#include <pthread.h>
#include <uriparser/Uri.h>
#include <uthash.h>
#include <netinet/in.h>

#include "stun.h"
#include "event.h"
#include "pconn.h"

#define FLOCK_SIGNATURE_METHOD SHA256
#define FLOCK_SIGNATURE_DIGEST_SZ 32
#define FLOCK_SIGNATURE_DIGEST_HEX_SZ "64"
#define FLOCK_MAX_CERT_DEPTH      16

#define FLOCK_DEFAULT_PORT 6854
#define FLOCK_URI_SCHEME "kite+flock"
#define STUN_URI_SCHEME  "stun"
#define STUNS_URI_SCHEME "stuns"

#define FLOCK_INITIAL_REGISTRATION_RTO 150 // 150 milliseconds
#define FLOCK_SEND_FAIL_INTERVAL       500 // After a socket failure, wait a half second
#define FLOCK_FLAG_TRY_AGAIN_INTERVAL  1000
#define FLOCK_SEND_REGISTRATION_INTERVAL (2 * 60000) // Send a new registration every two minutes
#define FLOCK_MAX_RETRIES              7
#define FLOCK_RETRY_RESOLUTION_INTERVAL 60000

#define FLOCK_TIMEOUT(f, initial) (initial << (f)->f_retries)
#define FLOCK_HAS_FAILED(f) ((f)->f_flock_state >= FLOCK_STATE_SUSPENDED)
#define FLOCK_IS_FAILING(f) ((f)->f_flags & FLOCK_FLAG_FAILING)
#define FLOCK_NO_MORE_RETRIES(f) ((f)->f_retries >= FLOCK_MAX_RETRIES)
#define FLOCK_NEXT_RETRY(f, el)                              \
  if (1) {                                                   \
    if ( FLOCK_IS_FAILING(f) && FLOCK_NO_MORE_RETRIES(f) ) { \
      (f)->f_flock_state = FLOCK_STATE_SUSPENDED;            \
      flock_shutdown_connection(f, (el));                    \
    } else {                                                 \
      (f)->f_flags |= FLOCK_FLAG_FAILING;                     \
      (f)->f_retries ++;                                     \
    }                                                        \
  }

struct flock {
  pthread_mutex_t f_mutex;

  char *f_uri_str; // Dynamically allocated raw normalized flock URI string
  char *f_hostname; // Dynamically allocated raw hostname

  uint16_t f_flock_state;
  uint32_t f_flags;

  unsigned char f_expected_digest[FLOCK_SIGNATURE_DIGEST_SZ];

  // An event thaht is triggered when a newly added flock is registered
  struct qdevtsub f_on_should_save;

  struct sockaddr_in f_cur_addr;

  UT_hash_handle f_hh;

  // Hash table of pending connection by id
  struct pconn *f_pconns;

  // Pending connections which have things to write on this flock
  DLIST_HEAD(struct pconn) f_pconns_with_response;

  union {
    struct dnssub f_resolver;
    struct timersub f_resolve_timer;
    struct {
      int  f_socket;
      struct fdsub f_socket_sub;
      SSL* f_dtls_client;

      int f_retries;

      struct timersub f_registration_timeout;
      struct stuntxid f_last_registration_tx;
      struct stunmsg f_registration_msg;

      struct timersub f_refresh_timer;
    };
  };
};

// The flock has not yet had service started
#define FLOCK_STATE_UNSTARTED   0
// The flock has not yet been contacted for joining
#define FLOCK_STATE_PENDING     1
// The flock address has been resolved, and we are in the process of sending the DTLS handshake
#define FLOCK_STATE_CONNECTING  2
// DTLS connection established and we need to send a registration message
#define FLOCK_STATE_SEND_REGISTRATION 3
// The DTLS connection has been established, we have sent a registration message and are waiting
#define FLOCK_STATE_REGISTERING 4
// The connection has been established and we have confirmed registration
#define FLOCK_STATE_REGISTERED  5
// The remote server has not responded in a while, and we have given up trying to connect again for now
#define FLOCK_STATE_SUSPENDED   6
// The DTLS handshake resulted in a certificate we did not accept
#define FLOCK_STATE_SRV_CRT_REJ 7
// The domainn name could not be resolved
#define FLOCK_STATE_NM_NOT_RES  8

#define FLOCK_FLAG_INITIALIZED        0x01
// We have been requested to force acceptance of the server certificate
#define FLOCK_FLAG_FORCE_ACCEPT       0x02
// Use insecure STUN to connect
#define FLOCK_FLAG_INSECURE           0x04
// The flock is currently registered
#define FLOCK_FLAG_REGISTRATION_VALID 0x08
// Set if the last registration failed
#define FLOCK_FLAG_FAILING            0x10
// Set if the flock has been added, but is not saved
#define FLOCK_FLAG_PENDING            0x20
// Validate the certificate when establishing the DTLS connection
#define FLOCK_FLAG_VALIDATE_CERT      0x40
// Only use STUN to connect to this flock
#define FLOCK_FLAG_STUN_ONLY          0x80
// Only use this flock for kite registration
#define FLOCK_FLAG_KITE_ONLY          0x100
// The flock encountered a conflict during registration
#define FLOCK_FLAG_CONFLICT           0x200

void flock_clear(struct flock *f);
void flock_release(struct flock *f);

// moves src into dst. Neither should be members of a hash table
void flock_move(struct flock *dst, struct flock *src);
int flock_assign_uri(struct flock *dst, UriUriA *uri);

void flock_start_service(struct flock *f, struct eventloop *el);
void flock_pconn_expires(struct flock *f, struct pconn *pc);

void flock_request_pconn_write(struct flock *f, struct pconn *pc);
void flock_request_pconn_write_unlocked(struct flock *f, struct pconn *pc);

#endif
