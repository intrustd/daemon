#ifndef __appliance_persona_H__
#define __appliance_persona_H__

#include <openssl/sha.h>
#include <uthash.h>

#include "buffer.h"
#include "util.h"
#include "bridge.h"
#include "application.h"

#define PERSONA_ID_X_LENGTH 64
#define PERSONA_ID_LENGTH   32

#define PAUTH_DATA_SIZE     256

#define PAUTH_TYPE_SHA256   1
#define PAUTH_TYPE_TOKEN    2

#define PERSONA_HOSTNAME_PREFIX "persona-"

struct pauth {
  int pa_type;
  struct pauth *pa_next;
  char pa_data[PAUTH_DATA_SIZE];
};

struct appstate;
struct appinstance;
struct pconn;

// struct personaport {
//   uint16_t pp_port;
//   UT_hash_handle pp_hh;
// };

struct persona {
  struct shared p_shared;

  struct appstate *p_appstate;
  pthread_mutex_t p_mutex;

  char p_persona_id[PERSONA_ID_LENGTH];
  UT_hash_handle p_hh;

  // Personal information
  char *p_display_name;

  EVP_PKEY *p_private_key;

  // Authentication mechanisms that are required to log in
  struct pauth *p_auths;

//  uint16_t p_last_port;
//  struct personaport *p_ports;

  uint32_t p_flags;

  struct appinstance *p_instances;
};

#define PERSONA_REF(p) SHARED_REF(&(p)->p_shared)
#define PERSONA_UNREF(p) SHARED_UNREF(&(p)->p_shared)

int persona_init(struct persona *p, struct appstate *as,
                 const char *display_name,
                 int display_name_sz,
                 EVP_PKEY *private_key);
int persona_init_fp(struct persona *p, struct appstate *as, FILE *fp);

int persona_add_password(struct persona *p,
                         const char *password,
                         int password_sz);
int persona_add_token_security(struct persona *p);

// Save the persona to the FILE. You must hold p_mutex
int persona_save_fp(struct persona *p, FILE *fp);
struct persona *persona_read_fp(FILE *fp);

int persona_write_as_vcard(struct persona *p, struct buffer *b);

// pc->pc_mutex must be held!!
int persona_credential_validates(struct persona *p, struct pconn *pc,
                                 const char *cred, size_t cred_sz);

// int persona_allocate_port(struct persona *p, uint16_t *port);
// void persona_release_port(struct persona *p, uint16_t port);

// Runs a new webrtc proxy and returns the PID of the proxy.
pid_t persona_run_webrtc_proxy(struct persona *p, uint16_t port);

pid_t persona_run_ping_test(struct persona *p);

// Send the given signal to the process
void persona_kill(struct persona *p, pid_t which, int sig);

// Wait for the given process to end
int persona_wait(struct persona *p, pid_t which, int *sts);

// A personaset is a set of personas that have been serialized to a
// buffer. The buffer is managed via a shared pointer, so that its
// lifetime is managed separately from any personas.
//
// The serialization format is a sequence of VCards.
//
// A persona set has a unique sha256 key. The key of the newest
// persona set at the time of connection creation is transmitted in
// every start connection response. The current persona set is
// retrieved via call to appstate_get_personaset, which returns a
// reference to a new personaset. PERSONASET_UNREF should be called
// when complete.
//
// A persona set can be transmitted to a flock, but only a maximum
// number may be in transmission at any one time.
struct personaset {
  struct shared ps_shared;

  unsigned char ps_hash[SHA256_DIGEST_LENGTH];

  const char   *ps_buf;
  size_t        ps_buf_sz;
};

#define PERSONASET_REF(ps)   SHARED_REF(&(ps)->ps_shared)
#define PERSONASET_UNREF(ps) SHARED_UNREF(&(ps)->ps_shared)

struct personaset *personaset_from_buf(const char *buf, size_t sz);

#endif
