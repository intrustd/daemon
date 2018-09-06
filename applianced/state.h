#ifndef __appliance_state_H__
#define __appliance_state_H__

#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <time.h>

#include "configuration.h"
#include "event.h"
#include "bridge.h"
#include "persona.h"
#include "application.h"
#include "flock.h"

#define DEFAULT_EC_CURVE_NAME NID_X9_62_prime256v1

struct appstate {
  uint32_t as_mutexes_initialized;

  char     as_appliance_name[KITE_APPLIANCE_NAME_MAX];

  const char *as_conf_dir;

  X509     *as_cert;
  EVP_PKEY *as_privkey;

  SSL_CTX  *as_dtls_ctx;

  struct brstate as_bridge;

  // Flocks that we have joined
  pthread_rwlock_t as_flocks_mutex;
  struct flock *as_flocks;

  // Personas that we have loaded
  pthread_rwlock_t as_personas_mutex;
  struct persona *as_personas;
  struct personaset *as_cur_personaset;

  // Apps that we have loaded
  pthread_rwlock_t as_applications_mutex;
  struct app *as_apps;
  DLIST_HEAD(struct appinstance) as_app_instances;

  int as_local_fd;
  struct fdsub as_local_sub;

  struct eventloop as_eventloop;
};

#define AS_FLOCK_MUTEX_INITIALIZED    0x1
#define AS_PERSONAS_MUTEX_INITIALIZED 0x2
#define AS_APPS_MUTEX_INITIALIZED     0x4

void init_appliance_global();
int SSL_CTX_set_appstate(SSL_CTX *ctx, struct appstate *as);
struct appstate *SSL_CTX_get_appstate(SSL_CTX *ctx);
int SSL_set_flock(SSL *ssl, struct flock *f);
struct flock *SSL_get_flock(SSL *ssl);

int appstate_setup(struct appstate *as, struct appconf *ac);
void appstate_release(struct appstate *as);

void appstate_start_services(struct appstate *as, struct appconf *ac);

int appstate_create_persona(struct appstate *as,
                            const char *display_name, int display_name_sz,
                            const char *password, int password_sz,
                            struct persona **p);
// The as_personas_mutex must be held for writing. The mutex of p should not be held for write
int appstate_save_persona(struct appstate *as, struct persona *p);

int appstate_lookup_persona(struct appstate *as, const char *pid, struct persona **p);

int appstate_create_flock(struct appstate *as, struct flock *f, int is_old);

// Return the current persona set. Returns 0 on success, -1 on error
int appstate_get_personaset(struct appstate *as, struct personaset **ps);

X509 *appstate_get_certificate(struct appstate *as);

#define APPSTATE_FROM_EVENTLOOP(el) STRUCT_FROM_BASE(struct appstate, as_eventloop, el)

#endif
