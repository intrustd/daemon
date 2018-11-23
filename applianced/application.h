#ifndef __appliance_application_H__
#define __appliance_application_H__

#include <openssl/sha.h>
#include <uthash.h>

#include "util.h"
#include "container.h"

#define APP_SCHEME   "kite+app"
#define APP_MANIFEST_MAX_SIZE (64 * 1024)

#define APP_FORCE_RESET_TIMEOUT (2 * 60 * 1000) // Allow two minutes before force restarting an app

struct appstate;
struct appinstance {
  struct shared   inst_shared;
  struct app     *inst_app;
  struct persona *inst_persona;

  struct appstate *inst_appstate;

  // A mutex controlling access to the init process
  pthread_mutex_t inst_mutex;
  // A socket we can use to communicate with the init daemon (or 0) if the instance is not running
  int    inst_init_comm;

  struct container inst_container;

  // Entry in (struct app -> app_instances)
  UT_hash_handle inst_app_hh;
  // Entry in (struct persona -> p_instances)
  UT_hash_handle inst_persona_hh;

  uint32_t        inst_flags;
  struct qdevtsub inst_reset, inst_reset_complete;
  struct timersub inst_force_reset_timeout;
};

#define APPINSTANCE_REF(ai)    SHARED_REF(&(ai)->inst_shared)
#define APPINSTANCE_UNREF(ai)  SHARED_UNREF(&(ai)->inst_shared)
#define APPINSTANCE_WREF(ai)   SHARED_WREF(&(ai)->inst_shared)
#define APPINSTANCE_WUNREF(ai) SHARED_WUNREF(&(ai)->inst_shared)
#define APPINSTANCE_LOCK(ai)   SHARED_LOCK(&(ai)->inst_shared)

#define APPINSTANCE_FLAG_RESETTING 0x00000001

void appinstance_request_reset(struct eventloop *el, struct appinstance *ai);

struct appmanifest {
  struct shared am_shared;

  unsigned char am_digest[SHA256_DIGEST_LENGTH];

  uint32_t am_flags;

  // The entire manifest file, stored in memory
  unsigned int am_major, am_minor, am_revision;

  const char *am_domain;
  const char *am_name;
  const char *am_nix_closure;

  size_t am_bin_caches_count;
  const char **am_bin_caches;

  size_t am_bind_mount_count;
  const char **am_bind_mounts;
};

#define APPMANIFEST_FLAG_RUN_AS_ADMIN 0x1
#define APPMANIFEST_FLAG_SINGLETON    0x2

#define APPMANIFEST_REF(au) SHARED_REF(&(au)->am_shared)
#define APPMANIFEST_UNREF(au) SHARED_UNREF(&(au)->am_shared)

struct appmanifest *appmanifest_parse(const char *data, size_t data_sz);
struct appmanifest *appmanifest_parse_from_file(const char *filename, unsigned char *exp_digest);
int appmanifest_newer(struct appmanifest *new, struct appmanifest *old);

struct app {
  struct shared app_shared;

  char *app_domain;
  UT_hash_handle app_hh;

  pthread_mutex_t app_mutex;
  uint32_t app_flags;

  // The application manifest provides data about this application
  struct appmanifest *app_current_manifest;

  // A hash table of persona ids to appinstances
  struct appinstance *app_instances;

  struct appinstance *app_singleton;
};

#define APP_FLAG_MUTEX_INITIALIZED 0x1
#define APP_FLAG_BUILDABLE         0x2
#define APP_FLAG_UPDATING          0x4
#define APP_FLAG_BUILT             0x8
#define APP_FLAG_DOWNLOADING_MFST  0x10
#define APP_FLAG_RUN_AS_ADMIN      0x20
#define APP_FLAG_SINGLETON         0x40
#define APP_FLAG_AUTOSTART         0x80
#define APP_FLAG_SIGNED            0x100

#define APP_HAS_UNIVERSAL_ACCESS(app) ((app)->app_flags & APP_FLAG_RUN_AS_ADMIN)

#define APPLICATION_REF(app) SHARED_REF(&(app)->app_shared)
#define APPLICATION_UNREF(app) SHARED_UNREF(&(app)->app_shared)
#define APPLICATION_WREF(app) SHARED_WREF(&(app)->app_shared)
#define APPLICATION_WUNREF(app) SHARED_WUNREF(&(app)->app_shared)

struct app *application_from_manifest(struct appmanifest *mf);
void application_unset_flags(struct app *a, uint32_t fs);
void application_set_flags(struct app *a, uint32_t fs);
void application_request_instance_resets(struct eventloop *el, struct app *a); // app_mutex must be locked
int validate_perm_url(const char *url,
                      char *app_name, size_t app_name_sz,
                      char *app_domain, size_t app_domain_sz);

struct appmanifest *application_get_manifest(struct app *a);

struct appinstance *launch_app_instance(struct appstate *as, struct persona *p, struct app *a);

#endif
