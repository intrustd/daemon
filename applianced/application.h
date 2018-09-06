#ifndef __appliance_application_H__
#define __appliance_application_H__

#include <uthash.h>

#include "util.h"

#define APP_PROTO   "kite+app:"
#define APP_URL_MAX 1024

struct appinstance {
  struct app     *inst_app;
  struct persona *inst_persona;

  // A mutex controlling access to the init process
  pthread_mutex_t inst_mutex;
  // A socket we can use to communicate with the init daemon (or 0) if the instance is not running
  int    inst_init_comm;

  // Entry in (struct app -> app_instances)
  UT_hash_handle inst_app_instance_hh;
  // Entry in (struct persona -> p_instances)
  UT_hash_handle inst_persona_instance_hh;

  // The application state keeps a list of all instances, and it
  // ultimately owns the memory for each instance
  DLIST(struct appinstance) inst_list_entry;
};

struct app {
  char *app_canonical_url;
  UT_hash_handle app_hh;

  pthread_mutex_t app_mutex;
  uint32_t app_flags;

  // Path to the latest directory containing the nix expression
  char *app_path;

  // Hash table mapping persona IDs to running applicatiosn
};

#define APP_FLAG_MUTEX_INITIALIZED 0x1
// Set when the application is building
#define APP_FLAG_IS_BUILDING       0x2

#endif
