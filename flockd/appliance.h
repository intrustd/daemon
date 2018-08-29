#ifndef __flock_appliance_H__
#define __flock_appliance_H__

#include <sys/socket.h>
#include <netinet/ip.h>
#include <uthash.h>

#include "util.h"

struct applianceinfo {
  // Must be the first field, because it's cast directly to aih_name in appinfo hash
  char               ai_name[KITE_APPLIANCE_NAME_MAX];
  struct sockaddr_in ai_addr;
  UT_hash_handle     aih_hash_ent;
};

void applianceinfo_clear(struct applianceinfo *info);

#endif
