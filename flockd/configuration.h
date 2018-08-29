#ifndef __flock_configuration_H__
#define __flock_configuration_H__

#include "stdint.h"

struct flockconf {
  const char *fc_certificate_file;
  const char *fc_privkey_file;
  const char *fc_shards_file;
  uint16_t fc_service_port;
  uint16_t fc_websocket_port;
};

void flockconf_init(struct flockconf *c);
int flockconf_parse_options(struct flockconf *c, int argc, char **argv);
int flockconf_validate(struct flockconf *c, int do_debug);

#endif
