#ifndef __stork_init_proto_H__
#define __stork_init_proto_H__

#include <stdint.h>

#define STK_MAX_PKT_SZ (2 * 1024 * 1024)
#define STK_ARG_MAX (64 * 1024)
#define ENV_ARG_MAX (64 * 1024)

struct stkinitmsg {
  uint16_t sim_req;
  uint32_t sim_flags;
  union {
    struct {
      int argc, envc;
    } run;
  } un;
  char after[];
};

#define STK_ARGS(msg) ((msg)->after)

#define STK_REQ_RUN 0x0001

// The process follows the kite initialization protocol. Set this flag
// to wait for the process to really start
#define STK_RUN_FLAG_KITE 0x00000001

#endif
