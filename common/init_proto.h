#ifndef __intrustd_init_proto_H__
#define __intrustd_init_proto_H__

#include <stdint.h>

#define APPINIT_MAX_PKT_SZ (2 * 1024 * 1024)
#define APPINIT_ARG_MAX (64 * 1024)
#define APPINIT_ENV_MAX (64 * 1024)

struct appinitmsg {
  uint16_t aim_req;
  uint32_t aim_flags;
  union {
    struct {
      int argc, envc;
    } run;
    struct {
      pid_t which;
      int sig;
    } kill;
    struct {
      int dir;
      uint16_t dom_len, tgt_len;
    } modhost;
  } un;
  char after[];
};

#define APPINIT_ARGS(msg) ((msg)->after)

#define APPINIT_REQ_RUN  0x0001
#define APPINIT_REQ_KILL 0x0002
#define APPINIT_REQ_MOD_HOST_ENTRY 0x0003

// The process follows the intrustd initialization protocol. Set this flag
// to wait for the process to really start
#define APPINIT_RUN_FLAG_INTRUSTD_INIT 0x00000001

#define APPINIT_RUN_FLAG_STDIN  0x00000002
#define APPINIT_RUN_FLAG_STDOUT 0x00000004
#define APPINIT_RUN_FLAG_STDERR 0x00000008

// Causes the process to send its return code on a pipe when it exits
#define APPINIT_RUN_FLAG_WAIT   0x00000010

#endif
