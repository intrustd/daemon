#ifndef __flock_proto_H__
#define __flock_proto_H__

#include <arpa/inet.h>

#define FLOCK_PACKED __attribute__((packed))

struct flockmsg {
  uint8_t  fm_op;
  uint8_t  fm_flags;
  uint32_t fm_tag;
} FLOCK_PACKED;

#define FM_OP_REGISTER         0x1
#define FM_OP_START_CONNECTION 0x2
#define FM_OP_REPORT_ICE_CAND  0x3

#define FM_FLAG_RESPONSE       0x1
#define FM_FLAG_ERROR          0x2

struct flockmsgattr {
  uint8_t  fma_name;
  uint16_t fma_length;
  uint8_t  fma_flags;
} FLOCK_PACKED;

#define FM_FIRST_ATTR(msg, sz) ((struct flockmsgattr *) ((sz) >= sizeof(flockmsg) ? ((uintptr_t) (msg)) + sizeof(struct flockmsg) : 0))
#define FM_NEXT_ATTR(msg, sz, attr)                                     \
  ((struct flockmsgattr *) ((sz) >= (((uintptr_t) (attr)) - ((uintptr_t) (msg)) + ntohs((attr)->fma_length)) ? \
                            (((uintptr_t) attr) + ntohs((attr)->fma_length)) : NULL))

#define FMA_APPLIANCE_NAME     0x1
#define FMA_APPLIANCE_PUBKEY   0x2
#define FMA_CONN_TAG           0x3
#define FMA_ICE_CANDIDATE      0x4

#endif
