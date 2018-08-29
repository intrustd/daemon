#ifndef __kite_stun_H__
#define __kite_stun_H__

#include <stdint.h>
#include <zlib.h>

#include "util.h"

#define STUN_MAX_ATTRIBUTES_SIZE 556 // Based on maximum message size

struct stuntxid {
  uint32_t a, b, c;
} KITE_PACKED;

struct stunmsg {
  uint16_t        sm_type;
  uint16_t        sm_len;
  uint32_t        sm_magic_cookie;
  struct stuntxid sm_tx_id;
  char            sm_attributes[STUN_MAX_ATTRIBUTES_SIZE];
} KITE_PACKED;

#define STUN_MAGIC_COOKIE 0x2112a442

#define STUN_INVALID_REQUEST   0x0000
#define STUN_BINDING           0x0001
#define STUN_KITE_REGISTRATION 0x0022

#define STUN_RESPONSE          0x0100
#define STUN_ERROR             0x0010

#define STUN_REQUEST_TYPE(hdr) (ntohs((hdr)->sm_type) & ~(STUN_RESPONSE | STUN_ERROR))

struct stunattr {
  uint16_t sa_name;
  uint16_t sa_length;
} KITE_PACKED;

#define STUN_IS_VALID(ptr, msg, sz) ((((uintptr_t) ptr) - ((uintptr_t) msg)) < sz)

#define STUN_ALIGN(len) (4 * ((len + 3) / 4))
#define STUN_FIRSTATTR(msg) ((struct stunattr *) (msg)->sm_attributes)
#define STUN_NEXTATTR(attr) ((struct stunattr *) (((uintptr_t) attr) + STUN_ALIGN(ntohs((attr)->sa_length))))
#define STUN_ATTR_DATA(attr) ((void *) ((uintptr_t) attr) + sizeof(struct stunattr))
#define STUN_MSG_LENGTH(msg) ntohs((msg)->sm_len)

#define STUN_INIT_MSG(msg, ty)                          \
  if(1) {                                               \
    (msg)->sm_type = htons(ty);                         \
    (msg)->sm_magic_cookie = htonl(STUN_MAGIC_COOKIE);  \
  }
#define STUN_FINISH_MSG(msg, last_attr, sz_ptr)                         \
  if (1) {                                                              \
    last_attr = STUN_NEXTATTR(last_attr);                               \
    (msg)->sm_len = htons(((uintptr_t) last_attr) - ((uintptr_t) msg)); \
  }
#define STUN_INIT_ATTR(attr, nm, payload)                               \
  if (1) {                                                              \
    (attr)->sa_name = htons(nm);                                        \
    (attr)->sa_length = htons(payload + sizeof(struct stunattr));       \
  }

#define STUN_ADD_FINGERPRINT(attr, msg)                                 \
  if (1) {                                                              \
    uint32_t __crc_ ## __LINE__;                                        \
                                                                        \
    attr = STUN_NEXTATTR(attr);                                         \
    STUN_INIT_ATTR(attr, STUN_ATTR_FINGERPRINT, 4);                     \
    *((uint32_t *) STUN_ATTR_DATA(attr)) = 0;                           \
                                                                        \
    __crc_ ## __LINE__ = crc32(0, (void *) msg,                         \
                               ((uintptr_t) attr) -                     \
                               ((uintptr_t) msg));                      \
    *((uint32_t *) STUN_ATTR_DATA(attr)) = ntohl(__crc_ ## __LINE__);   \
  }

#define STUN_ATTR_MAPPED_ADDRESS     0x0001
#define STUN_ATTR_USERNAME           0x0006
#define STUN_ATTR_MESSAGE_INTEGRITY  0x0008
#define STUN_ATTR_ERROR_CODE         0x0009
#define STUN_ATTR_XOR_MAPPED_ADDRESS 0x0020
#define STUN_ATTR_PRIORITY           0x0024
#define STUN_ATTR_USE_CANDIDATE      0x0025
#define STUN_ATTR_FINGERPRINT        0x8028
#define STUN_ATTR_ICE_CONTROLLED     0x8029
#define STUN_ATTR_ICE_CONTROLLING    0x802A
#define STUN_ATTR_RESPONSE_ORIGIN    0x802B
#define STUN_ATTR_OTHER_ADDRESS      0x802C

#define STUN_ATTR_KITE_APPL_NM       0x0040
#define STUN_ATTR_KITE_APPL_FPRINT   0x0041
#define STUN_ATTR_KITE_ICE_CAND      0x0042
#define STUN_ATTR_KITE_SIGNAL_ID     0x0043

#define STUN_ATTR_REQUIRED(attr)     (((attr) & 0x8000) == 0)
#define STUN_ATTR_OPTIONAL(attr)     (((attr) & 0x8000) != 0)

#define STUN_ATTR_TYPE(attr)         ntohs((attr)->sa_type)
#define STUN_ATTR_PAYLOAD_SZ(attr)   (ntohs((attr)->sa_length) - sizeof(stunattr))


#endif
