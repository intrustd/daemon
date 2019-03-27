#ifndef __intrustd_stun_H__
#define __intrustd_stun_H__

#include <stdint.h>
#include <zlib.h>
#include <arpa/inet.h>
#include <openssl/sha.h>

#include "util.h"

#define STUN_MAX_ATTRIBUTES_SIZE 556 // Based on maximum message size
#define MAX_STUN_MSG_SIZE 576
#define STUN_MSG_HDR_SZ 20
#define STUN_FINGERPRINT_GAP 12 // How much space we should leave in a buffer for the fingerprint attribute
#define STUN_MESSAGE_INTEGRITY_LENGTH SHA_DIGEST_LENGTH

struct stuntxid {
  union {
    struct { uint32_t a, b, c; };
    char stx_raw_bytes[12];
  };
} INTRUSTD_PACKED;


struct stunmsg {
  uint16_t        sm_type;
  uint16_t        sm_len;
  uint32_t        sm_magic_cookie;
  struct stuntxid sm_tx_id;
  char            sm_attributes[STUN_MAX_ATTRIBUTES_SIZE];
} INTRUSTD_PACKED;

#define STUN_MAGIC_COOKIE 0x2112a442

#define STUN_INVALID_REQUEST   0x0000
#define STUN_BINDING           0x0001
#define STUN_INTRUSTD_REGISTRATION 0x0022
#define STUN_INTRUSTD_STARTCONN    0x0023
#define STUN_INTRUSTD_GET_PERSONAS 0x0024
#define STUN_INTRUSTD_SENDOFFER    0x0025

#define STUN_RESPONSE          0x0100
#define STUN_ERROR             0x0010
#define STUN_INDICATION        0x0010

#define STUN_MESSAGE_TYPE(hdr) ntohs((hdr)->sm_type)
#define STUN_REQUEST_TYPE(hdr) (STUN_MESSAGE_TYPE(hdr) & ~(STUN_RESPONSE | STUN_ERROR))
#define STUN_MSG_CLASS(hdr) (STUN_MESSAGE_TYPE(hdr) & (STUN_RESPONSE | STUN_INDICATION))

struct stunattr {
  uint16_t sa_name;
  uint16_t sa_length;
} INTRUSTD_PACKED;

#define STUN_IS_VALID(ptr, msg, sz) ((((uintptr_t) ptr) - ((uintptr_t) msg)) < sz)
#define STUN_CAN_WRITE_ATTR(attr, msg, sz) (STUN_IS_VALID(((uintptr_t) attr) + sizeof(struct stunattr), msg, sz))
#define STUN_ATTR_IS_VALID(attr, msg, sz) \
  (STUN_IS_VALID(attr, msg, sz) && (((uintptr_t) STUN_NEXTATTR(attr)) - ((uintptr_t) msg)) <= sz)
#define STUN_COOKIE_VALID(msg) (ntohl((msg)->sm_magic_cookie) == STUN_MAGIC_COOKIE)
#define STUN_IS_STUN(msg) ((*((uint8_t *) msg) & 0xC0) == 0)

#define STUN_ALIGN(len) ((len) > 0 ? (4 * (((len) + 3) / 4)) : 0)
#define STUN_FIRSTATTR(msg) ((struct stunattr *) (msg)->sm_attributes)
#define STUN_NEXTATTR(attr) ((struct stunattr *) (((uintptr_t) attr) + STUN_ATTR_TOTAL_SZ(attr)))
#define STUN_ATTR_DATA(attr) ((void *) ((uintptr_t) attr) + sizeof(struct stunattr))
#define STUN_MSG_LENGTH(msg) (ntohs((msg)->sm_len) + STUN_MSG_HDR_SZ)
#define STUN_OFFSET(msg, attr) (((uintptr_t) attr) - ((uintptr_t)msg))

#define STUN_INIT_MSG(msg, ty)                          \
  if(1) {                                               \
    (msg)->sm_type = htons(ty);                         \
    (msg)->sm_magic_cookie = htonl(STUN_MAGIC_COOKIE);  \
  }
#define STUN_INIT_ATTR(attr, nm, payload)                               \
  if (1) {                                                              \
    (attr)->sa_name = htons(nm);                                        \
    (attr)->sa_length = htons(payload);                                 \
  }
#define STUN_REMAINING_BYTES(attr, msg, sz) (sz - (((uintptr_t)attr) - ((uintptr_t)msg)))

#define STUN_FINISH_WITH_FINGERPRINT(attr, msg, sz, err)                \
  do {                                                                  \
    uint32_t __crc_ ## __LINE__;                                        \
    struct stunattr *__attr_ ## __LINE__;                               \
                                                                        \
    (err) = 0;                                                          \
    attr = STUN_NEXTATTR(attr);                                         \
    if ( !STUN_IS_VALID(attr, msg, sz) ) { (err) = -1; break; }         \
    STUN_INIT_ATTR(attr, STUN_ATTR_FINGERPRINT, 4);                     \
    if ( !STUN_ATTR_IS_VALID(attr, msg, sz) ) { (err) = -1; break; }    \
    *((uint32_t *) STUN_ATTR_DATA(attr)) = 0;                           \
    __attr_ ## __LINE__ = STUN_NEXTATTR(attr);                          \
                                                                        \
    (msg)->sm_len = htons(((uintptr_t) __attr_ ## __LINE__) - ((uintptr_t) (msg)->sm_attributes)); \
                                                                        \
    __crc_ ## __LINE__ = crc32(0, (void *) msg,                         \
                               ((uintptr_t) attr) -                     \
                               ((uintptr_t) msg));                      \
    __crc_ ## __LINE__ ^= 0x5354554e;                                   \
    *((uint32_t *) STUN_ATTR_DATA(attr)) = ntohl(__crc_ ## __LINE__);   \
  } while(0)

#define STUN_ATTR_MAPPED_ADDRESS     0x0001
#define STUN_ATTR_USERNAME           0x0006
#define STUN_ATTR_PASSWORD           0x0007
#define STUN_ATTR_MESSAGE_INTEGRITY  0x0008
#define STUN_ATTR_ERROR_CODE         0x0009
#define STUN_ATTR_UNKNOWN_ATTRIBUTES 0x000A
#define STUN_ATTR_XOR_MAPPED_ADDRESS 0x0020
#define STUN_ATTR_PRIORITY           0x0024
#define STUN_ATTR_USE_CANDIDATE      0x0025
#define STUN_ATTR_FINGERPRINT        0x8028
#define STUN_ATTR_ICE_CONTROLLED     0x8029
#define STUN_ATTR_ICE_CONTROLLING    0x802A
#define STUN_ATTR_RESPONSE_ORIGIN    0x802B
#define STUN_ATTR_OTHER_ADDRESS      0x802C

#define STUN_ATTR_INTRUSTD_APPL_FPRINT   0x0040
#define STUN_ATTR_INTRUSTD_ICE_CAND      0x0041
#define STUN_ATTR_INTRUSTD_CONN_ID       0x0042
#define STUN_ATTR_INTRUSTD_PERSONAS_HASH 0x0043
#define STUN_ATTR_INTRUSTD_CANCELED      0x0044
#define STUN_ATTR_INTRUSTD_SDP_LINE      0x0045
#define STUN_ATTR_INTRUSTD_PERSONAS_OFFS 0x0046
#define STUN_ATTR_INTRUSTD_PERSONAS_SIZE 0x0047
#define STUN_ATTR_INTRUSTD_PERSONAS_DATA 0x0048
#define STUN_ATTR_INTRUSTD_ANSWER        0x0049
#define STUN_ATTR_INTRUSTD_ANSWER_OFFSET 0x004A
#define STUN_ATTR_INTRUSTD_FORMAT        0x004B

#define STUN_ATTR_REQUIRED(attr)     (((attr) & 0x8000) == 0)
#define STUN_ATTR_OPTIONAL(attr)     (((attr) & 0x8000) != 0)

#define STUN_ATTR_NAME(attr)         ntohs((attr)->sa_name)
#define STUN_ATTR_PAYLOAD_SZ(attr)   ntohs((attr)->sa_length)
#define STUN_ATTR_TOTAL_SZ(attr)     (STUN_ALIGN(ntohs((attr)->sa_length)) + sizeof(struct stunattr))

#define STUN_ADDR_IN  1
#define STUN_ADDR_IN6 2

#define STUN_NOT_STUN           (-1)
#define STUN_SUCCESS            000
#define STUN_TRY_ALTERNATE      300
#define STUN_BAD_REQUEST        400
#define STUN_UNAUTHORIZED       401
#define STUN_NOT_FOUND          404
#define STUN_CONFLICT           409
#define STUN_UNKNOWN_ATTRIBUTES 420
#define STUN_TOO_EARLY          425
#define STUN_STALE_NONCE        438
#define STUN_ROLE_CONFLICT      487
#define STUN_SERVER_ERROR       500

#define STUN_MISSING_ERROR_CODE 0x10000
#define STUN_REQUEST_MISMATCH   0x10001
#define STUN_TX_ID_MISMATCH     0x10002

#define STUN_INTRUSTD_FORMAT_WEBRTC 0x1
#define STUN_INTRUSTD_FORMAT_VLAN   0x2

typedef int(*stunusercb)(const char *, size_t, const char **, size_t *, void *);
typedef int(*stunattrcb)(uint16_t, const char *, size_t, void *);

#define STUN_ACCEPT_UNKNOWN stun_accept_unknown
int stun_accept_unknown(uint16_t attr, const char *data, size_t sz, void *a);

#define STUN_VALIDATE_VERBOSE       0x1
#define STUN_NEED_FINGERPRINT       0x2
#define STUN_NEED_MESSAGE_INTEGRITY 0x4
#define STUN_HAD_FINGERPRINT        0x8
#define STUN_HAD_MESSAGE_INTEGRITY  0x10
#define STUN_FINGERPRINT_VALID      0x20
#define STUN_VALIDATE_RESPONSE      0x40
#define STUN_VALIDATE_TX_ID         0x80
#define STUN_VALIDATE_REQUEST       0x100
#define STUN_HAD_USERNAME           0x200
#define STUN_ACCEPT_INDICATION      0x400
#define STUN_IS_INDICATION          0x800

struct stunvalidation {
  int        sv_flags;

  uint16_t   sv_req_code;
  struct stuntxid *sv_tx_id;

  stunusercb sv_user_cb;
  stunattrcb sv_unknown_cb;
  void      *sv_user_data;

  uint16_t  sv_error_code;

  uint16_t *sv_unknown_attrs;
  int       sv_unknown_attrs_sz;
};

int stun_validate(const char *buf, int buf_sz, struct stunvalidation *v);
int stun_add_mapped_address_attrs(struct stunattr **attr, struct stunmsg *msg, int max_msg_sz,
                                  void *app_addr, int app_addr_sz);
int stun_add_xor_mapped_address_attr(struct stunattr **attr, struct stunmsg *msg, int max_msg_sz,
                                     void *app_addr, int app_addr_sz);
int stun_add_message_integrity(struct stunattr **attr, struct stunmsg *msg, int max_msg_sz,
                               const char *key, int key_sz);
void stun_random_tx_id(struct stuntxid *tx);
const char *stun_strerror(int err);

int stun_process_binding_response(struct stunmsg *msg, struct sockaddr *sa, socklen_t *sz);
int stun_format_error(struct stunmsg *rsp, int rsp_sz, const struct stunmsg *msg,
                      int err_code, struct stunvalidation *v);
// out should be STUN_MESSAGE_INTEGRITY_LENGTH bytes in size at least
int stun_calculate_message_integrity(const struct stunmsg *msg, int buf_sz, unsigned char *out,
                                     const char *key, size_t key_len);

#endif
