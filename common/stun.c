#include <openssl/rand.h>
#include <openssl/err.h>
#include <assert.h>
#include <string.h>

#include "stun.h"

#define SVDBG(...)                              \
  if ( v->sv_flags & STUN_VALIDATE_VERBOSE ) {  \
    fprintf(stderr, __VA_ARGS__);               \
  }

int stun_accept_unknown(uint16_t attr, const char *data, size_t sz, void *a) {
  return STUN_SUCCESS;
}

int stun_validate(const char *buf, int buf_sz, struct stunvalidation *v) {
  const struct stunmsg *msg = (const struct stunmsg *)buf;
  const struct stunattr *attr;

  int err, ret = STUN_SUCCESS, max_attrs = v->sv_unknown_attrs_sz;
  int rsp_error_code = STUN_SUCCESS;

  v->sv_unknown_attrs_sz = 0;

  v->sv_flags &= ~(STUN_HAD_FINGERPRINT | STUN_HAD_MESSAGE_INTEGRITY);

  if ( buf_sz < STUN_MSG_HDR_SZ ) {
    SVDBG("stun_validate: message too small (%d < %ld)\n", buf_sz, sizeof(struct stunmsg));
    return STUN_BAD_REQUEST;
  }

  if ( !STUN_IS_STUN(msg) ) {
    SVDBG("stun_validate: not STUN\n");
    return STUN_NOT_STUN;
  }

  if ( !STUN_COOKIE_VALID(msg) ) {
    SVDBG("stun_validate: cookie not valid: %x\n", ntohl(msg->sm_magic_cookie));
    return STUN_BAD_REQUEST;
  }

  if ( (v->sv_flags & STUN_VALIDATE_RESPONSE) && (STUN_MESSAGE_TYPE(msg) & STUN_RESPONSE) == 0 ) {
    SVDBG("stun_validate: expected response, but this is a request: %x\n", STUN_MESSAGE_TYPE(msg));
    return STUN_BAD_REQUEST;
  }

  if ( (v->sv_flags & STUN_VALIDATE_RESPONSE) && (STUN_MESSAGE_TYPE(msg) & STUN_ERROR) ) {
    SVDBG("stun_validate: server responded with error\n");
    rsp_error_code = STUN_MISSING_ERROR_CODE;
  }

  if ( (v->sv_flags & STUN_VALIDATE_RESPONSE) &&
       STUN_REQUEST_TYPE(msg) != v->sv_req_code ) {
    SVDBG("stun_validate: response doesn't match request code\n");
    return STUN_REQUEST_MISMATCH;
  }

  if ( (v->sv_flags & STUN_VALIDATE_TX_ID) && v->sv_tx_id &&
       memcmp(v->sv_tx_id, &msg->sm_tx_id, sizeof(struct stuntxid)) != 0 ) {
    SVDBG("stun_validate: transaction id mismatch\n");
    SVDBG("expected %08x %08x %08x\n", v->sv_tx_id->a, v->sv_tx_id->b, v->sv_tx_id->c);
    SVDBG("     got %08x %08x %08x\n", msg->sm_tx_id.a, msg->sm_tx_id.b, msg->sm_tx_id.c);
    return STUN_TX_ID_MISMATCH;
  }

  if ( (v->sv_flags & STUN_VALIDATE_REQUEST) &&
       STUN_REQUEST_TYPE(msg) != STUN_MESSAGE_TYPE(msg) ) {
    SVDBG("stun_validate: expected request, but got response\n");
    return STUN_BAD_REQUEST;
  }

  for ( attr = STUN_FIRSTATTR(msg); STUN_ATTR_IS_VALID(attr, msg, buf_sz);
        attr = STUN_NEXTATTR(attr) ) {

    switch ( STUN_ATTR_NAME(attr) ) {
    case STUN_ATTR_ERROR_CODE:
      if ( STUN_MESSAGE_TYPE(msg) & STUN_RESPONSE ) {
        rsp_error_code = ntohs(*((uint16_t *) STUN_ATTR_DATA(attr)));
        return -rsp_error_code;
      } else {
        SVDBG("stun_validate: encountered error code in request\n");
        return STUN_BAD_REQUEST;
      }
    case STUN_ATTR_FINGERPRINT:
      if ( v->sv_flags & STUN_HAD_FINGERPRINT ) {
        SVDBG("stun_validate: encountered fingerprint in the middle of message\n");
        return STUN_BAD_REQUEST;
      }

      v->sv_flags |= STUN_HAD_FINGERPRINT;

      // TODO validate fingerprint
      break;

    case STUN_ATTR_MESSAGE_INTEGRITY:
      // TODO Check message integrity
      break;

    default:
      if ( v->sv_unknown_cb ) {
        err = v->sv_unknown_cb(STUN_ATTR_NAME(attr), STUN_ATTR_DATA(attr), STUN_ATTR_PAYLOAD_SZ(attr),
                         v->sv_user_data);
        if ( err != STUN_UNKNOWN_ATTRIBUTES ) return err;
      }

      if ( STUN_ATTR_REQUIRED(STUN_ATTR_NAME(attr)) ) {
        ret = STUN_UNKNOWN_ATTRIBUTES;
        if ( v->sv_unknown_attrs ) {
          if ( v->sv_unknown_attrs_sz < max_attrs )
            v->sv_unknown_attrs[v->sv_unknown_attrs_sz++] = htons(STUN_ATTR_NAME(attr));
          else {
            SVDBG("Not reporting unknown attribute %d, because there is no space\n", STUN_ATTR_NAME(attr));
          }
        }
      }

      break;
    }
  }

  if ( v->sv_flags & STUN_NEED_FINGERPRINT ) {
    if ( (v->sv_flags & (STUN_HAD_FINGERPRINT | STUN_FINGERPRINT_VALID)) == 0 )
      return STUN_BAD_REQUEST;
  }

  if ( v->sv_flags & STUN_NEED_MESSAGE_INTEGRITY ) {
    if ( (v->sv_flags & STUN_HAD_MESSAGE_INTEGRITY) == 0 ) return STUN_UNAUTHORIZED;
  }

  return STUN_SUCCESS;
}

struct stunmappedaddress {
  uint16_t sma_type;
  uint16_t sma_port;
  char     sma_data[];
} KITE_PACKED;

int stun_add_mapped_address_attrs(struct stunattr **attr, struct stunmsg *msg, int max_msg_sz,
                                  void *app_addr, int app_addr_sz) {
  struct sockaddr *sa_addr = (struct sockaddr *)app_addr;
  struct sockaddr_in *sin_addr;
  struct sockaddr_in6 *sin6_addr;
  struct stunmappedaddress *stun_addr, *stun_xor_addr;
  struct stunattr *mapped_attr;

  char *addr_data;

  stun_addr = (struct stunmappedaddress *) STUN_ATTR_DATA(*attr);
  addr_data = (char *) ((uintptr_t) stun_addr) + sizeof(struct stunmappedaddress);

  switch ( sa_addr->sa_family ) {
  case AF_INET:
    sin_addr = (struct sockaddr_in *) sa_addr;
    STUN_INIT_ATTR(*attr, STUN_ATTR_MAPPED_ADDRESS, 4 + sizeof(struct stunmappedaddress));
    if ( STUN_ATTR_IS_VALID(*attr, msg, max_msg_sz) ) {
      stun_addr->sma_type = htons(STUN_ADDR_IN);
      stun_addr->sma_port = sin_addr->sin_port;
      memcpy(addr_data, &sin_addr->sin_addr.s_addr, 4);
    } else goto overflow;
    break;
  case AF_INET6:
    sin6_addr = (struct sockaddr_in6 *) sa_addr;
    STUN_INIT_ATTR(*attr, STUN_ATTR_MAPPED_ADDRESS, 16 + sizeof(struct stunmappedaddress));
    if ( STUN_ATTR_IS_VALID(*attr, msg, max_msg_sz) ) {
      stun_addr->sma_type = htons(STUN_ADDR_IN6);
      stun_addr->sma_port = sin6_addr->sin6_port;
      memcpy(addr_data, sin6_addr->sin6_addr.s6_addr, 16);
    } else goto overflow;
    break;
  default:
    fprintf(stderr, "STUN: can't add mapped address data for family %d\n", sa_addr->sa_family);
    return -1;
  }

  mapped_attr = *attr;
  *attr = STUN_NEXTATTR(*attr);
  assert(STUN_IS_VALID(*attr, msg, max_msg_sz));
  STUN_INIT_ATTR(*attr, STUN_ATTR_XOR_MAPPED_ADDRESS, STUN_ATTR_PAYLOAD_SZ(mapped_attr));
  if ( STUN_ATTR_IS_VALID(*attr, msg, max_msg_sz) ) {
    union {
      uint32_t xor_magic_cookie;
      char xor_raw_bytes[16];
    } xor_value;
    int i;
    char *raw_attr_data = STUN_ATTR_DATA(*attr);

    xor_value.xor_magic_cookie = htonl(STUN_MAGIC_COOKIE);
    memcpy(xor_value.xor_raw_bytes + 4, msg->sm_tx_id.stx_raw_bytes, sizeof(msg->sm_tx_id.stx_raw_bytes));

    stun_xor_addr = (struct stunmappedaddress *) STUN_ATTR_DATA(*attr);
    stun_xor_addr->sma_type = stun_addr->sma_type;
    stun_xor_addr->sma_port = stun_addr->sma_port;

    for ( i = 4; i < STUN_ATTR_PAYLOAD_SZ(mapped_attr); ++i ) {
      raw_attr_data[i] ^= xor_value.xor_raw_bytes[i - 4];
    }

  } else goto overflow;

  return 0;

 overflow:
  fprintf(stderr, "STUN: can't add mapped address data because there is not enough space in the me ssage\n");
  return -1;
}

int stun_add_message_integrity(struct stunattr **attr, struct stunmsg *msg, int max_msg_sz,
                               const char *key, int key_len) {
//  HMAC_CTX *ctx = HMAC_CTX_new();
//  if ( !ctx ) return -1;
//
//  if ( !HMAC_Init_ex(ctx,
  return -1;
}

void stun_random_tx_id(struct stuntxid *tx) {
  if ( !RAND_bytes((unsigned char *) tx, sizeof(*tx)) ) {
    fprintf(stderr, "stun_random_tx_id: RAND_bytes failed\n");
    ERR_print_errors_fp(stderr);
  }
}
