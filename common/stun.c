#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <assert.h>
#include <string.h>

#include "stun.h"

#define SVDBG(...)                              \
  if ( v->sv_flags & STUN_VALIDATE_VERBOSE ) {  \
    fprintf(stderr, __VA_ARGS__);               \
  }

typedef unsigned char stun_xor_bytes[16];

#define STUN_XOR_BYTES(msg) {                   \
  0x21, 0x12, 0xa4, 0x42,                       \
    (msg)->sm_tx_id.stx_raw_bytes[0],           \
    (msg)->sm_tx_id.stx_raw_bytes[1],           \
    (msg)->sm_tx_id.stx_raw_bytes[2],           \
    (msg)->sm_tx_id.stx_raw_bytes[3],           \
    (msg)->sm_tx_id.stx_raw_bytes[4],           \
    (msg)->sm_tx_id.stx_raw_bytes[5],           \
    (msg)->sm_tx_id.stx_raw_bytes[6],           \
    (msg)->sm_tx_id.stx_raw_bytes[7],           \
    (msg)->sm_tx_id.stx_raw_bytes[8],           \
    (msg)->sm_tx_id.stx_raw_bytes[9],           \
    (msg)->sm_tx_id.stx_raw_bytes[10],          \
    (msg)->sm_tx_id.stx_raw_bytes[11]           \
  }

static void memcpy_xorred(void *outp, const void *srcp, const void *xorp,
                          size_t sz) {
  unsigned char *out = outp;
  const unsigned char *src = srcp;
  const unsigned char *xor = xorp;
  size_t i;

  for ( i = 0; i < sz; ++i )
    out[i] = src[i] ^ xor[i];
}

int stun_accept_unknown(uint16_t attr, const char *data, size_t sz, void *a) {
  return STUN_SUCCESS;
}

int stun_validate(const char *buf, int buf_sz, struct stunvalidation *v) {
  const struct stunmsg *msg = (const struct stunmsg *)buf;
  const struct stunattr *attr;

  int err, ret = STUN_SUCCESS, max_attrs = v->sv_unknown_attrs_sz;
  int rsp_error_code = STUN_SUCCESS;

  const char *password = NULL;
  size_t password_sz = 0;

  v->sv_unknown_attrs_sz = 0;

  v->sv_flags &= ~(STUN_HAD_FINGERPRINT | STUN_HAD_MESSAGE_INTEGRITY | STUN_FINGERPRINT_VALID);

  if ( buf_sz < STUN_MSG_HDR_SZ ) {
    SVDBG("stun_validate: message too small (%d < %zu)\n", buf_sz, sizeof(struct stunmsg));
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
    uint32_t exp_crc, act_crc;

    SVDBG("stun_validate: Got stun attribute %04x of size %d\n", STUN_ATTR_NAME(attr),
          STUN_ATTR_PAYLOAD_SZ(attr));

    if ( v->sv_flags & STUN_HAD_FINGERPRINT ) {
      // The fingerprint should be the last attribute
      SVDBG("stun_validate: encountered fingerprint in the middle of message\n");
      return STUN_BAD_REQUEST;
    }

    switch ( STUN_ATTR_NAME(attr) ) {
    case STUN_ATTR_ERROR_CODE:
      if ( STUN_MESSAGE_TYPE(msg) & STUN_RESPONSE ) {
        rsp_error_code = ntohs(*((uint16_t *) STUN_ATTR_DATA(attr)));
        SVDBG("stun_validate: return error response\n");
        return -rsp_error_code;
      } else {
        SVDBG("stun_validate: encountered error code in request\n");
        return STUN_BAD_REQUEST;
      }
      break;
    case STUN_ATTR_FINGERPRINT:

      v->sv_flags |= STUN_HAD_FINGERPRINT;

      exp_crc = crc32(0, (void *) msg, STUN_OFFSET(msg, attr));
      exp_crc ^= 0x5354554e;
      memcpy(&act_crc, STUN_ATTR_DATA(attr), sizeof(act_crc));
      act_crc = ntohl(act_crc);

      SVDBG("stun_validate: got fingerprint %08x, expected %08x\n",
            act_crc, exp_crc);

      if ( act_crc == exp_crc ) {
        SVDBG("stun_validate: set fingerprint valid\n");
        v->sv_flags |= STUN_FINGERPRINT_VALID;
      }

      break;


    case STUN_ATTR_MESSAGE_INTEGRITY:
      if ( STUN_ATTR_PAYLOAD_SZ(attr) != STUN_MESSAGE_INTEGRITY_LENGTH ) {
        SVDBG("stun_validate: expected %d for MESSAGE-INTEGRITY length, but got %d\n",
              STUN_MESSAGE_INTEGRITY_LENGTH, STUN_ATTR_PAYLOAD_SZ(attr));

        ret = STUN_BAD_REQUEST;
        break;
      }

      if ( !password ) {
        if ( v->sv_user_cb ) {
          err = v->sv_user_cb(NULL, 0, &password, &password_sz, v->sv_user_data);
          if ( err != STUN_SUCCESS )
            ret = STUN_UNAUTHORIZED;
        }
      }

      if ( password && ret != STUN_UNAUTHORIZED ) {
        unsigned char expected[STUN_MESSAGE_INTEGRITY_LENGTH];
        SVDBG("stun_validate: would check message integrity\n");

        err = stun_calculate_message_integrity(msg, buf_sz, expected, password, password_sz);
        if ( err < 0 ) {
          SVDBG("stun_validate: stun_calculate_message_integrity fails\n");
          ret = STUN_SERVER_ERROR;
        }

        if ( memcmp(expected, STUN_ATTR_DATA(attr), STUN_MESSAGE_INTEGRITY_LENGTH) == 0 ) {
          SVDBG("stun_validate: had message integrity\n");
          v->sv_flags |= STUN_HAD_MESSAGE_INTEGRITY;
        } else {
          const unsigned char *actual = STUN_ATTR_DATA(attr);
          SVDBG("stun_validate: message integrity mismatch\n");
          SVDBG("stun_validate: expected: "
                "%02x%02x%02x%02x%02x"
                "%02x%02x%02x%02x%02x"
                "%02x%02x%02x%02x%02x"
                "%02x%02x%02x%02x%02x\n",
                expected[0], expected[1], expected[2], expected[3], expected[4],
                expected[5], expected[6], expected[7], expected[8], expected[9],
                expected[10], expected[11], expected[12], expected[13], expected[14],
                expected[15], expected[16], expected[17], expected[18], expected[19]);
          SVDBG("stun_validate: actual: "
                "%02x%02x%02x%02x%02x"
                "%02x%02x%02x%02x%02x"
                "%02x%02x%02x%02x%02x"
                "%02x%02x%02x%02x%02x\n",
                actual[0], actual[1], actual[2], actual[3], actual[4],
                actual[5], actual[6], actual[7], actual[8], actual[9],
                actual[10], actual[11], actual[12], actual[13], actual[14],
                actual[15], actual[16], actual[17], actual[18], actual[19]);

          ret = STUN_UNAUTHORIZED;
        }
      }
      break;

    case STUN_ATTR_USERNAME:
      if ( v->sv_user_cb ) {
        err = v->sv_user_cb((const char *) STUN_ATTR_DATA(attr),
                            STUN_ATTR_PAYLOAD_SZ(attr),
                            &password, &password_sz,
                            v->sv_user_data);
        if ( err != STUN_SUCCESS ) {
          password = NULL;
          password_sz = 0;

          SVDBG("stun_validate: unauthorized response from user callback\n");
          ret = err;
        } else if ( !password ) {
          password_sz = 0;
          ret = STUN_UNAUTHORIZED;
        }

        continue;
      }

    default:
      if ( v->sv_unknown_cb ) {
        err = v->sv_unknown_cb(STUN_ATTR_NAME(attr), STUN_ATTR_DATA(attr), STUN_ATTR_PAYLOAD_SZ(attr),
                         v->sv_user_data);
        if ( err != STUN_SUCCESS && err != STUN_UNKNOWN_ATTRIBUTES ) return err;
      } else
        err = STUN_UNKNOWN_ATTRIBUTES;

      if ( STUN_ATTR_REQUIRED(STUN_ATTR_NAME(attr)) && err != STUN_SUCCESS ) {
        ret = STUN_UNKNOWN_ATTRIBUTES;
        if ( v->sv_unknown_attrs ) {
          if ( v->sv_unknown_attrs_sz < max_attrs )
            v->sv_unknown_attrs[v->sv_unknown_attrs_sz++] = STUN_ATTR_NAME(attr);
          else {
            SVDBG("Not reporting unknown attribute %d, because there is no space\n", STUN_ATTR_NAME(attr));
          }
        }
      }

      break;
    }
  }

  SVDBG("Running final stun checks: %08x\n", v->sv_flags);
  if ( v->sv_flags & STUN_NEED_FINGERPRINT ) {
    if ( (v->sv_flags & (STUN_HAD_FINGERPRINT | STUN_FINGERPRINT_VALID)) !=
         (STUN_HAD_FINGERPRINT | STUN_FINGERPRINT_VALID) ) {
      SVDBG("stun_validate: no fingerprint present, but one is required\n");
      return STUN_BAD_REQUEST;
    }
  }

  SVDBG("checking message integrity\n");
  if ( v->sv_flags & STUN_NEED_MESSAGE_INTEGRITY ) {
    SVDBG("stun_validate: needed mesage integrity and had %08x\n", v->sv_flags & STUN_HAD_MESSAGE_INTEGRITY);
    if ( (v->sv_flags & STUN_HAD_MESSAGE_INTEGRITY) == 0 ) return STUN_UNAUTHORIZED;
  }
  SVDBG("return success\n");

  return STUN_SUCCESS;
}

struct stunmappedaddress {
  uint16_t sma_type;
  uint16_t sma_port;
  char     sma_data[];
} INTRUSTD_PACKED;

int stun_add_mapped_address_attr(struct stunattr *attr, struct stunmsg *msg, int max_msg_sz,
                                 uint16_t attr_type, unsigned char *xor_value,
                                 void *app_addr, int app_addr_sz) {
  struct sockaddr *sa_addr = (struct sockaddr *)app_addr;
  struct sockaddr_in *sin_addr;
  struct sockaddr_in6 *sin6_addr;
  struct stunmappedaddress *stun_addr;
  char *raw_attr_data;

  char *addr_data;

  stun_addr = (struct stunmappedaddress *) STUN_ATTR_DATA(attr);
  addr_data = (char *) ((uintptr_t) stun_addr) + sizeof(struct stunmappedaddress);

  if ( !STUN_CAN_WRITE_ATTR(attr, msg, max_msg_sz) ) return -1;

  switch ( sa_addr->sa_family ) {
  case AF_INET:
    sin_addr = (struct sockaddr_in *) sa_addr;
    STUN_INIT_ATTR(attr, attr_type, 4 + sizeof(struct stunmappedaddress));
    if ( STUN_ATTR_IS_VALID(attr, msg, max_msg_sz) ) {
      stun_addr->sma_type = htons(STUN_ADDR_IN);
      stun_addr->sma_port = sin_addr->sin_port;
      memcpy(addr_data, &sin_addr->sin_addr.s_addr, 4);
    } else return -1;
    break;
  case AF_INET6:
    sin6_addr = (struct sockaddr_in6 *) sa_addr;
    STUN_INIT_ATTR(attr, attr_type, 16 + sizeof(struct stunmappedaddress));
    if ( STUN_ATTR_IS_VALID(attr, msg, max_msg_sz) ) {
      stun_addr->sma_type = htons(STUN_ADDR_IN6);
      stun_addr->sma_port = sin6_addr->sin6_port;
      memcpy(addr_data, sin6_addr->sin6_addr.s6_addr, 16);
    } else return -1;
    break;
  default:
    fprintf(stderr, "STUN: can't add mapped address data for family %d\n", sa_addr->sa_family);
    return -1;
  }

  if ( xor_value ) {
    raw_attr_data = STUN_ATTR_DATA(attr);

    raw_attr_data[2] ^= xor_value[0];
    raw_attr_data[3] ^= xor_value[1];

    memcpy_xorred(&raw_attr_data[4], STUN_ATTR_DATA(attr) + 4,
                  xor_value, STUN_ATTR_PAYLOAD_SZ(attr) - 4);
  }

  return 0;
}

int stun_add_mapped_address_attrs(struct stunattr **attr, struct stunmsg *msg, int max_msg_sz,
                                  void *app_addr, int app_addr_sz) {
  stun_xor_bytes xor_value = STUN_XOR_BYTES(msg);
  int err;

  err = stun_add_mapped_address_attr(*attr, msg, max_msg_sz, STUN_ATTR_MAPPED_ADDRESS, NULL,
                                     app_addr, app_addr_sz);
  if ( err < 0 ) return -1;

  *attr = STUN_NEXTATTR(*attr);
  err = stun_add_mapped_address_attr(*attr, msg, max_msg_sz, STUN_ATTR_XOR_MAPPED_ADDRESS,
                                     xor_value, app_addr, app_addr_sz);
  if ( err < 0 ) return -1;

  return 0;
}

int stun_add_xor_mapped_address_attr(struct stunattr **attr, struct stunmsg *msg, int max_msg_sz,
                                     void *app_addr, int app_addr_sz) {
  stun_xor_bytes xor_value = STUN_XOR_BYTES(msg);
  int err;

  err = stun_add_mapped_address_attr(*attr, msg, max_msg_sz, STUN_ATTR_XOR_MAPPED_ADDRESS,
                                     xor_value, app_addr, app_addr_sz);
  if ( err < 0 ) return -1;

  return 0;
}

int stun_add_message_integrity(struct stunattr **attr, struct stunmsg *msg, int max_msg_sz,
                               const char *key, int key_len) {
  if ( !STUN_CAN_WRITE_ATTR(*attr, msg, max_msg_sz) ) return -1;
  STUN_INIT_ATTR(*attr, STUN_ATTR_MESSAGE_INTEGRITY, STUN_MESSAGE_INTEGRITY_LENGTH);
  if ( !STUN_ATTR_IS_VALID(*attr, msg, max_msg_sz) ) return -1;

  return stun_calculate_message_integrity(msg, max_msg_sz, STUN_ATTR_DATA(*attr), key, key_len);
}

void stun_random_tx_id(struct stuntxid *tx) {
  if ( !RAND_bytes((unsigned char *) tx, sizeof(*tx)) ) {
    fprintf(stderr, "stun_random_tx_id: RAND_bytes failed\n");
    ERR_print_errors_fp(stderr);
  }
}

int stun_process_binding_response(struct stunmsg *msg, struct sockaddr *sa, socklen_t *sz) {
  int msgsz = STUN_MSG_LENGTH(msg);
  struct stunattr *attr;
  struct stunmappedaddress *stun_addr;
  int has_addr = 0;

  unsigned char *raw_attr;

  stun_xor_bytes msg_xor_value = STUN_XOR_BYTES(msg);

  for ( attr = STUN_FIRSTATTR(msg);
        STUN_IS_VALID(attr, msg, msgsz);
        attr = STUN_NEXTATTR(attr) ) {
    switch ( STUN_ATTR_NAME(attr) ) {
    case STUN_ATTR_MAPPED_ADDRESS:
    case STUN_ATTR_XOR_MAPPED_ADDRESS:
      fprintf(stderr, "Got payload size %d %zu\n", STUN_ATTR_PAYLOAD_SZ(attr), sizeof(*stun_addr));
      if ( STUN_ATTR_PAYLOAD_SZ(attr) > sizeof(*stun_addr) ) {
        stun_addr = (struct stunmappedaddress *) STUN_ATTR_DATA(attr);

        switch ( ntohs(stun_addr->sma_type) ) {
        case STUN_ADDR_IN:
          if ( STUN_ATTR_PAYLOAD_SZ(attr) < (sizeof(*stun_addr) + 4) ) {
            fprintf(stderr, "stun_process_binding_response: not enough data for IPv4 addr\n");
            return -1;
          }

          if ( has_addr && sa->sa_family != AF_INET ) {
            fprintf(stderr, "stun_process_binding_response: address family mismatch between mapped address attributes\n");
            return -1;
          } else {
            stun_xor_bytes xor_value;
            struct sockaddr_in new, *old = (struct sockaddr_in *) sa;

            memset(&new, 0, sizeof(new));

            raw_attr = STUN_ATTR_DATA(attr);

            if ( *sz < sizeof(new) ) return -1;
            *sz = sizeof(new);

            if ( STUN_ATTR_NAME(attr) == STUN_ATTR_XOR_MAPPED_ADDRESS )
              memcpy(xor_value, msg_xor_value, sizeof(xor_value));
            else
              memset(xor_value, 0, sizeof(xor_value));

            new.sin_family = AF_INET;
            memcpy_xorred(&new.sin_port, raw_attr + 2, xor_value, sizeof(new.sin_port));
            memcpy_xorred(&new.sin_addr.s_addr, raw_attr + 4, xor_value, sizeof(new.sin_addr.s_addr));

            if ( !has_addr )
              memcpy(sa, &new, sizeof(new));
            else if ( old->sin_port != new.sin_port ||
                      old->sin_addr.s_addr != new.sin_addr.s_addr ) {
              fprintf(stderr, "stun_process_binding_response: XOR-MAPPED-ADDRESS and MAPPED-ADDRESS mismatch (AF_INET)\n");
              return -1;
            } else {
              fprintf(stderr, "stun_process_binding_response: ports are the same: %d == %d\n",
                      ntohs(new.sin_port), ntohs(old->sin_port));
            }

            has_addr = 1;
          }
          break;
        case STUN_ADDR_IN6:
          if ( STUN_ATTR_PAYLOAD_SZ(attr) < (sizeof(*stun_addr) + 16) ) {
            fprintf(stderr, "stun_process_binding_response: not enough data for IPv6 addr\n");
            return -1;
          }

          if ( has_addr && sa->sa_family != AF_INET6 ) {
            fprintf(stderr, "stun_process_binding_response: address family mismatch between mapped address attributes\n");
            return -1;
          } else {
            stun_xor_bytes xor_value;
            struct sockaddr_in6 new, *old = (struct sockaddr_in6 *)sa;

            memset(&new, 0, sizeof(new));

            raw_attr = STUN_ATTR_DATA(attr);

            if ( *sz < sizeof(new) ) return -1;
            *sz = sizeof(new);

            if ( STUN_ATTR_NAME(attr) == STUN_ATTR_XOR_MAPPED_ADDRESS )
              memcpy(xor_value, msg_xor_value, sizeof(xor_value));
            else
              memset(xor_value, 0, sizeof(xor_value));

            new.sin6_family = AF_INET6;
            memcpy_xorred(&new.sin6_port, raw_attr + 2, xor_value, sizeof(new.sin6_port));
            memcpy_xorred(new.sin6_addr.s6_addr, raw_attr + 4, xor_value, sizeof(new.sin6_addr.s6_addr));

            if ( !has_addr )
              memcpy(sa, &new, sizeof(new));
            else if ( old->sin6_port != new.sin6_port ||
                      memcmp(old->sin6_addr.s6_addr, new.sin6_addr.s6_addr,
                             sizeof(new.sin6_addr.s6_addr)) != 0 ) {
              fprintf(stderr, "stun_process_binding_response: XOR-MAPPED-ADDRESS and MAPPED-ADDRESS mismatch (AF_INET6)\n");
              return -1;
            }

            has_addr = 1;
          }

          break;
        default:
          fprintf(stderr, "stun_process_binding_response: unnkown addr type %d\n", ntohs(stun_addr->sma_type));
          return -1;
        }
      } else {
        fprintf(stderr, "stun_process_binding_response: not enough data in mapped address\n");
        return -1;
      }
      break;
    default:
      break;
    }
  }

  if ( !has_addr ) {
    fprintf(stderr, "stun_process_binding_response: no address information\n");
    return -1;
  } else
    return 0;
}

#define STUN_LOCAL_REMOTE(cs, lbl)               \
  case cs: return lbl " (local)";                \
  case (-cs): return lbl " (remote)"
const char *stun_strerror(int err) {
  switch ( err ) {
  case STUN_MISSING_ERROR_CODE: return "Expected response, but there was no ERROR-CODE attribute";
  case STUN_REQUEST_MISMATCH:   return "The response was not for the request we issued";
  case STUN_TX_ID_MISMATCH:     return "The STUN transaction IDs did not match";
  case STUN_NOT_STUN:           return "The request was not a STUN request";
  case STUN_SUCCESS:            return "Successfully processed STUN message";
    STUN_LOCAL_REMOTE(STUN_TRY_ALTERNATE, "TRY-ALTERNATE");
    STUN_LOCAL_REMOTE(STUN_BAD_REQUEST, "BAD-REQUEST");
    STUN_LOCAL_REMOTE(STUN_UNAUTHORIZED, "UNAUTHORIZED");
    STUN_LOCAL_REMOTE(STUN_NOT_FOUND, "NOT-FOUND");
    STUN_LOCAL_REMOTE(STUN_UNKNOWN_ATTRIBUTES, "UNKNOWN-ATTRIBUTES");
    STUN_LOCAL_REMOTE(STUN_STALE_NONCE, "STALE-NONCE");
    STUN_LOCAL_REMOTE(STUN_SERVER_ERROR, "SERVER-ERROR");
  default:
    if ( err < 0 ) { return "Other unknown error from server"; }
    else { return "Other unknown error generated locally"; }
  }
}


int stun_format_error(struct stunmsg *rsp, int rsp_sz, const struct stunmsg *msg,
                      int err_code, struct stunvalidation *v) {
  if ( err_code > 0 && err_code < 0xFFFF ) {
    struct stunattr *attr;
    uint16_t err16 = err_code;
    int ret = 0;

    err16 = htons(err16);

    if ( rsp_sz < STUN_MSG_HDR_SZ ) return -1;

    STUN_INIT_MSG(rsp, STUN_REQUEST_TYPE(msg) | STUN_ERROR | STUN_RESPONSE);
    memcpy(&rsp->sm_tx_id, &msg->sm_tx_id, sizeof(rsp->sm_tx_id));

    attr = STUN_FIRSTATTR(rsp);
    if ( !STUN_IS_VALID(attr, rsp, rsp_sz) ) return -1;
    STUN_INIT_ATTR(attr, STUN_ATTR_ERROR_CODE, sizeof(err16));
    if ( !STUN_ATTR_IS_VALID(attr, rsp, rsp_sz) ) return -1;
    memcpy(STUN_ATTR_DATA(attr), &err16, sizeof(err16));

    if ( v->sv_unknown_attrs ) {
      int i;

      attr = STUN_NEXTATTR(attr);
      if ( !STUN_IS_VALID(attr, rsp, rsp_sz) ) return -1;
      STUN_INIT_ATTR(attr, STUN_ATTR_UNKNOWN_ATTRIBUTES, sizeof(*v->sv_unknown_attrs) * v->sv_unknown_attrs_sz);
      if ( !STUN_ATTR_IS_VALID(attr, rsp, rsp_sz) ) return -1;
      for ( i = 0; i < v->sv_unknown_attrs_sz; ++i ) {
        uint16_t attr_name = v->sv_unknown_attrs[i];
        attr_name = htons(attr_name);
        memcpy(STUN_ATTR_DATA(attr) + i * 2, &attr_name, sizeof(attr_name));
      }
    }

    STUN_FINISH_WITH_FINGERPRINT(attr, rsp, rsp_sz, ret);
    return ret;
  } else
    return -1;
}

int stun_calculate_message_integrity(const struct stunmsg *msg, int buf_sz, unsigned char *out,
                                     const char *key, size_t key_len) {
  struct stunattr *attr;
  int ret = 0;
  unsigned int len = STUN_MESSAGE_INTEGRITY_LENGTH;
  uintptr_t end = 0, length_end = 0;
  uint16_t virtual_length;
  HMAC_CTX *ctx;

  for ( attr = STUN_FIRSTATTR(msg); STUN_ATTR_IS_VALID(attr, msg, buf_sz);
        attr = STUN_NEXTATTR(attr) ) {
    if ( STUN_ATTR_NAME(attr) == STUN_ATTR_MESSAGE_INTEGRITY ) {
      end = (uintptr_t) attr;
      length_end = ((uintptr_t) STUN_ATTR_DATA(attr)) + STUN_MESSAGE_INTEGRITY_LENGTH;
    }
  }

  if ( !end || !length_end ) return -1;

  virtual_length = htons(length_end - ((uintptr_t) msg->sm_attributes));

  ctx = HMAC_CTX_new();
  if ( !ctx ) {
    fprintf(stderr, "stun_calculate_message_integrity: could not allocate HMAC context\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  if ( !HMAC_Init_ex(ctx, key, key_len, EVP_sha1(), NULL) ) {
    ret = -1;
    goto done;
  }

  if ( !HMAC_Update(ctx, (unsigned char *) &msg->sm_type, sizeof(msg->sm_type)) ) {
    ret = -1;
    goto done;
  }
  if ( !HMAC_Update(ctx, (unsigned char *) &virtual_length, sizeof(virtual_length)) ) {
    ret = -1;
    goto done;
  }
  if ( !HMAC_Update(ctx, (unsigned char *) &msg->sm_magic_cookie,
                    end - ((uintptr_t) &msg->sm_magic_cookie)) ) {
    ret = -1;
    goto done;
  }

  if ( !HMAC_Final(ctx, out, &len) ) {
    ret = -1;
    goto done;
  }

  assert(len == STUN_MESSAGE_INTEGRITY_LENGTH);

 done:
  HMAC_CTX_free(ctx);
  if ( ret < 0 ) {
    fprintf(stderr, "stun_calculate_message_integrity: HMAC_* call failed\n");
    ERR_print_errors_fp(stderr);
  }
  return ret;
}
