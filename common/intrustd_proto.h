#ifndef __common_intrustdd_proto_H__
#define __common_intrustdd_proto_H__

#include <stdint.h>

#include "util.h"

struct appdmsg {
  uint32_t am_flags;
  union {
    struct {
      uint32_t am_family;
      uint32_t am_addr;
    } am_opened_app;
    uint32_t am_error;
  } am_data;
} INTRUSTD_PACKED;

#define APPD_REQ(msg) (ntohl((msg)->am_flags) & 0xFF)
#define APPD_MSG_FLAGS(msg) (ntohl((msg)->am_flags) >> 8)
#define APPD_IS_RSP(msg) (APPD_MSG_FLAGS(msg) & APPD_RSP)
#define APPD_IS_ERROR(msg) (APPD_MSG_FLAGS(msg) & APPD_ERROR)
#define APPD_ERR_IS_TEMPORARY(err)    \
  ((err) == APPD_ERROR_SYSTEM_BUSY ||       \
   (err) == APPD_ERROR_TEMP_UNAVAILABLE ||  \
   (err) == APPD_ERROR_CONN_REFUSED)

#define APPD_MKFLAGS(flags, req) (htonl(((flags) << 8) | (req)))

#define APPD_RSP   0x1
#define APPD_ERROR 0x2

#define APPD_ERROR_MSG_SZ       8
#define APPD_OPENED_APP_RSP_SZ 12

#define APPD_OPEN_APP_REQUEST 0x0

#define APPD_ERROR_APP_DOES_NOT_EXIST     1
#define APPD_ERROR_APP_NOT_INSTALLED      2
#define APPD_ERROR_MALFORMED_NAME         3
#define APPD_ERROR_PERSONA_DOES_NOT_EXIST 4
#define APPD_ERROR_SYSTEM_ERROR           5
#define APPD_ERROR_SYSTEM_BUSY            6
#define APPD_ERROR_TEMP_UNAVAILABLE       7
#define APPD_ERROR_NO_SPACE               8
#define APPD_ERROR_INVALID_SOCKET_TYPE    9
#define APPD_ERROR_CONN_REFUSED           10
#define APPD_ERROR_INVALID_ADDR           11

#endif
