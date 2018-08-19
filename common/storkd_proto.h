#ifndef __common_storkd_proto_H__
#define __common_storkd_proto_H__

#include <stdint.h>

struct stkdmsg {
  uint32_t sm_flags;
  union {
    struct {
      uint32_t sm_family;
      uint32_t sm_addr;
    } sm_opened_app;
    uint32_t sm_error;
  } sm_data;
} __attribute__((packed));

#define STKD_REQ(msg) (ntohl((msg)->sm_flags) & 0xFF)
#define STKD_MSG_FLAGS(msg) (ntohl((msg)->sm_flags) >> 8)
#define STKD_IS_RSP(msg) (STKD_MSG_FLAGS(msg) & STKD_RSP)
#define STKD_IS_ERROR(msg) (STKD_MSG_FLAGS(msg) & STKD_ERROR)
#define STKD_ERR_IS_TEMPORARY(err)    \
  ((err) == STKD_ERROR_SYSTEM_BUSY ||       \
   (err) == STKD_ERROR_TEMP_UNAVAILABLE ||  \
   (err) == STKD_ERROR_CONN_REFUSED)

#define STKD_MKFLAGS(flags, req) (htonl(((flags) << 8) | (req)))

#define STKD_RSP   0x1
#define STKD_ERROR 0x2

#define STKD_ERROR_MSG_SZ       8
#define STKD_OPENED_APP_RSP_SZ 12

#define STKD_OPEN_APP_REQUEST 0x0

#define STKD_ERROR_APP_DOES_NOT_EXIST     1
#define STKD_ERROR_APP_NOT_INSTALLED      2
#define STKD_ERROR_MALFORMED_NAME         3
#define STKD_ERROR_PERSONA_DOES_NOT_EXIST 4
#define STKD_ERROR_SYSTEM_ERROR           5
#define STKD_ERROR_SYSTEM_BUSY            6
#define STKD_ERROR_TEMP_UNAVAILABLE       7
#define STKD_ERROR_NO_SPACE               8
#define STKD_ERROR_INVALID_SOCKET_TYPE    9
#define STKD_ERROR_CONN_REFUSED           10
#define STKD_ERROR_INVALID_ADDR           11

#endif
