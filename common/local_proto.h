#ifndef __applianced_local_proto_H__
#define __applianced_local_proto_H__

#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "util.h"

#define APPLIANCED_MAX_LOCAL_MSG_SZ 4096
#define APPLIANCED_LOCAL_API_SOCK "applianced-control"

struct applocalmsg {
  uint16_t alm_req;
  uint16_t alm_req_flags;
} INTRUSTD_PACKED;

struct applocalattr {
  uint16_t ala_name;
  uint16_t ala_length; // Includes sizeof (applocalattr)
} INTRUSTD_PACKED;

#define ALM_REQ_OP(msg)        (ntohs((msg)->alm_req) & 0x00FF)
#define ALM_REQ_GET    0x00
#define ALM_REQ_CREATE 0x01
#define ALM_REQ_DELETE 0x02
#define ALM_REQ_UPDATE 0x03
#define ALM_REQ_STOP   0x04 // Kills running containers
#define ALM_REQ_SUB    0x05 // Runs a command within a container

#define ALM_REQ_ENTITY(msg)    (ntohs((msg)->alm_req) & 0x7F00)
#define ALM_REQ_ENTITY_PERSONA 0x0100
#define ALM_REQ_ENTITY_APP     0x0200
#define ALM_REQ_ENTITY_FLOCK   0x0300
#define ALM_REQ_ENTITY_CONTAINER 0x0400
#define ALM_REQ_ENTITY_SYSTEM  0x0500

#define ALM_RESPONSE           0x8000

#define ALM_IS_END(msg)        (ntohs((msg)->alm_req_flags) & ALM_IS_LAST)
#define ALM_RETURN_MULTIPLE    0x0001
#define ALM_IS_LAST            0x0002

#define ALA_RESPONSE_CODE      0x0000
#define ALA_PERSONA_ID         0x0001
#define ALA_APP_URL            0x0002
#define ALA_APP_MANIFEST_URL   0x0003
#define ALA_REQUEST_ATTRIBUTE  0x0004
#define ALA_APP_PERMISSION     0x0005
#define ALA_FLOCK_URL          0x0006
#define ALA_ENTITY             0x0007
#define ALA_MESSAGE            0x0008
#define ALA_OPERATION          0x0009
#define ALA_SYSTEM_ERROR       0x000A
#define ALA_FLOCK_SIGNATURE    0x000B
#define ALA_FLOCK_STATUS       0x000C
#define ALA_PERSONA_DISPLAYNM  0x000D
#define ALA_PERSONA_PASSWORD   0x000E
#define ALA_FORCE              0x000F
#define ALA_ADDR               0x0010
#define ALA_CONTAINER_TYPE     0x0011
#define ALA_PCONN_ID           0x0012
#define ALA_SITE_ID            0x0013
#define ALA_MANIFEST_NAME      0x0014
#define ALA_SIGNED             0x0015
#define ALA_TOKEN              0x0016
#define ALA_ARG                0x0017
#define ALA_STDOUT             0x0018
#define ALA_STDERR             0x0019
#define ALA_STDIN              0x001A
#define ALA_ATTRIBUTE          0x001B
#define ALA_EXIT_CODE          0x001C
#define ALA_PERSONA_FLAGS      0x001D /* Two uint32_ts. First are flags to add. second is flags to remove */
#define ALA_SYSTEM_TYPE        0x001E
#define ALA_APP_SIGNATURE_URL  0x001F
#define ALA_CRED               0x0020
#define ALA_GUEST              0x0021
#define ALA_RESET_PHOTO        0x0022

#define ALE_SUCCESS            0x0000
#define ALE_NOT_IMPLEMENTED    0x0001
#define ALE_BAD_ENTITY         0x0002
#define ALE_BAD_OP             0x0003
#define ALE_MISSING_ATTRIBUTES 0x0004
#define ALE_INVALID_URL        0x0005
#define ALE_SYSTEM_ERROR       0x0006
#define ALE_NOT_FOUND          0x0007
#define ALE_NOT_ALLOWED        0x0008

#define PERSONA_FLAG_SUPERUSER 0x1

#define ALM_SIZE_INIT sizeof(struct applocalmsg)
#define ALA_PAYLOAD_SIZE(a) (ntohs((a)->ala_length) - sizeof(struct applocalattr))
#define ALA_SIZE(data_sz) (sizeof(struct applocalattr) + data_sz)
#define ALM_SIZE_ADD_ATTR(sz, attr) (sz) += 4 * (((htons((attr)->ala_length)) + 3) / 4)
#define ALM_FIRSTATTR(msg, sz) ((sz) <= sizeof(struct applocalmsg) ? NULL : ((struct applocalattr *) (((uintptr_t) msg) + sizeof(struct applocalmsg))))
#define ALM_NEXTATTR_(attr) (((attr)->ala_length == 0) ? 0 : (((uintptr_t) attr) + 4 * ((htons((attr)->ala_length) + 3) / 4)))
#define ALM_NEXTATTR(msg, attr, sz) (((ALM_NEXTATTR_(attr) - ((uintptr_t) msg)) < sz) ? (struct applocalattr *) ALM_NEXTATTR_(attr) : NULL)
#define ALA_DATA(attr, buf, sz)                                         \
  ((((((uintptr_t) attr) + sizeof(struct applocalattr)) - ((uintptr_t) buf)) < sz) ? \
   (char *) (((uintptr_t) attr) + sizeof(struct applocalattr)) : NULL)
#define ALA_DATA_AS(attr, buf, sz, type) ((type) (ALA_DATA(attr, buf, sz)))
#define ALA_DATA_UNSAFE(attr, type) ((type) (((uintptr_t)attr) + sizeof(struct applocalattr)))
#define ALA_NAME(attr) ntohs((attr)->ala_name)

#endif
