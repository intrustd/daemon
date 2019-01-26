#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "local_proto.h"
#include "commands.h"

const char *intrustd_error_code_str(uint16_t code) {
  switch ( code ) {
  case ALE_SUCCESS: return "Success";
  case ALE_NOT_IMPLEMENTED: return "Not implemented";
  case ALE_NOT_FOUND: return "Not found";
  case ALE_BAD_ENTITY: return "Bad entity";
  case ALE_BAD_OP: return "Bad operation";
  case ALE_MISSING_ATTRIBUTES: return "Missing attributes";
  case ALE_INVALID_URL: return "Invalid URL";
  case ALE_SYSTEM_ERROR: return "System error";
  default: return "Unknown";
  }
}

const char *intrustd_entity_str(uint16_t entity) {
  entity &= 0x7F00;

  switch ( entity ) {
  case ALM_REQ_ENTITY_PERSONA: return "Persona";
  case ALM_REQ_ENTITY_APP: return "Application";
  case ALM_REQ_ENTITY_FLOCK: return "Flock";
  case ALM_REQ_ENTITY_CONTAINER: return "Container";
  default: return "Unknown";
  }
}

const char *intrustd_operation_str(uint16_t otype) {
  otype &= 0x00FF;

  switch ( otype ) {
  case ALM_REQ_GET: return "GET";
  case ALM_REQ_CREATE: return "CREATE";
  case ALM_REQ_DELETE: return "DELETE";
  case ALM_REQ_UPDATE: return "UPDATE";
  case ALM_REQ_STOP: return "STOP";
  case ALM_REQ_SUB: return "SUB";
  default: return "Unknown";
  }
}

void intrustd_print_attr_data(FILE *out, struct applocalattr *attr) {
  uint16_t attr_type = ntohs(attr->ala_name), attr_len = ntohs(attr->ala_length);
  //  uint16_t *attr_d16;

  attr_len -= sizeof(*attr);

  switch ( attr_type ) {
  case ALA_RESPONSE_CODE:
    if ( ntohs(attr->ala_length) == ALA_SIZE(sizeof(uint16_t)) ) {
      fprintf(out, "  Response code: %d\n", ntohs(*ALA_DATA_UNSAFE(attr, uint16_t *)));
      return;
    } else goto unknown;
  case ALA_ENTITY:
    if ( ntohs(attr->ala_length) == ALA_SIZE(sizeof(uint16_t)) ) {
      uint16_t etype = ntohs(*ALA_DATA_UNSAFE(attr, uint16_t *));
      fprintf(out, "  Entity: %s (%x)\n", intrustd_entity_str(etype), etype);
      return;
    } else goto unknown;
  case ALA_SYSTEM_ERROR:
    if ( ntohs(attr->ala_length) == ALA_SIZE(sizeof(uint32_t)) ) {
      fprintf(out, "   Error: %s\n", strerror(ntohl(*ALA_DATA_UNSAFE(attr, uint32_t *))));
      return;
    } else goto unknown;
  case ALA_OPERATION:
    if ( ntohs(attr->ala_length) == ALA_SIZE(sizeof(uint16_t)) ) {
      uint16_t otype = ntohs(*ALA_DATA_UNSAFE(attr, uint16_t *));
      fprintf(out, "  Operation: %s (%x)\n", intrustd_operation_str(otype), otype);
      return;
    } else goto unknown;
  case ALA_PERSONA_DISPLAYNM:
    fprintf(out, "  Display Name: %.*s\n", (int) ALA_PAYLOAD_SIZE(attr),
            ALA_DATA_UNSAFE(attr, char *));
    return;
  case ALA_PERSONA_ID:
    if ( ALA_PAYLOAD_SIZE(attr) <= 100 ) {
      char hex_str[201];
      fprintf(out, "  Persona ID: %s\n", hex_digest_str(ALA_DATA_UNSAFE(attr, unsigned char *),
                                                        hex_str, ALA_PAYLOAD_SIZE(attr)));
      return;
    } else goto unknown;
  default: goto unknown;
  }
  unknown:
    fprintf(out, "  Unknown Attribute(%d) with %d bytes of data: \n", attr_type, attr_len);
}

int display_intrustd_response(char *buf, int size, const char *success_msg) {
  struct applocalmsg *msg;
  struct applocalattr *attr;
  int found_response = 0, response_code = 0, is_error = 1;

  if ( size < sizeof(*msg) ) {
    fprintf(stderr, "Response did not contain enough bytes\n");
    exit(1);
  }

  msg = (struct applocalmsg *) buf;
  if ( (ntohs(msg->alm_req) & ALM_RESPONSE) == 0 ) {
    fprintf(stderr, "Response was not a response (%04x)\n", ntohs(msg->alm_req));
    exit(1);
  }

  // Go over each attribute
  for ( attr = ALM_FIRSTATTR(msg, size); attr; attr = ALM_NEXTATTR(msg, attr, size) ) {
    if ( ntohs(attr->ala_name) == ALA_RESPONSE_CODE ) {
      uint16_t *code = ALA_DATA_AS(attr, msg, size, uint16_t *);
      found_response = 1;

      if ( !code ) {
        fprintf(stderr, "Not enough data in response\n");
        exit(1);
      }
      response_code = ntohs(*code);
      break;
    }
  }

  if ( !found_response ) {
    fprintf(stderr, "No ALA_RESPONSE_CODE attribute in response\n");
    exit(1);
  }

  is_error = response_code != ALE_SUCCESS;
  if ( !is_error ) {
    if ( success_msg )
      fprintf(stderr, "%s\n", success_msg);

    return 0;
  } else {
    fprintf(stderr, "Got error code: %s\n", intrustd_error_code_str(response_code));
    for ( attr = ALM_FIRSTATTR(msg, size); attr; attr = ALM_NEXTATTR(msg, attr, size) ) {
      intrustd_print_attr_data(stderr, attr);
    }

    return -1;
  }
}

int mk_api_socket() {
  struct sockaddr_un addr;
  int err, sk;
  char *intrustd_path = getenv("INTRUSTD_APPLIANCE_DIR");

  addr.sun_family = AF_UNIX;

  if ( intrustd_path )
    err = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/" APPLIANCED_LOCAL_API_SOCK, intrustd_path);
  else
    err = strnlen(strncpy(addr.sun_path, APPLIANCED_LOCAL_API_SOCK, sizeof(addr.sun_path)),
                  sizeof(addr.sun_path));
  assert(err < sizeof(addr.sun_path));

  sk = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if ( sk < 0 ) {
    perror("mk_api_socket: socket");
    return -1;
  }

  err = connect(sk, (struct sockaddr *)&addr, sizeof(addr));
  if ( err < 0 ) {
    perror("mk_api_socket: connect");
    close(sk);
    return -1;
  }

  return sk;
}

int send_with_fds(int sk, const void *buf, size_t bufsz, int flags,
                  int *fds, int nfds) {
  char *cbuf[CMSG_SPACE(sizeof(int) * nfds)];
  struct iovec iov[1] = {
    { .iov_base = (void *) buf, .iov_len = bufsz }
  };
  struct msghdr msg = {
    .msg_name = NULL,
    .msg_namelen = 0,

    .msg_iov = iov,
    .msg_iovlen = 1,

    .msg_control = cbuf,
    .msg_controllen = CMSG_SPACE(sizeof(int) * nfds),

    .msg_flags = flags
  };
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int) * nfds);
  memcpy((int *) CMSG_DATA(cmsg), fds, sizeof(*fds) * nfds);

  return sendmsg(sk, &msg, 0);
}
