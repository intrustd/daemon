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

static const char *kite_error_code_str(uint16_t code) {
  switch ( code ) {
  case KLE_SUCCESS: return "Success";
  case KLE_NOT_IMPLEMENTED: return "Not implemented";
  case KLE_BAD_ENTITY: return "Bad entity";
  case KLE_BAD_OP: return "Bad operation";
  case KLE_MISSING_ATTRIBUTES: return "Missing attributes";
  case KLE_INVALID_URL: return "Invalid URL";
  case KLE_SYSTEM_ERROR: return "System error";
  default: return "Unknown";
  }
}

static const char *kite_entity_str(uint16_t entity) {
  entity &= 0xFF00;

  switch ( entity ) {
  case KLM_REQ_ENTITY_PERSONA: return "Persona";
  case KLM_REQ_ENTITY_APP: return "Application";
  case KLM_REQ_ENTITY_FLOCK: return "Flock";
  default: return "Unknown";
  }
}

static void kite_print_attr_data(FILE *out, struct kitelocalattr *attr) {
  uint16_t attr_type = ntohs(attr->kla_name), attr_len = ntohs(attr->kla_length);
  uint16_t *attr_d16;

  attr_len -= sizeof(*attr);

  switch ( attr_type ) {
  case KLA_RESPONSE_CODE:
    if ( ntohs(attr->kla_length) == KLA_SIZE(sizeof(uint16_t)) ) {
      fprintf(out, "  Response code: %d\n", ntohs(*KLA_DATA_UNSAFE(attr, uint16_t *)));
      return;
    } else goto unknown;
  case KLA_ENTITY:
    if ( ntohs(attr->kla_length) == KLA_SIZE(sizeof(uint16_t)) ) {
      uint16_t etype = ntohs(*KLA_DATA_UNSAFE(attr, uint16_t *));
      fprintf(out, "  Entity: %s (%x)\n", kite_entity_str(etype), etype);
      return;
    } else goto unknown;
  case KLA_SYSTEM_ERROR:
    if ( ntohs(attr->kla_length) == KLA_SIZE(sizeof(uint32_t)) ) {
      fprintf(out, "   Error: %s\n", strerror(ntohl(*KLA_DATA_UNSAFE(attr, uint32_t *))));
      return;
    } else goto unknown;
  default: goto unknown;
  }
  unknown:
    fprintf(out, "  Unknown Attribute(%d) with %d bytes of data: \n", attr_type, attr_len);
}

void display_stork_response(char *buf, int size, const char *success_msg) {
  struct kitelocalmsg *msg;
  struct kitelocalattr *attr;
  int found_response = 0, response_code = 0, is_error = 1;

  if ( size < sizeof(*msg) ) {
    fprintf(stderr, "Response did not contain enough bytes\n");
    exit(1);
  }

  msg = (struct kitelocalmsg *) buf;
  if ( (ntohs(msg->klm_req) & KLM_RESPONSE) == 0 ) {
    fprintf(stderr, "Response was not a response (%04x)\n", ntohs(msg->klm_req));
    exit(1);
  }

  // Go over each attribute
  for ( attr = KLM_FIRSTATTR(msg, size); attr; attr = KLM_NEXTATTR(msg, attr, size) ) {
    if ( ntohs(attr->kla_name) == KLA_RESPONSE_CODE ) {
      uint16_t *code = KLA_DATA_AS(attr, msg, size, uint16_t *);
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
    fprintf(stderr, "No KLA_RESPONSE_CODE attribute in response\n");
    exit(1);
  }

  is_error = response_code != KLE_SUCCESS;
  if ( !is_error )
    fprintf(stderr, "%s\n", success_msg);
  else {
    fprintf(stderr, "Got error code: %s\n", kite_error_code_str(response_code));
    for ( attr = KLM_FIRSTATTR(msg, size); attr; attr = KLM_NEXTATTR(msg, attr, size) ) {
      kite_print_attr_data(stderr, attr);
    }
  }
}

int mk_api_socket() {
  struct sockaddr_un addr;
  int err, sk;
  char *stork_path = getenv("STORK_APPLIANCE_DIR");

  addr.sun_family = AF_UNIX;

  if ( stork_path )
    err = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/" KITE_LOCAL_API_SOCK, stork_path);
  else
    err = strnlen(strncpy(addr.sun_path, KITE_LOCAL_API_SOCK, sizeof(addr.sun_path)),
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

int join_flock(int argc, char **argv) {
  char buf[KITE_MAX_LOCAL_MSG_SZ];
  struct kitelocalmsg *msg = (struct kitelocalmsg *)buf;
  struct kitelocalattr *attr = KLM_FIRSTATTR(msg, sizeof(buf));
  char *flock_uri;
  int err, sk = 0, sz = KLM_SIZE_INIT;

  if ( argc < 2 ) {
    fprintf(stderr, "Expected flock URI on command line\n");
    fprintf(stderr, "Usage: appliancectl join-flock <FLOCK-URI>\n");
    return 1;
  }

  flock_uri = argv[1];

  assert(attr);

  msg->klm_req = ntohs(KLM_REQ_CREATE | KLM_REQ_ENTITY_FLOCK);
  msg->klm_req_flags = 0;
  attr->kla_name = ntohs(KLA_FLOCK_URL);
  attr->kla_length = ntohs(KLA_SIZE(strlen(flock_uri)));

  KLM_SIZE_ADD_ATTR(sz, attr);

  assert(KLA_DATA(attr, buf, sizeof(buf)));
  memcpy(KLA_DATA(attr, buf, sizeof(buf)), flock_uri, strlen(flock_uri));

  sk = mk_api_socket();
  if ( sk < 0 ) {
    fprintf(stderr, "join_flock: mk_api_socket failed\n");
    return 3;
  }

  err = send(sk, buf, sz, 0);
  if ( err < 0 ) {
    perror("join_flock: send");
    close(sk);
    return 3;
  }

  sz = recv(sk, buf, sizeof(buf), 0);
  if ( sz < 0 ) {
    perror("join_flock: recv");
    close(sk);
    return 4;
  }

  display_stork_response(buf, sz, "Flock request submitted (use list-flocks command to see status)");

  close(sk);
}
