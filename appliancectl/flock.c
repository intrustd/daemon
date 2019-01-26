#include <assert.h>

#include "local_proto.h"
#include "commands.h"

int join_flock(int argc, char **argv) {
  char buf[APPLIANCED_MAX_LOCAL_MSG_SZ];
  struct applocalmsg *msg = (struct applocalmsg *)buf;
  struct applocalattr *attr = ALM_FIRSTATTR(msg, sizeof(buf));
  char *flock_uri;
  int err, sk = 0, sz = ALM_SIZE_INIT;

  if ( argc != 2 ) {
    fprintf(stderr, "Usage: appliancectl join-flock <FLOCK-URI>\n");
    return 1;
  }

  flock_uri = argv[1];

  assert(attr);

  msg->alm_req = ntohs(ALM_REQ_CREATE | ALM_REQ_ENTITY_FLOCK);
  msg->alm_req_flags = 0;
  attr->ala_name = ntohs(ALA_FLOCK_URL);
  attr->ala_length = ntohs(ALA_SIZE(strlen(flock_uri)));

  ALM_SIZE_ADD_ATTR(sz, attr);

  assert(ALA_DATA(attr, buf, sizeof(buf)));
  memcpy(ALA_DATA_UNSAFE(attr, void*), flock_uri, strlen(flock_uri));

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

  display_intrustd_response(buf, sz, "Flock request submitted (use list-flocks command to see status)");

  close(sk);

  return EXIT_SUCCESS;
}

int list_flocks(int argc, char **argv) {
  char buf[APPLIANCED_MAX_LOCAL_MSG_SZ];
  struct applocalmsg *msg = (struct applocalmsg *)buf;
  struct applocalattr *attr;
  int sz = ALM_SIZE_INIT, sk, err;

  if ( argc > 1 ) {
    fprintf(stderr, "Usage: appliancectl list-flocks\n");
    return 1;
  }

  msg->alm_req = ntohs(ALM_REQ_GET | ALM_REQ_ENTITY_FLOCK);
  msg->alm_req_flags = htons(ALM_RETURN_MULTIPLE);

  sk = mk_api_socket();
  if ( sk < 0 ) {
    fprintf(stderr, "list_flocks: mk_api_socket failed\n");
    return 3;
  }

  err = send(sk, buf, sz, 0);
  if ( err < 0 ) {
    perror("list_flocks: send");
    close(sk);
    return 3;
  }

  do {
    sz = recv(sk, buf, sizeof(buf), 0);
    if ( sz < 0 ) {
      perror("list_flocks: recv");
      close(sk);
      return 4;
    }

    if ( display_intrustd_response(buf, sz, NULL) == 0 ) {
      // Successful response, print result in tabular format
      uint32_t flock_status = 0xFFFFFFFF;
      unsigned char *flock_signature_start, *flock_signature_end;
      char *flock_url_start, *flock_url_end;
      flock_signature_start = flock_signature_end = NULL;
      flock_url_start = flock_url_end = NULL;

      assert( ALM_REQ_ENTITY(msg) == ALM_REQ_ENTITY_FLOCK &&
              ALM_REQ_OP(msg) == ALM_REQ_GET );

      for ( attr = ALM_FIRSTATTR(msg, sz); attr; attr = ALM_NEXTATTR(msg, attr, sz) ) {
        switch ( ntohs(attr->ala_name) ) {
        case ALA_FLOCK_URL:
          flock_url_start = ALA_DATA(attr, msg, sz);
          flock_url_end = flock_url_start + ALA_PAYLOAD_SIZE(attr);
          break;
        case ALA_FLOCK_SIGNATURE:
          flock_signature_start = (unsigned char *)ALA_DATA(attr, msg, sz);
          flock_signature_end = flock_signature_start + ALA_PAYLOAD_SIZE(attr);
          break;
        case ALA_FLOCK_STATUS:
          if ( ALA_PAYLOAD_SIZE(attr) != sizeof(flock_status) ) {
            fprintf(stderr, "list_flocks: Invalid payload length for ALA_FLOCK_STATUS: %zu\n", ALA_PAYLOAD_SIZE(attr));
          } else {
            flock_status = ntohl(*(ALA_DATA_AS(attr, buf, sz, uint32_t *)));
          }
        default:
          break;
        }
      }

      if ( !flock_url_start || flock_status == ~0 ) {
        fprintf(stderr, "list_flocks: missing attributes in response\n");
        return 6;
      } else {
        char flock_signature_hex[flock_signature_start ? (flock_signature_end - flock_signature_start) * 2 + 1 : 1];
        char *flock_signature_str;

        if ( flock_signature_start )
          flock_signature_str = hex_digest_str(flock_signature_start, flock_signature_hex,
                                               flock_signature_end - flock_signature_start);
        else
          flock_signature_str = "<none>";

        printf("%.*s %08x %s\n",
               (int) (flock_url_end - flock_url_start), flock_url_start,
               flock_status, flock_signature_str);
      }
    } else
      return 5;

  } while ( !ALM_IS_END(msg) );

  return EXIT_SUCCESS;
}
