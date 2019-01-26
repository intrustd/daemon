#include <getopt.h>

#include "local_proto.h"
#include "commands.h"

#define MANIFEST_URL_ARG 0x200
#define IDENTIFIER_ARG   0x201

static int register_app_usage() {
  fprintf(stderr, "Usage: appliancectl register-app [-h] [-f] [-P] <app-manifest-url> [-S <signature-url>]\n");
  return 1;
}

int register_app(int argc, char **argv) {
  char buf[APPLIANCED_MAX_LOCAL_MSG_SZ];
  char *app_manifest;
  const char *signature = NULL;
  struct applocalmsg *msg = (struct applocalmsg *)buf;
  struct applocalattr *attr = ALM_FIRSTATTR(msg, sizeof(buf));
  int sz = ALM_SIZE_INIT, sk, err, c, do_force = 0, show_progress = 0;

  while ( (c = getopt(argc, argv, "hfPS:")) ) {
    if ( c == -1 ) break;

    switch ( c ) {
    case 'f':
      do_force = 1;
      break;

    case 'P':
      show_progress = 1;
      break;

    case 'S':
      signature = optarg;
      break;

    case 'h':
    default:
      return register_app_usage();
    }
  }

  if ( optind >= argc ) {
    fprintf(stderr, "Expected app manifest url\n");
    return register_app_usage();
  }


  app_manifest = argv[optind];

  msg->alm_req = ntohs(ALM_REQ_CREATE | ALM_REQ_ENTITY_APP);
  msg->alm_req_flags = 0;

  attr->ala_name = ntohs(ALA_APP_MANIFEST_URL);
  attr->ala_length = ntohs(ALA_SIZE(strlen(app_manifest)));
  memcpy(ALA_DATA_UNSAFE(attr, char*), app_manifest, strlen(app_manifest));
  ALM_SIZE_ADD_ATTR(sz, attr);

  if ( do_force ) {
    attr = ALM_NEXTATTR(msg, attr, sizeof(buf));
    assert(attr);
    attr->ala_name = ntohs(ALA_FORCE);
    attr->ala_length = ntohs(ALA_SIZE(0));
    ALM_SIZE_ADD_ATTR(sz, attr);
  }

  if ( signature ) {
    attr = ALM_NEXTATTR(msg, attr, sizeof(buf));
    assert(attr);
    attr->ala_name = ntohs(ALA_APP_SIGNATURE_URL);
    attr->ala_length = ntohs(ALA_SIZE(strlen(signature)));
    memcpy(ALA_DATA_UNSAFE(attr, char*), signature, strlen(signature));
    ALM_SIZE_ADD_ATTR(sz, attr);
  }

  if ( show_progress ) {
    uint8_t fdidx = 0;

    attr = ALM_NEXTATTR(msg, attr, sizeof(buf));
    assert(attr);
    attr->ala_name = ntohs(ALA_STDOUT);
    attr->ala_length = ntohs(ALA_SIZE(sizeof(fdidx)));
    memcpy(ALA_DATA_UNSAFE(attr, char*), &fdidx, sizeof(fdidx));
    ALM_SIZE_ADD_ATTR(sz, attr);
  }

  sk = mk_api_socket();
  if ( sk < 0 ) {
    fprintf(stderr, "register_app: mk_api_socket failed\n");
    return 3;
  }

  if ( !show_progress ) {
    err = send(sk, buf, sz, 0);
  } else {
    int fds[1] = { STDOUT_FILENO };
    err = send_with_fds(sk, buf, sz, 0, fds, 1);
  }
  if ( err < 0 ) {
    perror("register_app: send");
    close(sk);
    return 3;
  }

  err = recv(sk, buf, sizeof(buf), 0);
  if ( err < 0 ) {
    perror("register_app: recv");
    close(sk);
    return 2;
  }

  if ( display_intrustd_response(buf, err, "Successfully registered application\n") < 0 )
    return EXIT_FAILURE;

  return EXIT_SUCCESS;
}
