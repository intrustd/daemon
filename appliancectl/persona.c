#include <assert.h>
#include <stdio.h>
#include <getopt.h>

#include "local_proto.h"
#include "commands.h"

#define DISPLAY_NAME_ARG 0x200
#define PASSWORD_ARG     0x201
#define SUPERUSER_ARG    0x202

int create_persona_usage() {
  fprintf(stderr, "Usage: appliancectl create-persona [--display-name <name>] [--password <pw>] [--superuser]\n");
  return 1;
}

int create_persona(int argc, char **argv) {
  static const struct option options[] = {
    { "display-name", 1, NULL, DISPLAY_NAME_ARG },
    { "password", 1, NULL, PASSWORD_ARG },
    { "superuser", 0, NULL, SUPERUSER_ARG },
    {0, 0, 0, 0}
  };

  char buf[APPLIANCED_MAX_LOCAL_MSG_SZ];
  struct applocalmsg *msg = (struct applocalmsg *) buf;
  struct applocalattr *attr = ALM_FIRSTATTR(msg, sizeof(buf));
  int optind = 0, c, sz = ALM_SIZE_INIT, sk, err;

  char *display_name = NULL;
  char *password = NULL;
  uint32_t flags = 0;

  while ( (c = getopt_long(argc, argv, "h", options, &optind)) ) {
    if ( c == -1 ) break;

    switch ( c ) {
    case DISPLAY_NAME_ARG:
      display_name = optarg;
      break;
    case PASSWORD_ARG:
      password = optarg;
      break;
    case SUPERUSER_ARG:
      flags |= PERSONA_FLAG_SUPERUSER;
      break;
    case 'h':
    default:
      return create_persona_usage();
    }
  }

  // Prompt for anything remaining (TODO)
  if ( !display_name || !password )
    return create_persona_usage();

  msg->alm_req = ntohs(ALM_REQ_CREATE | ALM_REQ_ENTITY_PERSONA);
  msg->alm_req_flags = 0;

  attr->ala_name = ntohs(ALA_PERSONA_DISPLAYNM);
  attr->ala_length = ntohs(ALA_SIZE(strlen(display_name)));
  memcpy(ALA_DATA_UNSAFE(attr, char *), display_name, strlen(display_name));
  ALM_SIZE_ADD_ATTR(sz, attr);

  attr = ALM_NEXTATTR(msg, attr, sizeof(buf));
  assert(attr);
  attr->ala_name = ntohs(ALA_PERSONA_PASSWORD);
  attr->ala_length = ntohs(ALA_SIZE(strlen(password)));
  memcpy(ALA_DATA_UNSAFE(attr, char *), password, strlen(password));
  ALM_SIZE_ADD_ATTR(sz, attr);

  if ( flags ) {
    attr = ALM_NEXTATTR(msg, attr, sizeof(buf));
    assert(attr);
    attr->ala_name = ntohs(ALA_PERSONA_FLAGS);
    attr->ala_length = ntohs(ALA_SIZE(sizeof(uint32_t) * 2));
    memset(ALA_DATA_UNSAFE(attr, void *), 0, sizeof(uint32_t) * 2);
    flags = ntohl(flags);
    memcpy(ALA_DATA_UNSAFE(attr, void *), &flags, sizeof(flags));
    ALM_SIZE_ADD_ATTR(sz, attr);
  }

  sk = mk_api_socket();
  if ( sk < 0 ) {
    fprintf(stderr, "create_persona: mk_api_socket failed\n");
    return 3;
  }

  err = send(sk, buf, sz, 0);
  if ( err < 0 ) {
    perror("create_persona: send");
    close(sk);
    return 3;
  }

  err = recv(sk, buf, sizeof(buf), 0);
  if ( err < 0 ) {
    perror("create_persona: recv");
    close(sk);
    return 2;
  }

  display_intrustd_response(buf, err, "Successfully created persona");

  return 0;
}

int list_personas(int argc, char **argv) {
  return 1;
}
