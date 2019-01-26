#include <errno.h>

#include "commands.h"
#include "local_proto.h"

static int run_in_container_usage() {
  fprintf(stderr, "Usage: appliancectl run-in-container <container-addr> [command...]\n");
  return 1;
}

int run_in_container(int argc, char **argv) {
  uint32_t addr;

  char buf[APPLIANCED_MAX_LOCAL_MSG_SZ];
  struct applocalmsg *msg = (struct applocalmsg *)buf;
  struct applocalattr *attr = ALM_FIRSTATTR(msg, sizeof(buf));
  int sz = ALM_SIZE_INIT, i, sk, fds[3], err;
  uint8_t fdix;

  if ( argc < 2 )
    return run_in_container_usage();

  if ( inet_pton(AF_INET, argv[1], &addr) <= 0 ) {
    if ( errno == 0 ) {
      fprintf(stderr, "Invalid address %s\n", argv[1]);
    } else {
      perror("inet_pton");
    }
    return 1;
  }

  msg->alm_req = ntohs(ALM_REQ_SUB | ALM_REQ_ENTITY_CONTAINER);
  msg->alm_req_flags = 0;

  attr->ala_name = ntohs(ALA_ADDR);
  attr->ala_length = ntohs(ALA_SIZE(sizeof(addr)));
  memcpy(ALA_DATA_UNSAFE(attr, char *), &addr, sizeof(addr));
  ALM_SIZE_ADD_ATTR(sz, attr);

  fdix = 0;
  fds[fdix] = STDIN_FILENO;
  attr = ALM_NEXTATTR(msg, attr, sizeof(buf));
  attr->ala_name = ntohs(ALA_STDIN);
  attr->ala_length = ntohs(ALA_SIZE(sizeof(fdix)));
  memcpy(ALA_DATA_UNSAFE(attr, char *), &fdix, sizeof(fdix));
  ALM_SIZE_ADD_ATTR(sz, attr);

  fdix = 1;
  fds[fdix] = STDOUT_FILENO;
  attr = ALM_NEXTATTR(msg, attr, sizeof(buf));
  attr->ala_name = ntohs(ALA_STDOUT);
  attr->ala_length = ntohs(ALA_SIZE(sizeof(fdix)));
  memcpy(ALA_DATA_UNSAFE(attr, char *), &fdix, sizeof(fdix));
  ALM_SIZE_ADD_ATTR(sz, attr);

  fdix = 2;
  fds[fdix] = STDERR_FILENO;
  attr = ALM_NEXTATTR(msg, attr, sizeof(buf));
  attr->ala_name = ntohs(ALA_STDERR);
  attr->ala_length = ntohs(ALA_SIZE(sizeof(fdix)));
  memcpy(ALA_DATA_UNSAFE(attr, char *), &fdix, sizeof(fdix));
  ALM_SIZE_ADD_ATTR(sz, attr);

  for ( i = 2; i < argc; ++i ) {
    int argsz = strlen(argv[i]);

    attr = ALM_NEXTATTR(msg, attr, sizeof(buf));
    if ( !attr ) goto overflow;

    attr->ala_name = ntohs(ALA_ARG);
    attr->ala_length = ntohs(ALA_SIZE(argsz));
    if ( ! (ALA_DATA(attr, buf, sizeof(buf))) ) goto overflow;
    memcpy(ALA_DATA_UNSAFE(attr, char *), argv[i], argsz);
    ALM_SIZE_ADD_ATTR(sz, attr);
  }

  sk = mk_api_socket();
  if ( sk < 0 ) {
    fprintf(stderr, "run_in_container: mk_api_socket failed\n");
    return 3;
  }

  // Send this along with file descriptors
  err = send_with_fds(sk, buf, sz, 0, fds, 3);
  if ( err < 0 ) {
    perror("run_in_container: send");
    close(sk);
    return 3;
  }

  err = recv(sk, buf, sizeof(buf), 0);
  if ( err < 0 ) {
    perror("run_in_container: recv");
    close(sk);
    return 2;
  }

  if ( display_intrustd_response(buf, err, NULL) == 0 ) {
    msg = (struct applocalmsg *) buf;
    for ( attr = ALM_FIRSTATTR(msg, err);
          attr;
          attr = ALM_NEXTATTR(msg, attr, err) ) {
      if ( ntohs(attr->ala_name) == ALA_EXIT_CODE &&
           ALA_PAYLOAD_SIZE(attr) == sizeof(uint32_t) ) {
        uint32_t sts;
        memcpy(&sts, ALA_DATA_UNSAFE(attr, void *), sizeof(sts));
        sts = htonl(sts);
        return sts;
      }
    }
    fprintf(stderr, "No status in response\n");
    return 32767;
  } else
    return 32768;

  // TODO optionally wait

 overflow:
  fprintf(stderr, "Command is too long\n");
  return 5;
}
