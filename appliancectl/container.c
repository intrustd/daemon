#include <errno.h>

#include "commands.h"
#include "local_proto.h"

static int run_in_container_usage() {
  fprintf(stderr, "Usage: appliancectl run-in-container <container-addr> [command...]\n");
  return 1;
}

int run_in_container(int argc, char **argv) {
  uint32_t addr;

  char buf[KITE_MAX_LOCAL_MSG_SZ];
  struct kitelocalmsg *msg = (struct kitelocalmsg *)buf;
  struct kitelocalattr *attr = KLM_FIRSTATTR(msg, sizeof(buf));
  int sz = KLM_SIZE_INIT, i, sk, fds[3], err;
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

  msg->klm_req = ntohs(KLM_REQ_SUB | KLM_REQ_ENTITY_CONTAINER);
  msg->klm_req_flags = 0;

  attr->kla_name = ntohs(KLA_ADDR);
  attr->kla_length = ntohs(KLA_SIZE(sizeof(addr)));
  memcpy(KLA_DATA_UNSAFE(attr, char *), &addr, sizeof(addr));
  KLM_SIZE_ADD_ATTR(sz, attr);

  fdix = 0;
  fds[fdix] = STDIN_FILENO;
  attr = KLM_NEXTATTR(msg, attr, sizeof(buf));
  attr->kla_name = ntohs(KLA_STDIN);
  attr->kla_length = ntohs(KLA_SIZE(sizeof(fdix)));
  memcpy(KLA_DATA_UNSAFE(attr, char *), &fdix, sizeof(fdix));
  KLM_SIZE_ADD_ATTR(sz, attr);

  fdix = 1;
  fds[fdix] = STDOUT_FILENO;
  attr = KLM_NEXTATTR(msg, attr, sizeof(buf));
  attr->kla_name = ntohs(KLA_STDOUT);
  attr->kla_length = ntohs(KLA_SIZE(sizeof(fdix)));
  memcpy(KLA_DATA_UNSAFE(attr, char *), &fdix, sizeof(fdix));
  KLM_SIZE_ADD_ATTR(sz, attr);

  fdix = 2;
  fds[fdix] = STDERR_FILENO;
  attr = KLM_NEXTATTR(msg, attr, sizeof(buf));
  attr->kla_name = ntohs(KLA_STDERR);
  attr->kla_length = ntohs(KLA_SIZE(sizeof(fdix)));
  memcpy(KLA_DATA_UNSAFE(attr, char *), &fdix, sizeof(fdix));
  KLM_SIZE_ADD_ATTR(sz, attr);

  for ( i = 2; i < argc; ++i ) {
    int argsz = strlen(argv[i]);

    attr = KLM_NEXTATTR(msg, attr, sizeof(buf));
    if ( !attr ) goto overflow;

    attr->kla_name = ntohs(KLA_ARG);
    attr->kla_length = ntohs(KLA_SIZE(argsz));
    if ( ! (KLA_DATA(attr, buf, sizeof(buf))) ) goto overflow;
    memcpy(KLA_DATA_UNSAFE(attr, char *), argv[i], argsz);
    KLM_SIZE_ADD_ATTR(sz, attr);
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

  if ( display_stork_response(buf, err, NULL) == 0 ) {
    msg = (struct kitelocalmsg *) buf;
    for ( attr = KLM_FIRSTATTR(msg, err);
          attr;
          attr = KLM_NEXTATTR(msg, attr, err) ) {
      if ( ntohs(attr->kla_name) == KLA_EXIT_CODE &&
           KLA_PAYLOAD_SIZE(attr) == sizeof(uint32_t) ) {
        uint32_t sts;
        memcpy(&sts, KLA_DATA_UNSAFE(attr, void *), sizeof(sts));
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
