#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "util.h"

int strncpy_safe(char *dst, const char *src, size_t sz) {
  size_t src_sz = strlen(src);

  if ( src_sz < (sz - 1) ) {
    // Src fits completely
    memcpy(dst, src, src_sz + 1);
    return 1;
  } else {
    return 0;
  }
}

int mkdir_recursive(const char *path) {
  char lpath[PATH_MAX], dir_path[PATH_MAX];
  char *cur_path, *saveptr, *cur_comp;
  int err;

  if ( !strncpy_safe(lpath, path, sizeof(lpath)) ) {
    errno = ENOSPC;
    return 0;
  }

  dir_path[0] = '\0';
  if ( lpath[0] == '/' ) {
    dir_path[0] = '/';
    dir_path[1] = '\0';
  }

  for ( cur_path = lpath; cur_comp = strtok_r(cur_path, "/", &saveptr); cur_path = NULL ) {
    size_t dir_sz = strlen(dir_path);
    if ( dir_sz >= sizeof(dir_path) ) {
      errno = ENOSPC;
      return 0;
    }

    strncat(dir_path, cur_comp, sizeof(dir_path) - dir_sz - 1);

    dir_sz = strlen(dir_path);
    if ( dir_sz >= sizeof(dir_path) ) {
      errno = ENOSPC;
      return 0;
    }

    dir_path[dir_sz++] = '/';
    dir_path[dir_sz] = '\0';

    err = mkdir(dir_path, 0755);
    if ( err < 0 && errno != EEXIST )
      return -1;
  }

  return 0;
}

int send_fd(int fd, size_t num, int *fds) {
  if ( num == 0 ) {
    errno = EINVAL;
    return -1;
  } else {
    uint8_t cbuf[CMSG_SPACE(sizeof(int) * num)];
    struct msghdr msg = { 0 };
    struct cmsghdr *cmsg;
    int err;

    msg.msg_iov = NULL;
    msg.msg_iovlen = 0;
    msg.msg_control = cbuf;
    msg.msg_controllen = CMSG_SPACE(sizeof(int) * num);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int) * num);
    memcpy((int *) CMSG_DATA(cmsg), fds, sizeof(*fds) * num);

    err = sendmsg(fd, &msg, 0);
    if ( err < 0 ) return -1;

    return 0;
  }
}

int recv_fd(int fd, size_t num, int *fds) {
  if ( num == 0 ) {
    errno = EINVAL;
    return -1;
  } else {
    int err;
    uint8_t cbuf[CMSG_SPACE(sizeof(int) * num)];
    struct msghdr msg = { 0 };
    struct cmsghdr *cmsg;
    int *returned_fds;

    msg.msg_iov = NULL;
    msg.msg_iovlen = 0;
    msg.msg_control = cbuf;
    msg.msg_controllen = CMSG_SPACE(sizeof(int) * num);

    err = recvmsg(fd, &msg, 0);
    if ( err < 0 ) return -1;

    cmsg = CMSG_FIRSTHDR(&msg);
    if ( !cmsg || cmsg->cmsg_level != SOL_SOCKET ||
         cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len != CMSG_LEN(sizeof(int) * num) ) {
      errno = EPROTO;
      return -1;
    }

    returned_fds = (int *)CMSG_DATA(cmsg);
    memcpy(fds, returned_fds, sizeof(*fds) * num);

    return 0;
  }
}
