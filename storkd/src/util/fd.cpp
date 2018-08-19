#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "fd.hpp"

std::error_code send_fd(int fd, std::size_t num, int *fds) {
  if ( num == 0 )
    return std::make_error_code(std::errc::invalid_argument);
  else {
    std::uint8_t cbuf[CMSG_SPACE(sizeof(int) * num)];
    struct msghdr msg = { 0 };
    msg.msg_iov = nullptr;
    msg.msg_iovlen = 0;
    msg.msg_control = cbuf;
    msg.msg_controllen = CMSG_SPACE(sizeof(int) * num);

    struct cmsghdr *cmsg(CMSG_FIRSTHDR(&msg));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int) * num);
    std::copy(fds, fds + num, (int *) CMSG_DATA(cmsg));

    int err(sendmsg(fd, &msg, 0));
    if ( err < 0 ) {
      return std::error_code(errno, std::generic_category());
    }

    return std::error_code();
  }
}

std::error_code recv_fd(int fd, std::size_t num, int *fds) {
  if ( num == 0 ) {
    return std::make_error_code(std::errc::invalid_argument);
  } else {
    std::uint8_t cbuf[CMSG_SPACE(sizeof(int) * num)];
    struct msghdr msg = { 0 };
    msg.msg_iov = nullptr;
    msg.msg_iovlen = 0;
    msg.msg_control = cbuf;
    msg.msg_controllen = CMSG_SPACE(sizeof(int) * num);

    int err(recvmsg(fd, &msg, 0));
    if ( err < 0 ) {
      return std::error_code(errno, std::generic_category());
    }

    struct cmsghdr *cmsg(CMSG_FIRSTHDR(&msg));
    if ( !cmsg || cmsg->cmsg_level != SOL_SOCKET ||
         cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len != CMSG_LEN(sizeof(int) * num) ) {
      return std::make_error_code(std::errc::protocol_error);
    }

    int *returned_fds((int *)CMSG_DATA(cmsg));
    std::copy(returned_fds, returned_fds + num, fds);

    return std::error_code();
  }
}
