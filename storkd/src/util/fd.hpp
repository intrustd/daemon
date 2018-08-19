#ifndef __stork_util_fd_HPP__
#define __stork_util_fd_HPP__

#include <cstdint>
#include <system_error>

std::error_code recv_fd(int fd, std::size_t num, int *fds);
std::error_code send_fd(int fd, std::size_t num, int *fds);

#endif
