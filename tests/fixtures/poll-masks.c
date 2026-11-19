// SPDX-License-Identifier: GPL-3.0-or-later
// Additional ABI coverage for combinations absent from the upstream poll suite.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <unistd.h>
#define CHECK(e)                                                               \
  do {                                                                         \
    if (!(e)) {                                                                \
      fprintf(stderr, "line %d: %s, errno %d\n", __LINE__, #e, errno);         \
      return 1;                                                                \
    }                                                                          \
  } while (0)
int main(void) {
  const char *path = "/tmp/norm-fifo";
  CHECK(mkfifo(path, 0600) == 0);
  int fd = open(path, O_RDWR | O_NONBLOCK);
  CHECK(fd >= 0 && unlink(path) == 0);
  struct pollfd p = {.fd = fd, .events = POLLRDNORM | POLLWRNORM};
  CHECK(poll(&p, 1, 0) == 1 && p.revents == POLLWRNORM);
  int ep = epoll_create1(0);
  struct epoll_event watch = {.events = EPOLLRDNORM | EPOLLET, .data.u64 = 42},
                     ready;
  CHECK(ep >= 0 && epoll_ctl(ep, EPOLL_CTL_ADD, fd, &watch) == 0);
  CHECK(write(fd, "a", 1) == 1);
  CHECK(poll(&p, 1, 0) == 1 && p.revents == (POLLRDNORM | POLLWRNORM));
  CHECK(epoll_wait(ep, &ready, 1, 0) == 1 && ready.events == EPOLLRDNORM &&
        ready.data.u64 == 42);
  CHECK(epoll_wait(ep, &ready, 1, 0) == 0);
  char c;
  CHECK(read(fd, &c, 1) == 1 && write(fd, "b", 1) == 1);
  CHECK(epoll_wait(ep, &ready, 1, 0) == 1 && ready.events == EPOLLRDNORM);

  CHECK(dup2(fd, 511) == 511);
  struct rlimit l;
  CHECK(getrlimit(RLIMIT_NOFILE, &l) == 0);
  l.rlim_cur = 2;
  CHECK(setrlimit(RLIMIT_NOFILE, &l) == 0);
  fd_set reads, writes, exceptions;
  FD_ZERO(&reads);
  FD_ZERO(&writes);
  FD_ZERO(&exceptions);
  FD_SET(511, &reads);
  FD_SET(511, &writes);
  FD_SET(511, &exceptions);
  struct timeval zero = {0};
  CHECK(select(512, &reads, &writes, &exceptions, &zero) == 2);
  CHECK(FD_ISSET(511, &reads) && FD_ISSET(511, &writes) &&
        !FD_ISSET(511, &exceptions));
  struct pollfd three[3] = {{.fd = 511, .events = POLLIN},
                            {.fd = 511, .events = POLLOUT},
                            {.fd = -1}};
  CHECK(poll(three, 2, 0) == 2);
  CHECK(poll(three, 3, 0) == -1 && errno == EINVAL);
  CHECK(close(511) == 0);
  FD_ZERO(&reads);
  FD_SET(511, &reads);
  CHECK(select(512, &reads, 0, 0, &zero) == -1 && errno == EBADF);
  CHECK(close(ep) == 0 && close(fd) == 0);
  puts("PASS bidirectional FIFO, normal-only epoll edges, high FD and lowered "
       "limit");
  return 0;
}
