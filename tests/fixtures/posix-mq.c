// SPDX-License-Identifier: GPL-3.0-or-later
// Guest ABI coverage complementary to gVisor's mq_test (which never sends).
#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#define CHECK(e)                                                               \
  do {                                                                         \
    if (!(e)) {                                                                \
      fprintf(stderr, "line %d: %s (errno %d)\n", __LINE__, #e, errno);        \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
static void expect_message(mqd_t q, char value, unsigned priority) {
  char buf[8];
  unsigned actual;
  CHECK(mq_receive(q, buf, sizeof(buf), &actual) == 1);
  CHECK(buf[0] == value && actual == priority);
}
int main(void) {
  struct mq_attr at = {.mq_maxmsg = 3, .mq_msgsize = 8}, old;
  const char *name = "/trames-mq-smoke";
  mqd_t q = mq_open(name, O_CREAT | O_EXCL | O_RDWR, 0600, &at);
  CHECK(q >= 0);
  CHECK(fcntl(q, F_GETFD) & FD_CLOEXEC);
  int ep = epoll_create1(0);
  struct epoll_event ev = {.events = EPOLLIN | EPOLLET, .data.u32 = 42}, result;
  CHECK(ep >= 0 && epoll_ctl(ep, EPOLL_CTL_ADD, q, &ev) == 0);
  CHECK(epoll_wait(ep, &result, 1, 0) == 0);
  CHECK(mq_send(q, "a", 1, 1) == 0 && mq_send(q, "b", 1, 8) == 0 &&
        mq_send(q, "c", 1, 8) == 0);
  CHECK(epoll_wait(ep, &result, 1, 0) == 1 && result.data.u32 == 42);
  struct pollfd p = {.fd = q, .events = POLLIN | POLLOUT};
  CHECK(poll(&p, 1, 0) == 1 && p.revents == POLLIN);
  struct timespec past = {0};
  CHECK(mq_timedsend(q, "d", 1, 1, &past) == -1 && errno == ETIMEDOUT);
  CHECK(mq_getattr(q, &old) == 0 && old.mq_curmsgs == 3 &&
        old.mq_msgsize == 8 && old.mq_maxmsg == 3);
  expect_message(q, 'b', 8);
  expect_message(q, 'c', 8);
  expect_message(q, 'a', 1);
  char buf[8];
  CHECK(mq_timedreceive(q, buf, 8, 0, &past) == -1 && errno == ETIMEDOUT);
  int dupfd = dup(q);
  at.mq_flags = O_NONBLOCK;
  CHECK(mq_setattr(dupfd, &at, &old) == 0 && old.mq_flags == 0);
  CHECK(mq_receive(q, buf, 8, 0) == -1 && errno == EAGAIN);
  at.mq_flags = 0;
  CHECK(mq_setattr(q, &at, &old) == 0 && old.mq_flags == O_NONBLOCK);
  CHECK(mq_unlink(name) == 0);
  int replacement =
      mq_open(name, O_CREAT | O_EXCL | O_RDWR | O_NONBLOCK, 0600, &at);
  CHECK(replacement >= 0 && mq_unlink(name) == 0);
  int sync[2];
  CHECK(pipe(sync) == 0);
  int child = fork();
  CHECK(child >= 0);
  if (!child) {
    close(sync[0]);
    CHECK(write(sync[1], "r", 1) == 1);
    expect_message(dupfd, 'z', 3);
    _exit(0);
  }
  close(sync[1]);
  CHECK(read(sync[0], buf, 1) == 1);
  CHECK(mq_send(q, "z", 1, 3) == 0);
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  CHECK(mq_receive(replacement, buf, 8, 0) == -1 && errno == EAGAIN);
  CHECK(mq_send(q, "e", 1, 0) == 0 && epoll_wait(ep, &result, 1, 0) == 1);
  expect_message(q, 'e', 0);
  struct timespec deadline;
  CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
  deadline.tv_nsec += 30000000;
  if (deadline.tv_nsec >= 1000000000) {
    deadline.tv_nsec -= 1000000000;
    deadline.tv_sec++;
  }
  CHECK(mq_timedreceive(q, buf, 8, 0, &deadline) == -1 && errno == ETIMEDOUT);
  CHECK(mq_close(replacement) == 0 && close(dupfd) == 0 && mq_close(q) == 0 &&
        close(ep) == 0);
  struct rlimit limit;
  CHECK(getrlimit(RLIMIT_MSGQUEUE, &limit) == 0);
  // Three 8-byte messages, each charged two 48-byte ARM64 kernel headers.
  limit.rlim_cur = 3 * (8 + 48 + 48);
  CHECK(setrlimit(RLIMIT_MSGQUEUE, &limit) == 0);
  q = mq_open(name, O_CREAT | O_EXCL | O_RDONLY, 0600, &at);
  CHECK(q >= 0 && mq_unlink(name) == 0);
  CHECK(mq_open(name, O_CREAT | O_EXCL | O_RDWR, 0600, &at) == -1 &&
        errno == EMFILE);
  CHECK(mq_close(q) == 0);
  q = mq_open(name, O_CREAT | O_EXCL | O_WRONLY, 0600, &at);
  CHECK(q >= 0 && mq_receive(q, buf, 8, 0) == -1 && errno == EBADF);
  CHECK(mq_unlink(name) == 0 && mq_close(q) == 0);
  puts("PASS POSIX queue traffic, priority, readiness, wakeup, unlink, "
       "deadlines and per-user capacity");
}
