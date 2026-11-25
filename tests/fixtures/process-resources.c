// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/keyctl.h>
#include <linux/sched.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static void check(int ok, const char *what) {
    if (!ok) { perror(what); exit(1); }
}
static long keyctl(unsigned long op, long key, unsigned long a, unsigned long b) {
    return syscall(SYS_keyctl, op, key, a, b, 0);
}
static void keyrings(void) {
    long ring = keyctl(KEYCTL_JOIN_SESSION_KEYRING, 0, 0, 0);
    check(ring > 0, "join private session");
    long user = keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_USER_KEYRING, 1, 0);
    check(user > 0 && user != ring, "user keyring");
    check(keyctl(KEYCTL_LINK, user, ring, 0) == 0, "link user keyring");
    int32_t member = 0;
    check(keyctl(KEYCTL_READ, ring, (uintptr_t)&member, sizeof(member)) == 4 && member == user, "read membership");
    unsigned char byte = 0;
    errno = 0;
    check(keyctl(KEYCTL_READ, ring, (uintptr_t)&byte, 1) == -1 && errno == EINVAL, "unaligned read size");
    check(keyctl(KEYCTL_READ, ring, 0, 1) == 4, "null size query ignores capacity");
    check(keyctl(KEYCTL_READ, ring, 1, 0) == 4, "zero capacity ignores pointer");
    byte = 0;
    check(keyctl(KEYCTL_DESCRIBE, ring, (uintptr_t)&byte, 1) > 1 && byte == 0, "short description leaves buffer unchanged");
    long user_session = keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_USER_SESSION_KEYRING, 1, 0);
    check(user_session > 0 && keyctl(KEYCTL_LINK, user_session, ring, 0) == 0, "link second member");
    member = -1;
    check(keyctl(KEYCTL_READ, ring, (uintptr_t)&member, 4) == 8 && member == -1, "aligned short read leaves buffer unchanged");
    check(keyctl(KEYCTL_UNLINK, user_session, ring, 0) == 0, "unlink second member");
    unsigned char large[4097]; memset(large, 0, sizeof(large));
    check(keyctl(KEYCTL_READ, ring, (uintptr_t)large, sizeof(large)) == 4 && !memcmp(large, &user, 4), "large read uses actual payload length");
    errno = 0;
    check(keyctl(KEYCTL_LINK, ring, ring, 0) == -1 && errno == EDEADLK, "self cycle");
    int gate[2]; check(pipe(gate) == 0, "pipe");
    pid_t child = fork(); check(child >= 0, "fork keyring");
    if (child == 0) {
        close(gate[1]);
        char ack; check(read(gate[0], &ack, 1) == 1, "fork gate");
        check(keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING, 0, 0) == ring, "inherited session");
        check(keyctl(KEYCTL_READ, ring, 0, 0) == 0, "shared unlink");
        _exit(0);
    }
    close(gate[0]);
    check(keyctl(KEYCTL_UNLINK, user, ring, 0) == 0, "unlink");
    check(write(gate[1], "x", 1) == 1, "release child"); close(gate[1]);
    int status; check(waitpid(child, &status, 0) == child && status == 0, "wait keyring");
    errno = 0;
    check(keyctl(KEYCTL_UNLINK, user, ring, 0) == -1 && errno == ENOENT, "absent membership");
    check(keyctl(KEYCTL_LINK, user, ring, 0) == 0 && keyctl(KEYCTL_CLEAR, ring, 0, 0) == 0, "clear");
    check(keyctl(KEYCTL_READ, ring, 0, 0) == 0, "empty after clear");
    puts("keyrings: ok");
}
static void fdinfo(int fd, int expected) {
    char data[4096], pid[64];
    check(lseek(fd, 0, SEEK_SET) == 0, "rewind fdinfo");
    ssize_t n = read(fd, data, sizeof(data)-1); check(n > 0, "read fdinfo"); data[n] = 0;
    snprintf(pid, sizeof(pid), "Pid:\t%d\n", expected);
    check(strstr(data, pid) && strstr(data, "NSpid:\t"), "original pidfd identity");
}
static void pidfds(int clone_pidfd) {
    int gate[2], handle = -1; check(pipe(gate) == 0, "pipe");
    struct clone_args args = {.flags = CLONE_PIDFD, .pidfd = (uintptr_t)&handle, .exit_signal = SIGCHLD};
    pid_t child = clone_pidfd ? syscall(SYS_clone3, &args, sizeof(args)) : fork();
    check(child >= 0, "create child");
    if (child == 0) { close(gate[1]); char ack; check(read(gate[0], &ack, 1) == 1, "child gate"); _exit(0); }
    close(gate[0]);
    if (!clone_pidfd) handle = syscall(SYS_pidfd_open, child, 0);
    check(handle >= 0, "pidfd");
    char path[64]; snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", handle);
    int info = open(path, O_RDONLY); check(info >= 0, "open fdinfo"); fdinfo(info, child);
    struct pollfd pollfd = {.fd = handle, .events = POLLIN};
    check(poll(&pollfd, 1, 0) == 0, "live pidfd readiness");
    check(write(gate[1], "x", 1) == 1, "release child"); close(gate[1]);
    int status; check(waitpid(child, &status, 0) == child && status == 0, "wait child");
    fdinfo(info, -1);
    check(poll(&pollfd, 1, 0) == 1 && (pollfd.revents & (POLLIN | POLLHUP)) == (POLLIN | POLLHUP), "reaped pidfd readiness");
    close(info); close(handle);
    puts(clone_pidfd ? "clone-pidfd: ok" : "pidfd: ok");
}
int main(int argc, char **argv) {
    check(argc == 2, "one mode required");
    if (!strcmp(argv[1], "keyrings")) keyrings();
    else if (!strcmp(argv[1], "pidfd")) pidfds(0);
    else if (!strcmp(argv[1], "clone-pidfd")) pidfds(1);
    else return 2;
    return 0;
}
