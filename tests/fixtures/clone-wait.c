// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <linux/sched.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "line %d: %s (errno %d)\n", __LINE__, #expr, errno); return 1; } } while (0)

// With a private VM and a null stack, this is the fork-like clone ABI.
static pid_t spawn(int flags) {
    return syscall(SYS_clone, flags, 0, 0, 0, 0);
}

static int wait_signal(int signo, pid_t pid) {
    sigset_t set;
    siginfo_t info;
    struct timespec timeout = {5, 0};
    sigemptyset(&set);
    sigaddset(&set, signo);
    return sigtimedwait(&set, &info, &timeout) == signo && info.si_pid == pid;
}

static int reap(pid_t pid, int flags, int code) {
    int status = -1;
    return waitpid(pid, &status, flags) == pid && WIFEXITED(status) && WEXITSTATUS(status) == code;
}

static void *orphan_zombie(void *arg) {
    pid_t child = spawn(0);
    if (child == 0) _exit(27);
    siginfo_t si = {0};
    if (child < 0 || waitid(P_PID, child, &si, WEXITED | WNOWAIT | __WCLONE | __WNOTHREAD) < 0)
        return (void *)(intptr_t)-1;
    return (void *)(intptr_t)child;
}

int main(int argc, char **argv) {
    if (argc == 3) {
        pid_t child = atoi(argv[1]);
        CHECK(write(atoi(argv[2]), "x", 1) == 1);
        CHECK(wait_signal(SIGCHLD, child));
        CHECK(reap(child, __WCLONE, 31));
        puts("clone wait lifecycle ok");
        return 0;
    }
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGCHLD);
    sigaddset(&blocked, SIGUSR1);
    CHECK(sigprocmask(SIG_BLOCK, &blocked, NULL) == 0);
    pid_t pid = spawn(SIGUSR1);
    if (pid == 0) _exit(21);
    CHECK(pid > 0 && wait_signal(SIGUSR1, pid));
    CHECK(reap(pid, __WCLONE, 21));

    CHECK(signal(SIGCHLD, SIG_IGN) != SIG_ERR);
    struct clone_args args = { .exit_signal = 65 };
    CHECK(syscall(SYS_clone3, &args, sizeof(args)) == -1 && errno == EINVAL);
    args.exit_signal = 0;
    pid = syscall(SYS_clone3, &args, sizeof(args));
    if (pid == 0) _exit(22);
    CHECK(pid > 0 && reap(pid, __WCLONE, 22));
    CHECK(signal(SIGCHLD, SIG_DFL) != SIG_ERR);

    pid = spawn(0);
    if (pid == 0) { execl("/bin/sh", "sh", "-c", "exit 23", (char *)NULL); _exit(127); }
    CHECK(pid > 0 && wait_signal(SIGCHLD, pid));
    CHECK(reap(pid, 0, 23));

    int pipefd[2];
    CHECK(pipe(pipefd) == 0);
    pid = spawn(0);
    if (pid == 0) {
        pid_t sibling = spawn(CLONE_PARENT | SIGCHLD);
        if (sibling == 0) _exit(25);
        if (sibling < 0 || write(pipefd[1], &sibling, sizeof(sibling)) != sizeof(sibling)) _exit(1);
        _exit(24);
    }
    pid_t sibling;
    CHECK(pid > 0 && reap(pid, __WCLONE, 24));
    CHECK(read(pipefd[0], &sibling, sizeof(sibling)) == sizeof(sibling));
    CHECK(waitpid(sibling, NULL, WNOHANG) == -1 && errno == ECHILD);
    CHECK(reap(sibling, __WCLONE | __WNOTHREAD, 25));

    pthread_t thread;
    void *zombie;
    CHECK(pthread_create(&thread, NULL, orphan_zombie, NULL) == 0);
    CHECK(pthread_join(thread, &zombie) == 0 && (intptr_t)zombie > 0);
    CHECK(reap((intptr_t)zombie, __WNOTHREAD | __WCLONE, 27));

    // Adoption by a subreaper restores the ordinary SIGCHLD wait class.
    int child_gate[2];
    CHECK(pipe(child_gate) == 0 && prctl(PR_SET_CHILD_SUBREAPER, 1) == 0);
    pid = fork();
    if (pid == 0) {
        pid_t orphan = spawn(0);
        if (orphan == 0) {
            char byte;
            _exit(read(child_gate[0], &byte, 1) == 1 ? 29 : 1);
        }
        if (orphan < 0 || write(pipefd[1], &orphan, sizeof(orphan)) != sizeof(orphan)) _exit(1);
        _exit(28);
    }
    CHECK(pid > 0 && wait_signal(SIGCHLD, pid) && reap(pid, 0, 28));
    pid_t orphan;
    CHECK(read(pipefd[0], &orphan, sizeof(orphan)) == sizeof(orphan));
    CHECK(write(child_gate[1], "x", 1) == 1 && wait_signal(SIGCHLD, orphan));
    CHECK(waitpid(orphan, NULL, __WCLONE | WNOHANG) == -1 && errno == ECHILD);
    CHECK(reap(orphan, __WNOTHREAD, 29));

    // Parent exec changes the signal delivered, but preserves the wait class.
    pid = spawn(SIGUSR1);
    if (pid == 0) {
        char byte;
        _exit(read(pipefd[0], &byte, 1) == 1 ? 31 : 127);
    }
    CHECK(pid > 0);
    char id[32], fd[32];
    snprintf(id, sizeof(id), "%d", pid);
    snprintf(fd, sizeof(fd), "%d", pipefd[1]);
    execl(argv[0], argv[0], id, fd, (char *)NULL);
    return 1;
}
