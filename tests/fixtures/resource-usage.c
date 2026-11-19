// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/times.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "line %d: %s (errno %d)\n", __LINE__, #expr, errno); return 1; } } while (0)

static long proc_peak(void) {
    char line[128];
    long kb = -1;
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "VmHWM: %ld kB", &kb) == 1) break;
    fclose(f);
    return kb;
}

int main(void) {
    struct rusage before, current, seen, reaped;
    struct tms t;
    siginfo_t si;
    const size_t bytes = 8 * 1024 * 1024;
    CHECK(syscall(SYS_getrusage, 2, &current) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_getrusage, RUSAGE_SELF, (void *)1) == -1 && errno == EFAULT);
    CHECK(syscall(SYS_times, (void *)1) == -1 && errno == EFAULT);
    CHECK(syscall(SYS_times, NULL) >= 0);
    CHECK(getrusage(RUSAGE_THREAD, &current) == 0 && current.ru_maxrss > 0);
    CHECK(getrusage(RUSAGE_CHILDREN, &before) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        unsigned char vec[1];
        void *lazy = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NONBLOCK | MAP_POPULATE, -1, 0);
        CHECK(lazy != MAP_FAILED && mincore(lazy, 4096, vec) == 0 && (vec[0] & 1) == 0);
        void *pages = mmap(NULL, bytes, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
        CHECK(pages != MAP_FAILED && mincore(pages, 4096, vec) == 0 && (vec[0] & 1));
        CHECK(munmap(pages, bytes) == 0);
        CHECK(proc_peak() >= (long)(bytes / 1024));
        CHECK(getrusage(RUSAGE_SELF, &current) == 0 && current.ru_maxrss >= (long)(bytes / 1024));
        clock_t start = clock();
        CHECK(start != (clock_t)-1);
        while (clock() - start < CLOCKS_PER_SEC / 10) { }
        _exit(42);
    }
    for (int i = 0; i < 2; i++) {
        CHECK(syscall(SYS_waitid, P_PID, pid, &si, WEXITED | WNOWAIT, &seen) == 0);
        CHECK(si.si_pid == pid && si.si_status == 42 && seen.ru_maxrss >= (long)(bytes / 1024));
        CHECK(getrusage(RUSAGE_CHILDREN, &current) == 0 && current.ru_maxrss == before.ru_maxrss);
    }
    int status;
    CHECK(wait4(pid, &status, 0, &reaped) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 42);
    CHECK(seen.ru_maxrss == reaped.ru_maxrss);
    CHECK(getrusage(RUSAGE_CHILDREN, &current) == 0 && current.ru_maxrss >= reaped.ru_maxrss);
    CHECK(times(&t) != (clock_t)-1 && t.tms_cutime + t.tms_cstime >= 10);
    CHECK(waitpid(pid, &status, 0) == -1 && errno == ECHILD);
    puts("resource usage ok");
    return 0;
}
