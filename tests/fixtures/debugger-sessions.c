// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <elf.h>
#include <grp.h>
#include <linux/capability.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static int running;
static volatile sig_atomic_t released;
static unsigned checkpoints;
volatile uint64_t debugger_value = 17;
volatile uint64_t debugger_register_value;
static void check(int okay, const char *what) {
    if (!okay) { perror(what); exit(1); }
}
static void release_handler(int signo) { (void)signo; released = 1; }
__attribute__((noinline)) void debugger_checkpoint(unsigned thread) {
    __atomic_add_fetch(&checkpoints, 1, __ATOMIC_RELAXED);
    __asm__ volatile("" : : "r"(thread) : "memory");
}
#if defined(__aarch64__)
extern void debugger_register_checkpoint(volatile uint64_t *);
__asm__(".text\n.align 2\n.global debugger_register_checkpoint\n"
        ".type debugger_register_checkpoint,%function\n"
        "debugger_register_checkpoint:\n stp x19,x30,[sp,#-16]!\n mov x19,#17\n"
        ".global debugger_register_store\n debugger_register_store:\n str x19,[x0]\n"
        " ldp x19,x30,[sp],#16\n ret\n"
        ".size debugger_register_checkpoint,.-debugger_register_checkpoint\n");
#else
static void debugger_register_checkpoint(volatile uint64_t *out) { *out = 17; }
#endif
static void *worker(void *argument) {
    check(pthread_mutex_lock(&lock) == 0, "worker lock");
    while (!running) check(pthread_cond_wait(&condition, &lock) == 0, "worker wait");
    check(pthread_mutex_unlock(&lock) == 0, "worker unlock");
    debugger_checkpoint((unsigned)(uintptr_t)argument);
    return NULL;
}
static void create_threads(pthread_t *threads, unsigned count) {
    for (unsigned i = 0; i < count; ++i)
        check(pthread_create(&threads[i], NULL, worker, (void *)(uintptr_t)(i + 1)) == 0, "pthread_create");
}
static void unprivileged(void) {
    if (geteuid() == 0) {
        check(setgroups(0, NULL) == 0, "setgroups");
        check(setgid(1000) == 0 && setuid(1000) == 0, "setuid");
    }
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0}, {0}};
    check(syscall(SYS_capset, &header, caps) == 0, "clear capabilities");
}
static void *sibling_ptracer(void *argument) {
    pid_t pid = *(pid_t *)argument;
    unsigned long registers[34];
    struct iovec iov = {registers, sizeof(registers)};
    errno = 0;
    check(ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) == -1 && errno == ESRCH, "sibling GETREGSET must fail ESRCH");
    errno = 0;
    check(ptrace(PTRACE_PEEKDATA, pid, &debugger_value, NULL) == -1 && errno == ESRCH, "sibling PEEKDATA must fail ESRCH");
    errno = 0;
    check(ptrace(PTRACE_CONT, pid, NULL, NULL) == -1 && errno == ESRCH, "sibling CONT must fail ESRCH");
    return NULL;
}
static int ptrace_ownership(void) {
    pid_t child = fork(); check(child >= 0, "ownership fork");
    if (!child) { for (;;) pause(); }
    check(ptrace(PTRACE_ATTACH, child, NULL, NULL) == 0, "owner attach");
    int status;
    check(waitpid(child, &status, __WALL) == child && WIFSTOPPED(status), "owner stop");
    pthread_t sibling;
    check(pthread_create(&sibling, NULL, sibling_ptracer, &child) == 0, "ptracer sibling");
    check(pthread_join(sibling, NULL) == 0, "ptracer join");
    errno = 0;
    check(ptrace(PTRACE_PEEKDATA, child, &debugger_value, NULL) == 17 && errno == 0, "original owner reads original mm");
    check(ptrace(PTRACE_DETACH, child, NULL, NULL) == 0, "owner detach");
    check(kill(child, SIGKILL) == 0, "ownership cleanup");
    check(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL, "ownership reap");
    puts("DEBUGGER-OWNERSHIP-PASSED");
    return 0;
}
static void *exec_thread(void *argument) {
    char *path = argument;
    execl(path, path, "exec-child", NULL);
    _exit(127);
}
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(35);
    check(argc >= 2, "missing mode");
    if (!strcmp(argv[1], "exec-unprivileged")) {
        check(argc > 2, "missing command"); unprivileged();
        execvp(argv[2], argv + 2); perror("execvp"); return 1;
    }
    if (!strcmp(argv[1], "ptrace-ownership")) return ptrace_ownership();
    if (!strcmp(argv[1], "exec-child")) { puts("DEBUGGER-EXEC-CHILD"); return 42; }
    if (!strcmp(argv[1], "thread-exec")) {
        pthread_t thread;
        check(pthread_create(&thread, NULL, exec_thread, argv[0]) == 0, "exec thread");
        for (;;) pause();
    }
    if (!strcmp(argv[1], "fork-exec")) {
        pid_t pid = fork(); check(pid >= 0, "fork");
        if (!pid) { execl(argv[0], argv[0], "exec-child", NULL); _exit(127); }
        int status;
        check(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 42, "exec child status");
        puts("DEBUGGER-FORK-EXEC-DONE"); return 0;
    }
    int denied = !strcmp(argv[1], "denied");
    int dynamic = !strcmp(argv[1], "dynamic");
    int launch = !strcmp(argv[1], "launch");
    int early = !strcmp(argv[1], "early-exit");
    check(denied || dynamic || launch || early || !strcmp(argv[1], "live"), "unknown mode");
    if (denied) { unprivileged(); check(prctl(PR_SET_DUMPABLE, 0) == 0, "nondumpable"); }
    struct sigaction action = {.sa_handler = release_handler};
    sigemptyset(&action.sa_mask);
    check(sigaction(SIGUSR1, &action, NULL) == 0, "sigaction");
    sigset_t blocked, previous;
    sigemptyset(&blocked); sigaddset(&blocked, SIGUSR1);
    check(pthread_sigmask(SIG_BLOCK, &blocked, &previous) == 0, "block release signal");
    unsigned count = argc > 2 ? (unsigned)strtoul(argv[2], NULL, 10) : 2;
    uint64_t expected = argc > 3 ? strtoull(argv[3], NULL, 10) : 17;
    uint64_t expected_register = argc > 4 ? strtoull(argv[4], NULL, 10) : 17;
    check(count <= 16, "thread bound");
    pthread_t threads[16];
    if (!dynamic) create_threads(threads, count);
    printf("DEBUGGER-READY %ld %u\n", (long)getpid(), dynamic ? 1 : count + 1);
    sigdelset(&previous, SIGUSR1);
    if (launch) released = 1;
    while (!released) sigsuspend(&previous);
    if (early) { puts("DEBUGGER-EARLY-EXIT"); return 23; }
    if (dynamic) create_threads(threads, count);
    check(pthread_mutex_lock(&lock) == 0, "main lock"); running = 1;
    check(pthread_cond_broadcast(&condition) == 0, "broadcast");
    check(pthread_mutex_unlock(&lock) == 0, "main unlock");
    debugger_checkpoint(0);
    debugger_register_checkpoint(&debugger_register_value);
    for (unsigned i = 0; i < count; ++i) check(pthread_join(threads[i], NULL) == 0, "pthread_join");
    check(__atomic_load_n(&checkpoints, __ATOMIC_RELAXED) == count + 1, "checkpoint count");
    check(debugger_value == expected, "original process observed debugger memory write");
    check(debugger_register_value == expected_register, "original CPU executed debugger register write");
    printf("DEBUGGER-DONE %u %llu %llu\n", checkpoints, (unsigned long long)debugger_value, (unsigned long long)debugger_register_value);
    return 0;
}
