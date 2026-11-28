// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { RECORD = 4096, MAX_WRITERS = 16, MAX_ROUNDS = 100000 };
static void check(int condition, const char *message) {
    if (!condition) { perror(message); exit(1); }
}
static uint64_t number(const char *text, uint64_t maximum) {
    char *end;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 10);
    check(*text && !*end && !errno && value <= maximum, "invalid number");
    return value;
}
static uint64_t now(void) {
    struct timespec time;
    check(clock_gettime(CLOCK_MONOTONIC, &time) == 0, "clock_gettime");
    return (uint64_t)time.tv_sec * 1000000000ULL + (uint64_t)time.tv_nsec;
}
static uint64_t checksum(const unsigned char *record) {
    uint64_t hash = 14695981039346656037ULL;
    for (unsigned i = 0; i < RECORD - 8; ++i) hash = (hash ^ record[i]) * 1099511628211ULL;
    return hash;
}
static void record_bytes(unsigned char *record, uint64_t writer, uint64_t sequence) {
    for (unsigned i = 0; i < RECORD; ++i) record[i] = (unsigned char)(i ^ writer ^ sequence);
    memcpy(record, &writer, 8); memcpy(record + 8, &sequence, 8);
    uint64_t hash = checksum(record); memcpy(record + RECORD - 8, &hash, 8);
}
static void writer(int directory, unsigned id, unsigned rounds, int full) {
    char name[64]; snprintf(name, sizeof(name), "writer-%u.log", id);
    int fd = openat(directory, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    check(fd >= 0, "create writer log");
    // Namespace durability is established before acknowledging any record.
    check(fsync(directory) == 0, "sync created file namespace");
    unsigned char record[RECORD];
    for (unsigned sequence = 1; sequence <= rounds; ++sequence) {
        record_bytes(record, id, sequence);
        uint64_t began = now();
        size_t done = 0;
        while (done < sizeof(record)) {
            ssize_t count = write(fd, record + done, sizeof(record) - done);
            if (count < 0 && errno == EINTR) continue;
            check(count > 0, "write record"); done += (size_t)count;
        }
        check((full ? fsync(fd) : fdatasync(fd)) == 0, "durability barrier");
        uint64_t elapsed = now() - began;
        // The external ledger observes an ACK only after the guest barrier
        // returns. Every acknowledged prefix must survive an abrupt host exit;
        // an incomplete/unacknowledged append is deliberately not promised.
        char line[256];
        int size = snprintf(line, sizeof(line), "{\"writer\":%u,\"sequence\":%u,\"latency_ns\":%llu,\"bytes\":%u,\"sync\":\"%s\"}\n",
                            id, sequence, (unsigned long long)elapsed, RECORD, full ? "full" : "data");
        check(size > 0 && (size_t)size < sizeof(line), "ACK size");
        ssize_t count;
        do { count = write(STDOUT_FILENO, line, (size_t)size); } while (count < 0 && errno == EINTR);
        check(count == size, "publish one complete ACK");
    }
    check(close(fd) == 0, "close writer log");
}
static void verify(int directory, unsigned writer, uint64_t acknowledged) {
    if (!acknowledged) return;
    char name[64]; snprintf(name, sizeof(name), "writer-%u.log", writer);
    int fd = openat(directory, name, O_RDONLY | O_NOFOLLOW);
    check(fd >= 0, "open acknowledged log after recovery");
    unsigned char actual[RECORD], expected[RECORD];
    for (uint64_t sequence = 1; sequence <= acknowledged; ++sequence) {
        size_t done = 0;
        while (done < sizeof(actual)) {
            ssize_t count = read(fd, actual + done, sizeof(actual) - done);
            if (count < 0 && errno == EINTR) continue;
            check(count > 0, "acknowledged prefix missing after recovery"); done += (size_t)count;
        }
        record_bytes(expected, writer, sequence);
        check(memcmp(actual, expected, RECORD) == 0, "acknowledged record differs after recovery");
    }
    check(close(fd) == 0, "close recovered log");
}
int main(int argc, char **argv) {
    check(argc >= 3, "usage: run DIRECTORY WRITERS ROUNDS data|full; verify DIRECTORY WRITER ACKNOWLEDGED");
    if (!strcmp(argv[1], "verify")) {
        check(argc == 5, "verify arguments");
        int directory = open(argv[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        check(directory >= 0, "open recovered directory");
        verify(directory, (unsigned)number(argv[3], MAX_WRITERS - 1), number(argv[4], MAX_ROUNDS));
        close(directory); puts("STORAGE-DURABILITY-VERIFIED"); return 0;
    }
    check(!strcmp(argv[1], "run") && argc == 6, "run arguments");
    unsigned writers = (unsigned)number(argv[3], MAX_WRITERS);
    unsigned rounds = (unsigned)number(argv[4], MAX_ROUNDS);
    check(writers && rounds, "nonzero workload");
    int full = !strcmp(argv[5], "full");
    check(full || !strcmp(argv[5], "data"), "unknown durability policy");
    check(mkdir(argv[2], 0700) == 0, "create fresh workload directory");
    int directory = open(argv[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    check(directory >= 0, "open fresh directory");
    // The workload parent is a disposable pre-created guest directory.
    int parent = openat(directory, "..", O_RDONLY | O_DIRECTORY);
    check(parent >= 0 && fsync(parent) == 0, "sync workload directory namespace"); close(parent);
    pid_t children[MAX_WRITERS];
    for (unsigned id = 0; id < writers; ++id) {
        children[id] = fork(); check(children[id] >= 0, "fork writer");
        if (!children[id]) { writer(directory, id, rounds, full); _exit(0); }
    }
    for (unsigned id = 0; id < writers; ++id) {
        int status;
        check(waitpid(children[id], &status, 0) == children[id] && WIFEXITED(status) && WEXITSTATUS(status) == 0, "writer completion");
        verify(directory, id, rounds);
    }
    close(directory); puts("STORAGE-DURABILITY-DONE"); return 0;
}
