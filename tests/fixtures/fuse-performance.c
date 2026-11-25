// SPDX-License-Identifier: GPL-3.0-or-later
// Identical ordinary Linux client ELF for native and interpreted measurements.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line=%d %s errno=%d\n", __LINE__, #x, errno); exit(1); } } while (0)
static unsigned char input[65536], output[65536];
static uint64_t now(void) {
    struct timespec t;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}
static void ready(const char *path) {
    uint64_t end = now() + 5000000000ULL;
    for (;;) {
        struct statfs fs;
        if (statfs(path, &fs) == 0 && fs.f_type == 0x65735546) return;
        CHECK(now() < end);
        struct timespec delay = {.tv_nsec = 10000000};
        CHECK(nanosleep(&delay, NULL) == 0);
    }
}
static uint64_t read_checked(int fd) {
    uint64_t start = now();
    for (unsigned i = 0; i < 128; ++i) {
        uint64_t marker = i, inverse = ~marker;
        memcpy(input, &marker, sizeof(marker));
        memcpy(input + sizeof(input) - sizeof(inverse), &inverse, sizeof(inverse));
        CHECK(read(fd, output, sizeof(output)) == sizeof(output));
        CHECK(memcmp(input, output, sizeof(input)) == 0);
    }
    CHECK(read(fd, output, 1) == 0);
    return now() - start;
}
static void transfer(const char *base, unsigned sample) {
    char path[1024];
    CHECK(snprintf(path, sizeof(path), "%s/transfer-%d", base, getpid()) < (int)sizeof(path));
    for (size_t i = 0; i < sizeof(input); ++i) input[i] = (unsigned char)(i * 17 + 5);
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(fd >= 0);
    uint64_t start = now();
    for (unsigned i = 0; i < 128; ++i) {
        uint64_t marker = i, inverse = ~marker;
        memcpy(input, &marker, sizeof(marker));
        memcpy(input + sizeof(input) - sizeof(inverse), &inverse, sizeof(inverse));
        CHECK(write(fd, input, sizeof(input)) == sizeof(input));
    }
    uint64_t write_ns = now() - start;
    start = now();
    CHECK(fsync(fd) == 0);
    uint64_t sync_ns = now() - start;
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    uint64_t warm_ns = read_checked(fd);
    CHECK(close(fd) == 0);
    // cache=auto does not set KEEP_CACHE: reopening exercises the cold inode
    // cache as well as the resident reads immediately after buffered writes.
    fd = open(path, O_RDONLY);
    CHECK(fd >= 0);
    uint64_t reopen_ns = read_checked(fd);
    CHECK(close(fd) == 0 && unlink(path) == 0);
    printf("{\"kind\":\"transfer\",\"sample\":%u,\"bytes\":8388608,\"write_ns\":%llu,\"sync_ns\":%llu,\"warm_read_ns\":%llu,\"reopen_read_ns\":%llu}\n",
        sample, (unsigned long long)write_ns, (unsigned long long)sync_ns,
        (unsigned long long)warm_ns, (unsigned long long)reopen_ns);
}
static void ordinary(const char *base, unsigned sample, unsigned scale) {
    char path[1024];
    CHECK(snprintf(path, sizeof(path), "%s/plain-%d", base, getpid()) < (int)sizeof(path));
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(fd >= 0);
    uint64_t start = now(), value = 0x12345678;
    for (unsigned i = 0; i < 200000 * scale; ++i) { value ^= value << 13; value ^= value >> 7; value ^= value << 17; }
    uint64_t cpu_ns = now() - start;
    struct stat fs;
    start = now();
    for (unsigned i = 0; i < 1000 * scale; ++i) {
        CHECK(stat(path, &fs) == 0);
        int other = open(path, O_RDONLY);
        CHECK(other >= 0 && close(other) == 0);
    }
    uint64_t metadata_ns = now() - start;
    memset(input, 0x5a, 4096);
    start = now();
    for (unsigned i = 0; i < 512 * scale; ++i) {
        CHECK(pwrite(fd, input, 4096, 0) == 4096);
        CHECK(pread(fd, output, 4096, 0) == 4096);
        CHECK(memcmp(input, output, 4096) == 0);
    }
    uint64_t file_ns = now() - start;
    int pipes[2];
    CHECK(pipe(pipes) == 0);
    start = now();
    for (unsigned i = 0; i < 512 * scale; ++i) {
        CHECK(write(pipes[1], input, 4096) == 4096);
        CHECK(read(pipes[0], output, 4096) == 4096);
        CHECK(memcmp(input, output, 4096) == 0);
    }
    uint64_t pipe_ns = now() - start;
    CHECK(close(pipes[0]) == 0 && close(pipes[1]) == 0);
    CHECK(close(fd) == 0 && unlink(path) == 0);
    printf("{\"kind\":\"ordinary\",\"sample\":%u,\"pid\":%d,\"cpu_ns\":%llu,\"metadata_ns\":%llu,\"file_ns\":%llu,\"pipe_ns\":%llu,\"checksum\":%llu}\n",
        sample, getpid(), (unsigned long long)cpu_ns, (unsigned long long)metadata_ns,
        (unsigned long long)file_ns, (unsigned long long)pipe_ns, (unsigned long long)value);
}
int main(int argc, char **argv) {
    CHECK(argc >= 3);
    if (!strcmp(argv[1], "ready")) { ready(argv[2]); return 0; }
    CHECK(argc == 4 || argc == 5);
    unsigned scale = argc == 5 ? (unsigned)strtoul(argv[4], NULL, 10) : 1;
    CHECK(scale >= 1 && scale <= 100);
    unsigned sample = (unsigned)strtoul(argv[3], NULL, 10);
    if (!strcmp(argv[1], "transfer")) transfer(argv[2], sample);
    else if (!strcmp(argv[1], "ordinary")) ordinary(argv[2], sample, scale);
    else CHECK(0);
    return 0;
}
