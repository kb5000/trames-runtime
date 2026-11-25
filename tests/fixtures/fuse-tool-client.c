// SPDX-License-Identifier: GPL-3.0-or-later
// Ordinary Linux clients for an unmodified libfuse filesystem. No FUSE protocol
// is implemented here; run the identical ELF on native Linux and the guest.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/aio_abi.h>
#include <linux/io_uring.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/sysmacros.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/utsname.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "case=%s line=%d %s errno=%d\n", scenario, __LINE__, #x, errno); \
    exit(1); } } while (0)
static const char *scenario = "arguments";
static char path[1024];
static unsigned char block[65536], received[65536];

static uint64_t now(void) {
    struct timespec t;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}
static int new_file(const char *base, const char *name, size_t size) {
    CHECK(snprintf(path, sizeof(path), "%s/%s", base, name) < (int)sizeof(path));
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(fd >= 0);
    CHECK(ftruncate(fd, (off_t)size) == 0);
    return fd;
}
static void finish(int fd) {
    CHECK(close(fd) == 0);
    CHECK(unlink(path) == 0);
}
static void ready(const char *mountpoint) {
    uint64_t end = now() + 5000000000ULL;
    for (;;) {
        struct statfs fs;
        if (statfs(mountpoint, &fs) == 0 && fs.f_type == 0x65735546) return;
        CHECK(now() < end);
        struct timespec pause = {.tv_nsec = 10000000};
        CHECK(nanosleep(&pause, NULL) == 0);
    }
}
static void mapping(const char *base) {
    int fd = new_file(base, "mapped", 8192);
    memset(block, 'a', 8192);
    CHECK(pwrite(fd, block, 8192, 0) == 8192);
    unsigned char *shared = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(shared != MAP_FAILED);
    CHECK(shared[0] == 'a' && shared[4096] == 'a');
    shared[31] = 'b'; shared[4097] = 'c';
    CHECK(msync(shared, 8192, MS_SYNC) == 0);
    CHECK(pread(fd, received, 8192, 0) == 8192);
    CHECK(received[31] == 'b' && received[4097] == 'c');
    unsigned char *private = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    CHECK(private != MAP_FAILED && private[31] == 'b');
    private[31] = 'z';
    CHECK(msync(private, 8192, MS_SYNC) == 0);
    CHECK(pread(fd, received, 1, 31) == 1 && received[0] == 'b');
    CHECK(munmap(private, 8192) == 0);
    CHECK(ftruncate(fd, 4096) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) { volatile unsigned char byte = shared[4096]; (void)byte; _exit(99); }
    int status;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGBUS);
    CHECK(close(fd) == 0);
    CHECK(unlink(path) == 0);
    shared[63] = 'd';
    CHECK(msync(shared, 4096, MS_SYNC) == 0 && shared[63] == 'd');
    CHECK(munmap(shared, 8192) == 0);
    errno = 0;
    CHECK(access(path, F_OK) == -1 && errno == ENOENT);
}
static void copyout(const char *base) {
    int fd = new_file(base, "pipe-pages", 8192);
    unsigned char *pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(pages != MAP_FAILED);
    int pipefd[2];
    CHECK(pipe2(pipefd, O_NONBLOCK) == 0);
    const char bytes[] = "retained-prefix!";
    CHECK(write(pipefd[1], bytes, 16) == 16);
    CHECK(read(pipefd[0], pages + 4096 - 8, 16) == 16);
    CHECK(memcmp(pages + 4096 - 8, bytes, 16) == 0);
    errno = 0;
    CHECK(read(pipefd[0], received, 1) == -1 && errno == EAGAIN);
    CHECK(close(pipefd[0]) == 0 && close(pipefd[1]) == 0);
    CHECK(msync(pages, 8192, MS_SYNC) == 0);
    CHECK(munmap(pages, 8192) == 0);
    CHECK(pread(fd, received, 16, 4096 - 8) == 16 && memcmp(received, bytes, 16) == 0);
    finish(fd);
}
static void metadata(const char *base) {
    int fd = new_file(base, "metadata-pages", 16384);
    unsigned char *pages = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(pages != MAP_FAILED);
    struct stat *st = (void *)(pages + 4096 - 64);
    CHECK(fstat(fd, st) == 0 && st->st_size == 16384);
    int pipefd[2];
    CHECK(pipe(pipefd) == 0 && write(pipefd[1], "data", 4) == 4);
    void *available = pages + 8192 - 2;
    int count;
    CHECK(ioctl(pipefd[0], FIONREAD, available) == 0);
    memcpy(&count, available, sizeof(count));
    CHECK(count == 4);
    CHECK(close(pipefd[0]) == 0 && close(pipefd[1]) == 0);
    int timer = timerfd_create(CLOCK_MONOTONIC, 0);
    CHECK(timer >= 0);
    struct itimerspec spec = {.it_interval.tv_sec = 10, .it_value.tv_sec = 3600};
    CHECK(timerfd_settime(timer, 0, &spec, NULL) == 0);
    struct itimerspec *old = (void *)(pages + 12288 - 16);
    CHECK(timerfd_gettime(timer, old) == 0);
    CHECK(old->it_interval.tv_sec == 10 && old->it_value.tv_sec >= 3590);
    CHECK(close(timer) == 0);
    struct utsname *uts = (void *)(pages + 4096 - 100);
    CHECK(uname(uts) == 0 && strcmp(uts->sysname, "Linux") == 0);
    CHECK(msync(pages, 16384, MS_SYNC) == 0);
    CHECK(munmap(pages, 16384) == 0);
    finish(fd);
}
static void special(const char *base) {
    CHECK(snprintf(path, sizeof(path), "%s/local-fifo", base) < (int)sizeof(path));
    CHECK(mkfifo(path, 0600) == 0);
    struct stat st;
    CHECK(stat(path, &st) == 0 && S_ISFIFO(st.st_mode));
    errno = 0;
    CHECK(open(path, O_WRONLY | O_NONBLOCK) == -1 && errno == ENXIO);
    int reader = open(path, O_RDONLY | O_NONBLOCK);
    CHECK(reader >= 0);
    int writer = open(path, O_WRONLY | O_NONBLOCK);
    CHECK(writer >= 0);
    CHECK(write(writer, "fifo", 4) == 4 && read(reader, received, 4) == 4);
    CHECK(!memcmp(received, "fifo", 4));
    errno = 0;
    CHECK(lseek(reader, 0, SEEK_SET) == -1 && errno == ESPIPE);
    CHECK(unlink(path) == 0);
    CHECK(write(writer, "kept", 4) == 4 && read(reader, received, 4) == 4);
    CHECK(!memcmp(received, "kept", 4));
    CHECK(close(writer) == 0 && read(reader, received, 1) == 0 && close(reader) == 0);

    CHECK(snprintf(path, sizeof(path), "%s/local-null", base) < (int)sizeof(path));
    CHECK(mknod(path, S_IFCHR | 0600, makedev(1, 3)) == 0);
    CHECK(stat(path, &st) == 0 && S_ISCHR(st.st_mode) && st.st_rdev == makedev(1, 3));
    struct statfs fs;
    CHECK(statfs(base, &fs) == 0);
    errno = 0;
    int null = open(path, O_RDWR);
    if (fs.f_flags & MS_NODEV) CHECK(null == -1 && errno == EACCES);
    else {
        CHECK(null >= 0 && read(null, received, 1) == 0);
        CHECK(write(null, "discard", 7) == 7 && close(null) == 0);
    }
    CHECK(unlink(path) == 0);

    struct sockaddr_un address = {.sun_family = AF_UNIX};
    CHECK(snprintf(address.sun_path, sizeof(address.sun_path), "%s/local-socket", base) < (int)sizeof(address.sun_path));
    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(listener >= 0 && bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
    CHECK(stat(address.sun_path, &st) == 0 && S_ISSOCK(st.st_mode));
    CHECK(listen(listener, 1) == 0);
    int client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(client >= 0 && connect(client, (struct sockaddr *)&address, sizeof(address)) == 0);
    int peer = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    CHECK(peer >= 0 && write(client, "unix", 4) == 4 && read(peer, received, 4) == 4);
    CHECK(!memcmp(received, "unix", 4));
    errno = 0;
    CHECK(umount("/work/view") == -1 && errno == EBUSY);
    CHECK(unlink(address.sun_path) == 0);
    CHECK(close(peer) == 0 && close(client) == 0 && close(listener) == 0);

    CHECK(snprintf(path, sizeof(path), "%s/socket-escape", base) < (int)sizeof(path));
    CHECK(symlink("/work/source", path) == 0);
    CHECK(snprintf(address.sun_path, sizeof(address.sun_path), "%s/socket-escape/escaped-socket", base) < (int)sizeof(address.sun_path));
    listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(listener >= 0 && client >= 0 && bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
    CHECK(stat("/work/source/escaped-socket", &st) == 0 && S_ISSOCK(st.st_mode));
    CHECK(listen(listener, 1) == 0 && connect(client, (struct sockaddr *)&address, sizeof(address)) == 0);
    peer = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    CHECK(peer >= 0 && close(peer) == 0 && close(client) == 0 && close(listener) == 0);
    CHECK(unlink("/work/source/escaped-socket") == 0 && unlink(path) == 0);

    CHECK(snprintf(address.sun_path, sizeof(address.sun_path), "%s/local-datagram", base) < (int)sizeof(address.sun_path));
    int receiver = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int sender = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    CHECK(receiver >= 0 && sender >= 0);
    CHECK(bind(receiver, (struct sockaddr *)&address, sizeof(address)) == 0);
    CHECK(sendto(sender, "sendto", 6, 0, (struct sockaddr *)&address, sizeof(address)) == 6);
    CHECK(recv(receiver, received, sizeof(received), 0) == 6 && !memcmp(received, "sendto", 6));
    struct iovec vector = {.iov_base = "sendmsg", .iov_len = 7};
    struct mmsghdr messages[2] = {
        {.msg_hdr = {.msg_name = &address, .msg_namelen = sizeof(address), .msg_iov = &vector, .msg_iovlen = 1}},
        {.msg_hdr = {.msg_name = &address, .msg_namelen = sizeof(address), .msg_iov = &vector, .msg_iovlen = 1}}
    };
    CHECK(sendmsg(sender, &messages[0].msg_hdr, 0) == 7);
    CHECK(recv(receiver, received, sizeof(received), 0) == 7 && !memcmp(received, "sendmsg", 7));
    CHECK(sendmmsg(sender, messages, 2, 0) == 2 && messages[0].msg_len == 7 && messages[1].msg_len == 7);
    CHECK(recv(receiver, received, sizeof(received), 0) == 7 && !memcmp(received, "sendmsg", 7));
    CHECK(recv(receiver, received, sizeof(received), 0) == 7 && !memcmp(received, "sendmsg", 7));
    CHECK(connect(sender, (struct sockaddr *)&address, sizeof(address)) == 0);
    CHECK(unlink(address.sun_path) == 0);
    CHECK(send(sender, "retained", 8, 0) == 8);
    CHECK(recv(receiver, received, sizeof(received), 0) == 8 && !memcmp(received, "retained", 8));
    CHECK(close(sender) == 0 && close(receiver) == 0);
}
static void aio_copy(const char *base) {
    int source = new_file(base, "aio-source", 16);
    CHECK(write(source, "original-result!", 16) == 16);
    int output = new_file(base, "aio-pages", 8192);
    unsigned char *pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, output, 0);
    CHECK(pages != MAP_FAILED);
    aio_context_t context = 0;
    CHECK(syscall(SYS_io_setup, 4, &context) == 0);
    struct iocb request = {.aio_data = 713, .aio_lio_opcode = IOCB_CMD_PREAD,
        .aio_fildes = (uint32_t)source, .aio_buf = (uintptr_t)(pages + 4096 - 4),
        .aio_nbytes = 16};
    struct iocb *requests[] = {&request};
    CHECK(syscall(SYS_io_submit, context, 1, requests) == 1);
    struct io_event event;
    struct timespec timeout = {.tv_sec = 5};
    CHECK(syscall(SYS_io_getevents, context, 1, 1, &event, &timeout) == 1);
    CHECK(event.data == 713 && event.res == 16 && event.res2 == 0);
    CHECK(memcmp(pages + 4096 - 4, "original-result!", 16) == 0);
    CHECK(syscall(SYS_io_destroy, context) == 0);
    CHECK(msync(pages, 8192, MS_SYNC) == 0);
    CHECK(munmap(pages, 8192) == 0);
    finish(output);
    CHECK(close(source) == 0);
    CHECK(snprintf(path, sizeof(path), "%s/aio-source", base) < (int)sizeof(path));
    CHECK(unlink(path) == 0);
}
static void transfer(const char *base) {
    int fd = new_file(base, "throughput", 0);
    for (size_t i = 0; i < sizeof(block); ++i) block[i] = (unsigned char)(i * 17 + 5);
    const unsigned count = 128;
    uint64_t start = now();
    for (unsigned i = 0; i < count; ++i) CHECK(write(fd, block, sizeof(block)) == sizeof(block));
    CHECK(fsync(fd) == 0);
    uint64_t written = now() - start;
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    start = now();
    for (unsigned i = 0; i < count; ++i) {
        CHECK(read(fd, received, sizeof(received)) == sizeof(received));
        CHECK(memcmp(block, received, sizeof(block)) == 0);
    }
    uint64_t read = now() - start;
    printf("transfer bytes=%zu write_sync_ns=%llu read_verify_ns=%llu\n",
        sizeof(block) * count, (unsigned long long)written, (unsigned long long)read);
    finish(fd);
}
static void copy_io(const char *base) {
    int source = new_file(base, "copy-source", 16384);
    char source_path[sizeof(path)];
    strcpy(source_path, path);
    for (size_t i = 0; i < sizeof(block); ++i) block[i] = (unsigned char)(i * 19 + 7);
    CHECK(pwrite(source, block, 8192, 0) == 8192);
    int output = new_file(base, "copy-output", 8192);
    off_t from = 7;
    CHECK(sendfile(output, source, &from, 123) == 123 && from == 130);
    CHECK(pread(output, received, 123, 0) == 123 && memcmp(received, block + 7, 123) == 0);
    CHECK(lseek(source, 0, SEEK_CUR) == 0 && lseek(output, 0, SEEK_CUR) == 123);
    from = 17;
    off_t to = 4096;
    CHECK(copy_file_range(source, &from, output, &to, 257, 0) == 257);
    CHECK(from == 274 && to == 4353);
    CHECK(pread(output, received, 257, 4096) == 257 && memcmp(received, block + 17, 257) == 0);
    CHECK(lseek(source, 0, SEEK_CUR) == 0 && lseek(output, 0, SEEK_CUR) == 123);
    int pipefd[2];
    CHECK(pipe2(pipefd, O_CLOEXEC) == 0);
    from = 33;
    CHECK(splice(source, &from, pipefd[1], NULL, 64, 0) == 64 && from == 97);
    CHECK(read(pipefd[0], received, 64) == 64 && memcmp(received, block + 33, 64) == 0);
    CHECK(write(pipefd[1], block + 200, 64) == 64);
    to = 5000;
    CHECK(splice(pipefd[0], NULL, output, &to, 64, 0) == 64 && to == 5064);
    CHECK(pread(output, received, 64, 5000) == 64 && memcmp(received, block + 200, 64) == 0);
    CHECK(close(pipefd[0]) == 0 && close(pipefd[1]) == 0);
    int plain = open("/work/plain-copy", O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(plain >= 0);
    from = 44;
    CHECK(sendfile(plain, source, &from, 113) == 113 && from == 157);
    CHECK(pread(plain, received, 113, 0) == 113 && memcmp(received, block + 44, 113) == 0);
    from = 0;
    CHECK(sendfile(output, plain, &from, 37) == 37 && from == 37);
    CHECK(pread(output, received, 37, 123) == 37 && memcmp(received, block + 44, 37) == 0);
    CHECK(lseek(plain, 0, SEEK_CUR) == 113 && lseek(output, 0, SEEK_CUR) == 160);
    from = 16384; to = 300;
    CHECK(copy_file_range(source, &from, output, &to, 8, 0) == 0);
    CHECK(from == 16384 && to == 300);
    CHECK(fsync(output) == 0);
    CHECK(close(plain) == 0 && unlink("/work/plain-copy") == 0);
    finish(output);
    CHECK(close(source) == 0 && unlink(source_path) == 0);
}
static void ring_io(const char *base) {
    struct io_uring_params params = {0};
    int ring = (int)syscall(SYS_io_uring_setup, 8, &params);
    CHECK(ring >= 0);
    size_t sq_size = params.sq_off.array + params.sq_entries * sizeof(uint32_t);
    size_t cq_size = params.cq_off.cqes + params.cq_entries * sizeof(struct io_uring_cqe);
    unsigned char *sq = mmap(NULL, sq_size, PROT_READ | PROT_WRITE, MAP_SHARED, ring, IORING_OFF_SQ_RING);
    unsigned char *cq = mmap(NULL, cq_size, PROT_READ | PROT_WRITE, MAP_SHARED, ring, IORING_OFF_CQ_RING);
    size_t entries_size = params.sq_entries * sizeof(struct io_uring_sqe);
    struct io_uring_sqe *entries = mmap(NULL, entries_size, PROT_READ | PROT_WRITE, MAP_SHARED, ring, IORING_OFF_SQES);
    CHECK(sq != MAP_FAILED && cq != MAP_FAILED && entries != MAP_FAILED);
    unsigned char buffers[3][64];
    struct iovec vectors[3];
    int files[3];
    char names[3][32];
    const size_t sizes[3] = {8, 17, 26};
    uint32_t *array = (void *)(sq + params.sq_off.array);
    for (unsigned i = 0; i < 3; ++i) {
        CHECK(snprintf(names[i], sizeof(names[i]), "ring-%u", i) > 0);
        files[i] = new_file(base, names[i], 0);
        memset(block, (int)('a' + i), sizes[i]);
        CHECK(pwrite(files[i], block, sizes[i], 0) == (ssize_t)sizes[i]);
        vectors[i] = (struct iovec){.iov_base = buffers[i], .iov_len = sizes[i]};
        entries[i] = (struct io_uring_sqe){.opcode = IORING_OP_READV,
            .fd = files[i], .addr = (uintptr_t)&vectors[i], .len = 1, .off = 0, .user_data = 17 + i};
        array[i] = i;
    }
    __atomic_store_n((uint32_t *)(sq + params.sq_off.tail), 3, __ATOMIC_RELEASE);
    CHECK(syscall(SYS_io_uring_enter, ring, 3, 3, IORING_ENTER_GETEVENTS, NULL, 0) == 3);
    CHECK(__atomic_load_n((uint32_t *)(cq + params.cq_off.tail), __ATOMIC_ACQUIRE) == 3);
    struct io_uring_cqe *completed = (void *)(cq + params.cq_off.cqes);
    unsigned seen = 0;
    for (unsigned i = 0; i < 3; ++i) {
        CHECK(completed[i].user_data >= 17 && completed[i].user_data < 20);
        unsigned index = (unsigned)completed[i].user_data - 17;
        CHECK(!(seen & (1u << index)));
        seen |= 1u << index;
        CHECK(completed[i].res == (int)sizes[index]);
        for (size_t j = 0; j < sizes[index]; ++j) CHECK(buffers[index][j] == 'a' + index);
    }
    CHECK(seen == 7);
    __atomic_store_n((uint32_t *)(cq + params.cq_off.head), 3, __ATOMIC_RELEASE);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    CHECK(snprintf(address.sun_path, sizeof(address.sun_path), "%s/ring-socket", base) < (int)sizeof(address.sun_path));
    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(listener >= 0 && client >= 0);
    // BIND=56 is newer than some distro userspace headers; the original
    // Linux reference validates the actual kernel opcode, without a fallback.
    uint32_t sq_mask = *(uint32_t *)(sq + params.sq_off.ring_mask);
    uint32_t cq_mask = *(uint32_t *)(cq + params.cq_off.ring_mask);
    entries[3 & sq_mask] = (struct io_uring_sqe){.opcode = 56, .fd = listener,
        .addr = (uintptr_t)&address, .off = sizeof(address), .user_data = 103};
    array[3 & sq_mask] = 3 & sq_mask;
    __atomic_store_n((uint32_t *)(sq + params.sq_off.tail), 4, __ATOMIC_RELEASE);
    CHECK(syscall(SYS_io_uring_enter, ring, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0) == 1);
    CHECK(completed[3 & cq_mask].user_data == 103 && completed[3 & cq_mask].res == 0);
    __atomic_store_n((uint32_t *)(cq + params.cq_off.head), 4, __ATOMIC_RELEASE);
    CHECK(listen(listener, 1) == 0);
    entries[4 & sq_mask] = (struct io_uring_sqe){.opcode = IORING_OP_CONNECT, .fd = client,
        .addr = (uintptr_t)&address, .off = sizeof(address), .user_data = 104};
    array[4 & sq_mask] = 4 & sq_mask;
    __atomic_store_n((uint32_t *)(sq + params.sq_off.tail), 5, __ATOMIC_RELEASE);
    CHECK(syscall(SYS_io_uring_enter, ring, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0) == 1);
    CHECK(completed[4 & cq_mask].user_data == 104 && completed[4 & cq_mask].res == 0);
    __atomic_store_n((uint32_t *)(cq + params.cq_off.head), 5, __ATOMIC_RELEASE);
    int peer = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    CHECK(peer >= 0 && write(client, "ring", 4) == 4 && read(peer, received, 4) == 4);
    CHECK(!memcmp(received, "ring", 4) && unlink(address.sun_path) == 0);
    CHECK(close(peer) == 0 && close(client) == 0 && close(listener) == 0);
    CHECK(munmap(entries, entries_size) == 0 && munmap(sq, sq_size) == 0 && munmap(cq, cq_size) == 0);
    CHECK(close(ring) == 0);
    for (unsigned i = 0; i < 3; ++i) {
        CHECK(snprintf(path, sizeof(path), "%s/%s", base, names[i]) < (int)sizeof(path));
        finish(files[i]);
    }
}

static void cached_io(const char *base) {
    int fd = new_file(base, "cached-io", 8192);
    memset(block, 'a', 8192);
    CHECK(pwrite(fd, block, 8192, 0) == 8192);
    CHECK(fsync(fd) == 0 && close(fd) == 0);
    // A write-only partial page must preserve bytes on both sides. The same
    // ordinary client runs against native Linux and the guest filesystem.
    fd = open(path, O_WRONLY);
    CHECK(fd >= 0);
    CHECK(pwrite(fd, "partial", 7, 4093) == 7);
    struct stat local, backing;
    CHECK(fstat(fd, &local) == 0 && local.st_size == 8192);
    CHECK(fsync(fd) == 0 && close(fd) == 0);
    fd = open(path, O_RDWR | O_APPEND);
    CHECK(fd >= 0);
    CHECK(pwrite(fd, "append", 6, 0) == 6);
    CHECK(lseek(fd, 0, SEEK_CUR) == 0);
    CHECK(fstat(fd, &local) == 0 && local.st_size == 8198);
    CHECK(pread(fd, received, 8198, 0) == 8198);
    CHECK(!memcmp(received + 4093, "partial", 7));
    CHECK(received[4092] == 'a' && received[4100] == 'a');
    CHECK(!memcmp(received + 8192, "append", 6));
    CHECK(fsync(fd) == 0 && close(fd) == 0);
    fd = open(path, O_RDWR | O_DSYNC);
    CHECK(fd >= 0 && pwrite(fd, "tail", 4, 32771) == 4);
    CHECK(fstat(fd, &local) == 0 && local.st_size == 32775);
    CHECK(pread(fd, received, 24577, 8198) == 24577);
    for (size_t i = 0; i < 24573; ++i) CHECK(received[i] == 0);
    CHECK(!memcmp(received + 24573, "tail", 4));
    CHECK(sync_file_range(fd, 4097, 8193,
                         SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE |
                         SYNC_FILE_RANGE_WAIT_AFTER) == 0);
    CHECK(fsync(fd) == 0);
    CHECK(fstat(fd, &local) == 0);
    CHECK(stat("/work/source/cached-io", &backing) == 0);
    CHECK(backing.st_size == local.st_size);
    CHECK(backing.st_mtim.tv_sec == local.st_mtim.tv_sec);
    CHECK(backing.st_mtim.tv_nsec == local.st_mtim.tv_nsec);
    CHECK(ftruncate(fd, 4097) == 0);
    CHECK(fsync(fd) == 0);
    CHECK(pread(fd, received, 16, 4090) == 7);
    CHECK(!memcmp(received, "aaapart", 7));
    finish(fd);
    fd = new_file(base, "accepted-readonly", 0);
    CHECK(write(fd, "accepted", 8) == 8);
    errno = 0;
    CHECK(mount(NULL, "/work/view", NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL) == -1 && errno == EBUSY);
    int retained = dup(fd);
    CHECK(retained >= 0);
    CHECK(fsync(fd) == 0);
    CHECK(close(fd) == 0);
    errno = 0;
    CHECK(mount(NULL, "/work/view", NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL) == -1 && errno == EBUSY);
    CHECK(close(retained) == 0);
    fd = open(path, O_RDONLY);
    CHECK(fd >= 0);
    CHECK(mount(NULL, "/work/view", NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL) == 0);
    errno = 0;
    CHECK(open(path, O_WRONLY) == -1 && errno == EROFS);
    CHECK(fsync(fd) == 0);
    CHECK(pread(fd, received, 8, 0) == 8 && !memcmp(received, "accepted", 8));
    CHECK(mount(NULL, "/work/view", NULL, MS_REMOUNT | MS_BIND, NULL) == 0);
    finish(fd);
}

int main(int argc, char **argv) {
    CHECK(argc == 3);
    scenario = argv[1];
    if (!strcmp(scenario, "ready")) ready(argv[2]);
    else if (!strcmp(scenario, "mapping")) mapping(argv[2]);
    else if (!strcmp(scenario, "copyout")) copyout(argv[2]);
    else if (!strcmp(scenario, "metadata")) metadata(argv[2]);
    else if (!strcmp(scenario, "aio")) aio_copy(argv[2]);
    else if (!strcmp(scenario, "special")) special(argv[2]);
    else if (!strcmp(scenario, "transfer")) transfer(argv[2]);
    else if (!strcmp(scenario, "copy")) copy_io(argv[2]);
    else if (!strcmp(scenario, "cached")) cached_io(argv[2]);
    else if (!strcmp(scenario, "ring")) ring_io(argv[2]);
    else CHECK(0);
    printf("client %s passed\n", scenario);
    return 0;
}
