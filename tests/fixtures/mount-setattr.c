// SPDX-License-Identifier: GPL-3.0-or-later
// Standalone Linux ARM64 fixture. Run as guest root or in a private mount namespace.
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/mount.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif

static long set_attr(int fd, const char *path, unsigned flags,
                     uint64_t set, uint64_t clear)
{
    struct mount_attr attr = {.attr_set = set, .attr_clr = clear};
    return syscall(SYS_mount_setattr, fd, path, flags, &attr, sizeof(attr));
}

static void fails(long result, int error)
{
    if (result != -1 || errno != error) {
        fprintf(stderr, "got %ld errno %d, expected errno %d\n", result, errno, error);
        abort();
    }
}

static void create(const char *path)
{
    int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        perror(path);
        abort();
    }
    assert(ftruncate(fd, 4096) == 0);
    assert(close(fd) == 0);
}

static void flags_are(const char *path, unsigned long expected)
{
    struct statvfs stat;
    assert(statvfs(path, &stat) == 0);
    assert((stat.f_flag & (ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC |
                           ST_NOATIME | ST_NODIRATIME | ST_RELATIME)) == expected);
}

int main(void)
{
    char tmp[] = "/tmp/mount-setattr.XXXXXX";
    assert(mkdtemp(tmp));
    assert(chdir(tmp) == 0);
    assert(mkdir("source", 0755) == 0);
    assert(mkdir("target", 0755) == 0);
    assert(syscall(SYS_mount, "none", "source", "tmpfs", 0, NULL) == 0);
    assert(mkdir("source/child", 0755) == 0);
    assert(syscall(SYS_mount, "none", "source/child", "tmpfs", 0, NULL) == 0);
    create("source/child/data");

    int tree = syscall(SYS_open_tree, AT_FDCWD, "source",
                       OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_RECURSIVE);
    assert(tree >= 0);
    const uint64_t attrs = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV |
                           MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOATIME | MOUNT_ATTR_NODIRATIME;
    const unsigned long applied = ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC |
                                  ST_NOATIME | ST_NODIRATIME;
    assert(set_attr(tree, "", AT_EMPTY_PATH | AT_RECURSIVE, attrs, MOUNT_ATTR__ATIME) == 0);
    assert(syscall(SYS_move_mount, tree, "", AT_FDCWD, "target", MOVE_MOUNT_F_EMPTY_PATH) == 0);
    assert(close(tree) == 0);
    flags_are("target", applied);
    flags_are("target/child", applied);
    flags_are("source", ST_RELATIME);
    flags_are("source/child", ST_RELATIME);
    fails(open("target/no", O_WRONLY | O_CREAT, 0600), EROFS);
    fails(open("target/child/no", O_WRONLY | O_CREAT, 0600), EROFS);
    create("source/child/source-writable");

    assert(set_attr(AT_FDCWD, "target", 0, 0, MOUNT_ATTR_RDONLY) == 0);
    create("target/root-writable");
    fails(open("target/child/still-ro", O_WRONLY | O_CREAT, 0600), EROFS);
    int dir = open("target", O_PATH | O_CLOEXEC);
    assert(dir >= 0);
    char procfd[64];
    assert(snprintf(procfd, sizeof(procfd), "/proc/self/fd/%d", dir) > 0);
    assert(set_attr(-1, procfd, AT_RECURSIVE, 0, attrs | MOUNT_ATTR__ATIME) == 0);
    assert(close(dir) == 0);
    flags_are("target", ST_RELATIME);
    flags_are("target/child", ST_RELATIME);

    int fd = open("target/child/data", O_RDWR);
    assert(fd >= 0);
    void *mapped = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    assert(mapped != MAP_FAILED);
    assert(close(fd) == 0);
    fails(set_attr(AT_FDCWD, "target", AT_RECURSIVE,
                   MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOEXEC, 0), EBUSY);
    flags_are("target", ST_RELATIME);
    flags_are("target/child", ST_RELATIME);
    assert(munmap(mapped, 4096) == 0);
    assert(set_attr(AT_FDCWD, "target", AT_RECURSIVE, MOUNT_ATTR_RDONLY, 0) == 0);
    flags_are("target", ST_RELATIME | ST_RDONLY);
    flags_are("target/child", ST_RELATIME | ST_RDONLY);

    assert(symlink("target", "alias") == 0);
    fails(set_attr(AT_FDCWD, "alias", AT_SYMLINK_NOFOLLOW, 0, MOUNT_ATTR_RDONLY), EINVAL);
    fails(set_attr(AT_FDCWD, "target/child/data", 0, 0, MOUNT_ATTR_RDONLY), EINVAL);
    fails(set_attr(AT_FDCWD, "target", 0, MOUNT_ATTR_NOATIME, 0), EINVAL);
    fails(set_attr(AT_FDCWD, "target", 0x40000000, 0, 0), EINVAL);
    fails(set_attr(AT_FDCWD, "target", 0, UINT64_C(1) << 63, 0), EINVAL);
    struct {
        struct mount_attr attr;
        uint64_t extension;
    } request = {0};
    assert(syscall(SYS_mount_setattr, -1, NULL, 0, &request, sizeof(request)) == 0);
    fails(syscall(SYS_mount_setattr, -1, NULL, 0, &request, 31), EINVAL);
    fails(syscall(SYS_mount_setattr, -1, NULL, 0, &request, 65536), E2BIG);
    request.extension = 1;
    fails(syscall(SYS_mount_setattr, -1, NULL, 0, &request, sizeof(request)), E2BIG);

    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setuid(65534) == 0);
        fails(syscall(SYS_mount_setattr, -1, NULL, 0, NULL, sizeof(request.attr)), EPERM);
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && status == 0);
    puts("PASS recursive attached/detached mount flags, isolation, rollback and ABI validation");
    return 0;
}
