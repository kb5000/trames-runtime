// SPDX-License-Identifier: GPL-3.0-or-later
// Standalone AArch64 Linux mount-query ABI fixture. Run in a private root guest.
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/mount.h>
#include <linux/stat.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_statmount
#define SYS_statmount 457
#define SYS_listmount 458
#endif
#ifndef STATX_MNT_ID_UNIQUE
#define STATX_MNT_ID_UNIQUE 0x4000
#endif

#ifndef LSMT_ROOT
#define LSMT_ROOT UINT64_MAX
#endif
#define LIST_REVERSE 1
#define STAT_BASIC 0x3
#define STAT_ROOT 0x8
#define STAT_POINT 0x10
#define STAT_TYPE 0x20
#define STAT_NS 0x40
#define STAT_OPTS 0x80
#define STAT_SOURCE 0x200

struct request {
    uint32_t size, spare;
    uint64_t mount, param, namespace;
};

struct mount_reply {
    uint32_t size, options;
    uint64_t mask;
    uint32_t major, minor;
    uint64_t magic;
    uint32_t sb_flags, type;
    uint64_t id, parent;
    uint32_t old_id, old_parent;
    uint64_t flags, propagation, peer, master, propagate_from;
    uint32_t root, point;
    uint64_t namespace;
    uint32_t subtype, source;
    unsigned char reserved[384];
    char strings[8192];
};
_Static_assert(__builtin_offsetof(struct mount_reply, strings) == 512, "statmount layout");

static void fails(long value, int expected)
{
    if (value != -1 || errno != expected) {
        fprintf(stderr, "got %ld errno %d, expected errno %d\n", value, errno, expected);
        abort();
    }
}

static long mount_list(uint64_t mount, uint64_t cursor, uint64_t ns,
                       uint64_t *out, size_t count, unsigned flags)
{
    struct request req = {sizeof(req), 0, mount, cursor, ns};
    return syscall(SYS_listmount, &req, out, count, flags);
}

static int mount_stat(uint64_t id, uint64_t ns, uint64_t mask, struct mount_reply *out)
{
    struct request req = {sizeof(req), 0, id, mask, ns};
    return syscall(SYS_statmount, &req, out, sizeof(*out), 0);
}

static struct statx identity(int fd, const char *path, int flags, unsigned mask)
{
    struct statx st;
    assert(syscall(SYS_statx, fd, path, flags, mask, &st) == 0);
    assert((st.stx_mask & (STATX_MNT_ID | STATX_MNT_ID_UNIQUE)) == mask);
    return st;
}

static uint64_t path_id(const char *path)
{
    return identity(AT_FDCWD, path, 0, STATX_MNT_ID_UNIQUE).stx_mnt_id;
}

static void tmpfs(const char *path)
{
    assert(mkdir(path, 0755) == 0);
    assert(syscall(SYS_mount, "mount-query", path, "tmpfs", 0, "mode=701") == 0);
}

static void pagination(void)
{
    uint64_t all[4096], page[3];
    long n = mount_list(LSMT_ROOT, 0, 0, all, 4096, 0);
    assert(n > 3 && n < 4096);
    for (unsigned reverse = 0; reverse <= LIST_REVERSE; reverse++) {
        uint64_t cursor = 0;
        for (long i = 0; i < n;) {
            long got = mount_list(LSMT_ROOT, cursor, 0, page, 3, reverse);
            assert(got == (n - i < 3 ? n - i : 3));
            for (long j = 0; j < got; j++, i++) {
                assert(page[j] == all[reverse ? n - i - 1 : i]);
            }
            cursor = page[got - 1];
        }
        assert(mount_list(LSMT_ROOT, cursor, 0, page, 3, reverse) == 0);
    }
    for (long i = 1; i < n; i++) {
        assert(all[i - 1] < all[i]);
    }
}

static void wait_success(pid_t child)
{
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(void)
{
    char scratch[] = "/tmp/mount-query.XXXXXX";
    assert(mkdtemp(scratch) && chdir(scratch) == 0);
    tmpfs("source");
    assert(mkdir("source/inside", 0755) == 0);
    tmpfs("source/inside/child");
    assert(mkdir("source/directory with spaces", 0755) == 0);
    assert(mkdir("bind alias", 0755) == 0);
    assert(syscall(SYS_mount, "source/directory with spaces", "bind alias", NULL, 4096, NULL) == 0);

    uint64_t outer = path_id("source");
    uint64_t nested = path_id("source/inside/child");
    struct statx info = identity(AT_FDCWD, "bind alias", 0, STATX_MNT_ID_UNIQUE);
    uint64_t legacy = identity(AT_FDCWD, "bind alias", 0, STATX_MNT_ID).stx_mnt_id;
    struct mount_reply data;
    uint64_t mask = STAT_BASIC | STAT_ROOT | STAT_POINT | STAT_TYPE | STAT_NS | STAT_OPTS;
    assert(mount_stat(info.stx_mnt_id, 0, mask | STAT_SOURCE, &data) == 0);
    assert((data.mask & mask) == mask && data.size > 512 && data.size <= sizeof(data));
    assert(data.id == info.stx_mnt_id && data.old_id == legacy && data.id != data.old_id);
    assert(data.major == info.stx_dev_major && data.minor == info.stx_dev_minor);
    assert(data.magic == 0x1021994 && strcmp(data.strings + data.type, "tmpfs") == 0);
    assert(strcmp(data.strings + data.root, "/directory with spaces") == 0);
    assert(strstr(data.strings + data.point, "/bind alias"));
    assert(strstr(data.strings + data.options, "mode=701"));
    if (data.mask & STAT_SOURCE) {
        assert(strcmp(data.strings + data.source, "mount-query") == 0);
    }
    assert(data.parent == path_id("."));
    uint64_t own_ns = data.namespace;
    assert(own_ns != 0);
    assert(mount_stat(nested, own_ns, STAT_BASIC, &data) == 0 && data.parent == outer);
    pagination();
    uint64_t ids[3];
    assert(mount_list(outer, 0, 0, ids, 3, 0) == 1 && ids[0] == nested);

    struct request req = {24, 0, info.stx_mnt_id, STAT_BASIC, 123};
    uint32_t used = 0;
    assert(syscall(SYS_statmount, &req, &used, sizeof(used), 0) == 0 && used == 4);
    req.param = STAT_TYPE;
    fails(syscall(SYS_statmount, &req, &data, 512, 0), EOVERFLOW);
    fails(syscall(SYS_statmount, &req, &data, sizeof(data), 2), EINVAL);
    fails(syscall(SYS_statmount, &req, NULL, sizeof(data), 0), EFAULT);
    req.mount = legacy;
    fails(syscall(SYS_statmount, &req, &data, sizeof(data), 0), EINVAL);
    fails(mount_list(LSMT_ROOT, legacy, 0, ids, 3, 0), EINVAL);
    fails(mount_list(LSMT_ROOT, 0, 0, ids, 1000001, 0), EOVERFLOW);
    /* Guest Linux uses 4 KiB pages. Native reference may use a larger page. */
    req.size = (uint32_t)sysconf(_SC_PAGESIZE) + 1;
    fails(syscall(SYS_statmount, &req, &data, sizeof(data), 0), E2BIG);

    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(chroot("source/inside") == 0 && chdir("/") == 0);
        assert(mount_list(LSMT_ROOT, 0, 0, ids, 3, 0) == 1 && ids[0] == nested);
        assert(mount_stat(nested, 0, STAT_POINT, &data) == 0);
        assert(strcmp(data.strings + data.point, "/child") == 0);
        assert(setuid(65534) == 0);
        fails(mount_stat(outer, 0, STAT_POINT, &data), EPERM);
        fails(mount_list(outer, 0, 0, ids, 3, 0), EPERM);
        _exit(0);
    }
    wait_success(child);

    child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(unshare(CLONE_NEWNS) == 0);
        uint64_t child_id = path_id("source");
        assert(child_id != outer);
        assert(mount_stat(child_id, 0, STAT_NS, &data) == 0 && data.namespace != own_ns);
        assert(mount_stat(outer, own_ns, STAT_BASIC, &data) == 0 && data.id == outer);
        assert(mount_list(outer, 0, own_ns, ids, 3, 0) == 1 && ids[0] == nested);
        fails(mount_stat(outer, 0, STAT_BASIC, &data), ENOENT);
        assert(setuid(65534) == 0);
        int rc = mount_stat(outer, own_ns, STAT_BASIC, &data);
        /* Linux v6.12 hides the foreign namespace. Newer kernels use EPERM. */
        assert(rc == -1 && (errno == ENOENT || errno == EPERM));
        _exit(0);
    }
    wait_success(child);

    assert(mkdir("installed", 0755) == 0);
    int fd = syscall(SYS_open_tree, AT_FDCWD, "source", OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
    assert(fd >= 0);
    uint64_t detached = identity(fd, "", AT_EMPTY_PATH, STATX_MNT_ID_UNIQUE).stx_mnt_id;
    fails(mount_stat(detached, 0, STAT_BASIC, &data), ENOENT);
    assert(syscall(SYS_move_mount, fd, "", AT_FDCWD, "installed", MOVE_MOUNT_F_EMPTY_PATH) == 0);
    assert(path_id("installed") == detached && mount_stat(detached, 0, STAT_BASIC, &data) == 0);
    assert(close(fd) == 0);
    assert(syscall(SYS_umount2, "installed", 0) == 0);
    fails(mount_stat(detached, 0, STAT_BASIC, &data), ENOENT);
    int ends[2];
    struct statx pipe_stat;
    assert(pipe(ends) == 0);
    assert(syscall(SYS_statx, ends[0], "", AT_EMPTY_PATH, STATX_MNT_ID_UNIQUE, &pipe_stat) == 0);
    if (pipe_stat.stx_mask & STATX_MNT_ID_UNIQUE) {
        fails(mount_stat(pipe_stat.stx_mnt_id, 0, STAT_BASIC, &data), ENOENT);
    }
    assert(close(ends[0]) == 0 && close(ends[1]) == 0);
    puts("PASS mount metadata, pagination, statx IDs, chroot, namespace authority and detached lifetime");
    return 0;
}
