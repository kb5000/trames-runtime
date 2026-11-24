// SPDX-License-Identifier: GPL-3.0-or-later
// LOOKUP publication remains observable when the pathname operation fails.
#define main permissions_fixture_main
#include "fuse-posix-acl.c"
#undef main
#include <linux/stat.h>
#include <sys/syscall.h>

#define LOOKUP_CASES 16
#define LOOKUP_TARGET "/fuse-lookup-target"
static unsigned lookup_gets[LOOKUP_CASES], lookup_aliases[LOOKUP_CASES];
static unsigned lookup_links[LOOKUP_CASES], lookup_releases;
static int lifetime_bad(unsigned test) {
    return test <= 3 || (test >= 6 && test <= 10);
}
static struct fuse_attr lifetime_attr(unsigned test, unsigned mode) {
    return (struct fuse_attr){.ino = 200 + test, .size = 8, .mode = mode,
                              .nlink = 1, .blksize = 4096};
}
static void lifetime_serve(int fd, int done) {
    for (;;) {
        ssize_t size = read(fd, input, sizeof(input));
        if (size < 0 && errno == ENODEV) {
            for (unsigned i = 0; i < LOOKUP_CASES; ++i) {
                fprintf(stderr, "lookup-count case=%u alias=%u get=%u link=%u\n",
                        i, lookup_aliases[i], lookup_gets[i], lookup_links[i]);
                CHECK(lookup_aliases[i] == 1 && lookup_gets[i] == (i >= 7 && i <= 10) &&
                      lookup_links[i] == (i == 0));
            }
            _exit(0);
        }
        CHECK(size >= (ssize_t)sizeof(struct fuse_in_header));
        const struct fuse_in_header *in = (void *)input;
        const void *body = input + sizeof(*in);
        CHECK(in->len == size);
        switch (in->opcode) {
        case FUSE_INIT: {
            struct fuse_init_out out = {.major = 7, .minor = 31,
                .flags = FUSE_BIG_WRITES, .max_write = 16384, .time_gran = 1};
            reply(fd, in, 0, &out, sizeof(out));
            break;
        }
        case FUSE_LOOKUP: {
            CHECK(in->nodeid == 1);
            const char *name = body;
            int alias = !strncmp(name, "alias", 5);
            char *end;
            unsigned long test = strtoul(name + (alias ? 5 : 0), &end, 10);
            CHECK(!*end && test < LOOKUP_CASES);
            unsigned mode = S_IFREG | (alias ? 0600 : 0666);
            if (alias) {
                ++lookup_aliases[test];
                if (test == 0 || test == 3 || test == 6) mode = S_IFLNK | 0777;
                if (test == 2) mode = S_IFDIR | 0755;
                if (test == 12 || test == 14) mode = 0600;
                if (test == 15) mode = S_IFREG;
            }
            struct fuse_entry_out out = {.nodeid = 200 + test,
                .generation = alias && (test == 1 || test == 2 || test == 10) ? 2 : 1,
                .entry_valid = 3600, .attr_valid = 3600,
                .attr = lifetime_attr(test, mode)};
            if (alias && test == 13) out.attr.size = UINT64_MAX;
            reply(fd, in, 0, &out, sizeof(out));
            break;
        }
        case FUSE_GETATTR: {
            if (in->nodeid == 1) {
                struct fuse_attr_out out = {.attr_valid = 3600, .attr = attr(1)};
                reply(fd, in, 0, &out, sizeof(out));
                break;
            }
            CHECK(in->nodeid >= 200 && in->nodeid < 200 + LOOKUP_CASES);
            unsigned test = in->nodeid - 200;
            ++lookup_gets[test];
            struct fuse_attr_out out = {.attr_valid = 3600,
                .attr = lifetime_attr(test, test >= 7 && test <= 10 ?
                                      S_IFDIR | 0755 : S_IFREG | 0600)};
            reply(fd, in, 0, &out, sizeof(out));
            break;
        }
        case FUSE_OPEN: {
            struct fuse_open_out out = {.fh = in->nodeid};
            reply(fd, in, 0, &out, sizeof(out));
            break;
        }
        case FUSE_READLINK: {
            CHECK(in->nodeid >= 200 && in->nodeid < 200 + LOOKUP_CASES);
            ++lookup_links[in->nodeid - 200];
            reply(fd, in, 0, LOOKUP_TARGET, strlen(LOOKUP_TARGET));
            break;
        }
        case FUSE_RELEASE:
            reply(fd, in, 0, NULL, 0);
            if (++lookup_releases == LOOKUP_CASES) CHECK(write(done, "r", 1) == 1);
            break;
        case FUSE_FLUSH: reply(fd, in, 0, NULL, 0); break;
        case FUSE_FORGET: case FUSE_BATCH_FORGET: break;
        case FUSE_ACCESS: CHECK(0); break;
        default: reply(fd, in, ENOSYS, NULL, 0); break;
        }
    }
}
static int lifetime_stat(int fd, unsigned flags, struct statx *st) {
    return syscall(SYS_statx, fd, "", AT_EMPTY_PATH | flags, STATX_BASIC_STATS, st);
}
static void lifetime_path(unsigned test, const char *path) {
    struct stat st;
    errno = 0;
    int result, opened = 0;
    if (test == 2 || test == 3 || test == 4 || test == 7 || test == 14) {
        result = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
        opened = 1;
    } else if (test == 6) {
        result = open(path, O_RDONLY | O_NOFOLLOW);
        opened = 1;
    } else if (test == 9 || test == 10) {
        result = open(path, O_PATH);
        opened = 1;
    } else {
        result = stat(path, &st);
    }
    int error = errno;
    fprintf(stderr, "lookup-operation case=%u result=%d errno=%d\n",
            test, opened && result >= 0 ? 0 : result, error);
    const int errors[LOOKUP_CASES] = {0, ENOTDIR, EEXIST, EEXIST, EEXIST, ENOTDIR,
        ELOOP, EEXIST, EIO, 0, 0, ENOTDIR, EIO, EIO, EIO, ENOTDIR};
    CHECK(errors[test] ? result == -1 && error == errors[test] : result >= 0);
    if (opened && result >= 0) {
        struct statx cached;
        errno = 0;
        int state = lifetime_stat(result, AT_STATX_DONT_SYNC, &cached), state_error = errno;
        fprintf(stderr, "lookup-new case=%u result=%d errno=%d mode=%o\n", test,
                state, state_error, state ? 0 : cached.stx_mode);
        CHECK(test == 9 ? state == -1 && state_error == EIO :
              state == 0 && cached.stx_mode == (S_IFREG | 0600));
        CHECK(close(result) == 0);
    }
}
static int lifetime_fixture(void) {
    int target = open(LOOKUP_TARGET, O_CREAT | O_EXCL | O_RDWR, 0644);
    CHECK(target >= 0 && close(target) == 0);
    CHECK(mkdir(BASE, 0755) == 0);
    int fd = open("/dev/fuse", O_RDWR);
    CHECK(fd >= 0);
    char opts[160];
    snprintf(opts, sizeof(opts), "fd=%d,rootmode=40755,user_id=0,group_id=0,allow_other,default_permissions", fd);
    CHECK(mount("lookup-lifetime", BASE, "fuse", 0, opts) == 0);
    int done[2]; CHECK(pipe(done) == 0);
    pid_t daemon = fork(); CHECK(daemon >= 0);
    if (!daemon) {
        CHECK(close(done[0]) == 0);
        lifetime_serve(fd, done[1]); _exit(1);
    }
    CHECK(close(done[1]) == 0);
    struct stat root; CHECK(stat(BASE, &root) == 0);
    int pinned[LOOKUP_CASES];
    for (unsigned test = 0; test < LOOKUP_CASES; ++test) {
        char path[100]; snprintf(path, sizeof(path), BASE "/%u", test);
        pinned[test] = open(path, O_RDONLY); CHECK(pinned[test] >= 0);
    }
    for (unsigned test = 0; test < LOOKUP_CASES; ++test) {
        if (test >= 7 && test <= 10) {
            struct statx st; errno = 0;
            CHECK(lifetime_stat(pinned[test], AT_STATX_FORCE_SYNC, &st) == -1 && errno == EIO);
        }
        char path[100];
        snprintf(path, sizeof(path), BASE "/alias%u%s", test,
                 test == 1 || test == 5 || test == 15 ? "/child" : test == 11 ? "/" : "");
        if (test == 15) {
            pid_t child = fork(); CHECK(child >= 0);
            if (!child) {
                CHECK(setgroups(0, NULL) == 0 && setgid(1000) == 0 && setuid(1000) == 0);
                lifetime_path(test, path); _exit(0);
            }
            wait_client(child);
        } else lifetime_path(test, path);
        struct statx st; errno = 0;
        int result = lifetime_stat(pinned[test], AT_STATX_DONT_SYNC, &st), error = errno;
        fprintf(stderr, "lookup-old case=%u result=%d errno=%d mode=%o\n", test,
                result, error, result ? 0 : st.stx_mode);
        unsigned mode = S_IFREG | (test >= 12 && test <= 14 ? 0666 : test == 15 ? 0 : 0600);
        CHECK(lifetime_bad(test) ? result == -1 && error == EIO :
              result == 0 && st.stx_mode == mode);
    }
    for (unsigned test = 0; test < LOOKUP_CASES; ++test) {
        errno = 0; int result = close(pinned[test]), error = errno;
        fprintf(stderr, "lookup-close case=%u result=%d errno=%d\n", test, result, error);
        CHECK(lifetime_bad(test) ? result == -1 && error == EIO : result == 0);
    }
    char ready; CHECK(read(done[0], &ready, 1) == 1 && ready == 'r');
    CHECK(umount(BASE) == 0); wait_client(daemon);
    CHECK(close(done[0]) == 0 && close(fd) == 0 && rmdir(BASE) == 0 && unlink(LOOKUP_TARGET) == 0);
    puts("FUSE LOOKUP lifetime assertions passed");
    return 0;
}
int main(int argc, char **argv) {
    (void)argv;
    if (argc == 1) return lifetime_fixture();
    int ready[2], go[2]; CHECK(pipe(ready) == 0 && pipe(go) == 0);
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        CHECK(close(ready[0]) == 0 && close(go[1]) == 0);
        CHECK(unshare(CLONE_NEWUSER | CLONE_NEWNS) == 0 && write(ready[1], "r", 1) == 1);
        char ack; CHECK(read(go[0], &ack, 1) == 1 && close(ready[1]) == 0 && close(go[0]) == 0);
        _exit(lifetime_fixture());
    }
    CHECK(close(ready[1]) == 0 && close(go[0]) == 0);
    char ack; CHECK(read(ready[0], &ack, 1) == 1);
    for (int group = 0; group < 2; ++group) {
        char path[80]; snprintf(path, sizeof(path), "/proc/%d/%s_map", child, group ? "gid" : "uid");
        int mapfd = open(path, O_WRONLY); CHECK(mapfd >= 0);
        const char map[] = "0 0 1\n1000 101000 1001\n";
        CHECK(write(mapfd, map, sizeof(map) - 1) == sizeof(map) - 1 && close(mapfd) == 0);
    }
    CHECK(write(go[1], "g", 1) == 1 && close(go[1]) == 0 && close(ready[0]) == 0);
    wait_client(child); puts("FUSE mapped LOOKUP observations completed"); return 0;
}
