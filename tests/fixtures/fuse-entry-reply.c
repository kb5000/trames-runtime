// SPDX-License-Identifier: GPL-3.0-or-later
// Invalid entry replies do not grant lookup/open resources; root LOOKUP differs.
#define main permissions_fixture_main
#include "fuse-posix-acl.c"
#undef main
#include <linux/stat.h>
#include <sys/syscall.h>

#define ENTRY_CASES 35
static unsigned entry_case, entry_forgets, entry_releases;
static unsigned entry_lookups, entry_creates, entry_nodes, entry_rootgets;
static struct fuse_attr entry_attr(unsigned mode) {
    return (struct fuse_attr){.ino = 500 + entry_case, .size = 8,
        .mode = mode, .nlink = 1, .blksize = 4096};
}
static struct fuse_entry_out entry_response(void) {
    unsigned mode = S_IFREG | 0600;
    uint64_t node = 400 + entry_case;
    if (entry_case <= 2) { node = 1; mode = entry_case == 2 ? S_IFREG | 0600 : S_IFDIR | (0701 + entry_case); }
    if (entry_case >= 30) { node = 1; mode = S_IFDIR | (0701 + entry_case - 30); }
    if (entry_case == 3) { node = 0; mode = 0600; }
    if (entry_case == 4 || entry_case == 25) mode = 0600;
    if (entry_case == 6 || entry_case == 14 || entry_case == 23 || entry_case == 26) mode = S_IFDIR | 0755;
    if (entry_case >= 10 && entry_case <= 13) mode = entry_case == 10 ? S_IFREG | 0600 : S_IFDIR | 0755;
    if (entry_case >= 18 && entry_case <= 21) mode = entry_case == 18 ? S_IFREG | 0600 : S_IFLNK | 0777;
    if (entry_case == 8 || entry_case == 12 || entry_case == 16 || entry_case == 20 || entry_case == 28) node = 0;
    if (entry_case == 9 || entry_case == 13 || entry_case == 17 || entry_case == 21 || entry_case == 24 || entry_case == 25 || entry_case == 29) node = 1;
    struct fuse_entry_out out = {.nodeid = node, .generation = entry_case == 1 || entry_case == 31 ? 9 : 0,
        .entry_valid = 3600, .attr_valid = 3600, .attr = entry_attr(mode)};
    if (entry_case == 5 || entry_case == 7 || entry_case == 11 || entry_case == 15 || entry_case == 19 || entry_case == 22 || entry_case == 24 || entry_case == 27) out.attr.size = UINT64_MAX;
    return out;
}
static void entry_serve(int fd) {
    for (;;) {
        ssize_t size = read(fd, input, sizeof(input));
        if (size < 0 && errno == ENODEV) {
            fprintf(stderr, "entry-count case=%u lookup=%u create=%u node=%u rootget=%u forget=%u release=%u\n",
                entry_case, entry_lookups, entry_creates, entry_nodes, entry_rootgets, entry_forgets, entry_releases);
            CHECK(entry_forgets == 0 && entry_releases == 0);
            CHECK(entry_lookups == ((entry_case >= 26 && entry_case <= 29) || entry_case == 31 || entry_case == 34 ? 2u : 1u));
            CHECK(entry_creates == ((entry_case >= 6 && entry_case <= 9) || entry_case == 22 || entry_case == 23));
            CHECK(entry_nodes == ((entry_case >= 10 && entry_case <= 23) || (entry_case >= 26 && entry_case <= 29)));
            CHECK(entry_rootgets == (entry_case == 2 ? 1u : 2u));
            _exit(0);
        }
        CHECK(size >= (ssize_t)sizeof(struct fuse_in_header));
        const struct fuse_in_header *in = (void *)input;
        const void *body = input + sizeof(*in);
        CHECK(in->len == size);
        switch (in->opcode) {
        case FUSE_INIT: {
            struct fuse_init_out out = {.major = 7, .minor = 31, .flags = FUSE_BIG_WRITES,
                .max_write = 16384, .time_gran = 1};
            reply(fd, in, 0, &out, sizeof(out)); break;
        }
        case FUSE_GETATTR: {
            CHECK(in->nodeid == 1); ++entry_rootgets;
            if (entry_rootgets == 2) {
                fprintf(stderr, "entry-barrier case=%u forget=%u release=%u\n", entry_case, entry_forgets, entry_releases);
            }
            struct fuse_attr_out out = {.attr_valid = 3600, .attr = attr(1)};
            reply(fd, in, 0, &out, sizeof(out)); break;
        }
        case FUSE_LOOKUP: {
            CHECK(in->nodeid == 1); ++entry_lookups;
            if (!strcmp(body, "source")) {
                struct fuse_entry_out out = {.nodeid = 600, .generation = 1,
                    .entry_valid = 3600, .attr_valid = 3600,
                    .attr = {.ino = 600, .mode = S_IFREG | 0666, .nlink = 1, .blksize = 4096}};
                reply(fd, in, 0, &out, sizeof(out));
            } else if (entry_case <= 5 || entry_case == 24 || entry_case == 25 || entry_case >= 30) {
                struct fuse_entry_out out = entry_response(); reply(fd, in, 0, &out, sizeof(out));
            } else reply(fd, in, ENOENT, NULL, 0);
            break;
        }
        case FUSE_CREATE: {
            ++entry_creates;
            if (entry_case == 22 || entry_case == 23) reply(fd, in, ENOSYS, NULL, 0);
            else {
                struct { struct fuse_entry_out entry; struct fuse_open_out open; } out = {
                    .entry = entry_response(), .open = {.fh = 900 + entry_case}};
                reply(fd, in, 0, &out, sizeof(out));
            }
            break;
        }
        case FUSE_MKDIR: case FUSE_MKNOD: case FUSE_SYMLINK: case FUSE_LINK: {
            ++entry_nodes; struct fuse_entry_out out = entry_response();
            reply(fd, in, 0, &out, sizeof(out)); break;
        }
        case FUSE_FORGET:
            if (in->nodeid != 600) entry_forgets += ((const struct fuse_forget_in *)body)->nlookup;
            break;
        case FUSE_BATCH_FORGET: {
            const struct fuse_batch_forget_in *batch = body;
            const struct fuse_forget_one *items = (const void *)(batch + 1);
            for (unsigned i = 0; i < batch->count; ++i)
                if (items[i].nodeid != 600) entry_forgets += items[i].nlookup;
            break;
        }
        case FUSE_RELEASE:
            ++entry_releases; reply(fd, in, 0, NULL, 0); break;
        default: reply(fd, in, ENOSYS, NULL, 0); break;
        }
    }
}
static int entry_stat(int fd, unsigned flags, struct statx *st) {
    return syscall(SYS_statx, fd, "", AT_EMPTY_PATH | flags, STATX_BASIC_STATS, st);
}
static int entry_fixture(unsigned begin) {
    CHECK(mkdir(BASE, 0755) == 0);
    for (entry_case = begin; entry_case < ENTRY_CASES; ++entry_case) {
        entry_forgets = entry_releases = entry_lookups = entry_creates = entry_nodes = entry_rootgets = 0;
        int fd = open("/dev/fuse", O_RDWR); CHECK(fd >= 0);
        char opts[160]; snprintf(opts, sizeof(opts), "fd=%d,rootmode=40755,user_id=0,group_id=0,allow_other,default_permissions", fd);
        CHECK(mount("entry-reply", BASE, "fuse", 0, opts) == 0);
        pid_t daemon = fork(); CHECK(daemon >= 0);
        if (!daemon) { entry_serve(fd); _exit(1); }
        struct stat st; CHECK(stat(BASE, &st) == 0);
        int rootfd = open(BASE, O_PATH | O_DIRECTORY); CHECK(rootfd >= 0);
        errno = 0; int result;
        if (entry_case <= 5 || entry_case == 24 || entry_case == 25) result = stat(BASE "/new", &st);
        else if ((entry_case >= 6 && entry_case <= 9) || entry_case == 22 || entry_case == 23) result = open(BASE "/new", O_CREAT | O_EXCL | O_RDWR, 0600);
        else if (entry_case <= 13 || entry_case == 30) result = mkdir(BASE "/new", 0755);
        else if (entry_case <= 17 || entry_case == 32) result = mknod(BASE "/new", S_IFREG | 0600, 0);
        else if (entry_case <= 21 || entry_case == 33) result = symlink("target", BASE "/new");
        else if (entry_case == 34) result = rename(BASE "/source", BASE "/new");
        else result = link(BASE "/source", BASE "/new");
        int error = errno;
        fprintf(stderr, "entry-operation case=%u result=%d errno=%d\n", entry_case, result, error);
        CHECK(result == -1 && error == (entry_case == 3 ? ENOENT : EIO));
        struct statx cached; errno = 0;
        result = entry_stat(rootfd, AT_STATX_DONT_SYNC, &cached); error = errno;
        fprintf(stderr, "entry-root case=%u result=%d errno=%d mode=%o ino=%llu\n",
            entry_case, result, error, result ? 0 : cached.stx_mode,
            result ? 0 : (unsigned long long)cached.stx_ino);
        CHECK(entry_case == 2 ? result == -1 && error == EIO : result == 0 &&
              cached.stx_mode == (S_IFDIR | (entry_case <= 1 ? 0701 + entry_case : entry_case >= 30 ? 0701 + entry_case - 30 : 0755)) &&
              cached.stx_ino == (entry_case <= 1 || entry_case >= 30 ? 500 + entry_case : 1));
        // This force-sync request is a daemon-queue barrier after the operation.
        errno = 0; result = entry_stat(rootfd, AT_STATX_FORCE_SYNC, &cached); error = errno;
        fprintf(stderr, "entry-sync case=%u result=%d errno=%d\n", entry_case, result, error);
        CHECK(entry_case == 2 ? result == -1 && error == EIO : result == 0);
        CHECK(close(rootfd) == 0 && umount(BASE) == 0); wait_client(daemon); CHECK(close(fd) == 0);
    }
    CHECK(rmdir(BASE) == 0); puts("FUSE entry reply assertions passed"); return 0;
}
int main(int argc, char **argv) {
    int mapped = argc > 1 && !strcmp(argv[1], "userns");
    unsigned begin = argc > mapped + 1 && !strcmp(argv[mapped + 1], "resources") ? 6 : 0;
    if (!mapped) return entry_fixture(begin);
    int ready[2], go[2]; CHECK(pipe(ready) == 0 && pipe(go) == 0);
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        CHECK(close(ready[0]) == 0 && close(go[1]) == 0);
        CHECK(unshare(CLONE_NEWUSER | CLONE_NEWNS) == 0 && write(ready[1], "r", 1) == 1);
        char ack; CHECK(read(go[0], &ack, 1) == 1 && close(ready[1]) == 0 && close(go[0]) == 0);
        _exit(entry_fixture(begin));
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
    wait_client(child); return 0;
}
