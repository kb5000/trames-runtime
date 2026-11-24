// SPDX-License-Identifier: GPL-3.0-or-later
// A real guest daemon and client. Extend this fixture with the remaining FUSE
// namespace/mapping cases as those paths join the same accepted-work protocol.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fuse.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/xattr.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "pid=%d line=%d %s errno=%d\n", getpid(), __LINE__, #expr, errno); \
    _exit(1); } } while (0)

static unsigned char input[256 * 1024], output[256 * 1024];
struct node {
    uint64_t id, parent;
    unsigned mode, links, uid, gid;
    struct timespec times[3];
    struct { char name[64]; unsigned char value[256]; unsigned size; } attrs[4];
    int active;
    char name[64], link[128];
    size_t size;
    unsigned char data[32768];
};
#define MAX_NODES 128
#define EXPECT_RELEASED 16
static struct node nodes[MAX_NODES];
static int create_disabled;

struct mask_change { int request, ack; };
static int change_mask(void *opaque) {
    struct mask_change *change = opaque;
    for (;;) {
        char byte;
        CHECK(read(change->request, &byte, 1) == 1);
        switch (byte) {
        case 'm': case 'f': umask(0077); break;
        case 'p': umask(0002); break;
        case 'c': umask(0070); break;
        default: CHECK(0);
        }
        CHECK(write(change->ack, "m", 1) == 1);
        if (byte == 'f') return 0;
    }
}

static struct node *by_id(uint64_t id) {
    for (unsigned i = 0; i < MAX_NODES; ++i) if (nodes[i].id == id) return &nodes[i];
    return NULL;
}
static struct node *lookup(uint64_t parent, const char *name) {
    for (unsigned i = 0; i < MAX_NODES; ++i)
        if (nodes[i].active && nodes[i].parent == parent && !strcmp(nodes[i].name, name)) return &nodes[i];
    return NULL;
}
static struct node *create_node(uint64_t parent, const char *name, unsigned mode) {
    CHECK(strlen(name) < sizeof(nodes[0].name));
    for (unsigned i = 0; i < MAX_NODES; ++i) if (!nodes[i].id) {
        nodes[i].id = 20 + i;
        nodes[i].parent = parent;
        nodes[i].mode = mode;
        nodes[i].links = 1;
        nodes[i].active = 1;
        strcpy(nodes[i].name, name);
        return &nodes[i];
    }
    CHECK(0);
    return NULL;
}

static void respond(int fd, const struct fuse_in_header *in, int error,
                    const void *payload, size_t size) {
    struct fuse_out_header out = { .len = sizeof(out) + size, .error = -error, .unique = in->unique };
    memcpy(output, &out, sizeof(out));
    if (size) memcpy(output + sizeof(out), payload, size);
    CHECK(write(fd, output, out.len) == out.len);
}

static struct fuse_attr attributes(uint64_t node) {
    struct fuse_attr a = { .ino = node, .nlink = 1, .blksize = 4096 };
    struct node *n = by_id(node);
    CHECK(node == 1 || n);
    a.mode = node == 1 ? S_IFDIR | 0755 : n->mode;
    a.size = node == 1 ? 0 : n->size;
    a.nlink = node == 1 ? 1 : n->links;
    if (n) {
        a.uid = n->uid; a.gid = n->gid;
        a.atime = n->times[0].tv_sec; a.atimensec = n->times[0].tv_nsec;
        a.mtime = n->times[1].tv_sec; a.mtimensec = n->times[1].tv_nsec;
        a.ctime = n->times[2].tv_sec; a.ctimensec = n->times[2].tv_nsec;
    }
    return a;
}
static void entry_reply(int fd, const struct fuse_in_header *in, struct node *node, int opened) {
    struct {
        struct fuse_entry_out entry;
        struct fuse_open_out open;
    } out = { .entry = { .nodeid = node->id, .entry_valid = 1, .attr_valid = 1, .attr = attributes(node->id) },
              .open = { .fh = node->id + 10000, .open_flags = FOPEN_DIRECT_IO } };
    respond(fd, in, 0, &out, sizeof(out.entry) + (opened ? sizeof(out.open) : 0));
}

static size_t add_entry(unsigned char *buffer, uint64_t ino, uint64_t cookie, char name) {
    struct fuse_dirent *entry = (void *)buffer;
    entry->ino = ino;
    entry->off = cookie;
    entry->namelen = 1;
    entry->type = 8;
    entry->name[0] = name;
    return FUSE_DIRENT_SIZE(entry);
}

static void daemon_loop(int fd, int completed, int changes, int changed) {
    unsigned released = 0, mask_events = 0, unsupported_access = 0;
    for (;;) {
        ssize_t size = read(fd, input, sizeof(input));
        if (size == -1 && errno == ENODEV && released == EXPECT_RELEASED) _exit(0);
        CHECK(size >= (ssize_t)sizeof(struct fuse_in_header));
        const struct fuse_in_header *in = (void *)input;
        CHECK(in->len == size);
        const void *body = input + sizeof(*in);
        switch (in->opcode) {
        case FUSE_INIT: {
            struct fuse_init_out out = { .major = 7, .minor = 31, .flags = FUSE_BIG_WRITES,
                .max_background = 16, .max_write = 16 * 1024, .time_gran = 1 };
            respond(fd, in, 0, &out, sizeof(out));
            break;
        }
        case FUSE_STATFS: {
            struct fuse_statfs_out out = { .st = { .blocks = 123456, .bfree = 1234,
                .bavail = 567, .files = 890, .ffree = 321, .bsize = 8192,
                .namelen = 127, .frsize = 4096 } };
            struct node *node = by_id(in->nodeid);
            CHECK(in->nodeid == 1 || node);
            if (node && !strcmp(node->name, "statfs-readonly"))
                CHECK(mount(NULL, "/fuse-filesystem-test", NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL) == 0);
            if (node && !strcmp(node->name, "statfs-writable"))
                CHECK(mount(NULL, "/fuse-filesystem-test", NULL, MS_REMOUNT | MS_BIND, NULL) == 0);
            respond(fd, in, 0, &out, sizeof(out));
            break;
        }
        case FUSE_GETATTR: {
            struct fuse_attr_out out = { .attr_valid = 1, .attr = attributes(in->nodeid) };
            respond(fd, in, 0, &out, sizeof(out));
            break;
        }
        case FUSE_SETXATTR:
        case FUSE_GETXATTR:
        case FUSE_LISTXATTR:
        case FUSE_REMOVEXATTR: {
            static unsigned unsupported;
            unsigned bit = 1u << (in->opcode - FUSE_SETXATTR);
            CHECK(!(unsupported & bit));
            struct node *node = by_id(in->nodeid);
            if (!node) { respond(fd, in, ENODATA, NULL, 0); break; }
            const struct fuse_getxattr_in *get = body;
            const struct fuse_setxattr_in *set = body;
            const char *name = (const char *)body + (in->opcode == FUSE_REMOVEXATTR ? 0 : 8);
            if (in->opcode == FUSE_LISTXATTR) name = "";
            if (!strcmp(name, "user.unsupported") || (in->opcode == FUSE_LISTXATTR && !strcmp(node->name, "xattr-unsupported"))) {
                unsupported |= bit; respond(fd, in, ENOSYS, NULL, 0); break;
            }
            if (in->opcode == FUSE_GETXATTR && !strcmp(name, "user.capacity")) {
                CHECK(get->size == 65536); respond(fd, in, 0, NULL, 0); break;
            }
            if (in->opcode == FUSE_GETXATTR && !strcmp(name, "user.query-big")) {
                CHECK(get->size == 0); struct fuse_getxattr_out out = {.size = 70000};
                respond(fd, in, 0, &out, sizeof(out)); break;
            }
            if (in->opcode == FUSE_GETXATTR && !strcmp(name, "user.too-big")) {
                CHECK(get->size == 65536); respond(fd, in, ERANGE, NULL, 0); break;
            }
            if (!strncmp(name, "security.capability", 19) || !strncmp(name, "system.posix_acl_", 17))
                fprintf(stderr, "wire opcode=%u name=%s size=%u flags=%u\n", in->opcode, name, in->opcode == FUSE_REMOVEXATTR ? 0 : get->size, in->opcode == FUSE_SETXATTR ? set->flags : 0);
            if (!strcmp(name, "security.capability") && in->opcode == FUSE_GETXATTR && !strcmp(node->name, "xattr-cap-deny")) { respond(fd, in, EPERM, NULL, 0); break; }
            if (!strcmp(name, "security.capability") && in->opcode == FUSE_REMOVEXATTR && !strcmp(node->name, "xattr-cap-remove-deny")) { respond(fd, in, EPERM, NULL, 0); break; }
            int slot = -1, free_slot = -1;
            for (int i = 0; i < 4; ++i) {
                if (!node->attrs[i].name[0]) free_slot = i;
                if (!strcmp(node->attrs[i].name, name)) slot = i;
            }
            if (in->opcode == FUSE_SETXATTR) {
                CHECK((size_t)size == sizeof(*in) + 8 + strlen(name) + 1 + set->size);
                if (set->flags & XATTR_CREATE && slot >= 0) { respond(fd, in, EEXIST, NULL, 0); break; }
                if (set->flags & XATTR_REPLACE && slot < 0) { respond(fd, in, ENODATA, NULL, 0); break; }
                if (slot < 0) slot = free_slot;
                CHECK(slot >= 0 && strlen(name) < sizeof(node->attrs[slot].name) && set->size <= sizeof(node->attrs[slot].value));
                strcpy(node->attrs[slot].name, name); node->attrs[slot].size = set->size;
                memcpy(node->attrs[slot].value, name + strlen(name) + 1, set->size);
                respond(fd, in, 0, NULL, 0);
            } else if (in->opcode == FUSE_REMOVEXATTR) {
                if (slot < 0) { respond(fd, in, ENODATA, NULL, 0); break; }
                node->attrs[slot].name[0] = 0; respond(fd, in, 0, NULL, 0);
            } else {
                unsigned char data[1024]; size_t count = 0;
                if (in->opcode == FUSE_LISTXATTR) {
                    if (!strcmp(node->name, "xattr-list-bad")) { memcpy(data, "bad", 3); count = 3; }
                    else for (int i = 0; i < 4; ++i) if (node->attrs[i].name[0]) {
                        size_t n = strlen(node->attrs[i].name) + 1; memcpy(data + count, node->attrs[i].name, n); count += n;
                    }
                } else {
                    if (slot < 0) { respond(fd, in, ENODATA, NULL, 0); break; }
                    count = node->attrs[slot].size; memcpy(data, node->attrs[slot].value, count);
                }
                if (!get->size) { struct fuse_getxattr_out out = {.size = count}; respond(fd, in, 0, &out, sizeof(out)); }
                else if (count > get->size) respond(fd, in, ERANGE, NULL, 0);
                else respond(fd, in, 0, data, count);
            }
            break;
        }
        case FUSE_SETATTR: {
            const struct fuse_setattr_in *set = body;
            struct node *node = by_id(in->nodeid); CHECK(node);
            CHECK(size == sizeof(*in) + sizeof(*set));
            fprintf(stderr, "setattr node=%llu valid=%x fh=%llu mode=%o uid=%u gid=%u\n",
                (unsigned long long)in->nodeid, set->valid, (unsigned long long)set->fh,
                set->mode, set->uid, set->gid);
            if (!strcmp(node->name, "attr-denied")) { respond(fd, in, EPERM, NULL, 0); break; }
            struct timespec now; CHECK(clock_gettime(CLOCK_REALTIME, &now) == 0);
            if (set->valid & FATTR_MODE) node->mode = set->mode;
            if (set->valid & FATTR_UID) node->uid = set->uid;
            if (set->valid & FATTR_GID) node->gid = set->gid;
            if (set->valid & FATTR_ATIME) node->times[0] = (set->valid & FATTR_ATIME_NOW) ? now : (struct timespec){set->atime, set->atimensec};
            if (set->valid & FATTR_MTIME) node->times[1] = (set->valid & FATTR_MTIME_NOW) ? now : (struct timespec){set->mtime, set->mtimensec};
            node->times[2] = now;
            struct fuse_attr_out out = { .attr_valid = 1, .attr = attributes(in->nodeid) };
            respond(fd, in, 0, &out, sizeof(out));
            break;
        }
        case FUSE_ACCESS: {
            struct node *node = by_id(in->nodeid);
            CHECK(in->nodeid == 1 || node);
            int error = 0;
            if (node && (!strcmp(node->name, "access-denied") || !strcmp(node->name, "chroot-denied"))) error = EACCES;
            if (node && !strcmp(node->name, "access-readonly"))
                CHECK(mount(NULL, "/fuse-filesystem-test", NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL) == 0);
            if (node && !strcmp(node->name, "access-writable"))
                CHECK(mount(NULL, "/fuse-filesystem-test", NULL, MS_REMOUNT | MS_BIND, NULL) == 0);
            if (node && !strcmp(node->name, "access-unsupported")) {
                CHECK(++unsupported_access == 1);
                error = ENOSYS;
            }
            respond(fd, in, error, NULL, 0);
            break;
        }
        case FUSE_LOOKUP: {
            struct node *node = lookup(in->nodeid, body);
            const char *mask_names[] = { "mask-live", "create-parent-link", "create-live" };
            const char mask_commands[] = { 'm', 'p', 'c' };
            for (unsigned i = 0; i < 3; ++i) if (!strcmp(body, mask_names[i]) && !(mask_events & (1 << i))) {
                char byte;
                mask_events |= 1 << i;
                CHECK(write(changes, &mask_commands[i], 1) == 1);
                CHECK(read(changed, &byte, 1) == 1 && byte == 'm');
            }
            if (!node) {
                respond(fd, in, ENOENT, NULL, 0);
                break;
            }
            entry_reply(fd, in, node, 0);
            break;
        }
        case FUSE_LINK: {
            const struct fuse_link_in *link = body;
            const char *name = (const char *)body + sizeof(*link);
            struct node *source = by_id(link->oldnodeid);
            if (!strcmp(name, "hard-probe-unsupported")) {
                respond(fd, in, ENOSYS, NULL, 0); break;
            }
            CHECK(strcmp(name, "hard-probe-disabled"));
            CHECK(source && !S_ISDIR(source->mode));
            if (lookup(in->nodeid, name)) { respond(fd, in, EEXIST, NULL, 0); break; }
            struct node *alias = create_node(in->nodeid, name, source->mode);
            if (strcmp(name, "hard-probe-mismatch")) {
                alias->id = source->id;
                ++source->links;
            }
            entry_reply(fd, in, alias, 0);
            break;
        }
        case FUSE_CREATE:
        case FUSE_MKNOD:
        case FUSE_MKDIR:
        case FUSE_SYMLINK: {
            const char *name = body;
            unsigned mode = S_IFLNK | 0777;
            if (in->opcode == FUSE_CREATE) {
                const struct fuse_create_in *create = body;
                name += sizeof(*create); mode = create->mode;
                CHECK(!create_disabled);
                if (!strcmp(name, "create-live")) {
                    CHECK((mode & 0777) == 0606 && create->umask == 0070);
                }
                if (!strcmp(name, "fallback")) {
                    char byte;
                    CHECK(write(changes, "f", 1) == 1);
                    CHECK(read(changed, &byte, 1) == 1 && byte == 'm');
                    create_disabled = 1;
                    respond(fd, in, ENOSYS, NULL, 0);
                    break;
                }
            } else if (in->opcode == FUSE_MKNOD) {
                const struct fuse_mknod_in *create = body;
                name += sizeof(*create); mode = create->mode;
                if (!strcmp(name, "fallback")) CHECK((mode & 0777) == 0600 && create->umask == 0077);
            } else if (in->opcode == FUSE_MKDIR) {
                const struct fuse_mkdir_in *create = body;
                name += sizeof(*create); mode = S_IFDIR | create->mode;
            }
            if (lookup(in->nodeid, name)) { respond(fd, in, EEXIST, NULL, 0); break; }
            struct node *node = create_node(in->nodeid, name, mode);
            if (in->opcode == FUSE_SYMLINK) {
                const char *link = name + strlen(name) + 1;
                CHECK(strlen(link) < sizeof(node->link));
                strcpy(node->link, link);
            }
            entry_reply(fd, in, node, in->opcode == FUSE_CREATE);
            break;
        }
        case FUSE_READLINK: {
            struct node *node = by_id(in->nodeid);
            CHECK(node && S_ISLNK(node->mode));
            if (!strcmp(node->name, "hard-parent-rename") && !node->data[0]) {
                node->data[0] = 1;
                CHECK(rename("/fuse-hard-ordinary/source", "/fuse-hard-ordinary/moved") == 0);
                int replaced = open("/fuse-hard-ordinary/source", O_CREAT | O_EXCL | O_RDWR, 0600);
                CHECK(replaced >= 0 && close(replaced) == 0);
            }
            if (!strcmp(node->name, "parent-rename-link") && !node->data[0]) {
                CHECK(rename("/fuse-rename-parent", "/fuse-rename-moved") == 0);
                CHECK(mkdir("/fuse-rename-parent", 0700) == 0 && mkdir("/fuse-rename-parent/target", 0700) == 0);
                node->data[0] = 1;
            }
            respond(fd, in, 0, node->link, !strcmp(node->name, "empty-link") ? 0 : strlen(node->link));
            break;
        }
        case FUSE_UNLINK:
        case FUSE_RMDIR: {
            struct node *node = lookup(in->nodeid, body);
            if (!node) { respond(fd, in, ENOENT, NULL, 0); break; }
            int error = 0;
            if (in->opcode == FUSE_RMDIR && !S_ISDIR(node->mode)) error = ENOTDIR;
            if (in->opcode == FUSE_UNLINK && S_ISDIR(node->mode)) error = EISDIR;
            if (in->opcode == FUSE_RMDIR) for (unsigned i = 0; i < MAX_NODES; ++i)
                if (nodes[i].active && nodes[i].parent == node->id) error = ENOTEMPTY;
            if (!error) {
                struct node *inode = by_id(node->id);
                CHECK(inode && inode->links);
                --inode->links;
                node->active = 0;
            }
            respond(fd, in, error, NULL, 0);
            break;
        }
        case FUSE_RENAME:
        case FUSE_RENAME2: {
            const struct fuse_rename2_in *rename = body;
            unsigned flags = in->opcode == FUSE_RENAME2 ? rename->flags : 0;
            const char *old = (const char *)body + (in->opcode == FUSE_RENAME2 ? sizeof(*rename) : sizeof(struct fuse_rename_in));
            const char *name = old + strlen(old) + 1;
            struct node *source = lookup(in->nodeid, old), *dest = lookup(rename->newdir, name);
            if (!source || (flags == 2 && !dest)) { respond(fd, in, ENOENT, NULL, 0); break; }
            if (flags == 1 && dest) { respond(fd, in, EEXIST, NULL, 0); break; }
            if (flags == 2) {
                dest->parent = source->parent;
                strcpy(dest->name, old);
            } else if (dest) dest->active = 0;
            source->parent = rename->newdir;
            CHECK(strlen(name) < sizeof(source->name));
            strcpy(source->name, name);
            respond(fd, in, 0, NULL, 0);
            break;
        }
        case FUSE_OPEN:
        case FUSE_OPENDIR: {
            struct fuse_open_out out = { .fh = in->nodeid == 1 ? 731 : in->nodeid + 10000,
                .open_flags = in->nodeid == 1 ? 0 : FOPEN_DIRECT_IO };
            respond(fd, in, 0, &out, sizeof(out));
            break;
        }
        case FUSE_READDIR: {
            const struct fuse_read_in *read = body;
            CHECK(read->fh == 731);
            unsigned char entries[64] = {0};
            size_t used = 0;
            if (read->offset == 0) used += add_entry(entries, 10, 9, 'a');
            if (read->offset == 0 || read->offset == 9)
                used += add_entry(entries + used, 11, 777, 'b');
            CHECK(used <= read->size);
            respond(fd, in, 0, entries, used);
            break;
        }
        case FUSE_WRITE: {
            const struct fuse_write_in *write = body;
            struct node *node = by_id(in->nodeid);
            CHECK(node && write->fh == in->nodeid + 10000 && write->size <= 16 * 1024);
            CHECK(sizeof(*in) + sizeof(*write) + write->size == (size_t)size);
            size_t count = write->size > 8193 ? 8193 : write->size;
            CHECK(write->offset + count <= sizeof(node->data));
            memcpy(node->data + write->offset, (const unsigned char *)body + sizeof(*write), count);
            if (write->offset + count > node->size) node->size = write->offset + count;
            struct fuse_write_out out = { .size = count };
            respond(fd, in, 0, &out, sizeof(out));
            break;
        }
        case FUSE_READ: {
            const struct fuse_read_in *read = body;
            struct node *node = by_id(in->nodeid);
            CHECK(node && read->fh == in->nodeid + 10000);
            size_t count = read->offset >= node->size ? 0 : node->size - read->offset;
            if (count > read->size) count = read->size;
            respond(fd, in, 0, node->data + (count ? read->offset : 0), count);
            break;
        }
        case FUSE_FORGET:
        case FUSE_BATCH_FORGET:
            break;
        case FUSE_RELEASE:
        case FUSE_RELEASEDIR:
            respond(fd, in, 0, NULL, 0);
            if (++released == EXPECT_RELEASED) CHECK(write(completed, "r", 1) == 1);
            break;
        case FUSE_DESTROY:
            CHECK(released == EXPECT_RELEASED);
            respond(fd, in, 0, NULL, 0);
            _exit(0);
            break;
        case FUSE_FLUSH:
        case FUSE_FSYNC:
        case FUSE_FSYNCDIR:
            respond(fd, in, 0, NULL, 0);
            break;
        default:
            respond(fd, in, ENOSYS, NULL, 0);
        }
    }
}

static void directory_anchor_checks(void) {
    const char *parent = "/fuse-ordinary-parent", *moved = "/fuse-ordinary-moved";
    CHECK(mkdir(parent, 0755) == 0 && mkdir(moved, 0755) == 0);
    CHECK(mkdir("/fuse-ordinary-parent/dir", 0755) == 0 && mkdir("/fuse-ordinary-parent/dir/leaf", 0700) == 0);
    CHECK(mkdir("/fuse-ordinary-parent/peer", 0700) == 0 && mkdir("/fuse-ordinary-moved/peer", 0700) == 0);
    int fd = open("/fuse-ordinary-parent/dir", O_PATH | O_DIRECTORY);
    CHECK(fd >= 0);
    struct stat leaf, peer, st;
    CHECK(stat("/fuse-ordinary-parent/dir/leaf", &leaf) == 0 && stat("/fuse-ordinary-moved/peer", &peer) == 0);
    char target[128]; snprintf(target, sizeof(target), "/proc/self/fd/%d", fd);
    const char *proxy = "/fuse-filesystem-test/directory-anchor";
    CHECK(symlink(target, proxy) == 0);
    CHECK(rename("/fuse-ordinary-parent/dir", "/fuse-ordinary-moved/dir") == 0);
    CHECK(mkdir("/fuse-ordinary-parent/dir", 0755) == 0 && mkdir("/fuse-ordinary-parent/dir/leaf", 0700) == 0);
    CHECK(stat("/fuse-filesystem-test/directory-anchor/leaf", &st) == 0 && st.st_ino == leaf.st_ino);
    CHECK(stat("/fuse-filesystem-test/directory-anchor/../peer", &st) == 0 && st.st_ino == peer.st_ino);
    int alias = open("/fuse-filesystem-test/directory-anchor/leaf/.", O_PATH | O_DIRECTORY);
    CHECK(alias >= 0 && fstat(alias, &st) == 0 && st.st_ino == leaf.st_ino && close(alias) == 0);
    CHECK(chdir("/fuse-filesystem-test/directory-anchor/../peer") == 0);
    char cwd[256]; CHECK(getcwd(cwd, sizeof(cwd)) == cwd && !strcmp(cwd, "/fuse-ordinary-moved/peer"));
    CHECK(chdir("/") == 0);
    CHECK(mkdir("/fuse-filesystem-test/directory-anchor/new", 0700) == 0);
    CHECK(mknod("/fuse-filesystem-test/directory-anchor/file", S_IFREG | 0600, 0) == 0);
    CHECK(rename("/fuse-filesystem-test/directory-anchor/file", "/fuse-filesystem-test/directory-anchor/renamed") == 0);
    CHECK(unlink("/fuse-filesystem-test/directory-anchor/renamed") == 0 && rmdir("/fuse-filesystem-test/directory-anchor/new") == 0);
    CHECK(symlink("../peer", "/fuse-filesystem-test/directory-anchor/link") == 0);
    CHECK(stat("/fuse-filesystem-test/directory-anchor/link", &st) == 0 && st.st_ino == peer.st_ino);
    CHECK(unlink("/fuse-filesystem-test/directory-anchor/link") == 0);
    CHECK(mkdir("/fuse-ordinary-moved/dir/cover", 0700) == 0);
    CHECK(mount("tmpfs", "/fuse-ordinary-moved/dir/cover", "tmpfs", 0, NULL) == 0);
    CHECK(mkdir("/fuse-ordinary-moved/dir/cover/inside", 0700) == 0);
    CHECK(stat("/fuse-filesystem-test/directory-anchor/cover/inside", &st) == 0 && S_ISDIR(st.st_mode));
    CHECK(rmdir("/fuse-filesystem-test/directory-anchor/cover/inside") == 0);
    CHECK(umount("/fuse-ordinary-moved/dir/cover") == 0 && rmdir("/fuse-ordinary-moved/dir/cover") == 0);
    CHECK(unlink(proxy) == 0 && close(fd) == 0);
    CHECK(rmdir("/fuse-ordinary-parent/dir/leaf") == 0 && rmdir("/fuse-ordinary-parent/dir") == 0);
    CHECK(rmdir("/fuse-ordinary-moved/dir/leaf") == 0 && rmdir("/fuse-ordinary-moved/dir") == 0);
    CHECK(rmdir("/fuse-ordinary-parent/peer") == 0 && rmdir("/fuse-ordinary-moved/peer") == 0);
    CHECK(rmdir(parent) == 0 && rmdir(moved) == 0);
}

static void file_bind_checks(void) {
    const char *source = "/fuse-filesystem-test/bind-source", *bound = "/fuse-bind-bound";
    CHECK(mknod(source, S_IFREG | 0600, 0) == 0);
    int fd = open(source, O_RDWR), local = open(bound, O_CREAT | O_RDWR, 0600);
    CHECK(fd >= 0 && local >= 0 && close(local) == 0 && write(fd, "remote", 6) == 6);
    struct stat expected, actual;
    CHECK(fstat(fd, &expected) == 0);
    int tree = syscall(SYS_open_tree, fd, "", 1 | AT_EMPTY_PATH);
    CHECK(tree >= 0 && syscall(SYS_move_mount, tree, "", AT_FDCWD, bound, 4) == 0);
    CHECK(close(tree) == 0 && stat(bound, &actual) == 0 && actual.st_ino == expected.st_ino);
    CHECK(umount(bound) == 0 && mount(source, bound, NULL, MS_BIND, NULL) == 0);
    CHECK(stat(bound, &actual) == 0 && actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino);
    int path = open(bound, O_PATH);
    CHECK(path >= 0 && fstat(path, &actual) == 0 && actual.st_ino == expected.st_ino && close(path) == 0);
    CHECK(umount(bound) == 0);
    char proc[128]; snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
    CHECK(mount(proc, bound, NULL, MS_BIND, NULL) == 0 && close(fd) == 0);
    fd = open(bound, O_RDWR);
    char bytes[8];
    CHECK(fd >= 0 && pread(fd, bytes, 6, 0) == 6 && !memcmp(bytes, "remote", 6));
    CHECK(pwrite(fd, "bound", 5, 0) == 5 && unlink(source) == 0 && close(fd) == 0);
    fd = open(bound, O_RDONLY);
    CHECK(fd >= 0 && read(fd, bytes, 6) == 6 && !memcmp(bytes, "bounde", 6) && close(fd) == 0);
    CHECK(mount(NULL, bound, NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL) == 0);
    errno = 0; CHECK(open(bound, O_RDWR) == -1 && errno == EROFS);
    CHECK(umount(bound) == 0 && unlink(bound) == 0);
    const char *target = "/fuse-filesystem-test/bind-target", *plain = "/fuse-bind-local";
    CHECK(mknod(target, S_IFREG | 0600, 0) == 0);
    fd = open(plain, O_CREAT | O_RDWR, 0600);
    CHECK(fd >= 0 && write(fd, "local", 5) == 5 && close(fd) == 0);
    CHECK(mount(plain, target, NULL, MS_BIND, NULL) == 0);
    fd = open(target, O_RDONLY);
    CHECK(fd >= 0 && read(fd, bytes, 5) == 5 && !memcmp(bytes, "local", 5) && close(fd) == 0);
    CHECK(umount(target) == 0 && unlink(target) == 0 && unlink(plain) == 0);
}

static void mount_fd_checks(void) {
    const char *base = "/fuse-mount-fd-base", *target = "/fuse-mount-fd-target";
    const char *link = "/fuse-filesystem-test/mount-fd-link";
    const char *attached = "/fuse-filesystem-test/mount-fd-attached";
    const char *cover = "/fuse-filesystem-test/mount-fd-cover";
    CHECK(mkdir(base, 0700) == 0 && mkdir(target, 0700) == 0);
    CHECK(mkdir("/fuse-mount-fd-base/marker", 0700) == 0);
    struct stat expected, actual;
    CHECK(stat("/fuse-mount-fd-base/marker", &expected) == 0);
    CHECK(symlink(base, link) == 0);
    int symlink_tree = syscall(SYS_open_tree, AT_FDCWD, link, 1 | 0x100);
    CHECK(symlink_tree >= 0 && fstat(symlink_tree, &actual) == 0 && S_ISLNK(actual.st_mode));
    char link_target[256];
    CHECK(readlinkat(symlink_tree, "", link_target, sizeof(link_target)) == (ssize_t)strlen(base));
    CHECK(!memcmp(link_target, base, strlen(base)) && close(symlink_tree) == 0);

    int tree = syscall(SYS_open_tree, AT_FDCWD, link, 1 | O_CLOEXEC);
    CHECK(tree >= 0 && (fcntl(tree, F_GETFD) & FD_CLOEXEC));
    struct { uint64_t set, clear, propagation, userns; } attrs = { .set = 1 };
    CHECK(syscall(SYS_mount_setattr, tree, "", AT_EMPTY_PATH, &attrs, sizeof(attrs)) == 0);
    CHECK(syscall(SYS_move_mount, tree, "", AT_FDCWD, target, 4) == 0 && close(tree) == 0);
    errno = 0; CHECK(mkdir("/fuse-mount-fd-target/denied", 0700) == -1 && errno == EROFS);
    CHECK(symlink(target, attached) == 0);
    attrs.set = 0; attrs.clear = 1;
    CHECK(syscall(SYS_mount_setattr, AT_FDCWD, attached, 0, &attrs, sizeof(attrs)) == 0);
    CHECK(mkdir("/fuse-mount-fd-target/allowed", 0700) == 0 && rmdir("/fuse-mount-fd-target/allowed") == 0);
    CHECK(mkdir(cover, 0700) == 0);
    CHECK(syscall(SYS_move_mount, AT_FDCWD, attached, AT_FDCWD, cover, 1) == 0);
    CHECK(stat("/fuse-filesystem-test/mount-fd-cover/marker", &actual) == 0 && actual.st_ino == expected.st_ino);
    CHECK(umount(cover) == 0 && rmdir(cover) == 0);
    CHECK(unlink(link) == 0 && unlink(attached) == 0);
    CHECK(rmdir("/fuse-mount-fd-base/marker") == 0 && rmdir(base) == 0 && rmdir(target) == 0);

    const char *directory = "/fuse-filesystem-test/mount-fd-directory";
    CHECK(mkdir(directory, 0700) == 0 && mkdir(target, 0700) == 0);
    tree = syscall(SYS_open_tree, AT_FDCWD, directory, 1);
    CHECK(tree >= 0);
    int view = syscall(SYS_open_tree, AT_FDCWD, directory, O_CLOEXEC);
    CHECK(view >= 0 && fstat(view, &expected) == 0 && S_ISDIR(expected.st_mode) && close(view) == 0);
    CHECK(syscall(SYS_move_mount, tree, "", AT_FDCWD, target, 4) == 0 && close(tree) == 0);
    CHECK(stat(target, &actual) == 0 && actual.st_ino == expected.st_ino);
    CHECK(umount(target) == 0 && rmdir(target) == 0 && rmdir(directory) == 0);
}

static void symlink_inode_checks(void) {
    const char *parent = "/fuse-link-parent", *target = "/fuse-link-parent/target";
    const char *source = "/fuse-filesystem-test/inode-link", *alias = "/fuse-link-parent/alias";
    CHECK(mkdir(parent, 0700) == 0 && mkdir(target, 0700) == 0);
    struct stat expected, actual;
    CHECK(stat(target, &expected) == 0);
    const char *texts[] = { "target", "/fuse-link-parent/target" };
    for (unsigned i = 0; i < 2; ++i) {
        const char *text = texts[i];
        CHECK(symlink(text, source) == 0);
        int view = syscall(SYS_open_tree, AT_FDCWD, source, 0x100 | O_CLOEXEC);
        CHECK(view >= 0 && fstat(view, &actual) == 0 && S_ISLNK(actual.st_mode));
        CHECK(unlink(source) == 0 && symlink("replacement", source) == 0);
        char bytes[256];
        CHECK(readlinkat(view, "", bytes, sizeof(bytes)) == (ssize_t)strlen(text) && !memcmp(bytes, text, strlen(text)));
        CHECK(close(view) == 0 && unlink(source) == 0 && symlink(text, source) == 0);
        int tree = syscall(SYS_open_tree, AT_FDCWD, source, 1 | 0x100);
        struct { uint64_t set, clear, propagation, userns; } attrs = { .set = 1 };
        CHECK(tree >= 0 && syscall(SYS_mount_setattr, tree, "", AT_EMPTY_PATH, &attrs, sizeof(attrs)) == 0);
        int plain = open(alias, O_CREAT | O_RDWR, 0600);
        CHECK(tree >= 0 && plain >= 0 && close(plain) == 0);
        CHECK(syscall(SYS_move_mount, tree, "", AT_FDCWD, alias, 4) == 0 && close(tree) == 0);
        CHECK(unlink(source) == 0 && symlink("replacement", source) == 0);
        CHECK(lstat(alias, &actual) == 0 && S_ISLNK(actual.st_mode));
        CHECK(stat(alias, &actual) == 0 && actual.st_ino == expected.st_ino && S_ISDIR(actual.st_mode));
        CHECK(readlink(alias, bytes, sizeof(bytes)) == (ssize_t)strlen(text) && !memcmp(bytes, text, strlen(text)));
        view = open(alias, O_PATH | O_NOFOLLOW);
        CHECK(view >= 0 && readlinkat(view, "", bytes, sizeof(bytes)) == (ssize_t)strlen(text) && !memcmp(bytes, text, strlen(text)) && close(view) == 0);
        errno = 0; CHECK(open(alias, O_RDONLY | O_NOFOLLOW) == -1 && errno == ELOOP);
        CHECK(mkdir("/fuse-link-parent/alias/created", 0700) == 0);
        CHECK(stat("/fuse-link-parent/target/created", &actual) == 0 && S_ISDIR(actual.st_mode));
        CHECK(rmdir("/fuse-link-parent/alias/created") == 0);
        view = open(alias, O_RDONLY | O_DIRECTORY);
        CHECK(view >= 0 && fchdir(view) == 0 && close(view) == 0);
        char cwd[256]; CHECK(getcwd(cwd, sizeof(cwd)) == cwd && !strcmp(cwd, target));
        CHECK(chdir("/") == 0 && umount2(alias, 8 /* UMOUNT_NOFOLLOW */) == 0);
        CHECK(unlink(alias) == 0 && unlink(source) == 0);
    }
    CHECK(rmdir(target) == 0 && rmdir(parent) == 0);
}

static void renamed_symlink_parent_checks(void) {
    const char *source = "/fuse-filesystem-test/parent-rename-link";
    CHECK(mkdir("/fuse-rename-parent", 0700) == 0 && mkdir("/fuse-rename-parent/target", 0700) == 0);
    CHECK(symlink("target", source) == 0);
    int tree = syscall(SYS_open_tree, AT_FDCWD, source, 1 | 0x100);
    int plain = open("/fuse-rename-parent/alias", O_CREAT | O_RDWR, 0600);
    CHECK(tree >= 0 && plain >= 0 && close(plain) == 0);
    CHECK(syscall(SYS_move_mount, tree, "", AT_FDCWD, "/fuse-rename-parent/alias", 4) == 0 && close(tree) == 0);
    CHECK(mkdir("/fuse-rename-parent/alias/new", 0700) == 0);
    struct stat st;
    CHECK(stat("/fuse-rename-moved/target/new", &st) == 0 && S_ISDIR(st.st_mode));
    errno = 0; CHECK(stat("/fuse-rename-parent/target/new", &st) == -1 && errno == ENOENT);
    CHECK(umount2("/fuse-rename-moved/alias", 8) == 0 && unlink("/fuse-rename-moved/alias") == 0);
    CHECK(unlink(source) == 0 && rmdir("/fuse-rename-moved/target/new") == 0);
    CHECK(rmdir("/fuse-rename-moved/target") == 0 && rmdir("/fuse-rename-moved") == 0);
    CHECK(rmdir("/fuse-rename-parent/target") == 0 && rmdir("/fuse-rename-parent") == 0);
}

static void topology_checks(void) {
    const char *base = "/fuse-topology", *proxy = "/fuse-filesystem-test/topology";
    CHECK(mkdir(base, 0755) == 0 && mkdir("/fuse-topology/source", 0755) == 0 && mkdir("/fuse-topology/target", 0755) == 0);
    CHECK(symlink(base, proxy) == 0);
    CHECK(mount("tmpfs", "/fuse-filesystem-test/topology/target", "tmpfs", 0, NULL) == 0);
    CHECK(mkdir("/fuse-filesystem-test/topology/target/inside", 0700) == 0);
    CHECK(mount(NULL, "/fuse-filesystem-test/topology/target", NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL) == 0);
    errno = 0; CHECK(mkdir("/fuse-filesystem-test/topology/target/denied", 0700) == -1 && errno == EROFS);
    CHECK(mount(NULL, "/fuse-filesystem-test/topology/target", NULL, MS_REMOUNT | MS_BIND, NULL) == 0);
    CHECK(rmdir("/fuse-filesystem-test/topology/target/inside") == 0 && umount("/fuse-filesystem-test/topology/target") == 0);
    CHECK(mkdir("/fuse-topology/source/inside", 0700) == 0);
    struct stat expected, actual;
    CHECK(stat("/fuse-topology/source/inside", &expected) == 0);
    CHECK(mount("/fuse-filesystem-test/topology/source", "/fuse-filesystem-test/topology/target", NULL, MS_BIND, NULL) == 0);
    CHECK(stat("/fuse-filesystem-test/topology/target/inside", &actual) == 0 && actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino);
    CHECK(umount("/fuse-filesystem-test/topology/target") == 0 && rmdir("/fuse-topology/source/inside") == 0);
    CHECK(mount("tmpfs", "/fuse-filesystem-test/topology/source", "tmpfs", 0, NULL) == 0);
    CHECK(mkdir("/fuse-filesystem-test/topology/source/inside", 0700) == 0 && stat("/fuse-topology/source/inside", &expected) == 0);
    CHECK(mount("/fuse-filesystem-test/topology/source", "/fuse-filesystem-test/topology/target", NULL, MS_MOVE, NULL) == 0);
    CHECK(stat("/fuse-filesystem-test/topology/target/inside", &actual) == 0 && actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino);
    CHECK(rmdir("/fuse-filesystem-test/topology/target/inside") == 0 && umount("/fuse-filesystem-test/topology/target") == 0);
    errno = 0; CHECK(umount2(proxy, 8 /* UMOUNT_NOFOLLOW */) == -1 && errno == EINVAL);
    const char *cover = "/fuse-filesystem-test/topology-cover";
    CHECK(mkdir(cover, 0700) == 0 && mount("tmpfs", cover, "tmpfs", 0, NULL) == 0);
    CHECK(mkdir("/fuse-filesystem-test/topology-cover/inside", 0700) == 0 && rmdir("/fuse-filesystem-test/topology-cover/inside") == 0);
    CHECK(umount(cover) == 0 && rmdir(cover) == 0);
    CHECK(unlink(proxy) == 0 && rmdir("/fuse-topology/source") == 0 && rmdir("/fuse-topology/target") == 0 && rmdir(base) == 0);
}

static void access_checks(void) {
    const char *denied = "/fuse-filesystem-test/access-denied";
    const char *proxy = "/fuse-filesystem-test/access-proxy";
    char target[128];
    for (int directory = 0; directory < 2; ++directory) {
        if (directory) CHECK(mkdir(denied, 0700) == 0);
        else CHECK(mknod(denied, S_IFREG | 0600, 0) == 0);
        int source = open(denied, O_PATH | (directory ? O_DIRECTORY : 0));
        CHECK(source >= 0);
        snprintf(target, sizeof(target), "/proc/self/fd/%d", source);
        CHECK(symlink(target, proxy) == 0);
        errno = 0; CHECK(access(proxy, directory ? X_OK : R_OK) == -1 && errno == EACCES);
        errno = 0; CHECK(access(proxy, F_OK) == -1 && errno == EACCES);
        errno = 0; CHECK(chdir(proxy) == -1 && errno == (directory ? EACCES : ENOTDIR));
        CHECK(mount(NULL, "/fuse-filesystem-test", NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL) == 0);
        errno = 0; CHECK(access(proxy, W_OK) == -1 && errno == EACCES);
        CHECK(mount(NULL, "/fuse-filesystem-test", NULL, MS_REMOUNT | MS_BIND, NULL) == 0);
        CHECK(unlink(proxy) == 0 && close(source) == 0);
        if (directory) CHECK(rmdir(denied) == 0);
        else CHECK(unlink(denied) == 0);
    }
    for (int anonymous = 0; anonymous < 2; ++anonymous) {
        int source = anonymous ? eventfd(0, 0) : syscall(SYS_memfd_create, "access-original", 0);
        CHECK(source >= 0);
        if (!anonymous) CHECK(fchmod(source, 0600) == 0);
        snprintf(target, sizeof(target), "/proc/self/fd/%d", source);
        CHECK(symlink(target, proxy) == 0);
        CHECK(access(proxy, F_OK) == 0 && access(proxy, R_OK | W_OK) == 0);
        errno = 0; CHECK(access(proxy, X_OK) == -1 && errno == EACCES);
        errno = 0; CHECK(chdir(proxy) == -1 && errno == ENOTDIR);
        CHECK(unlink(proxy) == 0 && close(source) == 0);
    }
    const char *device = "/fuse-filesystem-test/access-device";
    CHECK(mknod(device, S_IFCHR | 0600, 0) == 0);
    CHECK(mount(NULL, "/fuse-filesystem-test", NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL) == 0);
    errno = 0; CHECK(access("/fuse-filesystem-test/data", W_OK) == -1 && errno == EROFS);
    CHECK(access("/fuse-filesystem-test/data", F_OK) == 0);
    CHECK(access(device, W_OK) == 0);
    CHECK(mount(NULL, "/fuse-filesystem-test", NULL, MS_REMOUNT | MS_BIND | MS_NOEXEC, NULL) == 0);
    errno = 0; CHECK(access("/fuse-filesystem-test/data", X_OK) == -1 && errno == EACCES);
    CHECK(access("/fuse-filesystem-test", X_OK) == 0);
    CHECK(mount(NULL, "/fuse-filesystem-test", NULL, MS_REMOUNT | MS_BIND, NULL) == 0);
    CHECK(unlink(device) == 0);
    const char *removed = "/fuse-filesystem-test/chdir-removed";
    CHECK(mkdir(removed, 0700) == 0);
    int source = open(removed, O_PATH | O_DIRECTORY);
    CHECK(source >= 0);
    snprintf(target, sizeof(target), "/proc/self/fd/%d", source);
    CHECK(symlink(target, proxy) == 0 && rmdir(removed) == 0);
    CHECK(chdir(proxy) == 0);
    char cwd[256];
    errno = 0; CHECK(getcwd(cwd, sizeof(cwd)) == NULL && errno == ENOENT);
    CHECK(chdir("..") == 0 && getcwd(cwd, sizeof(cwd)) == cwd && !strcmp(cwd, "/fuse-filesystem-test"));
    CHECK(chdir("/") == 0 && close(source) == 0 && unlink(proxy) == 0);
    const char *readonly = "/fuse-filesystem-test/access-readonly";
    const char *writable = "/fuse-filesystem-test/access-writable";
    CHECK(mknod(readonly, S_IFREG | 0600, 0) == 0 && mknod(writable, S_IFREG | 0600, 0) == 0);
    errno = 0; CHECK(access(readonly, W_OK) == -1 && errno == EROFS);
    CHECK(access(writable, W_OK) == 0);
    CHECK(unlink(readonly) == 0 && unlink(writable) == 0);
    const char *unsupported = "/fuse-filesystem-test/access-unsupported";
    CHECK(mknod(unsupported, S_IFREG | 0600, 0) == 0);
    CHECK(access(unsupported, R_OK) == 0 && access(unsupported, R_OK) == 0);
    CHECK(unlink(unsupported) == 0);
}

static void hardlink_checks(void) {
    const char *data = "/fuse-filesystem-test/data";
    const char *alias = "/fuse-filesystem-test/hard-alias";
    struct stat a, b;
    CHECK(link(data, alias) == 0);
    CHECK(stat(data, &a) == 0 && stat(alias, &b) == 0 && a.st_ino == b.st_ino);
    CHECK(a.st_nlink == 2 && b.st_nlink == 2);
    errno = 0; CHECK(link(data, alias) == -1 && errno == EEXIST);
    CHECK(unlink(alias) == 0 && stat(data, &a) == 0 && a.st_nlink == 1);
    int source = open(data, O_PATH);
    CHECK(source >= 0);
    CHECK(linkat(source, "", AT_FDCWD, alias, AT_EMPTY_PATH) == 0);
    CHECK(close(source) == 0 && stat(alias, &a) == 0 && a.st_nlink == 2);
    CHECK(unlink(alias) == 0);
    const char *sym = "/fuse-filesystem-test/hard-sym";
    CHECK(symlink("data", sym) == 0 && link(sym, alias) == 0);
    CHECK(lstat(sym, &a) == 0 && lstat(alias, &b) == 0 && S_ISLNK(b.st_mode));
    CHECK(a.st_ino == b.st_ino && a.st_nlink == 2 && b.st_nlink == 2);
    const char *followed = "/fuse-filesystem-test/hard-followed";
    CHECK(linkat(AT_FDCWD, sym, AT_FDCWD, followed, AT_SYMLINK_FOLLOW) == 0);
    CHECK(stat(data, &a) == 0 && lstat(followed, &b) == 0 && a.st_ino == b.st_ino && S_ISREG(b.st_mode));
    CHECK(unlink(sym) == 0 && lstat(alias, &a) == 0 && a.st_nlink == 1);
    char target[8]; CHECK(readlink(alias, target, sizeof(target)) == 4 && !memcmp(target, "data", 4));
    CHECK(unlink(alias) == 0 && unlink(followed) == 0);
    errno = 0; CHECK(link(data, "/hard-cross-mount") == -1 && errno == EXDEV);
    errno = 0; CHECK(link("/fuse-filesystem-test/parent", alias) == -1 && errno == EPERM);
    CHECK(mkdir("/fuse-hard-ordinary", 0700) == 0);
    CHECK(mount("tmpfs", "/fuse-hard-ordinary", "tmpfs", 0, NULL) == 0);
    int ordinary = open("/fuse-hard-ordinary/source", O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(ordinary >= 0 && fstat(ordinary, &a) == 0 && close(ordinary) == 0);
    CHECK(symlink("/fuse-hard-ordinary", "/fuse-filesystem-test/hard-parent-rename") == 0);
    CHECK(link("/fuse-hard-ordinary/source", "/fuse-filesystem-test/hard-parent-rename/alias") == 0);
    CHECK(stat("/fuse-hard-ordinary/alias", &b) == 0 && a.st_ino == b.st_ino);
    CHECK(stat("/fuse-hard-ordinary/source", &b) == 0 && a.st_ino != b.st_ino);
    CHECK(unlink("/fuse-hard-ordinary/alias") == 0 && unlink("/fuse-hard-ordinary/moved") == 0 && unlink("/fuse-hard-ordinary/source") == 0);
    CHECK(unlink("/fuse-filesystem-test/hard-parent-rename") == 0);
    CHECK(umount("/fuse-hard-ordinary") == 0 && rmdir("/fuse-hard-ordinary") == 0);
    const char *unsafe = "/fuse-filesystem-test/hard-protected";
    CHECK(mknod(unsafe, S_IFREG | 04600, 0) == 0);
    pid_t foreign = fork(); CHECK(foreign >= 0);
    if (!foreign) {
        CHECK(setresgid(1000,1000,1000) == 0 && setresuid(1000,1000,1000) == 0);
        CHECK(link(data, "/fuse-filesystem-test/hard-foreign") == 0);
        CHECK(unlink("/fuse-filesystem-test/hard-foreign") == 0);
        errno = 0; CHECK(link(unsafe, "/fuse-filesystem-test/hard-foreign-unsafe") == -1 && errno == EPERM);
        _exit(0);
    }
    int foreign_status;
    CHECK(waitpid(foreign, &foreign_status, 0) == foreign && WIFEXITED(foreign_status) && WEXITSTATUS(foreign_status) == 0);
    CHECK(unlink(unsafe) == 0);
    // Linux accepts a same-type LINK entry with another nodeid.
    const char *mismatch = "/fuse-filesystem-test/hard-probe-mismatch";
    CHECK(link(data, mismatch) == 0 && unlink(mismatch) == 0);
    const char *dead = "/fuse-filesystem-test/hard-probe-dead";
    CHECK(mknod(dead, S_IFREG | 0600, 0) == 0);
    int deadfd = open(dead, O_PATH); CHECK(deadfd >= 0 && unlink(dead) == 0);
    errno = 0; CHECK(linkat(deadfd, "", AT_FDCWD, alias, AT_EMPTY_PATH) == -1 && errno == ENOENT);
    CHECK(close(deadfd) == 0);
    errno = 0; CHECK(link(data, "/fuse-filesystem-test/hard-probe-unsupported") == -1 && errno == EPERM);
    errno = 0; CHECK(link(data, "/fuse-filesystem-test/hard-probe-disabled") == -1 && errno == EPERM);
    errno = 0; CHECK(link("/bin/sh", alias) == -1 && errno == EXDEV);
}

static void attribute_checks(void) {
    const char *path = "/fuse-filesystem-test/attr-file";
    struct stat st;
    CHECK(mknod(path, S_IFREG | 0600, 0) == 0);
    CHECK(chmod(path, 0671) == 0 && stat(path, &st) == 0 && (st.st_mode & 07777) == 0671);
    CHECK(chown(path, 123, 456) == 0 && stat(path, &st) == 0 && st.st_uid == 123 && st.st_gid == 456);
    struct timespec times[2] = {{123456789, 123}, {234567890, 456}};
    CHECK(utimensat(AT_FDCWD, path, times, 0) == 0 && stat(path, &st) == 0);
    CHECK(st.st_atim.tv_sec == times[0].tv_sec && st.st_atim.tv_nsec == times[0].tv_nsec);
    CHECK(st.st_mtim.tv_sec == times[1].tv_sec && st.st_mtim.tv_nsec == times[1].tv_nsec);
    int file = open(path, O_RDONLY); CHECK(file >= 0);
    CHECK(fchmod(file, 04700) == 0 && fstat(file, &st) == 0 && (st.st_mode & 07777) == 04700);
    CHECK(fchown(file, 0, 0) == 0 && fstat(file, &st) == 0 && st.st_uid == 0 && !(st.st_mode & 06000));
    times[0].tv_nsec = UTIME_OMIT; times[1] = (struct timespec){345678901, 789};
    CHECK(futimens(file, times) == 0 && fstat(file, &st) == 0);
    CHECK(st.st_atim.tv_sec == 123456789 && st.st_mtim.tv_sec == 345678901 && st.st_mtim.tv_nsec == 789);
    CHECK(close(file) == 0);
    int only = open(path, O_PATH); CHECK(only >= 0);
    CHECK(syscall(SYS_fchmodat2, only, "", 0610, AT_EMPTY_PATH) == 0);
    CHECK(fchownat(only, "", 17, 18, AT_EMPTY_PATH) == 0);
    CHECK(fstat(only, &st) == 0 && (st.st_mode & 07777) == 0610 && st.st_uid == 17 && st.st_gid == 18);
    CHECK(close(only) == 0);
    const char *sym = "/fuse-filesystem-test/attr-sym";
    CHECK(symlink("attr-file", sym) == 0 && lchown(sym, 77, 88) == 0);
    CHECK(lstat(sym, &st) == 0 && S_ISLNK(st.st_mode) && st.st_uid == 77 && st.st_gid == 88);
    errno = 0; CHECK(syscall(SYS_fchmodat2, AT_FDCWD, sym, 0600, AT_SYMLINK_NOFOLLOW) == -1 && errno == EOPNOTSUPP);
    const char *denied = "/fuse-filesystem-test/attr-denied";
    CHECK(mknod(denied, S_IFREG | 0600, 0) == 0);
    errno = 0; CHECK(chmod(denied, 0777) == -1 && errno == EPERM);
    CHECK(stat(denied, &st) == 0 && (st.st_mode & 07777) == 0600);
    const char *directory = "/fuse-filesystem-test/attr-dir";
    CHECK(mkdir(directory, 0755) == 0);
    int dir = open(directory, O_PATH | O_DIRECTORY); CHECK(dir >= 0);
    CHECK(chmod(directory, 0700) == 0);
    struct statx cached;
    CHECK(syscall(SYS_statx, dir, "", AT_EMPTY_PATH | AT_STATX_DONT_SYNC, STATX_MODE, &cached) == 0);
    CHECK((cached.stx_mode & 07777) == 0700);
    CHECK(close(dir) == 0 && rmdir(directory) == 0);
    CHECK(unlink(denied) == 0 && unlink(sym) == 0 && unlink(path) == 0);
}

static void verify_probe(const char *label, long result, int error) {
    static const struct { const char *name; long result; int error; } expected[] = {
        {"default-clear-set", 0, 0},
        {"default-clear-remove", 0, 0},
        {"default-nondir-set", -1, 13},
        {"acl-set", 0, 0},
        {"acl-query", 28, 0},
        {"acl-small", -1, 34},
        {"acl-create-existing", 0, 0},
        {"acl-remove", 0, 0},
        {"unknown-set", 0, 0},
        {"unknown-remove", 0, 0},
        {"cap-invalid", -1, 22},
        {"cap-set", 0, 0},
        {"cap-query", 20, 0},
        {"cap-read", 20, 0},
        {"cap-chown", 0, 0},
        {"cap-after-chown", -1, 61},
        {"foreign-default-clear-set", 0, 0},
        {"foreign-default-clear-remove", 0, 0},
        {"foreign-acl-set", -1, 1},
        {"foreign-user-set", 0, 0},
        {"foreign-cap-set", -1, 1},
        {"foreign-trusted-read", -1, 61},
        {"cap-get-denied-chown", 0, 0},
        {"cap-remove-denied-chown", -1, 1},
    };
    for (size_t i = 0; i < sizeof(expected)/sizeof(expected[0]); ++i) if (!strcmp(label, expected[i].name)) {
        CHECK(result == expected[i].result && error == expected[i].error); return;
    }
    CHECK(0);
}
#define PROBE(label, expression) do { errno = 0; long r = (expression); int error = errno; fprintf(stderr, "probe %s result=%ld errno=%d\n", label, r, error); verify_probe(label, r, error); } while (0)
static void xattr_diagnostics(void) {
    const char *path = "/fuse-filesystem-test/xattr-diagnostic";
    CHECK(mknod(path, S_IFREG | 0600, 0) == 0);
    unsigned char out[128];
    uint32_t acl[] = {2, 1 | (7 << 16), 0xffffffff, 4 | (5 << 16), 0xffffffff, 32, 0xffffffff};
    PROBE("default-clear-set", setxattr(path, "system.posix_acl_default", NULL, 0, 0));
    PROBE("default-clear-remove", removexattr(path, "system.posix_acl_default"));
    PROBE("default-nondir-set", setxattr(path, "system.posix_acl_default", acl, sizeof(acl), 0));
    PROBE("acl-set", setxattr(path, "system.posix_acl_access", acl, sizeof(acl), 0));
    PROBE("acl-query", getxattr(path, "system.posix_acl_access", NULL, 0));
    PROBE("acl-small", getxattr(path, "system.posix_acl_access", out, 8));
    PROBE("acl-create-existing", setxattr(path, "system.posix_acl_access", acl, sizeof(acl), XATTR_CREATE));
    PROBE("acl-remove", removexattr(path, "system.posix_acl_access"));
    PROBE("unknown-set", setxattr(path, "not-prefixed", "a", 1, 0));
    PROBE("unknown-remove", removexattr(path, "not-prefixed"));
    PROBE("cap-invalid", setxattr(path, "security.capability", "bad", 3, 0));
    uint32_t caps[5] = {0x02000001, 1, 0, 0, 0};
    PROBE("cap-set", setxattr(path, "security.capability", caps, sizeof(caps), 0));
    PROBE("cap-query", getxattr(path, "security.capability", NULL, 0));
    PROBE("cap-read", getxattr(path, "security.capability", out, sizeof(out)));
    PROBE("cap-chown", chown(path, 1, 1));
    PROBE("cap-after-chown", getxattr(path, "security.capability", NULL, 0));
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        CHECK(setresgid(1000,1000,1000) == 0 && setresuid(1000,1000,1000) == 0);
        PROBE("foreign-default-clear-set", setxattr(path, "system.posix_acl_default", NULL, 0, 0));
        PROBE("foreign-default-clear-remove", removexattr(path, "system.posix_acl_default"));
        PROBE("foreign-acl-set", setxattr(path, "system.posix_acl_access", acl, sizeof(acl), 0));
        PROBE("foreign-user-set", setxattr(path, "user.foreign", "a", 1, 0));
        PROBE("foreign-cap-set", setxattr(path, "security.capability", caps, sizeof(caps), 0));
        PROBE("foreign-trusted-read", getxattr(path, "trusted.secret", out, sizeof(out)));
        _exit(0);
    }
    int status; CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    const char *deny = "/fuse-filesystem-test/xattr-cap-deny";
    CHECK(mknod(deny, S_IFREG | 0600, 0) == 0);
    PROBE("cap-get-denied-chown", chown(deny, 1, 1));
    CHECK(unlink(deny) == 0);
    deny = "/fuse-filesystem-test/xattr-cap-remove-deny";
    CHECK(mknod(deny, S_IFREG | 0600, 0) == 0 && setxattr(deny, "security.capability", caps, sizeof(caps), 0) == 0);
    PROBE("cap-remove-denied-chown", chown(deny, 1, 1));
    CHECK(unlink(deny) == 0 && unlink(path) == 0);
}
static void xattr_checks(void) {
    const char *path = "/fuse-filesystem-test/xattr-file";
    CHECK(mknod(path, S_IFREG | 0600, 0) == 0);
    errno = 0; CHECK(setxattr(path, "", (void *)1, 1, 0) == -1 && errno == ERANGE);
    errno = 0; CHECK(setxattr(path, "", (void *)1, 65537, 0) == -1 && errno == ERANGE);
    unsigned char value[] = {0, 1, 255, 7}, out[32];
    CHECK(setxattr(path, "user.binary", value, sizeof(value), XATTR_CREATE) == 0);
    CHECK(getxattr(path, "user.binary", NULL, 0) == sizeof(value));
    CHECK(getxattr(path, "user.binary", out, sizeof(out)) == sizeof(value) && !memcmp(value, out, sizeof(value)));
    errno = 0; CHECK(getxattr(path, "user.binary", out, 1) == -1 && errno == ERANGE);
    errno = 0; CHECK(getxattr(path, "user.binary", (void *)1, sizeof(out)) == -1 && errno == EFAULT);
    CHECK(getxattr(path, "user.binary", (void *)1, 0) == sizeof(value));
    errno = 0; CHECK(setxattr(path, "user.binary", value, sizeof(value), XATTR_CREATE) == -1 && errno == EEXIST);
    CHECK(setxattr(path, "user.binary", "", 0, XATTR_REPLACE) == 0 && getxattr(path, "user.binary", NULL, 0) == 0);
    CHECK(listxattr(path, NULL, 0) == 12 && listxattr(path, (char *)out, sizeof(out)) == 12 && !strcmp((char *)out, "user.binary"));
    int fd = open(path, O_RDONLY); CHECK(fd >= 0);
    CHECK(fsetxattr(fd, "user.binary", value, sizeof(value), 0) == 0);
    CHECK(fgetxattr(fd, "user.binary", out, sizeof(out)) == sizeof(value));
    CHECK(flistxattr(fd, NULL, 0) == 12 && fremovexattr(fd, "user.binary") == 0);
    CHECK(close(fd) == 0);
    int only = open(path, O_PATH); CHECK(only >= 0);
    errno = 0; CHECK(fgetxattr(only, "user.none", NULL, 0) == -1 && errno == EBADF);
    CHECK(close(only) == 0);
    const char *sym = "/fuse-filesystem-test/xattr-sym"; CHECK(symlink("xattr-file", sym) == 0);
    errno = 0; CHECK(lsetxattr(sym, "user.bad", value, sizeof(value), 0) == -1 && errno == EPERM);
    errno = 0; CHECK(lgetxattr(sym, "user.bad", out, sizeof(out)) == -1 && errno == ENODATA);
    CHECK(lsetxattr(sym, "security.test", value, sizeof(value), 0) == 0);
    CHECK(lgetxattr(sym, "security.test", out, sizeof(out)) == sizeof(value));
    CHECK(lremovexattr(sym, "security.test") == 0);
    char *large = malloc(70000); CHECK(large);
    CHECK(getxattr(path, "user.capacity", large, 70000) == 0);
    CHECK(getxattr(path, "user.query-big", NULL, 0) == 65536);
    errno = 0; CHECK(getxattr(path, "user.too-big", large, 70000) == -1 && errno == E2BIG);
    free(large);
    const char *bad = "/fuse-filesystem-test/xattr-list-bad";
    CHECK(mknod(bad, S_IFREG | 0600, 0) == 0);
    errno = 0; CHECK(listxattr(bad, (char *)out, sizeof(out)) == -1 && errno == EIO);
    const char *unsupported = "/fuse-filesystem-test/xattr-unsupported";
    CHECK(mknod(unsupported, S_IFREG | 0600, 0) == 0);
    errno = 0; CHECK(getxattr(path, "user.unsupported", out, sizeof(out)) == -1 && errno == EOPNOTSUPP);
    errno = 0; CHECK(getxattr(path, "user.get-disabled", out, sizeof(out)) == -1 && errno == EOPNOTSUPP);
    errno = 0; CHECK(setxattr(path, "user.unsupported", value, sizeof(value), 0) == -1 && errno == EOPNOTSUPP);
    errno = 0; CHECK(setxattr(path, "user.set-disabled", value, sizeof(value), 0) == -1 && errno == EOPNOTSUPP);
    errno = 0; CHECK(removexattr(path, "user.unsupported") == -1 && errno == EOPNOTSUPP);
    errno = 0; CHECK(removexattr(path, "user.remove-disabled") == -1 && errno == EOPNOTSUPP);
    errno = 0; CHECK(listxattr(unsupported, NULL, 0) == -1 && errno == EOPNOTSUPP);
    errno = 0; CHECK(listxattr(unsupported, NULL, 0) == -1 && errno == EOPNOTSUPP);
    CHECK(unlink(sym) == 0 && unlink(bad) == 0 && unlink(unsupported) == 0 && unlink(path) == 0);
}

static void statfs_checks(void) {
    const char *paths[] = { "/fuse-filesystem-test", "/fuse-filesystem-test/data",
                            "/fuse-filesystem-test/parent" };
    for (unsigned i = 0; i < 3; ++i) {
        struct statfs fs;
        struct stat st;
        CHECK(statfs(paths[i], &fs) == 0 && stat(paths[i], &st) == 0);
        CHECK(fs.f_type == 0x65735546 && fs.f_bsize == 8192 && fs.f_blocks == 123456);
        CHECK(fs.f_bfree == 1234 && fs.f_bavail == 567 && fs.f_files == 890 && fs.f_ffree == 321);
        CHECK(fs.f_namelen == 127 && fs.f_frsize == 4096);
        CHECK(fs.f_fsid.__val[0] == 0 && fs.f_fsid.__val[1] == 0 && (fs.f_flags & 32));
        int fd = open(paths[i], O_PATH);
        CHECK(fd >= 0 && fstatfs(fd, &fs) == 0 && fs.f_bsize == 8192 && close(fd) == 0);
    }
    const char *ro = "/fuse-filesystem-test/statfs-readonly";
    const char *rw = "/fuse-filesystem-test/statfs-writable";
    CHECK(mknod(ro, S_IFREG | 0600, 0) == 0 && mknod(rw, S_IFREG | 0600, 0) == 0);
    struct statfs fs;
    CHECK(statfs(ro, &fs) == 0 && (fs.f_flags & 1));
    CHECK(statfs(rw, &fs) == 0 && !(fs.f_flags & 1));
    CHECK(unlink(ro) == 0 && unlink(rw) == 0);
    CHECK(symlink("/", "/fuse-filesystem-test/statfs-outside") == 0);
    struct statfs root;
    CHECK(statfs("/", &root) == 0 && statfs("/fuse-filesystem-test/statfs-outside", &fs) == 0);
    CHECK(fs.f_type == root.f_type);
    CHECK(unlink("/fuse-filesystem-test/statfs-outside") == 0);
    errno = 0; CHECK(statfs("/fuse-filesystem-test/missing", &fs) == -1 && errno == ENOENT);
}

static void chroot_checks(void) {
    const char *jail = "/fuse-filesystem-test/jail";
    const char *denied = "/fuse-filesystem-test/chroot-denied";
    CHECK(mkdir(jail, 0700) == 0 && mkdir(denied, 0700) == 0);
    CHECK(mknod("/fuse-filesystem-test/jail/inside", S_IFREG | 0600, 0) == 0);
    int root = open("/", O_PATH | O_DIRECTORY);
    CHECK(root >= 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        errno = 0; CHECK(chroot(denied) == -1 && errno == EACCES);
        errno = 0; CHECK(chroot("/fuse-filesystem-test/data") == -1 && errno == ENOTDIR);
        CHECK(chroot(jail) == 0);
        struct stat st;
        CHECK(stat("/inside", &st) == 0 && S_ISREG(st.st_mode));
        errno = 0; CHECK(stat("/fuse-filesystem-test/data", &st) == -1 && errno == ENOENT);
        CHECK(fstatat(root, "fuse-filesystem-test/data", &st, 0) == 0 && S_ISREG(st.st_mode));
        CHECK(chdir("/") == 0);
        char cwd[64];
        CHECK(getcwd(cwd, sizeof(cwd)) == cwd && !strcmp(cwd, "/"));
        CHECK(fchdir(root) == 0 && chroot(".") == 0 && close(root) == 0);
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(close(root) == 0);
    CHECK(unlink("/fuse-filesystem-test/jail/inside") == 0 && rmdir(jail) == 0 && rmdir(denied) == 0);
}

int main(void) {
    nodes[0].id = 10; nodes[0].parent = 1; nodes[0].active = 1;
    nodes[0].links = 1;
    nodes[0].mode = S_IFREG | 0600; strcpy(nodes[0].name, "data");
    CHECK(mkdir("/fuse-filesystem-test", 0755) == 0);
    int daemon = open("/dev/fuse", O_RDWR);
    CHECK(daemon >= 0);
    char options[128];
    snprintf(options, sizeof(options), "fd=%d,rootmode=40755,user_id=0,group_id=0,allow_other", daemon);
    CHECK(mount("fixture", "/fuse-filesystem-test", "fuse", 0, options) == 0);
    int completed[2], changes[2], changed[2];
    CHECK(pipe(completed) == 0 && pipe(changes) == 0 && pipe(changed) == 0);
    void *stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(stack != MAP_FAILED);
    struct mask_change change = { .request = changes[0], .ack = changed[1] };
    // Guest helper shares only fs_struct; daemon waits on pipes, including at one CPU.
    pid_t mask_child = clone(change_mask, (char *)stack + 65536, CLONE_FS | SIGCHLD, &change);
    CHECK(mask_child >= 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(close(completed[0]) == 0);
        daemon_loop(daemon, completed[1], changes[1], changed[0]);
    }
    CHECK(close(completed[1]) == 0);
    int directory = open("/fuse-filesystem-test", O_RDONLY | O_DIRECTORY);
    CHECK(directory >= 0);
    int alias = dup(directory);
    CHECK(alias >= 0);
    unsigned char small[64];
    errno = 0;
    CHECK(syscall(SYS_getdents64, directory, small, 1) == -1 && errno == EINVAL);
    unsigned char *pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(pages != MAP_FAILED && mprotect(pages + 4096, 4096, PROT_NONE) == 0);
    CHECK(syscall(SYS_getdents64, directory, pages + 4096 - 24, 64) == 24);
    CHECK(lseek(alias, 0, SEEK_CUR) == 9);
    CHECK(close(directory) == 0);
    CHECK(syscall(SYS_getdents64, alias, small, sizeof(small)) == 24);
    CHECK(lseek(alias, 0, SEEK_CUR) == 777);
    CHECK(syscall(SYS_getdents64, alias, small, sizeof(small)) == 0);
    CHECK(lseek(alias, 0, SEEK_SET) == 0);
    CHECK(syscall(SYS_getdents64, alias, small, sizeof(small)) == 48);
    CHECK(close(alias) == 0 && munmap(pages, 8192) == 0);

    int file = open("/fuse-filesystem-test/data", O_RDWR);
    CHECK(file >= 0);
    struct statfs file_fs;
    CHECK(fstatfs(file, &file_fs) == 0 && file_fs.f_bsize == 8192);
    unsigned char bytes[20000];
    memset(bytes, 42, sizeof(bytes));
    CHECK(write(file, bytes, sizeof(bytes)) == 8193);
    CHECK(lseek(file, 0, SEEK_CUR) == 8193);
    memset(bytes, 0, sizeof(bytes));
    CHECK(pread(file, bytes, sizeof(bytes), 0) == 8193);
    for (unsigned i = 0; i < 8193; ++i) CHECK(bytes[i] == 42);
    char proc_target[128];
    snprintf(proc_target, sizeof(proc_target), "/proc/self/fd/%d", file);
    CHECK(symlink(proc_target, "/fuse-filesystem-test/proc-file") == 0);
    CHECK(access("/fuse-filesystem-test/proc-file", R_OK | W_OK) == 0);
    errno = 0; CHECK(chdir("/fuse-filesystem-test/proc-file") == -1 && errno == ENOTDIR);
    int reopened = open("/fuse-filesystem-test/proc-file", O_RDONLY);
    CHECK(reopened >= 0 && read(reopened, bytes, 32) == 32);
    for (unsigned i = 0; i < 32; ++i) CHECK(bytes[i] == 42);
    CHECK(lseek(file, 0, SEEK_CUR) == 8193 && lseek(reopened, 0, SEEK_CUR) == 32);
    CHECK(close(reopened) == 0 && unlink("/fuse-filesystem-test/proc-file") == 0);
    CHECK(linkat(file, "", AT_FDCWD, "/fuse-filesystem-test/hard-data-fd", AT_EMPTY_PATH) == 0);
    struct stat linked_data;
    CHECK(fstat(file, &linked_data) == 0 && linked_data.st_nlink == 2);
    CHECK(unlink("/fuse-filesystem-test/hard-data-fd") == 0);
    CHECK(close(file) == 0);
    umask(0027);
    const char *parent = "/fuse-filesystem-test/parent";
    errno = 0; CHECK(mknod("/fuse-filesystem-test/forbidden-directory", S_IFDIR | 0700, 0) == -1 && errno == EPERM);
    CHECK(mkdir(parent, 0777) == 0);
    struct stat st;
    CHECK(stat(parent, &st) == 0 && (st.st_mode & 0777) == 0750);
    directory = open(parent, O_RDONLY | O_DIRECTORY);
    CHECK(directory >= 0);
    CHECK(mkdir("/fuse-filesystem-test/parent/child", 0700) == 0);
    snprintf(proc_target, sizeof(proc_target), "/proc/self/fd/%d", directory);
    CHECK(symlink(proc_target, "/fuse-filesystem-test/parent/proc-parent") == 0);
    CHECK(chdir("/fuse-filesystem-test/parent/proc-parent") == 0);
    char proc_cwd[256];
    CHECK(getcwd(proc_cwd, sizeof(proc_cwd)) == proc_cwd && !strcmp(proc_cwd, parent));
    CHECK(symlink("/proc/self/cwd", "/fuse-filesystem-test/parent/proc-cwd") == 0);
    CHECK(chdir("/fuse-filesystem-test/parent/proc-cwd") == 0);
    CHECK(getcwd(proc_cwd, sizeof(proc_cwd)) == proc_cwd && !strcmp(proc_cwd, parent));
    CHECK(chdir("/") == 0 && unlink("/fuse-filesystem-test/parent/proc-cwd") == 0);
    CHECK(stat("/fuse-filesystem-test/parent/proc-parent/child", &st) == 0 && S_ISDIR(st.st_mode));
    CHECK(mkdir("/fuse-filesystem-test/parent/proc-parent/proc-child", 0700) == 0);
    CHECK(rmdir("/fuse-filesystem-test/parent/proc-parent/proc-child") == 0);
    CHECK(unlink("/fuse-filesystem-test/parent/proc-parent") == 0);
    // Parent symlinks, dotdot and a covering mount use the common pathname walk.
    CHECK(symlink("child", "/fuse-filesystem-test/parent/dir-link") == 0);
    CHECK(mkdir("/fuse-filesystem-test/parent/dir-link/nested", 0700) == 0);
    CHECK(mknod("/fuse-filesystem-test/parent/dir-link/file", S_IFREG | 0600, 0) == 0);
    CHECK(symlink("file", "/fuse-filesystem-test/parent/dir-link/sym") == 0);
    CHECK(rename("/fuse-filesystem-test/parent/dir-link/file", "/fuse-filesystem-test/parent/child/moved") == 0);
    CHECK(unlink("/fuse-filesystem-test/parent/dir-link/moved") == 0);
    CHECK(unlink("/fuse-filesystem-test/parent/dir-link/sym") == 0);
    CHECK(rmdir("/fuse-filesystem-test/parent/dir-link/nested") == 0);
    CHECK(unlink("/fuse-filesystem-test/parent/dir-link") == 0);
    CHECK(mkdir("/fuse-filesystem-test/parent/child/../another", 0700) == 0);
    CHECK(rmdir("/fuse-filesystem-test/parent/another") == 0);
    CHECK(mkdir("/fuse-covered-back", 0755) == 0 && mkdir("/fuse-covered-out", 0755) == 0);
    CHECK(mount("tmpfs", "/fuse-covered-back", "tmpfs", 0, NULL) == 0);
    int covered = open("/fuse-filesystem-test/parent/child", O_RDONLY | O_DIRECTORY);
    CHECK(covered >= 0);
    int covering_tree = syscall(SYS_open_tree, AT_FDCWD, "/fuse-covered-back", 1);
    CHECK(covering_tree >= 0);
    CHECK(syscall(SYS_move_mount, covering_tree, "", covered, "", 4 | 0x40) == 0);
    CHECK(mkdir("/fuse-filesystem-test/parent/child/covered", 0700) == 0);
    CHECK(stat("/fuse-filesystem-test/parent/child/covered", &st) == 0 && S_ISDIR(st.st_mode));
    CHECK(rmdir("/fuse-filesystem-test/parent/child/covered") == 0);
    CHECK(syscall(SYS_move_mount, covering_tree, "", AT_FDCWD, "/fuse-covered-out", 4) == 0);
    CHECK(close(covering_tree) == 0 && close(covered) == 0);
    CHECK(umount("/fuse-covered-out") == 0 && umount("/fuse-covered-back") == 0);
    CHECK(rmdir("/fuse-covered-out") == 0 && rmdir("/fuse-covered-back") == 0);

    // A readonly source prefix does not prevent mutation after a link leaves it.
    CHECK(mkdir("/fuse-ordinary-parent", 0755) == 0);
    CHECK(symlink("/fuse-ordinary-parent", "/fuse-filesystem-test/parent/outdir") == 0);
    CHECK(mount(NULL, "/fuse-filesystem-test", NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL) == 0);
    CHECK(mkdir("/fuse-filesystem-test/parent/outdir/newdir", 0700) == 0);
    CHECK(mount(NULL, "/fuse-filesystem-test", NULL, MS_REMOUNT | MS_BIND, NULL) == 0);
    CHECK(mknod("/fuse-filesystem-test/parent/outdir/file", S_IFREG | 0600, 0) == 0);
    CHECK(rename("/fuse-filesystem-test/parent/outdir/file", "/fuse-ordinary-parent/moved") == 0);
    CHECK(rename("/fuse-ordinary-parent/moved", "/fuse-filesystem-test/parent/outdir/file") == 0);
    CHECK(symlink("file", "/fuse-filesystem-test/parent/outdir/sym") == 0);
    errno = 0; CHECK(unlink("/fuse-filesystem-test/parent/outdir/file/") == -1 && errno == ENOTDIR);
    errno = 0; CHECK(mknod("/fuse-filesystem-test/parent/outdir/missing/", S_IFREG | 0600, 0) == -1 && errno == ENOENT);
    CHECK(unlink("/fuse-filesystem-test/parent/outdir/sym") == 0);
    CHECK(unlink("/fuse-filesystem-test/parent/outdir/file") == 0);
    CHECK(rmdir("/fuse-filesystem-test/parent/outdir/newdir") == 0);
    CHECK(rmdir("/fuse-ordinary-parent") == 0);
    CHECK(unlink("/fuse-filesystem-test/parent/outdir") == 0);

    // The daemon changes the caller's shared fs_struct before the final ENOENT.
    CHECK(mkdir("/fuse-filesystem-test/parent/mask-live", 0777) == 0);
    CHECK(stat("/fuse-filesystem-test/parent/mask-live", &st) == 0 && (st.st_mode & 0777) == 0700);
    umask(0027);
    CHECK(rmdir("/fuse-filesystem-test/parent/mask-live") == 0);
    CHECK(symlink("child", "/fuse-filesystem-test/parent/create-parent-link") == 0);
    file = open("/fuse-filesystem-test/parent/create-parent-link/create-live", O_CREAT | O_EXCL | O_RDWR, 0666);
    CHECK(file >= 0 && fstat(file, &st) == 0 && (st.st_mode & 0777) == 0606 && close(file) == 0);
    CHECK(unlink("/fuse-filesystem-test/parent/child/create-live") == 0);
    CHECK(unlink("/fuse-filesystem-test/parent/create-parent-link") == 0);
    umask(0027);
    CHECK(chdir("/fuse-filesystem-test/parent/./child/..") == 0);
    char walked[256];
    CHECK(getcwd(walked, sizeof(walked)) == walked && !strcmp(walked, parent));
    CHECK(chdir("/") == 0);
    errno = 0; CHECK(rmdir(parent) == -1 && errno == ENOTEMPTY);
    CHECK(symlink("../data", "/fuse-filesystem-test/parent/link") == 0);
    errno = 0; CHECK(symlink("data", "/fuse-filesystem-test/missing-link/") == -1 && errno == ENOENT);
    errno = 0; CHECK(mknod("/fuse-filesystem-test/missing-file/", S_IFREG | 0600, 0) == -1 && errno == ENOENT);
    char link[32];
    CHECK(readlink("/fuse-filesystem-test/parent/link", link, sizeof(link)) == 7 && !memcmp(link, "../data", 7));
    CHECK(lstat("/fuse-filesystem-test/parent/link", &st) == 0 && S_ISLNK(st.st_mode));
    errno = 0; CHECK(open("/fuse-filesystem-test/parent/link", O_CREAT | O_EXCL | O_RDWR, 0600) == -1 && errno == EEXIST);
    errno = 0; CHECK(open("/fuse-filesystem-test/parent/link", O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW, 0600) == -1 && errno == EEXIST);
    struct { uint64_t flags, mode, resolve; } exclusive = { .flags = O_CREAT | O_EXCL | O_RDWR, .mode = 0600, .resolve = 4 };
    errno = 0; CHECK(syscall(SYS_openat2, AT_FDCWD, "/fuse-filesystem-test/parent/link", &exclusive, sizeof(exclusive)) == -1 && errno == EEXIST);
    CHECK(stat("/fuse-filesystem-test/parent/link", &st) == 0 && S_ISREG(st.st_mode) && st.st_size == 8193);
    file = open("/fuse-filesystem-test/parent/link", O_RDONLY);
    CHECK(file >= 0 && read(file, bytes, 32) == 32 && close(file) == 0);
    struct { uint64_t flags, mode, resolve; } how = { .flags = O_PATH, .resolve = 4 };
    errno = 0; CHECK(syscall(SYS_openat2, directory, "link", &how, sizeof(how)) == -1 && errno == ELOOP);
    how.resolve = 8;
    errno = 0; CHECK(syscall(SYS_openat2, directory, "link", &how, sizeof(how)) == -1 && errno == EXDEV);
    CHECK(symlink("child", "/fuse-filesystem-test/parent/inside-link") == 0);
    how.resolve = 16;
    int scoped = syscall(SYS_openat2, directory, "/inside-link", &how, sizeof(how));
    CHECK(scoped >= 0 && fstat(scoped, &st) == 0 && S_ISDIR(st.st_mode) && close(scoped) == 0);
    CHECK(mkdir("/fuse-filesystem-alias", 0755) == 0);
    int tree = syscall(SYS_open_tree, directory, "", 1 | AT_EMPTY_PATH);
    CHECK(tree >= 0);
    CHECK(syscall(SYS_move_mount, tree, "", AT_FDCWD, "/fuse-filesystem-alias", 4) == 0);
    CHECK(close(tree) == 0);
    CHECK(stat("/fuse-filesystem-alias", &st) == 0 && S_ISDIR(st.st_mode));
    CHECK(stat("/fuse-filesystem-alias/inside-link", &st) == 0 && S_ISDIR(st.st_mode));
    CHECK(chdir("/fuse-filesystem-alias/child/..") == 0);
    CHECK(getcwd(walked, sizeof(walked)) == walked && !strcmp(walked, "/fuse-filesystem-alias"));
    CHECK(chdir("..") == 0);
    CHECK(getcwd(walked, sizeof(walked)) == walked && !strcmp(walked, "/"));
    CHECK(umount("/fuse-filesystem-alias") == 0 && rmdir("/fuse-filesystem-alias") == 0);
    CHECK(unlink("/fuse-filesystem-test/parent/inside-link") == 0);
    CHECK(symlink("placeholder", "/fuse-filesystem-test/parent/empty-link") == 0);
    CHECK(readlink("/fuse-filesystem-test/parent/empty-link", link, sizeof(link)) == 0);
    CHECK(stat("/fuse-filesystem-test/parent/empty-link", &st) == 0 && S_ISDIR(st.st_mode));
    CHECK(unlink("/fuse-filesystem-test/parent/empty-link") == 0);
    CHECK(symlink("cycle", "/fuse-filesystem-test/parent/cycle") == 0);
    errno = 0; CHECK(stat("/fuse-filesystem-test/parent/cycle", &st) == -1 && errno == ELOOP);
    CHECK(unlink("/fuse-filesystem-test/parent/cycle") == 0);
    file = open("/fuse-filesystem-outside", O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(file >= 0 && write(file, "outside", 7) == 7 && close(file) == 0);
    file = open("/fuse-filesystem-outside", O_RDONLY);
    CHECK(file >= 0);
    snprintf(proc_target, sizeof(proc_target), "/proc/self/fd/%d", file);
    CHECK(symlink(proc_target, "/fuse-filesystem-test/parent/proc-outside") == 0);
    reopened = open("/fuse-filesystem-test/parent/proc-outside", O_RDONLY);
    CHECK(reopened >= 0 && read(reopened, bytes, 7) == 7 && !memcmp(bytes, "outside", 7));
    CHECK(close(reopened) == 0 && close(file) == 0);
    CHECK(unlink("/fuse-filesystem-test/parent/proc-outside") == 0);
    CHECK(symlink("/fuse-filesystem-outside", "/fuse-filesystem-test/parent/outside-link") == 0);
    CHECK(stat("/fuse-filesystem-test/parent/outside-link", &st) == 0 && st.st_size == 7);
    file = open("/fuse-filesystem-test/parent/outside-link", O_RDWR | O_TRUNC);
    CHECK(file >= 0 && fstat(file, &st) == 0 && st.st_size == 0 && close(file) == 0);
    CHECK(unlink("/fuse-filesystem-test/parent/outside-link") == 0);
    CHECK(unlink("/fuse-filesystem-outside") == 0);
    CHECK(unlink("/fuse-filesystem-test/parent/link") == 0);
    CHECK(rmdir("/fuse-filesystem-test/parent/child") == 0);
    for (unsigned i = 0; i < 3; ++i) {
        const char *names[] = { "atomic", "fallback", "cached" };
        char path[128]; snprintf(path, sizeof(path), "%s/%s", parent, names[i]);
        file = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0666);
        CHECK(file >= 0 && fstat(file, &st) == 0 && (st.st_mode & 0777) == (i == 1 ? 0600 : 0640));
        CHECK(close(file) == 0);
        umask(0027);
    }
    int mask_status;
    CHECK(waitpid(mask_child, &mask_status, 0) == mask_child && WIFEXITED(mask_status) && WEXITSTATUS(mask_status) == 0);
    CHECK(munmap(stack, 65536) == 0);
    CHECK(close(changes[0]) == 0 && close(changes[1]) == 0 && close(changed[0]) == 0 && close(changed[1]) == 0);
    directory_anchor_checks();
    topology_checks();
    file_bind_checks();
    mount_fd_checks();
    symlink_inode_checks();
    renamed_symlink_parent_checks();
    hardlink_checks();
    attribute_checks();
    xattr_diagnostics();
    xattr_checks();
    statfs_checks();
    chroot_checks();
    access_checks();

    errno = 0;
    CHECK(syscall(SYS_renameat2, AT_FDCWD, "/fuse-filesystem-test/parent/atomic", AT_FDCWD, "/fuse-filesystem-test/parent/cached", 1) == -1 && errno == EEXIST);
    CHECK(syscall(SYS_renameat2, AT_FDCWD, "/fuse-filesystem-test/parent/atomic", AT_FDCWD, "/fuse-filesystem-test/parent/cached", 2) == 0);
    CHECK(rename("/fuse-filesystem-test/parent/atomic", "/fuse-filesystem-test/renamed") == 0);
    CHECK(stat("/fuse-filesystem-test/renamed", &st) == 0 && S_ISREG(st.st_mode));
    errno = 0; CHECK(stat("/fuse-filesystem-test/parent/atomic", &st) == -1 && errno == ENOENT);
    CHECK(unlink("/fuse-filesystem-test/renamed") == 0);
    CHECK(unlink("/fuse-filesystem-test/parent/fallback") == 0);
    CHECK(unlink("/fuse-filesystem-test/parent/cached") == 0);
    CHECK(fchdir(directory) == 0);
    char cwd[256];
    CHECK(getcwd(cwd, sizeof(cwd)) == cwd && !strcmp(cwd, parent));
    alias = openat(directory, ".", O_RDONLY | O_DIRECTORY);
    CHECK(alias >= 0);
    CHECK(fstatat(directory, "../data", &st, 0) == 0 && S_ISREG(st.st_mode));
    CHECK(rename(parent, "/fuse-filesystem-test/moved-parent") == 0);
    CHECK(getcwd(cwd, sizeof(cwd)) == cwd && !strcmp(cwd, "/fuse-filesystem-test/moved-parent"));
    CHECK(close(alias) == 0);
    CHECK(rmdir("/fuse-filesystem-test/moved-parent") == 0);
    errno = 0; CHECK(getcwd(cwd, sizeof(cwd)) == NULL && errno == ENOENT);
    CHECK(chdir("..") == 0);
    CHECK(getcwd(cwd, sizeof(cwd)) == cwd && !strcmp(cwd, "/fuse-filesystem-test"));
    CHECK(chdir("/") == 0 && close(directory) == 0);
    char ack;
    CHECK(read(completed[0], &ack, 1) == 1 && ack == 'r');
    CHECK(close(completed[0]) == 0);
    CHECK(umount("/fuse-filesystem-test") == 0);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(close(daemon) == 0 && rmdir("/fuse-filesystem-test") == 0);
    puts("FUSE directory cookies, partial copy, negotiated I/O, namespace mutations, retained directories, followed parents, shared umask, final-inode access and proc chdir passed");
    return 0;
}
