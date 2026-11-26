// SPDX-License-Identifier: GPL-3.0-or-later
// Same ELF on native Linux and Trames. All mounts are confined to this process.
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/mount.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"line %d: %s errno=%d\n",__LINE__,#x,errno); exit(1); } } while (0)
#define FAIL(x,e) do { errno=0; long rc=(x); CHECK(rc == -1 && errno == (e)); } while (0)
static void put(const char *p, const char *s) { int fd=open(p,O_WRONLY); CHECK(fd>=0); CHECK(write(fd,s,strlen(s))==(ssize_t)strlen(s)); CHECK(close(fd)==0); }
static void file(const char *p) { int fd=open(p,O_CREAT|O_EXCL|O_RDWR,0600); CHECK(fd>=0); CHECK(close(fd)==0); }
static void owner(const char *p, unsigned uid, unsigned gid) { struct stat s; CHECK(stat(p,&s)==0); CHECK(s.st_uid==uid && s.st_gid==gid); }
static void waited(pid_t pid) { int status; CHECK(waitpid(pid,&status,0)==pid); CHECK(WIFEXITED(status) && WEXITSTATUS(status)==0); }
static int userns(void) {
    int ready[2],release[2]; CHECK(pipe(ready)==0 && pipe(release)==0);
    pid_t p=fork(); CHECK(p>=0);
    if (!p) { close(ready[0]); close(release[1]); CHECK(unshare(CLONE_NEWUSER)==0); CHECK(write(ready[1],"r",1)==1); char c; CHECK(read(release[0],&c,1)==1); _exit(0); }
    close(ready[1]);close(release[0]);char c;CHECK(read(ready[0],&c,1)==1);close(ready[0]);
    char path[128];snprintf(path,sizeof(path),"/proc/%d/uid_map",p);put(path,"0 100000 65536\n");
    snprintf(path,sizeof(path),"/proc/%d/gid_map",p);put(path,"0 200000 65536\n");
    snprintf(path,sizeof(path),"/proc/%d/ns/user",p);int ns=open(path,O_RDONLY|O_CLOEXEC);CHECK(ns>=0);
    CHECK(write(release[1],"x",1)==1);close(release[1]);waited(p);return ns;
}
static long attr(int tree,unsigned flags,uint64_t set,uint64_t clear,uint64_t ns) {
    struct mount_attr a={.attr_set=set,.attr_clr=clear,.userns_fd=ns};
    return syscall(SYS_mount_setattr,tree,"",AT_EMPTY_PATH|flags,&a,sizeof(a));
}
static void mapping(void) {
    CHECK(mkdir("source",0777)==0 && mkdir("mapped",0777)==0 && mkdir("alias",0777)==0);
    CHECK(mount("none","source","tmpfs",0,"mode=0777")==0);file("source/file");
    int ns=userns();int tree=syscall(SYS_open_tree,AT_FDCWD,"source",OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC);CHECK(tree>=0);
    FAIL(attr(tree,0,MOUNT_ATTR_IDMAP,0,(uint64_t)INT32_MAX+1),EINVAL);
    FAIL(attr(tree,0,MOUNT_ATTR_IDMAP,0,1234567),EBADF);
    int wrong=open("/dev/null",O_RDONLY);CHECK(wrong>=0);FAIL(attr(tree,0,MOUNT_ATTR_IDMAP,0,wrong),EINVAL);CHECK(close(wrong)==0);
    int initial=open("/proc/self/ns/user",O_RDONLY);CHECK(initial>=0);FAIL(attr(tree,0,MOUNT_ATTR_IDMAP,0,initial),EPERM);CHECK(close(initial)==0);
    int writer=openat(tree,"file",O_RDWR);CHECK(writer>=0);FAIL(attr(tree,0,MOUNT_ATTR_IDMAP,0,ns),EBUSY);
    CHECK(ftruncate(writer,4096)==0);void *private=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE,writer,0);CHECK(private!=MAP_FAILED);
    CHECK(close(writer)==0);FAIL(attr(tree,0,MOUNT_ATTR_IDMAP,0,ns),EBUSY);CHECK(munmap(private,4096)==0);
    CHECK(attr(tree,0,MOUNT_ATTR_IDMAP,0,ns)==0);
    FAIL(attr(tree,0,MOUNT_ATTR_IDMAP,0,ns),EPERM);
    CHECK(syscall(SYS_move_mount,tree,"",AT_FDCWD,"mapped",MOVE_MOUNT_F_EMPTY_PATH)==0);
    CHECK(close(tree)==0);owner("source/file",0,0);owner("mapped/file",100000,200000);
    int fd=open("mapped/file",O_RDONLY);CHECK(fd>=0);
    CHECK(mount("mapped","alias",NULL,MS_BIND,NULL)==0);
    FAIL(open("mapped/overflow",O_CREAT|O_RDWR,0600),EOVERFLOW);
    CHECK(chown("mapped/file",100001,200002)==0);owner("source/file",1,2);owner("alias/file",100001,200002);
    FAIL(chown("mapped/file",999,200002),EOVERFLOW);owner("source/file",1,2);
    // Named POSIX ACL identities are returned in the original mount's domain.
    struct {uint32_t version; struct {uint16_t tag,perm;uint32_t id;} e[5];} acl={2,{{1,6,-1U},{2,4,3},{4,0,-1U},{16,4,-1U},{32,0,-1U}}};
    CHECK(setxattr("source/file","system.posix_acl_access",&acl,sizeof(acl),0)==0);
    typeof(acl) projected;CHECK(getxattr("mapped/file","system.posix_acl_access",&projected,sizeof(projected))==(ssize_t)sizeof(projected));CHECK(projected.e[1].id==100003);
    uint32_t caps[6]={0x03000001,1U<<10,0,0,0,100000}, gotcaps[6]={0};
    CHECK(setxattr("mapped/file","security.capability",caps,sizeof(caps),0)==0);
    CHECK(getxattr("source/file","security.capability",gotcaps,sizeof(gotcaps))==20);
    CHECK(getxattr("mapped/file","security.capability",gotcaps,sizeof(gotcaps))==24);CHECK(gotcaps[5]==100000);
    CHECK(mkdir("source/sgid",0777)==0);CHECK(chown("source/sgid",0,7)==0);CHECK(chmod("source/sgid",02777)==0);
    CHECK(umount2("mapped",MNT_DETACH)==0);CHECK(fchown(fd,100004,200005)==0);owner("source/file",4,5);
    struct stat st;CHECK(fstat(fd,&st)==0);CHECK(st.st_uid==100004 && st.st_gid==200005);CHECK(close(fd)==0);
    pid_t p=fork();CHECK(p>=0);
    if (!p) {CHECK(setgid(200004)==0 && setuid(100003)==0);file("alias/new");owner("alias/new",100003,200004);FAIL(open("source/new",O_RDONLY),EACCES);CHECK(chmod("alias/new",0640)==0);FAIL(chmod("source/new",0600),EPERM);CHECK(mkdir("alias/sgid/sub",0755)==0);owner("alias/sgid/sub",100003,200007);struct stat d;CHECK(stat("alias/sgid/sub",&d)==0);CHECK(d.st_mode&S_ISGID);_exit(0);}
    waited(p);owner("source/new",3,4);
    int read_only=open("alias/file",O_RDONLY);CHECK(read_only>=0);CHECK(mount(NULL,"alias",NULL,MS_REMOUNT|MS_BIND|MS_RDONLY,NULL)==0);
    FAIL(write(read_only,"x",1),EBADF);FAIL(pwrite(read_only,"x",1,0),EBADF);CHECK(close(read_only)==0);
    CHECK(mount(NULL,"alias",NULL,MS_REMOUNT|MS_BIND,NULL)==0);
    CHECK(chown("source/new",70000,70000)==0);owner("alias/new",65534,65534);FAIL(open("alias/new",O_RDONLY),EACCES);
    tree=syscall(SYS_open_tree,AT_FDCWD,"source",OPEN_TREE_CLOEXEC);CHECK(tree>=0);FAIL(attr(tree,0,MOUNT_ATTR_IDMAP,0,ns),EINVAL);CHECK(close(tree)==0);
    CHECK(mkdir("source/child",0755)==0);CHECK(mount("none","source/child","ramfs",0,NULL)==0);
    tree=syscall(SYS_open_tree,AT_FDCWD,"source",OPEN_TREE_CLONE|AT_RECURSIVE);CHECK(tree>=0);
    FAIL(attr(tree,AT_RECURSIVE,MOUNT_ATTR_IDMAP|MOUNT_ATTR_NOEXEC,0,ns),EINVAL);
    struct statvfs flags;CHECK(fstatvfs(tree,&flags)==0);CHECK(!(flags.f_flag&ST_NOEXEC));
    CHECK(attr(tree,0,MOUNT_ATTR_IDMAP,0,ns)==0);CHECK(close(tree)==0);
    CHECK(close(ns)==0);puts("PASS idmapped metadata/DAC/ACL/create/chown/OFD/recursive rollback");
}
static void unmapped_boundaries(void) {
    file("source/unmapped");CHECK(chown("source/unmapped",70000,70000)==0);CHECK(chmod("source/unmapped",0666)==0);
    int fd=open("alias/unmapped",O_RDONLY);CHECK(fd>=0);
    FAIL(open("alias/unmapped",O_WRONLY),EACCES);
    FAIL(chmod("alias/unmapped",0666),EOVERFLOW);
    FAIL(utimensat(AT_FDCWD,"alias/unmapped",NULL,0),EACCES);
    FAIL(setxattr("alias/unmapped","user.test","x",1,0),EPERM);
    FAIL(setxattr("alias/unmapped","trusted.test","x",1,0),EPERM);
    FAIL(link("alias/unmapped","alias/unmapped-link"),EOVERFLOW);
    FAIL(rename("alias/unmapped","alias/unmapped-rename"),EOVERFLOW);
    FAIL(unlink("alias/unmapped"),EOVERFLOW);
    FAIL(chown("alias/unmapped",100000,-1U),EOVERFLOW);
    CHECK(chown("alias/unmapped",100000,200000)==0);owner("source/unmapped",0,0);
    CHECK(close(fd)==0);
    file("source/gid-unmapped");CHECK(chown("source/gid-unmapped",0,70000)==0);CHECK(chmod("source/gid-unmapped",0666)==0);
    FAIL(chmod("alias/gid-unmapped",0666),EOVERFLOW);
    FAIL(utimensat(AT_FDCWD,"alias/gid-unmapped",NULL,0),EOVERFLOW);
    FAIL(chown("alias/gid-unmapped",100000,200000),EPERM);
    FAIL(setxattr("alias/gid-unmapped","user.test","x",1,0),EPERM);
    CHECK(chown("alias/gid-unmapped",-1U,200000)==0);owner("source/gid-unmapped",0,0);
    struct {uint32_t version;struct {uint16_t tag,perm;uint32_t id;} e[5];} bad_acl={2,{{1,6,-1U},{2,4,999},{4,0,-1U},{16,4,-1U},{32,0,-1U}}};
    FAIL(setxattr("alias/gid-unmapped","system.posix_acl_access",&bad_acl,sizeof(bad_acl),0),EINVAL);
    pid_t p=fork();CHECK(p>=0);if(!p){CHECK(setgid(200003)==0 && setuid(100003)==0);CHECK(chown("alias/gid-unmapped",-1U,-1U)==0);_exit(0);}waited(p);
    int original=open("alias/file",O_RDWR);CHECK(original>=0);CHECK(chown("source/file",70000,70000)==0);
    CHECK(write(original,"x",1)==1);FAIL(ftruncate(original,0),EOVERFLOW);CHECK(fallocate(original,0,0,8192)==0);CHECK(close(original)==0);
    puts("PASS unmapped writeback guards, namespace operations, ACL and chown recovery");
}
static void reconfigure(const char *kind,const char *path) {
    CHECK(mkdir(path,0755)==0);CHECK(mount("none",path,kind,0,NULL)==0);
    char alias[64];CHECK(snprintf(alias,sizeof(alias),"%s-alias",path)>0);CHECK(mkdir(alias,0755)==0);CHECK(mount(path,alias,NULL,MS_BIND,NULL)==0);
    CHECK(mount(NULL,alias,NULL,MS_REMOUNT|MS_BIND|MS_RDONLY,NULL)==0);
    int old=open(path,O_PATH|O_DIRECTORY);CHECK(old>=0);
    int ctx=syscall(SYS_fspick,AT_FDCWD,path,0);CHECK(ctx>=0);
    CHECK(syscall(SYS_fsconfig,ctx,FSCONFIG_SET_FLAG,"ro",NULL,0)==0);
    CHECK(syscall(SYS_fsconfig,ctx,FSCONFIG_CMD_RECONFIGURE,NULL,NULL,0)==0);
    struct statvfs s;CHECK(statvfs(path,&s)==0);CHECK(s.f_flag&ST_RDONLY);
    CHECK(fstatvfs(old,&s)==0);CHECK(s.f_flag&ST_RDONLY);CHECK(statvfs(alias,&s)==0);CHECK(s.f_flag&ST_RDONLY);
    file("root-still-writable");CHECK(unlink("root-still-writable")==0);
    CHECK(syscall(SYS_fsconfig,ctx,FSCONFIG_SET_FLAG,"rw",NULL,0)==0);
    CHECK(syscall(SYS_fsconfig,ctx,FSCONFIG_CMD_RECONFIGURE,NULL,NULL,0)==0);
    CHECK(statvfs(path,&s)==0);CHECK(!(s.f_flag&ST_RDONLY));CHECK(close(ctx)==0);
    CHECK(fstatvfs(old,&s)==0);CHECK(!(s.f_flag&ST_RDONLY));CHECK(close(old)==0);
    CHECK(statvfs(alias,&s)==0);CHECK(s.f_flag&ST_RDONLY);
    if (!strcmp(kind,"sysfs")) {
        ctx=syscall(SYS_fsopen,kind,0);CHECK(ctx>=0);
        CHECK(syscall(SYS_fsconfig,ctx,FSCONFIG_SET_FLAG,"ro",NULL,0)==0);
        CHECK(syscall(SYS_fsconfig,ctx,FSCONFIG_CMD_CREATE,NULL,NULL,0)==0);
        int tree=syscall(SYS_fsmount,ctx,0,0);CHECK(tree>=0);
        CHECK(fstatvfs(tree,&s)==0);CHECK(!(s.f_flag&ST_RDONLY));
        CHECK(close(tree)==0 && close(ctx)==0);
    }
}
int main(void) {
    setbuf(stdout,NULL);CHECK(unshare(CLONE_NEWNS)==0);CHECK(mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)==0);
    char dir[]="/tmp/modern-mounts.XXXXXX";CHECK(mkdtemp(dir));CHECK(chmod(dir,0777)==0);CHECK(chdir(dir)==0);
    mapping();unmapped_boundaries();reconfigure("ramfs","ram");reconfigure("proc","proc");reconfigure("sysfs","sys");
    puts("PASS non-tmpfs fspick/reconfigure and root superblock isolation");
    printf("MODERN_MOUNTS checks=%u failures=0\n",checks);return 0;
}
