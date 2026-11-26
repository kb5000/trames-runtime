// SPDX-License-Identifier: GPL-3.0-or-later
// Original syscall workload; identical ELF for Linux, interpreter and HVF.
#define main modern_mount_original_main
#include "modern-mounts.c"
#undef main
#include <dirent.h>
#include <mqueue.h>
#include <linux/openat2.h>

static int map_namespace(const char *uid,const char *gid) {
    int ready[2],release[2]; CHECK(pipe(ready)==0 && pipe(release)==0);pid_t p=fork();CHECK(p>=0);
    if (!p) {close(ready[0]);close(release[1]);CHECK(unshare(CLONE_NEWUSER)==0);CHECK(write(ready[1],"r",1)==1);char c;CHECK(read(release[0],&c,1)==1);_exit(0);}
    close(ready[1]);close(release[0]);char c;CHECK(read(ready[0],&c,1)==1);close(ready[0]);
    char path[128];snprintf(path,sizeof(path),"/proc/%d/uid_map",p);put(path,uid);snprintf(path,sizeof(path),"/proc/%d/gid_map",p);put(path,gid);
    snprintf(path,sizeof(path),"/proc/%d/ns/user",p);int ns=open(path,O_RDONLY|O_CLOEXEC);CHECK(ns>=0);CHECK(write(release[1],"x",1)==1);close(release[1]);waited(p);return ns;
}
static void mapped_bind(const char *source,const char *target,const char *uid,const char *gid) {
    int ns=map_namespace(uid,gid),tree=syscall(SYS_open_tree,AT_FDCWD,source,OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC);CHECK(tree>=0);
    CHECK(attr(tree,0,MOUNT_ATTR_IDMAP,0,ns)==0);CHECK(syscall(SYS_move_mount,tree,"",AT_FDCWD,target,MOVE_MOUNT_F_EMPTY_PATH)==0);CHECK(close(tree)==0 && close(ns)==0);
}
static unsigned entries(const char *path) {DIR *d=opendir(path);CHECK(d);unsigned n=0;struct dirent *e;while((e=readdir(d))) if(strcmp(e->d_name,".") && strcmp(e->d_name,"..")) ++n;CHECK(closedir(d)==0);return n;}
static void overlay_case(unsigned lower_map,unsigned upper_map) {
    char name[32];snprintf(name,sizeof(name),"case-%u-%u",lower_map,upper_map);CHECK(mkdir(name,0777)==0);CHECK(chdir(name)==0);
    const char *dirs[]={"lower","lower-map","store","upper-map","merged"};for(unsigned i=0;i<5;++i)CHECK(mkdir(dirs[i],0777)==0);
    CHECK(mount("tmpfs","lower","tmpfs",0,"mode=0777")==0 && mount("tmpfs","store","tmpfs",0,"mode=0777")==0);
    CHECK(mkdir("store/u",0777)==0 && mkdir("store/w",0777)==0);CHECK(chown("store/u",1000,2000)==0 && chown("store/w",1000,2000)==0);
    int f=open("lower/file",O_CREAT|O_RDWR,0666);CHECK(f>=0 && write(f,"abcdef",6)==6 && close(f)==0);CHECK(chown("lower/file",3,4)==0 && chmod("lower/file",0666)==0);CHECK(link("lower/file","lower/hard")==0);
    struct {uint32_t version;struct {uint16_t tag,perm;uint32_t id;}e[5];} acl={2,{{1,6,-1U},{2,4,5},{4,4,-1U},{16,4,-1U},{32,4,-1U}}};
    CHECK(setxattr("lower/file","system.posix_acl_access",&acl,sizeof(acl),0)==0);
    uint32_t cap[6]={0x02000001,1U<<10,0,0,0,0};CHECK(setxattr("lower/file","security.capability",cap,20,0)==0);
    if(lower_map)mapped_bind("lower","lower-map","0 1000 100\n","0 2000 100\n");
    if(upper_map)mapped_bind("store","upper-map","1000 0 65536\n","2000 0 65536\n");
    char options[256];snprintf(options,sizeof(options),"lowerdir=%s,upperdir=%s/u,workdir=%s/w",lower_map?"lower-map":"lower",upper_map?"upper-map":"store",upper_map?"upper-map":"store");
    CHECK(mount("overlay","merged","overlay",0,options)==0);unsigned uid=lower_map?1003:3,gid=lower_map?2004:4;owner("merged/file",uid,gid);
    struct stat a,b;CHECK(stat("merged/file",&a)==0 && stat("merged/hard",&b)==0 && a.st_ino==b.st_ino);
    CHECK(chmod("merged/file",0666)==0);
    f=open("merged/file",O_RDWR);CHECK(f>=0);owner("store/u/file",uid+(upper_map?1000:0),gid+(upper_map?2000:0));owner("lower/file",3,4);
    FAIL(stat("store/u/hard",&b),ENOENT);CHECK(stat("store/u/file",&a)==0 && a.st_nlink==1);CHECK(link("merged/file","merged/new-hard")==0);CHECK(stat("store/u/file",&a)==0 && stat("store/u/new-hard",&b)==0 && a.st_ino==b.st_ino && a.st_nlink==2);
    typeof(acl) got;CHECK(getxattr("store/u/file","system.posix_acl_access",&got,sizeof(got))==(ssize_t)sizeof(got));CHECK(got.e[1].id==(lower_map?1005U:5U)+(upper_map?1000U:0U));
    memset(cap,0,sizeof(cap));ssize_t size=getxattr("store/u/file","security.capability",cap,sizeof(cap));unsigned root=(lower_map?1000:0)+(upper_map?1000:0);CHECK(size==(root?24:20));CHECK(!root || cap[5]==root);
    int raw=open("store/u/file",O_RDONLY);CHECK(raw>=0);CHECK(pwrite(f,"XY",2,0)==2);char buf[8]={0};CHECK(pread(raw,buf,6,0)==6 && !memcmp(buf,"XYcdef",6));FAIL(getxattr("merged/file","security.capability",cap,sizeof(cap)),ENODATA);
    CHECK(fchown(f,uid+1,gid+1)==0);owner("store/u/file",uid+1+(upper_map?1000:0),gid+1+(upper_map?2000:0));
    CHECK(rename("merged/file","merged/renamed")==0);CHECK(unlink("merged/hard")==0 && unlink("merged/new-hard")==0 && unlink("merged/renamed")==0);FAIL(stat("merged/file",&a),ENOENT);CHECK(fchown(f,uid+2,gid+2)==0 && fstat(raw,&a)==0);CHECK(a.st_uid==uid+2+(upper_map?1000:0) && a.st_gid==gid+2+(upper_map?2000:0));CHECK(close(raw)==0 && close(f)==0);
    CHECK(umount("merged")==0);CHECK(mount("overlay","merged","overlay",0,options)==0);FAIL(stat("merged/file",&a),ENOENT);FAIL(stat("merged/hard",&a),ENOENT);CHECK(umount("merged")==0);CHECK(chdir("..")==0);
}
static void temporary(const char *kind,const char *name) {
    CHECK(mkdir(name,0777)==0);if(strcmp(kind,"overlay"))CHECK(mount(kind,name,kind,0,NULL)==0);else {
        CHECK(mkdir("tmp-lower",0777)==0 && mkdir("tmp-upper",0777)==0 && mkdir("tmp-work",0777)==0);CHECK(mount("overlay",name,"overlay",0,"lowerdir=tmp-lower,upperdir=tmp-upper,workdir=tmp-work")==0);
    }
    unsigned before=entries(name);struct open_how how={.flags=O_TMPFILE|O_RDWR,.mode=0600};int modern=syscall(SYS_openat2,AT_FDCWD,name,&how,sizeof(how));CHECK(modern>=0 && close(modern)==0);int fd=open(name,O_TMPFILE|O_RDWR,0600);CHECK(fd>=0);struct stat st;CHECK(fstat(fd,&st)==0 && st.st_nlink==0 && (st.st_mode&0777)==0600);CHECK(entries(name)==before);CHECK((fcntl(fd,F_GETFL)&O_TMPFILE)==O_TMPFILE);CHECK(write(fd,"private",7)==7);
    char path[128];snprintf(path,sizeof(path),"%s/published",name);CHECK(linkat(fd,"",AT_FDCWD,path,AT_EMPTY_PATH)==0);CHECK(stat(path,&st)==0 && st.st_nlink==1);CHECK(unlink(path)==0);snprintf(path,sizeof(path),"%s/resurrect",name);FAIL(linkat(fd,"",AT_FDCWD,path,AT_EMPTY_PATH),ENOENT);CHECK(close(fd)==0);
    fd=open(name,O_TMPFILE|O_EXCL|O_RDWR,0600);CHECK(fd>=0);FAIL(linkat(fd,"",AT_FDCWD,path,AT_EMPTY_PATH),ENOENT);CHECK(close(fd)==0);CHECK(entries(name)==before);FAIL(open(name,O_TMPFILE|O_RDONLY,0600),EINVAL);CHECK(umount(name)==0);
}
static int fs_create(const char *kind,const char *target) {
    int ctx=syscall(SYS_fsopen,kind,FSOPEN_CLOEXEC);CHECK(ctx>=0);if(!strcmp(kind,"devpts"))CHECK(syscall(SYS_fsconfig,ctx,FSCONFIG_SET_STRING,"ptmxmode","0666",0)==0);
    CHECK(syscall(SYS_fsconfig,ctx,FSCONFIG_CMD_CREATE,NULL,NULL,0)==0);int tree=syscall(SYS_fsmount,ctx,FSMOUNT_CLOEXEC,0);CHECK(tree>=0);CHECK(syscall(SYS_move_mount,tree,"",AT_FDCWD,target,MOVE_MOUNT_F_EMPTY_PATH)==0);CHECK(close(ctx)==0);return tree;
}
static void new_contexts(void) {
    CHECK(mkdir("modern-pts",0777)==0 && mkdir("modern-cgroup",0777)==0 && mkdir("modern-mq",0777)==0 && mkdir("modern-overlay",0777)==0);
    int fd=fs_create("devpts","modern-pts");struct stat st;CHECK(stat("modern-pts/ptmx",&st)==0 && S_ISCHR(st.st_mode) && (st.st_mode&0777)==0666);CHECK(close(fd)==0);
    fd=fs_create("cgroup2","modern-cgroup");CHECK(stat("modern-cgroup/cgroup.procs",&st)==0);CHECK(close(fd)==0);
    CHECK(mkdir("accepted:lower,",0777)==0 && mkdir("accepted-upper",0777)==0 && mkdir("accepted-work",0777)==0);file("accepted:lower,/file");
    int ctx=syscall(SYS_fsopen,"overlay",0);CHECK(ctx>=0);CHECK(syscall(SYS_fsconfig,ctx,FSCONFIG_SET_STRING,"lowerdir+","accepted:lower,",0)==0);CHECK(syscall(SYS_fsconfig,ctx,FSCONFIG_SET_STRING,"upperdir","accepted-upper",0)==0);CHECK(syscall(SYS_fsconfig,ctx,FSCONFIG_SET_STRING,"workdir","accepted-work",0)==0);CHECK(rename("accepted:lower,","renamed-lower")==0);CHECK(syscall(SYS_fsconfig,ctx,FSCONFIG_CMD_CREATE,NULL,NULL,0)==0);fd=syscall(SYS_fsmount,ctx,0,0);CHECK(fd>=0);CHECK(syscall(SYS_move_mount,fd,"",AT_FDCWD,"modern-overlay",MOVE_MOUNT_F_EMPTY_PATH)==0);CHECK(stat("modern-overlay/file",&st)==0);CHECK(close(ctx)==0 && close(fd)==0);
    mqd_t queue=mq_open("/modern-original",O_CREAT|O_RDWR,0600,NULL);CHECK(queue!=(mqd_t)-1);ctx=syscall(SYS_fsopen,"mqueue",0);CHECK(ctx>=0);CHECK(unshare(CLONE_NEWIPC)==0);CHECK(syscall(SYS_fsconfig,ctx,FSCONFIG_CMD_CREATE,NULL,NULL,0)==0);fd=syscall(SYS_fsmount,ctx,0,0);CHECK(fd>=0);CHECK(syscall(SYS_move_mount,fd,"",AT_FDCWD,"modern-mq",MOVE_MOUNT_F_EMPTY_PATH)==0);CHECK(stat("modern-mq/modern-original",&st)==0);FAIL(mq_open("/modern-original",O_RDONLY),ENOENT);CHECK(close(fd)==0 && close(ctx)==0 && mq_close(queue)==0);
}
int main(int argc,char **argv) {
    setbuf(stdout,NULL);
    if(argc==6 && !strcmp(argv[1],"map")){mapped_bind(argv[2],argv[3],argv[4],argv[5]);return 0;}
    if(argc==6 && !strcmp(argv[1],"mount")) {
        int ctx=syscall(SYS_fsopen,"overlay",0);CHECK(ctx>=0);
        CHECK(syscall(SYS_fsconfig,ctx,FSCONFIG_SET_STRING,"lowerdir+",argv[2],0)==0);
        CHECK(syscall(SYS_fsconfig,ctx,FSCONFIG_SET_STRING,"upperdir",argv[3],0)==0);
        CHECK(syscall(SYS_fsconfig,ctx,FSCONFIG_SET_STRING,"workdir",argv[4],0)==0);
        CHECK(syscall(SYS_fsconfig,ctx,FSCONFIG_CMD_CREATE,NULL,NULL,0)==0);
        int tree=syscall(SYS_fsmount,ctx,0,0);CHECK(tree>=0);
        CHECK(syscall(SYS_move_mount,tree,"",AT_FDCWD,argv[5],MOVE_MOUNT_F_EMPTY_PATH)==0);CHECK(close(tree)==0 && close(ctx)==0);return 0;
    }
    CHECK(unshare(CLONE_NEWNS)==0 && mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)==0);char dir[]="/tmp/modern-overlay.XXXXXX";CHECK(mkdtemp(dir));CHECK(mount("tmpfs",dir,"tmpfs",0,"mode=0777")==0);CHECK(chdir(dir)==0);umask(0);
    overlay_case(1,0);overlay_case(0,1);overlay_case(1,1);puts("PASS lower/upper/composed idmap copy-up, ACL, capability, hard link and retained FD");
    temporary("tmpfs","tmp-tmpfs");temporary("ramfs","tmp-ramfs");temporary("overlay","tmp-overlay");puts("PASS true anonymous tmpfiles, one-time linking and unsupported flags");
    new_contexts();puts("PASS modern overlay/devpts/cgroup2/mqueue contexts and accepted resources");printf("MODERN_OVERLAY checks=%u failures=0\n",checks);return 0;
}
