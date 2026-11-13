// SPDX-License-Identifier: GPL-3.0-or-later
// Identical ARM64 binary for native Linux and Trames mount propagation tests.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
static void check(int ok,const char *what){if(!ok){perror(what);exit(1);}}
static char base[512];
static const char *path(const char *suffix){static char names[8][1024];static unsigned slot;char *p=names[slot++%8];check(snprintf(p,1024,"%s/%s",base,suffix)<1024,"path");return p;}
static void directory(const char *name){check(mkdir(path(name),0755)==0,"mkdir");}
static unsigned long long device(const char *name){struct stat s;check(stat(path(name),&s)==0,"stat");return s.st_dev;}
static void byte(int fd,int write_mode){char c='x';check((write_mode?write(fd,&c,1):read(fd,&c,1))==1,"pipe byte");}
int main(int argc,char **argv){
    check(argc==2&&strlen(argv[1])<sizeof(base),"base argument");strcpy(base,argv[1]);
    check(unshare(CLONE_NEWNS)==0,"unshare");check(mount(NULL,"/",NULL,MS_PRIVATE|MS_REC,NULL)==0,"private root");
    check(mkdir(base,0755)==0,"base mkdir");check(mount("tmpfs",base,"tmpfs",0,"mode=755,uid=0,gid=0")==0,"base tmpfs");
    for(const char **n=(const char*[]){"src","peer","slave","private",NULL};*n;n++)directory(*n);
    check(mount("tmpfs",path("src"),"tmpfs",0,NULL)==0,"source tmpfs");check(mount(NULL,path("src"),NULL,MS_SHARED,NULL)==0,"shared source");
    for(const char **n=(const char*[]){"peer","slave","private",NULL};*n;n++)check(mount(path("src"),path(*n),NULL,MS_BIND,NULL)==0,"bind");
    check(mount(NULL,path("slave"),NULL,MS_SLAVE,NULL)==0,"slave");check(mount(NULL,path("private"),NULL,MS_PRIVATE,NULL)==0,"private");
    directory("src/sub");unsigned long long underlying=device("private/sub");check(mount("tmpfs",path("src/sub"),"tmpfs",0,NULL)==0,"child mount");
    unsigned long long actual=device("src/sub");check(actual!=underlying&&device("peer/sub")==actual&&device("slave/sub")==actual&&device("private/sub")==underlying,"propagation visibility");
    check(umount(path("slave/sub"))==0,"slave child unmount");check(device("src/sub")==actual&&device("slave/sub")==underlying,"no upstream unmount");
    int busy=open(path("peer/sub"),O_RDONLY|O_DIRECTORY|O_CLOEXEC);check(busy>=0,"busy peer directory");errno=0;
    check(umount(path("src/sub"))==-1&&errno==EBUSY,"busy propagated peer rejects unmount");check(close(busy)==0,"close busy peer");
    directory("src/cross");int ready[2],release[2];check(pipe(ready)==0&&pipe(release)==0,"pipes");pid_t child=fork();check(child>=0,"fork");
    if(!child){close(ready[0]);close(release[1]);check(unshare(CLONE_NEWNS)==0,"child namespace");check(mount("tmpfs",path("src/cross"),"tmpfs",0,NULL)==0,"cross namespace mount");byte(ready[1],1);byte(release[0],0);check(umount(path("src/cross"))==0,"cross namespace unmount");_exit(0);}
    close(ready[1]);close(release[0]);byte(ready[0],0);check(device("src/cross")==device("slave/cross")&&device("src/cross")!=device("private/cross"),"cross namespace delivery");
    check(mount(NULL,path("peer"),NULL,MS_PRIVATE|MS_REC,NULL)==0,"detach peer");unsigned long long retained=device("peer/cross");byte(release[1],1);int status;check(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0,"child status");
    check(device("src/cross")!=retained&&device("peer/cross")==retained,"private detach isolation");
    check(umount(path("src/sub"))==0,"source child unmount");check(device("peer/sub")==actual,"private old child retained");
    directory("downstream");check(mount(NULL,path("slave"),NULL,MS_SHARED,NULL)==0,"shared slave group");
    check(mount(path("slave"),path("downstream"),NULL,MS_BIND,NULL)==0,"downstream bind");check(mount(NULL,path("downstream"),NULL,MS_SLAVE,NULL)==0,"downstream slave");
    check(umount(path("slave"))==0,"remove immediate master");directory("src/after");check(mount("tmpfs",path("src/after"),"tmpfs",0,NULL)==0,"new upstream child");
    check(device("src/after")==device("downstream/after"),"orphan slave reparents upstream");
    check(umount2(base,MNT_DETACH)==0,"cleanup");check(rmdir(base)==0,"cleanup directory");puts("android-mounts: PASS shared slave private namespace-clone tmpfs-owner");return 0;
}
