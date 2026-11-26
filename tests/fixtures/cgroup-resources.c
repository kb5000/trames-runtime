// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void die(const char *operation) { perror(operation); exit(2); }
static void control(const char *path, const char *text) {
  int fd=open(path,O_WRONLY|O_CLOEXEC); if(fd<0)die(path);
  size_t length=strlen(text); if(write(fd,text,length)!=(ssize_t)length)die(path);
  if(close(fd))die("close control");
}
static size_t read_text(const char *path, char *out, size_t size) {
  int fd=open(path,O_RDONLY|O_CLOEXEC); if(fd<0)die(path);
  ssize_t n=read(fd,out,size-1); if(n<0)die(path); out[n]=0;
  if(close(fd))die("close read");
  return (size_t)n;
}
static unsigned long long number(const char *path) {
  char text[8192];read_text(path,text,sizeof(text));return strtoull(text,0,10);
}
static double now(void) { struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))die("clock");return t.tv_sec+t.tv_nsec/1e9; }
static void path(char *out,size_t size,const char *group,const char *name) {
  if(snprintf(out,size,"%s/%s",group,name)>=(int)size){errno=ENAMETOOLONG;die("path");}
}
static void move_to(const char *group) { char p[1024];path(p,sizeof(p),group,"cgroup.procs");control(p,"0"); }
static void require(int ok,const char *message) { if(!ok){fprintf(stderr,"FAIL %s\n",message);exit(1);} }
int main(int argc, char **argv) {
  alarm(25);
  char original[1024],text[8192],group[1024],p[1200],filename[256];
  read_text("/proc/self/cgroup",text,sizeof(text));char *start=strstr(text,"0::");require(start!=0,"unified membership");start+=3;char *end=strchr(start,'\n');if(end)*end=0;
  require(snprintf(original,sizeof(original),"/sys/fs/cgroup%s",start)<(int)sizeof(original),"original membership path");
  control("/sys/fs/cgroup/cgroup.subtree_control","+memory +io");
  snprintf(group,sizeof(group),"/sys/fs/cgroup/trames-accept-%ld",(long)getpid());if(mkdir(group,0700))die("mkdir group");move_to(group);
  path(p,sizeof(p),group,"memory.current");unsigned long long before=number(p);
  size_t length=2*1024*1024;volatile unsigned char *bytes=mmap(0,length,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(bytes==MAP_FAILED)die("mmap");
  for(size_t i=0;i<length;i+=4096)bytes[i]=42;
  unsigned long long resident=number(p);require(resident>=before+length/2,"anonymous physical memory is charged");
  if(munmap((void*)bytes,length))die("munmap");
  snprintf(filename,sizeof(filename),"/tmp/trames-cgroup-io-%ld",(long)getpid());int fd=open(filename,O_CREAT|O_TRUNC|O_RDWR|O_CLOEXEC,0600);if(fd<0)die("data open");struct stat st;if(fstat(fd,&st))die("fstat");
  unsigned device_major=major(st.st_dev),device_minor=minor(st.st_dev);
  if(argc>1)require(sscanf(argv[1],"%u:%u",&device_major,&device_minor)==2,"device override");
  char limit[128];snprintf(limit,sizeof(limit),"%u:%u wbps=32768",device_major,device_minor);path(p,sizeof(p),group,"io.max");control(p,limit);
  unsigned char block[4096];memset(block,0x5a,sizeof(block));double begin=now();
  for(int i=0;i<16;i++)if(write(fd,block,sizeof(block))!=(ssize_t)sizeof(block))die("limited write");
  if(fsync(fd))die("fsync");
  double elapsed=now()-begin;require(elapsed>=0.8,"io.max delays actual backend IO");require(elapsed<20,"limited IO completes within its bound");
  path(p,sizeof(p),group,"io.stat");read_text(p,text,sizeof(text));printf("memory_before=%llu memory_resident=%llu io_seconds=%.6f io_stat=%s",before,resident,elapsed,text);fflush(stdout);
  path(p,sizeof(p),group,"io.max");
  snprintf(limit,sizeof(limit),"%u:%u wbps=max",device_major,device_minor);control(p,limit);
  if(close(fd))die("close data");
  if(unlink(filename))die("unlink data");
  move_to(original);
  if(rmdir(group))die("remove IO group");
  snprintf(group,sizeof(group),"/sys/fs/cgroup/trames-oom-%ld",(long)getpid());if(mkdir(group,0700))die("mkdir OOM group");path(p,sizeof(p),group,"memory.max");control(p,"65536");
  pid_t child=fork();if(child<0)die("fork");if(child==0){move_to(group);volatile unsigned char *memory=mmap(0,1024*1024,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(memory==MAP_FAILED)_exit(3);for(size_t i=0;i<1024*1024;i+=4096)memory[i]=7;_exit(4);}
  int status;if(waitpid(child,&status,0)!=child)die("waitpid");require(WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL,"actual limited child is OOM killed");
  path(p,sizeof(p),group,"memory.events");read_text(p,text,sizeof(text));printf("oom_events=%s",text);require(strstr(text,"oom_kill 0\n")==0&&strstr(text,"oom_kill ")!=0,"actual OOM event is reported");if(rmdir(group))die("remove OOM group");puts("CGROUP_ACCEPTANCE_PASS");return 0;
}
