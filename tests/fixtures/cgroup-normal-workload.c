// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static void die(const char *s){perror(s);exit(1);}
static double now(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))die("clock");return t.tv_sec+t.tv_nsec/1e9;}
int main(void){
  char name[128];snprintf(name,sizeof(name),"/tmp/trames-ordinary-%ld",(long)getpid());
  int fd=open(name,O_CREAT|O_TRUNC|O_RDWR,0600);if(fd<0)die("open");
  char block[4096];memset(block,0x5a,sizeof(block));double t=now();
  for(int i=0;i<4096;i++)if(write(fd,block,sizeof(block))!=sizeof(block))die("write");
  if(fsync(fd))die("fsync");
  unsigned long checksum=0;
  for(int i=0;i<4096;i++){if(pread(fd,block,sizeof(block),i*4096)!=sizeof(block))die("pread");for(size_t j=0;j<sizeof(block);j++)checksum+=(unsigned char)block[j];}
  double io=now()-t;t=now();struct stat st;
  for(int i=0;i<60000;i++){if(stat(name,&st))die("stat");int copy=open(name,O_RDONLY);if(copy<0)die("open metadata");if(close(copy))die("close metadata");}
  double metadata=now()-t;t=now();int pipefd[2];if(pipe(pipefd))die("pipe");
  for(int i=0;i<102400;i++){if(write(pipefd[1],block,sizeof(block))!=sizeof(block))die("pipe write");if(read(pipefd[0],block,sizeof(block))!=sizeof(block))die("pipe read");}
  double pipes=now()-t;close(pipefd[0]);close(pipefd[1]);
  if(checksum!=1509949440||st.st_size!=16777216){fprintf(stderr,"wrong content/size\n");return 1;}
  if(close(fd)||unlink(name))die("cleanup");
  printf("{\"io\":%.9f,\"metadata\":%.9f,\"pipe\":%.9f,\"checksum\":%lu}\n",io,metadata,pipes,checksum);return 0;
}
