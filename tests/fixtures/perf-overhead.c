/* SPDX-License-Identifier: GPL-3.0-or-later
 * Fixed work, reported inside the guest; startup/import is outside the timer.
 * Used unchanged against the previous delivery and the candidate.
 */
#define _GNU_SOURCE
#include <inttypes.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
static uint64_t now(void) {
  struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))exit(2);
  return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;
}
__attribute__((noinline)) static uint64_t work(uint64_t count) {
  uint64_t x=17;
  for(uint64_t i=0;i<count;++i) {
    x=(x^(x>>13))*UINT64_C(0x9e3779b97f4a7c15)+i;
    __asm__ volatile("" : "+r"(x));
  }
  return x;
}
int main(int argc,char **argv) {
  const char *mode=argc>1?argv[1]:"none";
  uint64_t count=argc>2?strtoull(argv[2],NULL,10):10000000;
  int fd=-1;size_t length=0;struct perf_event_mmap_page *ring=NULL;
  if(strcmp(mode,"none")) {
    struct perf_event_attr a={.size=sizeof(a),.type=PERF_TYPE_SOFTWARE,.config=PERF_COUNT_SW_TASK_CLOCK,.disabled=1,.exclude_kernel=1};
    if(!strcmp(mode,"sample")) {a.sample_period=1000000;a.sample_type=PERF_SAMPLE_IP;a.wakeup_events=1;}
    fd=syscall(__NR_perf_event_open,&a,0,-1,-1,0);
    if(fd<0) {perror("perf_event_open");return 2;}
    if(a.sample_period) {
      length=65*sysconf(_SC_PAGESIZE);ring=mmap(NULL,length,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
      if(ring==MAP_FAILED) {perror("mmap");return 2;}
    }
    if(strcmp(mode,"disabled")&&ioctl(fd,PERF_EVENT_IOC_ENABLE,0))return 2;
  }
  /* A warmup also lets disabled events retire their sampling fast-path hint. */
  work(count/10);uint64_t started=now();uint64_t checksum=work(count);uint64_t elapsed=now()-started;
  if(fd>=0&&ioctl(fd,PERF_EVENT_IOC_DISABLE,0))return 2;
  uint64_t samples=ring?__atomic_load_n(&ring->data_head,__ATOMIC_ACQUIRE)/16:0;
  if(ring)munmap(ring,length);
  if(fd>=0)close(fd);
  printf("{\"mode\":\"%s\",\"iterations\":%"PRIu64",\"elapsed_ns\":%"PRIu64",\"checksum\":%"PRIu64",\"samples\":%"PRIu64"}\n",mode,count,elapsed,checksum,samples);
  return 0;
}
