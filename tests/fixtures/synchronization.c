// SPDX-License-Identifier: GPL-3.0-or-later
// Same static glibc ELF runs on ARM64 Linux, interpreter and HVF.
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/rseq.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#define W 449
#define WAKE 454
#define WAIT 455
#define REQUEUE 456
#define U32 2
#define PRIV (2|128)
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line=%d %s errno=%d\n",__LINE__,#x,errno); exit(1); } } while (0)
static int checks;
#define OK(name) do { printf("PASS %s\n",name); checks++; } while (0)
static long result(long r) { return r < 0 ? -errno : r; }
static struct timespec deadline(int ms) {
 struct timespec t; CHECK(!clock_gettime(CLOCK_MONOTONIC,&t));
 t.tv_nsec += (long)ms*1000000; t.tv_sec += t.tv_nsec/1000000000; t.tv_nsec%=1000000000; return t;
}
static uint64_t ns(void) { struct timespec t; CHECK(!clock_gettime(CLOCK_MONOTONIC,&t)); return (uint64_t)t.tv_sec*1000000000+t.tv_nsec; }
static long wake(uint32_t *p,unsigned mask,int n,unsigned f) { return result(syscall(WAKE,p,(unsigned long)mask,n,f)); }
static struct futex_waitv word(uint32_t *p,unsigned f) { return (struct futex_waitv){.uaddr=(uintptr_t)p,.flags=f}; }
struct waiter { struct futex_waitv v[2]; int count, vector, restart; unsigned mask; int timeout; _Atomic int ready,done; long ret; pthread_t thread; };
static void *waiter(void *v) {
 struct waiter *w=v; struct timespec t=deadline(w->timeout ? w->timeout : 3000);
 atomic_store(&w->ready,1);
 if (w->vector) w->ret=result(syscall(W,w->v,w->count,0,&t,CLOCK_MONOTONIC));
 else w->ret=result(syscall(WAIT,(void *)(uintptr_t)w->v[0].uaddr,0UL,(unsigned long)w->mask,w->v[0].flags,&t,CLOCK_MONOTONIC));
 atomic_store(&w->done,1); return NULL;
}
static void start(struct waiter *w) { CHECK(!pthread_create(&w->thread,NULL,waiter,w)); while(!atomic_load(&w->ready)) sched_yield(); usleep(20000); }
static void join(struct waiter *w,long expected) { CHECK(!pthread_join(w->thread,NULL)); CHECK(w->ret==expected); }
static long eventually_wake(uint32_t *p,unsigned mask,int n,unsigned f) {
 for (int i=0;i<1000;i++) { long r=wake(p,mask,n,f); if(r) return r; usleep(1000); } return 0;
}
static void validation(void) {
 uint32_t a=1,b=0; struct futex_waitv v[2]={word(&a,PRIV),word(&b,PRIV)};
 struct timespec past={0},bad={.tv_nsec=1000000000};
 CHECK(result(syscall(W,v,0,0,NULL,1))==-EINVAL);
 CHECK(result(syscall(W,v,129,0,NULL,1))==-EINVAL);
 CHECK(result(syscall(W,v,1,1,NULL,1))==-EINVAL);
 CHECK(result(syscall(W,NULL,1,0,NULL,1))==-EINVAL);
 CHECK(result(syscall(W,v,1,0,NULL,99))==-EAGAIN);
 v[0].__reserved=1; CHECK(result(syscall(W,v,1,0,NULL,1))==-EINVAL); v[0].__reserved=0;
 v[0].val=1ULL<<32; CHECK(result(syscall(W,v,1,0,NULL,1))==-EINVAL); v[0].val=0;
 for(unsigned f=0;f<4;f++) if(f!=2) {v[0].flags=f;CHECK(result(syscall(W,v,1,0,NULL,1))==-EINVAL);}
 v[0].flags=PRIV;
 CHECK(result(syscall(W,v,1,0,&past,99))==-EINVAL);
 CHECK(result(syscall(W,v,1,0,&bad,1))==-EINVAL);
 CHECK(result(syscall(WAIT,&a,0UL,1UL,PRIV,NULL,99))==-EAGAIN);
 CHECK(result(syscall(WAIT,&a,1UL<<32,1UL,PRIV,NULL,1))==-EINVAL);
 CHECK(result(syscall(WAIT,&a,0UL,1UL<<32,PRIV,NULL,1))==-EINVAL);
 CHECK(result(syscall(WAIT,&a,0UL,0UL,PRIV,NULL,1))==-EINVAL);
 CHECK(result(syscall(WAIT,(char *)&a+1,0UL,1UL,PRIV,NULL,1))==-EINVAL);
 CHECK(result(syscall(WAKE,&a,0UL,1,PRIV))==-EINVAL);
 CHECK(result(syscall(WAKE,&a,1UL<<32,1,PRIV))==-EINVAL);
 CHECK(result(syscall(REQUEUE,v,1,0,1))==-EINVAL);
 CHECK(result(syscall(REQUEUE,v,0,-1,1))==-EINVAL);
 CHECK(result(syscall(REQUEUE,v,0,0,-1))==-EINVAL);
 CHECK(result(syscall(REQUEUE,v,0,0,1))==-EAGAIN);
 CHECK(result(syscall(W,v,(1ULL<<32)|1,1ULL<<32,NULL,1))==-EAGAIN);
 a=0; CHECK(result(syscall(W,v,1,0,&past,1))==-ETIMEDOUT);
 CHECK(result(syscall(WAIT,&a,0UL,1UL,PRIV,&past,1))==-ETIMEDOUT);
 CHECK(wake(&a,~0U,INT_MAX,PRIV)==0);
 OK("futex2-validation-truncation-timeout");
}
static void queue_tests(void) {
 uint32_t a=0,b=0;
 struct waiter x={.v={word(&a,PRIV)},.count=1,.mask=1};
 struct waiter y={.v={word(&a,PRIV)},.count=1,.mask=2}; start(&x); start(&y);
 CHECK(wake(&a,3,0,PRIV)==0); CHECK(wake(&a,4,INT_MAX,PRIV)==0);
 CHECK(eventually_wake(&a,1,-1,PRIV)==1); join(&x,0);
 CHECK(eventually_wake(&a,2,-1,PRIV)==1); join(&y,0); CHECK(wake(&a,3,-1,PRIV)==0);
 OK("futex2-bitset-zero-negative-wake");
 for(int f=0;f<2;f++) {
  unsigned old=f?PRIV:U32,dest=f?U32:PRIV;
  struct waiter w={.v={word(&a,old)},.count=1,.mask=1}; start(&w);
  struct futex_waitv v[2]={word(&a,old),word(&b,dest)};
  CHECK(result(syscall(REQUEUE,v,0,0,1))==-EINVAL);
  v[1].flags=old; dest=old;
  long r=0; for(int i=0;i<1000 && !r;i++){r=result(syscall(REQUEUE,v,0,0,1));if(!r)usleep(1000);} CHECK(r==1);
  CHECK(wake(&a,1,1,old)==0); CHECK(wake(&b,1,1,dest)==1); join(&w,0);
 }
 OK("futex2-requeue-mixed-rejection-private-shared");
 for(int i=0;i<24;i++) {
  struct waiter w={.v={word(&a,PRIV),word(&b,PRIV)},.vector=1,.count=2}; start(&w);
  int index=i&1; CHECK(eventually_wake(index?&b:&a,~0U,1,PRIV)==1); join(&w,index);
  CHECK(wake(&a,~0U,INT_MAX,PRIV)==0); CHECK(wake(&b,~0U,INT_MAX,PRIV)==0);
 }
 OK("waitv-index-other-ticket-cancel");
 for(int vector=0;vector<2;vector++) {
  struct waiter w={.v={word(&a,PRIV),word(&b,PRIV)},.vector=vector,.count=2,.mask=1,.timeout=30}; start(&w); join(&w,-ETIMEDOUT);
  CHECK(wake(&a,~0U,INT_MAX,PRIV)==0); CHECK(wake(&b,~0U,INT_MAX,PRIV)==0);
 }
 OK("waitv-wait-timeout-cleanup");
}
static volatile sig_atomic_t signals;
static void handler(int sig) { (void)sig; signals++; }
static void signal_tests(void) {
 struct sigaction action={.sa_handler=handler}; sigemptyset(&action.sa_mask); CHECK(!sigaction(SIGUSR1,&action,NULL));
 uint32_t a=0;
 for(int vector=0;vector<2;vector++) {
  struct waiter w={.v={word(&a,PRIV)},.vector=vector,.count=1,.mask=1}; start(&w);
  CHECK(!pthread_kill(w.thread,SIGUSR1)); join(&w,-EINTR); CHECK(wake(&a,~0U,INT_MAX,PRIV)==0);
 }
 action.sa_flags=SA_RESTART; CHECK(!sigaction(SIGUSR1,&action,NULL));
 for(int vector=0;vector<2;vector++) {
  struct waiter w={.v={word(&a,PRIV)},.vector=vector,.count=1,.mask=1}; start(&w);
  CHECK(!pthread_kill(w.thread,SIGUSR1)); usleep(10000);
  CHECK(eventually_wake(&a,~0U,1,PRIV)==1); join(&w,0);
 }
 CHECK(signals==4); OK("futex2-signal-eintr-restart-cleanup");
}
static void shared_tests(void) {
 int fd=memfd_create("sync-alias",0); CHECK(fd>=0); CHECK(!ftruncate(fd,4096));
 uint32_t *a=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
 uint32_t *b=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0); CHECK(a!=MAP_FAILED && b!=MAP_FAILED && a!=b);
 int pipefd[2]; CHECK(!pipe(pipefd)); pid_t pid=fork();CHECK(pid>=0);
 if(!pid) { close(pipefd[0]); struct futex_waitv v=word(a,U32);struct timespec t=deadline(3000);CHECK(write(pipefd[1],"x",1)==1); long r=result(syscall(W,&v,1,0,&t,1));_exit(r==0?0:11); }
 close(pipefd[1]);char c;CHECK(read(pipefd[0],&c,1)==1); CHECK(eventually_wake(b,~0U,1,U32)==1);int status;CHECK(waitpid(pid,&status,0)==pid);CHECK(status==0);close(pipefd[0]);
 OK("waitv-shared-alias-fork");
 // Killing a blocked task must remove both members of the logical vector.
 CHECK(!pipe(pipefd));pid=fork();CHECK(pid>=0);
 if(!pid){struct futex_waitv v[2]={word(a,U32),word(a+1,U32)};close(pipefd[0]);CHECK(write(pipefd[1],"x",1)==1);syscall(W,v,2,0,NULL,1);_exit(12);}
 close(pipefd[1]);CHECK(read(pipefd[0],&c,1)==1);usleep(20000);CHECK(!kill(pid,SIGKILL));CHECK(waitpid(pid,&status,0)==pid);CHECK(WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL);
 CHECK(wake(b,~0U,INT_MAX,U32)==0);CHECK(wake(b+1,~0U,INT_MAX,U32)==0);close(pipefd[0]);
 CHECK(!munmap(a,4096));CHECK(!munmap(b,4096));close(fd);OK("waitv-task-exit-ticket-cleanup");
}
static void rseq_identity(void) {
 cpu_set_t original,one;CHECK(!sched_getaffinity(0,sizeof(original),&original));int enabled=__rseq_size!=0;
 for(int i=0;i<CPU_SETSIZE;i++) if(CPU_ISSET(i,&original)) {
  CPU_ZERO(&one);CPU_SET(i,&one);CHECK(!sched_setaffinity(0,sizeof(one),&one));
  for(int j=0;j<100;j++){unsigned cpu,node;CHECK(!syscall(SYS_getcpu,&cpu,&node,NULL));CHECK(sched_getcpu()==i && cpu==(unsigned)i);if(enabled){struct rseq *r=(void *)((char *)__builtin_thread_pointer()+__rseq_offset);CHECK(r->cpu_id==(unsigned)i && r->cpu_id_start==(unsigned)i);}if(!(j%10)){raise(SIGUSR1);sched_yield();}}
 }
 CHECK(!sched_setaffinity(0,sizeof(original),&original));printf("INFO glibc_rseq_size=%u offset=%td feature=%lu align=%lu\n",__rseq_size,__rseq_offset,getauxval(27),getauxval(28));OK(enabled?"glibc-rseq-affinity-signal-preempt":"glibc-getcpu-fallback-affinity-signal");
}
static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
static unsigned long counter;
static int repetitions;
static void *contend(void *unused) { (void)unused;for(int i=0;i<repetitions;i++){CHECK(!pthread_mutex_lock(&mutex));counter++;CHECK(!pthread_mutex_unlock(&mutex));} return NULL; }
static void performance(int n) {
 uint32_t a=0;uint64_t t=ns();for(int i=0;i<n;i++)CHECK(result(syscall(SYS_futex,&a,FUTEX_WAKE_PRIVATE,1,0,0,0))==0);uint64_t elapsed=ns()-t;printf("PERF legacy_wake iterations=%d elapsed_ns=%lu ns_per_op=%.2f\n",n,(unsigned long)elapsed,(double)elapsed/n);
 volatile unsigned sum=0;t=ns();for(int i=0;i<n;i++){int cpu=sched_getcpu();CHECK(cpu>=0);sum+=(unsigned)cpu;}elapsed=ns()-t;printf("PERF glibc_sched_getcpu rseq_size=%u iterations=%d elapsed_ns=%lu ns_per_op=%.2f checksum=%u\n",__rseq_size,n,(unsigned long)elapsed,(double)elapsed/n,sum);
 repetitions=n;pthread_t threads[4];t=ns();for(int i=0;i<4;i++)CHECK(!pthread_create(&threads[i],NULL,contend,NULL));for(int i=0;i<4;i++)CHECK(!pthread_join(threads[i],NULL));elapsed=ns()-t;CHECK(counter==(unsigned long)n*4);printf("PERF glibc_mutex threads=4 operations=%lu elapsed_ns=%lu ops_per_sec=%.2f\n",counter,(unsigned long)elapsed,(double)counter*1e9/elapsed);
}
int main(int argc,char **argv) {
 alarm(30);setvbuf(stdout,NULL,_IOLBF,0);
 if(argc>1 && !strcmp(argv[1],"perf")){performance(argc>2?atoi(argv[2]):10000);return 0;}
 validation();queue_tests();signal_tests();shared_tests();rseq_identity();printf("SUMMARY passed=%d\n",checks);return 0;
}
