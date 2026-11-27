/* SPDX-License-Identifier: GPL-3.0-or-later
 * One unmodified AArch64 ELF is run on Linux and both Trames CPU backends.
 * Assertions describe observable ABI relationships, not scheduling counts.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *mode;
static int checks;
static void check(int ok, const char *what) {
  ++checks;
  if (!ok) {
    fprintf(stderr,"FAIL %s: %s (errno=%d %s)\n",mode,what,errno,strerror(errno));
    exit(1);
  }
}
static int event(struct perf_event_attr *a,int pid,int cpu,int group,unsigned flags) {
  return syscall(__NR_perf_event_open,a,pid,cpu,group,flags);
}
static struct perf_event_attr attr(uint64_t config) {
  struct perf_event_attr a={.size=sizeof(a),.type=PERF_TYPE_SOFTWARE,.config=config};
  return a;
}
__attribute__((noinline)) static uint64_t hot(uint64_t x) {
  for (int j=0;j<8;++j) x=(x^(x>>13))*UINT64_C(0x9e3779b97f4a7c15)+j;
  __asm__ volatile("" : "+r"(x));
  return x;
}
static uint64_t burn(unsigned n) {
  uint64_t x=17;
  for (unsigned i=0;i<n;++i) x=hot(x+i);
  return x;
}
static uint64_t value(int fd) {
  uint64_t v=0;check(read(fd,&v,sizeof(v))==sizeof(v),"read counter");return v;
}
static void command(int fd,unsigned long op,unsigned long arg) {
  check(ioctl(fd,op,arg)==0,"counter ioctl");
}
static void child_ok(pid_t pid) {
  int status=0;check(waitpid(pid,&status,0)==pid,"wait child");
  check(WIFEXITED(status)&&WEXITSTATUS(status)==0,"child status");
}
static int cpus[CPU_SETSIZE],ncpus;
static void affinity(void) {
  cpu_set_t set;CPU_ZERO(&set);check(sched_getaffinity(0,sizeof(set),&set)==0,"get affinity");
  for(int i=0;i<CPU_SETSIZE;++i) if(CPU_ISSET(i,&set)) cpus[ncpus++]=i;
  check(ncpus>0,"available CPU");
}
static void pin(int cpu) {
  cpu_set_t set;CPU_ZERO(&set);CPU_SET(cpu,&set);
  check(sched_setaffinity(0,sizeof(set),&set)==0,"set affinity");
}
static void abi(void) {
  struct perf_event_attr a=attr(PERF_COUNT_SW_TASK_CLOCK);
  a.disabled=1;a.read_format=PERF_FORMAT_TOTAL_TIME_ENABLED|PERF_FORMAT_TOTAL_TIME_RUNNING|PERF_FORMAT_ID;
  int fd=event(&a,0,-1,-1,PERF_FLAG_FD_CLOEXEC);check(fd>=0,"open task clock");
  uint64_t id=0;command(fd,PERF_EVENT_IOC_ID,(unsigned long)&id);check(id!=0,"event ID");
  command(fd,PERF_EVENT_IOC_ENABLE,0);
  usleep(30000);printf("checksum=%"PRIu64"\n",burn(100000));
  command(fd,PERF_EVENT_IOC_DISABLE,0);
  uint64_t r[4],again[4];check(read(fd,r,sizeof(r))==sizeof(r),"read timed counter");
  printf("raw timing value=%"PRIu64" enabled=%"PRIu64" running=%"PRIu64" id=%"PRIu64"\n",r[0],r[1],r[2],r[3]);
  check(r[0]>0&&r[0]==r[1]&&r[1]==r[2]&&r[3]==id,"value/enabled/running/id");

  burn(10000);check(read(fd,again,sizeof(again))==sizeof(again)&&!memcmp(r,again,sizeof(r)),"disabled counter freezes");
  command(fd,PERF_EVENT_IOC_RESET,0);check(read(fd,again,sizeof(again))==sizeof(again),"read reset");
  check(again[0]==0&&again[1]==r[1]&&again[2]==r[2]&&again[3]==id,"reset preserves times and identity");
  check(fcntl(fd,F_GETFD)&FD_CLOEXEC,"CLOEXEC");
  int alias=dup(fd);check(alias>=0,"dup counter");close(fd);
  command(alias,PERF_EVENT_IOC_ENABLE,0);burn(10000);command(alias,PERF_EVENT_IOC_DISABLE,0);
  check(read(alias,again,sizeof(again))==sizeof(again)&&again[0]>0,"OFD survives alias close");close(alias);
  a.read_format=0;
  errno=0;check(event(&a,-2,-1,-1,0)==-1&&errno==ESRCH,"negative target PID is absent");
  errno=0;check(event(&a,-1,cpus[0],-1,PERF_FLAG_PID_CGROUP)==-1&&errno==EINVAL,"cgroup scope requires a directory FD");
  errno=0;check(event(&a,-2,cpus[0],-1,PERF_FLAG_PID_CGROUP)==-1&&errno==EBADF,"negative cgroup FD lookup");
  a.config=PERF_COUNT_SW_MAX+64;errno=0;
  check(event(&a,0,-1,-1,0)==-1,"invalid software configuration rejected");
  printf("timing value=%"PRIu64" enabled=%"PRIu64" running=%"PRIu64"\n",r[0],r[1],r[2]);
}
static void count(void) {
  const unsigned configs[]={PERF_COUNT_SW_PAGE_FAULTS,PERF_COUNT_SW_CONTEXT_SWITCHES,
    PERF_COUNT_SW_CPU_MIGRATIONS,PERF_COUNT_SW_PAGE_FAULTS_MIN,PERF_COUNT_SW_PAGE_FAULTS_MAJ};
  int fd[5];
  for(int i=0;i<5;++i) {
    struct perf_event_attr a=attr(configs[i]);a.inherit=1;
    fd[i]=event(&a,0,-1,-1,0);check(fd[i]>=0,"open produced software event");
  }
  size_t page=sysconf(_SC_PAGESIZE),bytes=128*page;
  volatile unsigned char *p=mmap(0,bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  check(p!=MAP_FAILED,"map anonymous faults");
  for(size_t i=0;i<bytes;i+=page) p[i]=1;
  int pipefd[2];check(pipe(pipefd)==0,"pipe");
  pid_t child=fork();check(child>=0,"fork inherited counters");
  if(!child) {
    for(size_t i=0;i<bytes;i+=page) p[i]=2;
    char byte;close(pipefd[1]);while(read(pipefd[0],&byte,1)==1) {}
    _exit(0);
  }
  close(pipefd[0]);usleep(10000);
  if(ncpus>1) {pin(cpus[1]);burn(10000);pin(cpus[0]);}
  close(pipefd[1]);child_ok(child);
  uint64_t v[5];for(int i=0;i<5;++i) {command(fd[i],PERF_EVENT_IOC_DISABLE,0);v[i]=value(fd[i]);close(fd[i]);}
  check(v[0]>=256&&v[3]>=256,"anonymous first write and inherited COW faults");
  check(v[0]>=v[3]&&v[0]>=v[4],"total/minor/major relationship");
  check(v[1]>0,"actual descheduling counted");
  if(ncpus>1) check(v[2]>0,"affinity migration counted");
  munmap((void*)p,bytes);
  printf("faults=%"PRIu64" switches=%"PRIu64" migrations=%"PRIu64" minor=%"PRIu64" major=%"PRIu64"\n",v[0],v[1],v[2],v[3],v[4]);
}
struct fault_wake {volatile unsigned char *page;size_t length;int fd;};
static int wake_fault_reader(void *argument) {
  struct fault_wake *wake=argument;
  usleep(50000);
  /* Discard in the same mm after read has entered its wait. Any eager input
   * check no longer makes the eventual copyout page resident. */
  if(madvise((void*)wake->page,wake->length,MADV_DONTNEED))return 115;
  return write(wake->fd,"x",1)==1?0:116;
}
static void fault_modes(void) {
  size_t page=sysconf(_SC_PAGESIZE);
  volatile unsigned char *p=mmap(0,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  check(p!=MAP_FAILED,"map fault destinations");
  int pipefd[2];check(pipe(pipefd)==0,"blocked copyout pipe");
  size_t stack_length=16*page;
  void *stack=mmap(0,stack_length,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  check(stack!=MAP_FAILED,"shared-mm helper stack");
  struct fault_wake wake={p,page,pipefd[1]};
  pid_t child=clone(wake_fault_reader,(char*)stack+stack_length,CLONE_VM|SIGCHLD,&wake);
  check(child>=0,"shared-mm fault producer child");
  close(pipefd[1]);
  struct perf_event_attr a=attr(PERF_COUNT_SW_PAGE_FAULTS_MIN);a.exclude_user=1;
  int kernel=event(&a,0,-1,-1,0);check(kernel>=0,"kernel-only minor faults");
  a.exclude_user=0;a.exclude_kernel=1;
  int user=event(&a,0,-1,-1,0);check(user>=0,"user-only minor faults");
  uint64_t before_user=value(user),before_kernel=value(kernel);
  check(read(pipefd[0],(void*)p,1)==1,"blocked read resumes into missing output page");
  uint64_t kernel_after=value(kernel),user_after=value(user);
  check(kernel_after>before_kernel,"syscall copyout fault is kernel mode");
  check(user_after==before_user,"syscall continuation is excluded from user faults");
  p[page]=7;
  check(value(user)>user_after,"guest first write is user mode");
  check(value(kernel)==kernel_after,"guest write excluded from kernel faults");
  check(p[0]=='x',"copyout contents");close(pipefd[0]);child_ok(child);close(kernel);close(user);munmap((void*)p,2*page);munmap(stack,stack_length);
}
static void scope(void) {
  /* Retire a previous base observer on CPU 0, then move while no observer
   * runs. Creating CPU 0's first filter on CPU 1 must not start its clock. */
  if(ncpus>1) {
    pin(cpus[0]);struct perf_event_attr warm=attr(PERF_COUNT_SW_TASK_CLOCK);
    int previous=event(&warm,0,-1,-1,0);check(previous>=0,"warm original task observer");
    burn(10000);close(previous);burn(500000);pin(cpus[1]);burn(10000);
  }
  struct perf_event_attr a=attr(PERF_COUNT_SW_TASK_CLOCK);a.disabled=1;
  int selected=cpus[0];int fd=event(&a,0,selected,-1,0);check(fd>=0,"task+CPU event");
  if(ncpus>1) {
    pin(cpus[1]);command(fd,PERF_EVENT_IOC_ENABLE,0);burn(100000);
    check(value(fd)==0,"task CPU filter excludes other CPU");
  } else command(fd,PERF_EVENT_IOC_ENABLE,0);
  pin(selected);burn(100000);command(fd,PERF_EVENT_IOC_DISABLE,0);
  check(value(fd)>0,"task CPU filter counts selected CPU");close(fd);
  a=attr(PERF_COUNT_SW_CPU_CLOCK);fd=event(&a,-1,selected,-1,0);check(fd>=0,"CPU-wide event");
  uint64_t before=value(fd);usleep(30000);uint64_t after=value(fd);
  check(after>=before+20000000,"CPU clock includes idle time");close(fd);
  int gate[2];check(pipe(gate)==0,"remote gate");pid_t child=fork();check(child>=0,"remote child");
  if(!child) {close(gate[1]);char b;check(read(gate[0],&b,1)==1,"remote release");burn(100000);_exit(0);}
  close(gate[0]);a=attr(PERF_COUNT_SW_TASK_CLOCK);fd=event(&a,child,-1,-1,0);check(fd>=0,"remote original task");
  before=value(fd);burn(100000);after=value(fd);check(after-before<1000000,"remote event excludes observer execution");
  check(write(gate[1],"x",1)==1,"release remote");close(gate[1]);child_ok(child);
  after=value(fd);check(after>before,"remote task executes");burn(10000);check(value(fd)==after,"dead original task counter freezes");
  struct pollfd pollfd={.fd=fd,.events=POLLIN};check(poll(&pollfd,1,0)==1&&(pollfd.revents&POLLHUP),"dead original task HUP");close(fd);
}
static void sample(void) {
  struct perf_event_attr a=attr(PERF_COUNT_SW_TASK_CLOCK);
  a.sample_period=500000;a.sample_type=PERF_SAMPLE_IP|PERF_SAMPLE_TID|PERF_SAMPLE_TIME|PERF_SAMPLE_CPU|PERF_SAMPLE_PERIOD|PERF_SAMPLE_IDENTIFIER;
  a.disabled=1;a.exclude_kernel=1;a.inherit=1;a.mmap=1;a.mmap2=1;a.comm=1;a.comm_exec=1;a.task=1;a.sample_id_all=1;a.wakeup_events=1;
  pin(cpus[0]);int fd=event(&a,0,cpus[0],-1,0);check(fd>=0,"open sampled clock with sideband");
  size_t page=sysconf(_SC_PAGESIZE),length=65*page;
  struct perf_event_mmap_page *meta=mmap(0,length,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
  check(meta!=MAP_FAILED,"map sample ring");command(fd,PERF_EVENT_IOC_ENABLE,0);
  pid_t child=fork();check(child>=0,"sample child");
  if(!child) {execl("/proc/self/exe","perf-tools","cpu","500000",NULL);_exit(111);}
  burn(500000);child_ok(child);command(fd,PERF_EVENT_IOC_DISABLE,0);
  uint64_t head=__atomic_load_n(&meta->data_head,__ATOMIC_ACQUIRE),tail=meta->data_tail;
  size_t size=meta->data_size,offset=meta->data_offset;check(size==64*page&&offset==page,"ring geometry");
  check(head>=tail&&head-tail<=size,"bounded ring occupancy");
  unsigned records[32]={0},users=0;uint64_t samples=0;
  while(tail<head) {
    struct perf_event_header h;unsigned char *data=(unsigned char*)meta+offset;
    for(size_t i=0;i<sizeof(h);++i) ((unsigned char*)&h)[i]=data[(tail+i)%size];
    check(h.size>=sizeof(h)&&h.size%8==0&&h.size<=head-tail,"record framing");
    if(h.type<32) ++records[h.type];
    if(h.type==PERF_RECORD_SAMPLE) {
      uint64_t ip=0;for(size_t i=0;i<8;++i) ((unsigned char*)&ip)[i]=data[(tail+16+i)%size];
      ++samples;if((h.misc&PERF_RECORD_MISC_CPUMODE_MASK)==PERF_RECORD_MISC_USER&&ip) ++users;
    }
    tail+=h.size;
  }
  __atomic_store_n(&meta->data_tail,tail,__ATOMIC_RELEASE);
  check(samples>0&&users>0,"actual user samples with guest PC");
  check(records[PERF_RECORD_FORK]&&records[PERF_RECORD_EXIT],"original fork/exit sideband");
  check(records[PERF_RECORD_COMM]&&(records[PERF_RECORD_MMAP]||records[PERF_RECORD_MMAP2]),"exec comm/map sideband");
  printf("records samples=%"PRIu64" user=%u comm=%u mmap=%u mmap2=%u fork=%u exit=%u lost=%u\n",samples,users,records[3],records[1],records[10],records[7],records[4],records[2]);
  munmap(meta,length);close(fd);
}
static void mapping(void) {
  struct perf_event_attr a=attr(PERF_COUNT_SW_TASK_CLOCK);a.sample_period=1000000;
  int fd=event(&a,0,-1,-1,0);check(fd>=0,"mapping event");
  size_t page=sysconf(_SC_PAGESIZE),length=9*page;
  unsigned char *p=mmap(0,length,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);check(p!=MAP_FAILED,"mapping ring");
  errno=0;check(munmap(p+page,page)==-1&&errno==EINVAL,"partial munmap cannot split perf VMA");
  check(mprotect(p+page,page,PROT_READ|PROT_WRITE)==0,"unchanged partial protection does not split VMA");
  errno=0;check(mprotect(p+page,page,PROT_READ)==-1&&errno==EINVAL,"partial mprotect cannot split perf VMA");
  check(mprotect(p,length,PROT_READ)==0&&mprotect(p,length,PROT_READ|PROT_WRITE)==0,"whole mapping protection");
  errno=0;check(madvise(p,length,MADV_DODUMP)==-1&&errno==EINVAL,"perf VMA cannot enter core dump");
  errno=0;check(mremap(p,length,length-page,0)==MAP_FAILED&&errno==EINVAL,"perf VMA cannot shrink");
  errno=0;check(mremap(p,length,length+page,MREMAP_MAYMOVE)==MAP_FAILED&&errno==EFAULT,"perf VMA cannot expand");
  void *target=mmap(0,length,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);check(target!=MAP_FAILED,"reserve move destination");
  void *moved=mremap(p,length,length,MREMAP_MAYMOVE|MREMAP_FIXED,target);
  check(moved==target,"whole mapping fixed relocation");munmap(moved,length);
  pid_t child=fork();check(child>=0,"data-page protection child");
  if(!child) {unsigned char *q=mmap(0,length,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);if(q==MAP_FAILED)_exit(112);q[page]=1;_exit(113);}
  int status;check(waitpid(child,&status,0)==child,"wait data write");check(WIFSIGNALED(status)&&WTERMSIG(status)==SIGBUS,"ring data page write SIGBUS");
  close(fd);
}
static void write_text(const char *path,const char *text) {
  int fd=open(path,O_WRONLY|O_CLOEXEC);check(fd>=0,"open cgroup control");
  check(write(fd,text,strlen(text))==(ssize_t)strlen(text),"write cgroup control");close(fd);
}
static void cgroup(void) {
  pin(cpus[0]);char group[256],control[300];
  snprintf(group,sizeof(group),"/sys/fs/cgroup/trames-perf-%ld",(long)getpid());
  check(mkdir(group,0700)==0,"create observed cgroup");
  int directory=open(group,O_RDONLY|O_DIRECTORY|O_CLOEXEC);check(directory>=0,"open original cgroup");
  struct perf_event_attr a=attr(PERF_COUNT_SW_TASK_CLOCK);
  int fd=event(&a,directory,cpus[0],-1,PERF_FLAG_PID_CGROUP);check(fd>=0,"open cgroup+CPU event");
  check(value(fd)==0,"empty cgroup has no task time");burn(100000);
  check(value(fd)==0,"unrelated observer excluded from cgroup");
  for(int generation=0;generation<2;++generation) {
    int gate[2];check(pipe(gate)==0,"cgroup child gate");pid_t child=fork();check(child>=0,"cgroup child");
    if(!child) {close(gate[1]);char b;check(read(gate[0],&b,1)==1,"cgroup release");burn(200000);_exit(0);}
    close(gate[0]);snprintf(control,sizeof(control),"%s/cgroup.procs",group);
    char pid[32];snprintf(pid,sizeof(pid),"%ld",(long)child);write_text(control,pid);
    int next=-1;if(generation) {
      int replacement=open(group,O_RDONLY|O_DIRECTORY|O_CLOEXEC);check(replacement>=0,"open replacement cgroup");
      next=event(&a,replacement,cpus[0],-1,PERF_FLAG_PID_CGROUP);close(replacement);check(next>=0,"observe replacement cgroup");
    }
    uint64_t before=value(fd);check(write(gate[1],"x",1)==1,"release observed child");close(gate[1]);child_ok(child);
    uint64_t after=value(fd);
    if(!generation) check(after>before,"original cgroup counts execution");
    else {check(after==before,"removed cgroup identity is not redirected by pathname");check(value(next)>0,"replacement cgroup counts independently");close(next);}
    check(rmdir(group)==0,"remove observed cgroup");
    if(!generation) check(mkdir(group,0700)==0,"recreate same cgroup pathname");
  }
  close(fd);close(directory);
}
static void secure_after(int fd) {
  check(geteuid()==0,"setuid image actually gained EUID");
  uint64_t before=value(fd);burn(200000);check(value(fd)==before,"privileged exec detaches previous context");
  struct perf_event_attr a=attr(PERF_COUNT_SW_TASK_CLOCK);int next=event(&a,0,-1,-1,0);check(next>=0,"living task opens new perf context");
  burn(100000);check(value(next)>0,"new context executes");close(next);close(fd);
}
static void secure_exec(const char *path) {
  struct stat st;check(stat(path,&st)==0&&(st.st_mode&S_ISUID)&&st.st_uid==0,"root-owned setuid fixture");
  pid_t child=fork();check(child>=0,"secure exec child");
  if(!child) {
    check(setresgid(1000,1000,1000)==0&&setresuid(1000,1000,1000)==0,"drop credentials");
    struct perf_event_attr a=attr(PERF_COUNT_SW_TASK_CLOCK);a.exclude_kernel=1;
    int fd=event(&a,0,-1,-1,0);check(fd>=0,"unprivileged self event");burn(10000);
    char number[32];snprintf(number,sizeof(number),"%d",fd);execl(path,path,"secure-after",number,NULL);_exit(114);
  }
  child_ok(child);
}
int main(int argc,char **argv) {
  mode=argc>1?argv[1]:"abi";
  setvbuf(stdout,NULL,_IOLBF,0);affinity();
  if(!strcmp(mode,"cpu")) {
    size_t page=sysconf(_SC_PAGESIZE),length=64*page;
    volatile unsigned char *p=mmap(0,length,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    check(p!=MAP_FAILED,"workload demand pages");
    for(size_t i=0;i<length;i+=page) p[i]=1;
    printf("checksum=%"PRIu64"\n",burn(argc>2?strtoul(argv[2],0,0):500000));
    check(munmap((void*)p,length)==0,"workload unmap");
  }
  else if(!strcmp(mode,"abi")) abi();
  else if(!strcmp(mode,"count")) count();
  else if(!strcmp(mode,"fault-modes")) fault_modes();
  else if(!strcmp(mode,"scope")) scope();
  else if(!strcmp(mode,"sample")) sample();
  else if(!strcmp(mode,"mapping")) mapping();
  else if(!strcmp(mode,"cgroup")) cgroup();
  else if(!strcmp(mode,"secure-after")) secure_after(atoi(argv[2]));
  else if(!strcmp(mode,"secure-exec")) secure_exec(argc>2?argv[2]:argv[0]);
  else {fprintf(stderr,"unknown mode %s\n",mode);return 2;}
  printf("PASS %s checks=%d cpus=%d\n",mode,checks,ncpus);return 0;
}
