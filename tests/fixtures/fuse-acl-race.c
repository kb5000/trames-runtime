// SPDX-License-Identifier: GPL-3.0-or-later
// Concurrent cache-fill ownership, controlled by request/completion handshakes.
#define main permissions_fixture_main
#include "fuse-posix-acl.c"
#undef main
#include <poll.h>
#include <signal.h>
#define RACES 12
static struct fuse_in_header pending[RACES][2];
static unsigned queries[RACES], race_releases;
static int notify_fd;
static void event(char value) { CHECK(write(notify_fd,&value,1)==1); }
static void acl_value(int fd,const struct fuse_in_header *in,unsigned perm) {
 struct {uint32_t version;struct acl_entry e[5];} value={2,{{1,0,UINT32_MAX},{2,perm,1000},{4,0,UINT32_MAX},{16,7,UINT32_MAX},{32,4,UINT32_MAX}}};
 reply(fd,in,0,&value,sizeof(value));
}
static struct fuse_attr race_attr(uint64_t node) {
 return node==1?attr(1):(struct fuse_attr){.ino=node,.mode=S_IFREG|0044,.nlink=1,.blksize=4096};
}
static void respond(int fd,unsigned test,unsigned which) {
 struct fuse_in_header *request=&pending[test][which];CHECK(request->unique);
 if(!which&&(test==3||test==7))reply(fd,request,EIO,NULL,0);
 else if(!which&&test==4)reply(fd,request,ENODATA,NULL,0);
 else acl_value(fd,request,which?6:4);
 request->unique=0;
}
static void serve_race(int fd,int controls) {
 for(;;){
  struct pollfd watch[2]={{.fd=fd,.events=POLLIN},{.fd=controls,.events=POLLIN}};
  CHECK(poll(watch,2,-1)>0);
  if(watch[1].revents&POLLIN){unsigned char command[2];CHECK(read(controls,command,2)==2);CHECK(command[0]<RACES&&command[1]<2);respond(fd,command[0],command[1]);}
  if(!(watch[0].revents&(POLLIN|POLLERR|POLLHUP)))continue;
  ssize_t size=read(fd,input,sizeof(input));
  if(size<0&&errno==ENODEV){for(unsigned i=0;i<RACES;i++){fprintf(stderr,"acl-race-queries case=%u count=%u\n",i,queries[i]);CHECK(queries[i]==((i==3||i==5||i==7||i==10)?3:2));}_exit(0);}
  CHECK(size>=(ssize_t)sizeof(struct fuse_in_header));const struct fuse_in_header *in=(void*)input;const void *body=input+sizeof(*in);CHECK(in->len==size);
  switch(in->opcode){
  case FUSE_INIT:{struct fuse_init_out out={.major=7,.minor=31,.flags=FUSE_BIG_WRITES|FUSE_POSIX_ACL|FUSE_DONT_MASK|FUSE_SETXATTR_EXT,.max_write=16384,.time_gran=1};reply(fd,in,0,&out,sizeof(out));break;}
  case FUSE_LOOKUP:{CHECK(in->nodeid==1);char *end;unsigned long test=strtoul(body,&end,10);CHECK(!*end&&test<RACES);struct fuse_entry_out out={.nodeid=100+test,.generation=1,.entry_valid=3600,.attr_valid=3600,.attr=race_attr(100+test)};reply(fd,in,0,&out,sizeof(out));break;}
  case FUSE_GETATTR:{struct fuse_attr_out out={.attr_valid=3600,.attr=race_attr(in->nodeid)};reply(fd,in,0,&out,sizeof(out));break;}
  case FUSE_GETXATTR:{const struct fuse_getxattr_in *get=body;const char *name=(const char*)body+sizeof(*get);CHECK(get->size==4096);if(in->nodeid==1){reply(fd,in,ENODATA,NULL,0);break;}CHECK(in->nodeid>=100&&in->nodeid<100+RACES);unsigned test=in->nodeid-100;CHECK(!strcmp(name,(test==1||test==3||test==6)?"system.posix_acl_default":"system.posix_acl_access"));unsigned number=queries[test]++;if(number<2){pending[test][number]=*in;event(number?'b':'a');}else acl_value(fd,in,2);break;}
  case FUSE_INTERRUPT:{CHECK((size_t)size>=sizeof(*in)+sizeof(struct fuse_interrupt_in));const struct fuse_interrupt_in *cancel=body;int found=0;for(unsigned test=0;test<RACES;test++)for(unsigned which=0;which<2;which++)if(pending[test][which].unique==cancel->unique){CHECK(((test==5||test==10)&&!which)||((test==6||test==11)&&which));reply(fd,in,0,NULL,0);reply(fd,&pending[test][which],EINTR,NULL,0);pending[test][which].unique=0;event('i');found=1;}CHECK(found);break;}
  case FUSE_OPEN:{struct fuse_open_out out={.fh=in->nodeid};reply(fd,in,0,&out,sizeof(out));break;}
  case FUSE_RELEASE:reply(fd,in,0,NULL,0);if(++race_releases==RACES)event('r');break;
  case FUSE_FLUSH:reply(fd,in,0,NULL,0);break;
  case FUSE_FORGET:case FUSE_BATCH_FORGET:break;
  case FUSE_ACCESS:CHECK(0);break;
  default:reply(fd,in,ENOSYS,NULL,0);break;
  }
 }
}
static void handler(int signal) { (void)signal; }
static const char *acl_name(unsigned test) { return(test==1||test==3||test==6)?"system.posix_acl_default":"system.posix_acl_access"; }
static unsigned perm_of(const unsigned char *bytes) { struct acl_entry user;memcpy(&user,bytes+12,sizeof(user));CHECK(user.tag==2&&user.id==1000);return user.perm; }
static pid_t start_reader(unsigned test,unsigned who,int fd) {
 pid_t child=fork();CHECK(child>=0);if(child)return child;
 struct sigaction action={.sa_handler=handler};CHECK(sigemptyset(&action.sa_mask)==0&&sigaction(SIGUSR1,&action,NULL)==0);
 CHECK(setgroups(0,NULL)==0&&setgid(1000)==0&&setuid(1000)==0);
 unsigned char bytes[128];errno=0;int result,permission=((test==8||test==10)&&!who)||((test==9||test==11)&&who==1);
 if(permission){char path[100];snprintf(path,sizeof(path),BASE "/%u",test);result=access(path,R_OK);}else result=fgetxattr(fd,acl_name(test),bytes,sizeof(bytes));
 int error=errno;unsigned perm=result==44?perm_of(bytes):0;
 fprintf(stderr,"acl-race-client case=%u who=%u result=%d errno=%d perm=%u\n",test,who,result,error,perm);
 int want=(test==3||test==7)&&!who?EIO:test==4&&!who?ENODATA:((test==5||test==10)&&!who)||((test==6||test==11)&&who==1)?EINTR:0;
 CHECK(want?result==-1&&error==want:permission?result==0:result==44&&perm==(who==2?2:who?6:4));_exit(0);
}
static void await_event(int fd,char expected) { char value;CHECK(read(fd,&value,1)==1&&value==expected); }
static void send_reply(int fd,unsigned test,unsigned which) { unsigned char command[2]={test,which};CHECK(write(fd,command,sizeof(command))==sizeof(command)); }
static int race_fixture(void) {
 CHECK(mkdir(BASE,0755)==0);int fd=open("/dev/fuse",O_RDWR);CHECK(fd>=0);char opts[128];snprintf(opts,sizeof(opts),"fd=%d,rootmode=40755,user_id=0,group_id=0,allow_other",fd);CHECK(mount("acl-race",BASE,"fuse",0,opts)==0);
 int commands[2],events[2];CHECK(pipe(commands)==0&&pipe(events)==0);pid_t daemon=fork();CHECK(daemon>=0);
 if(!daemon){CHECK(close(commands[1])==0&&close(events[0])==0);notify_fd=events[1];serve_race(fd,commands[0]);_exit(1);}CHECK(close(commands[0])==0&&close(events[1])==0);
 struct stat st;CHECK(stat(BASE,&st)==0);int pinned[RACES];for(unsigned i=0;i<RACES;i++){char path[100];snprintf(path,sizeof(path),BASE "/%u",i);pinned[i]=open(path,O_RDONLY);CHECK(pinned[i]>=0);}
 for(unsigned i=0;i<RACES;i++){
  pid_t first=start_reader(i,0,pinned[i]);await_event(events[0],'a');pid_t second=start_reader(i,1,pinned[i]);await_event(events[0],'b');
  if(i==2){send_reply(commands[1],i,1);wait_client(second);send_reply(commands[1],i,0);wait_client(first);}
  else if(i==5||i==6||i==10||i==11){int owner=i==5||i==10;CHECK(kill(owner?first:second,SIGUSR1)==0);await_event(events[0],'i');wait_client(owner?first:second);send_reply(commands[1],i,owner?1:0);wait_client(owner?second:first);}
  else{send_reply(commands[1],i,0);wait_client(first);if(i==7){pid_t third=start_reader(i,2,pinned[i]);wait_client(third);}send_reply(commands[1],i,1);wait_client(second);}
  unsigned char bytes[128];errno=0;int result=fgetxattr(pinned[i],acl_name(i),bytes,sizeof(bytes));int error=errno;unsigned perm=result==44?perm_of(bytes):0;
  fprintf(stderr,"acl-race-final case=%u result=%d errno=%d perm=%u\n",i,result,error,perm);CHECK(i==4?result==-1&&error==ENODATA:result==44&&perm==((i==3||i==5||i==7||i==10)?2:4));
 }
 for(unsigned i=0;i<RACES;i++){CHECK(close(pinned[i])==0);}
 await_event(events[0],'r');CHECK(umount(BASE)==0);wait_client(daemon);CHECK(close(commands[1])==0&&close(events[0])==0&&close(fd)==0&&rmdir(BASE)==0);puts("FUSE concurrent ACL fill assertions passed");return 0;
}
int main(int argc,char **argv) {
 (void)argv;if(argc==1){return race_fixture();}
 int ready[2],go[2];CHECK(pipe(ready)==0&&pipe(go)==0);pid_t child=fork();CHECK(child>=0);
 if(!child){CHECK(close(ready[0])==0&&close(go[1])==0);CHECK(unshare(CLONE_NEWUSER|CLONE_NEWNS)==0);CHECK(write(ready[1],"r",1)==1);char ack;CHECK(read(go[0],&ack,1)==1);CHECK(close(ready[1])==0&&close(go[0])==0);_exit(race_fixture());}
 CHECK(close(ready[1])==0&&close(go[0])==0);char ack;CHECK(read(ready[0],&ack,1)==1);
 for(int group=0;group<2;group++){char path[80];snprintf(path,sizeof(path),"/proc/%d/%s_map",child,group?"gid":"uid");int mapfd=open(path,O_WRONLY);CHECK(mapfd>=0);const char map[]="0 0 1\n1000 101000 1001\n";CHECK(write(mapfd,map,sizeof(map)-1)==sizeof(map)-1&&close(mapfd)==0);}
 CHECK(write(go[1],"g",1)==1&&close(go[1])==0&&close(ready[0])==0);wait_client(child);puts("FUSE mapped concurrent ACL assertions passed");return 0;
}
