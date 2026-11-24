// SPDX-License-Identifier: GPL-3.0-or-later
// Metadata request versions, retained inode state and invalid-attribute replies.
#define main permissions_fixture_main
#include "fuse-posix-acl.c"
#undef main
#include <linux/stat.h>
#include <poll.h>
#include <sys/syscall.h>
#define META_CASES 13
static struct fuse_in_header delayed[META_CASES][2];
static unsigned gets[META_CASES], metadata_releases;
static int metadata_events;
static struct fuse_attr metadata_attr(unsigned test,unsigned mode) {
 return(struct fuse_attr){.ino=100+test,.size=8,.mode=mode,.nlink=1,.blksize=4096,.atime=1,.mtime=2,.ctime=3,.atimensec=4,.mtimensec=5,.ctimensec=6};
}
static void metadata_reply(int fd,const struct fuse_in_header *in,struct fuse_attr attr) {
 struct fuse_attr_out out={.attr_valid=3600,.attr=attr};reply(fd,in,0,&out,sizeof(out));
}
static void metadata_event(char value) { CHECK(write(metadata_events,&value,1)==1); }
static void metadata_serve(int fd,int controls) {
 for(;;){
  struct pollfd watched[2]={{.fd=fd,.events=POLLIN},{.fd=controls,.events=POLLIN}};CHECK(poll(watched,2,-1)>0);
  if(watched[1].revents&POLLIN){unsigned char command[2];CHECK(read(controls,command,2)==2);unsigned test=command[0],which=command[1];CHECK(test<META_CASES&&which<2&&delayed[test][which].unique);struct fuse_attr a=metadata_attr(test,S_IFREG|(test==3?0604:which?0640:0666));if(test==10){a.atimensec=a.mtimensec=a.ctimensec=1000000123;}metadata_reply(fd,&delayed[test][which],a);delayed[test][which].unique=0;}
  if(!(watched[0].revents&(POLLIN|POLLERR|POLLHUP)))continue;
  ssize_t size=read(fd,input,sizeof(input));
  if(size<0&&errno==ENODEV){for(unsigned i=0;i<META_CASES;i++)fprintf(stderr,"metadata-gets case=%u count=%u\n",i,gets[i]);_exit(0);}
  CHECK(size>=(ssize_t)sizeof(struct fuse_in_header));const struct fuse_in_header *in=(void*)input;const void *body=input+sizeof(*in);CHECK(in->len==size);
  switch(in->opcode){
  case FUSE_INIT:{struct fuse_init_out out={.major=7,.minor=31,.flags=FUSE_BIG_WRITES,.max_write=16384,.time_gran=1};reply(fd,in,0,&out,sizeof(out));break;}
  case FUSE_LOOKUP:{CHECK(in->nodeid==1);const char *name=body;int alias=!strncmp(name,"alias",5);char *end;unsigned long test=strtoul(name+(alias?5:0),&end,10);CHECK(!*end&&test<META_CASES);struct fuse_entry_out out={.nodeid=100+test,.generation=alias&&test==11?2:1,.entry_valid=3600,.attr_valid=3600,.attr=metadata_attr(test,alias?(test==12?S_IFDIR|0755:S_IFREG|0640):S_IFREG|0666)};reply(fd,in,0,&out,sizeof(out));break;}
  case FUSE_GETATTR:{if(in->nodeid==1){metadata_reply(fd,in,attr(1));break;}CHECK(in->nodeid>=100&&in->nodeid<100+META_CASES);unsigned test=in->nodeid-100,number=gets[test]++;if((!number&&(test<=2||test==10))||(test==1&&number==1)){delayed[test][number]=*in;metadata_event(number?'b':'a');break;}struct fuse_attr a=metadata_attr(test,S_IFREG|(test==3&&!number?0640:0600));if(!number){if(test==4)a.mode=S_IFDIR|0755;else if(test==5)a.size=UINT64_MAX;else if(test==7)a.atimensec=a.mtimensec=a.ctimensec=1000000123;else if(test==9)a.uid=a.gid=UINT32_MAX;}metadata_reply(fd,in,a);break;}
  case FUSE_SETATTR:{CHECK(in->nodeid>=100&&in->nodeid<100+META_CASES);unsigned test=in->nodeid-100;const struct fuse_setattr_in *set=body;CHECK(set->valid&FATTR_MODE);if(test==3){CHECK((set->mode&0777)==0604);delayed[test][0]=*in;metadata_event('s');break;}struct fuse_attr a=metadata_attr(test,S_IFREG|0600);if(test==6)a.mode=S_IFDIR|0755;if(test==8){a.mode=S_IFREG|0604;a.atimensec=a.mtimensec=a.ctimensec=1000000123;}metadata_reply(fd,in,a);break;}
  case FUSE_OPEN:{struct fuse_open_out out={.fh=in->nodeid};reply(fd,in,0,&out,sizeof(out));break;}
  case FUSE_RELEASE:reply(fd,in,0,NULL,0);if(++metadata_releases==META_CASES)metadata_event('r');break;
  case FUSE_FLUSH:reply(fd,in,0,NULL,0);break;
  case FUSE_GETXATTR:reply(fd,in,ENODATA,NULL,0);break;
  case FUSE_READ:reply(fd,in,0,"x",1);break;
  case FUSE_FORGET:case FUSE_BATCH_FORGET:break;
  case FUSE_ACCESS:CHECK(0);break;
  default:reply(fd,in,ENOSYS,NULL,0);break;
  }
 }
}
static int metadata_stat(int fd,unsigned flags,struct statx *st) { return syscall(SYS_statx,fd,"",AT_EMPTY_PATH|flags,STATX_BASIC_STATS,st); }
static void metadata_wait(int fd,char wanted) { char value;CHECK(read(fd,&value,1)==1&&value==wanted); }
static void metadata_send(int fd,unsigned test,unsigned which) { unsigned char command[2]={test,which};CHECK(write(fd,command,2)==2); }
static pid_t metadata_reader(int fd,unsigned test,unsigned expected,unsigned nano) {
 pid_t child=fork();CHECK(child>=0);if(child)return child;struct statx st;errno=0;int result=metadata_stat(fd,AT_STATX_FORCE_SYNC,&st);int error=errno;
 fprintf(stderr,"metadata-reader case=%u result=%d errno=%d mode=%o nano=%u\n",test,result,error,result?0:st.stx_mode&0777,result?0:st.stx_mtime.tv_nsec);CHECK(result==0&&(st.stx_mode&0777)==expected&&st.stx_mtime.tv_nsec==nano);_exit(0);
}
static void metadata_cached(int fd,unsigned test,unsigned mode,unsigned nano) {
 struct statx st;errno=0;int result=metadata_stat(fd,AT_STATX_DONT_SYNC,&st);int error=errno;fprintf(stderr,"metadata-cache case=%u result=%d errno=%d mode=%o nano=%u\n",test,result,error,result?0:st.stx_mode&0777,result?0:st.stx_mtime.tv_nsec);CHECK(result==0&&(st.stx_mode&0777)==mode&&st.stx_mtime.tv_nsec==nano);
}
static void metadata_denied(int fd,unsigned test) {
 pid_t child=fork();CHECK(child>=0);if(child){wait_client(child);return;}CHECK(setgroups(0,NULL)==0&&setgid(1000)==0&&setuid(1000)==0);errno=0;int result=syscall(SYS_faccessat2,fd,"",R_OK,AT_EMPTY_PATH),error=errno;fprintf(stderr,"metadata-access case=%u result=%d errno=%d\n",test,result,error);CHECK(result==-1&&error==EACCES);_exit(0);
}
static void metadata_bad(int fd,unsigned test) {
 struct statx st;char value;errno=0;int result=metadata_stat(fd,AT_STATX_DONT_SYNC,&st),error=errno;fprintf(stderr,"metadata-bad case=%u stat=%d errno=%d\n",test,result,error);CHECK(result==-1&&error==EIO);
 errno=0;CHECK(metadata_stat(fd,AT_STATX_FORCE_SYNC,&st)==-1&&errno==EIO);errno=0;CHECK(read(fd,&value,1)==-1&&errno==EIO);errno=0;CHECK(fgetxattr(fd,"user.test",&value,1)==-1&&errno==EIO);errno=0;CHECK(fchmod(fd,0644)==-1&&errno==EIO);
}
static int metadata_fixture(void) {
 CHECK(mkdir(BASE,0755)==0);int fd=open("/dev/fuse",O_RDWR);CHECK(fd>=0);char opts[160];snprintf(opts,sizeof(opts),"fd=%d,rootmode=40755,user_id=0,group_id=0,allow_other,default_permissions",fd);CHECK(mount("metadata",BASE,"fuse",0,opts)==0);
 int commands[2],events[2];CHECK(pipe(commands)==0&&pipe(events)==0);pid_t daemon=fork();CHECK(daemon>=0);if(!daemon){CHECK(close(commands[1])==0&&close(events[0])==0);metadata_events=events[1];metadata_serve(fd,commands[0]);_exit(1);}CHECK(close(commands[0])==0&&close(events[1])==0);
 struct stat root;CHECK(stat(BASE,&root)==0);int pinned[META_CASES];for(unsigned i=0;i<META_CASES;i++){char path[100];snprintf(path,sizeof(path),BASE "/%u",i);pinned[i]=open(path,O_RDONLY);CHECK(pinned[i]>=0);}
 for(unsigned test=0;test<META_CASES;test++){
  int file=pinned[test];
  if(test<=2||test==10){pid_t first=metadata_reader(file,test,0666,test==10?1000000123:5);metadata_wait(events[0],'a');if(test==1){pid_t second=metadata_reader(file,test,0640,5);metadata_wait(events[0],'b');metadata_send(commands[1],test,1);wait_client(second);}else if(test==2){struct stat st;CHECK(stat(BASE "/alias2",&st)==0&&(st.st_mode&0777)==0640);}else CHECK(fchmod(file,0600)==0);metadata_send(commands[1],test,0);wait_client(first);metadata_cached(file,test,test==1||test==2?0640:0600,5);if(test==0)metadata_denied(file,test);}
  else if(test==3){pid_t setter=fork();CHECK(setter>=0);if(!setter){CHECK(fchmod(file,0604)==0);_exit(0);}metadata_wait(events[0],'s');struct statx st;CHECK(metadata_stat(file,AT_STATX_FORCE_SYNC,&st)==0&&(st.stx_mode&0777)==0640);metadata_send(commands[1],test,0);wait_client(setter);metadata_cached(file,test,0604,5);metadata_denied(file,test);metadata_cached(file,test,0600,5);}
  else if(test==4||test==5||test==6){struct statx st;errno=0;int result=test==6?fchmod(file,0600):metadata_stat(file,AT_STATX_FORCE_SYNC,&st),error=errno;fprintf(stderr,"metadata-invalid case=%u result=%d errno=%d\n",test,result,error);CHECK(result==-1&&error==EIO);metadata_bad(file,test);}
  else if(test==7||test==8){if(test==7){struct statx st;CHECK(metadata_stat(file,AT_STATX_FORCE_SYNC,&st)==0&&st.stx_mtime.tv_nsec==999999999);}else CHECK(fchmod(file,0604)==0);metadata_cached(file,test,test==8?0604:0600,999999999);}
  else if(test==9){struct statx st;CHECK(metadata_stat(file,AT_STATX_FORCE_SYNC,&st)==0);fprintf(stderr,"metadata-unmapped uid=%u gid=%u\n",st.stx_uid,st.stx_gid);CHECK(st.stx_uid==65534&&st.stx_gid==65534);}
  else{char path[100];snprintf(path,sizeof(path),BASE "/alias%u",test);int alias=open(path,O_PATH);CHECK(alias>=0);struct statx st;CHECK(metadata_stat(alias,AT_STATX_DONT_SYNC,&st)==0&&(st.stx_mode&S_IFMT)==(test==12?S_IFDIR:S_IFREG));metadata_bad(file,test);CHECK(close(alias)==0);}
 }
 for(unsigned test=0;test<META_CASES;test++){errno=0;int result=close(pinned[test]),error=errno;int bad=test==4||test==5||test==6||test==11||test==12;CHECK(bad?result==-1&&error==EIO:result==0);}
 metadata_wait(events[0],'r');CHECK(umount(BASE)==0);wait_client(daemon);CHECK(close(commands[1])==0&&close(events[0])==0&&close(fd)==0&&rmdir(BASE)==0);puts("FUSE metadata version and bad-inode assertions passed");return 0;
}
int main(int argc,char **argv) {
 (void)argv;if(argc==1){return metadata_fixture();}
 int ready[2],go[2];CHECK(pipe(ready)==0&&pipe(go)==0);pid_t child=fork();CHECK(child>=0);
 if(!child){CHECK(close(ready[0])==0&&close(go[1])==0);CHECK(unshare(CLONE_NEWUSER|CLONE_NEWNS)==0);CHECK(write(ready[1],"r",1)==1);char ack;CHECK(read(go[0],&ack,1)==1);CHECK(close(ready[1])==0&&close(go[0])==0);_exit(metadata_fixture());}
 CHECK(close(ready[1])==0&&close(go[0])==0);char ack;CHECK(read(ready[0],&ack,1)==1);
 for(int group=0;group<2;group++){char path[80];snprintf(path,sizeof(path),"/proc/%d/%s_map",child,group?"gid":"uid");int mapfd=open(path,O_WRONLY);CHECK(mapfd>=0);const char map[]="0 0 1\n1000 101000 1001\n";CHECK(write(mapfd,map,sizeof(map)-1)==sizeof(map)-1&&close(mapfd)==0);}
 CHECK(write(go[1],"g",1)==1&&close(go[1])==0&&close(ready[0])==0);wait_client(child);puts("FUSE mapped metadata assertions passed");return 0;
}
