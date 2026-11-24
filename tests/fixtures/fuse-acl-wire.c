// SPDX-License-Identifier: GPL-3.0-or-later
// Backing-store decoding, public ACL caching and setter error ordering.
#define main permissions_fixture_main
#include "fuse-posix-acl.c"
#undef main
#define CASES 21
static unsigned reads[CASES][2], wire_releases;
static int mapped, reader_mode;
static size_t value_for(unsigned test, unsigned char *data) {
 struct {uint32_t version;struct acl_entry e[5];} a={2,{{1,0,17},{2,4,1000},{4,0,18},{16,4,19},{32,4,20}}};
 size_t size=sizeof(a);
 switch(test){
 case 1:a.version=1;break;
 case 2:size=3;break;
 case 3:size=5;break;
 case 4:a.e[1].tag=64;break;
 case 5:a.e[1].id=UINT32_MAX;break;
 case 6:a.e[1].perm=12;break;
 case 7:a.e[0]=(struct acl_entry){32,4,1};a.e[1]=(struct acl_entry){1,0,2};a.e[2]=(struct acl_entry){4,0,3};a.e[3]=(struct acl_entry){16,0,4};size=36;break;
 case 8:a.e[0]=(struct acl_entry){2,4,1000};size=12;break;
 case 9:a.e[0]=(struct acl_entry){16,7,1};size=12;break;
 case 10:size=4;break;
 case 11:size=0;break;
 case 16:a.e[1].id=99999;break;
 case 20:a.version=1;size=5;break;
 default:break;
 }
 memcpy(data,&a,size);return size;
}
static struct fuse_attr wire_attr(uint64_t node) {
 return node==1?attr(1):(struct fuse_attr){.ino=node,.mode=S_IFREG|0044,.nlink=1,.blksize=4096};
}
static void serve_wire(int fd,int done) {
 for(;;){
  ssize_t size=read(fd,input,sizeof(input));
  if(size<0&&errno==ENODEV){for(unsigned i=0;i<CASES;i++)fprintf(stderr,"wire-reads case=%u access=%u default=%u\n",i,reads[i][0],reads[i][1]);_exit(0);}
  CHECK(size>=(ssize_t)sizeof(struct fuse_in_header));const struct fuse_in_header *in=(void*)input;const void *body=input+sizeof(*in);CHECK(in->len==size);
  switch(in->opcode){
  case FUSE_INIT:{struct fuse_init_out out={.major=7,.minor=31,.flags=FUSE_BIG_WRITES|FUSE_POSIX_ACL|FUSE_DONT_MASK|FUSE_SETXATTR_EXT,.max_write=16384,.time_gran=1};reply(fd,in,0,&out,sizeof(out));break;}
  case FUSE_LOOKUP:{CHECK(in->nodeid==1);char *end;unsigned long i=strtoul(body,&end,10);CHECK(!*end&&i<CASES);struct fuse_entry_out out={.nodeid=100+i,.generation=1,.entry_valid=3600,.attr_valid=3600,.attr=wire_attr(100+i)};reply(fd,in,0,&out,sizeof(out));break;}
  case FUSE_GETATTR:{struct fuse_attr_out out={.attr_valid=3600,.attr=wire_attr(in->nodeid)};reply(fd,in,0,&out,sizeof(out));break;}
  case FUSE_GETXATTR:{const struct fuse_getxattr_in *get=body;const char *name=(const char*)body+sizeof(*get);CHECK(get->size==4096);if(in->nodeid==1){reply(fd,in,ENODATA,NULL,0);break;}CHECK(in->nodeid>=100&&in->nodeid<100+CASES);unsigned i=in->nodeid-100,def=!strcmp(name,"system.posix_acl_default");CHECK(def||!strcmp(name,"system.posix_acl_access"));unsigned count=++reads[i][def];int error=i==12?ERANGE:i==13?EOPNOTSUPP:i==14?EIO:i==15?ENODATA:i==17?ENOSYS:0;if(error){reply(fd,in,error,NULL,0);break;}unsigned char value[64];size_t length=value_for(i,value);if((i==18||i==19)&&count>1){uint16_t denied=0;memcpy(value+14,&denied,sizeof(denied));}reply(fd,in,0,value,length);break;}
  case FUSE_OPEN:{struct fuse_open_out out={.fh=in->nodeid};reply(fd,in,0,&out,sizeof(out));break;}
  case FUSE_RELEASE:reply(fd,in,0,NULL,0);if(++wire_releases==CASES)CHECK(write(done,"r",1)==1);break;
  case FUSE_FLUSH:reply(fd,in,0,NULL,0);break;
  case FUSE_FORGET:case FUSE_BATCH_FORGET:break;
  case FUSE_ACCESS:case FUSE_SETXATTR:case FUSE_REMOVEXATTR:CHECK(0);break;
  default:reply(fd,in,ENOSYS,NULL,0);break;
  }
 }
}
static void wire_client(void) {
 CHECK(setgroups(0,NULL)==0&&setgid(1000)==0&&setuid(1000)==0);
 // Conversion errors precede ownership; semantic validation follows it.
 for(unsigned i=0;i<10;i++){
  unsigned char value[64];size_t size=value_for(i,value);errno=0;int result=setxattr(BASE "/0","system.posix_acl_access",value,size,0);int error=errno;
  int want=i==1?EOPNOTSUPP:i>=2&&i<=5?EINVAL:EPERM;
  fprintf(stderr,"wire-set case=%u result=%d errno=%d\n",i,result,error);CHECK(result==-1&&error==want);
 }
 for(unsigned round=0;round<CASES;round++){
  unsigned i=round==17?18:round==18?19:round==19?20:round==20?17:round;
  char path[100];snprintf(path,sizeof(path),BASE "/%u",i);unsigned char bytes[128];errno=0;
  ssize_t size=getxattr(path,i==19?"system.posix_acl_default":"system.posix_acl_access",bytes,sizeof(bytes));int error=errno;
  int want=i==1||i==20?EOPNOTSUPP:i>=2&&i<=5?EINVAL:i==10||i==11||i==15||i==17?ENODATA:i==12?E2BIG:i==13?EOPNOTSUPP:i==14?EIO:i==16&&mapped?EINVAL:0;
  fprintf(stderr,"wire-get case=%u result=%zd errno=%d\n",i,size,error);
  CHECK(want?size==-1&&error==want:size==(ssize_t)(i==7?36:i==8||i==9?12:44));
  if(size>0){uint32_t version;memcpy(&version,bytes,sizeof(version));CHECK(version==2);for(size_t e=4;e<(size_t)size;e+=8){struct acl_entry entry;memcpy(&entry,bytes+e,sizeof(entry));CHECK(entry.id==((entry.tag==2||entry.tag==8)?(i==16?99999:1000):UINT32_MAX));}}
  errno=0;int result;
  if(i==19){result=getxattr(path,"system.posix_acl_default",bytes,sizeof(bytes));uint16_t perm;memcpy(&perm,bytes+14,sizeof(perm));CHECK(result==44&&perm==4);continue;}
  result=access(path,R_OK);error=errno;
  if(want==ENODATA)want=0;
  if(i==9)want=EIO;
  fprintf(stderr,"wire-access case=%u result=%d errno=%d\n",i,result,error);CHECK(want?result==-1&&error==want:result==0);
  if(i==18){CHECK(getxattr(path,"system.posix_acl_access",bytes,sizeof(bytes))==44);uint16_t perm;memcpy(&perm,bytes+14,sizeof(perm));CHECK(perm==4);}
 }
}
static void reader_client(void) {
 CHECK(setgroups(0,NULL)==0&&setgid(0)==0&&setuid(0)==0);
 // The filesystem is in the ancestor namespace; its cached ACL stays global.
 const unsigned cases[]={0,6,16,18,19};
 for(unsigned round=0;round<sizeof(cases)/sizeof(cases[0]);round++){
  unsigned i=cases[round];char path[100];snprintf(path,sizeof(path),BASE "/%u",i);
  for(unsigned repeat=0;repeat<2;repeat++){
   unsigned char bytes[128];CHECK(getxattr(path,i==19?"system.posix_acl_default":"system.posix_acl_access",bytes,sizeof(bytes))==44);
   struct acl_entry user;memcpy(&user,bytes+12,sizeof(user));CHECK(user.id==(i==16?UINT32_MAX:0));
   CHECK(user.perm==(i==6?12:4));
   if(i!=19)CHECK(access(path,R_OK)==0);
   fprintf(stderr,"wire-reader case=%u repeat=%u id=%u perm=%u\n",i,repeat,user.id,user.perm);
  }
 }
 unsigned char value[64];size_t size=value_for(6,value);uint32_t uid=0;memcpy(value+16,&uid,sizeof(uid));
 errno=0;CHECK(setxattr(BASE "/0","system.posix_acl_access",value,size,0)==-1&&errno==EPERM);
}
static int wire_fixture(void) {
 CHECK(mkdir(BASE,0755)==0);int fd=open("/dev/fuse",O_RDWR);CHECK(fd>=0);char opts[128];snprintf(opts,sizeof(opts),"fd=%d,rootmode=40755,user_id=0,group_id=0,allow_other",fd);CHECK(mount("acl-wire",BASE,"fuse",0,opts)==0);
 int done[2];CHECK(pipe(done)==0);pid_t daemon=fork();CHECK(daemon>=0);if(!daemon){CHECK(close(done[0])==0);serve_wire(fd,done[1]);_exit(1);}CHECK(close(done[1])==0);
 struct stat st;CHECK(stat(BASE,&st)==0);int pinned[CASES];for(unsigned i=0;i<CASES;i++){char path[100];snprintf(path,sizeof(path),BASE "/%u",i);pinned[i]=open(path,O_RDONLY);CHECK(pinned[i]>=0);}
 for(unsigned i=6;i<=9;i++){unsigned char value[64];size_t size=value_for(i,value);errno=0;int result=setxattr(BASE "/0","system.posix_acl_access",value,size,0);int error=errno;fprintf(stderr,"wire-owner-set case=%u result=%d errno=%d\n",i,result,error);CHECK(result==-1&&error==EINVAL);}
 int ready[2],go[2];CHECK(pipe(ready)==0&&pipe(go)==0);pid_t child=fork();CHECK(child>=0);
 if(!child){CHECK(close(ready[0])==0&&close(go[1])==0);if(reader_mode){CHECK(unshare(CLONE_NEWUSER)==0);CHECK(write(ready[1],"r",1)==1);char ack;CHECK(read(go[0],&ack,1)==1);}CHECK(close(ready[1])==0&&close(go[0])==0);if(reader_mode)reader_client();else wire_client();_exit(0);}
 CHECK(close(ready[1])==0&&close(go[0])==0);
 if(reader_mode){char ack;CHECK(read(ready[0],&ack,1)==1);for(int group=0;group<2;group++){char path[80];snprintf(path,sizeof(path),"/proc/%d/%s_map",child,group?"gid":"uid");int mapfd=open(path,O_WRONLY);CHECK(mapfd>=0);const char map[]="0 1000 1\n";CHECK(write(mapfd,map,sizeof(map)-1)==sizeof(map)-1&&close(mapfd)==0);}CHECK(write(go[1],"g",1)==1);}
 CHECK(close(ready[0])==0&&close(go[1])==0);wait_client(child);
 for(unsigned i=0;i<CASES;i++)CHECK(close(pinned[i])==0);
 char ack;CHECK(read(done[0],&ack,1)==1&&close(done[0])==0);CHECK(umount(BASE)==0);wait_client(daemon);CHECK(close(fd)==0&&rmdir(BASE)==0);puts("FUSE ACL wire/cache assertions passed");return 0;
}
int main(int argc,char **argv) {
 if(argc==1){return wire_fixture();}
 if(!strcmp(argv[1],"reader")){reader_mode=1;return wire_fixture();}
 mapped=1;
 int ready[2],go[2];CHECK(pipe(ready)==0&&pipe(go)==0);pid_t child=fork();CHECK(child>=0);
 if(!child){CHECK(close(ready[0])==0&&close(go[1])==0);CHECK(unshare(CLONE_NEWUSER|CLONE_NEWNS)==0);CHECK(write(ready[1],"r",1)==1);char ack;CHECK(read(go[0],&ack,1)==1);CHECK(close(ready[1])==0&&close(go[0])==0);_exit(wire_fixture());}
 CHECK(close(ready[1])==0&&close(go[0])==0);char ack;CHECK(read(ready[0],&ack,1)==1);
 for(int group=0;group<2;group++){char path[80];snprintf(path,sizeof(path),"/proc/%d/%s_map",child,group?"gid":"uid");int mapfd=open(path,O_WRONLY);CHECK(mapfd>=0);const char map[]="0 0 1\n1000 101000 1001\n";CHECK(write(mapfd,map,sizeof(map)-1)==sizeof(map)-1&&close(mapfd)==0);}
 CHECK(write(go[1],"g",1)==1&&close(go[1])==0&&close(ready[0])==0);wait_client(child);puts("FUSE mapped ACL wire assertions passed");return 0;
}
