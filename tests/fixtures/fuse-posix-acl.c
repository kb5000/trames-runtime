// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/fuse.h>
#include <stdint.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"pid=%d line=%d %s errno=%d\n",getpid(),__LINE__,#x,errno);_exit(1);}}while(0)
#define BASE "/fuse-posix-acl-test"
static unsigned char input[65536],output[65536];
static unsigned grant_mode=0040,sgid_mode=02640,created_file,created_dir,released,root_case,root_acl_reads,root_after_set,root_after_reads,hard_linked,release_target=5;
static char user_echo='x';
static void reply(int fd,const struct fuse_in_header *in,int error,const void *data,size_t size){struct fuse_out_header h={.len=sizeof(h)+size,.error=-error,.unique=in->unique};memcpy(output,&h,sizeof(h));if(size)memcpy(output+sizeof(h),data,size);CHECK(write(fd,output,h.len)==h.len);}
static struct fuse_attr attr(uint64_t id){return(struct fuse_attr){.ino=id,.mode=(id==1?S_IFDIR|0755:id==4||id==8?S_IFDIR|0070:id==6?S_IFDIR|0770:S_IFREG|(id==2?grant_mode:id==5?0660:id==7?sgid_mode:0044)),.uid=id>=5?1000:0,.gid=id==7?2000:id>=5?1000:0,.nlink=1,.blksize=4096};}
struct acl_entry {uint16_t tag,perm;uint32_t id;};
static void acl_reply(int fd,const struct fuse_in_header *in){
 struct {uint32_t version;struct acl_entry e[6];} a={.version=2};unsigned n=0;uint64_t id=in->nodeid;
 a.e[n++]=(struct acl_entry){1,id>=5?6:0,UINT32_MAX};
 a.e[n++]=(struct acl_entry){2,id==3?0:id==4?7:id==6?5:id==8?7:id==2?6:4,id>=5?1001:1000};
 if(id==4)a.e[n++]=(struct acl_entry){2,7,1001};
 a.e[n++]=(struct acl_entry){4,0,UINT32_MAX};
 a.e[n++]=(struct acl_entry){16,id==4||id==6||id==8?7:id==2?(grant_mode>>3)&7:id==5?6:4,UINT32_MAX};
 a.e[n++]=(struct acl_entry){32,id==3?4:0,UINT32_MAX};
 reply(fd,in,0,&a,4+n*sizeof(a.e[0]));
}
static void entry_reply(int fd,const struct fuse_in_header *in,uint64_t id,int opened){struct {struct fuse_entry_out e;struct fuse_open_out o;} out={.e={.nodeid=id,.generation=1,.entry_valid=3600,.attr_valid=3600,.attr=attr(id)},.o={.fh=id}};reply(fd,in,0,&out,sizeof(out.e)+(opened?sizeof(out.o):0));}
static void serve(int fd,int done){for(;;){ssize_t size=read(fd,input,sizeof(input));if(size<0&&errno==ENODEV){if(root_case)fprintf(stderr,"root-acl-reads=%u\n",root_acl_reads);_exit(0);}CHECK(size>=(ssize_t)sizeof(struct fuse_in_header));struct fuse_in_header *in=(void*)input;void *body=input+sizeof(*in);CHECK(in->len==size);fprintf(stderr,"acl-wire opcode=%u node=%llu uid=%u\n",in->opcode,(unsigned long long)in->nodeid,in->uid);
 switch(in->opcode){
 case FUSE_INIT:{const struct fuse_init_in *init=body;fprintf(stderr,"acl-init offered=%x\n",init->flags);struct fuse_init_out out={.major=7,.minor=31,.flags=FUSE_BIG_WRITES|FUSE_POSIX_ACL|FUSE_DONT_MASK|FUSE_SETXATTR_EXT,.max_write=16384,.time_gran=1};reply(fd,in,0,&out,sizeof(out));break;}
 case FUSE_LOOKUP:{uint64_t id=0;if(in->nodeid==1)id=!strcmp(body,"grant")?2:!strcmp(body,"deny")?3:!strcmp(body,"directory")?4:!strcmp(body,"sgid")?7:!strcmp(body,"other")?8:0;else if(in->nodeid==4)id=hard_linked&&!strcmp(body,"hard")?2:created_file&&!strcmp(body,"new")?5:created_dir&&!strcmp(body,"newdir")?6:0;if(id)entry_reply(fd,in,id,0);else reply(fd,in,ENOENT,NULL,0);break;}
 case FUSE_CREATE:{const struct fuse_create_in *c=body;CHECK(in->nodeid==4&&!created_file&&(c->mode&0777)==0666&&c->umask==0077);created_file=1;entry_reply(fd,in,5,1);break;}
 case FUSE_MKDIR:{const struct fuse_mkdir_in *m=body;CHECK(in->nodeid==4&&!created_dir&&(m->mode&0777)==0777&&m->umask==0077);created_dir=1;entry_reply(fd,in,6,0);break;}
 case FUSE_LINK:{const struct fuse_link_in *l=body;CHECK(in->nodeid==4&&l->oldnodeid==2&&!hard_linked&&!strcmp((const char*)body+sizeof(*l),"hard"));hard_linked=1;entry_reply(fd,in,2,0);break;}
 case FUSE_UNLINK:CHECK(in->nodeid==4&&hard_linked&&!strcmp(body,"hard"));hard_linked=0;reply(fd,in,0,NULL,0);break;
 case FUSE_SETATTR:{const struct fuse_setattr_in *a=body;if(root_case&&in->nodeid==1){CHECK(a->valid&FATTR_MODE);root_after_set=1;root_after_reads=0;struct fuse_attr_out out={.attr_valid=3600,.attr=attr(1)};reply(fd,in,0,&out,sizeof(out));break;}CHECK(in->nodeid==2);if(a->valid&FATTR_MODE){grant_mode=a->mode&07777;}else{CHECK((a->valid&(FATTR_ATIME|FATTR_MTIME))==(FATTR_ATIME|FATTR_MTIME));}struct fuse_attr_out out={.attr_valid=3600,.attr=attr(2)};reply(fd,in,0,&out,sizeof(out));break;}
 case FUSE_SETXATTR:{const struct fuse_setxattr_in *set=body;if(in->nodeid==2){const char *name=(const char*)body+sizeof(*set);CHECK(!strcmp(name,"user.echo")&&set->flags==0&&set->setxattr_flags==0&&set->size==1);user_echo=name[strlen(name)+1];reply(fd,in,0,NULL,0);break;}CHECK(in->nodeid==7&&set->flags==0&&set->setxattr_flags==FUSE_SETXATTR_ACL_KILL_SGID);CHECK(!strcmp((const char*)body+sizeof(*set),"system.posix_acl_access"));sgid_mode&=~02000;reply(fd,in,0,NULL,0);break;}
 case FUSE_GETATTR:{struct fuse_attr_out out={.attr_valid=3600,.attr=attr(in->nodeid)};reply(fd,in,0,&out,sizeof(out));break;}
 case FUSE_GETXATTR:{const struct fuse_getxattr_in *get=body;const char *name=(const char*)body+sizeof(*get);if(!strcmp(name,"user.echo")){CHECK(in->nodeid==2&&get->size==1);reply(fd,in,0,&user_echo,1);break;}CHECK(get->size==4096);if(root_case&&in->nodeid==1&&!strcmp(name,"system.posix_acl_access")){root_acl_reads++;unsigned count=root_after_set?root_after_reads++:root_acl_reads-1;if(count==0)reply(fd,in,ENODATA,NULL,0);else acl_reply(fd,in);break;}if(in->nodeid==1||strcmp(name,"system.posix_acl_access"))reply(fd,in,ENODATA,NULL,0);else acl_reply(fd,in);break;}
 case FUSE_ACCESS:CHECK(0);break;
 case FUSE_OPEN:{struct fuse_open_out out={.fh=in->nodeid};reply(fd,in,0,&out,sizeof(out));break;}
 case FUSE_RELEASE:reply(fd,in,0,NULL,0);if(++released==release_target)CHECK(write(done,"r",1)==1);break;
 case FUSE_FLUSH:reply(fd,in,0,NULL,0);break;
 case FUSE_FORGET:case FUSE_BATCH_FORGET:break;
 case FUSE_DESTROY:reply(fd,in,0,NULL,0);_exit(0);
 default:reply(fd,in,ENOSYS,NULL,0);break;
 }
}}
static void client(void){CHECK(setgroups(0,NULL)==0&&setgid(1000)==0&&setuid(1000)==0);int fd=open(BASE "/grant",O_RDONLY);CHECK(fd>=0&&close(fd)==0);errno=0;CHECK(open(BASE "/grant",O_WRONLY)==-1&&errno==EACCES);CHECK(access(BASE "/grant",R_OK)==0);char echo;CHECK(getxattr(BASE "/grant","user.echo",&echo,1)==1&&echo=='x');errno=0;CHECK(setxattr(BASE "/grant","user.echo","y",1,0)==-1&&errno==EACCES);errno=0;CHECK(utimensat(AT_FDCWD,BASE "/grant",NULL,0)==-1&&errno==EACCES);errno=0;int linked=link(BASE "/grant",BASE "/directory/hard");int link_error=errno;fprintf(stderr,"acl-protected-link result=%d errno=%d\n",linked,link_error);CHECK(linked==-1&&link_error==EPERM);errno=0;CHECK(access(BASE "/grant",W_OK)==-1&&errno==EACCES);errno=0;CHECK(open(BASE "/deny",O_RDONLY)==-1&&errno==EACCES);CHECK(chdir(BASE "/directory")==0&&chdir("/")==0);umask(0077);fd=open(BASE "/directory/new",O_CREAT|O_EXCL|O_RDWR,0666);CHECK(fd>=0&&close(fd)==0);CHECK(mkdir(BASE "/directory/newdir",0777)==0);
 struct {uint32_t version;struct acl_entry e[5];} a={2,{{1,6,UINT32_MAX},{2,4,1001},{4,0,UINT32_MAX},{16,4,UINT32_MAX},{32,0,UINT32_MAX}}};
 CHECK(setxattr(BASE "/sgid","system.posix_acl_access",&a,sizeof(a),XATTR_CREATE)==0);struct stat st;CHECK(stat(BASE "/sgid",&st)==0&&(st.st_mode&02000)==0);
}
static void wait_client(pid_t child){int status;CHECK(child>=0&&waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);}
static int filesystem_fixture(void){CHECK(mkdir(BASE,0755)==0);int fd=open("/dev/fuse",O_RDWR);CHECK(fd>=0);char opts[128];snprintf(opts,sizeof(opts),"fd=%d,rootmode=40755,user_id=0,group_id=0,allow_other",fd);CHECK(mount("acl-fixture",BASE,"fuse",0,opts)==0);int done[2];CHECK(pipe(done)==0);pid_t daemon=fork();CHECK(daemon>=0);if(!daemon){CHECK(close(done[0])==0);serve(fd,done[1]);}CHECK(close(done[1])==0);
 int pinned=open(BASE "/grant",O_RDONLY);CHECK(pinned>=0);
 pid_t child=fork();CHECK(child>=0);if(!child){client();_exit(0);}wait_client(child);
 CHECK(chmod(BASE "/grant",0060)==0);
 child=fork();CHECK(child>=0);if(!child){CHECK(setgroups(0,NULL)==0&&setgid(1000)==0&&setuid(1000)==0);int data=open(BASE "/grant",O_WRONLY);CHECK(data>=0&&close(data)==0);CHECK(utimensat(AT_FDCWD,BASE "/grant",NULL,0)==0);CHECK(setxattr(BASE "/grant","user.echo","y",1,0)==0);char echo;CHECK(getxattr(BASE "/grant","user.echo",&echo,1)==1&&echo=='y');CHECK(link(BASE "/grant",BASE "/directory/hard")==0&&unlink(BASE "/directory/hard")==0);_exit(0);}wait_client(child);
 child=fork();CHECK(child>=0);if(!child){CHECK(setgroups(0,NULL)==0&&setgid(1001)==0&&setuid(1001)==0);int data=open(BASE "/directory/new",O_RDONLY);CHECK(data>=0&&close(data)==0);errno=0;CHECK(open(BASE "/directory/new",O_WRONLY)==-1&&errno==EACCES);CHECK(chdir(BASE "/directory/newdir")==0&&chdir("/")==0);errno=0;int moved=rename(BASE "/directory/newdir",BASE "/other/moved");int move_error=errno;fprintf(stderr,"acl-directory-move result=%d errno=%d\n",moved,move_error);CHECK(moved==-1&&move_error==EACCES);_exit(0);}wait_client(child);
 CHECK(close(pinned)==0);char ack;CHECK(read(done[0],&ack,1)==1&&ack=='r'&&close(done[0])==0);int status;CHECK(umount(BASE)==0&&waitpid(daemon,&status,0)==daemon&&WIFEXITED(status)&&WEXITSTATUS(status)==0);CHECK(close(fd)==0&&rmdir(BASE)==0);puts("FUSE negotiated ACL permissions and inheritance passed");return 0;}

static int root_cache_fixture(void){
 root_case=1;release_target=2;CHECK(mkdir(BASE,0755)==0);int fd=open("/dev/fuse",O_RDWR);CHECK(fd>=0);char opts[128];snprintf(opts,sizeof(opts),"fd=%d,rootmode=40755,user_id=0,group_id=0,allow_other",fd);CHECK(mount("root-acl-fixture",BASE,"fuse",0,opts)==0);int done[2];CHECK(pipe(done)==0);pid_t daemon=fork();CHECK(daemon>=0);if(!daemon){CHECK(close(done[0])==0);serve(fd,done[1]);}CHECK(close(done[1])==0);
 struct stat root_stat;CHECK(stat(BASE,&root_stat)==0);pid_t child=fork();CHECK(child>=0);if(!child){CHECK(setgroups(0,NULL)==0&&setgid(1000)==0&&setuid(1000)==0);int data=open(BASE "/grant",O_RDONLY);CHECK(data>=0&&close(data)==0);errno=0;data=open(BASE "/grant",O_RDONLY);int error=errno;fprintf(stderr,"root-acl-second-open result=%d errno=%d\n",data,error);CHECK(data==-1&&error==EACCES);_exit(0);}wait_client(child);
 CHECK(chmod(BASE,0755)==0);child=fork();CHECK(child>=0);if(!child){CHECK(setgroups(0,NULL)==0&&setgid(1000)==0&&setuid(1000)==0);int data=open(BASE "/grant",O_RDONLY);CHECK(data>=0&&close(data)==0);errno=0;data=open(BASE "/grant",O_RDONLY);int error=errno;fprintf(stderr,"root-acl-after-setattr result=%d errno=%d\n",data,error);CHECK(data==-1&&error==EACCES);_exit(0);}wait_client(child);
 char ack;CHECK(read(done[0],&ack,1)==1&&close(done[0])==0);int status;CHECK(umount(BASE)==0&&waitpid(daemon,&status,0)==daemon&&WIFEXITED(status)&&WEXITSTATUS(status)==0);CHECK(close(fd)==0&&rmdir(BASE)==0);puts("FUSE pre-init root ACL cache passed");return 0;
}
int main(int argc,char **argv){
 if(argc>1&&!strcmp(argv[1],"root-cache")){return root_cache_fixture();}
 if(argc==1){return filesystem_fixture();}
 int ready[2],go[2];CHECK(pipe(ready)==0&&pipe(go)==0);pid_t child=fork();CHECK(child>=0);
 if(!child){CHECK(close(ready[0])==0&&close(go[1])==0);CHECK(unshare(CLONE_NEWUSER|CLONE_NEWNS)==0);CHECK(write(ready[1],"r",1)==1);char ack;CHECK(read(go[0],&ack,1)==1);CHECK(close(ready[1])==0&&close(go[0])==0);_exit(filesystem_fixture());}
 CHECK(close(ready[1])==0&&close(go[0])==0);char ack;CHECK(read(ready[0],&ack,1)==1);
 for(int group=0;group<2;group++){char path[80];snprintf(path,sizeof(path),"/proc/%d/%s_map",child,group?"gid":"uid");int fd=open(path,O_WRONLY);CHECK(fd>=0);const char map[]="0 0 1\n1000 101000 1001\n";CHECK(write(fd,map,sizeof(map)-1)==sizeof(map)-1&&close(fd)==0);}
 CHECK(write(go[1],"g",1)==1&&close(go[1])==0&&close(ready[0])==0);wait_client(child);puts("FUSE mapped user namespace ACL passed");return 0;
}
