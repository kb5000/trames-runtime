// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/fuse.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"pid=%d line=%d %s errno=%d\n",getpid(),__LINE__,#x,errno);_exit(1);}}while(0)
#define BASE "/fuse-permissions-test"
struct node {uint64_t id,parent;unsigned mode,uid,gid;int active;char name[32];};
static int diagnostics;
static unsigned release_target=5;
static struct node nodes[64]={
 {1,0,S_IFDIR|0755,0,0,1,""}, {2,1,S_IFDIR|0755,0,0,1,"public"},
 {3,1,S_IFDIR|0700,0,0,1,"private"}, {4,1,S_IFDIR|0777,0,0,1,"write"},
 {5,2,S_IFREG|0644,0,0,1,"readable"}, {6,2,S_IFREG|0600,0,0,1,"secret"},
 {7,2,S_IFREG|0600,1000,1000,1,"owned"}, {8,2,S_IFREG|0644,0,0,1,"refresh"},
 {9,2,S_IFREG|0600,0,0,1,"noexec"}, {10,3,S_IFREG|0644,0,0,1,"child"},
 {11,4,S_IFDIR|0555,1000,1000,1,"readonly-dir"}, {12,1,S_IFDIR|0777,0,0,1,"write2"},
 {13,2,S_IFREG|0666,0,0,1,"linkable"},
};
static struct node *by_id(uint64_t id){for(unsigned i=0;i<64;i++)if(nodes[i].id==id)return &nodes[i];return NULL;}
static struct node *find(uint64_t parent,const char *name){for(unsigned i=0;i<64;i++)if(nodes[i].active&&nodes[i].parent==parent&&!strcmp(nodes[i].name,name))return &nodes[i];return NULL;}
static struct fuse_attr attr(struct node *n){struct fuse_attr a={.ino=n->id,.mode=n->mode,.uid=n->uid,.gid=n->gid,.nlink=1,.blksize=4096};return a;}
static unsigned char input[65536],output[65536];
static void reply(int fd,const struct fuse_in_header *in,int error,const void *data,size_t size){
 struct fuse_out_header out={.len=sizeof(out)+size,.error=-error,.unique=in->unique};memcpy(output,&out,sizeof(out));if(size)memcpy(output+sizeof(out),data,size);CHECK(write(fd,output,out.len)==out.len);
}
static void entry(int fd,const struct fuse_in_header *in,struct node *n,int opened){
 struct {struct fuse_entry_out e;struct fuse_open_out o;} out={.e={.nodeid=n->id,.entry_valid=1,.attr_valid=1,.attr=attr(n)},.o={.fh=n->id}};
 if(n->id==8)out.e.attr.mode=S_IFREG;
 reply(fd,in,0,&out,sizeof(out.e)+(opened?sizeof(out.o):0));
}
static void daemon_loop(int fd,int completed){
 unsigned released=0;
 for(;;){ssize_t size=read(fd,input,sizeof(input));if(size<0&&errno==ENODEV)_exit(0);CHECK(size>=(ssize_t)sizeof(struct fuse_in_header));
 const struct fuse_in_header *in=(void*)input;const void *body=input+sizeof(*in);struct node *n=by_id(in->nodeid);CHECK(in->len==size);
 fprintf(stderr,"wire opcode=%u node=%llu uid=%u\n",in->opcode,(unsigned long long)in->nodeid,in->uid);
 switch(in->opcode){
 case FUSE_INIT:{struct fuse_init_out out={.major=7,.minor=31,.flags=FUSE_BIG_WRITES,.max_write=16384,.time_gran=1};reply(fd,in,0,&out,sizeof(out));break;}
 case FUSE_LOOKUP:{struct node *found=find(in->nodeid,body);if(found)entry(fd,in,found,0);else reply(fd,in,ENOENT,NULL,0);break;}
 case FUSE_GETATTR:{CHECK(n);struct fuse_attr_out out={.attr_valid=1,.attr=attr(n)};reply(fd,in,0,&out,sizeof(out));break;}
 case FUSE_SETATTR:{CHECK(n);const struct fuse_setattr_in *s=body;if(s->valid&FATTR_MODE)n->mode=s->mode;if(s->valid&FATTR_UID)n->uid=s->uid;if(s->valid&FATTR_GID)n->gid=s->gid;struct fuse_attr_out out={.attr_valid=1,.attr=attr(n)};reply(fd,in,0,&out,sizeof(out));break;}
 case FUSE_ACCESS:CHECK(0);break;
 case FUSE_OPEN:case FUSE_OPENDIR:{CHECK(n);struct fuse_open_out out={.fh=n->id};reply(fd,in,0,&out,sizeof(out));break;}
 case FUSE_CREATE:case FUSE_MKDIR:case FUSE_MKNOD:case FUSE_SYMLINK:{
  const char *name=body;unsigned mode=S_IFLNK|0777;int opened=in->opcode==FUSE_CREATE;
  if(opened){const struct fuse_create_in *c=body;mode=S_IFREG|c->mode;name=(const char*)body+sizeof(*c);}
  else if(in->opcode==FUSE_MKDIR){const struct fuse_mkdir_in *m=body;mode=S_IFDIR|m->mode;name=(const char*)body+sizeof(*m);}
  else if(in->opcode==FUSE_MKNOD){const struct fuse_mknod_in *m=body;mode=m->mode;name=(const char*)body+sizeof(*m);}
  CHECK(!find(in->nodeid,name));unsigned i;for(i=0;i<64;i++)if(!nodes[i].id)break;CHECK(i<64&&strlen(name)<sizeof(nodes[i].name));
  nodes[i]=(struct node){.id=100+i,.parent=in->nodeid,.mode=mode,.uid=in->uid,.gid=in->gid,.active=1};strcpy(nodes[i].name,name);entry(fd,in,&nodes[i],opened);break;}
 case FUSE_LINK:{const struct fuse_link_in *l=body;const char *name=(const char*)body+sizeof(*l);struct node *source=by_id(l->oldnodeid);CHECK(source&&!find(in->nodeid,name));unsigned i;for(i=0;i<64;i++)if(!nodes[i].id)break;CHECK(i<64);nodes[i]=*source;nodes[i].parent=in->nodeid;strcpy(nodes[i].name,name);entry(fd,in,&nodes[i],0);break;}
 case FUSE_UNLINK:case FUSE_RMDIR:{struct node *found=find(in->nodeid,body);CHECK(found);found->active=0;reply(fd,in,0,NULL,0);break;}
 case FUSE_RENAME:{const struct fuse_rename_in *r=body;const char *old=(const char*)body+sizeof(*r),*name=old+strlen(old)+1;struct node *found=find(in->nodeid,old);CHECK(found);found->parent=r->newdir;strcpy(found->name,name);reply(fd,in,0,NULL,0);break;}
 case FUSE_GETXATTR:{const char *name=(const char*)body+8;if(strcmp(name,"user.test")){reply(fd,in,ENODATA,NULL,0);break;}const struct fuse_getxattr_in *g=body;if(!g->size){struct fuse_getxattr_out out={.size=1};reply(fd,in,0,&out,sizeof(out));}else reply(fd,in,0,"x",1);break;}
 case FUSE_RELEASE:case FUSE_RELEASEDIR:reply(fd,in,0,NULL,0);if(++released==release_target)CHECK(write(completed,"r",1)==1);break;
 case FUSE_SETXATTR:case FUSE_REMOVEXATTR:case FUSE_FLUSH:reply(fd,in,0,NULL,0);break;
 case FUSE_FORGET:case FUSE_BATCH_FORGET:break;
 case FUSE_DESTROY:reply(fd,in,0,NULL,0);_exit(0);
 default:reply(fd,in,ENOSYS,NULL,0);break;
 }
 }
}
static void foreign(void){
 CHECK(setgroups(0,NULL)==0&&setgid(1000)==0&&setuid(1000)==0);int fd;struct stat st;char b;
 fd=open(BASE "/public/readable",O_RDONLY);CHECK(fd>=0&&close(fd)==0);
 errno=0;CHECK(open(BASE "/public/readable",O_WRONLY)==-1&&errno==EACCES);
 errno=0;CHECK(open(BASE "/public/readable",3)==-1&&errno==EACCES);
 CHECK(access(BASE "/public/readable",R_OK)==0);errno=0;CHECK(access(BASE "/public/readable",W_OK)==-1&&errno==EACCES);
 errno=0;CHECK(open(BASE "/public/secret",O_RDONLY)==-1&&errno==EACCES);
 fd=open(BASE "/public/owned",O_RDONLY);CHECK(fd>=0&&close(fd)==0);
 fd=open(BASE "/public/refresh",O_RDONLY);CHECK(fd>=0&&close(fd)==0);
 errno=0;CHECK(access(BASE "/public/noexec",X_OK)==-1&&errno==EACCES);
 errno=0;CHECK(chdir(BASE "/private")==-1&&errno==EACCES);
 errno=0;CHECK(stat(BASE "/private/child",&st)==-1&&errno==EACCES);
 errno=0;CHECK(stat(BASE "/private/./child",&st)==-1&&errno==EACCES);
 errno=0;CHECK(stat(BASE "/private/../public/readable",&st)==-1&&errno==EACCES);
 CHECK(chmod(BASE "/public/owned",0640)==0);errno=0;CHECK(chmod(BASE "/public/readable",0600)==-1&&errno==EPERM);
 errno=0;CHECK(chown(BASE "/public/owned",1001,(gid_t)-1)==-1&&errno==EPERM);
 struct timespec t[2]={{123,0},{123,0}};errno=0;CHECK(utimensat(AT_FDCWD,BASE "/public/readable",t,0)==-1&&errno==EPERM);
 CHECK(getxattr(BASE "/public/readable","user.test",&b,1)==1&&b=='x');errno=0;CHECK(setxattr(BASE "/public/readable","user.test","a",1,0)==-1&&errno==EACCES);
 errno=0;CHECK(getxattr(BASE "/public/secret","user.test",&b,1)==-1&&errno==EACCES);
 errno=0;CHECK(open(BASE "/public/readable",O_CREAT|O_EXCL|O_RDWR,0600)==-1&&errno==EEXIST);
 errno=0;CHECK(open(BASE "/public/new",O_CREAT|O_EXCL|O_RDWR,0600)==-1&&errno==EACCES);
 fd=open(BASE "/write/new",O_CREAT|O_EXCL|O_RDWR,0600);CHECK(fd>=0&&close(fd)==0);
 CHECK(mkdir(BASE "/write/newdir",0700)==0);errno=0;CHECK(mkdir(BASE "/public/newdir",0700)==-1&&errno==EACCES);
 errno=0;CHECK(rename(BASE "/write/new",BASE "/public/new")==-1&&errno==EACCES);
 errno=0;CHECK(unlink(BASE "/public/readable")==-1&&errno==EACCES);
 CHECK(unlink(BASE "/write/new")==0&&rmdir(BASE "/write/newdir")==0);
 errno=0;long linked=link(BASE "/public/readable",BASE "/write/protected");int link_error=errno;fprintf(stderr,"permission protected-link result=%ld errno=%d\n",linked,link_error);if(!diagnostics)CHECK(linked==-1&&link_error==EPERM);if(linked==0)CHECK(unlink(BASE "/write/protected")==0);
 CHECK(link(BASE "/public/linkable",BASE "/write/allowed-link")==0&&unlink(BASE "/write/allowed-link")==0);
 errno=0;long moved=rename(BASE "/write/readonly-dir",BASE "/write2/moved");int move_error=errno;fprintf(stderr,"permission readonly-directory-move result=%ld errno=%d\n",moved,move_error);if(!diagnostics)CHECK(moved==-1&&move_error==EACCES);if(moved==0)CHECK(rename(BASE "/write2/moved",BASE "/write/readonly-dir")==0);
 CHECK(chdir(BASE "/public")==0&&chdir("/")==0);
}
int main(int argc,char **argv){
 (void)argv;diagnostics=argc>1;
 CHECK(mkdir(BASE,0755)==0);int fd=open("/dev/fuse",O_RDWR);CHECK(fd>=0);char options[160];snprintf(options,sizeof(options),"fd=%d,rootmode=40755,user_id=0,group_id=0,allow_other,default_permissions",fd);
 CHECK(mount("permission-fixture",BASE,"fuse",0,options)==0);int completed[2];CHECK(pipe(completed)==0);pid_t daemon=fork();CHECK(daemon>=0);if(!daemon){CHECK(close(completed[0])==0);daemon_loop(fd,completed[1]);}CHECK(close(completed[1])==0);
 pid_t client=fork();CHECK(client>=0);if(!client){foreign();_exit(0);}int status;CHECK(waitpid(client,&status,0)==client&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
 errno=0;CHECK(access(BASE "/public/noexec",X_OK)==-1&&errno==EACCES);
 int data=open(BASE "/public/secret",O_RDONLY);CHECK(data>=0&&close(data)==0);
 char ack;CHECK(read(completed[0],&ack,1)==1&&ack=='r'&&close(completed[0])==0);CHECK(umount(BASE)==0);CHECK(waitpid(daemon,&status,0)==daemon&&WIFEXITED(status)&&WEXITSTATUS(status)==0);CHECK(close(fd)==0&&rmdir(BASE)==0);puts("FUSE default mode permissions passed");return 0;
}
