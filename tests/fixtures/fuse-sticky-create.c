// SPDX-License-Identifier: GPL-3.0-or-later
#define main mode_permission_main
#include "fuse-permissions.c"
#undef main
static int sticky_local;
static void policy(unsigned value) {
 int fd=open("/proc/sys/fs/protected_regular",O_WRONLY);CHECK(fd>=0);
 char b='0'+value;CHECK(write(fd,&b,1)==1&&close(fd)==0);
 fd=open("/proc/sys/fs/protected_fifos",O_WRONLY);CHECK(fd>=0);
 CHECK(write(fd,"2",1)==1&&close(fd)==0);
}
static void existing(const char *path) {
 int fd=open(path,O_CREAT|O_RDONLY,0600);CHECK(fd>=0&&close(fd)==0);
}
static void denied(const char *label,const char *path,int flags,int error) {
 errno=0;int fd=open(path,flags,0600);int e=errno;
 fprintf(stderr,"sticky %s result=%d errno=%d\n",label,fd,e);
 if(!sticky_local&&error==EACCES&&strcmp(label,"bound-regular")){CHECK(fd>=0&&close(fd)==0);}else CHECK(fd==-1&&e==error);
}
static void sticky_client(void) {
 CHECK(setgroups(0,NULL)==0&&setgid(1000)==0&&setuid(1000)==0);
 denied("regular",BASE "/sticky/foreign",O_CREAT|O_RDONLY,EACCES);
 denied("exclusive",BASE "/sticky/foreign",O_CREAT|O_EXCL|O_RDONLY,EEXIST);
 denied("directory-flag",BASE "/sticky/foreign",O_CREAT|O_DIRECTORY|O_RDONLY,EINVAL);
 if(sticky_local)denied("fifo",BASE "/sticky/fifo",O_CREAT|O_NONBLOCK|O_RDWR,EACCES);
 denied("group-regular",BASE "/group-sticky/foreign",O_CREAT|O_RDONLY,EACCES);
 denied("bound-regular","/fuse-sticky-outer/bound",O_CREAT|O_RDONLY,EACCES);
 existing(BASE "/sticky/owned");existing(BASE "/sticky/parent-owned");
 int fd=open(BASE "/sticky/foreign",O_RDONLY);CHECK(fd>=0);
 char path[80];snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
 existing(path);CHECK(close(fd)==0);
}
int main(int argc,char **argv) {
 int local=argc==1||strcmp(argv[1],"delegated");sticky_local=local;release_target=local?6:9;
 memset(nodes,0,sizeof(nodes));
 nodes[0]=(struct node){1,0,S_IFDIR|0755,0,0,1,""};
 nodes[1]=(struct node){2,1,S_IFDIR|01777,2000,1000,1,"sticky"};
 nodes[2]=(struct node){3,2,S_IFREG|0666,3000,1000,1,"foreign"};
 nodes[3]=(struct node){4,2,S_IFREG|0666,1000,1000,1,"owned"};
 nodes[4]=(struct node){5,2,S_IFREG|0666,2000,1000,1,"parent-owned"};
 nodes[5]=(struct node){6,2,S_IFIFO|0666,3000,1000,1,"fifo"};
 nodes[6]=(struct node){7,1,S_IFDIR|01770,2000,1000,1,"group-sticky"};
 nodes[7]=(struct node){8,7,S_IFREG|0666,3000,1000,1,"foreign"};
 policy(2);CHECK(mkdir(BASE,0755)==0);int fd=open("/dev/fuse",O_RDWR);CHECK(fd>=0);
 char options[160];snprintf(options,sizeof(options),"fd=%d,rootmode=40755,user_id=0,group_id=0,allow_other%s",fd,local?",default_permissions":"");
 CHECK(mount("sticky-fixture",BASE,"fuse",0,options)==0);int completed[2];CHECK(pipe(completed)==0);
 pid_t daemon=fork();CHECK(daemon>=0);if(!daemon){CHECK(close(completed[0])==0);daemon_loop(fd,completed[1]);}CHECK(close(completed[1])==0);
 CHECK(mkdir("/fuse-sticky-outer",0700)==0&&chown("/fuse-sticky-outer",2000,1000)==0&&chmod("/fuse-sticky-outer",01777)==0);
 int bound=open("/fuse-sticky-outer/bound",O_CREAT|O_EXCL|O_RDWR,0600);CHECK(bound>=0&&close(bound)==0);
 CHECK(mount(BASE "/sticky/foreign","/fuse-sticky-outer/bound",NULL,MS_BIND,NULL)==0);
 pid_t client=fork();CHECK(client>=0);if(!client){sticky_client();_exit(0);}int status;CHECK(waitpid(client,&status,0)==client&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
 denied("root-capability",BASE "/sticky/foreign",O_CREAT|O_RDONLY,EACCES);
 policy(1);existing(BASE "/group-sticky/foreign");
 policy(0);existing(BASE "/sticky/foreign");
 char ack;CHECK(read(completed[0],&ack,1)==1&&ack=='r'&&close(completed[0])==0);
 CHECK(umount("/fuse-sticky-outer/bound")==0&&unlink("/fuse-sticky-outer/bound")==0&&rmdir("/fuse-sticky-outer")==0);
 CHECK(umount(BASE)==0&&waitpid(daemon,&status,0)==daemon&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
 CHECK(close(fd)==0&&rmdir(BASE)==0);puts("FUSE sticky creation passed");return 0;
}
