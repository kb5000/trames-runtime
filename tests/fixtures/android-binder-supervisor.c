// SPDX-License-Identifier: GPL-3.0-or-later
// Runs unchanged Waydroid/Bionic servicemanager and service binaries in one
// guest environment. This is an acceptance fixture, never a production init.
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
extern char **environ;
static void check(int ok,const char *what) { if(!ok) { perror(what); exit(1); } }
static void client(const char *binary,const char *operation,const char *name,const char *expected) {
    int channel[2]; check(pipe(channel)==0,"pipe service");
    pid_t pid=fork(); check(pid>=0,"fork service");
    if(pid==0) { close(channel[0]); check(dup2(channel[1],STDOUT_FILENO)==STDOUT_FILENO,"redirect service"); close(channel[1]); char *args[]={(char *)binary,(char *)operation,(char *)name,NULL}; execve(args[0],args,environ); perror("exec service"); _exit(1); }
    close(channel[1]); char output[8192]={0}; size_t used=0;
    while(used<sizeof(output)-1) { ssize_t n=read(channel[0],output+used,sizeof(output)-1-used); if(n<0&&errno==EINTR)continue; check(n>=0,"read service"); if(!n)break; used+=(size_t)n; }
    close(channel[0]); fputs(output,stdout); fflush(stdout); check(strstr(output,expected)!=NULL,"service output");
    int status=0; check(waitpid(pid,&status,0)==pid,"wait service"); check(WIFEXITED(status)&&WEXITSTATUS(status)==0,"service result");
}
int main(void) {
    check(setenv("LD_LIBRARY_PATH","/system/lib64:/apex/com.android.runtime/lib64/bionic",1)==0,"library path");
    check(setenv("ANDROID_ROOT","/system",1)==0,"Android root"); check(setenv("ANDROID_DATA","/data",1)==0,"Android data");
    check(setenv("ANDROID_RUNTIME_ROOT","/apex/com.android.runtime",1)==0,"Android runtime");
    client("/system/bin/toybox","getenforce",NULL,"Disabled");
    pid_t manager=fork(); check(manager>=0,"fork manager");
    if(manager==0) { char *args[]={"/system/bin/servicemanager","/dev/binder",NULL}; execve(args[0],args,environ); perror("exec manager"); _exit(1); }
    struct timespec delay={0,250000000}; while(nanosleep(&delay,&delay)<0&&errno==EINTR) {}
    client("/system/bin/service","list",NULL,"manager: ["); client("/system/bin/service","check","manager","Service manager: found");
    check(kill(manager,SIGTERM)==0,"stop manager"); int status=0; check(waitpid(manager,&status,0)==manager,"wait manager");
    puts("android-binder: PASS original Waydroid servicemanager, service list, service check manager, SELinux Disabled"); return 0;
}
