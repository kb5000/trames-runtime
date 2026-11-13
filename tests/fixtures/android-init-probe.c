// SPDX-License-Identifier: GPL-3.0-or-later
// A static acceptance client launched by the original Android init. All
// property, log and Binder wire protocols are exercised by original binaries.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
static void record(const char *name,const char *text) {int fd=open(name,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0644);if(fd>=0){if(write(fd,text,strlen(text))<0)perror(name);close(fd);}}
static void check(int ok,const char *what) {if(!ok){record("/data/trames-foundation/failure",what);perror(what);exit(1);}}
static void command(char *const args[],const char *expected) {
    record("/data/trames-foundation/stage",args[1]);
    int channel[2];check(pipe(channel)==0,"pipe");pid_t pid=fork();check(pid>=0,"fork");
    if(!pid){close(channel[0]);check(dup2(channel[1],STDOUT_FILENO)==STDOUT_FILENO,"stdout");check(dup2(channel[1],STDERR_FILENO)==STDERR_FILENO,"stderr");close(channel[1]);execve(args[0],args,environ);perror(args[0]);_exit(127);}
    close(channel[1]);char out[32768]={0};size_t used=0;
    while(used<sizeof(out)-1){ssize_t n=read(channel[0],out+used,sizeof(out)-1-used);if(n<0&&errno==EINTR)continue;check(n>=0,"read");if(!n)break;used+=(size_t)n;}
    record("/data/trames-foundation/last-output",out);close(channel[0]);int status;check(waitpid(pid,&status,0)==pid,"wait");check(WIFEXITED(status)&&WEXITSTATUS(status)==0,"command status");
    if(expected)check(strstr(out,expected)!=NULL,"command output");
}
int main(void) {
    command((char*[]){"/system/bin/getprop","trames.foundation.init",NULL},"ready");
    command((char*[]){"/system/bin/setprop","trames.foundation.roundtrip","original-property-service",NULL},NULL);
    command((char*[]){"/system/bin/getprop","trames.foundation.roundtrip",NULL},"original-property-service");
    command((char*[]){"/system/bin/toybox","getenforce",NULL},"Disabled");
    command((char*[]){"/system/bin/service","check","manager",NULL},"Service manager: found");
    command((char*[]){"/system/bin/toybox","log","-p","i","-t","TramesFoundation","original-logd-roundtrip",NULL},NULL);
    command((char*[]){"/system/bin/logcat","-b","main","-d","-s","TramesFoundation:I","*:S",NULL},"original-logd-roundtrip");
    int fd=open("/data/trames-foundation/ok",O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0644);check(fd>=0,"marker");
    const char *result="PASS original init property-service logd logcat Binder SELinux Disabled\n";
    check(write(fd,result,strlen(result))==(ssize_t)strlen(result),"marker write");check(close(fd)==0,"close marker");return 0;
}
