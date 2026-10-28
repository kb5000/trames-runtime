// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
// Test the syscall itself: musl may implement sendmmsg as a userspace loop.
#define sendmmsg(fd, messages, count, flags) ((int)syscall(SYS_sendmmsg, fd, messages, count, flags))
static volatile sig_atomic_t pipes;
static void pipe_signal(int value) { (void)value; pipes++; }
int main(void) {
 int fds[2]; assert(!socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, fds));
 char a[]="abc", b[]="xyz", output[8];
 struct iovec io[2]={{a,3},{b,3}};
 struct mmsghdr msg[2]={0};
 for(unsigned i=0;i<2;i++){msg[i].msg_hdr.msg_iov=&io[i];msg[i].msg_hdr.msg_iovlen=1;}
 assert(sendmmsg(fds[0],msg,2,MSG_NOSIGNAL)==2);
 assert(msg[0].msg_len==3 && msg[1].msg_len==3);
 assert(recv(fds[1],output,sizeof output,0)==3 && !memcmp(output,a,3));
 assert(recv(fds[1],output,sizeof output,0)==3 && !memcmp(output,b,3));
 io[1].iov_base=(void *)1; msg[0].msg_len=msg[1].msg_len=0;
 assert(sendmmsg(fds[0],msg,2,0)==1 && msg[0].msg_len==3 && msg[1].msg_len==0);
 assert(recv(fds[1],output,sizeof output,0)==3 && !memcmp(output,a,3));
 assert(recv(fds[1],output,sizeof output,0)==-1 && errno==EAGAIN);
 struct mmsghdr *readonly=mmap(0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 assert(readonly!=MAP_FAILED); *readonly=msg[0];
 assert(!mprotect(readonly,4096,PROT_READ));
 assert(sendmmsg(fds[0],readonly,1,0)==-1 && errno==EFAULT);
 assert(recv(fds[1],output,sizeof output,0)==3 && !memcmp(output,a,3));
 assert(sendmmsg(-1,0,0,0)==-1 && errno==EBADF);
 assert(sendmmsg(1,0,0,0)==-1 && errno==ENOTSOCK);
 assert(sendmmsg(fds[0],0,0,0)==0);
 assert(!munmap(readonly,4096)); assert(!close(fds[0]) && !close(fds[1]));
 assert(signal(SIGPIPE,pipe_signal)!=SIG_ERR);
 assert(!socketpair(AF_UNIX,SOCK_STREAM,0,fds)); assert(!close(fds[1]));
 assert(sendmmsg(fds[0],msg,1,0)==-1 && errno==EPIPE && pipes==1);
 assert(sendmmsg(fds[0],msg,1,MSG_NOSIGNAL)==-1 && errno==EPIPE && pipes==1);
 assert(!close(fds[0]));
 puts("sendmmsg: datagrams, partial progress, length faults, signals, zero-length validation passed");
}
