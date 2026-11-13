// SPDX-License-Identifier: GPL-3.0-or-later
// The same AArch64 Linux binary runs against Linux Binder and Trames Binder.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/android/binder.h>
#include <linux/memfd.h>
#include <stdint.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line %d: %s (errno=%d)\n",__LINE__,#x,errno); exit(1); } } while(0)
struct endpoint { int fd; void *mapping; };
static const size_t pool_size = 1024 * 1024;
static binder_uintptr_t last_decref_pointer,last_decref_cookie;
static void wr(int fd, const void *bytes, size_t size) {
    struct binder_write_read request = { .write_size=size, .write_buffer=(uintptr_t)bytes };
    int rc; do { rc=ioctl(fd,BINDER_WRITE_READ,&request); } while (rc<0 && errno==EINTR);
    CHECK(rc==0 && request.write_consumed==size);
}
static void command(int fd,uint32_t cmd,const void *argument,size_t length) {
    unsigned char bytes[128]; CHECK(length+4<=sizeof(bytes));
    memcpy(bytes,&cmd,4); if(length) memcpy(bytes+4,argument,length); wr(fd,bytes,length+4);
}
static struct endpoint open_endpoint(const char *path) {
    struct endpoint e = { .fd=open(path,O_RDWR|O_CLOEXEC) }; CHECK(e.fd>=0);
    struct binder_version v={0}; CHECK(ioctl(e.fd,BINDER_VERSION,&v)==0 && v.protocol_version==8);
    uint32_t threads=0; CHECK(ioctl(e.fd,BINDER_SET_MAX_THREADS,&threads)==0);
    e.mapping=mmap(NULL,pool_size,PROT_READ,MAP_PRIVATE|MAP_NORESERVE,e.fd,0); CHECK(e.mapping!=MAP_FAILED);
    CHECK(mprotect(e.mapping,4096,PROT_READ|PROT_WRITE)<0);
    return e;
}
static void transaction(int fd,uint32_t command_code,uint32_t handle,uint32_t code,
                        const void *data,size_t size,const binder_size_t *offsets,size_t count) {
    struct binder_transaction_data t={0}; t.target.handle=handle; t.code=code;
    t.flags=TF_ACCEPT_FDS; t.data_size=size; t.offsets_size=count*sizeof(*offsets);
    t.data.ptr.buffer=(uintptr_t)data; t.data.ptr.offsets=(uintptr_t)offsets;
    command(fd,command_code,&t,sizeof(t));
}
static struct binder_transaction_data receive(int fd,uint32_t wanted) {
    for (;;) {
        unsigned char bytes[4096]; struct binder_write_read request={ .read_size=sizeof(bytes), .read_buffer=(uintptr_t)bytes };
        int rc; do { rc=ioctl(fd,BINDER_WRITE_READ,&request); } while(rc<0 && errno==EINTR); CHECK(rc==0);
        struct binder_transaction_data result={0};int found=0;
        for(size_t at=0;at<request.read_consumed;) {
            uint32_t cmd; CHECK(at+4<=request.read_consumed); memcpy(&cmd,bytes+at,4); at+=4;
            size_t length=_IOC_SIZE(cmd); CHECK(at+length<=request.read_consumed);
            if(cmd==BR_DECREFS) {
                struct binder_ptr_cookie released;memcpy(&released,bytes+at,sizeof(released));
                last_decref_pointer=released.ptr;last_decref_cookie=released.cookie;
            }
            if(cmd==BR_INCREFS || cmd==BR_ACQUIRE) command(fd,cmd==BR_INCREFS?BC_INCREFS_DONE:BC_ACQUIRE_DONE,bytes+at,length);
            if(cmd==BR_TRANSACTION && wanted==BR_REPLY) {
                struct binder_transaction_data callback; memcpy(&callback,bytes+at,sizeof(callback));
                CHECK(callback.target.ptr==0x12340000 && callback.cookie==0x56780000 && callback.code==2);
                CHECK(callback.data_size==8 && memcmp((void *)(uintptr_t)callback.data.ptr.buffer,"callback",8)==0);
                transaction(fd,BC_REPLY,0,0,"callback-ok",11,NULL,0);
                command(fd,BC_FREE_BUFFER,&callback.data.ptr.buffer,sizeof(binder_uintptr_t));
            } else if(cmd==wanted) {
                found=1;
                if(wanted==BR_DEAD_BINDER) {
                    binder_uintptr_t cookie; memcpy(&cookie,bytes+at,sizeof(cookie)); CHECK(cookie==0x9988);
                    command(fd,BC_DEAD_BINDER_DONE,&cookie,sizeof(cookie));
                } else if(wanted==BR_RELEASE || wanted==BR_DECREFS) {
                    struct binder_ptr_cookie released;memcpy(&released,bytes+at,sizeof(released));
                    result.target.ptr=released.ptr;result.cookie=released.cookie;
                } else if(wanted!=BR_FAILED_REPLY && wanted!=BR_DEAD_REPLY && wanted!=BR_TRANSACTION_COMPLETE) memcpy(&result,bytes+at,sizeof(result));
            } else CHECK(cmd==BR_NOOP || cmd==BR_TRANSACTION_COMPLETE || cmd==BR_RELEASE || cmd==BR_DECREFS || cmd==BR_INCREFS || cmd==BR_ACQUIRE);
            at+=length;
        }
        if(found)return result;
    }
}
static pthread_mutex_t poll_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t poll_cond=PTHREAD_COND_INITIALIZER;
static int poll_ready,poll_continue;
static void oneway(int fd,uint32_t code) {
    struct binder_transaction_data t={.code=code,.flags=TF_ONE_WAY};command(fd,BC_TRANSACTION,&t,sizeof(t));
}
static void *poll_worker(void *arg) {
    int fd=*(int *)arg;oneway(fd,88);
    CHECK(!pthread_mutex_lock(&poll_lock));poll_ready=1;CHECK(!pthread_cond_signal(&poll_cond));
    while(!poll_continue){CHECK(!pthread_cond_wait(&poll_cond,&poll_lock));}
    CHECK(!pthread_mutex_unlock(&poll_lock));
    receive(fd,BR_TRANSACTION_COMPLETE);return NULL;
}
static void per_thread_poll(int fd) {
    int ep=epoll_create1(EPOLL_CLOEXEC);CHECK(ep>=0);struct epoll_event event={.events=EPOLLIN,.data.u64=17};CHECK(!epoll_ctl(ep,EPOLL_CTL_ADD,fd,&event));
    pthread_t worker;CHECK(!pthread_create(&worker,NULL,poll_worker,&fd));
    CHECK(!pthread_mutex_lock(&poll_lock));while(!poll_ready)CHECK(!pthread_cond_wait(&poll_cond,&poll_lock));
    struct pollfd p={.fd=fd,.events=POLLIN};CHECK(poll(&p,1,0)==0);CHECK(epoll_wait(ep,&event,1,0)==0);
    poll_continue=1;CHECK(!pthread_cond_signal(&poll_cond)&&!pthread_mutex_unlock(&poll_lock));CHECK(!pthread_join(worker,NULL));
    oneway(fd,89);p.revents=0;CHECK(poll(&p,1,0)==1&&(p.revents&POLLIN));CHECK(epoll_wait(ep,&event,1,0)==1&&event.data.u64==17);receive(fd,BR_TRANSACTION_COMPLETE);close(ep);
}
static void seals(void) {
    int fd=memfd_create("android-seals",MFD_CLOEXEC|MFD_ALLOW_SEALING); CHECK(fd>=0); CHECK(ftruncate(fd,4096)==0);
    unsigned char *before=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0); CHECK(before!=MAP_FAILED);
    CHECK(fcntl(fd,F_ADD_SEALS,F_SEAL_FUTURE_WRITE)==0);
    CHECK(pwrite(fd,"x",1,0)<0 && errno==EPERM); before[0]=73;
    unsigned char value=0; CHECK(pread(fd,&value,1,0)==1 && value==73);
    CHECK(mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0)==MAP_FAILED && errno==EPERM);
    void *after=mmap(NULL,4096,PROT_READ,MAP_SHARED,fd,0); CHECK(after!=MAP_FAILED);
    CHECK(mprotect(after,4096,PROT_READ|PROT_WRITE)<0); CHECK(ftruncate(fd,8192)==0);
    CHECK(munmap(before,4096)==0 && munmap(after,4096)==0); close(fd);
}
int main(int argc,char **argv) {
    CHECK(argc==2); seals(); struct endpoint manager=open_endpoint(argv[1]);
    struct flat_binder_object context={ .flags=FLAT_BINDER_FLAG_ACCEPTS_FDS }; CHECK(ioctl(manager.fd,BINDER_SET_CONTEXT_MGR_EXT,&context)==0);
    command(manager.fd,BC_ENTER_LOOPER,NULL,0);
    pid_t child=fork(); CHECK(child>=0);
    if(child==0) {
        unsigned char resident; CHECK(mincore(manager.mapping,4096,&resident)<0 && errno==ENOMEM); close(manager.fd);
        struct endpoint client=open_endpoint(argv[1]); uint32_t handle=0; command(client.fd,BC_ACQUIRE,&handle,sizeof(handle));
        struct binder_handle_cookie death={ .handle=0, .cookie=0x9988 }; command(client.fd,BC_REQUEST_DEATH_NOTIFICATION,&death,sizeof(death));
        int original=memfd_create("binder-ofd",MFD_CLOEXEC); CHECK(original>=0); CHECK(write(original,"from-client",11)==11); CHECK(lseek(original,0,SEEK_SET)==0);
        struct { uint64_t tag; struct flat_binder_object callback; struct binder_fd_object fd; } data={0};
        data.tag=0x11223344; data.callback.hdr.type=BINDER_TYPE_BINDER; data.callback.flags=FLAT_BINDER_FLAG_ACCEPTS_FDS;
        data.callback.binder=0x12340000; data.callback.cookie=0x56780000; data.fd.hdr.type=BINDER_TYPE_FD; data.fd.fd=original;
        binder_size_t offsets[]={8,32}; transaction(client.fd,BC_TRANSACTION,0,1,&data,sizeof(data),offsets,2); close(original);
        int replacement=memfd_create("replacement",MFD_CLOEXEC); CHECK(replacement==original); CHECK(write(replacement,"replacement",11)==11);
        struct binder_transaction_data reply=receive(client.fd,BR_REPLY); CHECK(reply.data_size==4 && memcmp((void *)(uintptr_t)reply.data.ptr.buffer,"done",4)==0);
        command(client.fd,BC_FREE_BUFFER,&reply.data.ptr.buffer,sizeof(binder_uintptr_t));
        for(uint32_t generation=1;generation<=8;generation++) {
            struct flat_binder_object object={.hdr.type=BINDER_TYPE_BINDER,.flags=FLAT_BINDER_FLAG_ACCEPTS_FDS,.binder=0xabcd0000,.cookie=0x1000+generation};
            binder_size_t offset=0;
            transaction(client.fd,BC_TRANSACTION,0,10+generation,&object,sizeof(object),&offset,1);
            reply=receive(client.fd,BR_REPLY);command(client.fd,BC_FREE_BUFFER,&reply.data.ptr.buffer,sizeof(binder_uintptr_t));
            transaction(client.fd,BC_TRANSACTION,0,30+generation,"acknowledged",12,NULL,0);
            reply=receive(client.fd,BR_REPLY);command(client.fd,BC_FREE_BUFFER,&reply.data.ptr.buffer,sizeof(binder_uintptr_t));
            while(last_decref_pointer!=object.binder || last_decref_cookie!=object.cookie) receive(client.fd,BR_DECREFS);
        }
        per_thread_poll(client.fd);
        transaction(client.fd,BC_TRANSACTION,0,99,"bad reply",9,NULL,0);receive(client.fd,BR_FAILED_REPLY);
        transaction(client.fd,BC_TRANSACTION,0,100,"recovered",9,NULL,0);
        reply=receive(client.fd,BR_REPLY);CHECK(reply.data_size==2&&memcmp((void *)(uintptr_t)reply.data.ptr.buffer,"ok",2)==0);
        command(client.fd,BC_FREE_BUFFER,&reply.data.ptr.buffer,sizeof(binder_uintptr_t));receive(client.fd,BR_DEAD_BINDER);
        close(replacement); close(client.fd); CHECK(munmap(client.mapping,pool_size)==0); _exit(0);
    }
    struct binder_transaction_data request=receive(manager.fd,BR_TRANSACTION); CHECK(request.code==1 && request.sender_pid==child && request.data_size==56);
    unsigned char *data=(void *)(uintptr_t)request.data.ptr.buffer;
    struct flat_binder_object callback; struct binder_fd_object carried;
    memcpy(&callback,data+8,sizeof(callback)); memcpy(&carried,data+32,sizeof(carried));
    CHECK(callback.hdr.type==BINDER_TYPE_HANDLE && carried.hdr.type==BINDER_TYPE_FD);
    CHECK(fcntl(carried.fd,F_GETFD)&FD_CLOEXEC); char contents[12]={0}; CHECK(read(carried.fd,contents,11)==11 && strcmp(contents,"from-client")==0); close(carried.fd);
    transaction(manager.fd,BC_TRANSACTION,callback.handle,2,"callback",8,NULL,0);
    struct binder_transaction_data nested=receive(manager.fd,BR_REPLY); CHECK(nested.data_size==11 && memcmp((void *)(uintptr_t)nested.data.ptr.buffer,"callback-ok",11)==0);
    command(manager.fd,BC_FREE_BUFFER,&nested.data.ptr.buffer,sizeof(binder_uintptr_t)); transaction(manager.fd,BC_REPLY,0,0,"done",4,NULL,0);
    command(manager.fd,BC_FREE_BUFFER,&request.data.ptr.buffer,sizeof(binder_uintptr_t));
    for(uint32_t generation=1;generation<=8;generation++) {
        request=receive(manager.fd,BR_TRANSACTION);CHECK(request.code==10+generation);
        struct flat_binder_object object;memcpy(&object,(void *)(uintptr_t)request.data.ptr.buffer,sizeof(object));CHECK(object.hdr.type==BINDER_TYPE_HANDLE);
        command(manager.fd,BC_INCREFS,&object.handle,sizeof(object.handle));command(manager.fd,BC_ACQUIRE,&object.handle,sizeof(object.handle));
        transaction(manager.fd,BC_REPLY,0,0,"held",4,NULL,0);command(manager.fd,BC_FREE_BUFFER,&request.data.ptr.buffer,sizeof(binder_uintptr_t));
        request=receive(manager.fd,BR_TRANSACTION);CHECK(request.code==30+generation);
        command(manager.fd,BC_RELEASE,&object.handle,sizeof(object.handle));command(manager.fd,BC_DECREFS,&object.handle,sizeof(object.handle));
        transaction(manager.fd,BC_REPLY,0,0,"released",8,NULL,0);command(manager.fd,BC_FREE_BUFFER,&request.data.ptr.buffer,sizeof(binder_uintptr_t));
    }
    for(uint32_t code=88;code<=89;code++) { request=receive(manager.fd,BR_TRANSACTION);CHECK(request.code==code&&(request.flags&TF_ONE_WAY));command(manager.fd,BC_FREE_BUFFER,&request.data.ptr.buffer,sizeof(binder_uintptr_t)); }
    request=receive(manager.fd,BR_TRANSACTION);CHECK(request.code==99);
    transaction(manager.fd,BC_REPLY,0,0,(const void *)1,8,NULL,0);receive(manager.fd,BR_TRANSACTION_COMPLETE);command(manager.fd,BC_FREE_BUFFER,&request.data.ptr.buffer,sizeof(binder_uintptr_t));
    request=receive(manager.fd,BR_TRANSACTION);CHECK(request.code==100);
    transaction(manager.fd,BC_REPLY,0,0,"ok",2,NULL,0);command(manager.fd,BC_FREE_BUFFER,&request.data.ptr.buffer,sizeof(binder_uintptr_t));
    close(manager.fd); CHECK(munmap(manager.mapping,pool_size)==0);
    int status; CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
    puts("binder-foundation: PASS nested fd death vm_dontcopy seal_future_write node_reuse failed_reply thread_poll"); return 0;
}
