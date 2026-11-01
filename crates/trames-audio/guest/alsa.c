// SPDX-License-Identifier: GPL-3.0-or-later
// Standard ALSA terminal PCM plugin; libc/ALSA retain conversion and mixing.
#define _GNU_SOURCE
#include <alsa/asoundlib.h>
#include <alsa/pcm_external.h>
#include <sys/auxv.h>
#include <sys/eventfd.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <poll.h>
#include <unistd.h>

extern int64_t trames_audio_call(uint64_t op, uint64_t *args, uint64_t size);
typedef struct { snd_pcm_ioplug_t io; uint64_t stream; int event; snd_pcm_uframes_t boundary; } Audio;
static int64_t call(Audio *s, unsigned op, uint64_t arg1, uint64_t arg2) {
    uint64_t a[16]={s->stream,arg1,arg2};return trames_audio_call(op,a,sizeof a);
}
static int stats(Audio *s,uint64_t a[8]) {return call(s,7,(uintptr_t)a,0);}
static int start(snd_pcm_ioplug_t *io) {return call(io->private_data,3,0,0);}
static int stop(snd_pcm_ioplug_t *io) {return call(io->private_data,4,0,0);}
static int prepare(snd_pcm_ioplug_t *io) {return call(io->private_data,5,0,0);}
static int pause_pcm(snd_pcm_ioplug_t *io,int enabled) {return call(io->private_data,8,enabled,0);}
static snd_pcm_sframes_t position(snd_pcm_ioplug_t *io) {
    uint64_t a[8];int error=stats(io->private_data,a);return error<0?error:(snd_pcm_sframes_t)(a[0]%(((Audio *)io->private_data)->boundary?((Audio *)io->private_data)->boundary:io->buffer_size));
}
static snd_pcm_sframes_t transfer(snd_pcm_ioplug_t *io,const snd_pcm_channel_area_t *areas,snd_pcm_uframes_t offset,snd_pcm_uframes_t frames) {
    unsigned frame_bytes=io->channels*snd_pcm_format_physical_width(io->format)/8;
    if(areas[0].step!=frame_bytes*8 || areas[0].first%8)return -EINVAL;
    uintptr_t data=(uintptr_t)areas[0].addr+areas[0].first/8+offset*frame_bytes;
    return call(io->private_data,6,data,frames);
}
static int hw_free(snd_pcm_ioplug_t *io) {
    Audio *s=io->private_data;
    if(s->stream){call(s,2,0,0);s->stream=0;}
    if(s->event>=0){close(s->event);s->event=-1;}
    io->poll_fd=-1;return 0;
}
static int close_pcm(snd_pcm_ioplug_t *io) {hw_free(io);free(io->private_data);return 0;}
static int params(snd_pcm_ioplug_t *io,snd_pcm_hw_params_t *params) {
    (void)params;Audio *s=io->private_data;hw_free(io);
    s->event=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);if(s->event<0)return -errno;
    uint64_t a[16]={(uint64_t)s->event,io->stream==SND_PCM_STREAM_CAPTURE,io->rate,io->channels,
        io->format==SND_PCM_FORMAT_FLOAT_LE,io->period_size,io->buffer_size};
    int64_t id=trames_audio_call(1,a,sizeof a);
    if(id<0){hw_free(io);return id;}
    s->stream=id;io->poll_fd=s->event;io->poll_events=POLLIN;
    return snd_pcm_ioplug_reinit_status(io);
}
static int sw_params(snd_pcm_ioplug_t *io,snd_pcm_sw_params_t *params) {return snd_pcm_sw_params_get_boundary(params,&((Audio *)io->private_data)->boundary);}
static int revents(snd_pcm_ioplug_t *io,struct pollfd *pfd,unsigned n,unsigned short *events) {
    Audio *s=io->private_data;if(n!=1)return -EINVAL;
    if(pfd[0].revents&(POLLERR|POLLHUP|POLLNVAL)){*events=POLLERR;return 0;}
    uint64_t count;while(read(s->event,&count,sizeof count)>0){}
    uint64_t a[8];int error=stats(s,a);if(error<0)return error;
    *events=a[2]>=io->period_size?(io->stream==SND_PCM_STREAM_CAPTURE?POLLIN:POLLOUT):0;
    return 0;
}
static int delay_pcm(snd_pcm_ioplug_t *io,snd_pcm_sframes_t *delay) {
    uint64_t a[8];int error=stats(io->private_data,a);if(error<0)return error;*delay=a[1];return 0;
}
static int drain(snd_pcm_ioplug_t *io) {
    Audio *s=io->private_data;if(io->stream==SND_PCM_STREAM_CAPTURE)return 0;
    int error=start(io);if(error<0)return error;
    for(;;){
        uint64_t a[8];error=stats(s,a);if(error<0)return error;if(!a[1])return 0;
        if(io->nonblock)return -EAGAIN;
        struct pollfd fd={s->event,POLLIN,0};error=poll(&fd,1,10000);
        if(error<0)return -errno;
        if(!error)return -EIO;
        uint64_t count;while(read(s->event,&count,sizeof count)>0){}
    }
}
static const snd_pcm_ioplug_callback_t callbacks={.start=start,.stop=stop,.pointer=position,
    .transfer=transfer,.close=close_pcm,.hw_params=params,.hw_free=hw_free,.sw_params=sw_params,.prepare=prepare,
    .drain=drain,.pause=pause_pcm,.poll_revents=revents,.delay=delay_pcm};
SND_PCM_PLUGIN_DEFINE_FUNC(trames) {
    (void)root;(void)conf;
    if(getauxval(0x5452000a)!=0x10008)return -ENODEV;
    Audio *s=calloc(1,sizeof *s);if(!s)return -ENOMEM;s->event=-1;
    s->io.version=SND_PCM_IOPLUG_VERSION;s->io.flags=SND_PCM_IOPLUG_FLAG_BOUNDARY_WA;s->io.name="Trames native PCM";
    s->io.callback=&callbacks;s->io.private_data=s;s->io.poll_fd=-1;s->io.mmap_rw=0;
    int error=snd_pcm_ioplug_create(&s->io,name,stream,mode);if(error<0){free(s);return error;}
    static const unsigned access[]={SND_PCM_ACCESS_RW_INTERLEAVED};
    static const unsigned formats[]={SND_PCM_FORMAT_S16_LE,SND_PCM_FORMAT_FLOAT_LE};
    if((error=snd_pcm_ioplug_set_param_list(&s->io,SND_PCM_IOPLUG_HW_ACCESS,1,access))<0 ||
       (error=snd_pcm_ioplug_set_param_list(&s->io,SND_PCM_IOPLUG_HW_FORMAT,2,formats))<0 ||
       (error=snd_pcm_ioplug_set_param_minmax(&s->io,SND_PCM_IOPLUG_HW_CHANNELS,1,2))<0 ||
       (error=snd_pcm_ioplug_set_param_minmax(&s->io,SND_PCM_IOPLUG_HW_RATE,8000,192000))<0 ||
       (error=snd_pcm_ioplug_set_param_minmax(&s->io,SND_PCM_IOPLUG_HW_PERIOD_BYTES,128,65536))<0 ||
       (error=snd_pcm_ioplug_set_param_minmax(&s->io,SND_PCM_IOPLUG_HW_BUFFER_BYTES,256,1048576))<0 ||
       (error=snd_pcm_ioplug_set_param_minmax(&s->io,SND_PCM_IOPLUG_HW_PERIODS,2,16))<0) {
        snd_pcm_ioplug_delete(&s->io);return error;
    }
    *pcmp=s->io.pcm;return 0;
}
SND_PCM_PLUGIN_SYMBOL(trames);
