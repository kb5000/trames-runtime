// SPDX-License-Identifier: GPL-3.0-or-later
// Test-only ALSA device: real timerfd readiness, deterministic capture bytes.
// No helper thread, sound hardware or physical clock accuracy is claimed.
#define _GNU_SOURCE
#include <alsa/asoundlib.h>
#include <alsa/pcm_external.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef struct {snd_pcm_ioplug_t io;int timer;int running;uint64_t base,position;unsigned polls;int fault;} Clock;
static uint64_t now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
static uint64_t position(Clock *c){return c->position+(c->running?(now()-c->base)*c->io.rate/1000000000:0);}
static int timer(Clock *c,int on){struct itimerspec t={0};if(on){t.it_interval.tv_nsec=10000000;t.it_value=t.it_interval;}return timerfd_settime(c->timer,0,&t,0)<0?-errno:0;}
static int start(snd_pcm_ioplug_t *io){Clock*c=io->private_data;if(!c->running){c->base=now();c->running=1;}return timer(c,1);}
static int stop(snd_pcm_ioplug_t *io){Clock*c=io->private_data;c->position=position(c);c->running=0;return timer(c,0);}
static int prepare(snd_pcm_ioplug_t *io){Clock*c=io->private_data;stop(io);c->position=0;return 0;}
static int pause_pcm(snd_pcm_ioplug_t *io,int enabled){return enabled?stop(io):start(io);}
static snd_pcm_sframes_t pointer(snd_pcm_ioplug_t *io){return position(io->private_data)%io->buffer_size;}
static snd_pcm_sframes_t transfer(snd_pcm_ioplug_t *io,const snd_pcm_channel_area_t *areas,snd_pcm_uframes_t off,snd_pcm_uframes_t frames){
    if(io->stream==SND_PCM_STREAM_CAPTURE){unsigned frame=io->channels*snd_pcm_format_physical_width(io->format)/8;memset((char*)areas[0].addr+areas[0].first/8+off*frame,0x5a,frames*frame);}return frames;
}
static int revents(snd_pcm_ioplug_t *io,struct pollfd *fds,unsigned n,unsigned short *events){
    Clock*c=io->private_data;if(n!=1)return -EINVAL;uint64_t ticks;
    if(fds[0].revents&POLLIN){if(read(c->timer,&ticks,sizeof ticks)<0&&errno!=EAGAIN)return -errno;}
    // First tick deliberately has no PCM event; the adapter must rearm it.
    if(++c->polls==1){*events=0;return 0;}
    if(c->polls==2 && c->fault)return -c->fault;
    *events=io->stream==SND_PCM_STREAM_CAPTURE?POLLIN:POLLOUT;return 0;
}
static int close_pcm(snd_pcm_ioplug_t *io){Clock*c=io->private_data;close(c->timer);free(c);return 0;}
static const snd_pcm_ioplug_callback_t callbacks={.start=start,.stop=stop,.pointer=pointer,.transfer=transfer,.prepare=prepare,.pause=pause_pcm,.poll_revents=revents,.close=close_pcm};
SND_PCM_PLUGIN_DEFINE_FUNC(trames_clock){
    (void)root;(void)conf;Clock*c=calloc(1,sizeof *c);if(!c)return -ENOMEM;
    c->timer=timerfd_create(CLOCK_MONOTONIC,TFD_CLOEXEC|TFD_NONBLOCK);if(c->timer<0){free(c);return -errno;}
    c->fault=strstr(name,"removed")?ENODEV:strstr(name,"suspended")?ESTRPIPE:strstr(name,"xrun")?EPIPE:0;
    c->io.version=SND_PCM_IOPLUG_VERSION;c->io.name="Trames test clock";c->io.callback=&callbacks;c->io.private_data=c;c->io.poll_fd=c->timer;c->io.poll_events=POLLIN;c->io.mmap_rw=0;
    int error=snd_pcm_ioplug_create(&c->io,name,stream,mode);if(error<0){close(c->timer);free(c);return error;}
    static const unsigned access[]={SND_PCM_ACCESS_RW_INTERLEAVED};static const unsigned formats[]={SND_PCM_FORMAT_S16_LE,SND_PCM_FORMAT_FLOAT_LE};static const unsigned rates[]={48000};static const unsigned channels[]={2};
    if((error=snd_pcm_ioplug_set_param_list(&c->io,SND_PCM_IOPLUG_HW_ACCESS,1,access))<0||
       (error=snd_pcm_ioplug_set_param_list(&c->io,SND_PCM_IOPLUG_HW_FORMAT,2,formats))<0||
       (error=snd_pcm_ioplug_set_param_list(&c->io,SND_PCM_IOPLUG_HW_RATE,1,rates))<0||
       (error=snd_pcm_ioplug_set_param_list(&c->io,SND_PCM_IOPLUG_HW_CHANNELS,1,channels))<0||
       (error=snd_pcm_ioplug_set_param_minmax(&c->io,SND_PCM_IOPLUG_HW_PERIOD_BYTES,1920,3840))<0||
       (error=snd_pcm_ioplug_set_param_minmax(&c->io,SND_PCM_IOPLUG_HW_BUFFER_BYTES,7680,15360))<0||
       (error=snd_pcm_ioplug_set_param_minmax(&c->io,SND_PCM_IOPLUG_HW_PERIODS,4,4))<0){snd_pcm_ioplug_delete(&c->io);return error;}
    *pcmp=c->io.pcm;return 0;
}
SND_PCM_PLUGIN_SYMBOL(trames_clock);
