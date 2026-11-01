// SPDX-License-Identifier: GPL-3.0-or-later
#import <AudioToolbox/AudioToolbox.h>
#import <AVFoundation/AVFoundation.h>
#import <TargetConditionals.h>
#if TARGET_OS_OSX
#import <CoreAudio/CoreAudio.h>
#endif
#include <mach/mach_time.h>
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <new>
#include <vector>

struct Notification {
    void (*wake)(void *), (*release)(void *);
    void *data;
    bool owned=false;
    ~Notification() { if (owned) release(data); }
};
struct Samples {
    std::vector<uint8_t> ring;
    std::atomic<uint64_t> read{0}, write{0}, underruns{0}, overruns{0};
    std::atomic<bool> active{false};
    uint32_t rate, channels, frameBytes, period, capacity;
    bool capture, floating, wasEmpty=true;
    std::shared_ptr<Notification> notification;
    struct Anchor { uint64_t host=0, pcm=0; uint32_t frames=0; } anchors[256];
    std::mutex clock;
    uint64_t ticks=0, lastPosition=0;
    double framesPerTick;
    Samples(const uint64_t *a, std::shared_ptr<Notification> n):
        rate(a[2]), channels(a[3]), frameBytes(a[3]*(a[4]?4:2)), period(a[5]), capacity(a[6]),
        capture(a[1]), floating(a[4]), notification(std::move(n)) {
        ring.resize(static_cast<size_t>(capacity)*frameBytes);
        mach_timebase_info_data_t timebase{};mach_timebase_info(&timebase);
        framesPerTick=static_cast<double>(rate)*timebase.numer/timebase.denom/1e9;
    }
    void copyOut(uint8_t *dst,uint64_t start,size_t bytes) {
        size_t offset=start%ring.size(),first=std::min(bytes,ring.size()-offset);
        memcpy(dst,ring.data()+offset,first);memcpy(dst+first,ring.data(),bytes-first);
    }
    void copyIn(const uint8_t *src,uint64_t start,size_t bytes) {
        size_t offset=start%ring.size(),first=std::min(bytes,ring.size()-offset);
        memcpy(ring.data()+offset,src,first);memcpy(ring.data(),src+first,bytes-first);
    }
    OSStatus render(BOOL *silence,const AudioTimeStamp *time,UInt32 frames,AudioBufferList *out) {
        for(UInt32 b=0;b<out->mNumberBuffers;++b) memset(out->mBuffers[b].mData,0,out->mBuffers[b].mDataByteSize);
        if(!active.load(std::memory_order_relaxed)){*silence=YES;return noErr;}
        uint64_t r=read.load(std::memory_order_relaxed);
        uint32_t count=std::min<uint64_t>(frames,(write.load(std::memory_order_acquire)-r)/frameBytes);
        bool interleaved=out->mNumberBuffers==1 && channels>1;
        for(UInt32 c=0;c<channels;++c){
            float *dst=static_cast<float *>(out->mBuffers[interleaved?0:c].mData);
            for(UInt32 f=0;f<count;++f){
                size_t offset=(r+static_cast<uint64_t>(f)*frameBytes+c*(floating?4:2))%ring.size();
                float value;
                if(floating)memcpy(&value,ring.data()+offset,4);
                else{int16_t sample;memcpy(&sample,ring.data()+offset,2);value=sample/32768.0f;}
                // A brief fade only at real underrun boundaries prevents a
                // discontinuity against silence. Steady PCM is unchanged.
                if(wasEmpty && f<64)value*=static_cast<float>(f+1)/64;
                if(count<frames && count-f<=64)value*=static_cast<float>(count-f-1)/64;
                dst[interleaved?f*channels+c:f]=value;
            }
        }
        uint64_t host=(time->mFlags&kAudioTimeStampHostTimeValid)?time->mHostTime:mach_absolute_time();
        {
            // Publish only the small multi-field hardware-time mapping. No
            // device call, sample copy, notification or guest memory is locked.
            std::lock_guard<std::mutex> lock(clock);
            anchors[ticks%256]={host,r/frameBytes,count};++ticks;
        }
        read.store(r+static_cast<uint64_t>(count)*frameBytes,std::memory_order_release);
        if(count<frames)underruns.fetch_add(1,std::memory_order_relaxed);
        wasEmpty=count<frames;*silence=count==0;
        notification->wake(notification->data);
        return noErr;
    }
    uint64_t position() {
        uint64_t now=mach_absolute_time(),value=lastPosition;
        {
            std::lock_guard<std::mutex> lock(clock);
            for(uint64_t n=0;n<std::min<uint64_t>(ticks,256);++n){
                const auto &a=anchors[(ticks-1-n)%256];
                if(a.host<=now){value=a.pcm+std::min<uint64_t>(a.frames,static_cast<uint64_t>((now-a.host)*framesPerTick));break;}
            }
        }
        lastPosition=std::max(lastPosition,value);return lastPosition;
    }
};
struct PCM {
    uint64_t args[16];
    std::shared_ptr<Notification> notification;
    std::shared_ptr<Samples> samples;
    AudioQueueRef queue=nullptr;
    AudioQueueBufferRef buffers[3]{};
    AVAudioEngine *engine=nil;
    AVAudioSourceNode *source=nil;
    bool used=false;
};
static void input(void *data,AudioQueueRef,AudioQueueBufferRef buffer,const AudioTimeStamp *,UInt32,const AudioStreamPacketDescription *) {
    auto p=static_cast<PCM *>(data);auto s=p->samples;
    if(!s->active.load(std::memory_order_relaxed))return;
    uint64_t w=s->write.load(std::memory_order_relaxed);
    size_t free=s->ring.size()-(w-s->read.load(std::memory_order_acquire));
    size_t bytes=std::min<size_t>(buffer->mAudioDataByteSize,free);bytes-=bytes%s->frameBytes;
    s->copyIn(static_cast<const uint8_t *>(buffer->mAudioData),w,bytes);
    s->write.store(w+bytes,std::memory_order_release);
    if(bytes<buffer->mAudioDataByteSize)s->overruns.fetch_add(1,std::memory_order_relaxed);
    s->notification->wake(s->notification->data);
    AudioQueueEnqueueBuffer(p->queue,buffer,0,nullptr);
}
static OSStatus create(PCM *p) {
    auto s=p->samples;
    if(s->capture){
        AudioStreamBasicDescription format={static_cast<double>(s->rate),kAudioFormatLinearPCM,
            static_cast<UInt32>((s->floating?kAudioFormatFlagIsFloat:kAudioFormatFlagIsSignedInteger)|kAudioFormatFlagIsPacked),
            s->frameBytes,1,s->frameBytes,s->channels,static_cast<UInt32>(s->floating?32:16),0};
        OSStatus status=AudioQueueNewInput(&format,input,p,nullptr,nullptr,0,&p->queue);
        if(status)return status;
#if TARGET_OS_OSX
        const char *uid=getenv("TRAMES_AUDIO_INPUT_DEVICE");
        if(uid&&*uid){
            CFStringRef device=CFStringCreateWithCString(nullptr,uid,kCFStringEncodingUTF8);
            if(!device)return -50;
            status=AudioQueueSetProperty(p->queue,kAudioQueueProperty_CurrentDevice,&device,sizeof(device));CFRelease(device);
            if(status)return status;
        }
#endif
        for(auto &buffer:p->buffers){status=AudioQueueAllocateBuffer(p->queue,s->period*s->frameBytes,&buffer);if(status)return status;}
        return noErr;
    }
    p->engine=[[AVAudioEngine alloc] init];
#if TARGET_OS_OSX
    const char *uid=getenv("TRAMES_AUDIO_OUTPUT_DEVICE");
    if(uid&&*uid){
        CFStringRef text=CFStringCreateWithCString(nullptr,uid,kCFStringEncodingUTF8);
        AudioDeviceID device=kAudioObjectUnknown;AudioValueTranslation translation={&text,sizeof(text),&device,sizeof(device)};
        AudioObjectPropertyAddress address={kAudioHardwarePropertyDeviceForUID,kAudioObjectPropertyScopeGlobal,kAudioObjectPropertyElementMain};UInt32 size=sizeof(translation);
        OSStatus status=AudioObjectGetPropertyData(kAudioObjectSystemObject,&address,0,nullptr,&size,&translation);if(text)CFRelease(text);
        if(status||device==kAudioObjectUnknown)return -50;
        status=AudioUnitSetProperty(p->engine.outputNode.audioUnit,kAudioOutputUnitProperty_CurrentDevice,kAudioUnitScope_Global,0,&device,sizeof(device));if(status)return status;
    }
#endif
    AVAudioFormat *format=[[AVAudioFormat alloc] initStandardFormatWithSampleRate:s->rate channels:s->channels];
    // The block owns Samples, including the notification lease. A late render
    // can only see its old inactive allocation after prepare/dispose; it cannot
    // touch reset state or a freed Rust callback.
    p->source=[[AVAudioSourceNode alloc] initWithFormat:format renderBlock:^OSStatus(BOOL *silent,const AudioTimeStamp *stamp,AVAudioFrameCount count,AudioBufferList *buffers){return s->render(silent,stamp,count,buffers);}];
    [p->engine attachNode:p->source];
#if __MAC_OS_X_VERSION_MAX_ALLOWED >= 270000 || __IPHONE_OS_VERSION_MAX_ALLOWED >= 270000
    if(@available(macOS 27.0,iOS 27.0,tvOS 27.0,watchOS 27.0,*)) {
        NSError *error=nil;
        if(![p->engine connect:p->source to:p->engine.mainMixerNode format:format error:&error])return static_cast<OSStatus>(error.code?:-1);
    } else
#endif
    {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        [p->engine connect:p->source to:p->engine.mainMixerNode format:format];
#pragma clang diagnostic pop
    }
    [p->engine prepare];return noErr;
}
static void stop(PCM *p) {
    p->samples->active.store(false,std::memory_order_relaxed);
    if(p->queue){AudioQueueDispose(p->queue,true);p->queue=nullptr;}
    if(p->engine){[p->engine stop];if(p->source)[p->engine detachNode:p->source];p->source=nil;p->engine=nil;}
}
extern "C" void *trames_audio_new(const uint64_t *a,void (*wake)(void *),void (*release)(void *),void *data,int64_t *error) {
    if(a[1]){
        AVAuthorizationStatus permission=[AVCaptureDevice authorizationStatusForMediaType:AVMediaTypeAudio];
        if(permission==AVAuthorizationStatusNotDetermined){
            [AVCaptureDevice requestAccessForMediaType:AVMediaTypeAudio completionHandler:^(BOOL allowed){(void)allowed;}];*error=-13;return nullptr;
        }
        if(permission!=AVAuthorizationStatusAuthorized){*error=-13;return nullptr;}
    }
    PCM *p=nullptr;
    try{
        p=new PCM;memcpy(p->args,a,sizeof(p->args));
        p->notification=std::make_shared<Notification>();p->notification->wake=wake;p->notification->release=release;p->notification->data=data;
        p->samples=std::make_shared<Samples>(a,p->notification);
        OSStatus status=create(p);
        if(status){fprintf(stderr,"trames audio: create failed (OSStatus %d)\n",static_cast<int>(status));stop(p);delete p;*error=-5;return nullptr;}
    }catch(const std::bad_alloc &){if(p){if(p->samples)stop(p);delete p;}*error=-12;return nullptr;}
    p->notification->owned=true;p->notification->wake(data);return p;
}
extern "C" void trames_audio_free(void *stream){auto p=static_cast<PCM *>(stream);stop(p);delete p;}
extern "C" int64_t trames_audio_control(void *stream,uint64_t op) {
    auto p=static_cast<PCM *>(stream);auto s=p->samples;OSStatus status=noErr;
    if(op==3){
        if(!s->active.exchange(true,std::memory_order_relaxed)&&s->capture){for(auto buffer:p->buffers){status=AudioQueueEnqueueBuffer(p->queue,buffer,0,nullptr);if(status)break;}}
        p->used=true;
        if(!status){
            if(s->capture)status=AudioQueueStart(p->queue,nullptr);
            else{NSError *error=nil;if(![p->engine startAndReturnError:&error])status=static_cast<OSStatus>(error.code?:-1);}
        }
        if(status)s->active.store(false,std::memory_order_relaxed);
    }else if(op==8){if(s->capture)status=AudioQueuePause(p->queue);else[p->engine pause];}
    else if(op==4){s->active.store(false,std::memory_order_relaxed);if(s->capture)status=AudioQueueStop(p->queue,true);else[p->engine stop];}
    else if(op==5){
        if(p->used||s->write.load(std::memory_order_relaxed)){
            stop(p);
            try{p->samples=std::make_shared<Samples>(p->args,p->notification);status=create(p);p->used=false;}
            catch(const std::bad_alloc &){return -12;}
        }
    }else return -22;
    if(status)fprintf(stderr,"trames audio: operation %llu failed (OSStatus %d)\n",static_cast<unsigned long long>(op),static_cast<int>(status));
    return status?-5:0;
}
extern "C" int64_t trames_audio_transfer(void *stream,uint8_t *bytes,size_t len) {
    auto s=static_cast<PCM *>(stream)->samples;if(!len)return 0;
    if(s->capture){uint64_t r=s->read.load(std::memory_order_relaxed);len=std::min<uint64_t>(len,s->write.load(std::memory_order_acquire)-r);len-=len%s->frameBytes;s->copyOut(bytes,r,len);s->read.store(r+len,std::memory_order_release);}
    else{uint64_t w=s->write.load(std::memory_order_relaxed);len=std::min<uint64_t>(len,s->ring.size()-(w-s->read.load(std::memory_order_acquire)));len-=len%s->frameBytes;s->copyIn(bytes,w,len);s->write.store(w+len,std::memory_order_release);}
    return len?static_cast<int64_t>(len):-11;
}
extern "C" void trames_audio_status(void *stream,uint64_t *out) {
    auto s=static_cast<PCM *>(stream)->samples;
    uint64_t r=s->read.load(std::memory_order_acquire),w=s->write.load(std::memory_order_acquire);
    uint64_t position=s->capture?w/s->frameBytes:s->position();
    out[0]=position;out[1]=s->capture?(w-r)/s->frameBytes:w/s->frameBytes-position;
    out[2]=s->capture?(w-r)/s->frameBytes:s->capacity-(w-r)/s->frameBytes;
    out[3]=s->underruns.load(std::memory_order_relaxed);out[4]=s->overruns.load(std::memory_order_relaxed);
    out[5]=s->rate;out[6]=s->channels;out[7]=s->active.load(std::memory_order_relaxed);
}
