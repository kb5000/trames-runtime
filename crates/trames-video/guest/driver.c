// SPDX-License-Identifier: GPL-3.0-or-later
// Standard libva driver. Native objects are opaque IDs, never host pointers.
#define _GNU_SOURCE
#include <va/va_backend.h>
#include <va/va_drmcommon.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include "h264.h"

struct native_result {uint64_t value,fallback;};
extern struct native_result trames_video_call(uint64_t,const uint64_t*,size_t);
static int64_t call(unsigned op,const uint64_t args[16]) {
    int64_t r=(int64_t)trames_video_call(op,args,128).value;
    if(r<0 && r!=-EAGAIN && getenv("TRAMES_VIDEO_TRACE"))fprintf(stderr,"Trames video op=%u result=%lld\n",op,(long long)r);
    return r;
}
#define PTR(p) ((uint64_t)(uintptr_t)(p))
#define CALL(op,...) call(op,(uint64_t[16]){__VA_ARGS__})
enum Kind {CONFIG=1,SURFACE,CONTEXT,BUFFER,IMAGE};
typedef struct {enum Kind kind;void* object;uint32_t next_free;} Entry;
typedef struct {pthread_mutex_t lock;Entry* entries;uint32_t count,capacity,free_head;} Driver;
typedef struct {VAProfile profile;} Config;
typedef struct {uint64_t key;int fd;unsigned width,height;} Surface;
typedef struct {VABufferType type;unsigned size,count;size_t capacity;uint8_t* data;} Buffer;
typedef struct {VAImage value;} Image;
typedef struct {
    uint64_t key;VAProfile profile;unsigned width,height;VASurfaceID target;
    VAPictureParameterBufferH264 picture;VAIQMatrixBufferH264 matrix;
    int has_picture,has_matrix;
    VASliceParameterBufferH264* slices;size_t slice_count;
    uint8_t* bytes;size_t length,capacity;TramesH264 h264;
} Context;
static Driver* driver(VADriverContextP ctx){return ctx->pDriverData;}
static uint32_t add(VADriverContextP ctx,enum Kind kind,void* object) {
    Driver* d=driver(ctx);pthread_mutex_lock(&d->lock);
    uint32_t id=d->free_head!=VA_INVALID_ID?d->free_head:d->count;
    if(id==UINT32_MAX){pthread_mutex_unlock(&d->lock);return VA_INVALID_ID;}
    if(id==d->capacity) {
        uint32_t capacity=d->capacity?d->capacity*2:64;
        if(capacity<=id){pthread_mutex_unlock(&d->lock);return VA_INVALID_ID;}
        Entry* entries=realloc(d->entries,(size_t)capacity*sizeof(*entries));
        if(!entries){pthread_mutex_unlock(&d->lock);return VA_INVALID_ID;}
        d->entries=entries;d->capacity=capacity;
    }
    if(d->free_head!=VA_INVALID_ID)d->free_head=d->entries[id].next_free;else d->count++;
    d->entries[id]=(Entry){kind,object,VA_INVALID_ID};
    pthread_mutex_unlock(&d->lock);return id;
}
static void* get(VADriverContextP ctx,uint32_t id,enum Kind kind) {
    Driver* d=driver(ctx);pthread_mutex_lock(&d->lock);
    void* p=id<d->count && d->entries[id].kind==kind?d->entries[id].object:NULL;
    pthread_mutex_unlock(&d->lock);return p;
}
static void forget(VADriverContextP ctx,uint32_t id) {
    Driver* d=driver(ctx);pthread_mutex_lock(&d->lock);
    if(id<d->count && d->entries[id].kind){d->entries[id]=(Entry){0,NULL,d->free_head};d->free_head=id;}
    pthread_mutex_unlock(&d->lock);
}
static VAStatus failed(int64_t r) {
    if(r>=0)return VA_STATUS_SUCCESS;
    if(r==-ENOMEM)return VA_STATUS_ERROR_ALLOCATION_FAILED;
    if(r==-EINVAL)return VA_STATUS_ERROR_INVALID_PARAMETER;
    if(r==-ENOENT)return VA_STATUS_ERROR_INVALID_SURFACE;
    if(r==-ENOSYS || r==-ENOTSUP)return VA_STATUS_ERROR_UNIMPLEMENTED;
    return VA_STATUS_ERROR_DECODING_ERROR;
}
static int profile_ok(VAProfile p){return p==VAProfileH264ConstrainedBaseline || p==VAProfileH264Main || p==VAProfileH264High;}
static VAStatus query_profiles(VADriverContextP ctx,VAProfile* out,int* count) {
    (void)ctx;
    if(!(CALL(0,0)&1)){*count=0;return VA_STATUS_SUCCESS;}
    out[0]=VAProfileH264ConstrainedBaseline;out[1]=VAProfileH264Main;out[2]=VAProfileH264High;*count=3;return VA_STATUS_SUCCESS;
}
static VAStatus query_entrypoints(VADriverContextP ctx,VAProfile profile,VAEntrypoint* out,int* count) {
    (void)ctx;*count=0;if(!profile_ok(profile))return VA_STATUS_ERROR_UNSUPPORTED_PROFILE;
    out[0]=VAEntrypointVLD;*count=1;return VA_STATUS_SUCCESS;
}
static VAStatus config_attributes(VADriverContextP ctx,VAProfile profile,VAEntrypoint entry,VAConfigAttrib* attributes,int count) {
    (void)ctx;if(!profile_ok(profile))return VA_STATUS_ERROR_UNSUPPORTED_PROFILE;
    if(entry!=VAEntrypointVLD)return VA_STATUS_ERROR_UNSUPPORTED_ENTRYPOINT;
    for(int i=0;i<count;i++)attributes[i].value=attributes[i].type==VAConfigAttribRTFormat?VA_RT_FORMAT_YUV420:VA_ATTRIB_NOT_SUPPORTED;
    return VA_STATUS_SUCCESS;
}
static VAStatus create_config(VADriverContextP ctx,VAProfile profile,VAEntrypoint entry,VAConfigAttrib* attributes,int count,VAConfigID* id) {
    if(!profile_ok(profile))return VA_STATUS_ERROR_UNSUPPORTED_PROFILE;
    if(entry!=VAEntrypointVLD)return VA_STATUS_ERROR_UNSUPPORTED_ENTRYPOINT;
    for(int i=0;i<count;i++)if(attributes[i].type!=VAConfigAttribRTFormat || attributes[i].value!=VA_RT_FORMAT_YUV420)return VA_STATUS_ERROR_UNSUPPORTED_RT_FORMAT;
    Config* c=malloc(sizeof(*c));if(!c)return VA_STATUS_ERROR_ALLOCATION_FAILED;c->profile=profile;
    *id=add(ctx,CONFIG,c);if(*id==VA_INVALID_ID){free(c);return VA_STATUS_ERROR_ALLOCATION_FAILED;}return VA_STATUS_SUCCESS;
}
static VAStatus destroy_config(VADriverContextP ctx,VAConfigID id) {
    Config* c=get(ctx,id,CONFIG);if(!c)return VA_STATUS_ERROR_INVALID_CONFIG;forget(ctx,id);free(c);return VA_STATUS_SUCCESS;
}
static VAStatus query_config(VADriverContextP ctx,VAConfigID id,VAProfile* profile,VAEntrypoint* entry,VAConfigAttrib* attributes,int* count) {
    Config* c=get(ctx,id,CONFIG);if(!c)return VA_STATUS_ERROR_INVALID_CONFIG;
    *profile=c->profile;*entry=VAEntrypointVLD;attributes[0]=(VAConfigAttrib){VAConfigAttribRTFormat,VA_RT_FORMAT_YUV420};*count=1;return VA_STATUS_SUCCESS;
}
static VAStatus query_surface_attributes(VADriverContextP ctx,VAConfigID id,VASurfaceAttrib* attributes,unsigned* count) {
    if(!get(ctx,id,CONFIG))return VA_STATUS_ERROR_INVALID_CONFIG;
    const unsigned total=2;
    if(!attributes){*count=total;return VA_STATUS_SUCCESS;}
    if(*count<total){*count=total;return VA_STATUS_ERROR_MAX_NUM_EXCEEDED;}
    attributes[0]=(VASurfaceAttrib){.type=VASurfaceAttribPixelFormat,.flags=VA_SURFACE_ATTRIB_GETTABLE|VA_SURFACE_ATTRIB_SETTABLE,.value={.type=VAGenericValueTypeInteger,.value.i=VA_FOURCC_NV12}};
    attributes[1]=(VASurfaceAttrib){.type=VASurfaceAttribMemoryType,.flags=VA_SURFACE_ATTRIB_GETTABLE|VA_SURFACE_ATTRIB_SETTABLE,.value={.type=VAGenericValueTypeInteger,.value.i=VA_SURFACE_ATTRIB_MEM_TYPE_VA}};
    *count=total;return VA_STATUS_SUCCESS;
}
static VAStatus destroy_surfaces(VADriverContextP ctx,VASurfaceID* ids,int count) {
    for(int i=0;i<count;i++){Surface* s=get(ctx,ids[i],SURFACE);if(!s)return VA_STATUS_ERROR_INVALID_SURFACE;CALL(4,s->key);close(s->fd);forget(ctx,ids[i]);free(s);}return VA_STATUS_SUCCESS;
}
static VAStatus create_surfaces2(VADriverContextP ctx,unsigned format,unsigned width,unsigned height,VASurfaceID* ids,unsigned count,VASurfaceAttrib* attributes,unsigned attribute_count) {
    if(format!=VA_RT_FORMAT_YUV420)return VA_STATUS_ERROR_UNSUPPORTED_RT_FORMAT;
    if(!width || !height || width%2 || height%2)return VA_STATUS_ERROR_INVALID_PARAMETER;
    for(unsigned i=0;i<attribute_count;i++) {
        if(attributes[i].type==VASurfaceAttribPixelFormat && attributes[i].value.value.i!=VA_FOURCC_NV12)return VA_STATUS_ERROR_UNSUPPORTED_RT_FORMAT;
        if(attributes[i].type==VASurfaceAttribMemoryType && attributes[i].value.value.i!=VA_SURFACE_ATTRIB_MEM_TYPE_VA)return VA_STATUS_ERROR_UNSUPPORTED_MEMORY_TYPE;
        if(attributes[i].type==VASurfaceAttribExternalBufferDescriptor)return VA_STATUS_ERROR_UNSUPPORTED_MEMORY_TYPE;
    }
    for(unsigned i=0;i<count;i++) {
        Surface* s=calloc(1,sizeof(*s));if(!s){destroy_surfaces(ctx,ids,i);return VA_STATUS_ERROR_ALLOCATION_FAILED;}
        s->fd=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);s->width=width;s->height=height;
        int64_t key=s->fd<0?-ENOMEM:CALL(3,s->fd,width,height);
        if(key<0){if(s->fd>=0)close(s->fd);free(s);destroy_surfaces(ctx,ids,i);return failed(key);}
        s->key=key;ids[i]=add(ctx,SURFACE,s);
        if(ids[i]==VA_INVALID_ID){CALL(4,s->key);close(s->fd);free(s);destroy_surfaces(ctx,ids,i);return VA_STATUS_ERROR_ALLOCATION_FAILED;}
    }
    return VA_STATUS_SUCCESS;
}
static VAStatus create_surfaces(VADriverContextP ctx,int width,int height,int format,int count,VASurfaceID* ids) {
    if(width<=0 || height<=0 || count<0)return VA_STATUS_ERROR_INVALID_PARAMETER;
    return create_surfaces2(ctx,format,width,height,ids,count,NULL,0);
}
static VAStatus create_context(VADriverContextP ctx,VAConfigID config,int width,int height,int flags,VASurfaceID* targets,int count,VAContextID* id) {
    (void)flags;(void)targets;(void)count;Config* c=get(ctx,config,CONFIG);if(!c)return VA_STATUS_ERROR_INVALID_CONFIG;
    if(width<=0 || height<=0 || width%2 || height%2)return VA_STATUS_ERROR_INVALID_PARAMETER;
    Context* context=calloc(1,sizeof(*context));if(!context)return VA_STATUS_ERROR_ALLOCATION_FAILED;
    int64_t key=CALL(1,width,height);if(key<0){free(context);return failed(key);}
    context->key=key;context->profile=c->profile;context->width=width;context->height=height;context->target=VA_INVALID_ID;
    *id=add(ctx,CONTEXT,context);if(*id==VA_INVALID_ID){CALL(2,key);free(context);return VA_STATUS_ERROR_ALLOCATION_FAILED;}return VA_STATUS_SUCCESS;
}
static VAStatus destroy_context(VADriverContextP ctx,VAContextID id) {
    Context* c=get(ctx,id,CONTEXT);if(!c)return VA_STATUS_ERROR_INVALID_CONTEXT;
    CALL(2,c->key);forget(ctx,id);free(c->slices);free(c->bytes);free(c);return VA_STATUS_SUCCESS;
}
static VAStatus create_buffer(VADriverContextP ctx,VAContextID context,VABufferType type,unsigned size,unsigned count,void* data,VABufferID* id) {
    (void)context;
    if(count && size>SIZE_MAX/count)return VA_STATUS_ERROR_ALLOCATION_FAILED;
    Buffer* b=calloc(1,sizeof(*b));if(!b)return VA_STATUS_ERROR_ALLOCATION_FAILED;
    b->capacity=(size_t)size*count;b->data=calloc(b->capacity?b->capacity:1,1);
    if(!b->data){free(b);return VA_STATUS_ERROR_ALLOCATION_FAILED;}if(data)memcpy(b->data,data,b->capacity);
    b->type=type;b->size=size;b->count=count;*id=add(ctx,BUFFER,b);
    if(*id==VA_INVALID_ID){free(b->data);free(b);return VA_STATUS_ERROR_ALLOCATION_FAILED;}return VA_STATUS_SUCCESS;
}
static VAStatus buffer_elements(VADriverContextP ctx,VABufferID id,unsigned count) {
    Buffer* b=get(ctx,id,BUFFER);if(!b)return VA_STATUS_ERROR_INVALID_BUFFER;
    if(count && b->size>b->capacity/count)return VA_STATUS_ERROR_INVALID_PARAMETER;b->count=count;return VA_STATUS_SUCCESS;
}
static VAStatus map_buffer(VADriverContextP ctx,VABufferID id,void** out) {
    Buffer* b=get(ctx,id,BUFFER);if(!b)return VA_STATUS_ERROR_INVALID_BUFFER;*out=b->data;return VA_STATUS_SUCCESS;
}
static VAStatus unmap_buffer(VADriverContextP ctx,VABufferID id) {return get(ctx,id,BUFFER)?VA_STATUS_SUCCESS:VA_STATUS_ERROR_INVALID_BUFFER;}
static VAStatus destroy_buffer(VADriverContextP ctx,VABufferID id) {
    Buffer* b=get(ctx,id,BUFFER);if(!b)return VA_STATUS_ERROR_INVALID_BUFFER;forget(ctx,id);free(b->data);free(b);return VA_STATUS_SUCCESS;
}
static VAStatus sync_surface(VADriverContextP ctx,VASurfaceID id) {
    Surface* s=get(ctx,id,SURFACE);if(!s)return VA_STATUS_ERROR_INVALID_SURFACE;
    for(;;) {
        int64_t r=CALL(6,s->key);if(r!=-EAGAIN)return failed(r);
        struct pollfd p={s->fd,POLLIN,0};
        if(poll(&p,1,-1)<0){if(errno==EINTR)continue;return VA_STATUS_ERROR_OPERATION_FAILED;}
        if(p.revents&(POLLERR|POLLNVAL|POLLHUP))return VA_STATUS_ERROR_OPERATION_FAILED;
    }
}
static VAStatus surface_status(VADriverContextP ctx,VASurfaceID id,VASurfaceStatus* status) {
    Surface* s=get(ctx,id,SURFACE);if(!s)return VA_STATUS_ERROR_INVALID_SURFACE;
    int64_t r=CALL(6,s->key);*status=r==-EAGAIN?VASurfaceRendering:VASurfaceReady;return r==-EAGAIN?VA_STATUS_SUCCESS:failed(r);
}
static VAStatus surface_error(VADriverContextP ctx,VASurfaceID id,VAStatus error,void** info) {
    (void)error;*info=NULL;return get(ctx,id,SURFACE)?VA_STATUS_SUCCESS:VA_STATUS_ERROR_INVALID_SURFACE;
}
static VAStatus begin_picture(VADriverContextP ctx,VAContextID id,VASurfaceID target) {
    Context* c=get(ctx,id,CONTEXT);Surface* s=get(ctx,target,SURFACE);
    if(!c)return VA_STATUS_ERROR_INVALID_CONTEXT;if(!s)return VA_STATUS_ERROR_INVALID_SURFACE;
    VAStatus status=sync_surface(ctx,target);if(status)return status;
    uint64_t previous;while(read(s->fd,&previous,sizeof(previous))<0 && errno==EINTR){}
    c->target=target;c->length=0;c->slice_count=0;c->has_picture=c->has_matrix=0;return VA_STATUS_SUCCESS;
}
static VAStatus render_picture(VADriverContextP ctx,VAContextID id,VABufferID* ids,int count) {
    Context* c=get(ctx,id,CONTEXT);if(!c)return VA_STATUS_ERROR_INVALID_CONTEXT;
    if(c->target==VA_INVALID_ID)return VA_STATUS_ERROR_INVALID_SURFACE;
    for(int i=0;i<count;i++) {
        Buffer* b=get(ctx,ids[i],BUFFER);if(!b)return VA_STATUS_ERROR_INVALID_BUFFER;
        size_t size=(size_t)b->size*b->count;
        switch(b->type) {
        case VAPictureParameterBufferType:
            if(size<sizeof(c->picture))return VA_STATUS_ERROR_INVALID_PARAMETER;
            memcpy(&c->picture,b->data,sizeof(c->picture));c->has_picture=1;break;
        case VAIQMatrixBufferType:
            if(size<sizeof(c->matrix))return VA_STATUS_ERROR_INVALID_PARAMETER;
            memcpy(&c->matrix,b->data,sizeof(c->matrix));c->has_matrix=1;break;
        case VASliceParameterBufferType: {
            if(size%sizeof(*c->slices))return VA_STATUS_ERROR_INVALID_PARAMETER;
            if(c->slice_count)return VA_STATUS_ERROR_INVALID_PARAMETER;
            VASliceParameterBufferH264* slices=realloc(c->slices,size);
            if(!slices && size)return VA_STATUS_ERROR_ALLOCATION_FAILED;c->slices=slices;
            memcpy(c->slices,b->data,size);c->slice_count=size/sizeof(*c->slices);break;
        }
        case VASliceDataBufferType:
            if(!c->has_picture || !c->slice_count)return VA_STATUS_ERROR_INVALID_PARAMETER;
            for(size_t j=0;j<c->slice_count;j++) {
                VASliceParameterBufferH264* s=&c->slices[j];size_t n=s->slice_data_size,offset=s->slice_data_offset;
                if(s->slice_data_flag!=VA_SLICE_DATA_FLAG_ALL || offset>size || n>size-offset || n>UINT32_MAX || !n)return VA_STATUS_ERROR_INVALID_PARAMETER;
                const uint8_t* bytes=b->data+offset;
                if(trames_h264_slice(&c->h264,&c->picture,s,bytes,n))return VA_STATUS_ERROR_UNSUPPORTED_PROFILE;
                if(c->length>SIZE_MAX-4-n)return VA_STATUS_ERROR_ALLOCATION_FAILED;
                size_t need=c->length+4+n;
                if(need>c->capacity) {
                    uint8_t* data=realloc(c->bytes,need);if(!data)return VA_STATUS_ERROR_ALLOCATION_FAILED;
                    c->bytes=data;c->capacity=need;
                }
                c->bytes[c->length++]=n>>24;c->bytes[c->length++]=n>>16;c->bytes[c->length++]=n>>8;c->bytes[c->length++]=n;
                memcpy(c->bytes+c->length,bytes,n);c->length+=n;
            }
            c->slice_count=0;break;
        default:return VA_STATUS_ERROR_UNSUPPORTED_BUFFERTYPE;
        }
    }
    return VA_STATUS_SUCCESS;
}
static VAStatus end_picture(VADriverContextP ctx,VAContextID id) {
    Context* c=get(ctx,id,CONTEXT);if(!c)return VA_STATUS_ERROR_INVALID_CONTEXT;
    Surface* s=get(ctx,c->target,SURFACE);if(!s)return VA_STATUS_ERROR_INVALID_SURFACE;
    if(!c->has_picture || !c->has_matrix || !c->length || c->slice_count)return VA_STATUS_ERROR_INVALID_PARAMETER;
    if(trames_h264_parameters(&c->h264,c->profile,c->width,c->height,&c->picture,&c->matrix))return VA_STATUS_ERROR_UNSUPPORTED_PROFILE;
    int64_t r=CALL(5,c->key,s->key,PTR(c->h264.sps),c->h264.sps_size,PTR(c->h264.pps),c->h264.pps_size,PTR(c->bytes),c->length);
    c->target=VA_INVALID_ID;return failed(r);
}
static VAImageFormat nv12(void) {return (VAImageFormat){.fourcc=VA_FOURCC_NV12,.byte_order=VA_LSB_FIRST,.bits_per_pixel=12};}
static VAStatus query_images(VADriverContextP ctx,VAImageFormat* formats,int* count) {(void)ctx;formats[0]=nv12();*count=1;return VA_STATUS_SUCCESS;}
static VAStatus create_image(VADriverContextP ctx,VAImageFormat* format,int width,int height,VAImage* out) {
    if(format->fourcc!=VA_FOURCC_NV12)return VA_STATUS_ERROR_UNSUPPORTED_RT_FORMAT;
    if(width<=0 || height<=0 || width>UINT16_MAX || height>UINT16_MAX || width%2 || height%2 || (uint64_t)width*height*3/2>UINT32_MAX)return VA_STATUS_ERROR_INVALID_PARAMETER;
    Image* image=calloc(1,sizeof(*image));if(!image)return VA_STATUS_ERROR_ALLOCATION_FAILED;
    VABufferID buffer;unsigned size=(unsigned)width*height*3/2;
    VAStatus status=create_buffer(ctx,VA_INVALID_ID,VAImageBufferType,size,1,NULL,&buffer);
    if(status){free(image);return status;}
    *out=(VAImage){.format=nv12(),.buf=buffer,.width=width,.height=height,.data_size=size,.num_planes=2,.pitches={(unsigned)width,(unsigned)width,0},.offsets={0,(unsigned)width*height,0}};
    out->image_id=add(ctx,IMAGE,image);
    if(out->image_id==VA_INVALID_ID){destroy_buffer(ctx,buffer);free(image);return VA_STATUS_ERROR_ALLOCATION_FAILED;}
    image->value=*out;return VA_STATUS_SUCCESS;
}
static VAStatus destroy_image(VADriverContextP ctx,VAImageID id) {
    Image* image=get(ctx,id,IMAGE);if(!image)return VA_STATUS_ERROR_INVALID_IMAGE;
    destroy_buffer(ctx,image->value.buf);forget(ctx,id);free(image);return VA_STATUS_SUCCESS;
}
static VAStatus derive_image(VADriverContextP ctx,VASurfaceID surface,VAImage* image) {(void)ctx;(void)surface;(void)image;return VA_STATUS_ERROR_OPERATION_FAILED;}
static VAStatus get_image(VADriverContextP ctx,VASurfaceID surface,int x,int y,unsigned width,unsigned height,VAImageID id) {
    Surface* s=get(ctx,surface,SURFACE);Image* image=get(ctx,id,IMAGE);if(!s)return VA_STATUS_ERROR_INVALID_SURFACE;if(!image)return VA_STATUS_ERROR_INVALID_IMAGE;
    if(x || y || width!=image->value.width || height!=image->value.height)return VA_STATUS_ERROR_INVALID_PARAMETER;
    VAStatus status=sync_surface(ctx,surface);if(status)return status;
    Buffer* buffer=get(ctx,image->value.buf,BUFFER);if(!buffer)return VA_STATUS_ERROR_INVALID_BUFFER;
    // Native dimensions may contain coded padding. Crop into the requested image.
    if((uint64_t)s->width*s->height*3/2>SIZE_MAX)return VA_STATUS_ERROR_ALLOCATION_FAILED;
    size_t capacity=(size_t)s->width*s->height*3/2;uint8_t* bytes=malloc(capacity);if(!bytes)return VA_STATUS_ERROR_ALLOCATION_FAILED;
    uint64_t actual[2]={0};int64_t r=CALL(7,s->key,PTR(bytes),capacity,PTR(actual));
    if(r>=0) {
        if(actual[0]<width || actual[1]<height || actual[0]>s->width || actual[1]>s->height)r=-EINVAL;
        else {
            for(unsigned row=0;row<height;row++)memcpy(buffer->data+(size_t)row*width,bytes+(size_t)row*actual[0],width);
            for(unsigned row=0;row<height/2;row++)memcpy(buffer->data+(size_t)width*height+(size_t)row*width,bytes+actual[0]*actual[1]+row*actual[0],width);
        }
    }
    free(bytes);return failed(r);
}
static VAStatus buffer_info(VADriverContextP ctx,VABufferID id,VABufferType* type,unsigned* size,unsigned* count) {
    Buffer* b=get(ctx,id,BUFFER);if(!b)return VA_STATUS_ERROR_INVALID_BUFFER;*type=b->type;*size=b->size;*count=b->count;return VA_STATUS_SUCCESS;
}
static VAStatus export_surface(VADriverContextP ctx,VASurfaceID id,uint32_t memory_type,uint32_t flags,void* descriptor) {
    if(memory_type!=VA_SURFACE_ATTRIB_MEM_TYPE_DRM_PRIME_2 || (flags&3)!=VA_EXPORT_SURFACE_READ_ONLY)
        return VA_STATUS_ERROR_UNSUPPORTED_MEMORY_TYPE;
    Surface* surface=get(ctx,id,SURFACE);if(!surface)return VA_STATUS_ERROR_INVALID_SURFACE;
    VAStatus status=sync_surface(ctx,id);if(status)return status;
    uint64_t frame[8];int64_t r=CALL(8,surface->key,PTR(frame));if(r<0)return failed(r);
    if(frame[6]>UINT32_MAX || frame[7]>UINT32_MAX || frame[4]>UINT32_MAX || frame[5]>UINT32_MAX) {
        close((int)frame[2]);close((int)frame[3]);return VA_STATUS_ERROR_UNSUPPORTED_MEMORY_TYPE;
    }
    VADRMPRIMESurfaceDescriptor* d=descriptor;memset(d,0,sizeof(*d));
    d->fourcc=VA_FOURCC_NV12;d->width=frame[0];d->height=frame[1];d->num_objects=2;
    for(unsigned i=0;i<2;i++) {
        d->objects[i].fd=frame[2+i];d->objects[i].size=frame[6+i];
        // Ordinary uncompressed CVPixelBuffer planes are row-linear image
        // views, with the actual native byte pitch. Compressed CV formats are
        // not accepted by the shared image backend.
        d->objects[i].drm_format_modifier=0;
    }
    if(flags&VA_EXPORT_SURFACE_SEPARATE_LAYERS) {
        d->num_layers=2;
        for(unsigned i=0;i<2;i++) {
            d->layers[i].drm_format=i?VA_FOURCC('G','R','8','8'):VA_FOURCC('R','8',' ',' ');
            d->layers[i].num_planes=1;d->layers[i].object_index[0]=i;d->layers[i].pitch[0]=frame[4+i];
        }
    } else {
        d->num_layers=1;d->layers[0].drm_format=VA_FOURCC_NV12;d->layers[0].num_planes=2;
        for(unsigned i=0;i<2;i++) {d->layers[0].object_index[i]=i;d->layers[0].pitch[i]=frame[4+i];}
    }
    return VA_STATUS_SUCCESS;
}
// libva requires these legacy vtable slots even for a decode-only driver.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#define UNSUPPORTED(name,args) static VAStatus name args {return VA_STATUS_ERROR_UNIMPLEMENTED;}
UNSUPPORTED(palette,(VADriverContextP c,VAImageID i,unsigned char* p))
UNSUPPORTED(put_image,(VADriverContextP c,VASurfaceID s,VAImageID i,int sx,int sy,unsigned sw,unsigned sh,int dx,int dy,unsigned dw,unsigned dh))
static VAStatus subpictures(VADriverContextP c,VAImageFormat* f,unsigned* flags,unsigned* count){*count=0;return VA_STATUS_SUCCESS;}
UNSUPPORTED(create_subpicture,(VADriverContextP c,VAImageID i,VASubpictureID* s))
UNSUPPORTED(destroy_subpicture,(VADriverContextP c,VASubpictureID s))
UNSUPPORTED(subpicture_image,(VADriverContextP c,VASubpictureID s,VAImageID i))
UNSUPPORTED(subpicture_chroma,(VADriverContextP c,VASubpictureID s,unsigned a,unsigned b,unsigned m))
UNSUPPORTED(subpicture_alpha,(VADriverContextP c,VASubpictureID s,float a))
UNSUPPORTED(associate_subpicture,(VADriverContextP c,VASubpictureID s,VASurfaceID* t,int n,short sx,short sy,unsigned short sw,unsigned short sh,short dx,short dy,unsigned short dw,unsigned short dh,unsigned flags))
UNSUPPORTED(deassociate_subpicture,(VADriverContextP c,VASubpictureID s,VASurfaceID* t,int n))
static VAStatus display_attributes(VADriverContextP c,VADisplayAttribute* a,int* count){*count=0;return VA_STATUS_SUCCESS;}
UNSUPPORTED(get_display_attributes,(VADriverContextP c,VADisplayAttribute* a,int n))
UNSUPPORTED(set_display_attributes,(VADriverContextP c,VADisplayAttribute* a,int n))
#undef UNSUPPORTED
#pragma GCC diagnostic pop
static VAStatus terminate(VADriverContextP ctx) {
    Driver* d=driver(ctx);
    // Context teardown completes callbacks before logical surface/event release.
    for(uint32_t i=0;i<d->count;i++)if(d->entries[i].kind==CONTEXT)destroy_context(ctx,i);
    for(uint32_t i=0;i<d->count;i++)switch(d->entries[i].kind) {
        case CONFIG:destroy_config(ctx,i);break;case SURFACE:destroy_surfaces(ctx,&i,1);break;
        case IMAGE:destroy_image(ctx,i);break;case BUFFER:destroy_buffer(ctx,i);break;default:break;
    }
    free(d->entries);pthread_mutex_destroy(&d->lock);free(d);ctx->pDriverData=NULL;return VA_STATUS_SUCCESS;
}
__attribute__((visibility("default"))) VAStatus __vaDriverInit_1_0(VADriverContextP ctx) {
    if(getauxval(0x54520009UL)!=0x10007UL)return VA_STATUS_ERROR_OPERATION_FAILED;
    Driver* d=calloc(1,sizeof(*d));if(!d)return VA_STATUS_ERROR_ALLOCATION_FAILED;
    d->free_head=VA_INVALID_ID;pthread_mutex_init(&d->lock,NULL);ctx->pDriverData=d;
    ctx->version_major=VA_MAJOR_VERSION;ctx->version_minor=VA_MINOR_VERSION;
    ctx->max_profiles=3;ctx->max_entrypoints=1;ctx->max_attributes=1;
    ctx->max_image_formats=1;ctx->max_subpic_formats=1;ctx->max_display_attributes=0;
    ctx->str_vendor="Trames VideoToolbox H.264 decode";
    struct VADriverVTable* v=ctx->vtable;
    v->vaTerminate=terminate;v->vaQueryConfigProfiles=query_profiles;v->vaQueryConfigEntrypoints=query_entrypoints;
    v->vaGetConfigAttributes=config_attributes;v->vaCreateConfig=create_config;v->vaDestroyConfig=destroy_config;v->vaQueryConfigAttributes=query_config;
    v->vaCreateSurfaces=create_surfaces;v->vaCreateSurfaces2=create_surfaces2;v->vaDestroySurfaces=destroy_surfaces;v->vaQuerySurfaceAttributes=query_surface_attributes;
    v->vaCreateContext=create_context;v->vaDestroyContext=destroy_context;
    v->vaCreateBuffer=create_buffer;v->vaBufferSetNumElements=buffer_elements;v->vaMapBuffer=map_buffer;v->vaUnmapBuffer=unmap_buffer;v->vaDestroyBuffer=destroy_buffer;v->vaBufferInfo=buffer_info;
    v->vaBeginPicture=begin_picture;v->vaRenderPicture=render_picture;v->vaEndPicture=end_picture;
    v->vaSyncSurface=sync_surface;v->vaQuerySurfaceStatus=surface_status;v->vaQuerySurfaceError=surface_error;
    v->vaExportSurfaceHandle=export_surface;
    v->vaSetImagePalette=palette;v->vaPutImage=put_image;v->vaQuerySubpictureFormats=subpictures;
    v->vaCreateSubpicture=create_subpicture;v->vaDestroySubpicture=destroy_subpicture;v->vaSetSubpictureImage=subpicture_image;
    v->vaSetSubpictureChromakey=subpicture_chroma;v->vaSetSubpictureGlobalAlpha=subpicture_alpha;
    v->vaAssociateSubpicture=associate_subpicture;v->vaDeassociateSubpicture=deassociate_subpicture;
    v->vaQueryDisplayAttributes=display_attributes;v->vaGetDisplayAttributes=get_display_attributes;v->vaSetDisplayAttributes=set_display_attributes;
    v->vaQueryImageFormats=query_images;v->vaCreateImage=create_image;v->vaDeriveImage=derive_image;v->vaDestroyImage=destroy_image;v->vaGetImage=get_image;
    return VA_STATUS_SUCCESS;
}
