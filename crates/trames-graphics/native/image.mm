// SPDX-License-Identifier: GPL-3.0-or-later
#import <Foundation/Foundation.h>
#import <CoreVideo/CoreVideo.h>
#import <IOSurface/IOSurfaceRef.h>
#import <Metal/Metal.h>
#include <algorithm>
#include <memory>
#include <unistd.h>
struct Image {CVPixelBufferRef buffer;unsigned plane;IOSurfaceRef surface=nullptr;unsigned native_format=0;};
struct Texture {CVMetalTextureRef cv=nullptr;id<MTLTexture> texture;};
struct Cache {CVMetalTextureCacheRef cache;id<MTLDevice> device;};
static IOSurfaceRef surface(Image* image) {return image->surface?image->surface:CVPixelBufferGetIOSurface(image->buffer);}
extern "C" void* trames_graphics_default_device() {
    static id<MTLDevice> device=MTLCreateSystemDefaultDevice();
    return (__bridge void*)device;
}
static unsigned format(Image* image) {
    if(image->surface)return image->native_format;
    OSType type=CVPixelBufferGetPixelFormatType(image->buffer);
    switch(type) {
        case kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange:
        case kCVPixelFormatType_420YpCbCr8BiPlanarFullRange:return image->plane?16:9;
        case kCVPixelFormatType_OneComponent8:return 9;
        case kCVPixelFormatType_TwoComponent8:return 16;
        case kCVPixelFormatType_32RGBA:return 37;
        case kCVPixelFormatType_32BGRA:return 44;
        default:return 0;
    }
}
extern "C" void* trames_graphics_plane(void* pointer,unsigned plane) {
    auto buffer=(CVPixelBufferRef)pointer;
    if(!buffer || !CVPixelBufferGetIOSurface(buffer) || plane>=std::max((size_t)1,CVPixelBufferGetPlaneCount(buffer)))return nullptr;
    auto* image=new Image{CVPixelBufferRetain(buffer),plane};
    if(!format(image)){CVPixelBufferRelease(image->buffer);delete image;return nullptr;}
    return image;
}
extern "C" void* trames_graphics_allocate(unsigned fmt,unsigned width,unsigned height) { @autoreleasepool {
    OSType pixel;
    switch(fmt) {case 9:pixel=kCVPixelFormatType_OneComponent8;break;case 16:pixel=kCVPixelFormatType_TwoComponent8;break;
        case 37:pixel=kCVPixelFormatType_32RGBA;break;case 44:pixel=kCVPixelFormatType_32BGRA;break;default:return nullptr;}
    size_t bytes=fmt==9?1:fmt==16?2:4;
    if(!width || !height || width>(SIZE_MAX-63)/bytes)return nullptr;
    size_t pitch=(width*bytes+63)&~(size_t)63,page=getpagesize();
    if(pitch>(SIZE_MAX-(page-1))/height)return nullptr;
    size_t size=(pitch*height+page-1)&~(page-1);
    NSDictionary* attributes=@{(id)kIOSurfaceWidth:@(width),(id)kIOSurfaceHeight:@(height),(id)kIOSurfaceBytesPerElement:@(bytes),(id)kIOSurfaceBytesPerRow:@(pitch),(id)kIOSurfaceAllocSize:@(size),(id)kIOSurfacePixelFormat:@(pixel)};
    IOSurfaceRef allocation=IOSurfaceCreate((__bridge CFDictionaryRef)attributes);
    return allocation?new Image{nullptr,0,allocation,fmt}:nullptr;
} }
extern "C" void trames_graphics_image_free(void* pointer) {auto* image=(Image*)pointer;if(image->buffer)CVPixelBufferRelease(image->buffer);if(image->surface)CFRelease(image->surface);delete image;}
extern "C" int trames_graphics_cpu(void* pointer,uint64_t* values) {
    auto* image=(Image*)pointer;auto allocation=surface(image);
    if(!allocation)return -1;
    auto base=(uintptr_t)IOSurfaceGetBaseAddress(allocation);
    auto plane=IOSurfaceGetPlaneCount(allocation)?(uintptr_t)IOSurfaceGetBaseAddressOfPlane(allocation,image->plane):base;
    values[0]=base;values[1]=IOSurfaceGetAllocSize(allocation);values[2]=plane-base;
    return !base || plane<base;
}
extern "C" int trames_graphics_cpu_access(void* pointer,bool begin) {
    auto allocation=surface((Image*)pointer);
    return begin?IOSurfaceLock(allocation,0,nullptr):IOSurfaceUnlock(allocation,0,nullptr);
}
extern "C" int trames_graphics_info(void* pointer,uint64_t* values) {
    auto* image=(Image*)pointer;auto buffer=image->buffer;
    if(image->surface){values[0]=IOSurfaceGetWidth(image->surface);values[1]=IOSurfaceGetHeight(image->surface);values[2]=image->native_format;values[3]=IOSurfaceGetBytesPerRow(image->surface);values[4]=values[3]*values[1];return 0;}
    bool planar=CVPixelBufferIsPlanar(buffer);
    size_t width=planar?CVPixelBufferGetWidthOfPlane(buffer,image->plane):CVPixelBufferGetWidth(buffer);
    size_t height=planar?CVPixelBufferGetHeightOfPlane(buffer,image->plane):CVPixelBufferGetHeight(buffer);
    size_t pitch=planar?CVPixelBufferGetBytesPerRowOfPlane(buffer,image->plane):CVPixelBufferGetBytesPerRow(buffer);
    if(!width || !height || pitch>SIZE_MAX/height)return -1;
    values[0]=width;values[1]=height;values[2]=format(image);values[3]=pitch;values[4]=pitch*height;return 0;
}
extern "C" void* trames_graphics_cache(void* pointer) {
    CVMetalTextureCacheRef cache=nullptr;
    if(CVMetalTextureCacheCreate(nullptr,nullptr,(__bridge id<MTLDevice>)pointer,nullptr,&cache))return nullptr;
    return new Cache{cache,(__bridge id<MTLDevice>)pointer};
}
extern "C" void trames_graphics_cache_free(void* pointer) {auto* cache=(Cache*)pointer;CFRelease(cache->cache);delete cache;}
extern "C" void* trames_graphics_texture(void* pointer,void* cache) { @autoreleasepool {
    auto* image=(Image*)pointer;uint64_t info[5];if(trames_graphics_info(pointer,info))return nullptr;
    MTLPixelFormat fmt;
    switch(info[2]) {case 9:fmt=MTLPixelFormatR8Unorm;break;case 16:fmt=MTLPixelFormatRG8Unorm;break;
        case 37:fmt=MTLPixelFormatRGBA8Unorm;break;case 44:fmt=MTLPixelFormatBGRA8Unorm;break;default:return nullptr;}
    NSDictionary* attributes=@{(id)kCVMetalTextureUsage:@(MTLTextureUsageShaderRead|MTLTextureUsageShaderWrite|MTLTextureUsageRenderTarget|MTLTextureUsagePixelFormatView)};
    if(image->surface){
        auto descriptor=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:fmt width:info[0] height:info[1] mipmapped:NO];
        descriptor.storageMode=MTLStorageModeShared;descriptor.usage=MTLTextureUsageShaderRead|MTLTextureUsageShaderWrite|MTLTextureUsageRenderTarget|MTLTextureUsagePixelFormatView;
        id<MTLTexture> texture=[((Cache*)cache)->device newTextureWithDescriptor:descriptor iosurface:image->surface plane:0];
        return texture?new Texture{nullptr,texture}:nullptr;
    }
    CVMetalTextureRef texture=nullptr;
    if(CVMetalTextureCacheCreateTextureFromImage(nullptr,((Cache*)cache)->cache,image->buffer,(__bridge CFDictionaryRef)attributes,fmt,info[0],info[1],image->plane,&texture))return nullptr;
    return new Texture{texture,CVMetalTextureGetTexture(texture)};
} }
extern "C" void* trames_graphics_texture_handle(void* texture) {return (__bridge void*)((Texture*)texture)->texture;}
extern "C" void trames_graphics_texture_free(void* texture) {auto* value=(Texture*)texture;if(value->cv)CFRelease(value->cv);delete value;}

struct EventCompletion {
    void (*notify)(void*);void* data;void (*dispose)(void*);
    ~EventCompletion(){dispose(data);}
};
using EventObservation=std::shared_ptr<EventCompletion>;
extern "C" void* trames_graphics_observe_event(void* pointer,uint64_t value,void (*notify)(void*),void* data,void (*dispose)(void*)) { @autoreleasepool {
    if(!pointer){dispose(data);return nullptr;}
    auto owner=std::make_shared<EventCompletion>();owner->notify=notify;owner->data=data;owner->dispose=dispose;
    std::weak_ptr<EventCompletion> weak=owner;
    // Use the existing system dispatch pool, without a Trames service thread.
    static MTLSharedEventListener* listener=[[MTLSharedEventListener alloc] initWithDispatchQueue:dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0)];
    [(__bridge id<MTLSharedEvent>)pointer notifyListener:listener atValue:value block:^(id<MTLSharedEvent>,uint64_t){
        if(auto completion=weak.lock())completion->notify(completion->data);
    }];
    return new EventObservation(std::move(owner));
} }
extern "C" void trames_graphics_cancel_event(void* observation) {delete (EventObservation*)observation;}
