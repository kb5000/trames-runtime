// SPDX-License-Identifier: GPL-3.0-or-later
#import <Foundation/Foundation.h>
#import <CoreVideo/CoreVideo.h>
#import <IOSurface/IOSurfaceRef.h>
#import <Metal/Metal.h>
#include <algorithm>
struct Image {CVPixelBufferRef buffer;unsigned plane;};
struct Cache {CVMetalTextureCacheRef cache;id<MTLDevice> device;};
static unsigned format(Image* image) {
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
    NSDictionary* attributes=@{(id)kCVPixelBufferIOSurfacePropertiesKey:@{},(id)kCVPixelBufferMetalCompatibilityKey:@YES};
    CVPixelBufferRef buffer=nullptr;
    if(CVPixelBufferCreate(nullptr,width,height,pixel,(__bridge CFDictionaryRef)attributes,&buffer))return nullptr;
    auto* image=new Image{buffer,0};return image;
} }
extern "C" void trames_graphics_image_free(void* pointer) {auto* image=(Image*)pointer;CVPixelBufferRelease(image->buffer);delete image;}
extern "C" int trames_graphics_info(void* pointer,uint64_t* values) {
    auto* image=(Image*)pointer;auto buffer=image->buffer;
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
    CVMetalTextureRef texture=nullptr;
    if(CVMetalTextureCacheCreateTextureFromImage(nullptr,((Cache*)cache)->cache,image->buffer,(__bridge CFDictionaryRef)attributes,fmt,info[0],info[1],image->plane,&texture))return nullptr;
    return texture;
} }
extern "C" void* trames_graphics_texture_handle(void* texture) {return (__bridge void*)CVMetalTextureGetTexture((CVMetalTextureRef)texture);}
extern "C" void trames_graphics_texture_free(void* texture) {CFRelease(texture);}
