// SPDX-License-Identifier: GPL-3.0-or-later
#import <Foundation/Foundation.h>
#import <VideoToolbox/VideoToolbox.h>
#import <CoreVideo/CoreVideo.h>
#include <vector>
#include <cstring>

extern "C" void trames_video_free_bytes(void* data);
extern "C" void trames_video_complete(void* job, int status, void* frame);
struct Decoder {
    uint32_t width, height;
    VTDecompressionSessionRef session = nullptr;
    CMVideoFormatDescriptionRef format = nullptr;
    std::vector<uint8_t> sps, pps;
};
struct Frame { CVPixelBufferRef buffer; };
static void completed(void*, void* job, OSStatus status, VTDecodeInfoFlags, CVImageBufferRef image, CMTime, CMTime) {
    Frame* frame = image && !status ? new Frame{CVPixelBufferRetain(image)} : nullptr;
    trames_video_complete(job, status ? -5 : 0, frame);
}
static void release_bytes(void* ref, void*, size_t) { trames_video_free_bytes(ref); }
extern "C" uint64_t trames_video_caps() {
    // Other codecs are only hints until their VA input adaptation is validated.
    return VTIsHardwareDecodeSupported(kCMVideoCodecType_H264) ? 1 : 0;
}
extern "C" void* trames_video_decoder_new(uint32_t width, uint32_t height) {
    return new Decoder{width, height, nullptr, nullptr, {}, {}};
}
extern "C" void trames_video_decoder_free(void* opaque) {
    auto* decoder = (Decoder*)opaque;
    if (decoder->session) {
        // Invalidation drains native ownership at final context teardown.
        VTDecompressionSessionInvalidate(decoder->session);
        CFRelease(decoder->session);
    }
    if (decoder->format) CFRelease(decoder->format);
    delete decoder;
}
static OSStatus configure(Decoder* decoder, const uint8_t* sps, size_t sn, const uint8_t* pps, size_t pn) {
    if (decoder->sps.size()==sn && decoder->pps.size()==pn &&
        !memcmp(decoder->sps.data(),sps,sn) && !memcmp(decoder->pps.data(),pps,pn)) return 0;
    const uint8_t* parameters[] = {sps, pps};
    size_t sizes[] = {sn, pn};
    CMVideoFormatDescriptionRef format=nullptr;
    OSStatus status=CMVideoFormatDescriptionCreateFromH264ParameterSets(nullptr,2,parameters,sizes,4,&format);
    if (status) return status;
    if (decoder->session && !VTDecompressionSessionCanAcceptFormatDescription(decoder->session,format)) {
        CFRelease(format);
        return kVTFormatDescriptionChangeNotSupportedErr;
    }
    if (!decoder->session) {
        NSDictionary* specification=@{(id)kVTVideoDecoderSpecification_RequireHardwareAcceleratedVideoDecoder:@YES};
        NSDictionary* attributes=@{(id)kCVPixelBufferPixelFormatTypeKey:@(kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange),
            (id)kCVPixelBufferIOSurfacePropertiesKey:@{}, (id)kCVPixelBufferMetalCompatibilityKey:@YES};
        VTDecompressionOutputCallbackRecord callback={completed,nullptr};
        status=VTDecompressionSessionCreate(nullptr,format,(__bridge CFDictionaryRef)specification,
            (__bridge CFDictionaryRef)attributes,&callback,&decoder->session);
        if (status) { CFRelease(format); return status; }
        CFTypeRef hardware=nullptr;
        status=VTSessionCopyProperty(decoder->session,kVTDecompressionPropertyKey_UsingHardwareAcceleratedVideoDecoder,nullptr,&hardware);
        bool usingHardware=!status && hardware && CFEqual(hardware,kCFBooleanTrue);
        if (hardware) CFRelease(hardware);
        if (!usingHardware) {
            VTDecompressionSessionInvalidate(decoder->session); CFRelease(decoder->session); decoder->session=nullptr;
            CFRelease(format); return kVTCouldNotFindVideoDecoderErr;
        }
    }
    if (decoder->format) CFRelease(decoder->format);
    decoder->format=format;
    decoder->sps.assign(sps,sps+sn); decoder->pps.assign(pps,pps+pn);
    return 0;
}
extern "C" void trames_video_submit(void* opaque, const uint8_t* sps, size_t sn, const uint8_t* pps, size_t pn,
    const uint8_t* bytes, size_t size, void* ownedBytes, void* job) { @autoreleasepool {
    auto* decoder=(Decoder*)opaque;
    OSStatus status=configure(decoder,sps,sn,pps,pn);
    if (status) { trames_video_free_bytes(ownedBytes); trames_video_complete(job,-5,nullptr); return; }
    CMBlockBufferCustomBlockSource source={kCMBlockBufferCustomBlockSourceVersion,nullptr,release_bytes,ownedBytes};
    CMBlockBufferRef block=nullptr;
    status=CMBlockBufferCreateWithMemoryBlock(nullptr,(void*)bytes,size,nullptr,&source,0,size,0,&block);
    if (status) { trames_video_free_bytes(ownedBytes); trames_video_complete(job,-5,nullptr); return; }
    CMSampleBufferRef sample=nullptr;
    status=CMSampleBufferCreateReady(nullptr,block,decoder->format,1,0,nullptr,1,&size,&sample);
    if (!status) {
        status=VTDecompressionSessionDecodeFrame(decoder->session,sample,kVTDecodeFrame_EnableAsynchronousDecompression,job,nullptr);
        CFRelease(sample);
    }
    CFRelease(block);
    if (status) trames_video_complete(job,-5,nullptr);
} }
extern "C" void trames_video_frame_free(void* opaque) {
    auto* frame=(Frame*)opaque; CVPixelBufferRelease(frame->buffer); delete frame;
}
extern "C" void trames_video_frame_size(void* opaque, uint32_t* size) {
    auto buffer=((Frame*)opaque)->buffer;
    size[0]=(uint32_t)CVPixelBufferGetWidth(buffer); size[1]=(uint32_t)CVPixelBufferGetHeight(buffer);
}
extern "C" int trames_video_frame_copy(void* opaque, uint8_t* bytes, size_t size) {
    auto buffer=((Frame*)opaque)->buffer;
    size_t w=CVPixelBufferGetWidth(buffer),h=CVPixelBufferGetHeight(buffer);
    if (CVPixelBufferGetPixelFormatType(buffer)!=kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange ||
        w%2 || h%2 || size < w*h*3/2) return -1;
    if (CVPixelBufferLockBaseAddress(buffer,kCVPixelBufferLock_ReadOnly)) return -1;
    for (unsigned p=0;p<2;p++) {
        size_t rows=p?h/2:h, pitch=CVPixelBufferGetBytesPerRowOfPlane(buffer,p);
        auto* data=(const uint8_t*)CVPixelBufferGetBaseAddressOfPlane(buffer,p);
        for (size_t row=0;row<rows;row++) { memcpy(bytes,data+pitch*row,w); bytes+=w; }
    }
    CVPixelBufferUnlockBaseAddress(buffer,kCVPixelBufferLock_ReadOnly);
    return 0;
}

extern "C" void* trames_video_frame_buffer(void* opaque) {return ((Frame*)opaque)->buffer;}
