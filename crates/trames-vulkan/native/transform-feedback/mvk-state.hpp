// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#import <Metal/Metal.h>
#include <cstdint>
class MVKCommandEncoder;
class MVKTFQueryPool;
struct MVKTFBuffer {
    id<MTLBuffer> buffer = nil;
    NSUInteger offset = 0, size = 0;
};
struct MVKTFEncoderState {
    MVKTFBuffer outputs[4], counters, rows, map, draw, arguments, indices, safeIndices;
    id<MTLBuffer> fault = nil; // retained by the native completion callback
    MVKTFQueryPool* query = nullptr;
    uint32_t queryIndex = 0;
    bool active = false;
};
enum MVKTFKernel { MVKTFAssemble, MVKTFMap, MVKTFBegin, MVKTFEnd, MVKTFByteCount,
                  MVKTFParameters, MVKTFCopyIndices16, MVKTFCopyIndices32,
                  MVKTFQueryAccumulate, MVKTFQueryCopy, MVKTFDispatch, MVKTFVertexConstant, MVKTFKernelCount };
bool mvkTFDraw(MVKCommandEncoder*, uint32_t vertices, uint32_t instances, uint32_t first,
               int32_t baseVertex, uint32_t firstInstance, bool indexed,
               id<MTLBuffer> indirect = nil, NSUInteger indirectOffset = 0);

