// SPDX-License-Identifier: GPL-3.0-or-later
#include "metal.hpp"
#include <algorithm>
#include <limits>
#include <stdexcept>

namespace trames { namespace tf {
namespace {
void require(bool condition, const char* why) {
    if (!condition) throw std::runtime_error(why);
}
id<MTLComputePipelineState> pipeline(id<MTLDevice> device, id<MTLLibrary> library, NSString* name) {
    auto function = [library newFunctionWithName:name];
    require(function != nil, "Missing native transform feedback kernel");
    NSError* error = nil;
    auto state = [device newComputePipelineStateWithFunction:function error:&error];
    if (!state) throw std::runtime_error(error.description.UTF8String ?: "Could not compile native TF pipeline");
    return state;
}
void run(id<MTLComputeCommandEncoder> encoder, id<MTLComputePipelineState> state, NSUInteger threads) {
    [encoder dispatchThreads:MTLSizeMake(threads, 1, 1)
        threadsPerThreadgroup:MTLSizeMake(std::min(threads, state.threadExecutionWidth), 1, 1)];
    [encoder endEncoding];
}
}

Metal::Metal(id<MTLDevice> device, id<MTLLibrary> library, std::array<uint32_t, 4> strides)
    : assemble_(pipeline(device, library, @"trames_tf_assemble")),
      map_(pipeline(device, library, @"trames_tf_map")),
      scatter_(pipeline(device, library, @"trames_tf_scatter")),
      begin_(pipeline(device, library, @"trames_tf_begin")),
      end_(pipeline(device, library, @"trames_tf_end")),
      byte_count_(pipeline(device, library, @"trames_tf_byte_count")), strides_(strides) {
    dummy_ = [device newBufferWithLength:4 options:MTLResourceStorageModePrivate];
    require(dummy_ != nil, "Could not allocate native TF placeholder");
}

void Metal::bind(id<MTLComputeCommandEncoder> encoder, Buffer buffer, NSUInteger index, NSUInteger minimum) {
    require(buffer.object && !(buffer.offset & 3) && buffer.size >= minimum &&
            buffer.offset <= buffer.object.length && buffer.size <= buffer.object.length-buffer.offset,
            "Invalid native TF buffer range");
    [encoder setBuffer:buffer.object offset:buffer.offset atIndex:index];
}

void Metal::counters(id<MTLCommandBuffer> command, id<MTLComputePipelineState> state,
                     Buffer storage, const std::array<Buffer, 4>& buffers, uint32_t mask) {
    require(!(mask & ~15u), "Invalid native TF counter mask");
    auto encoder = [command computeCommandEncoder];
    [encoder setComputePipelineState:state];
    bind(encoder, storage, 0, sizeof(State));
    [encoder setBytes:&mask length:sizeof(mask) atIndex:1];
    for (uint32_t i = 0; i < 4; ++i)
        bind(encoder, mask & (1u << i) ? buffers[i] : Buffer{dummy_, 0, 4}, 2+i, 4);
    run(encoder, state, 1);
}
void Metal::begin(id<MTLCommandBuffer> command, Buffer state, const std::array<Buffer, 4>& values, uint32_t mask) {
    counters(command, begin_, state, values, mask);
}
void Metal::end(id<MTLCommandBuffer> command, Buffer state, const std::array<Buffer, 4>& values, uint32_t mask) {
    counters(command, end_, state, values, mask);
}

void Metal::validate(const Parameters& p) {
    uint64_t invocations = uint64_t(p.vertices) * p.instances;
    require(p.topology <= 5 && p.restart <= 1 && p.buffers && !(p.buffers & ~15u), "Invalid native TF draw parameters");
    require((p.index_type == 0 || p.index_type == 16 || p.index_type == 32) &&
            (!p.restart || p.index_type) && invocations <= (64u << 20) / 12u &&
            uint64_t(p.map_capacity) >= 3 * invocations, "Native TF map limit exceeded");
    for (uint32_t i = 0; i < 4; ++i) {
        require(bool(p.buffers & (1u << i)) == bool(strides_[i]) && p.strides[i] == strides_[i], "TF shader and draw layout disagree");
        if (strides_[i]) require(p.strides[i] <= 2048 && !(p.strides[i] & 3) && p.sizes[i] <= (64u << 20), "Invalid native TF output range");
    }
}

void Metal::assemble(id<MTLCommandBuffer> command, const Parameters& p, Buffer indices,
                     Buffer map, Buffer draw, Buffer state, Buffer indirect) {
    validate(p);
    auto encoder = [command computeCommandEncoder];
    [encoder setComputePipelineState:assemble_];
    [encoder setBytes:&p length:sizeof(p) atIndex:0];
    if (p.index_type) bind(encoder, indices, 1, (uint64_t(p.first_index)+p.vertices)*(p.index_type/8));
    else bind(encoder, {dummy_, 0, 4}, 1, 4);
    bind(encoder, map, 2, uint64_t(p.map_capacity)*4);
    bind(encoder, draw, 3, 32);bind(encoder, state, 4, sizeof(State));bind(encoder, indirect, 5, 16);
    run(encoder, assemble_, 1);
    if (!p.restart && p.map_capacity) {
        encoder = [command computeCommandEncoder];[encoder setComputePipelineState:map_];
        [encoder setBytes:&p length:sizeof(p) atIndex:0];
        bind(encoder, draw, 1, 32);bind(encoder, map, 2, uint64_t(p.map_capacity)*4);
        run(encoder, map_, p.map_capacity);
    }
}

void Metal::scatter(id<MTLCommandBuffer> command, const Parameters& p, Buffer rows, Buffer map, Buffer draw,
                    const std::array<Buffer, 4>& outputs) {
    validate(p);
    if (!p.map_capacity) return;
    auto encoder = [command computeCommandEncoder];
    [encoder setComputePipelineState:scatter_];
    bind(encoder, rows, 0, uint64_t(p.vertices)*p.instances*512);bind(encoder, map, 1, uint64_t(p.map_capacity)*4);bind(encoder, draw, 2, 32);
    for (uint32_t i = 0; i < 4; ++i) {
        if (p.buffers & (1u << i)) bind(encoder, outputs[i], 3+i, p.sizes[i]);
        else bind(encoder, {dummy_, 0, 4}, 3+i, 4);
    }
    run(encoder, scatter_, p.map_capacity);
}

void Metal::byte_count(id<MTLCommandBuffer> command, Buffer counter, uint32_t offset, uint32_t stride,
                       uint32_t instances, uint32_t first_instance, Buffer indirect) {
    require(stride && !(stride & 3), "Invalid native TF byte-count stride");
    uint32_t p[] = {offset, stride, instances, first_instance};
    auto encoder = [command computeCommandEncoder];
    [encoder setComputePipelineState:byte_count_];
    bind(encoder, counter, 0, 4);[encoder setBytes:p length:sizeof(p) atIndex:1];
    bind(encoder, indirect, 2, 16);run(encoder, byte_count_, 1);
}
}}
