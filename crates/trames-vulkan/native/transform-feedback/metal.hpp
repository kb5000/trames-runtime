// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#import <Metal/Metal.h>
#include <array>
#include <cstdint>

namespace trames { namespace tf {
struct alignas(16) Parameters {
    uint32_t vertices, instances, topology, restart;
    uint32_t index_type, first_index, buffers, map_capacity;
    uint32_t sizes[4], strides[4];
};
struct alignas(16) State {
    uint32_t cursors[4];
    uint64_t written, needed;
};
struct Buffer {
    id<MTLBuffer> object = nil;
    NSUInteger offset = 0, size = 0;
};
static_assert(sizeof(Parameters) == 64 && sizeof(State) == 32, "TF Metal ABI");

// Internal Metal engine. It does not advertise Vulkan capabilities. The adapter
// must retain these pipelines and each draw's scratch buffers until completion,
// as it already does for native pipelines/recording snapshots.
class Metal {
public:
    Metal(id<MTLDevice> device, id<MTLLibrary> library, std::array<uint32_t, 4> strides);
    void begin(id<MTLCommandBuffer> command, Buffer state, const std::array<Buffer, 4>& counters, uint32_t mask);
    void end(id<MTLCommandBuffer> command, Buffer state, const std::array<Buffer, 4>& counters, uint32_t mask);
    void assemble(id<MTLCommandBuffer> command, const Parameters& parameters, Buffer indices,
                  Buffer map, Buffer draw, Buffer state, Buffer indirect);
    void scatter(id<MTLCommandBuffer> command, const Parameters& parameters, Buffer rows, Buffer map, Buffer draw,
                 const std::array<Buffer, 4>& outputs);
    void byte_count(id<MTLCommandBuffer> command, Buffer counter, uint32_t offset, uint32_t stride,
                    uint32_t instances, uint32_t first_instance, Buffer indirect);
private:
    id<MTLComputePipelineState> assemble_, map_, scatter_, begin_, end_, byte_count_;
    id<MTLBuffer> dummy_;
    std::array<uint32_t, 4> strides_;
    void validate(const Parameters& parameters);
    void counters(id<MTLCommandBuffer>, id<MTLComputePipelineState>, Buffer, const std::array<Buffer, 4>&, uint32_t);
    void bind(id<MTLComputeCommandEncoder>, Buffer, NSUInteger index, NSUInteger minimum);
};
}}
