// SPDX-License-Identifier: GPL-3.0-or-later
#include <metal_stdlib>
using namespace metal;

// Private GPU ABI, not guest memory. Bound buffers are already authenticated by
// the Vulkan backend. Sizes/offsets are bytes, relative to the bound range.
struct TFParams {
    uint vertices, instances, topology, restart;
    uint indexType, firstIndex, buffers, mapCapacity;
    uint4 sizes;
    uint4 strides;
};
struct TFState {
    uint4 cursors;
    ulong written, needed;
};
// draw[0] = TF vertices; draw[1] = raster vertices; draw[4..7] = starting bytes.
// indirect[0..3] is a Metal DrawPrimitivesIndirectArguments on the GPU.
kernel void trames_tf_assemble(constant TFParams& p [[buffer(0)]],
    const device uint* indices [[buffer(1)]], device uint* map [[buffer(2)]],
    device uint* draw [[buffer(3)]], device TFState& state [[buffer(4)]],
    device uint* indirect [[buffer(5)]], uint tid [[thread_position_in_grid]]) {
    if (tid) return;
    uint primitiveSize = p.topology == 0 ? 1u : (p.topology <= 2 ? 2u : 3u);
    uint capacity = 0xffffffffu;
    for (uint b = 0; b < 4; ++b) {
        draw[4+b] = state.cursors[b];
        if (p.buffers & (1u << b)) {
            uint available = state.cursors[b] <= p.sizes[b] ? p.sizes[b] - state.cursors[b] : 0u;
            capacity = min(capacity, available / p.strides[b]);
        }
    }
    uint written = 0, needed = 0;
    bool full = false;
    if (!p.restart) {
        // Common draws use arithmetic counts and a parallel map dispatch below.
        // Never serialize every vertex through this control thread.
        uint primitives = p.topology == 0 ? p.vertices : p.topology == 1 ? p.vertices/2 :
            p.topology == 2 ? (p.vertices ? p.vertices-1 : 0) : p.topology == 3 ? p.vertices/3 :
            (p.vertices >= 2 ? p.vertices-2 : 0);
        needed = primitives * p.instances * primitiveSize;
        written = min(needed, capacity/primitiveSize*primitiveSize);
    }
    for (uint instance = 0; p.restart && instance < p.instances; ++instance) {
        uint pending[3] = {0, 0, 0};
        uint count = 0, parity = 0;
        for (uint vtx = 0; vtx < p.vertices; ++vtx) {
            uint source = instance * p.vertices + vtx;
            uint index = vtx;
            if (p.indexType == 16) index = reinterpret_cast<const device ushort*>(indices)[p.firstIndex+vtx];
            else if (p.indexType == 32) index = indices[p.firstIndex+vtx];
            uint restart = p.indexType == 16 ? 0xffffu : 0xffffffffu;
            if (p.restart && p.indexType && index == restart) { count = 0; parity = 0; continue; }
            pending[count++] = source;
            if (count < primitiveSize) continue;
            // All assembled primitives feed rasterization, even after TF is
            // full. Overflow never disables rendering or partially writes one.
            if (needed <= p.mapCapacity && primitiveSize <= p.mapCapacity-needed) {
                for (uint v = 0; v < primitiveSize; ++v) {
                    // Vulkan's default first provoking vertex is preserved by
                    // these rotations, in addition to preserving winding.
                    uint n = p.topology == 4 && parity && v > 0 ? 3u-v : p.topology == 5 ? (v+1u)%3u : v;
                    map[needed+v] = pending[n];
                }
            }
            needed += primitiveSize;
            if (!full && primitiveSize <= capacity-written) written += primitiveSize;
            else full = true;
            if (p.topology == 2) { pending[0] = pending[1]; count = 1; }
            else if (p.topology == 4) { pending[0] = pending[1]; pending[1] = pending[2]; count = 2; parity ^= 1; }
            else if (p.topology == 5) { pending[1] = pending[2]; count = 2; }
            else count = 0;
        }
    }
    // The host must reserve the checked worst case (3 * vertices * instances).
    // On a violated internal contract, prevent scatter/replay from using OOB
    // data. draw[2] is an internal validation failure, not guest success.
    draw[2] = needed > p.mapCapacity;
    draw[0] = needed <= p.mapCapacity ? written : 0;
    draw[1] = needed <= p.mapCapacity ? needed : 0;
    draw[3] = 0;
    if (needed <= p.mapCapacity) {
        state.written += written / primitiveSize;
        state.needed += needed / primitiveSize;
        for (uint b = 0; b < 4; ++b)
            if (p.buffers & (1u << b)) state.cursors[b] += written * p.strides[b];
    }
    indirect[0] = draw[1]; indirect[1] = 1; indirect[2] = 0; indirect[3] = 0;
}

kernel void trames_tf_map(constant TFParams& p [[buffer(0)]], const device uint* draw [[buffer(1)]],
    device uint* map [[buffer(2)]], uint i [[thread_position_in_grid]]) {
    if (p.restart || i >= draw[1]) return;
    uint size = p.topology == 0 ? 1u : p.topology <= 2 ? 2u : 3u;
    uint primitives = p.topology == 0 ? p.vertices : p.topology == 1 ? p.vertices/2 :
        p.topology == 2 ? (p.vertices ? p.vertices-1 : 0) : p.topology == 3 ? p.vertices/3 :
        (p.vertices >= 2 ? p.vertices-2 : 0);
    uint perInstance = primitives*size;
    uint instance = i/perInstance, local = i%perInstance, primitive = local/size, vtx = local%size;
    uint source = local;
    if (p.topology == 2) source = primitive+vtx;
    else if (p.topology == 4) source = primitive+((primitive&1u) && vtx>0 ? 3u-vtx : vtx);
    else if (p.topology == 5) source = vtx < 2 ? primitive+vtx+1 : 0;
    map[i] = instance*p.vertices+source;
}

// Optional begin/end counters remain GPU buffers, including pause/resume.
kernel void trames_tf_begin(device TFState& state [[buffer(0)]], constant uint& mask [[buffer(1)]],
    const device uint* c0 [[buffer(2)]], const device uint* c1 [[buffer(3)]],
    const device uint* c2 [[buffer(4)]], const device uint* c3 [[buffer(5)]], uint i [[thread_position_in_grid]]) {
    if (i) return;
    state.cursors = uint4(mask&1 ? *c0 : 0, mask&2 ? *c1 : 0, mask&4 ? *c2 : 0, mask&8 ? *c3 : 0);
    state.written = 0; state.needed = 0;
}
kernel void trames_tf_end(const device TFState& state [[buffer(0)]], constant uint& mask [[buffer(1)]],
    device uint* c0 [[buffer(2)]], device uint* c1 [[buffer(3)]],
    device uint* c2 [[buffer(4)]], device uint* c3 [[buffer(5)]], uint i [[thread_position_in_grid]]) {
    if (i) return;
    if (mask&1) *c0=state.cursors[0]; if (mask&2) *c1=state.cursors[1];
    if (mask&4) *c2=state.cursors[2]; if (mask&8) *c3=state.cursors[3];
}
kernel void trames_tf_byte_count(const device uint* counter [[buffer(0)]],
    constant uint4& p [[buffer(1)]], device uint* indirect [[buffer(2)]], uint i [[thread_position_in_grid]]) {
    if (i) return;
    uint bytes = *counter;
    indirect[0] = bytes >= p.x && p.y ? (bytes-p.x)/p.y : 0;
    indirect[1] = p.z; indirect[2] = 0; indirect[3] = p.w;
}

// MoltenVK command adapter: original indirect draw words stay on the GPU.
// out: TFParams(16 words), raw draw(8), MTLStageInRegion(6), dispatch(3), error.
kernel void trames_tf_parameters(constant TFParams& base [[buffer(0)]],
    const device uint* input [[buffer(1)]], device uint* out [[buffer(2)]],
    constant uint4& config [[buffer(3)]], device atomic_uint& fault [[buffer(4)]], const device uint* indices [[buffer(5)]], uint tid [[thread_position_in_grid]]) {
    if (tid) return;
    uint n = input[0], instances = input[1];
    bool valid = ulong(n)*instances <= base.mapCapacity/3u;
    device TFParams& p = *reinterpret_cast<device TFParams*>(out);
    p = base;p.vertices = valid ? n : 0;p.instances = valid ? instances : 0;p.firstIndex = 0;
    out[16] = p.vertices;out[17] = p.instances;out[18] = input[2];
    out[19] = config.x ? input[3] : 0;out[20] = input[config.x ? 4 : 3];
    out[21] = base.restart;out[22] = base.indexType;out[23] = 0;
    out[24] = config.x ? input[3] : input[2];out[25] = out[20];out[26] = 0;
    out[27] = p.vertices;out[28] = p.instances;out[29] = 1;
    out[30] = (p.vertices+config.y-1)/config.y;out[31] = p.instances;out[32] = 1;
    if (valid && base.restart && base.indexType) {
        bool found=false;
        for(uint i=0;i<n;++i) {
            uint x=base.indexType==16 ? uint(reinterpret_cast<const device ushort*>(indices)[input[2]+i]) : indices[input[2]+i];
            if(x!=(base.indexType==16 ? 0xffffu : 0xffffffffu)) { out[23]=x;found=true;break; }
        }
        // Restart markers never enter hardware vertex fetch. Reuse one known
        // valid source index, including positive/negative baseVertex; if all
        // indices are markers, suppress the vertex dispatch altogether.
        if (!found) out[30]=0;
    }
    out[33] = !valid;
    if (!valid) atomic_store_explicit(&fault,1u,memory_order_relaxed);
}
kernel void trames_tf_copy_indices16(const device ushort* input [[buffer(0)]],
    const device uint* raw [[buffer(1)]], device ushort* output [[buffer(2)]], device ushort* safe [[buffer(3)]], uint i [[thread_position_in_grid]]) {
    if (i < raw[0]) { ushort x=input[raw[2]+i];output[i]=x;safe[i]=raw[5] && x==0xffffu ? ushort(raw[7]) : x; }
}
kernel void trames_tf_copy_indices32(const device uint* input [[buffer(0)]],
    const device uint* raw [[buffer(1)]], device uint* output [[buffer(2)]], device uint* safe [[buffer(3)]], uint i [[thread_position_in_grid]]) {
    if (i < raw[0]) { uint x=input[raw[2]+i];output[i]=x;safe[i]=raw[5] && x==0xffffffffu ? raw[7] : x; }
}
kernel void trames_tf_dispatch(device uint* draw [[buffer(0)]], constant uint2& widths [[buffer(1)]],
    uint i [[thread_position_in_grid]]) {
    if (i) return;
    draw[8] = (draw[1]+widths.x-1)/widths.x;draw[9] = 1;draw[10] = 1;
    draw[11] = (draw[0]+widths.y-1)/widths.y;draw[12] = 1;draw[13] = 1;
}
kernel void trames_tf_query_accumulate(const device uint* draw [[buffer(0)]],
    device ulong* results [[buffer(1)]], constant uint& primitiveSize [[buffer(2)]], uint i [[thread_position_in_grid]]) {
    if (i) return;
    results[0] += draw[0]/primitiveSize;results[1] += draw[1]/primitiveSize;
}
kernel void trames_tf_query_copy(const device ulong* source [[buffer(0)]], device uchar* output [[buffer(1)]],
    constant uint4& p [[buffer(2)]], const device uint* availability [[buffer(3)]], uint i [[thread_position_in_grid]]) {
    if (i >= p.x) return;
    bool available = availability[i] != 0;
    device uchar* destination = output + ulong(i)*p.y;
    if (p.z&1u) {
        device ulong* dst = reinterpret_cast<device ulong*>(destination);
        if (available || (p.z&8u)) { dst[0]=source[i*2];dst[1]=source[i*2+1]; }
        if (p.z&4u) dst[2]=available;
    } else {
        device uint* dst = reinterpret_cast<device uint*>(destination);
        if (available || (p.z&8u)) { dst[0]=uint(source[i*2]);dst[1]=uint(source[i*2+1]); }
        if (p.z&4u) dst[2]=available;
    }
}

// Match upstream's zero-divisor firstInstance buffer adjustment, including
// indirect draws, without reading the draw arguments back to the CPU.
kernel void trames_tf_vertex_constant(const device uchar* input [[buffer(0)]],
    device uchar* output [[buffer(1)]], const device uint* draw [[buffer(2)]],
    constant uint& stride [[buffer(3)]], uint i [[thread_position_in_grid]]) {
    if (i < stride) output[i] = input[ulong(draw[4])*stride+i];
}
