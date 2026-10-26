// SPDX-License-Identifier: GPL-3.0-or-later
// Included by MVKCmdDraw.mm after original headers. Resources use original
// command-pool temporaries and the encoder's barriers/state invalidation.
#include "MVKQueryPool.h"
#include "metal.hpp"

static MVKTFBuffer mvkTFTemp(MVKCommandEncoder* encoder, NSUInteger bytes) {
    auto allocation = encoder->getTempMTLBuffer(std::max<NSUInteger>(bytes, 4), true);
    return {allocation->_mtlBuffer, allocation->_offset, allocation->_length};
}
static MVKTFBuffer mvkTFScratch(MVKCommandEncoder* encoder, MVKTFBuffer& slot, NSUInteger bytes) {
    if (slot.size < bytes || !slot.buffer) slot = mvkTFTemp(encoder, bytes);
    return slot;
}
static void mvkTFBind(id<MTLComputeCommandEncoder> encoder, MVKTFBuffer buffer, uint32_t index) {
    [encoder setBuffer:buffer.buffer offset:buffer.offset atIndex:index];
}
static id<MTLComputeCommandEncoder> mvkTFCompute(MVKCommandEncoder* encoder, uint32_t kind) {
    if (encoder->_mtlRenderEncoder) encoder->encodeStoreActions(true);
    auto metal = encoder->getMTLComputeEncoder(kMVKCommandUseTessellationVertexTessCtl);
    [metal setComputePipelineState:encoder->getCommandEncodingPool()->getTransformFeedbackPipeline(kind)];
    return metal;
}
static void mvkTFDispatch(MVKCommandEncoder* encoder, id<MTLComputeCommandEncoder> metal, uint32_t kind, NSUInteger count) {
    auto pipeline = encoder->getCommandEncodingPool()->getTransformFeedbackPipeline(kind);
    NSUInteger width = std::min(count, pipeline.threadExecutionWidth);
    if (count) [metal dispatchThreadgroups:MTLSizeMake(mvkCeilingDivide(count, width), 1, 1)
                  threadsPerThreadgroup:MTLSizeMake(width, 1, 1)];
    encoder->endCurrentMetalEncoding();
}

VkResult MVKCmdTransformFeedback::setContent(MVKCommandBuffer* command, uint32_t operation,
        uint32_t first, uint32_t count, const VkBuffer* buffers, const VkDeviceSize* offsets,
        const VkDeviceSize* sizes, uint32_t instances, uint32_t firstInstance, uint32_t counterOffset, uint32_t stride) {
    if (!command->getEnabledTransformFeedbackFeatures().transformFeedback)
        return command->reportError(VK_ERROR_FEATURE_NOT_PRESENT, "Transform feedback was not enabled.");
    if (first > 4 || count > 4-first) return VK_ERROR_VALIDATION_FAILED_EXT;
    _operation=operation;_first=first;_count=count;_instances=instances;_firstInstance=firstInstance;
    _counterOffset=counterOffset;_stride=stride;
    for (uint32_t i=0;i<4;++i) _buffers[i]={};
    for (uint32_t i=0;i<count;++i) if (buffers && buffers[i]) {
        auto buffer = (MVKBuffer*)buffers[i];
        VkDeviceSize offset = offsets ? offsets[i] : 0;
        VkDeviceSize size = sizes && sizes[i]!=VK_WHOLE_SIZE ? sizes[i] : buffer->getByteCount()-offset;
        if (offset>buffer->getByteCount() || size>buffer->getByteCount()-offset) return VK_ERROR_VALIDATION_FAILED_EXT;
        _buffers[i]={buffer->getMTLBuffer(), buffer->getMTLBufferOffset()+offset, size};
    }
    return VK_SUCCESS;
}

void MVKCmdTransformFeedback::encode(MVKCommandEncoder* encoder) {
    auto& tf=encoder->_transformFeedback;
    if (_operation==0) {
        for (uint32_t i=0;i<_count;++i) tf.outputs[_first+i]=_buffers[i];
        return;
    }
    if (_operation==1 || _operation==2) {
        if (_operation==1) tf.counters=mvkTFTemp(encoder,32);
        auto kind=_operation==1 ? MVKTFBegin : MVKTFEnd;
        auto metal=mvkTFCompute(encoder,kind);
        mvkTFBind(metal,tf.counters,0);
        uint32_t mask=0;
        for (uint32_t i=0;i<_count;++i) if (_buffers[i].buffer) mask|=1u<<(_first+i);
        encoder->setComputeBytes(metal,&mask,sizeof(mask),1);
        for (uint32_t i=0;i<4;++i)
            mvkTFBind(metal,(mask&(1u<<i)) ? _buffers[i-_first] : tf.counters,2+i);
        mvkTFDispatch(encoder,metal,kind,1);
        tf.active=_operation==1;
        return;
    }
    // Convert GPU byte count to ordinary indirect arguments, then reuse the
    // original draw implementation (or the active TF indirect path below).
    auto indirect=mvkTFTemp(encoder,16);
    auto metal=mvkTFCompute(encoder,MVKTFByteCount);
    mvkTFBind(metal,_buffers[0],0);
    uint32_t parameters[]={_counterOffset,_stride,_instances,_firstInstance};
    encoder->setComputeBytes(metal,parameters,sizeof(parameters),1);mvkTFBind(metal,indirect,2);
    mvkTFDispatch(encoder,metal,MVKTFByteCount,1);
    MVKCmdDrawIndirect draw;
    draw.setContent(encoder->_cmdBuffer,indirect.buffer,indirect.offset,1,16);
    draw.encode(encoder);
}

bool mvkTFDraw(MVKCommandEncoder* encoder, uint32_t vertices, uint32_t instances, uint32_t first,
        int32_t baseVertex, uint32_t firstInstance, bool indexed, id<MTLBuffer> input, NSUInteger inputOffset) {
    auto& tf=encoder->_transformFeedback;
    if (!tf.active) return false;
    auto pipeline=encoder->getGraphicsPipeline();
    if (!pipeline->getTransformFeedbackBuffers()) {
        encoder->_cmdBuffer->setConfigurationResult(encoder->reportError(VK_ERROR_FEATURE_NOT_PRESENT,"Active TF requires an Xfb vertex pipeline."));
        return true;
    }
    if (!input && (!vertices || !instances)) return true;
    uint64_t capacity=input ? 128*1024 : uint64_t(vertices)*instances;
    if (capacity > UINT32_MAX/3 || capacity*pipeline->getTransformFeedbackCaptureStride() > encoder->getMetalFeatures().maxMTLBufferSize) {
        encoder->_cmdBuffer->setConfigurationResult(encoder->reportError(VK_ERROR_OUT_OF_DEVICE_MEMORY,"Transform feedback scratch allocation exceeds native buffer size."));return true;
    }
    uint32_t topology=pipeline->getVkPrimitiveTopology();
    if (topology>VK_PRIMITIVE_TOPOLOGY_TRIANGLE_FAN) return true;
    auto index=encoder->getVkGraphics()._indexBuffer;
    uint32_t indexType=indexed ? (index.mtlIndexType==MTLIndexTypeUInt16 ? 16 : 32) : 0;
    trames::tf::Parameters params{};
    params.vertices=vertices;params.instances=instances;params.topology=topology;
    params.restart=indexed && encoder->getVkGraphics().isPrimitiveRestartEnabled();
    params.index_type=indexType;params.buffers=pipeline->getTransformFeedbackBuffers();params.map_capacity=uint32_t(capacity*3);
    for (uint32_t b=0;b<4;++b) {
        params.strides[b]=pipeline->getTransformFeedbackStrides()[b];
        if (params.buffers&(1u<<b)) {
            if (!tf.outputs[b].buffer || tf.outputs[b].size>(64u<<20)) {
                encoder->_cmdBuffer->setConfigurationResult(encoder->reportError(VK_ERROR_VALIDATION_FAILED_EXT,"Transform feedback output binding is missing or too large."));return true;
            }
            params.sizes[b]=uint32_t(tf.outputs[b].size);
        }
    }
    auto rows=mvkTFScratch(encoder,tf.rows,capacity*pipeline->getTransformFeedbackCaptureStride());
    auto map=mvkTFScratch(encoder,tf.map,capacity*12);
    auto draw=mvkTFScratch(encoder,tf.draw,64);
    auto arguments=mvkTFScratch(encoder,tf.arguments,160);
    auto copiedIndices=indexed ? mvkTFScratch(encoder,tf.indices,capacity*(indexType/8)) : tf.counters;
    auto safeIndices=indexed ? mvkTFScratch(encoder,tf.safeIndices,capacity*(indexType/8)) : tf.counters;
    if (!input) {
        uint32_t values[]={vertices,instances,first,indexed ? uint32_t(baseVertex) : firstInstance,firstInstance};
        auto allocation=encoder->copyToTempMTLBufferAllocation(values,indexed ? 20 : 16);
        input=allocation->_mtlBuffer;inputOffset=allocation->_offset;
    }
    auto vertexState=!indexed ? pipeline->getTessVertexStageState() : indexType==16 ?
        pipeline->getTessVertexStageIndex16State() : pipeline->getTessVertexStageIndex32State();
    uint32_t config[]={uint32_t(indexed),uint32_t(vertexState.threadExecutionWidth),0,0};
    // No CPU draw/count readback. A bounded emulation allocation failure must
    // still surface through the original device/fence error mechanism instead
    // of silently dropping a valid draw. Only this one error flag reaches CPU.
    if (!tf.fault) {
        id<MTLBuffer> fault=[encoder->getMTLDevice() newBufferWithLength:4 options:MTLResourceStorageModeShared];
        if (!fault) { encoder->_cmdBuffer->setConfigurationResult(VK_ERROR_OUT_OF_DEVICE_MEMORY);return true; }
        *(uint32_t*)fault.contents=0;tf.fault=fault;
        MVKDevice* device=encoder->getDevice();
        [encoder->_mtlCmdBuffer addCompletedHandler:^(id<MTLCommandBuffer>) {
            if (*(uint32_t*)fault.contents) {
                device->reportError(VK_ERROR_OUT_OF_DEVICE_MEMORY,"Indirect transform feedback exceeded its native GPU scratch allocation.");
                device->markLost();
            }
            [fault release];
        }];
    }
    auto metal=mvkTFCompute(encoder,MVKTFParameters);
    encoder->setComputeBytes(metal,&params,sizeof(params),0);
    [metal setBuffer:input offset:inputOffset atIndex:1];mvkTFBind(metal,arguments,2);
    encoder->setComputeBytes(metal,config,sizeof(config),3);[metal setBuffer:tf.fault offset:0 atIndex:4];
    [metal setBuffer:(indexed ? index.mtlBuffer : tf.fault) offset:(indexed ? index.offset : 0) atIndex:5];
    mvkTFDispatch(encoder,metal,MVKTFParameters,1);
    if (indexed) {
        uint32_t kind=indexType==16 ? MVKTFCopyIndices16 : MVKTFCopyIndices32;
        metal=mvkTFCompute(encoder,kind);
        [metal setBuffer:index.mtlBuffer offset:index.offset atIndex:0];
        [metal setBuffer:arguments.buffer offset:arguments.offset+64 atIndex:1];mvkTFBind(metal,copiedIndices,2);mvkTFBind(metal,safeIndices,3);
        mvkTFDispatch(encoder,metal,kind,capacity);
    }
    std::vector<std::pair<uint32_t,MVKTFBuffer>> constantInputs;
    for (const auto& binding : pipeline->getZeroDivisorVertexBindings()) {
        if (!binding.second) continue;
        uint32_t sourceBinding=binding.first, translation=0;
        for (const auto& entry : pipeline->getTranslatedVertexBindings())
            if (entry.translationBinding==binding.first) { sourceBinding=entry.binding;translation=entry.translationOffset;break; }
        const auto& source=encoder->getVkGraphics()._vertexBuffers[sourceBinding];
        auto copy=mvkTFTemp(encoder,binding.second);
        metal=mvkTFCompute(encoder,MVKTFVertexConstant);
        [metal setBuffer:source.mtlBuffer offset:source.offset+translation atIndex:0];mvkTFBind(metal,copy,1);
        [metal setBuffer:arguments.buffer offset:arguments.offset+64 atIndex:2];
        encoder->setComputeBytes(metal,&binding.second,4,3);mvkTFDispatch(encoder,metal,MVKTFVertexConstant,binding.second);
        constantInputs.emplace_back(pipeline->getMetalBufferIndexForVertexAttributeBinding(binding.first),copy);
    }
    encoder->_isIndexedDraw=indexed;
    encoder->finalizeDrawState(kMVKGraphicsStageVertex);
    metal=encoder->getMTLComputeEncoder(kMVKCommandUseTessellationVertexTessCtl);
    [metal setComputePipelineState:vertexState];
    for (const auto& binding : constantInputs) mvkTFBind(metal,binding.second,binding.first);
    auto& implicit=pipeline->getImplicitBuffers(kMVKShaderStageVertex).ids;
    mvkTFBind(metal,rows,implicit[MVKImplicitBuffer::Output]);
    mvkTFBind(metal,safeIndices,implicit[MVKImplicitBuffer::Index]);
    mvkTFBind(metal,copiedIndices,implicit[MVKImplicitBuffer::PatchOutput]);
    [metal setBuffer:arguments.buffer offset:arguments.offset+64 atIndex:implicit[MVKImplicitBuffer::IndirectParams]];
    if (pipeline->needsDrawIdBuffer()) {
        uint32_t id=0;encoder->setComputeBytes(metal,&id,4,implicit[MVKImplicitBuffer::DrawId]);
    }
    // Same native stage-in/indirect dispatch contract used by upstream tessellation.
    [metal setStageInRegion:MTLRegionMake2D(0,0,capacity,capacity)];
    [metal setStageInRegionWithIndirectBuffer:arguments.buffer indirectBufferOffset:arguments.offset+96];
    [metal dispatchThreadgroupsWithIndirectBuffer:arguments.buffer indirectBufferOffset:arguments.offset+120
                           threadsPerThreadgroup:MTLSizeMake(vertexState.threadExecutionWidth,1,1)];
    encoder->endCurrentMetalEncoding();

    metal=mvkTFCompute(encoder,MVKTFAssemble);
    mvkTFBind(metal,arguments,0);mvkTFBind(metal,copiedIndices,1);mvkTFBind(metal,map,2);
    mvkTFBind(metal,draw,3);mvkTFBind(metal,tf.counters,4);
    // Indirect raster args need separate storage from dispatch words 8..13.
    auto rasterArguments=mvkTFTemp(encoder,16);mvkTFBind(metal,rasterArguments,5);
    mvkTFDispatch(encoder,metal,MVKTFAssemble,1);
    auto scatter=pipeline->getTransformFeedbackScatterState();
    auto mapState=encoder->getCommandEncodingPool()->getTransformFeedbackPipeline(MVKTFMap);
    uint32_t widths[]={uint32_t(mapState.threadExecutionWidth),uint32_t(scatter.threadExecutionWidth)};
    metal=mvkTFCompute(encoder,MVKTFDispatch);mvkTFBind(metal,draw,0);
    encoder->setComputeBytes(metal,widths,sizeof(widths),1);mvkTFDispatch(encoder,metal,MVKTFDispatch,1);
    metal=mvkTFCompute(encoder,MVKTFMap);mvkTFBind(metal,arguments,0);mvkTFBind(metal,draw,1);mvkTFBind(metal,map,2);
    [metal dispatchThreadgroupsWithIndirectBuffer:draw.buffer indirectBufferOffset:draw.offset+32
                           threadsPerThreadgroup:MTLSizeMake(mapState.threadExecutionWidth,1,1)];
    encoder->endCurrentMetalEncoding();
    metal=encoder->getMTLComputeEncoder(kMVKCommandUseTessellationVertexTessCtl);
    [metal setComputePipelineState:scatter];mvkTFBind(metal,rows,0);mvkTFBind(metal,map,1);mvkTFBind(metal,draw,2);
    for(uint32_t b=0;b<4;++b)mvkTFBind(metal,tf.outputs[b].buffer ? tf.outputs[b] : tf.counters,3+b);
    [metal dispatchThreadgroupsWithIndirectBuffer:draw.buffer indirectBufferOffset:draw.offset+44
                           threadsPerThreadgroup:MTLSizeMake(scatter.threadExecutionWidth,1,1)];
    encoder->endCurrentMetalEncoding();
    if (tf.query) {
        uint32_t primitiveSize=topology==0 ? 1 : topology<=2 ? 2 : 3;
        metal=mvkTFCompute(encoder,MVKTFQueryAccumulate);mvkTFBind(metal,draw,0);
        [metal setBuffer:tf.query->results() offset:tf.queryIndex*16 atIndex:1];
        encoder->setComputeBytes(metal,&primitiveSize,4,2);mvkTFDispatch(encoder,metal,MVKTFQueryAccumulate,1);
    }
    if (pipeline->getTransformFeedbackReplayState()) {
        encoder->beginMetalRenderPass(kMVKCommandUseRestartSubpass);
        encoder->finalizeDrawState(kMVKGraphicsStageRasterization);
        [encoder->_mtlRenderEncoder setRenderPipelineState:pipeline->getTransformFeedbackReplayState()];
        [encoder->_mtlRenderEncoder setVertexBuffer:rows.buffer offset:rows.offset atIndex:0];
        [encoder->_mtlRenderEncoder setVertexBuffer:map.buffer offset:map.offset atIndex:1];
        MTLPrimitiveType primitive=topology==0 ? MTLPrimitiveTypePoint : topology<=2 ? MTLPrimitiveTypeLine : MTLPrimitiveTypeTriangle;
        [encoder->_mtlRenderEncoder drawPrimitives:primitive indirectBuffer:rasterArguments.buffer indirectBufferOffset:rasterArguments.offset];
        encoder->encodeStoreActions(true);encoder->endCurrentMetalEncoding();
    }
    // No user descriptors may stay aliased by the internal compute/replay bindings.
    encoder->beginMetalRenderPass(kMVKCommandUseRestartSubpass);
    return true;
}
