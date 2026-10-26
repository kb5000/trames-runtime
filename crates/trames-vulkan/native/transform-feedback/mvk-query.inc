// SPDX-License-Identifier: GPL-3.0-or-later
MVKTFQueryPool::MVKTFQueryPool(MVKDevice* device,const VkQueryPoolCreateInfo* info)
    : MVKQueryPool(device,info,2) {
    _results=[getMTLDevice() newBufferWithLength:NSUInteger(info->queryCount)*16 options:MTLResourceStorageModeShared];
    if (!_results) setConfigurationResult(reportError(VK_ERROR_OUT_OF_DEVICE_MEMORY,"Cannot allocate TF query results."));
}
MVKTFQueryPool::~MVKTFQueryPool() { [_results release]; }
void MVKTFQueryPool::beginQuery(uint32_t query,VkQueryControlFlags,MVKCommandEncoder* encoder) {
    encoder->_transformFeedback.query=this;encoder->_transformFeedback.queryIndex=query;
    encoder->activateTransformFeedbackQuery(this,query);
    if (encoder->_mtlRenderEncoder) encoder->encodeStoreActions(true);
    auto blit=encoder->getMTLBlitEncoder(kMVKCommandUseResetQueryPool);
    [blit fillBuffer:_results range:NSMakeRange(NSUInteger(query)*16,16) value:0];
    encoder->endCurrentMetalEncoding();
}
void MVKTFQueryPool::endQuery(uint32_t query,MVKCommandEncoder* encoder) {
    encoder->_transformFeedback.query=nullptr;
    MVKQueryPool::endQuery(query,encoder);
}
void MVKTFQueryPool::resetResults(uint32_t first,uint32_t count,MVKCommandEncoder* encoder) {
    MVKQueryPool::resetResults(first,count,encoder);
    if (encoder) {
        auto blit=encoder->getMTLBlitEncoder(kMVKCommandUseResetQueryPool);
        [blit fillBuffer:_results range:NSMakeRange(NSUInteger(first)*16,NSUInteger(count)*16) value:0];
    } else memset((char*)_results.contents+NSUInteger(first)*16,0,NSUInteger(count)*16);
}
NSData* MVKTFQueryPool::getQuerySourceData(uint32_t first,uint32_t count) {
    return [NSData dataWithBytesNoCopy:(char*)_results.contents+NSUInteger(first)*16 length:NSUInteger(count)*16 freeWhenDone:NO];
}
void MVKTFQueryPool::encodeCopyResults(MVKCommandEncoder* encoder,uint32_t first,uint32_t count,MVKBuffer* output,
        VkDeviceSize offset,VkDeviceSize stride,VkQueryResultFlags flags) {
    if (!count) return;
    if (encoder->_mtlRenderEncoder) encoder->encodeStoreActions(true);
    auto metal=encoder->getMTLComputeEncoder(kMVKCommandUseCopyQueryPoolResults);
    auto pipeline=encoder->getCommandEncodingPool()->getTransformFeedbackPipeline(MVKTFQueryCopy);
    [metal setComputePipelineState:pipeline];
    [metal setBuffer:_results offset:NSUInteger(first)*16 atIndex:0];
    [metal setBuffer:output->getMTLBuffer() offset:output->getMTLBufferOffset()+offset atIndex:1];
    uint32_t parameters[]={count,uint32_t(stride),flags,0};encoder->setComputeBytes(metal,parameters,sizeof(parameters),2);
    {
        std::lock_guard<std::mutex> lock(_availabilityLock);
        encoder->setComputeBytes(metal,_availability.data()+first,NSUInteger(count)*sizeof(Status),3);
    }
    NSUInteger width=std::min<NSUInteger>(count,pipeline.threadExecutionWidth);
    [metal dispatchThreadgroups:MTLSizeMake(mvkCeilingDivide<NSUInteger>(count,width),1,1) threadsPerThreadgroup:MTLSizeMake(width,1,1)];
    encoder->endCurrentMetalEncoding();
}
