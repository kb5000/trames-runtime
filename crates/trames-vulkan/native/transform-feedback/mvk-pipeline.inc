// SPDX-License-Identifier: GPL-3.0-or-later
// Compiled inside original MVKPipeline.mm. Keep its shader configuration,
// descriptor scripts, vertex fetch and pipeline lifetime/caching algorithms.
void MVKGraphicsPipeline::initTransformFeedback(const VkGraphicsPipelineCreateInfo* info,
        const SPIRVTessReflectionData& reflection, const VkPipelineShaderStageCreateInfo* vertex,
        VkPipelineCreationFeedback* feedback, MTLRenderPipelineDescriptor* rasterDescriptor) {
    if (!getEnabledTransformFeedbackFeatures().transformFeedback || isTessellationPipeline()) return;
    try {
        trames::tf::Compiler inspect(_vertexModule->getSPIRV());
        inspect.set_entry_point(vertex->pName, spv::ExecutionModelVertex);
        if (!inspect.get_execution_mode_bitset().get(spv::ExecutionModeXfb)) return;
        auto layout = inspect.describe_feedback();
        _tfBuffers = layout.buffers;
        for (uint32_t i = 0; i < 4; ++i) _tfStrides[i] = layout.strides[i];

        SPIRVToMSLConversionConfiguration config;
        initShaderConversionConfig(config, info, reflection);
        config.options.transformFeedback = true;
        auto& implicit = _stageResources[kMVKShaderStageVertex].implicitBuffers.ids;
        config.options.mslOptions.indirect_params_buffer_index = implicit[MVKImplicitBuffer::IndirectParams];
        config.options.mslOptions.shader_patch_output_buffer_index = implicit[MVKImplicitBuffer::PatchOutput];
        MTLComputePipelineDescriptor* descriptor = [MTLComputePipelineDescriptor new];
        MVKMTLFunction functions[3];SPIRVShaderInputs inputs;
        bool valid = addVertexShaderToPipeline(descriptor, info, config, inputs, vertex, feedback, functions);
        _translatedVertexBindings.clear();_zeroDivisorVertexBindings.clear();
        descriptor.stageInputDescriptor = [MTLStageInputOutputDescriptor stageInputOutputDescriptor];
        valid = valid && addVertexInputToPipeline(descriptor.stageInputDescriptor, info->pVertexInputState, config, true);
        descriptor.stageInputDescriptor.indexBufferIndex = implicit[MVKImplicitBuffer::Index];
        descriptor.threadGroupSizeIsMultipleOfThreadExecutionWidth = YES;
        if (valid) valid = compileTessVertexStageState(descriptor, functions, feedback);
        [descriptor release];
        valid = valid && _mtlTessVertexStageState && _mtlTessVertexStageIndex16State && _mtlTessVertexStageIndex32State;
        if (!valid) { _hasValidMTLPipelineStates = false;return; }

        _tfCaptureStride = functions[0].shaderConversionResults.transformFeedbackStride;
        id<MTLLibrary> library = functions[0].getMTLLibrary();
        id<MTLFunction> scatter = [library newFunctionWithName:@"trames_tf_scatter"];
        descriptor = [MTLComputePipelineDescriptor new];descriptor.computeFunction = scatter;
        getOrCompilePipeline(descriptor, _tfScatterState, "Transform feedback output scatter");
        [scatter release];[descriptor release];
        if (_isRasterizing) {
            id<MTLFunction> replay = [library newFunctionWithName:@"trames_tf_replay"];
            MTLRenderPipelineDescriptor* replayDescriptor = [rasterDescriptor copy];
            replayDescriptor.vertexFunction = replay;
            replayDescriptor.vertexDescriptor = [MTLVertexDescriptor vertexDescriptor];
            getOrCompilePipeline(replayDescriptor, _tfReplayState);
            [replay release];[replayDescriptor release];
        }
        // Both extra bindings are genuine vertex-compute implicit buffers.
        _stageResources[kMVKShaderStageVertex].implicitBuffers.needed.add(MVKImplicitBuffer::IndirectParams);
        _stageResources[kMVKShaderStageVertex].implicitBuffers.needed.add(MVKImplicitBuffer::PatchOutput);
        verifyImplicitBuffers(kMVKShaderStageVertex);
    } catch (const SPIRV_CROSS_NAMESPACE::CompilerError& error) {
        setConfigurationResult(reportError(VK_ERROR_FEATURE_NOT_PRESENT, "Transform feedback shader: %s", error.what()));
        _hasValidMTLPipelineStates = false;
    }
}
