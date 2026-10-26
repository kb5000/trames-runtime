// SPDX-License-Identifier: GPL-3.0-or-later
MVK_PUBLIC_VULKAN_SYMBOL void vkCmdBindTransformFeedbackBuffersEXT(VkCommandBuffer command,uint32_t first,
        uint32_t count,const VkBuffer* buffers,const VkDeviceSize* offsets,const VkDeviceSize* sizes) {
    MVKAddCmd(TransformFeedback,command,0,first,count,buffers,offsets,sizes);
}
MVK_PUBLIC_VULKAN_SYMBOL void vkCmdBeginTransformFeedbackEXT(VkCommandBuffer command,uint32_t first,
        uint32_t count,const VkBuffer* buffers,const VkDeviceSize* offsets) {
    MVKAddCmd(TransformFeedback,command,1,first,count,buffers,offsets,nullptr);
}
MVK_PUBLIC_VULKAN_SYMBOL void vkCmdEndTransformFeedbackEXT(VkCommandBuffer command,uint32_t first,
        uint32_t count,const VkBuffer* buffers,const VkDeviceSize* offsets) {
    MVKAddCmd(TransformFeedback,command,2,first,count,buffers,offsets,nullptr);
}
MVK_PUBLIC_VULKAN_SYMBOL void vkCmdDrawIndirectByteCountEXT(VkCommandBuffer command,uint32_t instances,
        uint32_t firstInstance,VkBuffer buffer,VkDeviceSize offset,uint32_t counterOffset,uint32_t stride) {
    MVKAddCmd(TransformFeedback,command,3,0,1,&buffer,&offset,nullptr,instances,firstInstance,counterOffset,stride);
}
MVK_PUBLIC_VULKAN_SYMBOL void vkCmdBeginQueryIndexedEXT(VkCommandBuffer command,VkQueryPool pool,
        uint32_t query,VkQueryControlFlags flags,uint32_t index) {
    if (index) { MVKCommandBuffer::getMVKCommandBuffer(command)->setConfigurationResult(VK_ERROR_FEATURE_NOT_PRESENT);return; }
    MVKAddCmd(BeginQuery,command,pool,query,flags);
}
MVK_PUBLIC_VULKAN_SYMBOL void vkCmdEndQueryIndexedEXT(VkCommandBuffer command,VkQueryPool pool,uint32_t query,uint32_t index) {
    if (index) { MVKCommandBuffer::getMVKCommandBuffer(command)->setConfigurationResult(VK_ERROR_FEATURE_NOT_PRESENT);return; }
    MVKAddCmd(EndQuery,command,pool,query);
}
