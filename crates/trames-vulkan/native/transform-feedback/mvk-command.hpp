// SPDX-License-Identifier: GPL-3.0-or-later
// Included after MVKCmdDraw declarations, with the original MVKCommand base.
class MVKCmdTransformFeedback : public MVKCommand {
public:
    VkResult setContent(MVKCommandBuffer*, uint32_t operation, uint32_t first, uint32_t count,
                        const VkBuffer* buffers, const VkDeviceSize* offsets, const VkDeviceSize* sizes,
                        uint32_t instances = 0, uint32_t firstInstance = 0,
                        uint32_t counterOffset = 0, uint32_t stride = 0);
    void encode(MVKCommandEncoder*) override;
protected:
    MVKCommandTypePool<MVKCommand>* getTypePool(MVKCommandPool*) override;
    MVKTFBuffer _buffers[4];
    uint32_t _operation, _first, _count, _instances, _firstInstance, _counterOffset, _stride;
};
