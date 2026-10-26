// SPDX-License-Identifier: GPL-3.0-or-later
// Included after the original MVKQueryPool declarations.
class MVKTFQueryPool : public MVKQueryPool {
public:
    MVKTFQueryPool(MVKDevice*, const VkQueryPoolCreateInfo*);
    ~MVKTFQueryPool() override;
    void beginQuery(uint32_t, VkQueryControlFlags, MVKCommandEncoder*) override;
    void endQuery(uint32_t, MVKCommandEncoder*) override;
    void resetResults(uint32_t, uint32_t, MVKCommandEncoder*) override;
    void encodeCopyResults(MVKCommandEncoder*, uint32_t, uint32_t, MVKBuffer*, VkDeviceSize,
                           VkDeviceSize, VkQueryResultFlags) override;
    id<MTLBuffer> results() { return _results; }
protected:
    NSData* getQuerySourceData(uint32_t, uint32_t) override;
    void propagateDebugName() override { setMetalObjectLabel(_results, _debugName); }
    id<MTLBuffer> _results;
};
