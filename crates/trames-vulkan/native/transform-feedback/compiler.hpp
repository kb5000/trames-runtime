// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "spirv_msl.hpp"
#include <array>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace trames { namespace tf {
// Compiles GPU shaders only. The original SPIRV-Cross vertex-as-compute
// lowering, resource accesses and vertex fetch remain unchanged. No CPU JIT.
struct Program {
    std::string source;
    std::string capture_entry;
    std::array<uint32_t, 4> strides{};
    uint32_t buffers = 0;
    uint32_t scalars = 0;
    uint32_t capture_stride = 0;
};

class Compiler : public SPIRV_CROSS_NAMESPACE::CompilerMSL {
public:
    using CompilerMSL::CompilerMSL;
    // Configure resources, stage inputs, index type and specialization through
    // the original CompilerMSL API before calling this exactly once.
    Program compile_feedback();
    Program describe_feedback();
    void configure_raster(std::function<void(SPIRV_CROSS_NAMESPACE::CompilerMSL&)> configure) { raster_configuration_ = std::move(configure); }
    void enable_runtime_parameters() { runtime_parameters_ = true; }
private:
    std::function<void(SPIRV_CROSS_NAMESPACE::CompilerMSL&)> raster_configuration_;
    bool runtime_parameters_ = false;
    bool runtime_hook_installed_ = false;
    struct Semantic {
        uint32_t location, component, builtin;
        bool operator<(const Semantic& b) const;
    };
    struct Scalar { Semantic semantic; uint32_t buffer, offset; };
    std::vector<Scalar> scalars_;
    Program program_;
    void reflect_outputs();
    uint32_t reflect_value(const SPIRV_CROSS_NAMESPACE::SPIRType& type, Semantic semantic,
                           uint32_t buffer, uint32_t offset);
    void reflect_stride(uint32_t buffer, uint32_t stride);
    std::map<Semantic, std::string> stage_values(const std::string& prefix);
    void stage_value(std::map<Semantic, std::string>& values, const SPIRV_CROSS_NAMESPACE::SPIRType& type,
                     Semantic semantic, const std::string& expression);
    void append_helpers(Compiler& raster);
    std::string entry_point_args_classic(bool append_comma) override;
    std::string entry_point_args_argument_buffer(bool append_comma) override;
    void emit_function_prototype(SPIRV_CROSS_NAMESPACE::SPIRFunction& function, const SPIRV_CROSS_NAMESPACE::Bitset& flags) override;
    std::string runtime_arguments();
};
}}
