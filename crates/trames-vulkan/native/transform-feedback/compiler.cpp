// SPDX-License-Identifier: GPL-3.0-or-later
#include "compiler.hpp"
#include <algorithm>
#include <map>
#include <set>
#include <tuple>

using namespace SPIRV_CROSS_NAMESPACE;
using namespace spv;
namespace trames { namespace tf {
namespace {
constexpr uint32_t none = ~0u;
void require(bool condition, const char* reason) {
    if (!condition) SPIRV_CROSS_THROW(reason);
}
}

bool Compiler::Semantic::operator<(const Semantic& b) const {
    return std::tie(builtin, location, component) < std::tie(b.builtin, b.location, b.component);
}

void Compiler::reflect_stride(uint32_t buffer, uint32_t stride) {
    require(buffer < 4, "Transform feedback buffer index exceeds four buffers.");
    require(stride && stride <= 2048 && !(stride & 3), "Unsupported transform feedback stride.");
    require(!program_.strides[buffer] || program_.strides[buffer] == stride,
            "Conflicting transform feedback strides.");
    program_.strides[buffer] = stride;
    program_.buffers |= 1u << buffer;
}

uint32_t Compiler::reflect_value(const SPIRType& type, Semantic semantic, uint32_t buffer, uint32_t offset) {
    require(type.width == 32 && (type.basetype == SPIRType::Float || type.basetype == SPIRType::Int ||
            type.basetype == SPIRType::UInt), "Transform feedback requires 32-bit numeric outputs.");
    require(type.basetype != SPIRType::Struct, "Nested transform feedback interface structs are unsupported.");
    if (!type.array.empty()) {
        require(type.array_size_literal.back() && type.array.back() && type.array.back() <= 512,
                "Transform feedback array must have a bounded literal size.");
        const auto& element = get<SPIRType>(type.parent_type);
        uint32_t used = 0;
        for (uint32_t i = 0; i < type.array.back(); ++i) {
            auto sub = semantic;
            if (sub.builtin == none) sub.location += i * type_to_location_count(element);
            else sub.component += i * element.vecsize * element.columns;
            used += reflect_value(element, sub, buffer, offset + used);
        }
        return used;
    }
    require(semantic.builtin != none || semantic.component + type.vecsize <= 4,
            "Transform feedback component exceeds an interface location.");
    for (uint32_t column = 0; column < type.columns; ++column) {
        for (uint32_t component = 0; component < type.vecsize; ++component) {
            auto sub = semantic;
            if (sub.builtin == none) sub.location += column;
            sub.component += component;
            require(scalars_.size() < 2048, "Transform feedback output is too large.");
            scalars_.push_back({sub, buffer, offset + 4 * (column * type.vecsize + component)});
        }
    }
    return 4 * type.columns * type.vecsize;
}

void Compiler::reflect_outputs() {
    require(get_execution_model() == ExecutionModelVertex && get_entry_point().flags.get(ExecutionModeXfb),
            "Transform feedback requires a vertex entry point with Xfb execution mode.");
    std::set<std::pair<uint32_t, uint32_t>> occupied;
    for (auto id : get_entry_point().interface_variables) {
        const auto& var = get<SPIRVariable>(id);
        if (var.storage != StorageClassOutput) continue;
        const auto& type = get_variable_data_type(var);
        require(!get_decoration(id, DecorationStream), "Only transform feedback stream zero is supported.");
        if (type.basetype == SPIRType::Struct) {
            require(type.array.empty(), "Arrayed transform feedback blocks are unsupported.");
            for (uint32_t i = 0; i < type.member_types.size(); ++i) {
                if (!has_member_decoration(type.self, i, DecorationOffset)) continue;
                require(!get_member_decoration(type.self, i, DecorationStream), "Only stream zero is supported.");
                auto buffer = has_member_decoration(type.self, i, DecorationXfbBuffer)
                    ? get_member_decoration(type.self, i, DecorationXfbBuffer) : get_decoration(id, DecorationXfbBuffer);
                auto stride = has_member_decoration(type.self, i, DecorationXfbStride)
                    ? get_member_decoration(type.self, i, DecorationXfbStride) : get_decoration(id, DecorationXfbStride);
                reflect_stride(buffer, stride);
                bool builtin = has_member_decoration(type.self, i, DecorationBuiltIn);
                require(builtin || has_member_decoration(type.self, i, DecorationLocation), "Missing TF member location.");
                reflect_value(get<SPIRType>(type.member_types[i]),
                    {builtin ? 0 : get_member_decoration(type.self, i, DecorationLocation),
                     get_member_decoration(type.self, i, DecorationComponent),
                     builtin ? get_member_decoration(type.self, i, DecorationBuiltIn) : none}, buffer,
                    get_member_decoration(type.self, i, DecorationOffset));
            }
        } else if (has_decoration(id, DecorationOffset)) {
            require(has_decoration(id, DecorationXfbBuffer) && has_decoration(id, DecorationXfbStride),
                    "Missing transform feedback buffer/stride.");
            auto buffer = get_decoration(id, DecorationXfbBuffer);
            reflect_stride(buffer, get_decoration(id, DecorationXfbStride));
            bool builtin = has_decoration(id, DecorationBuiltIn);
            require(builtin || has_decoration(id, DecorationLocation), "Missing TF output location.");
            reflect_value(type, {builtin ? 0 : get_decoration(id, DecorationLocation),
                get_decoration(id, DecorationComponent), builtin ? get_decoration(id, DecorationBuiltIn) : none},
                buffer, get_decoration(id, DecorationOffset));
        }
    }
    require(!scalars_.empty(), "Vertex entry point has no transform feedback output.");
    for (const auto& scalar : scalars_) {
        require(!(scalar.offset & 3) && scalar.offset < program_.strides[scalar.buffer], "TF output exceeds stride.");
        require(occupied.emplace(scalar.buffer, scalar.offset).second, "Overlapping transform feedback output.");
    }
    program_.scalars = uint32_t(scalars_.size());
}

void Compiler::stage_value(std::map<Semantic, std::string>& values, const SPIRType& type,
                           Semantic semantic, const std::string& expression) {
    require(type.width == 32, "Unsupported captured stage output width.");
    if (!type.array.empty()) {
        uint32_t elements = to_array_size_literal(type);
        require(elements <= 512, "Unsupported captured output array.");
        const auto& element = get<SPIRType>(type.parent_type);
        for (uint32_t i = 0; i < elements; ++i) {
            auto sub = semantic;
            if (sub.builtin == none) sub.location += i * type_to_location_count(element);
            else sub.component += i * element.vecsize * element.columns;
            stage_value(values, element, sub, expression + "[" + std::to_string(i) + "]");
        }
        return;
    }
    for (uint32_t col = 0; col < type.columns; ++col) for (uint32_t c = 0; c < type.vecsize; ++c) {
        auto sub = semantic;
        if (sub.builtin == none) sub.location += col;
        sub.component += c;
        auto value = expression + (type.columns == 1 ? "" : "[" + std::to_string(col) + "]");
        if (type.vecsize > 1) value += std::string(".") + "xyzw"[c];
        values.emplace(sub, value);
    }
}

std::map<Compiler::Semantic, std::string> Compiler::stage_values(const std::string& prefix) {
    const auto& output = get_stage_out_struct_type();
    std::map<Semantic, std::string> expressions;
    for (uint32_t i = 0; i < output.member_types.size(); ++i) {
        const auto& type = get<SPIRType>(output.member_types[i]);
        BuiltIn builtin;
        bool built = is_member_builtin(output, i, &builtin);
        uint32_t location = built ? 0 : get_member_decoration(output.self, i, DecorationLocation);
        uint32_t component = built && has_member_decoration(output.self, i, DecorationIndex)
            ? get_member_decoration(output.self, i, DecorationIndex) : get_member_decoration(output.self, i, DecorationComponent);
        stage_value(expressions, type, {location, component, built ? uint32_t(builtin) : none},
                    prefix + "." + to_member_name(output, i));
    }
    return expressions;
}

void Compiler::append_helpers(Compiler& raster) {
    const auto& output = get_stage_out_struct_type();
    // Use the original compiler's Metal ABI size/alignment rules, including
    // float3 and matrix/array padding. Scratch is exact rather than a guessed
    // maxVertexOutputComponents * 4 bytes.
    uint32_t stride = 0, alignment = 1;
    for (auto member : output.member_types) {
        uint32_t a = get_declared_type_alignment_msl(member, nullptr, false, false);
        alignment = std::max(alignment, a);
        stride = (stride + a - 1) & ~(a - 1);
        stride += get_declared_type_size_msl(member, nullptr, false, false);
    }
    program_.capture_stride = (stride + alignment - 1) & ~(alignment - 1);
    auto expressions = stage_values("out");
    buffer.reset();
    statement("kernel void trames_tf_scatter(const device ", type_to_glsl(output), "* rows [[buffer(0)]],");
    statement("const device uint* map [[buffer(1)]], const device uint* draw [[buffer(2)]],");
    statement("device uint* b0 [[buffer(3)]], device uint* b1 [[buffer(4)]],");
    statement("device uint* b2 [[buffer(5)]], device uint* b3 [[buffer(6)]], uint i [[thread_position_in_grid]])");
    begin_scope();
    statement("if (i >= draw[0]) return;");
    statement("const device auto& out = rows[map[i]];");
    for (const auto& scalar : scalars_) {
        auto found = expressions.find(scalar.semantic);
        require(found != expressions.end(), "Original compiler did not preserve a transform feedback output.");
        statement("b", scalar.buffer, "[draw[", 4 + scalar.buffer, "] / 4u + i * ",
                  program_.strides[scalar.buffer] / 4, "u + ", scalar.offset / 4, "u] = as_type<uint>(", found->second, ");");
    }
    end_scope();
    statement("");
    // Use the original compiler's *raster* interface too. Its capture interface
    // deliberately keeps matrix/array fields, whereas Metal vertex outputs
    // require the original flattening and interpolation/builtin qualifiers.
    raster.buffer.reset();
    raster.set_name(raster.get_stage_out_struct_type().self, "trames_tf_raster_out");
    raster.emit_interface_block(raster.stage_out_var_id);
    statement(raster.buffer.str());
    statement("vertex trames_tf_raster_out trames_tf_replay(uint i [[vertex_id]],");
    statement("const device ", type_to_glsl(output), "* rows [[buffer(0)]], const device uint* map [[buffer(1)]])");
    begin_scope();
    statement("const device auto& out = rows[map[i]];");
    statement("trames_tf_raster_out raster;");
    for (const auto& scalar : raster.stage_values("raster")) {
        auto found = expressions.find(scalar.first);
        require(found != expressions.end(), "Captured output cannot supply the raster interface.");
        statement(scalar.second, " = ", found->second, ";");
    }
    const auto& raster_output = raster.get_stage_out_struct_type();
    for (uint32_t i = 0; i < raster_output.member_types.size(); ++i) {
        BuiltIn builtin;
        if (!raster.is_member_builtin(raster_output, i, &builtin) || builtin != BuiltInPosition) continue;
        auto position = "raster." + raster.to_member_name(raster_output, i);
        if (options.vertex.flip_vert_y) statement(position, ".y = -", position, ".y;");
        if (options.vertex.fixup_clipspace) statement(position, ".z = (", position, ".z + ", position, ".w) * 0.5;");
    }
    statement("return raster;");
    end_scope();
    program_.source += buffer.str();
}

Program Compiler::compile_feedback() {
    require(scalars_.empty(), "Transform feedback compiler cannot be reused.");
    reflect_outputs();
    msl_options.capture_output_to_buffer = true;
    msl_options.vertex_for_tessellation = true;
    msl_options.disable_rasterization = true;
    // Vulkan captures the unmodified vertex output. Coordinate fixes belong in
    // replay, never in the data captured for the application.
    Compiler raster(ir);
    if (raster_configuration_) raster_configuration_(raster);
    auto raster_options = msl_options;
    raster_options.capture_output_to_buffer = false;
    raster_options.vertex_for_tessellation = false;
    raster_options.disable_rasterization = false;
    raster.set_msl_options(raster_options);
    raster.CompilerMSL::compile();
    auto original_common = options;
    options.vertex.flip_vert_y = false;
    options.vertex.fixup_clipspace = false;
    auto original_entry = get_entry_point().name;
    program_.source = CompilerMSL::compile();
    program_.capture_entry = get_cleansed_entry_point_name(original_entry, ExecutionModelVertex);
    options = original_common;
    append_helpers(raster);
    return program_;
}

Program Compiler::describe_feedback() {
    require(scalars_.empty(), "Transform feedback compiler cannot be reused.");
    reflect_outputs();return program_;
}

std::string Compiler::runtime_arguments() {
    if (!runtime_parameters_ || !processing_entry_point) return "";
    auto arguments = join(", constant uint* tramesTFDraw [[buffer(", msl_options.indirect_params_buffer_index, ")]]");
    if (msl_options.vertex_index_type != Options::IndexType::None)
        arguments += join(", const device ", msl_options.vertex_index_type == Options::IndexType::UInt16 ? "ushort" : "uint",
                          "* tramesTFIndices [[buffer(", msl_options.shader_patch_output_buffer_index, ")]]");
    return arguments;
}
std::string Compiler::entry_point_args_classic(bool comma) {
    return CompilerMSL::entry_point_args_classic(comma) + runtime_arguments();
}
std::string Compiler::entry_point_args_argument_buffer(bool comma) {
    return CompilerMSL::entry_point_args_argument_buffer(comma) + runtime_arguments();
}
void Compiler::emit_function_prototype(SPIRFunction& function, const Bitset& flags) {
    // The original compiler has already installed builtin/local fixups. Append
    // this before body emission, exactly once even if it recompiles the source.
    if (runtime_parameters_ && !runtime_hook_installed_ && function.self == ir.default_entry_point) {
        runtime_hook_installed_ = true;
        function.fixup_hooks_in.insert(function.fixup_hooks_in.begin(), [this]() {
            auto gid = to_expression(builtin_invocation_id_id);
            statement(to_expression(builtin_stage_input_size_id), " = uint3(tramesTFDraw[0], tramesTFDraw[1], 1);");
            statement("if (", gid, ".x >= tramesTFDraw[0] || ", gid, ".y >= tramesTFDraw[1]) return;");
            if (msl_options.vertex_index_type != Options::IndexType::None)
                statement("if (tramesTFDraw[5] && tramesTFIndices[", gid, ".x] == ",
                          msl_options.vertex_index_type == Options::IndexType::UInt16 ? "0xffffu" : "0xffffffffu", ") return;");
        });
    }
    CompilerMSL::emit_function_prototype(function, flags);
}
}}
