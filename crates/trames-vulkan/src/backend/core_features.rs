// SPDX-License-Identifier: GPL-3.0-or-later
//! Selected core features, shared by discovery and native device creation.
use super::*;

macro_rules! core_features {
    ($($bit:literal => $field:ident),+ $(,)?) => {
        pub(super) fn encode(native: vk::PhysicalDeviceFeatures) -> Vec<u8> {
            let mut bytes = vec![0; std::mem::size_of::<vk::PhysicalDeviceFeatures>()];
            $(let offset = std::mem::offset_of!(vk::PhysicalDeviceFeatures, $field);
            bytes[offset..offset + 4].copy_from_slice(&native.$field.to_le_bytes());)+
            bytes
        }
        pub(super) fn supported(native: vk::PhysicalDeviceFeatures) -> vk::PhysicalDeviceFeatures {
            vk::PhysicalDeviceFeatures { $($field: native.$field,)+ ..Default::default() }
        }
        pub(super) fn select(native: vk::PhysicalDeviceFeatures, bits: u64) -> Result<vk::PhysicalDeviceFeatures> {
            const MASK: u64 = 0 $(| (1 << $bit))+;
            if bits & !MASK != 0 { return unsupported(); }
            let mut enabled = vk::PhysicalDeviceFeatures::default();
            $(if bits & (1 << $bit) != 0 {
                if native.$field == 0 { return unsupported(); }
                enabled.$field = vk::TRUE;
            })+
            Ok(enabled)
        }
    }
}
// Bits 0..6 retain their original wire meaning. New bits are additive.
core_features! {
    0 => sampler_anisotropy,
    1 => logic_op,
    2 => fill_mode_non_solid,
    3 => shader_clip_distance,
    4 => independent_blend,
    5 => image_cube_array,
    6 => sample_rate_shading,
    7 => shader_image_gather_extended,
    8 => shader_storage_image_extended_formats,
    9 => shader_storage_image_read_without_format,
    10 => shader_storage_image_write_without_format,
    11 => vertex_pipeline_stores_and_atomics,
    12 => fragment_stores_and_atomics,
    13 => shader_uniform_buffer_array_dynamic_indexing,
    14 => shader_sampled_image_array_dynamic_indexing,
    15 => shader_storage_buffer_array_dynamic_indexing,
    16 => shader_storage_image_array_dynamic_indexing,
    17 => multi_draw_indirect,
    18 => draw_indirect_first_instance,
    19 => texture_compression_etc2,
    20 => texture_compression_astc_ldr,
    21 => texture_compression_bc,
    22 => shader_int16,
    23 => shader_int64,
    24 => alpha_to_one,
    25 => robust_buffer_access,
    26 => full_draw_index_uint32,
    27 => occlusion_query_precise,
}

// Limits describe this executable profile, including disabled optional stages.
// Native limits for a disabled feature must not contradict its feature bit.
pub(super) fn normalize_properties(
    p: &mut vk::PhysicalDeviceProperties,
    native: vk::PhysicalDeviceFeatures,
) {
    let f = supported(native);
    let l = &mut p.limits;
    if f.geometry_shader == 0 {
        l.max_geometry_shader_invocations = 0;
        l.max_geometry_input_components = 0;
        l.max_geometry_output_components = 0;
        l.max_geometry_output_vertices = 0;
        l.max_geometry_total_output_components = 0;
    }
    if f.tessellation_shader == 0 {
        l.max_tessellation_generation_level = 0;
        l.max_tessellation_patch_size = 0;
        l.max_tessellation_control_per_vertex_input_components = 0;
        l.max_tessellation_control_per_vertex_output_components = 0;
        l.max_tessellation_control_per_patch_output_components = 0;
        l.max_tessellation_control_total_output_components = 0;
        l.max_tessellation_evaluation_input_components = 0;
        l.max_tessellation_evaluation_output_components = 0;
    }
    if f.sparse_binding == 0 {
        l.sparse_address_space_size = 0;
    }
    if f.large_points == 0 {
        l.point_size_range = [1.0; 2];
        l.point_size_granularity = 0.0;
    }
    if f.wide_lines == 0 {
        l.line_width_range = [1.0; 2];
        l.line_width_granularity = 0.0;
    }
    if f.multi_viewport == 0 {
        l.max_viewports = 1;
    }
    if f.sampler_anisotropy == 0 {
        l.max_sampler_anisotropy = 1.0;
    }
    if f.shader_image_gather_extended == 0 {
        l.min_texel_gather_offset = 0;
        l.max_texel_gather_offset = 0;
    }
    if f.sample_rate_shading == 0 {
        l.min_interpolation_offset = 0.0;
        l.max_interpolation_offset = 0.0;
        l.sub_pixel_interpolation_offset_bits = 0;
    }
    if f.shader_storage_image_multisample == 0 {
        l.storage_image_sample_counts = vk::SampleCountFlags::TYPE_1;
    }
    if f.shader_clip_distance == 0 {
        l.max_clip_distances = 0;
    }
    if f.shader_cull_distance == 0 {
        l.max_cull_distances = 0;
    }
    l.max_combined_clip_and_cull_distances = l
        .max_combined_clip_and_cull_distances
        .min(l.max_clip_distances + l.max_cull_distances);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn feature_dependent_limits_describe_the_executable_profile() {
        let mut p = vk::PhysicalDeviceProperties::default();
        p.limits.point_size_range = [1.0, 64.0];
        p.limits.point_size_granularity = 0.125;
        p.limits.line_width_range = [1.0, 8.0];
        p.limits.line_width_granularity = 0.25;
        p.limits.max_geometry_output_vertices = 256;
        p.limits.max_clip_distances = 8;
        p.limits.max_cull_distances = 8;
        p.limits.max_combined_clip_and_cull_distances = 8;
        p.limits.max_sampler_anisotropy = 16.0;
        normalize_properties(
            &mut p,
            vk::PhysicalDeviceFeatures::default()
                .large_points(true)
                .geometry_shader(true)
                .shader_clip_distance(true)
                .sampler_anisotropy(true),
        );
        assert_eq!(p.limits.point_size_range, [1.0; 2]);
        assert_eq!(p.limits.point_size_granularity, 0.0);
        assert_eq!(p.limits.line_width_range, [1.0; 2]);
        assert_eq!(p.limits.line_width_granularity, 0.0);
        assert_eq!(p.limits.max_geometry_output_vertices, 0);
        assert_eq!(p.limits.max_clip_distances, 8);
        assert_eq!(p.limits.max_cull_distances, 0);
        assert_eq!(p.limits.max_combined_clip_and_cull_distances, 8);
        assert_eq!(p.limits.max_sampler_anisotropy, 16.0);
    }
    #[test]
    fn selected_features_preserve_legacy_bits_and_require_native_support() {
        let native = vk::PhysicalDeviceFeatures::default()
            .sampler_anisotropy(true)
            .shader_storage_image_extended_formats(true)
            .shader_storage_image_write_without_format(true)
            .fragment_stores_and_atomics(true)
            .texture_compression_astc_ldr(true)
            .geometry_shader(true);
        let bytes = encode(native);
        let field = |offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        assert_eq!(
            field(std::mem::offset_of!(
                vk::PhysicalDeviceFeatures,
                geometry_shader
            )),
            0
        );
        assert_eq!(
            field(std::mem::offset_of!(
                vk::PhysicalDeviceFeatures,
                shader_storage_image_extended_formats
            )),
            vk::TRUE
        );
        let enabled = select(native, 1 | (1 << 8) | (1 << 10) | (1 << 12) | (1 << 20)).unwrap();
        assert_eq!(enabled.sampler_anisotropy, vk::TRUE);
        assert_eq!(enabled.fragment_stores_and_atomics, vk::TRUE);
        assert_eq!(enabled.texture_compression_astc_ldr, vk::TRUE);
        assert_eq!(enabled.geometry_shader, 0);
        assert!(select(native, 2).is_err());
        assert!(select(native, 1 << 63).is_err());
    }
}
