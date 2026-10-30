// SPDX-License-Identifier: GPL-3.0-or-later
//! Promoted features use original driver extension entrypoints on the 1.0 host
//! instance. Only copied scalar/array payloads cross the guest boundary.
use super::*;

pub(super) const MAINTENANCE1: u64 = 1;
pub(super) const TIMELINE: u64 = 2;
pub(super) const DRIVER_PROPERTIES: u64 = 4;
pub(super) const MAINTENANCE2: u64 = 8;
pub(super) const MULTIVIEW: u64 = 16;
pub(super) const FORMAT_LIST: u64 = 32;
pub(super) const RENDERPASS2: u64 = 64;
pub(super) const IMAGELESS: u64 = 128;
pub(super) const SCALAR_LAYOUT: u64 = 256;
pub(super) const PORTABILITY: u64 = 512;
pub(super) const TRANSFORM_FEEDBACK: u64 = 1024;
pub(super) const VERTEX_DIVISOR: u64 = 2048;
pub(super) const ZERO_DIVISOR: u64 = 4096;

#[derive(Clone, Copy)]
pub(super) struct Divisor {
    pub maximum: u32,
    pub zero: bool,
}

#[derive(Default)]
pub(super) struct Capabilities {
    pub bits: u64,
    pub max_timeline_difference: u64,
    point_clipping: u32,
    pub portability: Option<vk::PhysicalDevicePortabilitySubsetFeaturesKHR<'static>>,
    portability_stride: u32,
    driver: Option<vk::PhysicalDeviceDriverProperties<'static>>,
    pub feedback: Option<vk::PhysicalDeviceTransformFeedbackPropertiesEXT<'static>>,
    pub divisor: Option<Divisor>,
}
impl Capabilities {
    pub fn query(instance: &Instance, physical: vk::PhysicalDevice) -> Result<Self> {
        let ext = unsafe {
            instance
                .native
                .enumerate_device_extension_properties(physical)
        }?;
        let has = |name: &std::ffi::CStr| {
            ext.iter()
                .any(|e| unsafe { std::ffi::CStr::from_ptr(e.extension_name.as_ptr()) == name })
        };
        let mut result = Self::default();
        if has(ash::khr::maintenance1::NAME) {
            result.bits |= MAINTENANCE1;
        }
        if instance.queries2 && has(ash::khr::maintenance2::NAME) {
            result.bits |= MAINTENANCE2;
        }
        // Multiview remains disabled in the selected single-layer profile.
        if has(ash::khr::multiview::NAME) {
            result.bits |= MULTIVIEW;
        }
        if has(ash::khr::image_format_list::NAME) {
            result.bits |= FORMAT_LIST;
        }
        if result.bits & (MAINTENANCE2 | MULTIVIEW) == MAINTENANCE2 | MULTIVIEW
            && has(ash::khr::create_renderpass2::NAME)
        {
            result.bits |= RENDERPASS2;
        }
        if !instance.queries2 {
            return Ok(result);
        }
        let queries = ash::khr::get_physical_device_properties2::Instance::new(
            &instance._entry,
            &instance.native,
        );
        if has(ash::ext::vertex_attribute_divisor::NAME) {
            let mut divisor = vk::PhysicalDeviceVertexAttributeDivisorFeaturesEXT::default();
            let mut features = vk::PhysicalDeviceFeatures2::default().push_next(&mut divisor);
            unsafe { queries.get_physical_device_features2(physical, &mut features) };
            if divisor.vertex_attribute_instance_rate_divisor != 0 {
                let mut limits = vk::PhysicalDeviceVertexAttributeDivisorPropertiesEXT::default();
                let mut properties =
                    vk::PhysicalDeviceProperties2::default().push_next(&mut limits);
                unsafe { queries.get_physical_device_properties2(physical, &mut properties) };
                result.divisor = Some(Divisor {
                    maximum: limits.max_vertex_attrib_divisor,
                    zero: divisor.vertex_attribute_instance_rate_zero_divisor != 0,
                });
                result.bits |= VERTEX_DIVISOR;
                if divisor.vertex_attribute_instance_rate_zero_divisor != 0 {
                    result.bits |= ZERO_DIVISOR;
                }
            }
        }
        if has(ash::ext::transform_feedback::NAME) {
            let mut feedback = vk::PhysicalDeviceTransformFeedbackFeaturesEXT::default();
            let mut features = vk::PhysicalDeviceFeatures2::default().push_next(&mut feedback);
            unsafe { queries.get_physical_device_features2(physical, &mut features) };
            if feedback.transform_feedback != 0 {
                let mut native = vk::PhysicalDeviceTransformFeedbackPropertiesEXT::default();
                let mut properties =
                    vk::PhysicalDeviceProperties2::default().push_next(&mut native);
                unsafe { queries.get_physical_device_properties2(physical, &mut properties) };
                native.p_next = std::ptr::null_mut();
                // No geometry stage or nonzero stream is exposed by this profile.
                native.max_transform_feedback_streams = 1;
                native.max_transform_feedback_buffers =
                    native.max_transform_feedback_buffers.min(4);
                native.max_transform_feedback_buffer_size = native
                    .max_transform_feedback_buffer_size
                    .min(MAX_ALLOCATION);
                native.transform_feedback_streams_lines_triangles = vk::FALSE;
                native.transform_feedback_rasterization_stream_select = vk::FALSE;
                result.feedback = Some(native);
                result.bits |= TRANSFORM_FEEDBACK;
            }
        }
        if has(ash::khr::portability_subset::NAME) {
            let mut native = vk::PhysicalDevicePortabilitySubsetFeaturesKHR::default();
            let mut features = vk::PhysicalDeviceFeatures2::default().push_next(&mut native);
            unsafe {
                queries.get_physical_device_features2(physical, &mut features);
            }
            // Only the paths actually implemented by the selected profile.
            result.portability = Some(
                vk::PhysicalDevicePortabilitySubsetFeaturesKHR::default()
                    .constant_alpha_color_blend_factors(
                        native.constant_alpha_color_blend_factors != 0,
                    )
                    .image_view_format_swizzle(native.image_view_format_swizzle != 0)
                    .image_view2_d_on3_d_image(native.image_view2_d_on3_d_image != 0)
                    .mutable_comparison_samplers(native.mutable_comparison_samplers != 0)
                    .point_polygons(native.point_polygons != 0)
                    .sampler_mip_lod_bias(native.sampler_mip_lod_bias != 0)
                    .triangle_fans(native.triangle_fans != 0)
                    .vertex_attribute_access_beyond_stride(
                        native.vertex_attribute_access_beyond_stride != 0,
                    ),
            );
            let mut portability = vk::PhysicalDevicePortabilitySubsetPropertiesKHR::default();
            let mut properties =
                vk::PhysicalDeviceProperties2::default().push_next(&mut portability);
            unsafe {
                queries.get_physical_device_properties2(physical, &mut properties);
            }
            result.portability_stride = portability.min_vertex_input_binding_stride_alignment;
            result.bits |= PORTABILITY;
        }
        if has(ash::ext::scalar_block_layout::NAME) {
            let mut scalar = vk::PhysicalDeviceScalarBlockLayoutFeatures::default();
            let mut features = vk::PhysicalDeviceFeatures2::default().push_next(&mut scalar);
            unsafe {
                queries.get_physical_device_features2(physical, &mut features);
            }
            if scalar.scalar_block_layout != 0 {
                result.bits |= SCALAR_LAYOUT;
            }
        }
        if result.bits & MAINTENANCE2 != 0 {
            let mut clipping = vk::PhysicalDevicePointClippingProperties::default();
            let mut properties = vk::PhysicalDeviceProperties2::default().push_next(&mut clipping);
            unsafe {
                queries.get_physical_device_properties2(physical, &mut properties);
            }
            result.point_clipping = clipping.point_clipping_behavior.as_raw() as u32;
        }
        if result.bits & (MAINTENANCE2 | FORMAT_LIST) == MAINTENANCE2 | FORMAT_LIST
            && has(ash::khr::imageless_framebuffer::NAME)
        {
            let mut imageless = vk::PhysicalDeviceImagelessFramebufferFeatures::default();
            let mut features = vk::PhysicalDeviceFeatures2::default().push_next(&mut imageless);
            unsafe {
                queries.get_physical_device_features2(physical, &mut features);
            }
            if imageless.imageless_framebuffer != 0 {
                result.bits |= IMAGELESS;
            }
        }
        if has(ash::khr::timeline_semaphore::NAME) {
            let mut timeline = vk::PhysicalDeviceTimelineSemaphoreFeatures::default();
            let mut features = vk::PhysicalDeviceFeatures2::default().push_next(&mut timeline);
            unsafe {
                queries.get_physical_device_features2(physical, &mut features);
            }
            if timeline.timeline_semaphore != 0 {
                let mut timeline = vk::PhysicalDeviceTimelineSemaphoreProperties::default();
                let mut properties =
                    vk::PhysicalDeviceProperties2::default().push_next(&mut timeline);
                unsafe {
                    queries.get_physical_device_properties2(physical, &mut properties);
                }
                result.bits |= TIMELINE;
                result.max_timeline_difference = timeline.max_timeline_semaphore_value_difference;
            }
        }
        if has(ash::khr::driver_properties::NAME) {
            let mut driver = vk::PhysicalDeviceDriverProperties::default();
            let mut properties = vk::PhysicalDeviceProperties2::default().push_next(&mut driver);
            unsafe {
                queries.get_physical_device_properties2(physical, &mut properties);
            }
            // The retained struct contains no host pNext link or borrowed data.
            driver.p_next = std::ptr::null_mut();
            result.driver = Some(driver);
            result.bits |= DRIVER_PROPERTIES;
        }
        Ok(result)
    }
    pub fn write_portability(&self, m: &mut impl CpuMemory, at: u64) -> Result<()> {
        let Some(p) = self.portability else {
            return unsupported();
        };
        let values = [
            p.constant_alpha_color_blend_factors,
            0,
            0,
            p.image_view_format_swizzle,
            p.image_view2_d_on3_d_image,
            0,
            p.mutable_comparison_samplers,
            p.point_polygons,
            p.sampler_mip_lod_bias,
            0,
            0,
            0,
            0,
            p.triangle_fans,
            p.vertex_attribute_access_beyond_stride,
            self.portability_stride,
        ];
        write(
            m,
            at,
            &values
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>(),
        )
    }
    pub fn write_clipping(&self, m: &mut impl CpuMemory, at: u64) -> Result<()> {
        if self.bits & MAINTENANCE2 == 0 {
            return unsupported();
        }
        write(m, at, &self.point_clipping.to_le_bytes())
    }
    pub fn write_driver(&self, m: &mut impl CpuMemory, at: u64) -> Result<()> {
        let Some(driver) = &self.driver else {
            return unsupported();
        };
        let mut bytes = Vec::with_capacity(520);
        bytes.extend_from_slice(&driver.driver_id.as_raw().to_le_bytes());
        bytes.extend(driver.driver_name.iter().flat_map(|x| x.to_ne_bytes()));
        bytes.extend(driver.driver_info.iter().flat_map(|x| x.to_ne_bytes()));
        let c = driver.conformance_version;
        bytes.extend_from_slice(&[c.major, c.minor, c.subminor, c.patch]);
        write(m, at, &bytes)
    }
}

pub(super) fn device_extensions(
    flags: u64,
    caps: &Capabilities,
    names: &mut Vec<*const std::ffi::c_char>,
) -> Result<()> {
    // Native dependencies can be promoted by a client's API version. Resolve
    // them on the host rather than requiring duplicated guest extension names;
    // no multiview feature is enabled or exposed by this single-layer profile.
    let mut flags = flags;
    if flags & 128 != 0 {
        flags |= 16 | 32;
    }
    if flags & 256 != 0 {
        flags |= 16 | 64;
    }
    // bit8 enables the timeline extension, bit2 separately enables its feature.
    if flags & !262143 != 0
        || flags & 7 & !caps.bits != 0
        || flags & 2 != 0 && flags & 8 == 0
        || flags & 8 != 0 && caps.bits & TIMELINE == 0
    {
        return unsupported();
    }
    for (flag, cap, name) in [
        (1024, SCALAR_LAYOUT, ash::ext::scalar_block_layout::NAME),
        (16, MAINTENANCE2, ash::khr::maintenance2::NAME),
        (32, MULTIVIEW, ash::khr::multiview::NAME),
        (64, FORMAT_LIST, ash::khr::image_format_list::NAME),
        (128, RENDERPASS2, ash::khr::create_renderpass2::NAME),
        (256, IMAGELESS, ash::khr::imageless_framebuffer::NAME),
        (8192, TRANSFORM_FEEDBACK, ash::ext::transform_feedback::NAME),
        (
            32768,
            VERTEX_DIVISOR,
            ash::ext::vertex_attribute_divisor::NAME,
        ),
    ] {
        if flags & flag != 0 {
            if caps.bits & cap == 0 {
                return unsupported();
            }
            names.push(name.as_ptr());
        }
    }
    if flags & 4096 != 0 && caps.bits & PORTABILITY == 0 {
        return unsupported();
    }
    if flags & 512 != 0 && flags & 256 == 0
        || flags & 2048 != 0 && flags & 1024 == 0
        || flags & 16384 != 0 && flags & 8192 == 0
        || flags & (65536 | 131072) != 0 && flags & 32768 == 0
        || flags & 131072 != 0 && caps.bits & ZERO_DIVISOR == 0
    {
        return unsupported();
    }
    if flags & MAINTENANCE1 != 0 {
        names.push(ash::khr::maintenance1::NAME.as_ptr());
    }
    if flags & 8 != 0 {
        names.push(ash::khr::timeline_semaphore::NAME.as_ptr());
    }
    if flags & DRIVER_PROPERTIES != 0 {
        names.push(ash::khr::driver_properties::NAME.as_ptr());
    }
    Ok(())
}

impl Backend {
    pub(super) fn zink_device(
        &mut self,
        m: &mut impl CpuMemory,
        op: u64,
        a: [u64; 16],
        dev: &Arc<Device>,
    ) -> Result<()> {
        let d = &dev.native;
        if op == 116 {
            if !dev.maintenance1 {
                return unsupported();
            }
            if a[2] != 0 {
                return invalid();
            }
            let pool = self.object(a[1], Kind::CommandPool)?;
            let api = ash::khr::maintenance1::Device::new(&dev.instance.native, d);
            unsafe {
                api.trim_command_pool(
                    vk::CommandPool::from_raw(pool.raw),
                    vk::CommandPoolTrimFlags::empty(),
                );
            }
            return Ok(());
        }
        if !dev.timeline {
            return unsupported();
        }
        let api = ash::khr::timeline_semaphore::Device::new(&dev.instance.native, d);
        if op == 119 {
            let count = bounded(a[3], 64)?;
            if count == 0 || a[4] & !1 != 0 {
                return invalid();
            }
            let values = words64(m, a[2], count)?;
            let objects: Vec<_> = words64(m, a[1], count)?
                .into_iter()
                .map(|id| self.object(id, Kind::Semaphore))
                .collect::<Result<_>>()?;
            if objects.iter().any(|s| s.flags != 1) {
                return invalid();
            }
            let semaphores: Vec<_> = objects
                .iter()
                .map(|s| vk::Semaphore::from_raw(s.raw))
                .collect();
            let info = vk::SemaphoreWaitInfo::default()
                .flags(vk::SemaphoreWaitFlags::from_raw(a[4] as u32))
                .semaphores(&semaphores)
                .values(&values);
            // A single native poll only. Guest waits yield through nanosleep;
            // no host worker/guest-memory guard is held across a blocking wait.
            unsafe { api.wait_semaphores(&info, 0) }?;
            self.coherent_download(m)?;
        } else {
            if op == 117 {
                output(m, a[2], 8)?;
            }
            let semaphore = self.object(a[1], Kind::Semaphore)?;
            if semaphore.flags != 1 {
                return invalid();
            }
            let native = vk::Semaphore::from_raw(semaphore.raw);
            match op {
                117 => {
                    let value = unsafe { api.get_semaphore_counter_value(native) }?;
                    write(m, a[2], &value.to_le_bytes())?;
                }
                118 => {
                    self.coherent_signal(m)?;
                    let info = vk::SemaphoreSignalInfo::default()
                        .semaphore(native)
                        .value(a[2]);
                    unsafe { api.signal_semaphore(&info) }?;
                }
                _ => return unsupported(),
            }
        }
        Ok(())
    }
}

impl Backend {
    pub(super) fn dynamic_call(&mut self, m: &impl CpuMemory, a: [u64; 16]) -> Result<()> {
        let command = self.object(a[1], Kind::CommandBuffer)?;
        if command.state.get() != 1 || !(2..=8).contains(&a[2]) {
            return invalid();
        }
        let count = match a[2] {
            2 => 1,
            3 => 3,
            4 => 4,
            _ => 2,
        };
        if a[4] != count {
            return invalid();
        }
        let words = words32(m, a[3], count as usize)?;
        let f: Vec<_> = words.iter().copied().map(f32::from_bits).collect();
        if a[2] <= 5 && f.iter().any(|x| !x.is_finite()) {
            return invalid();
        }
        let d = &command.device.native;
        let raw = vk::CommandBuffer::from_raw(command.raw);
        unsafe {
            match a[2] {
                2 => {
                    if f[0] != 1.0 {
                        return unsupported();
                    }
                    d.cmd_set_line_width(raw, f[0]);
                }
                3 => {
                    if f[1] != 0.0 {
                        return unsupported();
                    }
                    d.cmd_set_depth_bias(raw, f[0], f[1], f[2]);
                }
                4 => d.cmd_set_blend_constants(raw, &f.try_into().unwrap()),
                5 => {
                    if f[0] < 0.0 || f[1] > 1.0 || f[0] > f[1] {
                        return invalid();
                    }
                    d.cmd_set_depth_bounds(raw, f[0], f[1]);
                }
                6..=8 => {
                    if words[0] == 0 || words[0] & !3 != 0 {
                        return invalid();
                    }
                    let face = vk::StencilFaceFlags::from_raw(words[0]);
                    match a[2] {
                        6 => d.cmd_set_stencil_compare_mask(raw, face, words[1]),
                        7 => d.cmd_set_stencil_write_mask(raw, face, words[1]),
                        _ => d.cmd_set_stencil_reference(raw, face, words[1]),
                    };
                }
                _ => unreachable!(),
            }
        }
        Ok(())
    }
}
