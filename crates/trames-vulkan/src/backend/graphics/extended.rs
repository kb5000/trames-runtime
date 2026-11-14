// SPDX-License-Identifier: GPL-3.0-or-later
//! Original dynamic state. It is recorded once on the caller's native command
//! buffer, without state replay, pipeline variants, completion polling or a bus.
use super::*;

pub(super) fn feature(state: vk::DynamicState) -> Result<u128> {
    use vk::DynamicState as S;
    Ok(match state {
        S::CULL_MODE
        | S::FRONT_FACE
        | S::PRIMITIVE_TOPOLOGY
        | S::VIEWPORT_WITH_COUNT
        | S::SCISSOR_WITH_COUNT
        | S::VERTEX_INPUT_BINDING_STRIDE
        | S::DEPTH_TEST_ENABLE
        | S::DEPTH_WRITE_ENABLE
        | S::DEPTH_COMPARE_OP
        | S::DEPTH_BOUNDS_TEST_ENABLE
        | S::STENCIL_TEST_ENABLE
        | S::STENCIL_OP => compute::EXTENDED_DYNAMIC_STATE,
        S::RASTERIZER_DISCARD_ENABLE | S::DEPTH_BIAS_ENABLE | S::PRIMITIVE_RESTART_ENABLE => {
            compute::EXTENDED_DYNAMIC_STATE2
        }
        S::PATCH_CONTROL_POINTS_EXT => compute::EXTENDED_DYNAMIC_STATE2_PATCH_CONTROL_POINTS,
        S::LOGIC_OP_EXT => 1 << 77,
        S::DEPTH_CLAMP_ENABLE_EXT => compute::EXTENDED_DYNAMIC_STATE3_DEPTH_CLAMP_ENABLE,
        S::DEPTH_CLIP_ENABLE_EXT => compute::EXTENDED_DYNAMIC_STATE3_DEPTH_CLIP_ENABLE,
        S::POLYGON_MODE_EXT => compute::EXTENDED_DYNAMIC_STATE3_POLYGON_MODE,
        S::SAMPLE_LOCATIONS_ENABLE_EXT => compute::EXTENDED_DYNAMIC_STATE3_SAMPLE_LOCATIONS_ENABLE,
        S::LINE_RASTERIZATION_MODE_EXT => compute::EXTENDED_DYNAMIC_STATE3_LINE_RASTERIZATION_MODE,
        _ => return unsupported(),
    })
}
fn enabled(d: &Device, s: vk::DynamicState) -> Result<bool> {
    if s == vk::DynamicState::SAMPLE_LOCATIONS_EXT {
        return Ok(d.compute_extensions & compute::EXT_SAMPLE_LOCATIONS != 0);
    }
    if s == vk::DynamicState::LINE_STIPPLE_EXT {
        return Ok(d.compute_extensions & compute::EXT_LINE_RASTERIZATION != 0);
    }
    Ok(d.compute_features & feature(s)? != 0)
}
pub(super) fn pipeline_states(
    m: &impl CpuMemory,
    at: u64,
    device: &Device,
) -> Result<Vec<vk::DynamicState>> {
    let h = words64(m, at, 2)?;
    words32(m, h[1], bounded(h[0], 32)?)?
        .into_iter()
        .map(|state| {
            let state = vk::DynamicState::from_raw(state as i32);
            if !enabled(device, state)? {
                return unsupported();
            }
            Ok(state)
        })
        .collect()
}
impl Backend {
    pub(in crate::backend) fn extended_state(
        &mut self,
        m: &impl CpuMemory,
        a: [u64; 16],
    ) -> Result<()> {
        let c = self.object(a[1], Kind::CommandBuffer)?;
        let d = &c.device;
        let state = vk::DynamicState::from_raw(a[2] as i32);
        if !enabled(d, state)? {
            return unsupported();
        }
        if c.state.get() != 1 {
            return invalid();
        }
        let api = &d.commands.extended;
        let api2 = &d.commands.extended2;
        let api3 = &d.commands.extended3;
        let raw = vk::CommandBuffer::from_raw(c.raw);
        use vk::DynamicState as S;
        unsafe {
            match state {
                S::CULL_MODE => {
                    api.cmd_set_cull_mode(raw, vk::CullModeFlags::from_raw(a[3] as u32))
                }
                S::FRONT_FACE => api.cmd_set_front_face(raw, vk::FrontFace::from_raw(a[3] as i32)),
                S::PRIMITIVE_TOPOLOGY => api
                    .cmd_set_primitive_topology(raw, vk::PrimitiveTopology::from_raw(a[3] as i32)),
                S::DEPTH_TEST_ENABLE => api.cmd_set_depth_test_enable(raw, a[3] != 0),
                S::DEPTH_WRITE_ENABLE => api.cmd_set_depth_write_enable(raw, a[3] != 0),
                S::DEPTH_COMPARE_OP => {
                    api.cmd_set_depth_compare_op(raw, vk::CompareOp::from_raw(a[3] as i32))
                }
                S::DEPTH_BOUNDS_TEST_ENABLE => api.cmd_set_depth_bounds_test_enable(raw, a[3] != 0),
                S::STENCIL_TEST_ENABLE => api.cmd_set_stencil_test_enable(raw, a[3] != 0),
                S::STENCIL_OP => api.cmd_set_stencil_op(
                    raw,
                    vk::StencilFaceFlags::from_raw(a[3] as u32),
                    vk::StencilOp::from_raw(a[4] as i32),
                    vk::StencilOp::from_raw(a[5] as i32),
                    vk::StencilOp::from_raw(a[6] as i32),
                    vk::CompareOp::from_raw(a[7] as i32),
                ),
                S::RASTERIZER_DISCARD_ENABLE => {
                    api2.cmd_set_rasterizer_discard_enable(raw, a[3] != 0)
                }
                S::DEPTH_BIAS_ENABLE => api2.cmd_set_depth_bias_enable(raw, a[3] != 0),
                S::PRIMITIVE_RESTART_ENABLE => {
                    api2.cmd_set_primitive_restart_enable(raw, a[3] != 0)
                }
                S::PATCH_CONTROL_POINTS_EXT => api2.cmd_set_patch_control_points(raw, a[3] as u32),
                S::LOGIC_OP_EXT => api2.cmd_set_logic_op(raw, vk::LogicOp::from_raw(a[3] as i32)),
                S::DEPTH_CLAMP_ENABLE_EXT => api3.cmd_set_depth_clamp_enable(raw, a[3] != 0),
                S::DEPTH_CLIP_ENABLE_EXT => api3.cmd_set_depth_clip_enable(raw, a[3] != 0),
                S::POLYGON_MODE_EXT => {
                    api3.cmd_set_polygon_mode(raw, vk::PolygonMode::from_raw(a[3] as i32))
                }
                S::SAMPLE_LOCATIONS_ENABLE_EXT => {
                    api3.cmd_set_sample_locations_enable(raw, a[3] != 0)
                }
                S::LINE_RASTERIZATION_MODE_EXT => api3.cmd_set_line_rasterization_mode(
                    raw,
                    vk::LineRasterizationModeEXT::from_raw(a[3] as i32),
                ),
                S::SAMPLE_LOCATIONS_EXT => {
                    let points = sample_locations(m, true, &a[3..8])?;
                    let info = vk::SampleLocationsInfoEXT::default()
                        .sample_locations_per_pixel(vk::SampleCountFlags::from_raw(a[3] as u32))
                        .sample_location_grid_size(vk::Extent2D {
                            width: a[4] as u32,
                            height: a[5] as u32,
                        })
                        .sample_locations(&points);
                    d.commands.samples.cmd_set_sample_locations(raw, &info);
                }
                S::LINE_STIPPLE_EXT => {
                    (d.commands.lines.fp().cmd_set_line_stipple_ext)(raw, a[3] as u32, a[4] as u16)
                }
                S::VIEWPORT_WITH_COUNT => {
                    if a[3] != 1 {
                        return unsupported();
                    }
                    let v: Vec<_> = words32(m, a[4], 6)?
                        .into_iter()
                        .map(f32::from_bits)
                        .collect();
                    if !valid_viewport(&v, d.maintenance1, d.viewport_dimensions, d.viewport_bounds)
                    {
                        return invalid();
                    }
                    api.cmd_set_viewport_with_count(
                        raw,
                        &[vk::Viewport {
                            x: v[0],
                            y: v[1],
                            width: v[2],
                            height: v[3],
                            min_depth: v[4],
                            max_depth: v[5],
                        }],
                    );
                }
                S::SCISSOR_WITH_COUNT => {
                    if a[3] != 1 {
                        return unsupported();
                    }
                    let v = words32(m, a[4], 4)?;
                    let rect = vk::Rect2D {
                        offset: vk::Offset2D {
                            x: v[0] as i32,
                            y: v[1] as i32,
                        },
                        extent: vk::Extent2D {
                            width: v[2],
                            height: v[3],
                        },
                    };
                    api.cmd_set_scissor_with_count(raw, &[rect]);
                }
                S::VERTEX_INPUT_BINDING_STRIDE => {
                    let n = bounded(a[4], 16)?;
                    if a[3] + n as u64 > 16 {
                        return invalid();
                    }
                    let ids = words64(m, a[5], n)?;
                    let offsets = words64(m, a[6], n)?;
                    let sizes = if a[7] == 0 {
                        None
                    } else {
                        Some(words64(m, a[7], n)?)
                    };
                    let strides = if a[8] == 0 {
                        None
                    } else {
                        Some(words64(m, a[8], n)?)
                    };
                    let objects = ids
                        .into_iter()
                        .map(|id| self.object(id, Kind::Buffer))
                        .collect::<Result<Vec<_>>>()?;
                    for (i, b) in objects.iter().enumerate() {
                        if b.flags & vk::BufferUsageFlags::VERTEX_BUFFER.as_raw() == 0
                            || b.deps.borrow().is_empty()
                            || offsets[i] >= b.size
                            || sizes
                                .as_ref()
                                .is_some_and(|s| s[i] != u64::MAX && s[i] > b.size - offsets[i])
                        {
                            return invalid();
                        }
                    }
                    let buffers: Vec<_> = objects
                        .iter()
                        .map(|b| vk::Buffer::from_raw(b.raw))
                        .collect();
                    api.cmd_bind_vertex_buffers2(
                        raw,
                        a[3] as u32,
                        &buffers,
                        &offsets,
                        sizes.as_deref(),
                        strides.as_deref(),
                    );
                    for (i, (b, offset)) in objects.into_iter().zip(offsets).enumerate() {
                        let index = a[3] as u32 + i as u32;
                        {
                            let mut r = c.recording.borrow_mut();
                            r.vertices.insert(index, (b.clone(), offset));
                            if let Some(v) = &strides {
                                r.vertex_strides.insert(index, v[i]);
                            }
                        }
                        c.retain(b);
                    }
                }
                _ => return unsupported(),
            }
        }
        Ok(())
    }
}

pub(super) fn sample_locations(
    m: &impl CpuMemory,
    active: bool,
    h: &[u64],
) -> Result<Vec<vk::SampleLocationEXT>> {
    if !active || h[3] == 0 {
        return Ok(Vec::new());
    }
    let values = words32(m, h[4], bounded(h[3], 256)? * 2)?;
    Ok(values
        .chunks_exact(2)
        .map(|v| vk::SampleLocationEXT {
            x: f32::from_bits(v[0]),
            y: f32::from_bits(v[1]),
        })
        .collect())
}
impl Backend {
    pub(in crate::backend) fn sample_locations_query(
        &self,
        m: &mut impl CpuMemory,
        op: u64,
        a: [u64; 16],
    ) -> Result<()> {
        if self.capabilities.compute.extensions & compute::EXT_SAMPLE_LOCATIONS == 0 {
            return unsupported();
        }
        let instance = self.instance.as_ref().unwrap();
        if op == 265 {
            let api = ash::ext::sample_locations::Instance::new(&instance._entry, &instance.native);
            let mut properties = vk::MultisamplePropertiesEXT::default();
            unsafe {
                api.get_physical_device_multisample_properties(
                    self.physical,
                    vk::SampleCountFlags::from_raw(a[1] as u32),
                    &mut properties,
                );
            }
            return write(
                m,
                a[2],
                &[
                    properties.max_sample_location_grid_size.width.to_le_bytes(),
                    properties
                        .max_sample_location_grid_size
                        .height
                        .to_le_bytes(),
                ]
                .concat(),
            );
        }
        let api = ash::khr::get_physical_device_properties2::Instance::new(
            &instance._entry,
            &instance.native,
        );
        let mut p = vk::PhysicalDeviceSampleLocationsPropertiesEXT::default();
        let mut props = vk::PhysicalDeviceProperties2::default().push_next(&mut p);
        unsafe {
            api.get_physical_device_properties2(self.physical, &mut props);
        }
        let values = [
            p.sample_location_sample_counts.as_raw(),
            p.max_sample_location_grid_size.width,
            p.max_sample_location_grid_size.height,
            p.sample_location_coordinate_range[0].to_bits(),
            p.sample_location_coordinate_range[1].to_bits(),
            p.sample_location_sub_pixel_bits,
            p.variable_sample_locations,
        ];
        write(
            m,
            a[1],
            &values
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>(),
        )
    }
}
