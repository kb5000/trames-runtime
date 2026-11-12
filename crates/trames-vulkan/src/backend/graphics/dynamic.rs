// SPDX-License-Identifier: GPL-3.0-or-later
//! Original dynamic render scopes. Attachment leases stay in the recording
//! command graph; neither fabricated render passes nor a resource thread exist.
use super::*;

pub(in crate::backend) enum RenderScope {
    Pass(Rc<Object>),
    Rendering(Box<Rendering>),
}
pub(in crate::backend) struct Rendering {
    pub info: SubpassInfo,
}
impl RenderScope {
    pub(in crate::backend) fn legacy(&self) -> Option<&Object> {
        match self {
            Self::Pass(p) => Some(p),
            Self::Rendering(_) => None,
        }
    }
    pub(in crate::backend) fn subpass_count(&self) -> usize {
        self.legacy()
            .map_or(1, |p| p.pass.get().unwrap().subpasses.len())
    }
    pub(in crate::backend) fn info(&self, index: usize) -> Result<&SubpassInfo> {
        match self {
            Self::Pass(p) => p
                .pass
                .get()
                .unwrap()
                .subpasses
                .get(index)
                .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN)),
            Self::Rendering(r) if index == 0 => Ok(&r.info),
            _ => invalid(),
        }
    }
    pub(in crate::backend) fn compatible_pipeline(
        &self,
        pipeline: &Object,
        subpass: usize,
    ) -> bool {
        match self {
            Self::Pass(pass) => {
                pipeline.pass.get().is_none()
                    && pipeline
                        .deps
                        .borrow()
                        .get(1)
                        .is_some_and(|p| compatible_pass(p, pass))
            }
            Self::Rendering(r) => {
                subpass == 0
                    && pipeline
                        .pass
                        .get()
                        .is_some_and(|p| compatible(&r.info, &p.subpasses[0]))
            }
        }
    }
    pub(in crate::backend) fn compatible_scope(&self, expected: &Self) -> bool {
        match (self, expected) {
            (Self::Pass(a), Self::Pass(b)) => compatible_pass(a, b),
            (Self::Rendering(a), Self::Rendering(b)) => compatible(&a.info, &b.info),
            _ => false,
        }
    }
}
fn compatible(actual: &SubpassInfo, pipeline: &SubpassInfo) -> bool {
    actual.color_count == pipeline.color_count
        && actual.view_mask == pipeline.view_mask
        && actual.colors[..actual.color_count]
            .iter()
            .zip(&pipeline.colors)
            .all(|(a, b)| *a == vk::Format::UNDEFINED || a == b)
        && actual.depth.is_none_or(|a| Some(a) == pipeline.depth)
        && actual.stencil.is_none_or(|a| Some(a) == pipeline.stencil)
        && (actual.samples.is_empty() || actual.samples == pipeline.samples)
}
pub(super) fn formats(
    m: &impl CpuMemory,
    at: u64,
    samples: vk::SampleCountFlags,
) -> Result<SubpassInfo> {
    // viewMask, color count, color formats, depth format, stencil format.
    let v = words64(m, at, 5)?;
    let n = bounded(v[1], MAX_COLORS)?;
    let mut info = SubpassInfo::new(n);
    for (out, value) in info.colors.iter_mut().zip(words32(m, v[2], n)?) {
        *out = if value == 0 {
            vk::Format::UNDEFINED
        } else {
            format(u64::from(value))?
        };
    }
    info.depth = if v[3] == 0 { None } else { Some(format(v[3])?) };
    info.stencil = if v[4] == 0 { None } else { Some(format(v[4])?) };
    info.view_mask = v[0] as u32;
    info.samples = samples;
    Ok(info)
}
pub(super) fn pipeline_info(info: SubpassInfo) -> Box<PassInfo> {
    Box::new(PassInfo {
        formats: Vec::new(),
        sample_counts: Vec::new(),
        usages: Vec::new(),
        attachments: 0,
        clear_count: 0,
        view_mask: info.view_mask,
        subpasses: vec![info],
    })
}
impl Backend {
    fn rendering_attachment(
        &self,
        v: &[u64],
        resources: &mut Vec<Rc<Object>>,
        info: &mut SubpassInfo,
    ) -> Result<(vk::RenderingAttachmentInfo<'static>, Option<vk::Format>)> {
        let mut native = vk::RenderingAttachmentInfo::default();
        if v[0] == 0 {
            return Ok((native, None));
        }
        let view = self.object(v[0], Kind::ImageView)?;
        let shape = shape(&view)?;
        if info.samples.is_empty() {
            info.samples = shape.samples;
        }
        let clear = [
            v[7] as u32,
            (v[7] >> 32) as u32,
            v[8] as u32,
            (v[8] >> 32) as u32,
        ];
        native = native
            .image_view(vk::ImageView::from_raw(view.raw))
            .image_layout(self.native_layout(v[1], false)?)
            .resolve_mode(vk::ResolveModeFlags::from_raw(v[2] as u32))
            .load_op(vk::AttachmentLoadOp::from_raw(v[5] as i32))
            .store_op(vk::AttachmentStoreOp::from_raw(v[6] as i32))
            .clear_value(vk::ClearValue {
                color: vk::ClearColorValue { uint32: clear },
            });
        resources.push(view);
        if v[2] != 0 && v[3] != 0 {
            let resolve = self.object(v[3], Kind::ImageView)?;
            native = native
                .resolve_image_view(vk::ImageView::from_raw(resolve.raw))
                .resolve_image_layout(self.native_layout(v[4], false)?);
            resources.push(resolve);
        }
        Ok((native, Some(shape.format)))
    }
    pub(in crate::backend) fn dynamic_rendering(
        &mut self,
        m: &impl CpuMemory,
        op: u64,
        a: [u64; 16],
    ) -> Result<()> {
        let c = self.object(a[1], Kind::CommandBuffer)?;
        let device = &c.device;
        if device.compute_features & compute::DYNAMIC_RENDERING == 0 {
            return unsupported();
        }
        if c.state.get() != 1 || c.flags == 1 && c.command_usage.get() & 2 != 0 {
            return invalid();
        }
        let raw = vk::CommandBuffer::from_raw(c.raw);
        let api = ash::khr::dynamic_rendering::Device::new(&device.instance.native, &device.native);
        if op == 254 {
            let mut r = c.recording.borrow_mut();
            if !matches!(r.pass, Some(RenderScope::Rendering(_))) || r.feedback_active {
                return invalid();
            }
            unsafe {
                api.cmd_end_rendering(raw);
            }
            r.pass = None;
            r.render_area = None;
            return Ok(());
        }
        if c.recording.borrow().pass.is_some() {
            return invalid();
        }
        // All guest arrays are owned before the driver records a command.
        let h = words64(m, a[2], 11)?;
        if h[0] & !7 != 0 {
            return unsupported();
        }
        let mut signature = SubpassInfo::new(bounded(h[7], MAX_COLORS)?);
        signature.view_mask = h[6] as u32;
        let mut resources = Vec::new();
        let mut colors = Vec::new();
        for (i, v) in words64(m, h[8], signature.color_count * 9)?
            .chunks_exact(9)
            .enumerate()
        {
            let (native, format) = self.rendering_attachment(v, &mut resources, &mut signature)?;
            signature.colors[i] = format.unwrap_or(vk::Format::UNDEFINED);
            colors.push(native);
        }
        let mut depth = None;
        let mut stencil = None;
        if h[9] != 0 {
            let (native, format) =
                self.rendering_attachment(&words64(m, h[9], 9)?, &mut resources, &mut signature)?;
            signature.depth = format;
            depth = Some(native);
        }
        if h[10] != 0 {
            let (native, format) =
                self.rendering_attachment(&words64(m, h[10], 9)?, &mut resources, &mut signature)?;
            signature.stencil = format;
            stencil = Some(native);
        }
        let area = vk::Rect2D {
            offset: vk::Offset2D {
                x: h[1] as i32,
                y: h[2] as i32,
            },
            extent: vk::Extent2D {
                width: h[3] as u32,
                height: h[4] as u32,
            },
        };
        let flags = vk::RenderingFlags::from_raw(h[0] as u32);
        let mut info = vk::RenderingInfo::default()
            .flags(flags)
            .render_area(area)
            .layer_count(h[5] as u32)
            .view_mask(h[6] as u32)
            .color_attachments(&colors);
        if let Some(depth) = &depth {
            info = info.depth_attachment(depth);
        }
        if let Some(stencil) = &stencil {
            info = info.stencil_attachment(stencil);
        }
        let areas = if a[5] == 0 {
            Vec::new()
        } else {
            if a[5] != 1 {
                return unsupported();
            }
            let v = words64(m, a[4], 4)?;
            vec![vk::Rect2D {
                offset: vk::Offset2D {
                    x: v[0] as i32,
                    y: v[1] as i32,
                },
                extent: vk::Extent2D {
                    width: v[2] as u32,
                    height: v[3] as u32,
                },
            }]
        };
        let mut group = vk::DeviceGroupRenderPassBeginInfo::default()
            .device_mask(a[3] as u32)
            .device_render_areas(&areas);
        if a[3] != 0 {
            if a[3] != 1 {
                return unsupported();
            }
            info = info.push_next(&mut group);
        }
        unsafe {
            api.cmd_begin_rendering(raw, &info);
        }
        let mut r = c.recording.borrow_mut();
        r.pass = Some(RenderScope::Rendering(Box::new(Rendering {
            info: signature,
        })));
        r.subpass = 0;
        r.render_area = Some(areas.first().copied().unwrap_or(area));
        r.layers = if h[6] != 0 { 1 } else { h[5] as u32 };
        drop(r);
        for resource in resources {
            c.retain(resource);
        }
        Ok(())
    }
    pub(in crate::backend) fn write_memory_properties(
        &self,
        m: &mut impl CpuMemory,
        at: u64,
        p: &vk::PhysicalDeviceMemoryProperties,
    ) -> Result<()> {
        // Serialize initialized fields only, with deterministic ABI padding.
        let mut bytes = vec![0; std::mem::size_of::<vk::PhysicalDeviceMemoryProperties>()];
        bytes[..4].copy_from_slice(&p.memory_type_count.to_le_bytes());
        let start = std::mem::offset_of!(vk::PhysicalDeviceMemoryProperties, memory_types);
        for (i, t) in p
            .memory_types
            .iter()
            .take(p.memory_type_count as usize)
            .enumerate()
        {
            let at = start + i * 8;
            bytes[at..at + 4].copy_from_slice(&t.property_flags.as_raw().to_le_bytes());
            bytes[at + 4..at + 8].copy_from_slice(&t.heap_index.to_le_bytes());
        }
        let at_count = std::mem::offset_of!(vk::PhysicalDeviceMemoryProperties, memory_heap_count);
        bytes[at_count..at_count + 4].copy_from_slice(&p.memory_heap_count.to_le_bytes());
        let start = std::mem::offset_of!(vk::PhysicalDeviceMemoryProperties, memory_heaps);
        for (i, h) in p
            .memory_heaps
            .iter()
            .take(p.memory_heap_count as usize)
            .enumerate()
        {
            let at = start + i * 16;
            bytes[at..at + 8].copy_from_slice(&h.size.min(self.budget.limit()).to_le_bytes());
            bytes[at + 8..at + 12].copy_from_slice(&h.flags.as_raw().to_le_bytes());
        }
        write(m, at, &bytes)
    }
    pub(in crate::backend) fn memory_budget(
        &self,
        m: &mut impl CpuMemory,
        a: [u64; 16],
    ) -> Result<()> {
        if self.capabilities.compute.extensions & compute::EXT_MEMORY_BUDGET == 0 {
            return unsupported();
        }
        output(m, a[1], 32 * 8)?;
        if a[2] != 0 {
            output(
                m,
                a[2],
                std::mem::size_of::<vk::PhysicalDeviceMemoryProperties>(),
            )?;
        }
        let instance = self.instance.as_ref().unwrap();
        let api = ash::khr::get_physical_device_properties2::Instance::new(
            &instance._entry,
            &instance.native,
        );
        let mut budget = vk::PhysicalDeviceMemoryBudgetPropertiesEXT::default();
        let mut properties = vk::PhysicalDeviceMemoryProperties2::default().push_next(&mut budget);
        unsafe {
            api.get_physical_device_memory_properties2(self.physical, &mut properties);
        }
        let memory_properties = properties.memory_properties;
        // Preserve the existing explicit-session policy. Host-managed sessions
        // add no limit, and native process/heap usage is never fabricated.
        for (i, heap) in memory_properties
            .memory_heaps
            .iter()
            .take(memory_properties.memory_heap_count as usize)
            .enumerate()
        {
            budget.heap_budget[i] = budget.heap_budget[i]
                .min(heap.size)
                .min(self.budget.limit());
        }
        if a[2] != 0 {
            self.write_memory_properties(m, a[2], &memory_properties)?;
        }
        let values = budget
            .heap_budget
            .into_iter()
            .chain(budget.heap_usage)
            .collect::<Vec<_>>();
        write_words(m, a[1], &values, 32 * 8)
    }
}

#[cfg(all(test, target_vendor = "apple"))]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions};
    const OUT: u64 = 0x2000;
    fn invoke(b: &mut Backend, m: &mut Memory, op: u64, args: &[u64]) -> Invocation {
        let mut a = [0; 16];
        a[..args.len()].copy_from_slice(args);
        b.invoke_graph(m, op, a).unwrap()
    }
    fn ok(b: &mut Backend, m: &mut Memory, op: u64, args: &[u64]) -> u64 {
        assert_eq!(invoke(b, m, op, args), Invocation::Complete(0));
        m.read_u64(OUT).unwrap()
    }
    fn setup() -> (Backend, Memory, u64, u64) {
        let mut b = Backend::with_budget(crate::Budget::host_managed());
        let mut m = Memory::default();
        m.map(0x1000, 0x8000, Permissions::RW).unwrap();
        let instance = ok(&mut b, &mut m, 1, &[OUT]);
        m.write_array(0x2400, 1u32.to_le_bytes()).unwrap();
        let physical = ok(&mut b, &mut m, 3, &[instance, 0x2400, OUT]);
        (b, m, instance, physical)
    }
    #[test]
    #[ignore = "requires original native MoltenVK dynamic rendering"]
    fn hardware_dynamic_scope_ends_through_its_original_api_and_submission() {
        let (mut b, mut m, instance, physical) = setup();
        let device = ok(
            &mut b,
            &mut m,
            8,
            &[physical, 0, OUT, 0, 0, 0, 1 << 34, 0, 1 << 10],
        );
        let pool = ok(&mut b, &mut m, 34, &[device, 0, 0, OUT]);
        for level in [0, 1] {
            let command = ok(&mut b, &mut m, 36, &[device, pool, OUT, level]);
            m.write(0x3400, &[0; 48]).unwrap();
            ok(
                &mut b,
                &mut m,
                38,
                &[device, command, 1, if level == 1 { 0x3400 } else { 0 }],
            );
            let header = [0u64, 0, 0, 16, 16, 1, 0, 0, 0, 0, 0];
            m.write(
                0x3000,
                &header
                    .into_iter()
                    .flat_map(u64::to_le_bytes)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            ok(&mut b, &mut m, 253, &[device, command, 0x3000]);
            assert_ne!(
                invoke(&mut b, &mut m, 72, &[device, command]),
                Invocation::Complete(0)
            );
            assert_ne!(
                invoke(&mut b, &mut m, 39, &[device, command]),
                Invocation::Complete(0)
            );
            assert!(matches!(
                b.objects[&command].recording.borrow().pass,
                Some(RenderScope::Rendering(_))
            ));
            ok(&mut b, &mut m, 254, &[device, command]);
            ok(&mut b, &mut m, 39, &[device, command]);
            let primary = if level == 1 {
                let primary = ok(&mut b, &mut m, 36, &[device, pool, OUT, 0]);
                ok(&mut b, &mut m, 38, &[device, primary, 1]);
                m.write_array(0x3000, command.to_le_bytes()).unwrap();
                ok(&mut b, &mut m, 219, &[device, primary, 0x3000, 1]);
                ok(&mut b, &mut m, 39, &[device, primary]);
                primary
            } else {
                command
            };
            let fence = ok(&mut b, &mut m, 48, &[device, 0, OUT]);
            let queue = ok(&mut b, &mut m, 10, &[device, 0, 0, OUT]);
            m.write_array(0x3000, primary.to_le_bytes()).unwrap();
            ok(&mut b, &mut m, 52, &[device, queue, 0x3000, 1, fence]);
            unsafe { b.device.as_ref().unwrap().native.device_wait_idle() }.unwrap();
            b.collect();
            assert!(Backend::fence_ready(&b.objects[&fence]).unwrap());
        }
        ok(&mut b, &mut m, 9, &[device]);
        ok(&mut b, &mut m, 2, &[instance]);
        assert_eq!(b.live_objects.get(), 0);
    }
    fn native_budget(b: &Backend) -> vk::PhysicalDeviceMemoryBudgetPropertiesEXT<'static> {
        let instance = b.instance.as_ref().unwrap();
        let api = ash::khr::get_physical_device_properties2::Instance::new(
            &instance._entry,
            &instance.native,
        );
        let mut budget = vk::PhysicalDeviceMemoryBudgetPropertiesEXT::default();
        let mut p = vk::PhysicalDeviceMemoryProperties2::default().push_next(&mut budget);
        unsafe {
            api.get_physical_device_memory_properties2(b.physical, &mut p);
        }
        budget
    }
    fn check_budget(b: &mut Backend, m: &mut Memory, physical: u64) -> u64 {
        ok(b, m, 252, &[physical, OUT, 0x3000]);
        let native = native_budget(b);
        let count = read32(
            m,
            0x3000
                + std::mem::offset_of!(vk::PhysicalDeviceMemoryProperties, memory_heap_count)
                    as u64,
        )
        .unwrap();
        assert!(count != 0);
        for i in 0..16 {
            assert_eq!(
                m.read_u64(OUT + 128 + i as u64 * 8).unwrap(),
                native.heap_usage[i]
            );
            let budget = m.read_u64(OUT + i as u64 * 8).unwrap();
            if i < count as usize {
                assert!(budget != 0);
                assert!(budget <= native.heap_budget[i]);
            } else {
                assert_eq!(budget, 0);
            }
        }
        let before = m.read_array::<520>(0x3000).unwrap();
        ok(b, m, 5, &[physical, 0x3000]);
        assert_eq!(m.read_array::<520>(0x3000).unwrap(), before);
        m.read_u64(OUT + 128).unwrap()
    }
    #[test]
    #[ignore = "requires original native MoltenVK heap budget queries"]
    fn hardware_budget_matches_original_process_usage_and_original_heap_records() {
        let (mut b, mut m, instance, physical) = setup();
        let before = check_budget(&mut b, &mut m, physical);
        let device = ok(&mut b, &mut m, 8, &[physical, 0, OUT]);
        let buffer = ok(&mut b, &mut m, 11, &[device, 8 << 20, 3, OUT]);
        ok(&mut b, &mut m, 13, &[device, buffer, OUT]);
        let size = m.read_u64(OUT).unwrap();
        let bits = read32(&m, OUT + 16).unwrap();
        let memory = ok(
            &mut b,
            &mut m,
            14,
            &[device, size, u64::from(bits.trailing_zeros()), OUT],
        );
        ok(&mut b, &mut m, 16, &[device, buffer, memory, 0]);
        let during = check_budget(&mut b, &mut m, physical);
        assert!(during >= before);
        ok(&mut b, &mut m, 12, &[device, buffer]);
        ok(&mut b, &mut m, 15, &[device, memory]);
        ok(&mut b, &mut m, 9, &[device]);
        ok(&mut b, &mut m, 2, &[instance]);
        assert_eq!(b.budget.used(), 0);
    }
}
