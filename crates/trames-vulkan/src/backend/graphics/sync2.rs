// SPDX-License-Identifier: GPL-3.0-or-later
//! Original synchronization2 records. Masks stay 64-bit and every dependency
//! and lease belongs to the calling context; no legacy barrier emulation exists.
use super::*;

pub(in crate::backend) fn stage2(d: &Device, raw: u64) -> Result<vk::PipelineStageFlags2> {
    let high = vk::PipelineStageFlags2::COPY
        | vk::PipelineStageFlags2::BLIT
        | vk::PipelineStageFlags2::RESOLVE
        | vk::PipelineStageFlags2::CLEAR
        | vk::PipelineStageFlags2::INDEX_INPUT
        | vk::PipelineStageFlags2::VERTEX_ATTRIBUTE_INPUT
        | vk::PipelineStageFlags2::PRE_RASTERIZATION_SHADERS;
    if raw & !(u32::MAX as u64 | high.as_raw()) != 0 {
        return unsupported();
    }
    let low = raw as u32;
    // NONE is meaningful in sync2. Active legacy stages retain the existing
    // profile, without narrowing any of the new stage/access bits.
    let low = if low == 0 {
        0
    } else {
        d.stage(low)?.as_raw() as u64
    };
    Ok(vk::PipelineStageFlags2::from_raw(
        low | (raw & !u64::from(u32::MAX)),
    ))
}
struct Dependency {
    flags: vk::DependencyFlags,
    memory: Vec<vk::MemoryBarrier2<'static>>,
    buffers: Vec<vk::BufferMemoryBarrier2<'static>>,
    images: Vec<vk::ImageMemoryBarrier2<'static>>,
}
impl Dependency {
    fn info(&self) -> vk::DependencyInfo<'_> {
        vk::DependencyInfo::default()
            .dependency_flags(self.flags)
            .memory_barriers(&self.memory)
            .buffer_memory_barriers(&self.buffers)
            .image_memory_barriers(&self.images)
    }
}
impl Backend {
    fn dependency2(&self, m: &impl CpuMemory, c: &Rc<Object>, h: &[u64]) -> Result<Dependency> {
        if h[0] & !7 != 0 {
            return unsupported();
        }
        let d = &c.device;
        let mut dependency = Dependency {
            flags: vk::DependencyFlags::from_raw(h[0] as u32),
            memory: Vec::new(),
            buffers: Vec::new(),
            images: Vec::new(),
        };
        for v in descriptors::words(m, h[2], h[1], 4)?.chunks_exact(4) {
            dependency.memory.push(
                vk::MemoryBarrier2::default()
                    .src_stage_mask(stage2(d, v[0])?)
                    .src_access_mask(vk::AccessFlags2::from_raw(v[1]))
                    .dst_stage_mask(stage2(d, v[2])?)
                    .dst_access_mask(vk::AccessFlags2::from_raw(v[3])),
            );
        }
        for v in descriptors::words(m, h[4], h[3], 9)?.chunks_exact(9) {
            let buffer = self.object(v[0], Kind::Buffer)?;
            let size = if v[8] == vk::WHOLE_SIZE {
                buffer.size.saturating_sub(v[7])
            } else {
                v[8]
            };
            if v[7].checked_add(size).is_none_or(|n| n > buffer.size) {
                return invalid();
            }
            dependency.buffers.push(
                vk::BufferMemoryBarrier2::default()
                    .buffer(vk::Buffer::from_raw(buffer.raw))
                    .src_stage_mask(stage2(d, v[1])?)
                    .src_access_mask(vk::AccessFlags2::from_raw(v[2]))
                    .dst_stage_mask(stage2(d, v[3])?)
                    .dst_access_mask(vk::AccessFlags2::from_raw(v[4]))
                    .src_queue_family_index(v[5] as u32)
                    .dst_queue_family_index(v[6] as u32)
                    .offset(v[7])
                    .size(v[8]),
            );
            c.retain(buffer);
        }
        for v in descriptors::words(m, h[6], h[5], 14)?.chunks_exact(14) {
            let image = self.object(v[0], Kind::Image)?;
            if image.deps.borrow().is_empty()
                && image.swapchain.borrow().is_none()
                && image.wayland_pool.borrow().is_none()
            {
                return invalid();
            }
            let s = shape(&image)?;
            let range = s.range(&v[9..14])?;
            if range.aspect_mask != s.aspect()
                && d.compute_features & compute::SEPARATE_DEPTH_STENCIL_LAYOUTS == 0
            {
                return unsupported();
            }
            // Equal indices mean no ownership transfer. Their values are
            // ignored, including arbitrary or foreign family numbers.
            for &family in v[7..9].iter().filter(|_| v[7] != v[8]) {
                if family != u64::from(vk::QUEUE_FAMILY_IGNORED)
                    && !d.queue_families.iter().any(|f| family == u64::from(*f))
                    && !(image.external.borrow().is_some()
                        && matches!(family, 0xfffffffd | 0xfffffffe))
                {
                    return unsupported();
                }
            }
            let families = if v[7] != v[8]
                && v[7..9]
                    .iter()
                    .any(|f| matches!(*f, 0xfffffffd | 0xfffffffe))
            {
                [vk::QUEUE_FAMILY_IGNORED; 2]
            } else {
                [v[7] as u32, v[8] as u32]
            };
            // Equal layouts specify no transition, including UNDEFINED. Preserve
            // both original values so the driver does not discard image bytes.
            let equal = v[5] == v[6];
            dependency.images.push(
                vk::ImageMemoryBarrier2::default()
                    .image(vk::Image::from_raw(image.raw))
                    .src_stage_mask(stage2(d, v[1])?)
                    .src_access_mask(vk::AccessFlags2::from_raw(v[2]))
                    .dst_stage_mask(stage2(d, v[3])?)
                    .dst_access_mask(vk::AccessFlags2::from_raw(v[4]))
                    .old_layout(self.native_layout(v[5], true)?)
                    .new_layout(self.native_layout(v[6], equal)?)
                    .src_queue_family_index(families[0])
                    .dst_queue_family_index(families[1])
                    .subresource_range(range),
            );
            c.retain(image);
        }
        Ok(dependency)
    }
    pub(in crate::backend) fn sync2_command(
        &mut self,
        m: &impl CpuMemory,
        op: u64,
        a: [u64; 16],
    ) -> Result<()> {
        let c = self.object(a[1], Kind::CommandBuffer)?;
        let d = &c.device;
        if d.compute_features & compute::SYNCHRONIZATION2 == 0 {
            return unsupported();
        }
        if c.state.get() != 1 {
            return invalid();
        }
        let raw = vk::CommandBuffer::from_raw(c.raw);
        let api = &d.commands.sync2;
        match op {
            266 | 267 => {
                let at = if op == 266 { a[2] } else { a[3] };
                let dep = self.dependency2(m, &c, &words64(m, at, 7)?)?;
                unsafe {
                    if op == 266 {
                        api.cmd_pipeline_barrier2(raw, &dep.info());
                    } else {
                        let e = self.object(a[2], Kind::Event)?;
                        api.cmd_set_event2(raw, vk::Event::from_raw(e.raw), &dep.info());
                        c.retain(e);
                    }
                }
            }
            268 => {
                let e = self.object(a[2], Kind::Event)?;
                unsafe {
                    api.cmd_reset_event2(raw, vk::Event::from_raw(e.raw), stage2(d, a[3])?);
                }
                c.retain(e);
            }
            269 => {
                let ids = descriptors::words(m, a[2], a[4], 1)?;
                let headers = descriptors::words(m, a[3], a[4], 7)?;
                let mut events = Vec::with_capacity(ids.len());
                let mut deps = Vec::with_capacity(ids.len());
                for (id, h) in ids.into_iter().zip(headers.chunks_exact(7)) {
                    let e = self.object(id, Kind::Event)?;
                    events.push(vk::Event::from_raw(e.raw));
                    c.retain(e);
                    deps.push(self.dependency2(m, &c, h)?);
                }
                let infos: Vec<_> = deps.iter().map(Dependency::info).collect();
                unsafe {
                    api.cmd_wait_events2(raw, &events, &infos);
                }
            }
            270 => {
                let pool = self.object(a[2], Kind::QueryPool)?;
                if pool.flags != vk::QueryType::TIMESTAMP.as_raw() as u32
                    || a[3] >= pool.size
                    || a[4].count_ones() != 1
                {
                    return invalid();
                }
                unsafe {
                    api.cmd_write_timestamp2(
                        raw,
                        stage2(d, a[4])?,
                        vk::QueryPool::from_raw(pool.raw),
                        a[3] as u32,
                    );
                }
                c.retain(pool);
            }
            _ => return unsupported(),
        }
        Ok(())
    }
    pub(in crate::backend) fn submit2(
        &mut self,
        m: &mut impl CpuMemory,
        a: [u64; 16],
        dev: Arc<Device>,
    ) -> Result<()> {
        if dev.compute_features & compute::SYNCHRONIZATION2 == 0 {
            return unsupported();
        }
        self.submission_capacity()?;
        let queue = self.queue(a[1])?;
        let wire = descriptors::words(m, a[2], a[3], 7)?;
        let mut owned = Vec::new();
        let mut commands = Vec::new();
        let mut semaphores = Vec::new();
        let mut states = BTreeMap::new();
        let mut timeline_completion = Vec::new();
        for r in wire.chunks_exact(7) {
            if r[0] != 0 {
                return unsupported();
            } // Protected memory is not exposed.
            timeline_completion.clear();
            let mut batch = (Vec::new(), Vec::new(), Vec::new());
            for (signal, at, n) in [(false, r[1], r[2]), (true, r[5], r[6])] {
                for v in descriptors::words(m, at, n, 4)?.chunks_exact(4) {
                    if v[3] != 0 {
                        return unsupported();
                    } // One physical-device group member.
                    let s = self.object(v[0], Kind::Semaphore)?;
                    let state = states.entry(v[0]).or_insert(s.state.get());
                    let mut host_ready = false;
                    if s.flags == 0 {
                        if signal {
                            if *state != 0 {
                                return invalid();
                            }
                            *state = 1;
                        } else {
                            if !matches!(*state, 1 | HOST_SIGNALED) {
                                return invalid();
                            }
                            host_ready = *state == HOST_SIGNALED;
                            *state = 0;
                        }
                    } else if !dev.timeline {
                        return unsupported();
                    }
                    if !host_ready {
                        let info = vk::SemaphoreSubmitInfo::default()
                            .semaphore(vk::Semaphore::from_raw(s.raw))
                            .value(if s.flags == 0 { 0 } else { v[1] })
                            .stage_mask(stage2(&dev, v[2])?)
                            .device_index(0);
                        if signal {
                            batch.2.push(info);
                            // A sync2 signal may cover an early pipeline stage.
                            // Only ALL_COMMANDS proves the entire command graph
                            // reusable; narrower signals keep the native fence.
                            if s.flags != 0
                                && info
                                    .stage_mask
                                    .contains(vk::PipelineStageFlags2::ALL_COMMANDS)
                            {
                                timeline_completion.push((s.clone(), v[1]));
                            }
                        } else {
                            batch.0.push(info);
                        }
                    }
                    semaphores.push((v[0], s));
                }
            }
            for v in descriptors::words(m, r[3], r[4], 2)?.chunks_exact(2) {
                let c = self.object(v[0], Kind::CommandBuffer)?;
                let simultaneous = c.command_usage.get() & 4 != 0;
                if v[1] & !1 != 0
                    || c.flags != 0
                    || !(c.state.get() == 2 || simultaneous && c.state.get() == 3)
                    || !simultaneous && commands.iter().any(|other| Rc::ptr_eq(other, &c))
                {
                    return invalid();
                }
                batch.1.push(
                    vk::CommandBufferSubmitInfo::default()
                        .command_buffer(vk::CommandBuffer::from_raw(c.raw))
                        .device_mask(v[1] as u32),
                );
                commands.push(c);
            }
            owned.push(batch);
        }
        let infos: Vec<_> = owned
            .iter()
            .map(|(w, c, s)| {
                vk::SubmitInfo2::default()
                    .wait_semaphore_infos(w)
                    .command_buffer_infos(c)
                    .signal_semaphore_infos(s)
            })
            .collect();
        let resources = SubmitResources {
            commands,
            semaphores,
            states,
            timeline_completion,
        };
        self.submit_native(m, a[4], dev.clone(), resources, |fence| unsafe {
            dev.commands.sync2.queue_submit2(queue, &infos, fence)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions};
    const OUT: u64 = 0x1000;
    fn call(b: &mut Backend, m: &mut Memory, op: u64, args: &[u64]) -> u64 {
        let mut a = [0; 16];
        a[..args.len()].copy_from_slice(args);
        assert_eq!(
            b.invoke_graph(m, op, a).unwrap(),
            Invocation::Complete(0),
            "op={op}"
        );
        m.read_u64(OUT).unwrap()
    }
    fn words(m: &mut Memory, at: u64, data: &[u64]) {
        m.write(
            at,
            &data
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    }
    #[cfg(trames_moltenvk)]
    #[test]
    #[ignore = "requires original native timeline shared events"]
    fn hardware_timeline_wait_wakes_without_a_submission_fence_and_cancels() {
        struct Wake(std::sync::mpsc::Sender<()>);
        impl trames_shared::IoWake for Wake {
            fn wake_io(&self, _: &Arc<trames_shared::IoSignal>) {
                let _ = self.0.send(());
            }
        }
        let mut b = Backend::with_budget(crate::Budget::host_managed());
        let mut m = Memory::default();
        m.map(0x1000, 0x20000, Permissions::RW).unwrap();
        let instance = call(&mut b, &mut m, 1, &[OUT]);
        m.write_array(0x2000, 1u32.to_le_bytes()).unwrap();
        let physical = call(&mut b, &mut m, 3, &[instance, 0x2000, OUT]);
        let device = call(&mut b, &mut m, 8, &[physical, 0, OUT, 0, 0, 10]);
        let semaphore = call(&mut b, &mut m, 54, &[device, OUT, 1, 0]);
        let dev = b.device.as_ref().unwrap().clone();
        let api = ash::khr::timeline_semaphore::Device::new(&dev.instance.native, &dev.native);
        let (tx, rx) = std::sync::mpsc::channel();
        let target: Arc<dyn trames_shared::IoWake> = Arc::new(Wake(tx));
        let signal = trames_shared::IoSignal::new(1, Arc::downgrade(&target));
        let _subscription = b.completion.subscribe(&signal);
        words(&mut m, 0x3000, &[semaphore]);
        for value in [1, 2] {
            words(&mut m, 0x4000, &[value]);
            let mut args = [0; 16];
            args[..6].copy_from_slice(&[device, 0x3000, 0x4000, 1, 0, u64::MAX]);
            let Invocation::Pending(job) = b.invoke_graph(&mut m, 202, args).unwrap() else {
                panic!("future timeline value must park");
            };
            if value == 2 {
                b.abandon(job);
                signal.reset();
            }
            unsafe {
                api.signal_semaphore(
                    &vk::SemaphoreSignalInfo::default()
                        .semaphore(vk::Semaphore::from_raw(b.objects[&semaphore].raw))
                        .value(value),
                )
                .unwrap();
            }
            if value == 1 {
                rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
                assert_eq!(b.poll(&mut m, job).unwrap(), Some(0));
                assert!(
                    b.submissions.is_empty(),
                    "no final fence generated the wake"
                );
            } else {
                assert!(rx
                    .recv_timeout(std::time::Duration::from_millis(50))
                    .is_err());
                assert!(
                    !signal.ready(),
                    "abandoned observer cannot wake a later wait"
                );
            }
        }
    }
    #[test]
    #[ignore = "requires original native synchronization2"]
    fn hardware_early_sync2_signals_keep_native_fence_authority_and_rejected_batches_do_not_commit()
    {
        let mut b = Backend::with_budget(crate::Budget::host_managed());
        let mut m = Memory::default();
        m.map(0x1000, 0x20000, Permissions::RW).unwrap();
        let instance = call(&mut b, &mut m, 1, &[OUT]);
        m.write_array(0x2000, 1u32.to_le_bytes()).unwrap();
        let physical = call(&mut b, &mut m, 3, &[instance, 0x2000, OUT]);
        assert!(
            b.capabilities.compute.extensions & (1 << 44) != 0,
            "extension mask {:x}",
            b.capabilities.compute.extensions
        );
        assert!(
            b.capabilities.compute.features & compute::SYNCHRONIZATION2 != 0,
            "feature mask {:x}",
            b.capabilities.compute.features
        );
        let device = call(
            &mut b,
            &mut m,
            8,
            &[physical, 0, OUT, 0, 0, 10, 1 << 44, 0, 1 << 53],
        );
        assert_eq!(
            b.device.as_ref().unwrap().stage(0).unwrap(),
            vk::PipelineStageFlags::empty()
        );
        assert!(
            compute_stage(0).is_err(),
            "legacy clients without sync2 keep the original contract"
        );
        let timeline = call(&mut b, &mut m, 54, &[device, OUT, 1, 0]);
        let queue = b.queue_id;
        for (value, stage, whole) in [
            (1, vk::PipelineStageFlags2::TOP_OF_PIPE, false),
            (2, vk::PipelineStageFlags2::ALL_COMMANDS, true),
        ] {
            words(&mut m, 0x3000, &[timeline, value, stage.as_raw(), 0]);
            words(&mut m, 0x4000, &[0, 0, 0, 0, 0, 0x3000, 1]);
            call(&mut b, &mut m, 271, &[device, queue, 0x4000, 1, 0]);
            assert_eq!(
                !b.submissions.last().unwrap().timeline_completion.is_empty(),
                whole,
                "a signal scope before command completion cannot make the graph reusable"
            );
        }
        let binary = call(&mut b, &mut m, 54, &[device, OUT, 0, 0]);
        words(
            &mut m,
            0x3000,
            &[binary, 0, vk::PipelineStageFlags2::ALL_COMMANDS.as_raw(), 0],
        );
        words(
            &mut m,
            0x4000,
            &[0, 0, 0, 0, 0, 0x3000, 1, 0, 0x3010, 1, 0, 0, 0, 0],
        );
        let mut a = [0; 16];
        a[..5].copy_from_slice(&[device, queue, 0x4000, 2, 0]);
        assert_ne!(
            b.invoke_graph(&mut m, 271, a).unwrap(),
            Invocation::Complete(0)
        );
        assert_eq!(
            b.objects[&binary].state.get(),
            0,
            "rejected native batches must not consume or publish binary signals"
        );
        unsafe {
            b.device
                .as_ref()
                .unwrap()
                .native
                .device_wait_idle()
                .unwrap();
        }
        b.collect();
        assert!(b.submissions.is_empty());
    }
}
