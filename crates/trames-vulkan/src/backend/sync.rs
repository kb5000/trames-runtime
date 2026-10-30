// SPDX-License-Identifier: GPL-3.0-or-later
//! Original native events and core memory/layout queries. No polling service
//! or additional CPU synchronization policy is introduced.
use super::*;
impl Backend {
    pub(super) fn sync_call(
        &mut self,
        m: &mut impl CpuMemory,
        op: u64,
        a: [u64; 16],
    ) -> Result<()> {
        let device = self.device.as_ref().unwrap().clone();
        let d = &device.native;
        match op {
            220 => {
                if a[1] != 0 {
                    return unsupported();
                }
                self.room(1)?;
                output(m, a[2], 8)?;
                let event = unsafe { d.create_event(&vk::EventCreateInfo::default(), None) }?;
                let id = self.put(Kind::Event, event.as_raw(), Vec::new(), 0, 0);
                self.publish(m, a[2], id)?;
            }
            221 => self.remove(a[1], Kind::Event)?,
            222..=224 => {
                let e = self.object(a[1], Kind::Event)?;
                let raw = vk::Event::from_raw(e.raw);
                if op == 222 {
                    let set = unsafe { d.get_event_status(raw) }?;
                    if set {
                        self.coherent_download(m)?;
                    }
                    return Err((if set {
                        vk::Result::EVENT_SET
                    } else {
                        vk::Result::EVENT_RESET
                    })
                    .into());
                }
                if op == 223 {
                    self.coherent_signal(m)?;
                    unsafe { d.set_event(raw) }?;
                } else {
                    unsafe { d.reset_event(raw) }?;
                }
            }
            225..=227 => {
                let c = self.object(a[1], Kind::CommandBuffer)?;
                if c.state.get() != 1 {
                    return invalid();
                }
                let raw = vk::CommandBuffer::from_raw(c.raw);
                if op != 227 {
                    let e = self.object(a[2], Kind::Event)?;
                    let stage = device.stage(a[3] as u32)?;
                    unsafe {
                        if op == 225 {
                            d.cmd_set_event(raw, vk::Event::from_raw(e.raw), stage);
                        } else {
                            d.cmd_reset_event(raw, vk::Event::from_raw(e.raw), stage);
                        }
                    }
                    c.retain(e);
                } else {
                    let h = words64(m, a[2], 10)?;
                    let mut events = Vec::new();
                    for id in descriptors::words(m, h[1], h[0], 1)? {
                        let e = self.object(id, Kind::Event)?;
                        events.push(vk::Event::from_raw(e.raw));
                        c.retain(e);
                    }
                    let mut memory = Vec::new();
                    for v in descriptors::words(m, h[5], h[4], 2)?.chunks_exact(2) {
                        memory.push(
                            vk::MemoryBarrier::default()
                                .src_access_mask(vk::AccessFlags::from_raw(v[0] as u32))
                                .dst_access_mask(vk::AccessFlags::from_raw(v[1] as u32)),
                        );
                    }
                    let buffers = self.buffer_barriers(m, &c, h[7], h[6])?;
                    let images = self.image_barriers(m, &c, h[9], h[8], 10)?;
                    unsafe {
                        d.cmd_wait_events(
                            raw,
                            &events,
                            device.stage(h[2] as u32)?,
                            device.stage(h[3] as u32)?,
                            &memory,
                            &buffers,
                            &images,
                        );
                    }
                }
            }
            228 => {
                let memory = self.object(a[1], Kind::Memory)?;
                let committed = unsafe {
                    d.get_device_memory_commitment(vk::DeviceMemory::from_raw(memory.raw))
                };
                write(m, a[2], &committed.to_le_bytes())?;
            }
            229 => {
                let image = self.object(a[1], Kind::Image)?;
                let shape = image
                    .image
                    .get()
                    .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
                if a[3] >= shape.mips as u64 || a[4] >= shape.layers as u64 {
                    return invalid();
                }
                let sub = vk::ImageSubresource::default()
                    .aspect_mask(vk::ImageAspectFlags::from_raw(a[2] as u32))
                    .mip_level(a[3] as u32)
                    .array_layer(a[4] as u32);
                let layout =
                    unsafe { d.get_image_subresource_layout(vk::Image::from_raw(image.raw), sub) };
                let values = [
                    layout.offset,
                    layout.size,
                    layout.row_pitch,
                    layout.array_pitch,
                    layout.depth_pitch,
                ];
                write_words(m, a[5], &values, 40)?;
            }
            232 => {
                let props = unsafe {
                    device
                        .instance
                        .native
                        .get_physical_device_memory_properties(self.physical)
                };
                if a[1] >= props.memory_heap_count as u64 || a[2] != 0 || a[3] != 0 {
                    return invalid();
                }
                // A physical-device group contains exactly this device. Local
                // memory supports both native copies and ordinary accesses.
                let flags = vk::PeerMemoryFeatureFlags::COPY_SRC
                    | vk::PeerMemoryFeatureFlags::COPY_DST
                    | vk::PeerMemoryFeatureFlags::GENERIC_SRC
                    | vk::PeerMemoryFeatureFlags::GENERIC_DST;
                write(m, a[4], &flags.as_raw().to_le_bytes())?;
            }
            233 => {
                self.object(a[1], Kind::Image)?;
                write(m, a[2], &0u32.to_le_bytes())?;
            }
            237..=238 => {
                // Capture/replay is deliberately unavailable until allocation
                // and buffer create support replay addresses. Never export a
                // fabricated address for an unenabled native feature.
                return unsupported();
            }
            239 => {
                let object =
                    self.object(a[2], if a[1] == 1 { Kind::Buffer } else { Kind::Image })?;
                let mut dedicated = vk::MemoryDedicatedRequirements::default();
                let mut result = vk::MemoryRequirements2::default().push_next(&mut dedicated);
                unsafe {
                    if a[1] == 1 {
                        d.get_buffer_memory_requirements2(
                            &vk::BufferMemoryRequirementsInfo2::default()
                                .buffer(vk::Buffer::from_raw(object.raw)),
                            &mut result,
                        );
                    } else {
                        d.get_image_memory_requirements2(
                            &vk::ImageMemoryRequirementsInfo2::default()
                                .image(vk::Image::from_raw(object.raw)),
                            &mut result,
                        );
                    }
                }
                let r = result.memory_requirements;
                let mut bytes = Vec::new();
                bytes.extend(r.size.to_le_bytes());
                bytes.extend(r.alignment.to_le_bytes());
                bytes.extend(r.memory_type_bits.to_le_bytes());
                bytes.extend([0; 4]);
                write(m, a[3], &bytes)?;
                if a[4] != 0 {
                    let mut bytes = dedicated
                        .prefers_dedicated_allocation
                        .to_le_bytes()
                        .to_vec();
                    bytes.extend(dedicated.requires_dedicated_allocation.to_le_bytes());
                    write(m, a[4], &bytes)?;
                }
            }
            _ => return unsupported(),
        }
        Ok(())
    }
    pub(super) fn buffer_barriers(
        &self,
        m: &impl CpuMemory,
        c: &Rc<Object>,
        at: u64,
        count: u64,
    ) -> Result<Vec<vk::BufferMemoryBarrier<'static>>> {
        let mut values = Vec::new();
        for v in descriptors::words(m, at, count, 7)?.chunks_exact(7) {
            let buffer = self.object(v[0], Kind::Buffer)?;
            let size = if v[6] == vk::WHOLE_SIZE {
                buffer.size.saturating_sub(v[5])
            } else {
                v[6]
            };
            if v[5].checked_add(size).is_none_or(|end| end > buffer.size) {
                return invalid();
            }
            values.push(
                vk::BufferMemoryBarrier::default()
                    .buffer(vk::Buffer::from_raw(buffer.raw))
                    .src_access_mask(vk::AccessFlags::from_raw(v[1] as u32))
                    .dst_access_mask(vk::AccessFlags::from_raw(v[2] as u32))
                    .src_queue_family_index(v[3] as u32)
                    .dst_queue_family_index(v[4] as u32)
                    .offset(v[5])
                    .size(v[6]),
            );
            c.retain(buffer);
        }
        Ok(values)
    }
}
