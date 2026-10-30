// SPDX-License-Identifier: GPL-3.0-or-later
//! Small core commands forward directly to the original driver on this context.
use super::*;

impl Backend {
    pub(super) fn core_command(
        &mut self,
        m: &mut impl CpuMemory,
        op: u64,
        a: [u64; 16],
        dev: &Arc<Device>,
    ) -> Result<()> {
        let d = &dev.native;
        match op {
            209 => {
                if dev.compute_features & compute::HOST_QUERY_RESET == 0 {
                    return unsupported();
                }
                let pool = self.object(a[1], Kind::QueryPool)?;
                if a[3] == 0 || a[2].checked_add(a[3]).is_none_or(|end| end > pool.size) {
                    return invalid();
                }
                unsafe {
                    d.reset_query_pool(vk::QueryPool::from_raw(pool.raw), a[2] as u32, a[3] as u32);
                }
            }
            214 => {
                let pass = self.object(a[1], Kind::RenderPass)?;
                let extent =
                    unsafe { d.get_render_area_granularity(vk::RenderPass::from_raw(pass.raw)) };
                let mut bytes = extent.width.to_le_bytes().to_vec();
                bytes.extend(extent.height.to_le_bytes());
                write(m, a[2], &bytes)?;
            }
            210 | 211 | 213 => {
                let c = self.object(a[1], Kind::CommandBuffer)?;
                if c.state.get() != 1 {
                    return invalid();
                }
                let raw = vk::CommandBuffer::from_raw(c.raw);
                if op == 211 {
                    if a[2] != 1 {
                        return unsupported();
                    }
                    unsafe {
                        d.cmd_set_device_mask(raw, 1);
                    }
                    return Ok(());
                }
                if c.recording.borrow().pass.is_some() {
                    return invalid();
                }
                if op == 210 {
                    let recording = c.recording.borrow();
                    let pipeline = recording
                        .compute_pipeline
                        .as_ref()
                        .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
                    if (0..3).any(|i| {
                        a[2 + i]
                            .checked_add(a[5 + i])
                            .is_none_or(|n| n > dev.compute_workgroup_count[i] as u64)
                    }) {
                        return invalid();
                    }
                    if a[2..5].iter().any(|&n| n != 0)
                        && pipeline.pipeline_flags.get()
                            & vk::PipelineCreateFlags::DISPATCH_BASE.as_raw()
                            == 0
                    {
                        return invalid();
                    }
                    unsafe {
                        d.cmd_dispatch_base(
                            raw,
                            a[2] as u32,
                            a[3] as u32,
                            a[4] as u32,
                            a[5] as u32,
                            a[6] as u32,
                            a[7] as u32,
                        );
                    }
                } else {
                    let buffer = self.object(a[2], Kind::Buffer)?;
                    if buffer.flags & vk::BufferUsageFlags::TRANSFER_DST.as_raw() == 0
                        || a[4] == 0
                        || a[4] > 65536
                        || !a[3].is_multiple_of(4)
                        || !a[4].is_multiple_of(4)
                        || a[3].checked_add(a[4]).is_none_or(|n| n > buffer.size)
                    {
                        return invalid();
                    }
                    let mut bytes = vec![0; a[4] as usize];
                    m.read(a[5], &mut bytes)?;
                    unsafe {
                        d.cmd_update_buffer(raw, vk::Buffer::from_raw(buffer.raw), a[3], &bytes);
                    }
                    c.retain(buffer);
                }
            }
            _ => return unsupported(),
        }
        Ok(())
    }
}
