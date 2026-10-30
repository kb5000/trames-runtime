// SPDX-License-Identifier: GPL-3.0-or-later
//! Native secondary command buffers and subpass transitions. Their resource
//! graphs are retained by the executing primary and its actual GPU submission.
use super::*;
impl Backend {
    pub(in crate::backend) fn begin_command(
        &mut self,
        m: &impl CpuMemory,
        a: [u64; 16],
    ) -> Result<()> {
        let c = self.object(a[1], Kind::CommandBuffer)?;
        if c.state.get() == 3 || a[2] & !7 != 0 || a[2] & 5 == 5 {
            return invalid();
        }
        let mut info = vk::CommandBufferBeginInfo::default()
            .flags(vk::CommandBufferUsageFlags::from_raw(a[2] as u32));
        let mut inheritance = vk::CommandBufferInheritanceInfo::default();
        let mut resources = Vec::new();
        let mut recording = Recording::default();
        if c.flags == 1 {
            if a[3] == 0 {
                return invalid();
            }
            let v = words64(m, a[3], 6)?;
            inheritance = inheritance
                .subpass(v[1] as u32)
                .occlusion_query_enable(v[3] != 0)
                .query_flags(vk::QueryControlFlags::from_raw(v[4] as u32))
                .pipeline_statistics(vk::QueryPipelineStatisticFlags::from_raw(v[5] as u32));
            if a[2] & 2 != 0 {
                let pass = self.object(v[0], Kind::RenderPass)?;
                if v[1] >= pass.pass.get().unwrap().subpasses.len() as u64 {
                    return invalid();
                }
                inheritance = inheritance.render_pass(vk::RenderPass::from_raw(pass.raw));
                recording.subpass = v[1] as usize;
                recording.layers = 1;
                recording.render_area = Some(vk::Rect2D {
                    offset: vk::Offset2D::default(),
                    extent: vk::Extent2D {
                        width: DIMENSION,
                        height: DIMENSION,
                    },
                });
                if v[2] != 0 {
                    let fb = self.object(v[2], Kind::Framebuffer)?;
                    if !compatible_pass(&fb.deps.borrow()[0], &pass) {
                        return invalid();
                    }
                    let shape = shape(&fb)?;
                    recording.layers = shape.layers;
                    recording.render_area = Some(vk::Rect2D {
                        offset: vk::Offset2D::default(),
                        extent: vk::Extent2D {
                            width: shape.width,
                            height: shape.height,
                        },
                    });
                    inheritance = inheritance.framebuffer(vk::Framebuffer::from_raw(fb.raw));
                    resources.push(fb);
                }
                recording.pass = Some(pass.clone());
                resources.push(pass);
            }
            info = info.inheritance_info(&inheritance);
        } else if a[2] & 2 != 0 {
            return invalid();
        }
        unsafe {
            c.device
                .native
                .begin_command_buffer(vk::CommandBuffer::from_raw(c.raw), &info)
        }?;
        c.command_usage.set(a[2] as u32);
        c.deps.borrow_mut().truncate(1);
        *c.recording.borrow_mut() = recording;
        for resource in resources {
            c.retain(resource);
        }
        c.state.set(1);
        Ok(())
    }
    pub(in crate::backend) fn command_control(
        &mut self,
        m: &impl CpuMemory,
        op: u64,
        a: [u64; 16],
    ) -> Result<()> {
        let c = self.object(a[1], Kind::CommandBuffer)?;
        if c.state.get() != 1 || c.flags != 0 {
            return invalid();
        }
        let raw = vk::CommandBuffer::from_raw(c.raw);
        if op == 218 {
            if a[2] > 1 {
                return unsupported();
            }
            let mut recording = c.recording.borrow_mut();
            let pass = recording
                .pass
                .as_ref()
                .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
            if recording.subpass + 1 >= pass.pass.get().unwrap().subpasses.len() {
                return invalid();
            }
            unsafe {
                if a[3] != 0 {
                    let begin = vk::SubpassBeginInfo::default()
                        .contents(vk::SubpassContents::from_raw(a[2] as i32));
                    let end = vk::SubpassEndInfo::default();
                    let api = ash::khr::create_renderpass2::Device::new(
                        &c.device.instance.native,
                        &c.device.native,
                    );
                    api.cmd_next_subpass2(raw, &begin, &end);
                } else {
                    c.device
                        .native
                        .cmd_next_subpass(raw, vk::SubpassContents::from_raw(a[2] as i32));
                }
            }
            recording.subpass += 1;
        } else {
            let ids = descriptors::words(m, a[2], a[3], 1)?;
            let mut native = Vec::with_capacity(ids.len());
            let mut owned = Vec::with_capacity(ids.len());
            let recording = c.recording.borrow();
            for id in ids {
                let secondary = self.object(id, Kind::CommandBuffer)?;
                if secondary.flags != 1
                    || !matches!(secondary.state.get(), 2 | 3)
                    || secondary.state.get() == 3 && secondary.command_usage.get() & 4 == 0
                {
                    return invalid();
                }
                let inherited = secondary.recording.borrow();
                match recording.pass.as_ref().zip(inherited.pass.as_ref()) {
                    Some((actual, expected))
                        if compatible_pass(actual, expected)
                            && recording.subpass == inherited.subpass => {}
                    None if recording.pass.is_none() && inherited.pass.is_none() => {}
                    _ => return invalid(),
                }
                drop(inherited);
                native.push(vk::CommandBuffer::from_raw(secondary.raw));
                owned.push(secondary);
            }
            unsafe {
                c.device.native.cmd_execute_commands(raw, &native);
            }
            drop(recording);
            for secondary in owned {
                c.retain(secondary);
            }
        }
        Ok(())
    }
}
