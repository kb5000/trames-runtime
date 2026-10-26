// SPDX-License-Identifier: GPL-3.0-or-later
//! GPU transform feedback and query pools. Counters and captured vertices stay
//! on the native GPU; host result reads poll once and never block a worker.
use super::*;

impl Device {
    pub(super) fn stage(&self, raw: u32) -> Result<vk::PipelineStageFlags> {
        let stage = compute_stage(raw)?;
        if stage.contains(vk::PipelineStageFlags::TRANSFORM_FEEDBACK_EXT) && self.feedback.is_none()
        {
            return unsupported();
        }
        Ok(stage)
    }
}
impl zink::Capabilities {
    pub(super) fn write_feedback(&self, m: &mut impl CpuMemory, at: u64) -> Result<()> {
        let p = self.feedback.unwrap_or_default();
        write_words(
            m,
            at,
            &[
                u64::from(self.feedback.is_some()),
                0,
                p.max_transform_feedback_streams as u64,
                p.max_transform_feedback_buffers as u64,
                p.max_transform_feedback_buffer_size,
                p.max_transform_feedback_stream_data_size as u64,
                p.max_transform_feedback_buffer_data_size as u64,
                p.max_transform_feedback_buffer_data_stride as u64,
                p.transform_feedback_queries as u64,
                0,
                0,
                p.transform_feedback_draw as u64,
            ],
            96,
        )
    }
}

fn query_range(pool: &Object, first: u64, count: u64) -> Result<()> {
    if count == 0 || first >= pool.size || count > pool.size - first {
        return invalid();
    }
    Ok(())
}
fn query_layout(ty: u32, count: u64, stride: u64, flags: u64) -> Result<(usize, usize)> {
    if flags & !15 != 0 || ty == vk::QueryType::TIMESTAMP.as_raw() as u32 && flags & 8 != 0 {
        return unsupported();
    }
    let unit = if flags & 1 != 0 { 8 } else { 4 };
    let values = if ty == vk::QueryType::TRANSFORM_FEEDBACK_STREAM_EXT.as_raw() as u32 {
        2
    } else {
        1
    };
    let row = unit * (values + u64::from(flags & 4 != 0));
    if count == 0 || !stride.is_multiple_of(unit) || (count > 1 || flags & 4 != 0) && stride < row {
        return invalid();
    }
    let span = (count - 1)
        .checked_mul(stride)
        .and_then(|n| n.checked_add(row))
        .filter(|&n| n <= MAX_ALLOCATION)
        .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
    Ok((unit as usize, span as usize))
}

impl Backend {
    pub(super) fn feedback_call(
        &mut self,
        m: &mut impl CpuMemory,
        op: u64,
        a: [u64; 16],
        dev: &Arc<Device>,
    ) -> Result<()> {
        let d = &dev.native;
        if op == 138 {
            self.room(1)?;
            output(m, a[3], 8)?;
            let ty = vk::QueryType::from_raw(a[1] as i32);
            if a[1] > u32::MAX as u64
                || !matches!(
                    ty,
                    vk::QueryType::OCCLUSION
                        | vk::QueryType::TIMESTAMP
                        | vk::QueryType::TRANSFORM_FEEDBACK_STREAM_EXT
                )
            {
                return unsupported();
            }
            if a[2] == 0 || a[2] > 4096 {
                return invalid();
            }
            if ty == vk::QueryType::TRANSFORM_FEEDBACK_STREAM_EXT
                && !dev
                    .feedback
                    .is_some_and(|p| p.transform_feedback_queries != 0)
            {
                return unsupported();
            }
            if ty == vk::QueryType::TIMESTAMP {
                let queues = unsafe {
                    dev.instance
                        .native
                        .get_physical_device_queue_family_properties(self.physical)
                };
                if queues[self.family as usize].timestamp_valid_bits == 0 {
                    return unsupported();
                }
            }
            let info = vk::QueryPoolCreateInfo::default()
                .query_type(ty)
                .query_count(a[2] as u32);
            let native = unsafe { d.create_query_pool(&info, None) }?;
            let id = self.put(Kind::QueryPool, native.as_raw(), vec![], a[2], a[1] as u32);
            return write(m, a[3], &id.to_le_bytes());
        }
        if op == 139 {
            return self.remove(a[1], Kind::QueryPool);
        }
        if op == 141 {
            let pool = self.object(a[1], Kind::QueryPool)?;
            query_range(&pool, a[2], a[3])?;
            let (unit, span) = query_layout(pool.flags, a[3], a[6], a[7])?;
            if a[4] < span as u64 || !a[5].is_multiple_of(unit as u64) {
                return invalid();
            }
            output(m, a[5], span)?;
            // Preserve unavailable results, stride padding and trailing bytes.
            // Native drivers receive aligned host storage, never a guest pointer.
            let mut bytes = vec![0u64; span.div_ceil(8)];
            let host =
                unsafe { std::slice::from_raw_parts_mut(bytes.as_mut_ptr().cast::<u8>(), span) };
            m.read(a[5], host)?;
            let r = unsafe {
                (d.fp_v1_0().get_query_pool_results)(
                    d.handle(),
                    vk::QueryPool::from_raw(pool.raw),
                    a[2] as u32,
                    a[3] as u32,
                    span,
                    host.as_mut_ptr().cast(),
                    a[6],
                    vk::QueryResultFlags::from_raw(
                        a[7] as u32
                            & !(vk::QueryResultFlags::WAIT.as_raw()
                                | if a[7] & 2 != 0 {
                                    vk::QueryResultFlags::PARTIAL.as_raw()
                                } else {
                                    0
                                }),
                    ),
                )
            };
            if r == vk::Result::SUCCESS || r == vk::Result::NOT_READY {
                write(m, a[5], host)?;
            }
            if r != vk::Result::SUCCESS {
                return Err(r.into());
            }
            return Ok(());
        }
        let c = self.object(a[1], Kind::CommandBuffer)?;
        if c.state.get() != 1 {
            return invalid();
        }
        let raw = vk::CommandBuffer::from_raw(c.raw);
        if op <= 145 {
            let pool = self.object(a[2], Kind::QueryPool)?;
            let native = vk::QueryPool::from_raw(pool.raw);
            let ty = vk::QueryType::from_raw(pool.flags as i32);
            query_range(&pool, a[3], if op == 140 || op == 142 { a[4] } else { 1 })?;
            match op {
                140 => {
                    let r = c.recording.borrow();
                    if r.pass.is_some()
                        || r.queries.values().any(|(p, q)| {
                            Rc::ptr_eq(p, &pool) && (*q as u64) >= a[3] && (*q as u64) < a[3] + a[4]
                        })
                    {
                        return invalid();
                    }
                    unsafe { d.cmd_reset_query_pool(raw, native, a[3] as u32, a[4] as u32) };
                }
                142 => {
                    if c.recording.borrow().pass.is_some() {
                        return invalid();
                    }
                    let buffer = self.object(a[5], Kind::Buffer)?;
                    let (unit, span) = query_layout(pool.flags, a[4], a[7], a[8])?;
                    if buffer.deps.borrow().is_empty()
                        || buffer.flags & vk::BufferUsageFlags::TRANSFER_DST.as_raw() == 0
                        || !a[6].is_multiple_of(unit as u64)
                        || a[6]
                            .checked_add(span as u64)
                            .is_none_or(|n| n > buffer.size)
                    {
                        return invalid();
                    }
                    unsafe {
                        d.cmd_copy_query_pool_results(
                            raw,
                            native,
                            a[3] as u32,
                            a[4] as u32,
                            vk::Buffer::from_raw(buffer.raw),
                            a[6],
                            a[7],
                            vk::QueryResultFlags::from_raw(a[8] as u32),
                        )
                    };
                    c.retain(buffer);
                }
                143 => {
                    if ty != vk::QueryType::TIMESTAMP
                        || a[4] > u32::MAX as u64
                        || a[4].count_ones() != 1
                    {
                        return invalid();
                    }
                    unsafe {
                        d.cmd_write_timestamp(raw, dev.stage(a[4] as u32)?, native, a[3] as u32)
                    };
                }
                144 | 145 => {
                    // Stream zero only: geometryStreams is not exposed. Core
                    // begin/end and indexed entrypoints share this state.
                    if ty == vk::QueryType::TIMESTAMP
                        || a[4] != 0
                        || a[5] != 0
                        || a[6] > 1
                        || a[6] != 0 && !dev.feedback_extension
                    {
                        return unsupported();
                    }
                    if ty == vk::QueryType::OCCLUSION && c.recording.borrow().pass.is_none() {
                        return invalid();
                    }
                    let key = (ty.as_raw(), 0);
                    let mut r = c.recording.borrow_mut();
                    if op == 144 {
                        if r.queries.contains_key(&key) {
                            return invalid();
                        }
                    } else if !r
                        .queries
                        .get(&key)
                        .is_some_and(|(p, q)| Rc::ptr_eq(p, &pool) && *q == a[3] as u32)
                    {
                        return invalid();
                    }
                    if ty == vk::QueryType::TRANSFORM_FEEDBACK_STREAM_EXT {
                        let api =
                            ash::ext::transform_feedback::Device::new(&dev.instance.native, d);
                        unsafe {
                            if op == 144 {
                                (api.fp().cmd_begin_query_indexed_ext)(
                                    raw,
                                    native,
                                    a[3] as u32,
                                    vk::QueryControlFlags::empty(),
                                    0,
                                );
                            } else {
                                (api.fp().cmd_end_query_indexed_ext)(raw, native, a[3] as u32, 0);
                            }
                        }
                    } else {
                        unsafe {
                            if op == 144 {
                                d.cmd_begin_query(
                                    raw,
                                    native,
                                    a[3] as u32,
                                    vk::QueryControlFlags::empty(),
                                );
                            } else {
                                d.cmd_end_query(raw, native, a[3] as u32);
                            }
                        }
                    }
                    if op == 144 {
                        r.queries.insert(key, (pool.clone(), a[3] as u32));
                    } else {
                        r.queries.remove(&key);
                    }
                }
                _ => unreachable!(),
            }
            c.retain(pool);
            return Ok(());
        }
        let Some(props) = dev.feedback else {
            return unsupported();
        };
        let api = ash::ext::transform_feedback::Device::new(&dev.instance.native, d);
        if op == 149 {
            if props.transform_feedback_draw == 0 {
                return unsupported();
            }
            let r = c.recording.borrow();
            let pass = r
                .pass
                .as_ref()
                .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
            let p = r
                .pipeline
                .as_ref()
                .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
            if !graphics::compatible_pass(&p.deps.borrow()[1], pass)
                || !r.viewport && p.static_states.get() & 1 == 0
                || !r.scissor && p.static_states.get() & 2 == 0
                || [a[2], a[3], a[6], a[7]]
                    .iter()
                    .any(|&n| n > u32::MAX as u64)
                || a[7] == 0
                || !a[6].is_multiple_of(4)
                || !a[7].is_multiple_of(4)
                || a[7] > props.max_transform_feedback_buffer_data_stride as u64
            {
                return invalid();
            }
            // The vertex count is GPU-resident; do not read the counter back or
            // scan index/vertex data to validate application-owned draw inputs.
            graphics::instance_base(&p.vertex_inputs.borrow(), a[3])?;
            for input in p.vertex_inputs.borrow().iter().filter(|x| x.extent != 0) {
                if !r.vertices.contains_key(&input.binding) {
                    return invalid();
                }
            }
            let counter = self.object(a[4], Kind::Buffer)?;
            if counter.deps.borrow().is_empty()
                || counter.flags & vk::BufferUsageFlags::INDIRECT_BUFFER.as_raw() == 0
                || a[5] % 4 != 0
                || a[5].checked_add(4).is_none_or(|n| n > counter.size)
            {
                return invalid();
            }
            unsafe {
                (api.fp().cmd_draw_indirect_byte_count_ext)(
                    raw,
                    a[2] as u32,
                    a[3] as u32,
                    vk::Buffer::from_raw(counter.raw),
                    a[5],
                    a[6] as u32,
                    a[7] as u32,
                )
            };
            c.retain(counter);
            return Ok(());
        }
        let first = a[2];
        let count = bounded(a[3], props.max_transform_feedback_buffers as usize)?;
        if first >= props.max_transform_feedback_buffers as u64
            || count as u64 > props.max_transform_feedback_buffers as u64 - first
        {
            return invalid();
        }
        let r = c.recording.borrow();
        if op == 146 && (r.feedback_active || count == 0 || a[5] == 0)
            || op == 147 && (r.feedback_active || r.pass.is_none() || r.pipeline.is_none())
            || op == 148 && !r.feedback_active
        {
            return invalid();
        }
        drop(r);
        let ids = if count == 0 {
            Vec::new()
        } else if op != 146 && a[4] == 0 {
            vec![0; count]
        } else {
            words64(m, a[4], count)?
        };
        let offsets = if count == 0 || a[5] == 0 {
            vec![0; count]
        } else {
            words64(m, a[5], count)?
        };
        let sizes = if op == 146 && a[6] != 0 {
            words64(m, a[6], count)?
        } else {
            vec![u64::MAX; count]
        };
        let mut native = Vec::with_capacity(count);
        let mut ranges = Vec::with_capacity(count);
        let mut objects = Vec::new();
        for (i, id) in ids.into_iter().enumerate() {
            if id == 0 && op != 146 {
                native.push(vk::Buffer::null());
                ranges.push(0);
                continue;
            }
            let b = self.object(id, Kind::Buffer)?;
            let usage = if op == 146 {
                vk::BufferUsageFlags::TRANSFORM_FEEDBACK_BUFFER_EXT
            } else {
                vk::BufferUsageFlags::TRANSFORM_FEEDBACK_COUNTER_BUFFER_EXT
            };
            let size = if op != 146 {
                4
            } else if sizes[i] == u64::MAX {
                b.size.saturating_sub(offsets[i])
            } else {
                sizes[i]
            };
            if b.deps.borrow().is_empty()
                || b.flags & usage.as_raw() == 0
                || offsets[i] % 4 != 0
                || size == 0
                || offsets[i].checked_add(size).is_none_or(|n| n > b.size)
                || op == 146 && size > props.max_transform_feedback_buffer_size
            {
                return invalid();
            }
            native.push(vk::Buffer::from_raw(b.raw));
            ranges.push(size);
            objects.push((i, b));
        }
        let ptr = if count == 0 {
            std::ptr::null()
        } else {
            native.as_ptr()
        };
        let off = if count == 0 {
            std::ptr::null()
        } else {
            offsets.as_ptr()
        };
        unsafe {
            match op {
                146 => (api.fp().cmd_bind_transform_feedback_buffers_ext)(
                    raw,
                    first as u32,
                    count as u32,
                    ptr,
                    off,
                    ranges.as_ptr(),
                ),
                147 => (api.fp().cmd_begin_transform_feedback_ext)(
                    raw,
                    first as u32,
                    count as u32,
                    ptr,
                    off,
                ),
                148 => (api.fp().cmd_end_transform_feedback_ext)(
                    raw,
                    first as u32,
                    count as u32,
                    ptr,
                    off,
                ),
                _ => unreachable!(),
            }
        }
        let mut r = c.recording.borrow_mut();
        if op == 146 {
            for (i, b) in &objects {
                r.feedback_buffers.insert(
                    first as u32 + *i as u32,
                    (b.clone(), offsets[*i], ranges[*i]),
                );
            }
        } else {
            r.feedback_active = op == 147;
        }
        for (_, b) in objects {
            c.retain(b);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn query_result_footprints_do_not_touch_padding_or_overflow() {
        assert_eq!(query_layout(0, 3, 24, 5).unwrap(), (8, 64));
        assert_eq!(
            query_layout(
                vk::QueryType::TRANSFORM_FEEDBACK_STREAM_EXT.as_raw() as u32,
                3,
                32,
                5
            )
            .unwrap(),
            (8, 88)
        );
        assert_eq!(query_layout(2, 1, 0, 1).unwrap(), (8, 8));
        for (count, stride) in [(0, 8), (2, 4), (2, u64::MAX), (u64::MAX, 8)] {
            assert!(query_layout(0, count, stride, 5).is_err());
        }
        assert!(query_layout(2, 1, 8, 8).is_err());
    }
}
