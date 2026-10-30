// SPDX-License-Identifier: GPL-3.0-or-later
//! Native descriptor layouts and variable allocations. Resource slots stay
//! sparse and follow their live set, including after command recording.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Binding {
    pub ty: u32,
    pub count: u32,
    pub stages: u32,
    pub flags: u32,
    pub immutable: Vec<u64>,
}
impl Binding {
    pub fn count(&self, set: &Object) -> u32 {
        if self.flags & vk::DescriptorBindingFlags::VARIABLE_DESCRIPTOR_COUNT.as_raw() != 0 {
            set.size as u32
        } else {
            self.count
        }
    }
}
// Layout/allocation payloads are not bounded by the old smoke-test array sizes.
// Preflight before allocating their owned copy, then let allocation/driver limits
// decide capacity. Updates retain the existing bounded wire chunks.
pub(super) fn words(m: &impl CpuMemory, at: u64, count: u64, width: usize) -> Result<Vec<u64>> {
    let count = usize::try_from(count)
        .ok()
        .and_then(|n| n.checked_mul(width))
        .ok_or(Failure::Vk(vk::Result::ERROR_OUT_OF_HOST_MEMORY))?;
    let bytes = count
        .checked_mul(8)
        .ok_or(Failure::Vk(vk::Result::ERROR_OUT_OF_HOST_MEMORY))?;
    m.check(at, bytes, Access::Read)?;
    let mut data = Vec::new();
    data.try_reserve_exact(bytes)
        .map_err(|_| Failure::Vk(vk::Result::ERROR_OUT_OF_HOST_MEMORY))?;
    data.resize(bytes, 0);
    m.read(at, &mut data)?;
    Ok(data
        .chunks_exact(8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .collect())
}
pub(super) fn words32(m: &impl CpuMemory, at: u64, count: u64) -> Result<Vec<u32>> {
    let count =
        usize::try_from(count).map_err(|_| Failure::Vk(vk::Result::ERROR_OUT_OF_HOST_MEMORY))?;
    let size = count
        .checked_mul(4)
        .ok_or(Failure::Vk(vk::Result::ERROR_OUT_OF_HOST_MEMORY))?;
    m.check(at, size, Access::Read)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| Failure::Vk(vk::Result::ERROR_OUT_OF_HOST_MEMORY))?;
    bytes.resize(size, 0);
    m.read(at, &mut bytes)?;
    Ok(bytes
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .collect())
}
fn flags(device: &Device, ty: u32, value: u64) -> Result<u32> {
    let f = device.compute_features;
    if value & !15 != 0 {
        return unsupported();
    }
    if value & 1 != 0 {
        let feature = match ty {
            0..=2 => compute::DESCRIPTOR_BINDING_SAMPLED_IMAGE_UPDATE_AFTER_BIND,
            3 => compute::DESCRIPTOR_BINDING_STORAGE_IMAGE_UPDATE_AFTER_BIND,
            4 => compute::DESCRIPTOR_BINDING_UNIFORM_TEXEL_BUFFER_UPDATE_AFTER_BIND,
            5 => compute::DESCRIPTOR_BINDING_STORAGE_TEXEL_BUFFER_UPDATE_AFTER_BIND,
            6 => compute::DESCRIPTOR_BINDING_UNIFORM_BUFFER_UPDATE_AFTER_BIND,
            7 => compute::DESCRIPTOR_BINDING_STORAGE_BUFFER_UPDATE_AFTER_BIND,
            _ => return unsupported(),
        };
        if f & feature == 0 {
            return unsupported();
        }
    }
    if value & 2 != 0 && f & compute::DESCRIPTOR_BINDING_UPDATE_UNUSED_WHILE_PENDING == 0
        || value & 4 != 0 && f & compute::DESCRIPTOR_BINDING_PARTIALLY_BOUND == 0
        || value & 8 != 0
            && (f & compute::DESCRIPTOR_BINDING_VARIABLE_DESCRIPTOR_COUNT == 0
                || matches!(ty, 8 | 9))
    {
        return unsupported();
    }
    Ok(value as u32)
}
impl Backend {
    pub(super) fn descriptor_layout(
        &mut self,
        m: &mut impl CpuMemory,
        op: u64,
        a: [u64; 16],
    ) -> Result<()> {
        let result = self.descriptor_layout_inner(m, op, a);
        if op == 212
            && matches!(
                result,
                Err(Failure::Vk(vk::Result::ERROR_FEATURE_NOT_PRESENT))
            )
        {
            return write(m, a[3], &vk::FALSE.to_le_bytes());
        }
        result
    }
    fn descriptor_layout_inner(
        &mut self,
        m: &mut impl CpuMemory,
        op: u64,
        a: [u64; 16],
    ) -> Result<()> {
        output(m, a[3], if op == 23 { 8 } else { 4 })?;
        let device = self.device.as_ref().unwrap().clone();
        if a[4] & !2 != 0 || a[5] != 0 && a[5] != 6 {
            return unsupported();
        }
        let stride = if a[5] == 0 { 4 } else { 6 };
        let wire = words(m, a[1], a[2], stride)?;
        let mut metadata = BTreeMap::new();
        let mut resources = Vec::new();
        let mut samplers = Vec::new();
        for row in wire.chunks_exact(stride) {
            if row[0] > u32::MAX as u64 || row[1] > 10 || row[2] > u32::MAX as u64 {
                return unsupported();
            }
            visibility_stages(row[3])?;
            let binding_flags =
                flags(&device, row[1] as u32, if stride == 6 { row[4] } else { 0 })?;
            if binding_flags & 1 != 0 && a[4] & 2 == 0 {
                return invalid();
            }
            let immutable = if stride == 6 && row[5] != 0 {
                words(m, row[5], row[2], 1)?
            } else {
                Vec::new()
            };
            if !immutable.is_empty() && row[1] > 1 {
                return invalid();
            }
            let mut native = Vec::new();
            for &id in &immutable {
                let s = self.object(id, Kind::Sampler)?;
                native.push(vk::Sampler::from_raw(s.raw));
                resources.push(s);
            }
            let immutable = native.iter().map(|s| s.as_raw()).collect();
            samplers.push(native);
            if metadata
                .insert(
                    row[0] as u32,
                    Binding {
                        ty: row[1] as u32,
                        count: row[2] as u32,
                        stages: row[3] as u32,
                        flags: binding_flags,
                        immutable,
                    },
                )
                .is_some()
            {
                return invalid();
            }
        }
        let maximum = metadata.last_key_value().map(|(&key, _)| key);
        if metadata
            .iter()
            .any(|(&key, b)| b.flags & 8 != 0 && Some(key) != maximum)
        {
            return invalid();
        }
        let mut bindings = Vec::new();
        let mut binding_flags = Vec::new();
        for (row, immutable) in wire.chunks_exact(stride).zip(&samplers) {
            let b = &metadata[&(row[0] as u32)];
            let mut native = vk::DescriptorSetLayoutBinding::default()
                .binding(row[0] as u32)
                .descriptor_type(vk::DescriptorType::from_raw(b.ty as i32))
                .descriptor_count(b.count)
                .stage_flags(visibility_stages(row[3])?);
            if !immutable.is_empty() {
                native.p_immutable_samplers = immutable.as_ptr();
            }
            bindings.push(native);
            binding_flags.push(vk::DescriptorBindingFlags::from_raw(b.flags));
        }
        let mut flags_info =
            vk::DescriptorSetLayoutBindingFlagsCreateInfo::default().binding_flags(&binding_flags);
        let mut info = vk::DescriptorSetLayoutCreateInfo::default()
            .flags(vk::DescriptorSetLayoutCreateFlags::from_raw(a[4] as u32))
            .bindings(&bindings);
        if binding_flags.iter().any(|v| !v.is_empty()) {
            info = info.push_next(&mut flags_info);
        }
        if op == 212 {
            let mut variable = vk::DescriptorSetVariableDescriptorCountLayoutSupport::default();
            let mut support = vk::DescriptorSetLayoutSupport::default().push_next(&mut variable);
            unsafe {
                device
                    .native
                    .get_descriptor_set_layout_support(&info, &mut support);
            }
            write(m, a[3], &support.supported.to_le_bytes())?;
            if a[6] != 0 {
                write(
                    m,
                    a[6],
                    &variable.max_variable_descriptor_count.to_le_bytes(),
                )?;
            }
        } else {
            self.room(1)?;
            let raw = unsafe { device.native.create_descriptor_set_layout(&info, None) }?;
            let id = self.put(
                Kind::DescriptorLayout,
                raw.as_raw(),
                resources,
                0,
                a[4] as u32,
            );
            *self.objects[&id].bindings.borrow_mut() = metadata;
            self.publish(m, a[3], id)?;
        }
        Ok(())
    }
    pub(super) fn allocate_descriptors(
        &mut self,
        m: &mut impl CpuMemory,
        a: [u64; 16],
    ) -> Result<()> {
        let ids = words(m, a[2], a[3], 1)?;
        let count = ids.len();
        self.room(count)?;
        output(m, a[4], count * 8)?;
        let pool = self.object(a[1], Kind::DescriptorPool)?;
        let counts = if a[5] != 0 {
            words32(m, a[5], count as u64)?
        } else {
            vec![0; count]
        };
        let mut deps = Vec::new();
        let mut layouts = Vec::new();
        for (&id, &count) in ids.iter().zip(&counts) {
            let layout = self.object(id, Kind::DescriptorLayout)?;
            if layout.flags & 2 != 0 && pool.flags & 2 == 0 {
                return invalid();
            }
            if let Some(b) = layout.bindings.borrow().values().find(|b| b.flags & 8 != 0) {
                if count > b.count {
                    return invalid();
                }
            }
            layouts.push(vk::DescriptorSetLayout::from_raw(layout.raw));
            deps.push(layout);
        }
        let mut variable = vk::DescriptorSetVariableDescriptorCountAllocateInfo::default()
            .descriptor_counts(&counts);
        let mut info = vk::DescriptorSetAllocateInfo::default()
            .descriptor_pool(vk::DescriptorPool::from_raw(pool.raw))
            .set_layouts(&layouts);
        if a[5] != 0 {
            info = info.push_next(&mut variable);
        }
        let raw = unsafe { pool.device.native.allocate_descriptor_sets(&info) }?;
        for (i, ((native, layout), &count)) in raw.into_iter().zip(deps).zip(&counts).enumerate() {
            let id = self.put(
                Kind::DescriptorSet,
                native.as_raw(),
                vec![pool.clone(), layout],
                count as u64,
                0,
            );
            self.objects[&id]
                .descriptor_epoch
                .set(pool.descriptor_epoch.get());
            self.publish(m, a[4] + i as u64 * 8, id)?;
        }
        Ok(())
    }
}

// Binding traversal also serves consecutive-binding writes/copies. Sparse array
// capacities are metadata; only initialized slots own resources.
pub(super) fn spans(
    layout: &Object,
    set: &Object,
    binding: u32,
    offset: u32,
    count: u32,
    ty: u32,
) -> Result<Vec<(u32, u32, u32)>> {
    let bindings = layout.bindings.borrow();
    let first = bindings
        .get(&binding)
        .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
    let mut skip = offset;
    let mut remaining = count;
    let mut result = Vec::new();
    for (&key, b) in bindings.range(binding..) {
        let capacity = b.count(set);
        if capacity == 0 {
            continue;
        }
        if b.ty != ty
            || b.stages != first.stages
            || b.flags != first.flags
            || b.immutable.is_empty() != first.immutable.is_empty()
        {
            return invalid();
        }
        if skip >= capacity {
            skip -= capacity;
            continue;
        }
        let n = remaining.min(capacity - skip);
        result.push((key, skip, n));
        remaining -= n;
        skip = 0;
        if remaining == 0 {
            return Ok(result);
        }
    }
    invalid()
}
impl Backend {
    pub(super) fn descriptor_pending(
        &mut self,
        m: &mut impl CpuMemory,
        set: &Rc<Object>,
        new: Vec<Rc<Object>>,
    ) -> Result<()> {
        if set.pending_submissions.get() == 0 {
            return Ok(());
        }
        let (resources, _) = resource_graph(new);
        let scope = coherent::Scope::resources(&resources);
        self.coherent_sync_scope(m, &scope, true)?;
        for submission in &mut self.submissions {
            if submission.commands_complete
                || !submission
                    .descriptor_sets
                    .iter()
                    .any(|s| Rc::ptr_eq(s, set))
            {
                continue;
            }
            for r in &resources {
                if submission.resource_ids.insert(Rc::as_ptr(r) as usize) {
                    submission._resources.push(r.clone());
                }
            }
            submission.coherent_scope.extend(&scope);
        }
        self.coherent_submitted(&scope);
        Ok(())
    }
    pub(super) fn copy_descriptors(&mut self, m: &mut impl CpuMemory, a: [u64; 16]) -> Result<()> {
        let src = self.object(a[1], Kind::DescriptorSet)?;
        let dst = self.object(a[4], Kind::DescriptorSet)?;
        let source_layout = src.deps.borrow()[1].clone();
        let target_layout = dst.deps.borrow()[1].clone();
        let ty = source_layout
            .bindings
            .borrow()
            .get(&(a[2] as u32))
            .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?
            .ty;
        let sources = spans(
            &source_layout,
            &src,
            a[2] as u32,
            a[3] as u32,
            a[7] as u32,
            ty,
        )?;
        let targets = spans(
            &target_layout,
            &dst,
            a[5] as u32,
            a[6] as u32,
            a[7] as u32,
            ty,
        )?;
        let mut slots = Vec::new();
        let mut ranges = Vec::new();
        for &(binding, offset, count) in &sources {
            for index in offset..offset + count {
                let mut slot = src.bound_resources.borrow().get(&(binding, index)).cloned();
                if slot.is_none() && ty == 0 {
                    let meta = source_layout.bindings.borrow();
                    let binding = &meta[&binding];
                    if let Some(raw) = binding.immutable.get(index as usize) {
                        slot = Some(
                            source_layout
                                .deps
                                .borrow()
                                .iter()
                                .filter(|r| r.kind == Kind::Sampler && r.raw == *raw)
                                .cloned()
                                .collect(),
                        );
                    }
                }
                slots.push(slot);
                ranges.push(src.dynamic_ranges.borrow().get(&(binding, index)).copied());
            }
        }
        self.descriptor_pending(m, &dst, slots.iter().flatten().flatten().cloned().collect())?;
        let mut copies = Vec::new();
        let (mut si, mut ti, mut so, mut to) = (0, 0, 0, 0);
        while si < sources.len() && ti < targets.len() {
            let (sbind, selem, snum) = sources[si];
            let (tbind, telem, tnum) = targets[ti];
            let count = (snum - so).min(tnum - to);
            copies.push(
                vk::CopyDescriptorSet::default()
                    .src_set(vk::DescriptorSet::from_raw(src.raw))
                    .src_binding(sbind)
                    .src_array_element(selem + so)
                    .dst_set(vk::DescriptorSet::from_raw(dst.raw))
                    .dst_binding(tbind)
                    .dst_array_element(telem + to)
                    .descriptor_count(count),
            );
            so += count;
            to += count;
            if so == snum {
                si += 1;
                so = 0;
            }
            if to == tnum {
                ti += 1;
                to = 0;
            }
        }
        unsafe {
            dst.device.native.update_descriptor_sets(&[], &copies);
        }
        let mut i = 0;
        let mut out = dst.bound_resources.borrow_mut();
        let mut dynamic = dst.dynamic_ranges.borrow_mut();
        for (binding, offset, count) in targets {
            for index in offset..offset + count {
                if let Some(slot) = slots[i].take() {
                    out.insert((binding, index), slot);
                } else {
                    out.remove(&(binding, index));
                }
                if let Some(range) = ranges[i] {
                    dynamic.insert((binding, index), range);
                } else {
                    dynamic.remove(&(binding, index));
                }
                i += 1;
            }
        }
        Ok(())
    }
}
