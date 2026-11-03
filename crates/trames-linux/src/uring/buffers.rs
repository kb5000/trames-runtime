// SPDX-License-Identifier: GPL-3.0-or-later
//! Provided buffer pools and descriptor rings. Pool entries are guest virtual
//! ranges; only a registered descriptor ring is pinned, never implicitly the data.
use super::{u32_at, u64_at, Linux, Result};
use std::collections::{BTreeMap, VecDeque};
use trames_memory::{Access, MemoryError, PAGE_SIZE};
use trames_vfs::{
    Errno, UringBufferGroup, UringBufferSource, UringProvidedBuffer, UringSqe, UringState,
};
const MAX_SLOTS: usize = 65536;
const MAX_GROUPS: usize = 256;
fn capacity(
    provided: &BTreeMap<u16, UringBufferGroup>,
    count: usize,
    new_group: bool,
) -> Result<()> {
    if new_group && provided.len() >= MAX_GROUPS
        || provided.values().map(|g| g.slots()).sum::<usize>() + count > MAX_SLOTS
    {
        return Err(Errno(12));
    }
    Ok(())
}
pub(crate) fn provide(
    s: &UringSqe,
    owner: u64,
    provided: &mut BTreeMap<u16, UringBufferGroup>,
) -> Result<(i32, bool)> {
    if s.op_flags() != 0 || s.fd() <= 0 {
        return Err(Errno(22));
    }
    let count = s.fd() as usize;
    let id = s.buffer_group();
    if s.opcode() == 32 {
        if s.address() != 0 || s.offset() != 0 || s.length() != 0 {
            return Err(Errno(22));
        }
        let group = provided.get_mut(&id).ok_or(Errno(2))?;
        let UringBufferSource::Classic(buffers) = &mut group.source else {
            return Err(Errno(22));
        };
        let removed = count.min(buffers.len());
        for _ in 0..removed {
            buffers.pop_front();
        }
        return Ok((removed as i32, true));
    }
    if s.length() == 0
        || s.offset() > u16::MAX as u64
        || count > MAX_SLOTS
        || s.offset() + count as u64 > 65536
    {
        return Err(Errno(22));
    }
    (s.length() as u64)
        .checked_mul(count as u64)
        .and_then(|n| s.address().checked_add(n))
        .ok_or(Errno(75))?;
    let old = provided.get(&id);
    if old.is_some_and(|g| !matches!(g.source, UringBufferSource::Classic(_)) || g.owner != owner) {
        return Err(Errno(17));
    }
    capacity(provided, count, old.is_none())?;
    let group = provided.entry(id).or_insert_with(|| {
        UringBufferGroup::new(owner, UringBufferSource::Classic(VecDeque::new()))
    });
    let UringBufferSource::Classic(buffers) = &mut group.source else {
        unreachable!()
    };
    for i in 0..count {
        buffers.push_back(UringProvidedBuffer {
            address: s.address() + i as u64 * s.length() as u64,
            length: s.length(),
            id: (s.offset() + i as u64) as u16,
        });
    }
    Ok((0, true))
}
pub(crate) fn peek(
    s: &UringSqe,
    owner: u64,
    provided: &BTreeMap<u16, UringBufferGroup>,
) -> Result<UringProvidedBuffer> {
    let group = provided.get(&s.buffer_group()).ok_or(Errno(105))?;
    // Pools are VM scoped: do not turn another submitter's virtual pointer
    // into a write through the current task's unrelated address space.
    if group.owner != owner {
        return Err(Errno(14));
    }
    match &group.source {
        UringBufferSource::Classic(buffers) => buffers.front().copied().ok_or(Errno(105)),
        UringBufferSource::Ring {
            memory,
            head,
            entries,
        } => {
            // The retained SharedPage guard observes descriptor publication on
            // either execution path; no raw pointer/atomic alias is created.
            let tail = u16::from_le_bytes(memory.read_array(14).map_err(|_| Errno(14))?);
            let available = tail.wrapping_sub(*head);
            if available > *entries {
                return Err(Errno(22));
            }
            if available == 0 {
                return Err(Errno(105));
            }
            let bytes = memory
                .read_array::<16>((*head & (*entries - 1)) as usize * 16)
                .map_err(|_| Errno(14))?;
            Ok(UringProvidedBuffer {
                address: u64_at(&bytes, 0),
                length: u32_at(&bytes, 8),
                id: u16::from_le_bytes(bytes[12..14].try_into().unwrap()),
            })
        }
    }
}

pub(crate) fn ring_control(
    state: &mut UringState,
    a: [u64; 6],
    memory: &mut impl trames_memory::CpuMemory,
) -> Result<u64> {
    let provided = &mut state.provided;
    if a[3] != 1 {
        return Err(Errno(22));
    }
    let bytes = memory.read_array::<40>(a[2]).map_err(|_| Errno(14))?;
    if a[1] == 26 {
        if bytes[8..].iter().any(|b| *b != 0) || u32_at(&bytes, 0) > u16::MAX as u32 {
            return Err(Errno(22));
        }
        Linux::check(memory, a[2], 40, Access::Write)?;
        let group = provided.get(&(u32_at(&bytes, 0) as u16)).ok_or(Errno(2))?;
        let UringBufferSource::Ring { head, .. } = &group.source else {
            return Err(Errno(22));
        };
        memory
            .write_array(a[2] + 4, (*head as u32).to_le_bytes())
            .map_err(|_| Errno(14))?;
        return Ok(0);
    }
    let id = u16::from_le_bytes(bytes[12..14].try_into().unwrap());
    if bytes[14..].iter().any(|b| *b != 0) {
        return Err(Errno(22));
    }
    if a[1] == 23 {
        if bytes[..12].iter().any(|b| *b != 0) {
            return Err(Errno(22));
        }
        if !provided
            .get(&id)
            .is_some_and(|g| matches!(g.source, UringBufferSource::Ring { .. }))
        {
            return Err(Errno(2));
        }
        let group = provided.remove(&id).unwrap();
        if state.busy_groups.contains(&group.identity) {
            state.retired_groups.insert(group.identity, group);
        }
        return Ok(0);
    }
    unreachable!("only status/unregister passed to ring control")
}

pub(crate) fn register_ring(
    state: &mut UringState,
    a: [u64; 6],
    memory: &mut impl trames_memory::CpuMemory,
    deferred: &std::cell::Cell<bool>,
) -> Result<u64> {
    if matches!(a[1], 23 | 26) {
        return ring_control(state, a, memory);
    }
    if a[3] != 1 {
        return Err(Errno(22));
    }
    let bytes = memory.read_array::<40>(a[2]).map_err(|_| Errno(14))?;
    let id = u16::from_le_bytes(bytes[12..14].try_into().unwrap());
    if bytes[14..].iter().any(|b| *b != 0) {
        return Err(Errno(22));
    }
    let address = u64_at(&bytes, 0);
    let entries = u32_at(&bytes, 8);
    if !address.is_multiple_of(PAGE_SIZE)
        || entries == 0
        || entries > 32768
        || !entries.is_power_of_two()
    {
        return Err(Errno(22));
    }
    if state.provided.contains_key(&id) {
        return Err(Errno(17));
    }
    capacity(&state.provided, entries as usize, true)?;
    let ring = memory
        .pin_buffer_rw(address, entries as usize * 16)
        .unwrap_or_else(|| {
            deferred.set(true);
            Err(MemoryError::BackingIo(95))
        })
        .map_err(|e| match e {
            MemoryError::Limit => Errno(12),
            MemoryError::BackingIo(95) => Errno(95),
            _ => Errno(14),
        })?;
    state.provided.insert(
        id,
        UringBufferGroup::new(
            memory.instruction_identity().0,
            UringBufferSource::Ring {
                memory: std::sync::Arc::new(ring),
                head: 0,
                entries: entries as u16,
            },
        ),
    );
    Ok(0)
}
