// SPDX-License-Identifier: GPL-3.0-or-later
//! Provided buffer pools and descriptor rings. Pool entries are guest virtual
//! ranges; only a registered descriptor ring is pinned, never implicitly the data.
use super::{u32_at, u64_at, Linux, Result};
use std::collections::{BTreeMap, VecDeque};
use trames_memory::{Access, Memory, MemoryError, PAGE_SIZE};
use trames_vfs::{
    Errno, UringBufferGroup, UringBufferSource, UringProvidedBuffer, UringRequest, UringSqe,
    UringState,
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
impl Linux {
    pub(super) fn uring_buffer_register(
        &mut self,
        state: &mut UringState,
        a: [u64; 6],
        memory: &mut Memory,
    ) -> Result<u64> {
        if matches!(a[1], 23 | 26) {
            return ring_control(&mut state.provided, a, memory);
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
            .pin_rw(address, entries as usize * 16)
            .map_err(|e| match e {
                MemoryError::Limit => Errno(12),
                MemoryError::BackingIo(95) => Errno(95),
                _ => Errno(14),
            })?;
        state.provided.insert(
            id,
            UringBufferGroup {
                owner: memory.instruction_identity().0,
                source: UringBufferSource::Ring {
                    memory: std::sync::Arc::new(ring),
                    head: 0,
                    entries: entries as u16,
                },
            },
        );
        Ok(0)
    }
    pub(super) fn uring_provide(
        &mut self,
        request: &UringRequest,
        state: &mut UringState,
    ) -> Result<(i32, bool)> {
        provide(&request.sqe, request.owner, &mut state.provided)
    }
    pub(super) fn uring_selected_io(
        &mut self,
        request: &UringRequest,
        state: &mut UringState,
        memory: &mut Memory,
    ) -> (Result<(i32, bool)>, u32) {
        let selected = match peek(&request.sqe, request.owner, &state.provided) {
            Ok(b) => b,
            Err(e) => return (Err(e), 0),
        };
        if request.file.as_ref().is_some_and(|f| f.poll(1) == 0) {
            return (Err(Errno(11)), 0);
        }
        let count = if request.sqe.opcode() == 27 && request.sqe.length() == 0 {
            selected.length
        } else {
            selected.length.min(request.sqe.length())
        };
        let mut view = request.clone();
        view.sqe.0[16..24].copy_from_slice(&selected.address.to_le_bytes());
        view.sqe.0[24..28].copy_from_slice(&count.to_le_bytes());
        view.requested = count as u64;
        let result = if view.sqe.opcode() == 22 {
            self.uring_rw(&view, memory)
        } else {
            self.uring_network(&view, memory)
        };
        // A failed readiness probe consumes no buffer. The descriptor/payload
        // stays owned by the application until a non-EAGAIN completion.
        if result == Err(Errno(11)) {
            return (result, 0);
        }
        match &mut state
            .provided
            .get_mut(&request.sqe.buffer_group())
            .unwrap()
            .source
        {
            UringBufferSource::Classic(buffers) => {
                buffers.pop_front();
            }
            UringBufferSource::Ring { head, .. } => *head = head.wrapping_add(1),
        }
        (result, 1 | ((selected.id as u32) << 16))
    }
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
    let group = provided.entry(id).or_insert_with(|| UringBufferGroup {
        owner,
        source: UringBufferSource::Classic(VecDeque::new()),
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
    provided: &mut BTreeMap<u16, UringBufferGroup>,
    a: [u64; 6],
    memory: &mut impl trames_memory::CpuMemory,
) -> Result<u64> {
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
        match provided.get(&id) {
            Some(UringBufferGroup {
                source: UringBufferSource::Ring { .. },
                ..
            }) => {
                provided.remove(&id);
                return Ok(0);
            }
            _ => return Err(Errno(2)),
        }
    }
    unreachable!("only status/unregister passed to ring control")
}
