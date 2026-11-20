// SPDX-License-Identifier: GPL-3.0-or-later
//! The guest exposes one NUMA node. Placement therefore changes policy
//! metadata without migrating host pages or consulting policy on a CPU access.
use crate::Linux;
use std::sync::atomic::{AtomicU32, Ordering};
use trames_memory::{Access, CpuMemory, Memory, MemoryError, ADDRESS_LIMIT, PAGE_SIZE};
use trames_vfs::Errno;

const DEFAULT: u32 = 0;
const PREFERRED: u32 = 1;
const BIND: u32 = 2;
const INTERLEAVE: u32 = 3;
const LOCAL: u32 = 4;
const PREFERRED_MANY: u32 = 5;
const WEIGHTED_INTERLEAVE: u32 = 6;
const STATIC: u32 = 1 << 15;
const RELATIVE: u32 = 1 << 14;
const BALANCING: u32 = 1 << 13;
const MODE_FLAGS: u32 = STATIC | RELATIVE | BALANCING;
const MASK_BITS: u64 = PAGE_SIZE * 8;

#[derive(Default)]
pub struct TaskMemoryPolicy(AtomicU32);
impl TaskMemoryPolicy {
    pub(crate) fn fork(&self) -> Self {
        Self(AtomicU32::new(self.0.load(Ordering::Relaxed)))
    }

    pub(crate) fn set(&self, memory: &impl CpuMemory, a: [u64; 6]) -> Result<u64, Errno> {
        let (mode, has_node) = arguments(memory, a[0], a[1], a[2])?;
        self.0.store(normalize(mode, has_node)?, Ordering::Relaxed);
        Ok(0)
    }
    pub(crate) fn get(&self, memory: &mut impl CpuMemory, a: [u64; 6]) -> Result<u64, Errno> {
        let flags = a[4];
        if flags & !7 != 0 || flags & 4 != 0 && flags != 4 || flags & 6 == 0 && a[3] != 0 {
            return Err(Errno(22));
        }
        let mode = if flags & 2 != 0 {
            if a[3] >= ADDRESS_LIMIT || memory.check_translation(a[3]).is_err() {
                return Err(Errno(14));
            }
            memory.numa_mode_at(a[3])
        } else if flags == 4 {
            DEFAULT
        } else {
            self.0.load(Ordering::Relaxed)
        };
        if flags == 1 && !matches!(mode & !MODE_FLAGS, INTERLEAVE | WEIGHTED_INTERLEAVE) {
            return Err(Errno(22));
        }
        if a[0] != 0 {
            Linux::check(memory, a[0], 4, Access::Write)?;
        }
        let length = if a[1] == 0 {
            0
        } else {
            if !(1..=MASK_BITS).contains(&a[2]) {
                return Err(Errno(22));
            }
            let bytes = a[2].div_ceil(64) as usize * 8;
            Linux::check(memory, a[1], bytes, Access::Write)?;
            bytes
        };
        if a[0] != 0 {
            let value = if flags & 1 == 0 { mode } else { 0 };
            memory
                .write_array(a[0], value.to_le_bytes())
                .map_err(|_| Errno(14))?;
        }
        if length != 0 {
            let mut mask = vec![0; length];
            mask[0] = u8::from(flags == 4 || !matches!(mode & !MODE_FLAGS, DEFAULT | LOCAL));
            memory.write(a[1], &mask).map_err(|_| Errno(14))?;
        }
        Ok(0)
    }
}

fn arguments(
    memory: &impl CpuMemory,
    raw: u64,
    address: u64,
    maxnode: u64,
) -> Result<(u32, bool), Errno> {
    let mode = raw as u32;
    let base = mode & !MODE_FLAGS;
    if base > WEIGHTED_INTERLEAVE
        || mode & (STATIC | RELATIVE) == STATIC | RELATIVE
        || mode & BALANCING != 0 && !matches!(base, BIND | PREFERRED_MANY)
    {
        return Err(Errno(22));
    }
    // Linux get_nodes subtracts one before copying the user bitmap.
    let bits = maxnode.wrapping_sub(1);
    if address == 0 || bits == 0 {
        return Ok((mode, false));
    }
    if bits > MASK_BITS {
        return Err(Errno(22));
    }
    let mut node_zero = false;
    for word in (0..bits.div_ceil(64)).rev() {
        let src = address.checked_add(word * 8).ok_or(Errno(14))?;
        let mut value = u64::from_le_bytes(memory.read_array(src).map_err(|_| Errno(14))?);
        let width = (bits - word * 64).min(64);
        value &= u64::MAX >> (64 - width);
        if word == 0 {
            node_zero = value & 1 != 0;
            value &= !1;
        }
        if value != 0 {
            return Err(Errno(22));
        }
    }
    Ok((mode, node_zero))
}
fn normalize(mode: u32, node: bool) -> Result<u32, Errno> {
    match mode & !MODE_FLAGS {
        DEFAULT if !node => Ok(DEFAULT),
        LOCAL | PREFERRED if !node && mode & MODE_FLAGS == 0 => Ok(LOCAL),
        DEFAULT | LOCAL => Err(Errno(22)),
        _ if node => Ok(mode),
        _ => Err(Errno(22)),
    }
}

fn range(start: u64, len: u64) -> Result<(u64, u64), Errno> {
    let start = crate::memory_queries::untag_mapping(start);
    if !start.is_multiple_of(PAGE_SIZE) {
        return Err(Errno(22));
    }
    let len = len.checked_add(PAGE_SIZE - 1).ok_or(Errno(22))? & !(PAGE_SIZE - 1);
    let end = start.checked_add(len).ok_or(Errno(22))?;
    Ok((start, end))
}
pub(crate) fn bind(memory: &mut Memory, a: [u64; 6], can_move_all: bool) -> Result<u64, Errno> {
    let (mode, has_node) = arguments(memory, a[2], a[3], a[4])?;
    let flags = a[5] as u32;
    if flags & !7 != 0 {
        return Err(Errno(22));
    }
    if flags & 4 != 0 && !can_move_all {
        return Err(Errno(1));
    }
    let (start, end) = range(a[0], a[1])?;
    if start == end {
        return Ok(0);
    }
    let mode = normalize(mode, has_node)?;
    if end > ADDRESS_LIMIT {
        return Err(Errno(14));
    }
    memory
        .bind_numa_policy(start, end - start, mode)
        .map_err(|e| match e {
            MemoryError::Unmapped(_) => Errno(14),
            _ => Linux::memory_errno(e),
        })?;
    Ok(0)
}
pub(crate) fn home_node(memory: &Memory, a: [u64; 6]) -> Result<u64, Errno> {
    if a[2] != 0 || a[3] != 0 {
        return Err(Errno(22));
    }
    let (start, end) = range(a[0], a[1])?;
    if start == end {
        return Ok(0);
    }
    let modes = memory.numa_modes_in(start, end);
    if modes.is_empty() {
        return Err(Errno(2));
    }
    if modes
        .iter()
        .any(|mode| !matches!(mode & !MODE_FLAGS, BIND | PREFERRED_MANY))
    {
        return Err(Errno(95));
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::Permissions;

    #[test]
    fn mask_width_and_move_all_capability_precede_policy_changes() {
        let mut mm = Memory::default();
        mm.map(0x1000, 2 * PAGE_SIZE, Permissions::RW).unwrap();
        mm.write_array(0x1000, 3u64.to_le_bytes()).unwrap();
        let task = TaskMemoryPolicy::default();
        // maxnode minus one selects just bit zero; the next bit is ignored.
        task.set(&mm, [BIND.into(), 0x1000, 2, 0, 0, 0]).unwrap();
        assert_eq!(
            task.set(&mm, [INTERLEAVE.into(), 0x1000, 3, 0, 0, 0]),
            Err(Errno(22))
        );
        assert_eq!(
            task.set(&mm, [INTERLEAVE.into(), 0x4000, 64, 0, 0, 0]),
            Err(Errno(14))
        );
        task.get(&mut mm, [0x1100, 0x1108, 130, 0, 0, 0]).unwrap();
        assert_eq!(mm.read_array::<4>(0x1100).unwrap(), BIND.to_le_bytes());
        assert_eq!(mm.read_array::<8>(0x1108).unwrap(), 1u64.to_le_bytes());
        assert_eq!(mm.read_array::<16>(0x1110).unwrap(), [0; 16]);
        let args = [0x2000, PAGE_SIZE, BIND.into(), 0x1000, 2, 4];
        assert_eq!(bind(&mut mm, args, false), Err(Errno(1)));
        assert_eq!(mm.numa_mode_at(0x2000), DEFAULT);
        assert_eq!(bind(&mut mm, args, true), Ok(0));
        assert_eq!(mm.numa_mode_at(0x2000), BIND);
    }
}
