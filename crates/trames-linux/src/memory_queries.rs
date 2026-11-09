// SPDX-License-Identifier: GPL-3.0-or-later
//! Read-only VM observation and non-discard advice share one source/solo ABI.
use crate::Linux;
use trames_memory::{Access, CpuMemory, ADDRESS_LIMIT, PAGE_SIZE};
use trames_vfs::Errno;

pub fn memory_query_entry(number: u32, args: [u64; 6]) -> bool {
    matches!(number, 232 | 236) || number == 233 && args[2] as u32 != 4
}

pub fn memory_query(
    memory: &mut impl CpuMemory,
    number: u32,
    args: [u64; 6],
) -> Option<Result<u64, Errno>> {
    match number {
        236 => Some(mempolicy(memory, args)),
        232 => mincore(memory, args),
        233 if args[2] as u32 != 4 => advice(memory, args),
        _ => None,
    }
}

fn mempolicy(memory: &mut impl CpuMemory, a: [u64; 6]) -> Result<u64, Errno> {
    let flags = a[4];
    if flags & !7 != 0
        || flags & 4 != 0 && flags & 3 != 0
        || flags == 1
        || a[3] != 0 && flags & 2 == 0
    {
        return Err(Errno(22));
    }
    // This ABI's target address is untagged, unlike ordinary TBI byte accesses.
    // Translation checks include inaccessible reservations without paging in.
    if flags & 2 != 0 && (a[3] >= ADDRESS_LIMIT || memory.check_translation(a[3]).is_err()) {
        return Err(Errno(14));
    }
    if a[0] != 0 {
        Linux::check(memory, a[0], 4, Access::Write)?;
    }
    let length = if a[1] != 0 {
        if a[2] == 0 || a[2] > 65536 {
            return Err(Errno(22));
        }
        let length = a[2].div_ceil(64) as usize * 8;
        Linux::check(memory, a[1], length, Access::Write)?;
        length
    } else {
        0
    };
    if a[0] != 0 {
        memory
            .write_array(a[0], 0u32.to_le_bytes())
            .map_err(|_| Errno(14))?;
    }
    if length != 0 {
        let mut mask = vec![0; length];
        if flags & 4 != 0 {
            mask[0] = 1;
        }
        memory.write(a[1], &mask).map_err(|_| Errno(14))?;
    }
    Ok(0)
}

fn mincore(memory: &mut impl CpuMemory, a: [u64; 6]) -> Option<Result<u64, Errno>> {
    if a[1] == 0 {
        return Some(if a[0].is_multiple_of(PAGE_SIZE) {
            Ok(0)
        } else {
            Err(Errno(22))
        });
    }
    let len = match Linux::page_length(a[1]) {
        Ok(len) => len,
        Err(error) => return Some(Err(error)),
    };
    if len > trames_memory::MAX_DESCRIBED_BYTES as u64 {
        return Some(Err(Errno(12)));
    }
    let resident = memory.resident(a[0], len)?;
    Some(resident.map_err(Linux::memory_errno).and_then(|resident| {
        Linux::check(memory, a[2], resident.len(), Access::Write)?;
        memory.write(a[2], &resident).map_err(|_| Errno(14))?;
        Ok(0)
    }))
}

fn advice(memory: &mut impl CpuMemory, a: [u64; 6]) -> Option<Result<u64, Errno>> {
    if !a[0].is_multiple_of(PAGE_SIZE) || !matches!(a[2] as u32,0..=3|14..=17) {
        return Some(Err(Errno(22)));
    }
    if a[1] == 0 {
        return Some(Ok(0));
    }
    let len = match Linux::page_length(a[1]) {
        Ok(len) => len,
        Err(error) => return Some(Err(error)),
    };
    Some(
        memory
            .validate_mapped(a[0], len)?
            .map(|()| 0)
            .map_err(Linux::memory_errno),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions};
    fn memory() -> Memory {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x1000, &[0xa5; 256]).unwrap();
        memory.map(0x4000, 3 * PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x5000, &[42]).unwrap();
        memory.reserve(0x8000, 2 * PAGE_SIZE, false).unwrap();
        memory
    }
    #[test]
    fn memory_query_abi_is_shared_by_original_memory_and_admitted_views() {
        let mut cases = vec![
            (236, [0, 0, u64::MAX, 0, 0, 0], 0u32),
            (236, [0x1000, 0x1010, 65, 0, 4, 0], 0),
            (236, [0x1000, 0, 0, 0x4001, 3, 0], 0),
            (236, [0x1000, 0, 0, 0x8001, 2, 0], 0),
            (236, [0x1000, 0, 0, 0x7000, 2, 0], 14),
            (236, [0x1000, 0, 0, 0xab00000000004000, 2, 0], 14),
            (236, [0x1000, 0, 0, 0x4000, 0, 0], 22),
            (236, [0x1000, 0, 0, 0, 1, 0], 22),
            (236, [0x1000, 0, 0, 0, 8, 0], 22),
            (236, [0x1000, 0, 0, 0, 6, 0], 22),
            (236, [0x1000, 0x1010, 0, 0, 0, 0], 22),
            (236, [0x1000, 0x1010, 65537, 0, 0, 0], 22),
            (236, [0x1000, 0x1ff8, 65, 0, 0, 0], 14),
            (236, [0x1fff, 0x1010, 0, 0, 0, 0], 14),
            (232, [0x4000, 3 * PAGE_SIZE, 0x1000, 0, 0, 0], 0),
            (232, [0x8000, 2 * PAGE_SIZE, 0x1000, 0, 0, 0], 0),
            (232, [0x4000, 0, 0, 0, 0, 0], 0),
            (232, [0x4001, 0, 0, 0, 0, 0], 22),
            (232, [0x4001, PAGE_SIZE, 0x1000, 0, 0, 0], 22),
            (232, [0x7000, PAGE_SIZE, 0, 0, 0, 0], 12),
            (232, [0x6000, 3 * PAGE_SIZE, 0, 0, 0, 0], 12),
            (232, [0x4000, 3 * PAGE_SIZE, 0, 0, 0, 0], 14),
            (
                232,
                [
                    0x4001,
                    trames_memory::MAX_DESCRIBED_BYTES as u64 + 1,
                    0,
                    0,
                    0,
                    0,
                ],
                12,
            ),
            (232, [0x4000, u64::MAX, 0, 0, 0, 0], 22),
            (233, [0x4001, 0, 0, 0, 0, 0], 22),
            (233, [0x4000, 0, 9, 0, 0, 0], 22),
            (233, [0x4000, 0, 0, 0, 0, 0], 0),
            (233, [0x6000, 3 * PAGE_SIZE, 0, 0, 0, 0], 12),
        ];
        for advice in [0, 1, 2, 3, 14, 15, 16, 17, 1u64 << 32 | 3] {
            cases.push((233, [0x8000, 2 * PAGE_SIZE, advice, 0, 0, 0], 0));
        }
        for (number, args, error) in cases {
            let expected = Some(if error == 0 { Ok(0) } else { Err(Errno(error)) });
            let mut owner = memory();
            let mut original = memory();
            let mut view = original
                .parallel_view(&mut trames_memory::parallel::Registry::default())
                .unwrap();
            assert!(memory_query_entry(number, args));
            assert_eq!(
                memory_query(&mut owner, number, args),
                expected,
                "owner {number} {args:?}"
            );
            assert_eq!(
                memory_query(&mut view, number, args),
                expected,
                "view {number} {args:?}"
            );
            assert_eq!(
                owner.read_array::<256>(0x1000).unwrap(),
                view.read_array::<256>(0x1000).unwrap(),
                "outputs {number} {args:?}"
            );
            if error != 0 {
                assert_eq!(owner.read_array::<256>(0x1000).unwrap(), [0xa5; 256]);
            }
        }
    }
    #[test]
    fn mincore_observes_before_an_overlapping_result_buffer_becomes_resident() {
        fn check(memory: &mut impl CpuMemory) {
            assert_eq!(
                memory_query(memory, 232, [0x4000, 3 * PAGE_SIZE, 0x4000, 0, 0, 0]),
                Some(Ok(0))
            );
            assert_eq!(memory.read_array::<3>(0x4000).unwrap(), [0, 1, 0]);
            assert_eq!(
                memory.resident(0x4000, 3 * PAGE_SIZE),
                Some(Ok(vec![1, 1, 0]))
            );
        }
        check(&mut memory());
        let mut original = memory();
        check(
            &mut original
                .parallel_view(&mut trames_memory::parallel::Registry::default())
                .unwrap(),
        );
    }
    struct Legacy(Memory);
    impl CpuMemory for Legacy {
        fn read(&self, a: u64, b: &mut [u8]) -> Result<(), trames_memory::MemoryError> {
            CpuMemory::read(&self.0, a, b)
        }
        fn write(&mut self, a: u64, b: &[u8]) -> Result<(), trames_memory::MemoryError> {
            CpuMemory::write(&mut self.0, a, b)
        }
        fn check(&self, a: u64, n: usize, x: Access) -> Result<(), trames_memory::MemoryError> {
            CpuMemory::check(&self.0, a, n, x)
        }
        fn check_translation(&self, a: u64) -> Result<(), trames_memory::MemoryError> {
            CpuMemory::check_translation(&self.0, a)
        }
        fn fetch_u32(&self, a: u64) -> Result<u32, trames_memory::MemoryError> {
            CpuMemory::fetch_u32(&self.0, a)
        }
        fn instruction_identity(&self) -> (u64, u64, u64) {
            CpuMemory::instruction_identity(&self.0)
        }
        fn instruction_page_identity(
            &self,
            a: u64,
        ) -> Result<(u64, u64, u64), trames_memory::MemoryError> {
            CpuMemory::instruction_page_identity(&self.0, a)
        }
        fn atomic_update<T>(
            &mut self,
            a: u64,
            n: usize,
            f: impl FnOnce(&mut [u8]) -> (T, bool),
        ) -> Result<T, trames_memory::MemoryError> {
            CpuMemory::atomic_update(&mut self.0, a, n, f)
        }
        fn exclusive_read(
            &mut self,
            a: u64,
            b: &mut [u8],
        ) -> Result<u128, trames_memory::MemoryError> {
            CpuMemory::exclusive_read(&mut self.0, a, b)
        }
        fn exclusive_write(
            &mut self,
            a: u64,
            b: &[u8],
            t: Option<u128>,
        ) -> Result<bool, trames_memory::MemoryError> {
            CpuMemory::exclusive_write(&mut self.0, a, b, t)
        }
    }
    #[test]
    fn missing_observation_capability_defers_before_effects_and_discard_keeps_its_mutator() {
        let mut memory = Legacy(memory());
        for (number, args) in [
            (232, [0x4000, PAGE_SIZE, 0x1000, 0, 0, 0]),
            (233, [0x4000, PAGE_SIZE, 0, 0, 0, 0]),
        ] {
            assert_eq!(memory_query(&mut memory, number, args), None);
            assert_eq!(memory.0.read_array::<256>(0x1000).unwrap(), [0xa5; 256]);
        }
        let discard = [0x4000, PAGE_SIZE, 4, 0, 0, 0];
        assert!(!memory_query_entry(233, discard));
        assert_eq!(memory_query(&mut memory, 233, discard), None);
        assert_eq!(
            memory_query(&mut memory, 233, [0x4000, 0, 100, 0, 0, 0]),
            Some(Err(Errno(22)))
        );
    }
}
