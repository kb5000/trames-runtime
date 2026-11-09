// SPDX-License-Identifier: GPL-3.0-or-later
//! Read-only observations of the original admitted VMA/frame metadata.
use super::*;
impl View {
    pub(super) fn observe_mapped(&self, address: u64, len: u64) -> Result<(), MemoryError> {
        let end = Memory::mapping_end(address, len)?;
        let mut at = address;
        while at < end {
            if let Some(stop) = self.snapshot.anonymous.mapped_end(at) {
                at = stop.min(end);
            } else if let Some(&stop) = self
                .snapshot
                .reservations
                .range(..=at)
                .next_back()
                .map(|(_, end)| end)
                .filter(|&&end| at < end)
            {
                at = stop.min(end);
            } else if self.snapshot.pages.contains_key(&at) {
                at += PAGE_SIZE;
            } else {
                return Err(MemoryError::Unmapped(at));
            }
        }
        Ok(())
    }
    pub(super) fn observe_resident(&self, address: u64, len: u64) -> Result<Vec<u8>, MemoryError> {
        self.observe_mapped(address, len)?;
        Ok((address..address + len)
            .step_by(PAGE_SIZE as usize)
            .map(|base| {
                if let Some(&index) = self.snapshot.pages.get(&base) {
                    let frame = &self.snapshot.frames[index];
                    u8::from(frame.charge.resident() && frame.error.is_none())
                } else {
                    self.snapshot.anonymous.resident(base)
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observations_skip_unreached_anonymous_ranges_and_inaccessible_reservations() {
        let mut memory = Memory::default();
        memory.map(0x1000, 3 * PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x2000, &[1]).unwrap();
        memory.reserve(0x5000, 2 * PAGE_SIZE, false).unwrap();
        memory.map(0x100000000, 1 << 36, Permissions::RW).unwrap();
        let used = memory.resident_bytes();
        let view = memory.parallel_view(&mut Registry::default()).unwrap();
        assert_eq!(
            CpuMemory::resident(&view, 0x1000, 3 * PAGE_SIZE),
            Some(Ok(vec![0, 1, 0]))
        );
        assert_eq!(
            CpuMemory::resident(&view, 0x5000, 2 * PAGE_SIZE),
            Some(Ok(vec![0, 0]))
        );
        assert_eq!(
            CpuMemory::validate_mapped(&view, 0x100000000, 1 << 36),
            Some(Ok(()))
        );
        for (address, length) in [
            (0x1000, 3 * PAGE_SIZE),
            (0x1000, 6 * PAGE_SIZE),
            (0x1001, PAGE_SIZE),
            (ADDRESS_LIMIT, PAGE_SIZE),
            (0x5000, 0),
        ] {
            assert_eq!(
                CpuMemory::validate_mapped(&view, address, length),
                Some(memory.validate_mapped(address, length))
            );
        }
        assert!(view.snapshot.anonymous.cached(0x1000).is_none());
        assert!(view.snapshot.anonymous.cached(0x100000000).is_none());
        assert_eq!(memory.resident_bytes(), used);
    }
    #[test]
    fn observations_follow_original_live_additions_and_other_actor_writes() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut registry = Registry::default();
        let mut first = memory.parallel_view(&mut registry).unwrap();
        let second = memory.parallel_view(&mut registry).unwrap();
        assert_eq!(
            CpuMemory::validate_mapped(&first, 0x200000, 2 * PAGE_SIZE),
            Some(Err(MemoryError::Unmapped(0x200000)))
        );
        memory.map_anonymous_live(0x200000, 2 * PAGE_SIZE).unwrap();
        assert_eq!(
            CpuMemory::validate_mapped(&second, 0x200000, 2 * PAGE_SIZE),
            Some(Ok(()))
        );
        assert_eq!(
            CpuMemory::resident(&second, 0x200000, 2 * PAGE_SIZE),
            Some(Ok(vec![0, 0]))
        );
        first.write(0x201000, &[42]).unwrap();
        assert_eq!(
            CpuMemory::resident(&second, 0x200000, 2 * PAGE_SIZE),
            Some(Ok(vec![0, 1]))
        );
        assert!(second.snapshot.anonymous.cached(0x200000).is_none());
        drop((first, second));
        assert_eq!(memory.resident(0x200000, 2 * PAGE_SIZE), Ok(vec![0, 1]));
    }
    #[test]
    fn descriptor_residency_observation_never_loads_deferred_backing_bytes() {
        use std::sync::atomic::AtomicUsize;
        struct Source {
            page: Arc<SharedPage>,
            loads: AtomicUsize,
        }
        impl PageSource for Source {
            fn load(&self) -> Result<Arc<SharedPage>, MemoryError> {
                self.loads.fetch_add(1, Ordering::Relaxed);
                Ok(self.page.clone())
            }
        }
        struct Backing(Arc<Source>);
        impl PageBacking for Backing {
            fn parallel_key(&self) -> Option<(u64, u64)> {
                Some((0xabcd, 1))
            }
            fn check(&self, _: u64) -> Result<(), MemoryError> {
                Ok(())
            }
            fn read(&self, _: usize, _: &mut [u8]) -> Result<(), MemoryError> {
                panic!("unexpected backing read")
            }
            fn write(&self, _: usize, _: &[u8]) -> Result<(), MemoryError> {
                panic!("unexpected backing write")
            }
            fn sync(&self) -> Result<(), MemoryError> {
                Ok(())
            }
            fn writable(&self) -> bool {
                true
            }
            fn version(&self) -> u64 {
                1
            }
            fn next_page(&self, _: u64) -> Result<Arc<dyn PageBacking>, MemoryError> {
                Err(MemoryError::BackingIo(95))
            }
            fn page_source(&self) -> Option<Arc<dyn PageSource>> {
                Some(self.0.clone())
            }
        }
        let source = Arc::new(Source {
            page: Arc::new(SharedPage::zero()),
            loads: AtomicUsize::new(0),
        });
        let mut memory = Memory::default();
        memory
            .map_backed(
                0x1000,
                vec![Arc::new(Backing(source.clone()))],
                true,
                Permissions::RW,
                false,
            )
            .unwrap();
        let view = memory.parallel_view(&mut Registry::default()).unwrap();
        for _ in 0..4 {
            assert_eq!(
                CpuMemory::resident(&view, 0x1000, PAGE_SIZE),
                Some(Ok(vec![0]))
            );
        }
        assert_eq!(source.loads.load(Ordering::Relaxed), 0);
        let mut byte = [0];
        view.read(0x1000, &mut byte).unwrap();
        assert_eq!(source.loads.load(Ordering::Relaxed), 1);
        assert_eq!(
            CpuMemory::resident(&view, 0x1000, PAGE_SIZE),
            Some(Ok(vec![1]))
        );
        assert_eq!(memory.resident(0x1000, PAGE_SIZE), Ok(vec![1]));
    }
}
