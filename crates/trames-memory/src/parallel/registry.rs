// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold publication resources. CPU/native views never enter these locks.
use super::*;
use parking_lot::Mutex;

type Pages = BTreeMap<(u64, u64), Weak<ConcurrentPage>>;
#[derive(Clone, Default)]
pub(super) struct SharedPages(Arc<Mutex<Pages>>);

impl SharedPages {
    /// Preserve one canonical live wrapper even when two address spaces prepare
    /// the same backing concurrently. Creation, page-in, byte refresh and final
    /// candidate destruction happen outside membership custody.
    pub(super) fn intern(
        &self,
        key: (u64, u64),
        matches: impl Fn(&ConcurrentPage) -> bool,
        make: impl FnOnce() -> Arc<ConcurrentPage>,
    ) -> (Arc<ConcurrentPage>, bool) {
        let current = self.0.lock().get(&key).and_then(Weak::upgrade);
        if let Some(current) = current.filter(|page| matches(page)) {
            return (current, false);
        }
        let candidate = make();
        let mut pages = self.0.lock();
        let current = pages.get(&key).and_then(Weak::upgrade);
        if current.as_ref().is_some_and(|page| matches(page)) {
            drop(pages);
            return (current.expect("matched page"), false);
        }
        pages.insert(key, Arc::downgrade(&candidate));
        drop(pages);
        drop(current);
        (candidate, true)
    }

    pub(super) fn prune(&self) {
        self.0.lock().retain(|_, page| page.strong_count() != 0);
    }
}

impl Registry {
    /// New preparation cursor over the original session's frame, code and
    /// physical-window resources. Metrics stay local to the caller; this does
    /// not create a second memory/alias domain or retain any Memory root.
    pub fn share(&self) -> Self {
        Self {
            hardware: self.hardware,
            mmu: self.mmu.clone(),
            shared: self.shared.clone(),
            code_epoch: self.code_epoch.clone(),
            metrics: Metrics::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn concurrent_preparations_keep_original_frames_code_epoch_and_cached_snapshot() {
        let registry = Registry::default();
        let mut original = Memory::default();
        original
            .map_shared_anonymous(
                0x40000,
                PAGE_SIZE,
                Permissions {
                    execute: true,
                    ..Permissions::RW
                },
                false,
            )
            .unwrap();
        let start = Arc::new(Barrier::new(4));
        let joins: Vec<_> = (0..4)
            .map(|_| {
                let mut memory = original.clone();
                let mut cursor = registry.share();
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    let view = memory.parallel_view(&mut cursor).unwrap();
                    (memory, cursor, view)
                })
            })
            .collect();
        let mut results: Vec<_> = joins.into_iter().map(|join| join.join().unwrap()).collect();
        let canonical = results[0]
            .2
            .frame(0x40000, Access::Read)
            .unwrap()
            .bytes
            .clone();
        for (_, cursor, view) in &results {
            assert!(Arc::ptr_eq(&cursor.code_epoch, &registry.code_epoch));
            assert!(Arc::ptr_eq(
                &canonical,
                &view.frame(0x40000, Access::Read).unwrap().bytes
            ));
            assert_eq!(cursor.metrics.full_rebuilds, 1);
        }
        let epoch = registry.code_epoch.load(Ordering::Relaxed);
        results[0]
            .2
            .write_array(0x40000, 42u64.to_le_bytes())
            .unwrap();
        assert!(registry.code_epoch.load(Ordering::Relaxed) > epoch);
        for (_, _, view) in &results {
            assert_eq!(view.read_u64(0x40000).unwrap(), 42);
        }
        let (mut memory, cursor, view) = results.pop().unwrap();
        let mut other = cursor.share();
        let before = memory
            .parallel_cache
            .as_ref()
            .unwrap()
            .source_backing_revision;
        let resumed = memory.parallel_view(&mut other).unwrap();
        let after = memory
            .parallel_cache
            .as_ref()
            .unwrap()
            .source_backing_revision;
        // Other tests can legitimately advance the process-wide backing
        // revision while this mm is unchanged. Require the cache hit only
        // when eligible; original physical/code identity must always survive.
        if before == after {
            assert!(Arc::ptr_eq(&resumed.snapshot, &view.snapshot));
            assert_eq!(other.metrics.cache_hits, 1);
            assert_eq!(other.metrics.full_rebuilds, 0);
        }
        assert!(Arc::ptr_eq(
            &resumed.frame(0x40000, Access::Read).unwrap().bytes,
            &canonical
        ));
        assert!(Arc::ptr_eq(
            &resumed.snapshot.code_epoch,
            &registry.code_epoch
        ));
        assert_eq!(resumed.read_u64(0x40000).unwrap(), 42);
        assert_eq!(
            registry.metrics.full_rebuilds, 0,
            "metrics stay caller-local"
        );
    }

    #[test]
    fn racing_candidates_publish_once_without_holding_membership_during_creation() {
        let registry = Registry::default();
        let start = Arc::new(Barrier::new(4));
        let joins: Vec<_> = (0..4)
            .map(|_| {
                let cursor = registry.share();
                let start = start.clone();
                std::thread::spawn(move || {
                    cursor.shared.intern(
                        (1, 0),
                        |_| true,
                        || {
                            // All candidates must reach construction concurrently;
                            // holding membership across construction would deadlock.
                            start.wait();
                            Arc::new(ConcurrentPage::shared(
                                Arc::new(SharedPage::zero()),
                                cursor.code_epoch.clone(),
                            ))
                        },
                    )
                })
            })
            .collect();
        let pages: Vec<_> = joins.into_iter().map(|join| join.join().unwrap()).collect();
        assert_eq!(pages.iter().filter(|(_, inserted)| *inserted).count(), 1);
        for (page, _) in &pages {
            assert!(Arc::ptr_eq(page, &pages[0].0));
        }
        registry.shared.prune();
        assert_eq!(registry.shared.0.lock().len(), 1);
        drop(pages);
        registry.shared.prune();
        assert!(registry.shared.0.lock().is_empty());
    }

    #[test]
    fn separate_executors_keep_one_deferred_source_without_paging_in_during_preparation() {
        struct Source {
            page: Arc<SharedPage>,
            loads: AtomicU64,
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
                Some((self.0.page.identity, 0))
            }
            fn page_source(&self) -> Option<Arc<dyn PageSource>> {
                Some(self.0.clone())
            }
            fn check(&self, _: u64) -> Result<(), MemoryError> {
                Ok(())
            }
            fn read(&self, _: usize, _: &mut [u8]) -> Result<(), MemoryError> {
                panic!("deferred preparation must not read backing bytes")
            }
            fn write(&self, _: usize, _: &[u8]) -> Result<(), MemoryError> {
                Err(MemoryError::BackingIo(95))
            }
            fn sync(&self) -> Result<(), MemoryError> {
                Ok(())
            }
            fn version(&self) -> u64 {
                0
            }
            fn writable(&self) -> bool {
                false
            }
            fn next_page(&self, _: u64) -> Result<Arc<dyn PageBacking>, MemoryError> {
                Err(MemoryError::InvalidRange)
            }
        }
        let source = Arc::new(Source {
            page: Arc::new(SharedPage::new([42; PAGE_SIZE as usize])),
            loads: AtomicU64::new(0),
        });
        let registry = Registry::default();
        let start = Arc::new(Barrier::new(4));
        let joins: Vec<_> = (0..4)
            .map(|_| {
                let mut memory = Memory::default();
                memory
                    .map_backed(
                        0x40000,
                        vec![Arc::new(Backing(source.clone()))],
                        true,
                        Permissions::R,
                        false,
                    )
                    .unwrap();
                let mut cursor = registry.share();
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    memory.parallel_view(&mut cursor).unwrap()
                })
            })
            .collect();
        drop(registry);
        let views: Vec<_> = joins.into_iter().map(|join| join.join().unwrap()).collect();
        assert_eq!(source.loads.load(Ordering::Relaxed), 0);
        for view in &views {
            assert!(Arc::ptr_eq(
                &view.frame(0x40000, Access::Read).unwrap().bytes,
                &views[0].frame(0x40000, Access::Read).unwrap().bytes,
            ));
            assert_eq!(view.read_array::<4>(0x40000).unwrap(), [42; 4]);
        }
        assert_eq!(source.loads.load(Ordering::Relaxed), 1);
    }
}
