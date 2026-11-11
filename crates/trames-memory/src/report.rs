// SPDX-License-Identifier: GPL-3.0-or-later
//! Read-only mm metadata. Reports retain accounting and immutable layout, never
//! a guest byte actor, a Memory Arc, a physical page, or an execution View.
use super::*;
use std::sync::{Arc, OnceLock, RwLock};

/// Original image bytes, independent of argv/envp pointer-array edits. These
/// ranges describe guest addresses only; observing them touches no guest page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageRanges {
    pub arguments: (u64, u64),
    pub environment: (u64, u64),
}
#[derive(Clone)]
pub struct MemoryReport(pub(super) Arc<Report>);
pub(super) struct Report {
    identity: u64,
    owner: std::sync::Weak<ReportOwner>,
    retired: std::sync::atomic::AtomicBool,
    image: RwLock<Option<ImageRanges>>,
    state: RwLock<Arc<Layout>>,
    pub(super) reads: OnceLock<read_export::Reads>,
    pub(super) read_waker: RwLock<Option<read_export::ReadWaker>>,
}
#[derive(Default)]
pub(super) struct ReportOwner(OnceLock<std::sync::Weak<Report>>);
impl Drop for ReportOwner {
    fn drop(&mut self) {
        if let Some(report) = self.0.get().and_then(std::sync::Weak::upgrade) {
            MemoryReport(report).retire();
        }
    }
}
struct Layout {
    virtual_bytes: u64,
    regions: Arc<RegionLayout>,
    account: Arc<Account>,
    maps: OnceLock<Arc<[u8]>>,
}

/// Immutable proc metadata, separate from resident pages and their ownership.
/// Actual virtual edits replace only their interval. A published report/fork
/// retains the previous compact value; it never retains a page or execution View.
#[derive(Clone, Default)]
pub(super) struct RegionLayout {
    pub(super) ranges: Vec<(u64, u64, Permissions)>,
}
impl RegionLayout {
    pub(super) fn replace(&mut self, start: u64, end: u64, permissions: Option<Permissions>) {
        let first = self.ranges.partition_point(|r| r.1 <= start);
        let last = self.ranges.partition_point(|r| r.0 < end);
        let mut replacement = Vec::with_capacity(5);
        if first > 0 {
            replacement.push(self.ranges[first - 1]);
        }
        if first < last && self.ranges[first].0 < start {
            replacement.push((self.ranges[first].0, start, self.ranges[first].2));
        }
        if let Some(p) = permissions {
            replacement.push((start, end, p));
        }
        if first < last && self.ranges[last - 1].1 > end {
            replacement.push((end, self.ranges[last - 1].1, self.ranges[last - 1].2));
        }
        if last < self.ranges.len() {
            replacement.push(self.ranges[last]);
        }
        let mut merged: Vec<(u64, u64, Permissions)> = Vec::with_capacity(replacement.len());
        for r in replacement {
            if let Some(previous) = merged.last_mut() {
                if previous.1 == r.0 && previous.2 == r.2 {
                    previous.1 = r.1;
                    continue;
                }
            }
            merged.push(r);
        }
        let stop = (last + 1).min(self.ranges.len());
        self.ranges.splice(first.saturating_sub(1)..stop, merged);
    }
}
impl Memory {
    /// Match an already-published original mm without rebuilding unrelated
    /// layout metadata during a pending reader's target lookup.
    pub fn has_memory_report(&self, report: &MemoryReport) -> bool {
        if let Some(shared) = &self.shared {
            return shared.borrow().has_memory_report(report);
        }
        self.report_cache
            .borrow()
            .as_ref()
            .is_some_and(|(_, current, _)| current.same_resource(report))
    }
    /// A Runtime may explicitly run an exited image again. Begin its new
    /// logical task lifetime without reviving any old opened proc resource.
    pub fn renew_memory_report(&self) {
        if let Some(shared) = &self.shared {
            return shared.borrow().renew_memory_report();
        }
        let mut cache = self.report_cache.borrow_mut();
        if cache
            .as_ref()
            .is_some_and(|(_, report, _)| report.0.retired.load(Ordering::Relaxed))
        {
            *cache = None;
        }
    }
    /// One checked page fragment through the same translation/region access as
    /// CPU reads. File/shmem pages are excluded; private COW pages are accepted.
    pub fn read_proc_chunk(&self, address: u64, out: &mut [u8]) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow().read_proc_chunk(address, out);
        }
        let address = address & 0x00ffffffffffffff;
        if out.len() > (PAGE_SIZE - address % PAGE_SIZE) as usize {
            return Err(MemoryError::InvalidRange);
        }
        if out.is_empty() {
            return Ok(());
        }
        let page = self.page_for_access(address, out.len(), Access::Read)?;
        if !page.proc_anonymous() {
            return Err(MemoryError::BackingIo(95));
        }
        page.read_bytes((address % PAGE_SIZE) as usize, out)
    }
    /// Set by the shared Linux image builder after packing the entry stack.
    /// Fork inherits the ranges; exec builds a fresh Memory/image identity.
    pub fn set_image_ranges(&mut self, ranges: ImageRanges) {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().set_image_ranges(ranges);
        }
        self.image_ranges = Some(ranges);
        if let Some((_, report, _)) = &*self.report_cache.borrow() {
            *report.0.image.write().unwrap() = Some(ranges);
        }
    }
    /// Publish at actual mapping/accounting changes. Live residency is queried
    /// from the original account on demand; layout publication reads no bytes.
    pub fn memory_report(&self) -> MemoryReport {
        if let Some(shared) = &self.shared {
            return shared.borrow().memory_report();
        }
        let mut cache = self.report_cache.borrow_mut();
        if let Some((generation, report, _)) = &*cache {
            if *generation == self.layout_revision
                && Arc::ptr_eq(&report.0.state.read().unwrap().account, &self.account)
            {
                return report.clone();
            }
        }
        let layout = Arc::new(Layout {
            virtual_bytes: self.virtual_bytes(),
            regions: self.region_layout.clone(),
            account: self.account.clone(),
            maps: OnceLock::new(),
        });
        let owner = cache.as_ref().map_or_else(
            || Arc::new(ReportOwner::default()),
            |(_, _, owner)| owner.clone(),
        );
        let report = if let Some((_, report, _)) = &*cache {
            *report.0.state.write().unwrap() = layout;
            report.clone()
        } else {
            MemoryReport(Arc::new(Report {
                identity: self.original_identity,
                owner: Arc::downgrade(&owner),
                retired: std::sync::atomic::AtomicBool::new(false),
                image: RwLock::new(self.image_ranges),
                state: RwLock::new(layout),
                reads: OnceLock::new(),
                read_waker: RwLock::new(None),
            }))
        };
        owner.0.get_or_init(|| Arc::downgrade(&report.0));
        *cache = Some((self.layout_revision, report.clone(), owner));
        report
    }
    /// The last logical mm owner has exited or exec'd. Physical custody may
    /// remain for an already accepted guarded borrower; proc readers must not
    /// mistake that retirement reference for a live Linux address space.
    /// Call only at the existing last-owner lifecycle boundary. No guest bytes
    /// or execution View are inspected or released here.
    pub fn retire_memory_report(&self) {
        if let Some(shared) = &self.shared {
            return shared.borrow().retire_memory_report();
        }
        if let Some((_, report, _)) = &*self.report_cache.borrow() {
            report.retire();
        }
    }
}
impl Page {
    pub(super) fn proc_anonymous(&self) -> bool {
        self.backing
            .as_ref()
            .is_none_or(|b| !b.shared && b.private_copy)
    }
}
impl MemoryReport {
    pub(super) fn retire(&self) {
        self.0.retired.store(true, Ordering::Relaxed);
        self.retire_reads();
    }
    pub fn image_ranges(&self) -> Option<ImageRanges> {
        *self.0.image.read().unwrap()
    }
    /// Metadata observers do not keep a dead address space alive. CLONE_VM
    /// aliases retain the same original owner until its last Memory is gone.
    pub fn alive(&self) -> bool {
        !self.0.retired.load(Ordering::Relaxed) && self.0.owner.strong_count() != 0
    }
    pub fn identity(&self) -> u64 {
        self.0.identity
    }
    pub fn virtual_bytes(&self) -> u64 {
        self.0.state.read().unwrap().virtual_bytes
    }
    pub fn resident_bytes(&self) -> usize {
        {
            let account = self.0.state.read().unwrap().account.clone();
            account.resident_bytes()
        }
    }
    pub fn maps(&self) -> Arc<[u8]> {
        let layout = self.0.state.read().unwrap().clone();
        layout
            .maps
            .get_or_init(|| {
                use std::fmt::Write;
                let mut maps = String::new();
                for &(start, end, access) in &layout.regions.ranges {
                    let _ = writeln!(
                        maps,
                        "{start:012x}-{end:012x} {}{}{}p 00000000 00:00 0",
                        if access.read { 'r' } else { '-' },
                        if access.write { 'w' } else { '-' },
                        if access.execute { 'x' } else { '-' }
                    );
                    if maps.len() >= 1024 * 1024 {
                        break;
                    }
                }
                maps.into_bytes().into()
            })
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compact_layout_matches_page_and_reservation_oracle_across_virtual_edits() {
        let mut memory = Memory::default();
        let report = memory.memory_report();
        let mut seed = 0x1234_5678_9abc_def0u64;
        for _ in 0..3000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let base = (1 + (seed >> 3) % 64) * PAGE_SIZE;
            let len = (1 + (seed >> 12) % 7) * PAGE_SIZE;
            let permissions = [
                Permissions::NONE,
                Permissions::R,
                Permissions::RW,
                Permissions::RX,
            ][(seed >> 20) as usize & 3];
            let _ = match seed & 7 {
                0 => memory.map(base, len, permissions),
                1 => memory.map_fixed(base, len, permissions),
                2 => memory.protect(base, len, permissions),
                3 => memory.reserve(base, len, true),
                4 => memory.unmap(base, len),
                5 => memory.discard(base, len),
                6 => memory.remap(base, PAGE_SIZE, 0x100000 + base, PAGE_SIZE, true),
                _ => {
                    let mut fork = memory.clone();
                    fork.map_fixed(base, len, permissions).unwrap();
                    assert_eq!(fork.regions(), fork.regions_from_pages());
                    Ok(())
                }
            };
            let expected = memory.regions_from_pages();
            assert_eq!(memory.regions(), expected);
            memory.memory_report();
            let layout = report.0.state.read().unwrap().clone();
            assert_eq!(layout.regions.ranges, expected);
            assert_eq!(
                report.virtual_bytes(),
                expected.iter().map(|r| r.1 - r.0).sum::<u64>()
            );
        }
    }

    #[test]
    fn published_layout_retains_compact_value_across_materialization_fork_and_failed_edits() {
        let mut memory = Memory::default();
        let huge = PAGE_SIZE * 1_048_576;
        memory.map(0x1000, huge, Permissions::RW).unwrap();
        let report = memory.memory_report();
        let original = report.0.state.read().unwrap().clone();
        let maps = report.maps();
        let regions = memory.region_layout.clone();
        memory.write(0x1000, b"x").unwrap();
        memory.discard(0x1000, PAGE_SIZE).unwrap();
        memory.memory_report();
        assert!(Arc::ptr_eq(&regions, &memory.region_layout));
        assert!(Arc::ptr_eq(&maps, &report.maps()));
        assert_eq!(
            memory.protect(huge, PAGE_SIZE * 2, Permissions::R),
            Err(MemoryError::Unmapped(huge + PAGE_SIZE))
        );
        assert!(Arc::ptr_eq(&regions, &memory.region_layout));
        let mut fork = memory.clone();
        fork.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        assert_eq!(
            memory.regions(),
            vec![(0x1000, 0x1000 + huge, Permissions::RW)]
        );
        memory.reserve(0x1000, PAGE_SIZE, true).unwrap();
        memory.memory_report();
        assert_eq!(
            original.regions.ranges,
            vec![(0x1000, 0x1000 + huge, Permissions::RW)]
        );
        assert_eq!(report.virtual_bytes(), huge);
        assert_eq!(memory.regions(), memory.regions_from_pages());
    }
    #[test]
    #[ignore = "layout publication timing; run with --release --nocapture"]
    fn mapping_report_publication_benchmark() {
        let mut memory = Memory::default();
        let pages = 65_536;
        memory
            .map(0x10000, PAGE_SIZE * pages, Permissions::R)
            .unwrap();
        // Same descriptor population as a large file mapping, without reading
        // or allocating its bytes. Each tiny edit must publish current proc maps.
        memory.materialize_descriptors(0x10000, (PAGE_SIZE * pages) as usize);
        let report = memory.memory_report();
        let began = std::time::Instant::now();
        for _ in 0..200 {
            memory.map(0x20000000, PAGE_SIZE, Permissions::RW).unwrap();
            memory.memory_report();
            assert_eq!(report.virtual_bytes(), (pages + 1) * PAGE_SIZE);
            memory.unmap(0x20000000, PAGE_SIZE).unwrap();
            memory.memory_report();
        }
        println!(
            "layout publication: 400 edits, {pages} page descriptors, {} us",
            began.elapsed().as_micros()
        );
        assert_eq!(
            memory.regions(),
            vec![(0x10000, 0x10000 + pages * PAGE_SIZE, Permissions::R)]
        );
    }
    #[test]
    fn jit_writes_and_residency_preserve_published_layout_until_mapping_changes() {
        let mut memory = Memory::default();
        memory
            .map(
                0x1000,
                PAGE_SIZE,
                Permissions {
                    read: true,
                    write: true,
                    execute: true,
                },
            )
            .unwrap();
        memory.map(0x3000, PAGE_SIZE * 32, Permissions::RW).unwrap();
        let report = memory.memory_report();
        let original = report.0.state.read().unwrap().clone();
        let maps = report.maps();
        let code = memory.instruction_revision();
        for value in 0..64 {
            memory.write(0x1000, &[value]).unwrap();
            memory.write(0x3000 + value as u64, &[value]).unwrap();
            memory.memory_report();
        }
        let mut registry = Default::default();
        let mut view = memory.parallel_view(&mut registry).unwrap();
        view.write(0x1000, &[99]).unwrap();
        drop(view);
        memory.commit_parallel().unwrap();
        memory.memory_report();
        assert_ne!(memory.instruction_revision(), code);
        assert!(Arc::ptr_eq(&original, &report.0.state.read().unwrap()));
        assert!(Arc::ptr_eq(&maps, &report.maps()));
        assert_eq!(report.resident_bytes(), PAGE_SIZE as usize * 2);

        memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        memory.memory_report();
        assert!(!Arc::ptr_eq(&original, &report.0.state.read().unwrap()));
        assert!(String::from_utf8_lossy(&report.maps()).contains("r-xp"));
        memory.unmap(0x3000, PAGE_SIZE * 32).unwrap();
        memory.memory_report();
        assert_eq!(report.virtual_bytes(), PAGE_SIZE);
        memory.map_anonymous_live(0x50000, PAGE_SIZE).unwrap();
        memory.memory_report();
        assert_eq!(report.virtual_bytes(), PAGE_SIZE * 2);
    }

    #[test]
    fn mapping_generation_wrap_keeps_original_observers_and_updates_layout() {
        let mut memory = Memory::default();
        let report = memory.memory_report();
        memory.layout_revision = u64::MAX;
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let current = memory.memory_report();
        assert!(current.same_resource(&report));
        assert!(report.alive());
        assert_eq!(report.virtual_bytes(), PAGE_SIZE);
        assert!(String::from_utf8_lossy(&report.maps()).contains("rw-p"));
    }

    #[test]
    fn rerunning_an_exited_image_does_not_revive_its_original_report() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let old = memory.memory_report();
        memory.retire_memory_report();
        assert!(!old.alive());
        memory.renew_memory_report();
        let current = memory.memory_report();
        assert!(current.alive());
        assert!(!old.alive());
        memory.unmap(0x1000, PAGE_SIZE).unwrap();
        memory.memory_report();
        assert_eq!(current.virtual_bytes(), 0);
        assert_eq!(
            old.virtual_bytes(),
            PAGE_SIZE,
            "old observations remain in their original lifetime"
        );
    }
    #[test]
    fn proc_chunk_distinguishes_shmem_from_private_cow_on_owner_and_cpu_views() {
        let mut memory = Memory::default();
        memory
            .map_shared_anonymous(0x3000, PAGE_SIZE, Permissions::RW, false)
            .unwrap();
        memory.write(0x3000, b"back").unwrap();
        let object = memory.frames[memory.frame(0x3000).unwrap()]
            .as_ref()
            .unwrap()
            .backing
            .as_ref()
            .unwrap()
            .object
            .clone();
        memory
            .map_backed(0x4000, vec![object], false, Permissions::RW, false)
            .unwrap();
        let mut out = [0; 4];
        assert_eq!(memory.read_array::<4>(0x4000).unwrap(), *b"back");
        assert_eq!(
            memory.read_proc_chunk(0x3000, &mut out),
            Err(MemoryError::BackingIo(95))
        );
        assert_eq!(
            memory.read_proc_chunk(0x4000, &mut out),
            Err(MemoryError::BackingIo(95))
        );
        let mut registry = Default::default();
        let mut view = memory.parallel_view(&mut registry).unwrap();
        assert_eq!(
            view.proc_read_chunk(0x3000, &mut out),
            Some(Err(MemoryError::BackingIo(95)))
        );
        assert_eq!(
            view.proc_read_chunk(0x4000, &mut out),
            Some(Err(MemoryError::BackingIo(95)))
        );
        view.write(0x4000, b"copy").unwrap();
        assert_eq!(view.proc_read_chunk(0x4000, &mut out), Some(Ok(())));
        assert_eq!(&out, b"copy");
        drop(view);
        memory.commit_parallel().unwrap();
        assert_eq!(memory.read_proc_chunk(0x4000, &mut out), Ok(()));
        assert_eq!(
            memory.pin_read(0x4000, 4).unwrap().read(0, 4).unwrap(),
            b"copy"
        );
        assert!(memory.pin_read(0x3000, 4).is_err());
        // Reusing the incremental snapshot after dirty-journal drain preserves
        // the actual private-COW classification without re-reading its source.
        let view = memory.parallel_view(&mut registry).unwrap();
        assert_eq!(view.proc_read_chunk(0x4000, &mut out), Some(Ok(())));
        assert_eq!(&out, b"copy");
        assert_eq!(
            view.proc_read_chunk(0x3000, &mut out),
            Some(Err(MemoryError::BackingIo(95)))
        );
    }
    #[test]
    fn image_ranges_are_shared_metadata_without_guest_byte_authority_or_residency() {
        let mut memory = Memory::default();
        let report = memory.memory_report();
        assert_eq!(report.image_ranges(), None);
        let image = ImageRanges {
            arguments: (0x1000, 0x1008),
            environment: (0x1008, 0x1010),
        };
        memory.set_image_ranges(image);
        assert_eq!(report.image_ranges(), Some(image));
        assert_eq!(
            report.resident_bytes(),
            0,
            "recording ranges does not touch any guest page"
        );
        let mut fork = memory.clone();
        assert_eq!(fork.memory_report().image_ranges(), Some(image));
        assert_ne!(fork.memory_report().identity(), report.identity());
        fork.set_image_ranges(ImageRanges {
            arguments: (0x2000, 0x2008),
            environment: (0x2008, 0x2008),
        });
        assert_eq!(report.image_ranges(), Some(image));
        let mut shared = memory.share();
        shared.set_image_ranges(ImageRanges {
            arguments: image.arguments,
            environment: (0x1010, 0x1020),
        });
        assert_eq!(report.image_ranges(), shared.memory_report().image_ranges());
        drop(shared);
        drop(memory);
        assert!(!report.alive());
    }
    #[test]
    fn retired_report_is_dead_while_an_accepted_guarded_view_keeps_physical_memory() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x1000, &[7]).unwrap();
        let report = memory.memory_report();
        let mut borrower = memory.parallel_view(&mut Default::default()).unwrap();
        memory.retire_memory_report();
        memory.retire_memory_report();
        assert!(!report.alive());
        assert!(!memory.memory_report().alive());
        borrower.write(0x1000, &[8]).unwrap();
        assert_eq!(borrower.read_array::<1>(0x1000).unwrap(), [8]);
        drop(borrower);
        memory.commit_parallel().unwrap();
        assert_eq!(memory.read_array::<1>(0x1000).unwrap(), [8]);
        assert!(!report.alive());
    }
    #[test]
    fn remote_metadata_reports_live_residency_without_becoming_a_byte_actor() {
        fn shared<T: Send + Sync>() {}
        shared::<MemoryReport>();
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory
            .map(0x4000, PAGE_SIZE * 2, Permissions::NONE)
            .unwrap();
        let report = memory.memory_report();
        assert_eq!(report.resident_bytes(), 0);
        assert_eq!(report.virtual_bytes(), PAGE_SIZE * 3);
        let mut view = memory
            .parallel_view(&mut parallel::Registry::default())
            .unwrap();
        // SAFETY: the report has no physical bytes or View; this is the sole
        // execution actor and Memory remains untouched until it is dropped.
        assert!(unsafe { view.try_exclusive_private() });
        view.write(0x1000, &[1]).unwrap();
        let remote = report.clone();
        std::thread::spawn(move || {
            assert_eq!(remote.resident_bytes(), PAGE_SIZE as usize);
            assert!(String::from_utf8_lossy(&remote.maps()).contains("rw-p"));
            assert!(String::from_utf8_lossy(&remote.maps()).contains("---p"));
        })
        .join()
        .unwrap();
        drop(view);
        memory.commit_parallel().unwrap();
        memory.unmap(0x1000, PAGE_SIZE).unwrap();
        assert_eq!(report.resident_bytes(), 0);
        assert_eq!(
            report.virtual_bytes(),
            PAGE_SIZE * 3,
            "accepted immutable layout"
        );
        let current = memory.memory_report();
        assert_eq!(current.virtual_bytes(), PAGE_SIZE * 2);
        assert_eq!(current.identity(), report.identity());
        assert_eq!(
            report.virtual_bytes(),
            PAGE_SIZE * 2,
            "original mm publication reaches old observers"
        );
        assert_ne!(memory.clone().memory_report().identity(), report.identity());
        let peer = memory.share();
        drop(memory);
        assert!(report.alive());
        drop(peer);
        assert!(!report.alive());
    }
}
