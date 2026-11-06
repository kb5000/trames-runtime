// SPDX-License-Identifier: GPL-3.0-or-later
//! On-demand readers of original virtual pages. Only activation touches Memory,
//! at its existing quiescent boundary. Readers retain bounded physical pins;
//! mapping changes and last-mm retirement revoke the cached virtual authority.
use super::*;
use std::sync::{Arc, Mutex, RwLock, Weak};
use trames_shared::{IoSignal, IoSubscription, Readiness};

pub(super) type Reads = Mutex<BTreeMap<u64, Weak<ReadRange>>>;
pub(super) type ReadWaker = Arc<dyn Fn(MemoryReport) + Send + Sync>;

#[derive(Clone)]
pub struct MemoryRead(Arc<ReadRange>);
pub(super) struct ReadRange {
    report: MemoryReport,
    base: u64,
    state: RwLock<ReadState>,
    ready: Arc<Readiness>,
}
enum ReadState {
    Pending { requested: bool },
    Ready(Option<ReadLease>),
}
struct ReadLease {
    bytes: Option<ReadBuffer>,
    // Private file COW still obeys the original provider's EOF/check semantics.
    // A backing change requests revalidation at the original mm boundary; it
    // never grants an Arc provider to a worker or adds a CPU load/store check.
    backing_revision: Option<u64>,
}
impl ReadState {
    fn ready(&self) -> bool {
        match self {
            Self::Pending { .. } => false,
            Self::Ready(None) => true,
            Self::Ready(Some(lease)) => lease
                .backing_revision
                .is_none_or(|revision| revision == backing::backing_revision()),
        }
    }
}
impl MemoryReport {
    /// Rebind when the same live image enters a new execution session. The
    /// callback must weakly reference that session and must not retain Memory.
    pub fn bind_read_waker(&self, wake: ReadWaker) {
        *self.0.read_waker.write().unwrap() = Some(wake.clone());
        if self.has_requested_reads() {
            wake(self.clone());
        }
    }
    pub fn has_requested_reads(&self) -> bool {
        self.read_ranges(0, u64::MAX).iter().any(|read| {
            matches!(
                *read.state.read().unwrap(),
                ReadState::Pending { requested: true }
            )
        })
    }
    /// Retry an already requested read when its original task becomes visible.
    /// This neither creates a new request nor retains a guest byte actor.
    pub fn wake_requested_reads(&self) {
        if self.has_requested_reads() {
            self.wake_reads();
        }
    }
    /// Resource identity, including a renewed lifetime of the same image.
    pub fn same_resource(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub fn request_read_page(&self, address: u64) -> Option<MemoryRead> {
        let read = self.prepare_read_page(address)?;
        read.request();
        Some(read)
    }
    /// Gather one operation's page dependencies before publishing its wakeup.
    pub fn supports_reads(&self) -> bool {
        !self.alive() || self.0.read_waker.read().unwrap().is_some()
    }
    pub fn prepare_read_page(&self, address: u64) -> Option<MemoryRead> {
        if !self.supports_reads() {
            return None;
        }
        let base = (address & 0x00ffffffffffffff) & !(PAGE_SIZE - 1);
        let read = {
            let mut reads = self.0.reads.get_or_init(Default::default).lock().unwrap();
            if let Some(read) = reads.get(&base).and_then(Weak::upgrade) {
                MemoryRead(read)
            } else {
                if reads.len() >= 4096 {
                    reads.retain(|_, read| read.strong_count() != 0);
                }
                let read = Arc::new(ReadRange {
                    report: self.clone(),
                    base,
                    state: RwLock::new(if self.alive() {
                        ReadState::Pending { requested: false }
                    } else {
                        ReadState::Ready(None)
                    }),
                    ready: Default::default(),
                });
                reads.insert(base, Arc::downgrade(&read));
                MemoryRead(read)
            }
        };
        Some(read)
    }
    pub fn request_reads(&self, reads: &[MemoryRead]) {
        let mut requested = false;
        for read in reads {
            debug_assert!(read.0.report.same_resource(self));
            requested |= read.mark_requested();
        }
        if requested {
            self.wake_reads();
        }
    }
    fn wake_reads(&self) {
        let wake = self.0.read_waker.read().unwrap().clone();
        if let Some(wake) = wake {
            wake(self.clone());
        }
    }
    fn read_ranges(&self, start: u64, end: u64) -> Vec<Arc<ReadRange>> {
        self.0.reads.get().map_or_else(Vec::new, |reads| {
            reads
                .lock()
                .unwrap()
                .range(start..end)
                .filter_map(|(_, read)| read.upgrade())
                .collect()
        })
    }
    pub(super) fn retire_reads(&self) {
        for read in self.read_ranges(0, u64::MAX) {
            *read.state.write().unwrap() = ReadState::Ready(None);
            read.ready.notify_locked();
        }
    }
}

impl MemoryRead {
    fn request(&self) {
        if self.mark_requested() {
            self.0.report.wake_reads();
        }
    }
    fn mark_requested(&self) -> bool {
        let mut state = self.0.state.write().unwrap();
        if !self.0.report.alive() {
            *state = ReadState::Ready(None);
            false
        } else if state.ready() || matches!(*state, ReadState::Pending { requested: true }) {
            false
        } else {
            *state = ReadState::Pending { requested: true };
            true
        }
    }
    /// Subscribe before testing readiness. An invalidated reader requests a
    /// fresh activation; unused cached pages are never repinned speculatively.
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.0.ready.subscribe(signal)
    }
    pub fn ready(&self) -> bool {
        self.request();
        self.0.state.read().unwrap().ready()
    }
    /// None means wait before effects. The original state guard spans the byte
    /// copy, ordering a successful virtual invalidation after an accepted read.
    pub fn read_chunk(&self, address: u64, out: &mut [u8]) -> Option<Result<usize, MemoryError>> {
        let result = self.try_read_chunk(address, out);
        if result.is_none() {
            self.request();
        }
        result
    }
    /// Inspect a fragment while gathering a batch. The caller publishes all
    /// missing pages with request_reads before parking, without guessed output.
    pub fn try_read_chunk(
        &self,
        address: u64,
        out: &mut [u8],
    ) -> Option<Result<usize, MemoryError>> {
        let address = address & 0x00ffffffffffffff;
        let Some(offset) = address.checked_sub(self.0.base) else {
            return Some(Err(MemoryError::InvalidRange));
        };
        if offset >= PAGE_SIZE || out.len() > (PAGE_SIZE - offset) as usize {
            return Some(Err(MemoryError::InvalidRange));
        }
        if out.is_empty() {
            return Some(Ok(0));
        }
        let state = self.0.state.read().unwrap();
        if !self.0.report.alive() {
            return Some(Ok(0));
        }
        if state.ready() {
            return Some(match &*state {
                ReadState::Ready(Some(lease)) => lease.bytes.as_ref().map_or(Ok(0), |bytes| {
                    bytes.read_into(offset as usize, out).map(|()| out.len())
                }),
                ReadState::Ready(None) => Ok(0),
                ReadState::Pending { .. } => unreachable!(),
            });
        }
        None
    }
}
impl Memory {
    /// Activate requests only after the caller has released the original mm's
    /// execution Views and committed their effects. False means an external
    /// borrower remains: subscribe_parallel_idle, then retry; do not force it.
    pub fn activate_proc_reads(&mut self) -> bool {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().activate_proc_reads();
        }
        if !self.parallel_views_quiescent() {
            return false;
        }
        let report = self
            .report_cache
            .borrow()
            .as_ref()
            .map(|(_, r, _)| r.clone());
        let Some(report) = report else { return true };
        for read in report.read_ranges(0, u64::MAX) {
            let mut state = read.state.write().unwrap();
            if !matches!(*state, ReadState::Pending { requested: true }) {
                continue;
            }
            let lease = if report.alive() {
                let revision = self
                    .page_for_access_unchecked(read.base)
                    .and_then(|page| page.backing.as_ref())
                    .map(|_| backing::backing_revision());
                Some(ReadLease {
                    bytes: self.pin_read(read.base, PAGE_SIZE as usize).ok(),
                    backing_revision: revision,
                })
            } else {
                None
            };
            *state = ReadState::Ready(lease);
            drop(state);
            read.ready.notify_locked();
        }
        true
    }
    pub(super) fn invalidate_proc_reads(&self, start: u64, end: u64) {
        let report = self
            .report_cache
            .borrow()
            .as_ref()
            .map(|(_, r, _)| r.clone());
        if let Some(report) = report {
            for read in report.read_ranges(start, end) {
                let mut state = read.state.write().unwrap();
                // Keep a real request which raced this mapping operation.
                if matches!(*state, ReadState::Ready(_)) {
                    *state = ReadState::Pending { requested: false };
                }
                drop(state);
                read.ready.notify_locked();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    fn reader(memory: &Memory, address: u64) -> (MemoryReport, MemoryRead, Arc<AtomicUsize>) {
        let report = memory.memory_report();
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        report.bind_read_waker(Arc::new(move |_| {
            count.fetch_add(1, Ordering::Relaxed);
        }));
        let read = report.request_read_page(address).unwrap();
        (report, read, requests)
    }
    #[test]
    fn multiple_page_dependencies_publish_one_activation_request() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        let report = memory.memory_report();
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        report.bind_read_waker(Arc::new(move |_| {
            count.fetch_add(1, Ordering::Relaxed);
        }));
        let pages: Vec<_> = [0x1000, 0x2000]
            .into_iter()
            .map(|address| {
                let page = report.prepare_read_page(address).unwrap();
                assert_eq!(page.try_read_chunk(address, &mut [0]), None);
                page
            })
            .collect();
        assert_eq!(requests.load(Ordering::Relaxed), 0);
        report.request_reads(&pages);
        assert_eq!(requests.load(Ordering::Relaxed), 1);
        assert!(memory.activate_proc_reads());
        assert!(pages.iter().all(MemoryRead::ready));
    }
    #[test]
    fn original_mm_identity_and_pending_read_survive_decoder_wrap_and_waker_rebind() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let (report, read, first) = reader(&memory, 0x1000);
        let identity = memory.proc_address_space();
        memory.code_revision = u64::MAX;
        memory.advance_code_revision();
        assert_eq!(memory.proc_address_space(), identity);
        assert_eq!(identity, Some(report.identity()));
        assert!(memory.has_memory_report(&report));
        let rebound = Arc::new(AtomicUsize::new(0));
        let seen = rebound.clone();
        report.bind_read_waker(Arc::new(move |_| {
            seen.fetch_add(1, Ordering::Relaxed);
        }));
        assert_eq!(first.load(Ordering::Relaxed), 1);
        assert_eq!(
            rebound.load(Ordering::Relaxed),
            1,
            "a new session inherits actual pending work"
        );
        assert!(memory.activate_proc_reads());
        let view = memory.parallel_view(&mut Default::default()).unwrap();
        assert_eq!(view.proc_address_space(), identity);
        assert!(read.ready());
        drop(view);
        memory.commit_parallel().unwrap();
        memory.retire_memory_report();
        memory.renew_memory_report();
        assert!(!memory.has_memory_report(&report));
        assert!(!memory.memory_report().same_resource(&report));
    }

    #[test]
    fn private_cow_reader_revalidates_truncate_and_regrowth_without_unmapping() {
        struct Backing {
            valid: std::sync::atomic::AtomicBool,
        }
        impl PageBacking for Backing {
            fn check(&self, a: u64) -> Result<(), MemoryError> {
                if self.valid.load(Ordering::Relaxed) {
                    Ok(())
                } else {
                    Err(MemoryError::Bus(a))
                }
            }
            fn read(&self, _: usize, out: &mut [u8]) -> Result<(), MemoryError> {
                out.fill(1);
                Ok(())
            }
            fn write(&self, _: usize, _: &[u8]) -> Result<(), MemoryError> {
                unreachable!()
            }
            fn sync(&self) -> Result<(), MemoryError> {
                Ok(())
            }
            fn version(&self) -> u64 {
                0
            }
            fn writable(&self) -> bool {
                true
            }
            fn next_page(&self, _: u64) -> Result<Arc<dyn PageBacking>, MemoryError> {
                Err(MemoryError::InvalidRange)
            }
        }
        let mut memory = Memory::default();
        let backing = Arc::new(Backing {
            valid: std::sync::atomic::AtomicBool::new(true),
        });
        memory
            .map_backed(0x1000, vec![backing.clone()], false, Permissions::RW, false)
            .unwrap();
        memory.write(0x1000, &[7]).unwrap();
        let (_, read, _) = reader(&memory, 0x1000);
        memory.activate_proc_reads();
        let mut out = [0];
        assert_eq!(read.read_chunk(0x1000, &mut out), Some(Ok(1)));
        assert_eq!(out, [7]);
        backing.valid.store(false, Ordering::Relaxed);
        backing_changed();
        assert_eq!(read.read_chunk(0x1000, &mut out), None);
        memory.activate_proc_reads();
        assert_eq!(read.read_chunk(0x1000, &mut out), Some(Ok(0)));
        backing.valid.store(true, Ordering::Relaxed);
        backing_changed();
        assert_eq!(read.read_chunk(0x1000, &mut out), None);
        memory.activate_proc_reads();
        assert_eq!(read.read_chunk(0x1000, &mut out), Some(Ok(1)));
        assert_eq!(out, [7], "same original private COW bytes after regrowth");
    }

    #[test]
    fn bounded_live_reads_coalesce_and_only_reactivate_after_real_demand() {
        fn shared<T: Send + Sync>() {}
        shared::<MemoryRead>();
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        memory.write(0x1000, b"live").unwrap();
        let (report, read, count) = reader(&memory, 0x1000);
        let second = report.request_read_page(0x1010).unwrap();
        assert!(Arc::ptr_eq(&read.0, &second.0));
        let mut out = [0; 4];
        assert_eq!(read.read_chunk(0x1000, &mut out), None);
        assert_eq!(count.load(Ordering::Relaxed), 1);
        assert!(memory.activate_proc_reads());
        assert_eq!(read.read_chunk(0x1000, &mut out), Some(Ok(4)));
        assert_eq!(&out, b"live");
        let mut view = memory.parallel_view(&mut Default::default()).unwrap();
        assert!(
            !memory.activate_proc_reads(),
            "a View is an independent actor"
        );
        view.write(0x1000, b"next").unwrap();
        assert_eq!(read.read_chunk(0x1000, &mut out), Some(Ok(4)));
        assert_eq!(&out, b"next");
        drop(view);
        memory.commit_parallel().unwrap();
        memory.map(0x9000, PAGE_SIZE, Permissions::RW).unwrap();
        assert!(
            read.ready(),
            "unrelated mapping does not invalidate a reader"
        );
        memory.discard(0x1000, PAGE_SIZE).unwrap();
        assert_eq!(
            report.resident_bytes(),
            0,
            "cached pin releases discarded RAM"
        );
        assert!(memory.activate_proc_reads());
        assert_eq!(
            report.resident_bytes(),
            0,
            "invalidation alone does not repin"
        );
        assert_eq!(read.read_chunk(0x1000, &mut out), None);
        assert_eq!(count.load(Ordering::Relaxed), 2);
        assert!(memory.activate_proc_reads());
        assert_eq!(read.read_chunk(0x1000, &mut out), Some(Ok(4)));
        assert_eq!(out, [0; 4]);
    }
    #[test]
    fn mapping_protection_replacement_and_failed_mutations_use_original_virtual_page() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x1000, &[3]).unwrap();
        let (report, read, _) = reader(&memory, 0x1000);
        memory.activate_proc_reads();
        assert!(memory.map(0x1000, PAGE_SIZE, Permissions::RW).is_err());
        assert!(
            read.ready(),
            "a failed map preserves the accepted authority"
        );
        memory
            .protect(0x1000, PAGE_SIZE, Permissions::NONE)
            .unwrap();
        assert!(!read.ready());
        memory.activate_proc_reads();
        assert_eq!(read.read_chunk(0x1000, &mut [0]), Some(Ok(0)));
        memory.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        assert!(!read.ready());
        memory.activate_proc_reads();
        let mut out = [0];
        assert_eq!(read.read_chunk(0x1000, &mut out), Some(Ok(1)));
        assert_eq!(out, [3]);
        memory.unmap(0x1000, PAGE_SIZE).unwrap();
        assert_eq!(report.resident_bytes(), 0);
        assert!(!read.ready());
        memory.activate_proc_reads();
        assert_eq!(read.read_chunk(0x1000, &mut out), Some(Ok(0)));
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x1000, &[9]).unwrap();
        assert!(!read.ready());
        memory.activate_proc_reads();
        assert_eq!(read.read_chunk(0x1000, &mut out), Some(Ok(1)));
        assert_eq!(out, [9]);
    }
    #[test]
    fn root_drop_retirement_and_fork_do_not_retain_or_retarget_old_bytes() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x1000, &[1]).unwrap();
        let (report, read, _) = reader(&memory, 0x1000);
        memory.activate_proc_reads();
        let mut child = memory.clone();
        child.write(0x1000, &[2]).unwrap();
        let mut out = [0];
        assert_eq!(read.read_chunk(0x1000, &mut out), Some(Ok(1)));
        assert_eq!(out, [1]);
        memory.write(0x1000, &[3]).unwrap();
        assert_eq!(child.read_array::<1>(0x1000).unwrap(), [2]);
        assert_eq!(read.read_chunk(0x1000, &mut out), Some(Ok(1)));
        assert_eq!(out, [3]);
        drop(memory);
        assert!(!report.alive());
        assert_eq!(
            report.resident_bytes(),
            0,
            "an open reader is not a physical mm owner"
        );
        assert_eq!(read.read_chunk(0x1000, &mut out), Some(Ok(0)));
        assert!(read.ready());
        assert_eq!(child.read_array::<1>(0x1000).unwrap(), [2]);
    }
    #[test]
    fn invalidation_and_retirement_notify_without_a_service_or_poller() {
        struct Wake;
        impl trames_shared::IoWake for Wake {
            fn wake_io(&self, _: &Arc<IoSignal>) {}
        }
        let target: Arc<dyn trames_shared::IoWake> = Arc::new(Wake);
        let signal = IoSignal::new(1, Arc::downgrade(&target));
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let (_, read, _) = reader(&memory, 0x1000);
        let _subscription = read.subscribe(&signal);
        assert!(!read.ready());
        memory.activate_proc_reads();
        assert!(signal.ready());
        signal.reset();
        memory.unmap(0x1000, PAGE_SIZE).unwrap();
        assert!(signal.ready());
        assert!(!read.ready());
        signal.reset();
        memory.retire_memory_report();
        assert!(signal.ready());
        assert!(read.ready());
    }
}
