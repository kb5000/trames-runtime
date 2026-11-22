// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded cross-mm copies serviced by the original address-space owner.
//! Only Memory can publish a target. A read-only proc report cannot create one.
use super::*;
use std::sync::{Arc, Mutex, Weak};
use trames_shared::{IoSignal, IoSubscription, Readiness};

#[derive(Clone)]
pub struct TransferTarget {
    report: MemoryReport,
}
pub const TRANSFER_WINDOW: usize = 256 * 1024;

pub struct TransferRequest {
    address: u64,
    write: bool,
    ptrace: u8,
    state: Mutex<TransferState>,
    signal: Option<Arc<IoSignal>>,
    ready: Arc<Readiness>,
    completion: Option<Box<dyn Fn(Option<usize>) + Send + Sync>>,
}
enum TransferState {
    Queued(Vec<u8>),
    Completed(Result<Vec<u8>, TransferError>),
    Consumed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferError {
    Retired,
    Fault,
    Unavailable,
}
pub(super) type Transfers = Mutex<Vec<Weak<TransferRequest>>>;

impl Memory {
    pub fn transfer_target(&self) -> TransferTarget {
        TransferTarget {
            report: self.memory_report(),
        }
    }
}

impl Memory {
    /// Linux ptrace FOLL_FORCE access. Only the original mm owner calls this;
    /// mapping permissions stay unchanged, while COW and code invalidation use
    /// the ordinary page storage. Shared read-only file mappings remain protected.
    pub fn ptrace_word(
        &mut self,
        address: u64,
        write: Option<[u8; 8]>,
    ) -> Result<[u8; 8], MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().ptrace_word(address, write);
        }
        Self::end(address, 8)?;
        let mut done = 0;
        // Validate both fragments before writing a word across a page boundary.
        while done < 8 {
            let at = address + done as u64;
            let len = (8 - done).min((PAGE_SIZE - at % PAGE_SIZE) as usize);
            let entry = self
                .translation(at & !(PAGE_SIZE - 1))
                .ok_or(MemoryError::Unmapped(at))?;
            let page = self.translated_page(entry);
            page.check_backing(at)?;
            if write.is_some()
                && page.backing.as_ref().is_some_and(|b| {
                    b.shared && !page.permissions.write || !b.shared && !b.object.private_writable()
                })
            {
                return Err(MemoryError::Permission {
                    address: at,
                    access: Access::Write,
                });
            }
            done += len;
        }
        if write.is_some() {
            self.prepare_mmu_write(address, 8)?;
        }
        let mut bytes = [0; 8];
        done = 0;
        while done < 8 {
            let at = address + done as u64;
            let offset = (at % PAGE_SIZE) as usize;
            let len = (8 - done).min(PAGE_SIZE as usize - offset);
            let entry = self
                .translation(at & !(PAGE_SIZE - 1))
                .expect("validated word");
            if let Some(input) = write {
                let revision = self.code_revision.wrapping_add(1);
                let page = self.translated_page_mut(entry);
                page.write_bytes(offset, &input[done..done + len])
                    .map_err(|e| e.at_access(at))?;
                let executable = page.permissions.execute;
                if executable {
                    page.instruction_revision = revision;
                }
                self.note_parallel_write(entry.frame);
                self.revision = self.revision.wrapping_add(1);
                if executable {
                    self.advance_code_revision();
                }
            } else {
                self.translated_page(entry)
                    .read_bytes(offset, &mut bytes[done..done + len])
                    .map_err(|e| e.at_access(at))?;
            }
            done += len;
        }
        Ok(write.unwrap_or(bytes))
    }
}

impl Memory {
    fn ptrace_write_bytes(&mut self, address: u64, data: &[u8]) -> Result<usize, MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().ptrace_write_bytes(address, data);
        }
        let mut done = 0;
        while done < data.len() {
            let result = (|| {
                let at = address
                    .checked_add(done as u64)
                    .ok_or(MemoryError::InvalidRange)?;
                Self::end(at, 1)?;
                let len = (data.len() - done).min((PAGE_SIZE - at % PAGE_SIZE) as usize);
                let entry = self
                    .translation(at & !(PAGE_SIZE - 1))
                    .ok_or(MemoryError::Unmapped(at))?;
                let page = self.translated_page(entry);
                page.check_backing(at)?;
                if page.backing.as_ref().is_some_and(|b| {
                    b.shared && !page.permissions.write || !b.shared && !b.object.private_writable()
                }) {
                    return Err(MemoryError::Permission {
                        address: at,
                        access: Access::Write,
                    });
                }
                self.prepare_mmu_write(at, len)?;
                let entry = self
                    .translation(at & !(PAGE_SIZE - 1))
                    .expect("retained mapping");
                let revision = self.code_revision.wrapping_add(1);
                let page = self.translated_page_mut(entry);
                page.write_bytes((at % PAGE_SIZE) as usize, &data[done..done + len])
                    .map_err(|e| e.at_access(at))?;
                let executable = page.permissions.execute;
                if executable {
                    page.instruction_revision = revision;
                }
                self.note_parallel_write(entry.frame);
                self.revision = self.revision.wrapping_add(1);
                if executable {
                    self.advance_code_revision();
                }
                Ok(len)
            })();
            match result {
                Ok(n) => done += n,
                Err(e) if done == 0 => return Err(e),
                Err(_) => break,
            }
        }
        Ok(done)
    }
}

impl TransferTarget {
    pub fn matches(&self, report: &MemoryReport) -> bool {
        self.report.same_resource(report)
    }
    pub fn submit(
        &self,
        address: u64,
        write: bool,
        data: Vec<u8>,
        signal: Arc<IoSignal>,
    ) -> Result<Arc<TransferRequest>, TransferError> {
        self.submit_inner(address, write, 0, data, Some(signal), None)
    }
    pub fn submit_ptrace(
        &self,
        address: u64,
        write: bool,
        data: [u8; 8],
        signal: Arc<IoSignal>,
    ) -> Result<Arc<TransferRequest>, TransferError> {
        self.submit_inner(address, write, 1, data.to_vec(), Some(signal), None)
    }
    pub fn submit_forced_write(
        &self,
        address: u64,
        data: Vec<u8>,
        completion: Option<Box<dyn Fn(Option<usize>) + Send + Sync>>,
    ) -> Result<Arc<TransferRequest>, TransferError> {
        self.submit_inner(address, true, 2, data, None, completion)
    }
    fn submit_inner(
        &self,
        address: u64,
        write: bool,
        ptrace: u8,
        data: Vec<u8>,
        signal: Option<Arc<IoSignal>>,
        completion: Option<Box<dyn Fn(Option<usize>) + Send + Sync>>,
    ) -> Result<Arc<TransferRequest>, TransferError> {
        if data.is_empty() || data.len() > TRANSFER_WINDOW {
            return Err(TransferError::Fault);
        }
        if !self.report.supports_reads() {
            return Err(TransferError::Unavailable);
        }
        let request = Arc::new(TransferRequest {
            address,
            write,
            ptrace,
            state: Mutex::new(TransferState::Queued(data)),
            signal,
            ready: Arc::default(),
            completion,
        });
        {
            let mut queue = self
                .report
                .0
                .transfers
                .get_or_init(Default::default)
                .lock()
                .unwrap();
            if !self.report.alive() {
                return Err(TransferError::Retired);
            }
            queue.push(Arc::downgrade(&request));
        }
        self.report.wake_reads();
        Ok(request)
    }
}
impl Drop for TransferRequest {
    fn drop(&mut self) {
        if let Some(finish) = &self.completion {
            finish(None);
        }
    }
}
impl TransferRequest {
    pub fn ready(&self) -> bool {
        matches!(*self.state.lock().unwrap(), TransferState::Completed(_))
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.ready.subscribe(signal)
    }

    pub fn take(&self) -> Option<Result<Vec<u8>, TransferError>> {
        let mut state = self.state.lock().unwrap();
        if matches!(*state, TransferState::Completed(_)) {
            let TransferState::Completed(result) =
                std::mem::replace(&mut *state, TransferState::Consumed)
            else {
                unreachable!()
            };
            Some(result)
        } else {
            None
        }
    }
    fn finish(&self, memory: Option<&mut Memory>) {
        // A spurious caller wake can check completion while this owner's
        // guest file or memory access runs. Keep the result lock out of I/O.
        let queued = std::mem::replace(&mut *self.state.lock().unwrap(), TransferState::Consumed);
        let TransferState::Queued(mut data) = queued else {
            unreachable!()
        };
        let result = if let Some(memory) = memory {
            if self.ptrace == 2 {
                memory
                    .ptrace_write_bytes(self.address, &data)
                    .map(|n| {
                        data.truncate(n);
                        data
                    })
                    .map_err(|_| TransferError::Fault)
            } else if self.ptrace == 1 {
                memory
                    .ptrace_word(
                        self.address,
                        self.write
                            .then(|| data.as_slice().try_into().expect("ptrace word")),
                    )
                    .map(|b| b.to_vec())
                    .map_err(|_| TransferError::Fault)
            } else {
                let mut done = 0;
                while done < data.len() {
                    let Some(address) = self.address.checked_add(done as u64) else {
                        break;
                    };
                    let end = data
                        .len()
                        .min(done + (PAGE_SIZE - address % PAGE_SIZE) as usize);
                    let result = if self.write {
                        memory.write(address, &data[done..end])
                    } else {
                        memory.read(address, &mut data[done..end])
                    };
                    if result.is_err() {
                        break;
                    }
                    done = end;
                }
                data.truncate(done);
                if done == 0 {
                    Err(TransferError::Fault)
                } else {
                    Ok(data)
                }
            }
        } else {
            Err(TransferError::Retired)
        };
        if let Some(finish) = &self.completion {
            finish(result.as_ref().ok().map(Vec::len));
        }
        *self.state.lock().unwrap() = TransferState::Completed(result);
        if let Some(signal) = &self.signal {
            signal.notify();
        }
        self.ready.notify_locked();
    }
}
impl MemoryReport {
    pub(super) fn has_transfers(&self) -> bool {
        self.0
            .transfers
            .get()
            .is_some_and(|queue| !queue.lock().unwrap().is_empty())
    }
    pub(super) fn finish_transfers(&self, mut memory: Option<&mut Memory>) {
        if let Some(queue) = self.0.transfers.get() {
            let batch = std::mem::take(&mut *queue.lock().unwrap());
            for request in batch.into_iter().filter_map(|r| r.upgrade()) {
                request.finish(memory.as_deref_mut());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_shared::IoWake;

    struct Wake;
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    fn signal() -> Arc<IoSignal> {
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        IoSignal::new(1, Arc::downgrade(&wake))
    }

    #[test]
    fn forced_write_keeps_partial_progress_and_completes_offset_before_waking() {
        let mut mm = Memory::default();
        mm.map(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        mm.memory_report().bind_read_waker(Arc::new(|_| {}));
        let finished = Arc::new(std::sync::atomic::AtomicUsize::new(usize::MAX));
        let output = finished.clone();
        let request = mm
            .transfer_target()
            .submit_forced_write(
                0x1ffe,
                b"abcd".to_vec(),
                Some(Box::new(move |n| {
                    if let Some(n) = n {
                        output.store(n, Ordering::Relaxed);
                    }
                })),
            )
            .unwrap();
        assert!(!request.ready());
        mm.activate_proc_reads();
        assert!(request.ready());
        assert_eq!(finished.load(Ordering::Relaxed), 2);
        assert_eq!(request.take(), Some(Ok(b"ab".to_vec())));
        assert_eq!(mm.read_array::<2>(0x1ffe).unwrap(), *b"ab");
        assert!(mm.write_array(0x1ffe, *b"xy").is_err());
        let cancelled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = cancelled.clone();
        let request = mm
            .transfer_target()
            .submit_forced_write(
                0x1000,
                vec![9],
                Some(Box::new(move |n| {
                    assert!(n.is_none());
                    count.fetch_add(1, Ordering::Relaxed);
                })),
            )
            .unwrap();
        drop(request);
        mm.activate_proc_reads();
        assert_eq!(cancelled.load(Ordering::Relaxed), 1);
        assert_eq!(mm.read_array::<1>(0x1000).unwrap(), [0]);
    }

    #[test]
    fn ptrace_force_keeps_protection_cow_and_instruction_identity() {
        let mut mm = Memory::default();
        mm.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        mm.write_array(0x1ffc, *b"original").unwrap();
        let child = mm.clone();
        mm.protect(
            0x1000,
            PAGE_SIZE * 2,
            Permissions {
                read: false,
                write: false,
                execute: true,
            },
        )
        .unwrap();
        let before = mm.instruction_identity();
        assert_eq!(mm.ptrace_word(0x1ffc, None).unwrap(), *b"original");
        assert_eq!(
            mm.ptrace_word(0x1ffc, Some(*b"modified")).unwrap(),
            *b"modified"
        );
        assert_ne!(mm.instruction_identity(), before);
        assert_eq!(mm.ptrace_word(0x1ffc, None).unwrap(), *b"modified");
        assert!(mm.read_array::<8>(0x1ffc).is_err());
        assert!(mm.write_array(0x1ffc, [0; 8]).is_err());
        assert_eq!(child.read_array::<8>(0x1ffc).unwrap(), *b"original");
        mm.unmap(0x2000, PAGE_SIZE).unwrap();
        assert!(mm.ptrace_word(0x1ffc, Some([0; 8])).is_err());
        assert_eq!(mm.ptrace_word(0x1ff8, None).unwrap()[4..], *b"modi");
    }

    #[test]
    fn transfer_checks_current_pages_and_preserves_fork_cow_and_partial_results() {
        let mut mm = Memory::default();
        mm.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        mm.write(0x1ffe, b"old!").unwrap();
        let child = mm.clone();
        let target = mm.transfer_target();
        mm.memory_report().bind_read_waker(Arc::new(|_| {}));
        let done = signal();
        let request = target
            .submit(0x1ffe, true, b"new!".to_vec(), done.clone())
            .unwrap();
        assert!(request.take().is_none());
        mm.protect(0x2000, PAGE_SIZE, Permissions::R).unwrap();
        assert!(mm.activate_proc_reads());
        assert!(done.ready());
        assert_eq!(request.take(), Some(Ok(b"ne".to_vec())));
        assert_eq!(mm.read_array::<4>(0x1ffe).unwrap(), *b"ned!");
        assert_eq!(child.read_array::<4>(0x1ffe).unwrap(), *b"old!");
        let read = target.submit(0x1ffe, false, vec![0; 4], signal()).unwrap();
        mm.unmap(0x2000, PAGE_SIZE).unwrap();
        assert!(mm.activate_proc_reads());
        assert_eq!(read.take(), Some(Ok(b"ne".to_vec())));
    }

    #[test]
    fn cancelled_or_retired_requests_cannot_write_into_the_next_image() {
        let mut mm = Memory::default();
        mm.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        mm.memory_report().bind_read_waker(Arc::new(|_| {}));
        let old = mm.transfer_target();
        drop(old.submit(0x1000, true, vec![9], signal()).unwrap());
        assert!(mm.activate_proc_reads());
        assert_eq!(mm.read_array::<1>(0x1000).unwrap(), [0]);
        let done = signal();
        let pending = old.submit(0x1000, true, vec![7], done.clone()).unwrap();
        mm.retire_memory_report();
        assert!(done.ready());
        assert_eq!(pending.take(), Some(Err(TransferError::Retired)));
        mm.renew_memory_report();
        assert!(!old.matches(&mm.memory_report()));
        assert!(matches!(
            old.submit(0x1000, true, vec![3], signal()),
            Err(TransferError::Retired)
        ));
        assert_eq!(mm.read_array::<1>(0x1000).unwrap(), [0]);
    }
}
