// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded cross-mm copies serviced by the original address-space owner.
//! Only Memory can publish a target. A read-only proc report cannot create one.
use super::*;
use std::sync::{Arc, Mutex, Weak};
use trames_shared::IoSignal;

#[derive(Clone)]
pub struct TransferTarget {
    report: MemoryReport,
}
pub const TRANSFER_WINDOW: usize = 256 * 1024;

pub struct TransferRequest {
    address: u64,
    write: bool,
    state: Mutex<TransferState>,
    signal: Arc<IoSignal>,
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
        if data.is_empty() || data.len() > TRANSFER_WINDOW {
            return Err(TransferError::Fault);
        }
        if !self.report.supports_reads() {
            return Err(TransferError::Unavailable);
        }
        let request = Arc::new(TransferRequest {
            address,
            write,
            state: Mutex::new(TransferState::Queued(data)),
            signal,
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
impl TransferRequest {
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
        } else {
            Err(TransferError::Retired)
        };
        *self.state.lock().unwrap() = TransferState::Completed(result);
        self.signal.notify();
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
