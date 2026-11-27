// SPDX-License-Identifier: GPL-3.0-or-later
//! Accepted mutations of an original mm, run by its existing checkpoint executor.
//! The queue owns weak requests: cancellation cannot retain an mm or do work later.
use crate::*;
use std::sync::{Arc, Mutex, OnceLock, Weak};

pub enum ControlError {
    Errno(u32),
    Pending(Arc<PageWait>),
}
impl From<u32> for ControlError {
    fn from(errno: u32) -> Self {
        Self::Errno(errno)
    }
}
type Action = Box<dyn FnOnce(&mut Memory) -> Result<Vec<u8>, ControlError> + Send + Sync>;
pub(super) type Controls = Mutex<Vec<Weak<MmControl>>>;
pub struct MmControl {
    state: Mutex<State>,
    wait: Arc<PageWait>,
    release_on_retirement: bool,
    deferred: OnceLock<Arc<PageWait>>,
}
enum State {
    Queued(Action),
    Running,
    Complete(Result<Vec<u8>, u32>),
}
impl MmControl {
    pub fn result(&self) -> Option<Result<Vec<u8>, u32>> {
        match &*self.state.lock().unwrap() {
            State::Complete(value) => Some(value.clone()),
            _ => None,
        }
    }
    pub fn fault(&self, address: u64) -> MemoryError {
        self.wait.fault(address)
    }
    /// The original checkpoint released all mm borrows. The retained caller
    /// waits on this resource before submitting its next checkpoint operation.
    pub fn deferred_wait(&self) -> Option<Arc<PageWait>> {
        self.deferred.get().cloned()
    }
    pub fn subscribe(
        &self,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> Vec<trames_shared::IoSubscription> {
        self.wait.subscribe(signal)
    }
    fn finish(&self, memory: Option<&mut Memory>) {
        let action = {
            let mut state = self.state.lock().unwrap();
            if !matches!(*state, State::Queued(_)) {
                return;
            }
            let State::Queued(action) = std::mem::replace(&mut *state, State::Running) else {
                unreachable!()
            };
            action
        };
        let result = memory.map_or_else(
            || {
                if self.release_on_retirement {
                    Ok(Vec::new())
                } else {
                    Err(ControlError::Errno(3))
                }
            },
            action,
        );
        let result = result.map_err(|error| match error {
            ControlError::Errno(errno) => errno,
            ControlError::Pending(wait) => {
                let _ = self.deferred.set(wait);
                11
            }
        });
        *self.state.lock().unwrap() = State::Complete(result);
        self.wait.finish();
    }
}
impl MemoryReport {
    pub fn submit_control(
        &self,
        action: impl FnOnce(&mut Memory) -> Result<Vec<u8>, u32> + Send + Sync + 'static,
    ) -> Result<Arc<MmControl>, u32> {
        self.queue_control(move |memory| action(memory).map_err(Into::into), false)
    }
    pub fn submit_deferred_control(
        &self,
        action: impl FnOnce(&mut Memory) -> Result<Vec<u8>, ControlError> + Send + Sync + 'static,
    ) -> Result<Arc<MmControl>, u32> {
        self.queue_control(action, false)
    }
    /// A reaper already accepted this dying mm. If exit_mmap wins before the
    /// checkpoint, its work is complete; ordinary mutations still fail ESRCH.
    pub fn submit_release_control(
        &self,
        action: impl FnOnce(&mut Memory) -> Result<Vec<u8>, u32> + Send + Sync + 'static,
    ) -> Result<Arc<MmControl>, u32> {
        self.queue_control(move |memory| action(memory).map_err(Into::into), true)
    }
    fn queue_control(
        &self,
        action: impl FnOnce(&mut Memory) -> Result<Vec<u8>, ControlError> + Send + Sync + 'static,
        release_on_retirement: bool,
    ) -> Result<Arc<MmControl>, u32> {
        if !self.supports_reads() {
            return Err(95);
        }
        let request = Arc::new(MmControl {
            state: Mutex::new(State::Queued(Box::new(action))),
            wait: Arc::default(),
            release_on_retirement,
            deferred: OnceLock::new(),
        });
        {
            let mut queue = self
                .0
                .controls
                .get_or_init(Default::default)
                .lock()
                .unwrap();
            if !self.alive() {
                return Err(3);
            }
            queue.retain(|request| request.strong_count() != 0);
            queue.push(Arc::downgrade(&request));
        }
        self.wake_reads();
        Ok(request)
    }
    pub(super) fn has_controls(&self) -> bool {
        self.0
            .controls
            .get()
            .is_some_and(|queue| queue.lock().unwrap().iter().any(|r| r.strong_count() != 0))
    }
    pub(super) fn finish_controls(&self, mut memory: Option<&mut Memory>) {
        if let Some(queue) = self.0.controls.get() {
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
    #[test]
    fn cancelled_controls_do_not_run_and_retired_originals_do_not_mutate_new_images() {
        let mut memory = Memory::default();
        memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
        let original = memory.memory_report();
        original.bind_read_waker(Arc::new(|_| {}));
        drop(
            original
                .submit_control(|memory| {
                    memory.write(0x10000, b"x").unwrap();
                    Ok(Vec::new())
                })
                .unwrap(),
        );
        assert!(!original.has_requested_reads());
        assert!(memory.activate_proc_reads());
        assert_eq!(memory.read_array::<1>(0x10000).unwrap(), [0]);
        let request = original
            .submit_control(|_| panic!("retired control must not execute"))
            .unwrap();
        let release = original
            .submit_release_control(|_| panic!("exit already released this mm"))
            .unwrap();
        memory.retire_memory_report();
        assert_eq!(request.result(), Some(Err(3)));
        assert_eq!(release.result(), Some(Ok(Vec::new())));
        memory.renew_memory_report();
        assert!(!original.same_resource(&memory.memory_report()));
    }
}
