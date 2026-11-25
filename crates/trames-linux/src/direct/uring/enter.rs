// SPDX-License-Identifier: GPL-3.0-or-later
//! One original enter: submit first, then import GETEVENTS descriptors. Actual
//! timeout/mask accesses are reached only when the initial CQ test needs a wait.
use super::*;
use std::{sync::Mutex, time::Duration};

pub(super) const FLAGS: u32 = 1 | 2 | 4 | 8 | 32;
pub(super) fn normalize(mut args: [u64; 6]) -> Result<[u64; 6]> {
    for arg in &mut args[..4] {
        *arg = *arg as u32 as u64;
    }
    if args[3] as u32 & !FLAGS != 0 {
        return Err(Errno(22));
    }
    Ok(args)
}
#[derive(Clone, Copy)]
struct Descriptor {
    mask: u64,
    size: u64,
    timeout: u64,
    minimum_us: u32,
}
struct Control {
    ring: Option<Arc<Uring>>,
    lease: Option<Arc<dyn trames_vfs::TemporaryMask>>,
    reader: Option<Arc<dyn trames_vfs::SignalReader>>,
    deadline: Option<Instant>,
    minimum: Option<Instant>,
    timeouts: u32,
    interrupted: bool,
    result: Option<Result<u64>>,
}
/// Shared logical completion, bound to the original task rather than a FD slot.
/// Snapshot handoffs share this receipt and cannot restore a later mask.
pub struct EnterControl {
    task: u32,
    args: [u64; 6],
    submitted: u32,
    state: Mutex<Control>,
}
pub(super) enum Decision {
    Ready(Result<()>),
    Pending(Option<Instant>),
}
impl Drop for EnterControl {
    fn drop(&mut self) {
        let state = self.state.get_mut().unwrap();
        if let Some(lease) = state.lease.take() {
            lease.finish();
        }
        if state.result.is_none() {
            if let Some(ring) = state.ring.take() {
                ring.state.lock().unwrap().waits.remove(&self.task);
                ring.readiness.notify_locked();
            }
        }
    }
}
impl EnterControl {
    pub(super) fn retained(
        ring: Arc<Uring>,
        task: u32,
        args: [u64; 6],
        submitted: u32,
        deadline: Option<Instant>,
        timeouts: u32,
    ) -> Arc<Self> {
        Arc::new(Self {
            task,
            args,
            submitted,
            state: Mutex::new(Control {
                ring: Some(ring),
                lease: None,
                reader: None,
                deadline,
                minimum: None,
                timeouts,
                interrupted: false,
                result: None,
            }),
        })
    }
    pub fn ring(&self) -> Option<Arc<Uring>> {
        self.state.lock().unwrap().ring.clone()
    }
    pub fn result(&self) -> Option<Result<u64>> {
        self.state.lock().unwrap().result
    }
    pub fn native_mask(&self) -> bool {
        self.state.lock().unwrap().lease.is_some()
    }
    pub(super) fn args(&self) -> [u64; 6] {
        self.args
    }
    pub(super) fn submitted(&self) -> u32 {
        self.submitted
    }
    pub(super) fn deadline(&self) -> Option<Instant> {
        let state = self.state.lock().unwrap();
        state.minimum.or(state.deadline)
    }
    pub(super) fn poll(&self, count: u32, minimum: u32, timeouts: u32) -> Decision {
        self.poll_at(count, minimum, timeouts, Instant::now())
    }
    fn poll_at(&self, count: u32, minimum: u32, timeouts: u32, now: Instant) -> Decision {
        let mut state = self.state.lock().unwrap();
        if let Some(result) = state.result {
            return Decision::Ready(result.map(|_| ()));
        }
        if state
            .lease
            .as_ref()
            .is_some_and(|lease| lease.signal_pending())
            || state
                .reader
                .as_ref()
                .is_some_and(|reader| reader.interrupted())
        {
            state.interrupted = true;
            return Decision::Ready(if count != 0 { Ok(()) } else { Err(Errno(4)) });
        }
        if count >= minimum || timeouts != state.timeouts {
            return Decision::Ready(Ok(()));
        }
        if let Some(at) = state.minimum.filter(|at| *at <= now) {
            // At the minimum timer, native Linux returns for existing CQEs or
            // a shorter/absent normal timer; otherwise it arms the latter.
            if count != 0 || state.deadline.is_none_or(|deadline| deadline <= at) {
                return Decision::Ready(if count != 0 { Ok(()) } else { Err(Errno(62)) });
            }
            state.minimum = None;
        }
        if state.minimum.is_none() && state.deadline.is_some_and(|at| at <= now) {
            return Decision::Ready(if count != 0 { Ok(()) } else { Err(Errno(62)) });
        }
        Decision::Pending(state.minimum.or(state.deadline))
    }
    pub(super) fn finish(&self, result: Result<u64>, interrupted: bool) -> Result<u64> {
        let mut state = self.state.lock().unwrap();
        if let Some(result) = state.result {
            return result;
        }
        let interrupted = interrupted || state.interrupted;
        if let Some(lease) = state.lease.take() {
            if interrupted {
                lease.interrupted();
            } else {
                lease.finish();
            }
        }
        let result = if self.submitted != 0 {
            Ok(self.submitted as u64)
        } else {
            result
        };
        state.result = Some(result);
        let ring = state.ring.take();
        let reader = state.reader.take();
        drop(state);
        drop(reader);
        if let Some(ring) = ring {
            ring.state.lock().unwrap().waits.remove(&self.task);
            ring.readiness.notify_locked();
        }
        result
    }
}
#[cfg(test)]
#[path = "enter_tests.rs"]
mod tests;
pub(super) fn finish_attempt(control: &Option<Arc<EnterControl>>, attempt: IoAttempt) -> IoAttempt {
    match (control, attempt) {
        (Some(control), IoAttempt::Complete(result)) => {
            IoAttempt::Complete(control.finish(result, false))
        }
        (_, attempt) => attempt,
    }
}
pub struct EnterInput {
    ring: Arc<Uring>,
    args: [u64; 6],
    bytes: file_input::Bytes,
    clock: Instant,
    submitted: Option<u32>,
    descriptor: Option<Descriptor>,
    wait_started: Option<Instant>,
    deadline: Option<Option<Instant>>,
    timeouts: u32,
    control: Option<Arc<EnterControl>>,
}
impl EnterInput {
    pub(super) fn new(ring: Arc<Uring>, args: [u64; 6], clock: Instant) -> Self {
        Self {
            ring,
            args,
            bytes: Default::default(),
            clock,
            submitted: None,
            descriptor: None,
            wait_started: None,
            deadline: None,
            timeouts: 0,
            control: None,
        }
    }
    pub(crate) fn accepted(
        ring: Arc<Uring>,
        args: [u64; 6],
        clock: Instant,
        submitted: u32,
    ) -> Box<Self> {
        let mut call = Box::new(Self::new(ring, args, clock));
        call.submitted = Some(submitted);
        call
    }
    pub(crate) fn submitted(&self) -> u32 {
        self.submitted.unwrap_or(0)
    }
    fn complete(self: Box<Self>, source: &DirectSyscalls, result: Result<u64>) -> IoAttempt {
        source.urings.record_completed();
        let result = match self.submitted {
            Some(n) if n != 0 => Ok(n as u64),
            _ => result,
        };
        finish_attempt(&self.control, IoAttempt::Complete(result))
    }
    fn checkpoint(self: Box<Self>) -> IoAttempt {
        IoAttempt::FileCheckpoint(file::FileCheckpoint::new(file::FileBoundary::UringEnter(
            self,
        )))
    }
    fn page(
        self: Box<Self>,
        source: &DirectSyscalls,
        fault: trames_memory::PageFault,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let args = self.args;
        source.park_input(
            file_input::Accepted::UringEnter(self),
            fault,
            426,
            args,
            pid,
            target,
        )
    }
    pub fn resume(
        mut self: Box<Self>,
        source: &DirectSyscalls,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        self.args = match normalize(self.args) {
            Ok(args) => args,
            Err(error) => return self.complete(source, Err(error)),
        };
        source.urings.ensure_context(
            source.paths.as_ref(),
            source.resources.as_ref(),
            &source.files,
            source.file_executor.as_ref(),
            source.file_layouts.as_ref(),
            source.task_signal.as_ref(),
        );
        if self.submitted.is_none() {
            let mut submit = self.args;
            submit[2] = 0;
            submit[3] &= !1;
            match source.urings.start_ring(
                self.ring.clone(),
                submit,
                memory,
                pid,
                target,
                Some(None),
                None,
                false,
            ) {
                Some(IoAttempt::Complete(Ok(count))) => self.submitted = Some(count as u32),
                Some(IoAttempt::Complete(Err(error))) => return self.complete(source, Err(error)),
                Some(IoAttempt::Checkpoint) | None => return self.checkpoint(),
                Some(attempt) => return attempt,
            }
        }
        let submitted = self.submitted.unwrap();
        if submitted != self.args[1] as u32 || self.args[3] & 1 == 0 {
            return self.complete(source, Ok(submitted as u64));
        }
        if self.descriptor.is_none() {
            let reader = file_input::Reader::new(memory, &self.bytes);
            let result = (|| {
                if self.args[3] & 8 == 0 {
                    return Ok(Descriptor {
                        mask: self.args[4],
                        size: self.args[5],
                        timeout: 0,
                        minimum_us: 0,
                    });
                }
                if self.args[5] != 24 {
                    return Err(Errno(22));
                }
                let bytes = reader
                    .read_array::<24>(self.args[4])
                    .map_err(|_| Errno(14))?;
                Ok(Descriptor {
                    mask: crate::uring::u64_at(&bytes, 0),
                    size: crate::uring::u32_at(&bytes, 8) as u64,
                    timeout: crate::uring::u64_at(&bytes, 16),
                    minimum_us: crate::uring::u32_at(&bytes, 12),
                })
            })();
            if let Some(fault) = reader.fault() {
                return self.page(source, fault, pid, target);
            }
            self.descriptor = Some(match result {
                Ok(descriptor) => descriptor,
                Err(error) => return self.complete(source, Err(error)),
            });
        }
        if self.wait_started.is_none() {
            source.urings.progress(&self.ring, memory, pid);
            let mut state = self.ring.state.lock().unwrap();
            let flushed = self.ring.flush(&mut state);
            let count = state.tail.wrapping_sub(self.ring.load_queue(64));
            self.timeouts = state.timeout_completions;
            let event = self
                .ring
                .completion_event(&state, flushed.as_ref().copied().unwrap_or(0));
            drop(state);
            if flushed.as_ref().is_ok_and(|count| *count != 0) {
                self.ring.notify_completion(event);
            }
            if let Err(error) = flushed {
                return self.complete(source, Err(error));
            }
            if count >= (self.args[2] as u32).min(self.ring.cq_entries) {
                return self.complete(source, Ok(submitted as u64));
            }
            self.wait_started = Some(Instant::now());
        }
        let descriptor = self.descriptor.unwrap();
        if self.deadline.is_none() {
            let reader = file_input::Reader::new(memory, &self.bytes);
            let result = crate::uring::time::enter_timeout(
                &reader,
                descriptor.timeout,
                self.args[3] as u32,
                self.clock,
                self.wait_started.unwrap(),
            );
            if let Some(fault) = reader.fault() {
                return self.page(source, fault, pid, target);
            }
            self.deadline = Some(match result {
                Ok(deadline) => deadline,
                Err(error) => return self.complete(source, Err(error)),
            });
        }
        if self.control.is_none() {
            let reader = file_input::Reader::new(memory, &self.bytes);
            let mask = (|| {
                if descriptor.mask == 0 {
                    return Ok(None);
                }
                if descriptor.size != 8 {
                    return Err(Errno(22));
                }
                Ok(Some(
                    u64::from_le_bytes(
                        reader
                            .read_array::<8>(descriptor.mask)
                            .map_err(|_| Errno(14))?,
                    ) & !((1 << 8) | (1 << 18)),
                ))
            })();
            if let Some(fault) = reader.fault() {
                return self.page(source, fault, pid, target);
            }
            let mask = match mask {
                Ok(mask) => mask,
                Err(error) => return self.complete(source, Err(error)),
            };
            let lease = if let Some(mask) = mask {
                let Some(lease) = source
                    .task_signal
                    .clone()
                    .and_then(|task| task.temporary_mask(mask))
                else {
                    return self.checkpoint();
                };
                Some(lease)
            } else {
                None
            };
            let minimum = (descriptor.minimum_us != 0)
                .then(|| {
                    self.wait_started
                        .unwrap()
                        .checked_add(Duration::from_micros(descriptor.minimum_us as u64))
                })
                .flatten();
            self.control = Some(Arc::new(EnterControl {
                task: pid,
                args: self.args,
                submitted,
                state: Mutex::new(Control {
                    ring: Some(self.ring.clone()),
                    lease,
                    reader: source.signal_reader.clone(),
                    deadline: self.deadline.unwrap(),
                    minimum,
                    timeouts: self.timeouts,
                    interrupted: false,
                    result: None,
                }),
            }));
        }
        let deadline = self.control.as_ref().unwrap().deadline();
        self.ring
            .state
            .lock()
            .unwrap()
            .waits
            .insert(pid, (submitted, deadline));
        match source.urings.start_ring(
            self.ring.clone(),
            self.args,
            memory,
            pid,
            target,
            Some(deadline),
            self.control.clone(),
            true,
        ) {
            Some(IoAttempt::Checkpoint) | None => self.checkpoint(),
            Some(attempt) => finish_attempt(&self.control, attempt),
        }
    }
}
