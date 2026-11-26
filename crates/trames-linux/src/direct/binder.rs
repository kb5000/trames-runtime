// SPDX-License-Identifier: GPL-3.0-or-later
//! The original caller owns Binder commands, input/output cursors and waits.
use super::*;
use std::sync::Mutex;
use trames_memory::PageFault;
use trames_vfs::binder::{Ioctl, Started};

#[derive(Clone)]
pub struct RetainedBinder {
    pub args: [u64; 6],
    state: Arc<Mutex<State>>,
}
struct State {
    request: Option<Ioctl>,
    file: Option<trames_vfs::SharedFd>,
    actor: Option<trames_vfs::FileActorSnapshot>,
    fault: Option<PageFault>,
    result: Option<Result<u64, Errno>>,
}
impl RetainedBinder {
    fn new(mut request: Ioctl, args: [u64; 6], file: Option<trames_vfs::SharedFd>) -> Self {
        let fault = request.take_fault();
        Self {
            args,
            state: Arc::new(Mutex::new(State {
                request: Some(request),
                file,
                actor: trames_vfs::FileActorScope::frozen(),
                fault,
                result: None,
            })),
        }
    }
    fn progress(&self, memory: &mut impl CpuMemory, interrupt: bool) -> Option<Result<u64, Errno>> {
        let mut state = self.state.lock().unwrap();
        if let Some(result) = state.result {
            return Some(result);
        }
        let _actor = state
            .actor
            .as_ref()
            .map(trames_vfs::FileActorSnapshot::enter);
        let request = state.request.as_mut()?;
        let result = if interrupt {
            request.interrupt(memory)
        } else {
            request.finish(memory)
        };
        let fault = request.take_fault();
        state.fault = fault;
        let result = match result {
            Ok(Some(value)) => Some(Ok(value)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        };
        if let Some(result) = result {
            let request = state.request.take();
            let file = state.file.take();
            let actor = state.actor.take();
            state.result = Some(result);
            drop(state);
            drop(request);
            drop(file);
            drop(actor);
        }
        result
    }
    pub fn interruptible(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.fault.is_none() && state.request.as_ref().is_some_and(Ioctl::interruptible)
    }
    pub fn interrupted(&self, memory: &mut impl CpuMemory) -> Option<Result<u64, Errno>> {
        self.progress(memory, true)
    }
    pub fn copy_fault(&self) -> Option<PageFault> {
        self.state.lock().unwrap().fault.clone()
    }
    pub fn cancel(&self) {
        let mut state = self.state.lock().unwrap();
        let request = state.request.take();
        let file = state.file.take();
        let actor = state.actor.take();
        state.fault = None;
        state.result = Some(Err(Errno(4)));
        drop(state);
        drop(request);
        drop(file);
        drop(actor);
    }
    fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        let state = self.state.lock().unwrap();
        let mut subscriptions = Vec::new();
        if let Some(request) = &state.request {
            subscriptions.push(request.subscribe(signal));
        }
        if let Some(fault) = &state.fault {
            subscriptions.extend(fault.wait.subscribe(signal));
            if fault.wait.ready() {
                signal.notify();
            }
        }
        subscriptions
    }
}
impl DirectSyscalls {
    pub fn binder_exit(&self, tid: u32, last: bool) {
        if let Some(factory) = &self.resources {
            factory.binder_exit(tid, last);
        }
    }
    pub(super) fn start_binder(
        &self,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        tid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<IoAttempt> {
        let fallback = if self.resources.is_none() {
            self.paths
                .as_ref()
                .map(trames_vfs::PathQueries::control_factory)
        } else {
            None
        };
        let factory = self.resources.as_ref().or(fallback.as_ref())?;
        let control = match factory.descriptor_control(args[0] as u32) {
            Ok(control) => control,
            Err(error) => return Some(self.complete(29, args, Err(error))),
        };
        let original = control.shared_file();
        original.binder_file()?;
        if let Err(error) = original.check_ioctl(args[1] as u32) {
            return Some(self.complete(29, args, Err(error)));
        }
        Some(self.start_original_binder(original, factory.clone(), args, memory, tid, target))
    }
    pub(super) fn start_original_binder(
        &self,
        original: trames_vfs::SharedFd,
        factory: trames_vfs::DescriptorFactory,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        tid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        match Ioctl::start(
            original.clone(),
            factory,
            tid,
            args[1] as u32,
            args[2],
            memory,
        ) {
            Ok(Started::Complete(value)) => self.complete(29, args, Ok(value)),
            Ok(Started::Read(mut request)) => match request.finish(memory) {
                Ok(Some(value)) => self.complete(29, args, Ok(value)),
                Err(error) => self.complete(29, args, Err(error)),
                Ok(None) => self.start_retained_binder(
                    RetainedBinder::new(request, args, Some(original)),
                    memory,
                    tid,
                    target,
                ),
            },
            Err(error) => self.complete(29, args, Err(error)),
        }
    }
    pub fn start_retained_binder(
        &self,
        call: RetainedBinder,
        memory: &mut impl CpuMemory,
        tid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let signal = IoSignal::new(tid, target.clone());
        let subscriptions = call.subscribe(&signal);
        let args = call.args;
        self.resume_binder(
            PendingIo {
                aio: None,
                message: None,
                process_vm: None,
                binder: Some(call),
                number: 29,
                args,
                deadline: None,
                signal,
                flock: None,
                record: None,
                retained_byte: None,
                retained_socket: None,
                native_tcp: None,
                resource_deadline: None,
                retained_poll: None,
                epoll_revision: None,
                terminal_job: false,
                _subscriptions: subscriptions,
                host_subscription: None,
                socket_subscriptions: Vec::new(),
                uring: None,
                poll_uring: None,
                target: target.clone(),
                file: None,
                fifo_open: None,
            },
            memory,
        )
    }
    pub(super) fn resume_binder(
        &self,
        mut pending: PendingIo,
        memory: &mut impl CpuMemory,
    ) -> IoAttempt {
        pending.signal.reset();
        let call = pending.binder.as_ref().unwrap();
        match call.progress(memory, false) {
            Some(result) => self.complete(29, pending.args, result),
            None => {
                // Existing connection subscription covers queue changes during
                // progress. Add the actual page wait before parking the caller.
                let subscriptions = call.subscribe(&pending.signal);
                pending._subscriptions = subscriptions;
                IoAttempt::Blocked(pending)
            }
        }
    }
}
