// SPDX-License-Identifier: GPL-3.0-or-later
//! Binder work executes on its original caller. Only its read half can park.
use super::*;
use trames_vfs::binder::{Ioctl, Started};

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
        let factory = self.resources.as_ref()?;
        let file = match factory.binder_file(args[0] as u32)? {
            Ok(file) => file,
            Err(error) => return Some(self.complete(29, args, Err(error))),
        };
        let mut request =
            match Ioctl::start(file, factory.clone(), tid, args[1] as u32, args[2], memory) {
                Ok(Started::Complete(value)) => return Some(self.complete(29, args, Ok(value))),
                Ok(Started::Read(request)) => request,
                Err(error) => return Some(self.complete(29, args, Err(error))),
            };
        match request.finish(memory) {
            Ok(Some(value)) => return Some(self.complete(29, args, Ok(value))),
            Err(error) => return Some(self.complete(29, args, Err(error))),
            Ok(None) => {}
        }
        let signal = IoSignal::new(tid, target.clone());
        // Subscribe before the deciding read, including the immediate retry
        // after effects. No write command is executed again after a wake.
        let subscriptions = vec![request.subscribe(&signal)];
        Some(self.resume_binder(
            PendingIo {
                aio: None,
                binder: Some(Box::new(request)),
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
        ))
    }
    pub(super) fn resume_binder(
        &self,
        mut pending: PendingIo,
        memory: &mut impl CpuMemory,
    ) -> IoAttempt {
        pending.signal.reset();
        match pending.binder.as_mut().unwrap().finish(memory) {
            Ok(None) => IoAttempt::Blocked(pending),
            Ok(Some(value)) => self.complete(29, pending.args, Ok(value)),
            Err(error) => self.complete(29, pending.args, Err(error)),
        }
    }
}
