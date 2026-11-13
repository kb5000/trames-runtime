// SPDX-License-Identifier: GPL-3.0-or-later
//! Whole-file and POSIX/OFD range locks retain original resource authority.
use super::*;
impl DirectSyscalls {
    fn record_file(&self, fd: u32) -> Option<Result<trames_vfs::RecordFile, Errno>> {
        let context = self.lock_context.as_ref()?;
        let file = if let Some(factory) = &self.resources {
            match factory.descriptor_control(fd) {
                Ok(control) => control.filesystem_target().shared_file(),
                Err(error) => return Some(Err(error)),
            }
        } else {
            self.files.get(fd)?.shared_file()?
        };
        context.file(file).map(Ok)
    }
    pub(super) fn invoke_record_lock(
        &self,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        // Preserve the existing prepared regular-file path: no inode borrow
        // or wait-graph lookup is added to ordinary uncontended controls.
        if let (Some(context), Some(file)) = (&self.lock_context, self.files.get(args[0] as u32)) {
            let value = if !file.allows_record_locks() {
                Some(Err(Errno(9)))
            } else {
                crate::record_locks::call(
                    memory,
                    args[1],
                    args[2],
                    |kind, whence, start, length| {
                        if args[1] >= 36 {
                            file.normalize_ofd_lock(kind, whence, start, length)
                        } else {
                            file.normalize_lock(kind, whence, start, length, context.owner)
                        }
                    },
                    |requested| Ok(file.record_lock_conflict(requested)),
                    |requested| file.record_lock_set(requested),
                    |owner| context.visible_pid(owner),
                )
            };
            if let Some(value) = value {
                self.record_fd_control();
                return Some(value);
            }
        }
        let file = match self.record_file(args[0] as u32)? {
            Ok(file) => file,
            Err(error) => return Some(Err(error)),
        };
        let result = crate::record_locks::control(&file, args[1], args[2], memory);
        self.record_fd_control();
        Some(result)
    }
    pub(super) fn start_record_lock(
        &self,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<IoAttempt> {
        let file = match self.record_file(args[0] as u32)? {
            Ok(file) => file,
            Err(error) => return Some(self.complete(25, args, Err(error))),
        };
        let request = match crate::record_locks::prepare(&file, args[1], args[2], memory) {
            Ok(request) => request,
            Err(error) => return Some(self.complete(25, args, Err(error))),
        };
        match request.try_lock() {
            Err(Errno(11)) => {}
            result => return Some(self.complete(25, args, result.map(|()| 0))),
        }
        Some(match request.wait() {
            Ok(wait) => self.start_record_wait(wait, args, memory, pid, target),
            Err(error) => self.complete(25, args, Err(error)),
        })
    }
    pub fn start_record_wait(
        &self,
        request: trames_vfs::RecordWait,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        match request.try_lock() {
            Err(Errno(11)) => {}
            result => return self.complete(25, args, result.map(|()| 0)),
        }
        let signal = IoSignal::new(pid, target.clone());
        let subscriptions = vec![request.subscribe(&signal)];
        self.resume(
            PendingIo {
                binder: None,
                aio: None,
                number: 25,
                args,
                deadline: None,
                signal,
                flock: None,
                record: Some(request),
                retained_byte: None,
                retained_socket: None,
                native_tcp: None,
                resource_deadline: None,
                epoll_revision: None,
                retained_poll: None,
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
    pub(super) fn flock_request(
        &self,
        fd: u32,
        operation: u32,
    ) -> Option<Result<trames_vfs::FlockRequest, Errno>> {
        if let Some(factory) = &self.resources {
            Some(factory.flock_request(fd, operation))
        } else {
            Some(self.files.get(fd)?.flock_request(operation))
        }
    }
}

#[cfg(test)]
#[path = "lock_tests.rs"]
mod tests;
