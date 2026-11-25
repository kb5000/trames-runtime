// SPDX-License-Identifier: GPL-3.0-or-later
//! Original io_uring registration across metadata, pin and output waits.
use super::*;
pub struct Registration {
    ring: Arc<Uring>,
    args: [u64; 6],
    files: trames_vfs::SharedFiles,
    bytes: file_input::Bytes,
    accepted: Vec<(u32, Result<UringFile>)>,
    output: crate::copy_replay::Replay,
    result: Option<Result<u64>>,
}
impl Registration {
    pub(super) fn new(ring: Arc<Uring>, args: [u64; 6], files: trames_vfs::SharedFiles) -> Self {
        Self {
            ring,
            args,
            files,
            bytes: Default::default(),
            accepted: Vec::new(),
            output: Default::default(),
            result: None,
        }
    }
    pub fn resume(
        mut self: Box<Self>,
        source: &DirectSyscalls,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        if self.result.is_none() {
            let mut imported = file_input::RegistrationMemory {
                memory,
                bytes: &self.bytes,
                outputs: &mut self.output,
                fault: RefCell::default(),
            };
            let mut cursor = 0;
            let result = crate::uring::register(&self.ring, self.args, &mut imported, |fd| {
                let result = if let Some((original, result)) = self.accepted.get(cursor) {
                    debug_assert_eq!(*original, fd, "successful imported FD fragment");
                    result.clone()
                } else {
                    let result = self.files.uring_file(fd);
                    self.accepted.push((fd, result.clone()));
                    result
                };
                cursor += 1;
                Some(result)
            });
            let fault = imported.fault.borrow_mut().take();
            if let Some(fault) = fault {
                let args = self.args;
                return source.park_input(
                    file_input::Accepted::Registration(self),
                    fault,
                    427,
                    args,
                    pid,
                    target,
                );
            }
            let Some(result) = result else {
                return IoAttempt::FileCheckpoint(file::FileCheckpoint::new(
                    file::FileBoundary::Registration(self),
                ));
            };
            self.result = Some(result);
            self.ring.readiness.notify_locked();
        }
        let mut result = self.result.unwrap();
        if result.is_ok() {
            match self.output.progress(memory) {
                Ok(()) => {}
                Err(trames_memory::MemoryError::Pending(fault)) => {
                    let args = self.args;
                    return source.park_input(
                        file_input::Accepted::Registration(self),
                        fault,
                        427,
                        args,
                        pid,
                        target,
                    );
                }
                Err(_) => result = Err(Errno(14)),
            }
        }
        source.urings.record_completed();
        IoAttempt::Complete(result)
    }
}
