// SPDX-License-Identifier: GPL-3.0-or-later
//! Import before fdget; update once before copying the accepted old value.
use super::*;
#[cfg(test)]
#[path = "timer_control_tests.rs"]
mod tests;

pub struct TimerControl {
    number: u32,
    args: [u64; 6],
    files: DirectFds,
    fd: Option<trames_vfs::DirectFd>,
    imported: bool,
    input: Option<crate::timer::TimerFdInput>,
    resources: Option<trames_vfs::DescriptorFactory>,
    paths: Option<trames_vfs::PathQueries>,
    bytes: file_input::Bytes,
    started: Instant,
    boot: Option<trames_shared::boottime::Boottime>,
}
impl TimerControl {
    fn progress(&mut self, memory: &impl CpuMemory) -> Result<Step, trames_memory::PageFault> {
        if !self.imported {
            let input = if memory.async_faults_possible() {
                let reader = file_input::Reader::new(memory, &self.bytes);
                let input = crate::timer::timerfd_input(self.number, self.args, &reader);
                if let Some(fault) = reader.fault() {
                    return Err(fault);
                }
                input
            } else {
                crate::timer::timerfd_input(self.number, self.args, memory)
            };
            self.input = match input {
                Ok(input) => input,
                Err(error) => return Ok(Step::Reply(Err(error))),
            };
            self.imported = true;
        }
        if self.fd.is_none() {
            self.fd = Some(match self.files.capture_poll(self.args[0] as u32) {
                Some(Ok(trames_vfs::PollBinding::Direct(fd))) => fd,
                Some(Err(error)) => return Ok(Step::Reply(Err(error))),
                Some(Ok(trames_vfs::PollBinding::Original(_))) => {
                    return Ok(Step::Reply(Err(Errno(22))))
                }
                None => return Ok(Step::Reply(Err(Errno(9)))),
            });
        }
        let result = (|| {
            let fd = self.fd.as_ref().unwrap();
            let timer = fd.timer().ok_or(Errno(22))?;
            if self.number == 86 && matches!(timer.clock, 8 | 9) {
                if let Some(resources) = &self.resources {
                    trames_vfs::TimerFd::check_alarm(timer.clock, resources.local_credentials())?;
                } else if let Some(paths) = &self.paths {
                    paths.retained_control(fd.shared_file().ok_or(Errno(9))?, |vfs, _| {
                        trames_vfs::TimerFd::check_alarm(timer.clock, &vfs.credentials)
                    })?;
                } else {
                    return Ok(None);
                }
            }
            crate::timer::timerfd_update(timer, self.input.take(), self.started, self.boot)
                .map(Some)
        })();
        match result {
            Ok(None) => Ok(Step::Authority),
            result => {
                // Native fdput precedes put_itimerspec64. Only the immutable
                // result survives a lazy output page, not another timer fget.
                drop(self.fd.take());
                Ok(Step::Reply(result.map(|value| value.unwrap())))
            }
        }
    }
    fn finish(
        &self,
        source: &DirectSyscalls,
        value: Result<[u8; 32], Errno>,
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        source.completed.set(source.completed.get() + 1);
        source.timer_completed.set(source.timer_completed.get() + 1);
        let bytes = match value {
            Ok(bytes) => bytes,
            Err(error) => return Some(Err(error)),
        };
        let address = if self.number == 87 {
            self.args[1]
        } else {
            self.args[3]
        };
        if self.number == 86 && address == 0 {
            return Some(Ok(0));
        }
        if !memory.async_faults_possible() {
            return Some(crate::time_read::copy_bytes(memory, address, &bytes).map(|()| 0));
        }
        source.finish_metadata_output(
            self.number,
            self.args,
            address,
            bytes.to_vec(),
            false,
            memory,
        )
    }
    pub fn resume_joined(
        mut self: Box<Self>,
        source: &DirectSyscalls,
        vfs: &trames_vfs::Vfs,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        if self.resources.is_none() {
            self.resources = Some(vfs.descriptor_factory());
        }
        if self.paths.is_none() {
            self.paths = Some(vfs.path_queries());
        }
        self.resume(source, memory, pid, target)
    }
    pub fn resume(
        mut self: Box<Self>,
        source: &DirectSyscalls,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        if self.resources.is_none() {
            self.resources = source.resources.clone();
        }
        if self.paths.is_none() {
            self.paths = source
                .paths
                .as_ref()
                .map(trames_vfs::PathQueries::retain_context);
        }
        match self.progress(memory) {
            Err(fault) => {
                let (number, args) = (self.number, self.args);
                source.park_input(
                    file_input::Accepted::TimerFd(self),
                    fault,
                    number,
                    args,
                    pid,
                    target,
                )
            }
            Ok(Step::Authority) => IoAttempt::FileCheckpoint(file::FileCheckpoint::new(
                file::FileBoundary::TimerFd(self),
            )),
            Ok(Step::Reply(value)) => match self.finish(source, value, memory) {
                Some(value) => IoAttempt::Complete(value),
                None => source
                    .start_prepared_file(self.number, self.args, memory, pid, target)
                    .expect("accepted timer output"),
            },
        }
    }
}
enum Step {
    Reply(Result<[u8; 32], Errno>),
    Authority,
}
impl DirectSyscalls {
    pub(super) fn invoke_timer_control(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        if self.file_prepared(number, args) {
            return None;
        }
        if !self.descriptors.has_membership() && self.descriptors.get(args[0] as u32).is_none() {
            return None;
        }
        let mut call = TimerControl {
            number,
            args,
            files: self.descriptors.clone(),
            fd: None,
            imported: false,
            input: None,
            resources: self.resources.clone(),
            paths: if self.resources.is_some() {
                None
            } else {
                self.paths
                    .as_ref()
                    .map(trames_vfs::PathQueries::retain_context)
            },
            bytes: Default::default(),
            started: self.started.unwrap_or_else(Instant::now),
            boot: self.boot_clock,
        };
        match call.progress(memory) {
            Ok(Step::Authority) => {
                *self.file_prepared.borrow_mut() = Some(file::PreparedFileCall {
                    number,
                    args,
                    action: file::PreparedAction::Checkpoint(file::FileCheckpoint::new(
                        file::FileBoundary::TimerFd(Box::new(call)),
                    )),
                });
                None
            }
            Ok(Step::Reply(value)) => call.finish(self, value, memory),
            Err(fault) => {
                self.prepare_input(
                    file_input::Accepted::TimerFd(Box::new(call)),
                    fault,
                    number,
                    args,
                );
                None
            }
        }
    }
}
