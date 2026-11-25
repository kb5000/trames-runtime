// SPDX-License-Identifier: GPL-3.0-or-later
//! One imported sigwait/suspend, retaining a consumed signal through copyout.
use super::*;
use crate::user_copy::{Copies, CopyError};
use std::{sync::Arc, time::Instant};

pub struct WaitCall {
    entry: Option<(u32, [u64; 6])>,
    request: Option<SignalWait>,
    copies: Copies,
    fault: Option<trames_memory::PageFault>,
    output: Option<(u32, u64, [u8; 128])>,
    result: Option<Result<u64, Errno>>,
    suspended: bool,
}
impl WaitCall {
    pub fn new(number: u32, args: [u64; 6]) -> Self {
        Self {
            entry: Some((number, args)),
            request: None,
            copies: Default::default(),
            fault: None,
            output: None,
            result: None,
            suspended: false,
        }
    }
    pub fn accepted(request: SignalWait) -> Self {
        Self {
            entry: None,
            request: Some(request),
            copies: Default::default(),
            fault: None,
            output: None,
            result: None,
            suspended: false,
        }
    }
    pub fn deadline(&self) -> Option<Instant> {
        if self.fault.is_some() || self.output.is_some() {
            None
        } else {
            self.request.as_ref().and_then(SignalWait::deadline)
        }
    }
    pub fn interruptible(&self) -> bool {
        self.fault.is_none() && self.output.is_none()
    }
    pub fn fault(&self) -> Option<trames_memory::PageFault> {
        self.fault.clone()
    }
    pub fn ready(&self, task: &IoTask) -> bool {
        if let Some(fault) = &self.fault {
            return fault.wait.ready();
        }
        self.result.is_some()
            || self
                .request
                .as_ref()
                .is_none_or(|request| request.ready(task))
    }
    pub fn check(
        &mut self,
        task: &Arc<IoTask>,
        memory: &mut impl CpuMemory,
        namespace: &trames_vfs::PidNamespace,
    ) -> Option<Result<u64, Errno>> {
        if let Some(result) = self.result {
            return Some(result);
        }
        self.fault = None;
        let result = self.progress(task, memory, namespace);
        match result {
            Err(CopyError::Page(fault)) => {
                self.fault = Some(fault);
                None
            }
            Err(CopyError::Error(error)) => {
                self.result = Some(Err(error));
                self.result
            }
            Ok(Some(result)) => {
                self.result = Some(Ok(result));
                self.result
            }
            Ok(None) => None,
        }
    }
    fn progress(
        &mut self,
        task: &Arc<IoTask>,
        memory: &mut impl CpuMemory,
        namespace: &trames_vfs::PidNamespace,
    ) -> Result<Option<u64>, CopyError> {
        if self.request.is_none() {
            let (number, args) = self.entry.expect("original signal wait input");
            self.request = Some(
                self.copies
                    .run(memory, |view| SignalWait::prepare(number, args, view))?,
            );
        }
        let request = self.request.expect("accepted signal wait");
        if let SignalWait::Suspend { mask } = request {
            if !self.suspended {
                let lease = trames_vfs::TaskSignal::temporary_mask(task.clone(), mask)
                    .expect("original signal task authority");
                // A caught handler or the actual user-return boundary restores
                // this mask. Dropping a parked snapshot must not restore early.
                lease.interrupted();
                self.suspended = true;
            }
            return Ok(None);
        }
        let SignalWait::Timed {
            mask,
            info,
            deadline,
        } = request
        else {
            unreachable!()
        };
        if self.output.is_none() {
            if let Some((sig, mut value)) = task.dequeue(mask) {
                if value.user.is_none()
                    && value.timer.is_none()
                    && value.fault.is_none()
                    && value.poll.is_none()
                {
                    value.sender = namespace.local(value.sender);
                }
                let mut bytes = [0; 128];
                write_siginfo(&mut bytes, sig, *value);
                self.output = Some((sig, info, bytes));
            } else {
                return if deadline.is_some_and(|deadline| deadline <= Instant::now()) {
                    Err(CopyError::Error(Errno(11)))
                } else {
                    Ok(None)
                };
            }
        }
        let (sig, address, bytes) = self.output.as_ref().unwrap();
        if *address != 0 {
            self.copies.run(memory, |view| {
                view.write_array(*address, *bytes).map_err(|_| Errno(14))
            })?;
        }
        Ok(Some(*sig as u64))
    }
}
