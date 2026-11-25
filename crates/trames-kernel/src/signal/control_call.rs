// SPDX-License-Identifier: GPL-3.0-or-later
//! An accepted signal control owns its imported input, one state transition
//! and the predecessor output until the original caller finishes its copy.
use super::*;
use crate::user_copy::{Copies, CopyError};
use std::sync::Arc;
use trames_memory::{CopiedOutput, MemoryError, PageFault};

pub struct ControlCall {
    number: u32,
    args: [u64; 6],
    sp: u64,
    actions: Actions,
    directory: Arc<IoDirectory>,
    original: Option<Arc<IoTask>>,
    entry_mask: Option<u64>,
    input: Copies,
    output: CopiedOutput,
    rseq: Option<crate::rseq::Call>,
    accepted: bool,
    fault: Option<PageFault>,
    result: Option<Result<u64, Errno>>,
}
enum Input {
    Action(usize, Option<Action>),
    Mask(control::MaskInput),
    Stack(Option<AltStack>),
    Pending,
    Rseq,
}
impl ControlCall {
    pub fn new(
        number: u32,
        args: [u64; 6],
        sp: u64,
        actions: Actions,
        directory: Arc<IoDirectory>,
    ) -> Self {
        Self {
            number,
            args,
            sp,
            actions,
            directory,
            original: None,
            entry_mask: None,
            input: Default::default(),
            output: Default::default(),
            rseq: None,
            accepted: false,
            fault: None,
            result: None,
        }
    }
    pub fn fault(&self) -> Option<PageFault> {
        self.fault.clone()
    }
    pub fn ready(&self) -> bool {
        self.fault.as_ref().is_none_or(|fault| fault.wait.ready())
    }
    pub fn cancel(&mut self) {
        self.original = None;
        self.input = Copies::default();
        self.output = CopiedOutput::default();
        self.rseq = None;
        self.fault = None;
        self.result = Some(Err(Errno(4)));
    }
    pub fn check(
        &mut self,
        task: &Arc<IoTask>,
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        if let Some(result) = self.result {
            return Some(result);
        }
        if self.original.is_none() {
            self.original = Some(task.clone());
            // rt_sigprocmask captures its predecessor before importing nset.
            self.entry_mask = Some(task.mask());
        }
        self.fault = None;
        let result = self.progress(memory);
        match result {
            Err(CopyError::Page(fault)) => {
                self.fault = Some(fault);
                None
            }
            Err(CopyError::Error(error)) => self.complete(Err(error)),
            Ok(()) => self.complete(Ok(0)),
        }
    }
    fn complete(&mut self, result: Result<u64, Errno>) -> Option<Result<u64, Errno>> {
        self.original = None;
        self.input = Copies::default();
        self.output = CopiedOutput::default();
        self.rseq = None;
        self.result = Some(result);
        Some(result)
    }
    fn progress(&mut self, memory: &mut impl CpuMemory) -> Result<(), CopyError> {
        if !self.accepted {
            let (number, args) = (self.number, self.args);
            let input = self.input.run(memory, |view| match number {
                132 => AltStack::import(view, args[0]).map(Input::Stack),
                134 => Actions::import(args, view)
                    .map(|(signal, action)| Input::Action(signal, action)),
                135 => control::MaskInput::import(args, view).map(Input::Mask),
                136 if args[1] <= 8 => Ok(Input::Pending),
                293 => Ok(Input::Rseq),
                _ => Err(Errno(22)),
            })?;
            let task = self.original.as_ref().unwrap();
            match input {
                Input::Action(signal, next) => {
                    let old = self.actions.exchange(signal, next, |action| {
                        if ignored(signal as u32, action)
                            && !self.directory.discard_process(task.tgid(), signal as u32)
                        {
                            task.inbox.discard(signal as u32);
                            task.process().discard(signal as u32);
                        }
                    });
                    if args[2] != 0 {
                        self.output.push_slice(args[2], &old.encode());
                    }
                }
                Input::Mask(input) => {
                    if let Some(mask) = input.apply(task.mask()) {
                        task.context.lock().unwrap().mask = mask;
                        task.publish_mask(mask);
                    }
                    if args[2] != 0 {
                        self.output
                            .push_slice(args[2], &self.entry_mask.unwrap().to_le_bytes());
                    }
                }
                Input::Stack(next) => {
                    let old = task
                        .context
                        .lock()
                        .unwrap()
                        .alt_stack
                        .exchange(self.sp, next)
                        .map_err(CopyError::Error)?;
                    if args[1] != 0 {
                        self.output.push_slice(args[1], &old.encode(self.sp));
                    }
                }
                Input::Pending => {
                    if args[1] != 0 {
                        self.output.push_slice(
                            args[0],
                            &(task.pending_bits() & task.mask()).to_le_bytes()[..args[1] as usize],
                        );
                    }
                }
                Input::Rseq => {
                    self.rseq = Some(crate::rseq::Call::new(args));
                }
            }
            self.accepted = true;
            self.input = Copies::default();
        }
        if let Some(call) = &mut self.rseq {
            call.progress(&self.original.as_ref().unwrap().rseq, memory)?;
        }
        self.output.progress(memory).map_err(|error| match error {
            MemoryError::Pending(fault) => CopyError::Page(fault),
            _ => CopyError::Error(Errno(14)),
        })
    }
}
