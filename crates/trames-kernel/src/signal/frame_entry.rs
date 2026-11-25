// SPDX-License-Identifier: GPL-3.0-or-later
//! Accepted handler entry on the original task, including rseq's user copies.
use super::*;
use trames_execution::{Aarch64State, SmeConfig, SmeState};
use trames_memory::{MemoryError, PageFault};

pub struct FrameCommit {
    pub frame: FrameState,
    pub state: Aarch64State,
    pub clear_sme: bool,
    pub restored_sme: Option<Option<Box<SmeState>>>,
    pub returned: bool,
}
#[allow(clippy::large_enum_variant)] // The successful original CPU state moves directly to its executor.
pub enum FrameProgress {
    Complete(FrameCommit),
    Page(PageFault),
    EntryPage {
        fault: PageFault,
        pc: u64,
    },
    ReturnPage {
        fault: PageFault,
        partial: FrameCommit,
    },
    Rseq(crate::rseq::ResumeProgress),
    Error {
        error: Errno,
        signal: u32,
        pc: Option<u64>,
    },
    ReturnError {
        error: Errno,
        fault: Fault,
        partial: FrameCommit,
    },
}
#[allow(clippy::large_enum_variant)] // Original CPU state stays inline in the task's owned continuation.
pub(super) enum Entry {
    Enter(Entering),
    Return(Returning),
    Rseq(crate::rseq::Resume),
}
pub(super) struct Entering {
    signal: u32,
    rseq: Option<crate::rseq::Resume>,
    interrupted_pc: Option<u64>,
    prepared: Option<Result<PreparedFrame, Errno>>,
}
impl Entering {
    fn progress(&mut self, task: &IoTask, memory: &mut impl CpuMemory) -> FrameProgress {
        if let Some(rseq) = &mut self.rseq {
            let result = rseq.progress(&task.rseq, memory);
            self.interrupted_pc = Some(rseq.pc());
            let pc = match result {
                Ok(pc) => pc,
                Err(crate::rseq::ResumeError::Page(fault)) => {
                    return FrameProgress::EntryPage {
                        fault,
                        pc: rseq.pc(),
                    }
                }
                Err(crate::rseq::ResumeError::Error(error)) => {
                    return FrameProgress::Error {
                        error,
                        signal: self.signal,
                        pc: self.interrupted_pc,
                    }
                }
            };
            if let Some(Ok(prepared)) = &mut self.prepared {
                prepared.interrupted_pc(pc);
            }
            self.rseq = None;
        }
        let mut prepared = match self.prepared.take().expect("accepted frame") {
            Ok(prepared) => prepared,
            Err(error) => {
                return FrameProgress::Error {
                    error,
                    signal: self.signal,
                    pc: self.interrupted_pc,
                }
            }
        };
        match prepared.progress(memory) {
            Err(MemoryError::Pending(fault)) => {
                self.prepared = Some(Ok(prepared));
                if let Some(pc) = self.interrupted_pc {
                    FrameProgress::EntryPage { fault, pc }
                } else {
                    FrameProgress::Page(fault)
                }
            }
            Err(_) => FrameProgress::Error {
                error: Errno(14),
                signal: self.signal,
                pc: self.interrupted_pc,
            },
            Ok(()) => FrameProgress::Complete(prepared.finish()),
        }
    }
}
pub(super) struct Returning {
    frame: FrameState,
    state: Aarch64State,
    address: u64,
    gprs: super::return_gprs::Gprs,
    phase: u8,
    floating: super::return_fp::Floating,
    copies: crate::user_copy::Copies,
}
impl Returning {
    fn snapshot(&self) -> FrameCommit {
        FrameCommit {
            frame: FrameState {
                actions: self.frame.actions.shared(),
                mask: self.frame.mask,
                frames: self.frame.frames,
                alt_stack: self.frame.alt_stack,
            },
            state: self.state.clone(),
            clear_sme: false,
            restored_sme: self.floating.result(),
            returned: true,
        }
    }
    fn progress(&mut self, task: &IoTask, memory: &mut impl CpuMemory) -> FrameProgress {
        use crate::user_copy::CopyError;
        loop {
            let result = match self.phase {
                0 => self
                    .gprs
                    .progress(&mut self.frame, &mut self.state, Some(task), memory),
                1 => self.floating.progress(&mut self.state, memory),
                2 => self.copies.run(memory, |view| {
                    self.frame.restore_stack(&self.state, view, self.address)
                }),
                _ => {
                    return FrameProgress::Complete(FrameCommit {
                        frame: FrameState {
                            actions: self.frame.actions.shared(),
                            mask: self.frame.mask,
                            frames: self.frame.frames,
                            alt_stack: self.frame.alt_stack,
                        },
                        state: std::mem::take(&mut self.state),
                        restored_sme: self.floating.take_result(),
                        clear_sme: false,
                        returned: true,
                    })
                }
            };
            match result {
                Ok(()) => {
                    self.phase += 1;
                    self.copies = Default::default();
                }
                Err(CopyError::Page(fault)) => {
                    return FrameProgress::ReturnPage {
                        fault,
                        partial: self.snapshot(),
                    }
                }
                Err(CopyError::Error(error)) => {
                    return FrameProgress::ReturnError {
                        error,
                        // arm64 rt_sigreturn reports regs->sp after attempting
                        // all scalar restores, including a failed get_user's
                        // zeroed SP. The frame pointer only locates copy input.
                        fault: Fault::bad_frame(self.state.sp, memory),
                        partial: self.snapshot(),
                    };
                }
            }
        }
    }
}
impl Entry {
    fn progress(&mut self, task: &IoTask, memory: &mut impl CpuMemory) -> FrameProgress {
        match self {
            Self::Enter(entry) => entry.progress(task, memory),
            Self::Return(entry) => entry.progress(task, memory),
            Self::Rseq(resume) => FrameProgress::Rseq(match resume.progress(&task.rseq, memory) {
                Ok(pc) => crate::rseq::ResumeProgress::Complete(pc),
                Err(crate::rseq::ResumeError::Page(fault)) => crate::rseq::ResumeProgress::Page {
                    fault,
                    pc: resume.pc(),
                },
                Err(crate::rseq::ResumeError::Error(error)) => crate::rseq::ResumeProgress::Error {
                    error,
                    pc: resume.pc(),
                },
            }),
        }
    }
}
impl FrameProgress {
    fn pending(&self) -> bool {
        matches!(
            self,
            Self::Page(_)
                | Self::EntryPage { .. }
                | Self::ReturnPage { .. }
                | Self::Rseq(crate::rseq::ResumeProgress::Page { .. })
        )
    }
}
impl IoTask {
    pub fn start_rseq_resume(
        &self,
        pc: u64,
        cpu: u32,
        memory: &mut impl CpuMemory,
    ) -> Option<FrameProgress> {
        let resume = self.rseq.begin_resume(pc, cpu)?;
        Some(self.begin_frame_entry(Entry::Rseq(resume), memory))
    }
    #[allow(clippy::too_many_arguments)]
    pub fn start_frame(
        &self,
        frame: FrameState,
        state: &Aarch64State,
        sig: u32,
        info: Info,
        action: Action,
        sme: Option<(SmeConfig, Option<&SmeState>, bool)>,
        restore_mask: Option<u64>,
        memory: &mut impl CpuMemory,
    ) -> FrameProgress {
        let rseq = self.rseq.begin_signal(state.pc);
        let prepared =
            Some(frame.prepare_sme_restoring(state, sig, info, action, sme, restore_mask));
        self.begin_frame_entry(
            Entry::Enter(Entering {
                signal: sig,
                rseq,
                interrupted_pc: None,
                prepared,
            }),
            memory,
        )
    }
    pub fn start_frame_return(
        &self,
        frame: FrameState,
        state: Aarch64State,
        config: Option<SmeConfig>,
        sme2: bool,
        registers: Option<&SmeState>,
        memory: &mut impl CpuMemory,
    ) -> FrameProgress {
        let address = state.sp;
        self.begin_frame_entry(
            Entry::Return(Returning {
                frame,
                state,
                address,
                gprs: super::return_gprs::Gprs::new(address),
                phase: 0,
                floating: super::return_fp::Floating::new(address, config, sme2, registers),
                copies: Default::default(),
            }),
            memory,
        )
    }
    fn begin_frame_entry(&self, mut entry: Entry, memory: &mut impl CpuMemory) -> FrameProgress {
        assert!(
            !self.has_pending_frame(),
            "one original signal boundary per task"
        );
        let result = entry.progress(self, memory);
        if result.pending() {
            let mut slot = self.frame.lock().unwrap();
            assert!(slot.is_none(), "one original handler entry per task");
            *slot = Some(Box::new(entry));
            self.frame_pending
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        result
    }
    pub fn has_pending_frame(&self) -> bool {
        self.frame_pending
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn resume_frame(&self, memory: &mut impl CpuMemory) -> Option<FrameProgress> {
        if !self.has_pending_frame() {
            return None;
        }
        let mut slot = self.frame.lock().unwrap();
        let result = slot.as_mut()?.progress(self, memory);
        if !result.pending() {
            slot.take();
            self.frame_pending
                .store(false, std::sync::atomic::Ordering::Relaxed);
        }
        Some(result)
    }
    pub fn discard_frame(&self) {
        if !self.has_pending_frame() {
            return;
        }
        self.frame.lock().unwrap().take();
        self.frame_pending
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }
}
