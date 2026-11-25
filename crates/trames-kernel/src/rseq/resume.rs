// SPDX-License-Identifier: GPL-3.0-or-later
//! One accepted notify-resume. Registration/events and successful user copies
//! survive a backing-page wait; replay never consumes the task's events twice.
use super::*;
use crate::user_copy::Copies;
pub use crate::user_copy::CopyError as ResumeError;
pub struct Resume {
    registration: Registration,
    pc: u64,
    events: u32,
    cpu: u32,
    fixed_pc: Option<u64>,
    copies: Copies,
}
pub enum ResumeProgress {
    Complete(u64),
    Page {
        fault: trames_memory::PageFault,
        pc: u64,
    },
    Error {
        error: Errno,
        pc: u64,
    },
}
impl Resume {
    pub fn pc(&self) -> u64 {
        self.fixed_pc.unwrap_or(self.pc)
    }
    pub fn progress(
        &mut self,
        task: &Rseq,
        memory: &mut impl CpuMemory,
    ) -> Result<u64, ResumeError> {
        if self.fixed_pc.is_none() {
            self.fixed_pc = Some(self.copies.run(memory, |view| {
                Rseq::fixup(view, self.registration, self.pc, self.events)
            })?);
            self.copies = Default::default();
        }
        self.copies.run(memory, |view| {
            for (at, value) in [(0, self.cpu), (4, self.cpu), (20, 0), (24, self.cpu)] {
                view.write_array(self.registration.address + at, value.to_le_bytes())
                    .map_err(|_| Errno(14))?;
            }
            Ok(())
        })?;
        task.cpu.store(self.cpu, Relaxed);
        Ok(self.pc())
    }
}
impl Rseq {
    pub fn begin_signal(&self, pc: u64) -> Option<Resume> {
        let cpu = self.cpu.load(Relaxed);
        let cpu = if cpu == u32::MAX { 0 } else { cpu };
        self.begin_resume_event(pc, cpu, SIGNAL)
    }
    pub fn begin_resume(&self, pc: u64, cpu: u32) -> Option<Resume> {
        self.begin_resume_event(pc, cpu, 0)
    }
    pub(super) fn begin_resume_event(&self, pc: u64, cpu: u32, event: u32) -> Option<Resume> {
        if self.address.load(Relaxed) == 0 {
            return None;
        }
        let current = self.cpu.load(Relaxed);
        if event == 0 && current == cpu && self.pending.load(Relaxed) == 0 {
            return None;
        }
        let registration = (*self.registration.lock().unwrap())?;
        let migrate = current != u32::MAX && current != cpu;
        Some(Resume {
            registration,
            pc,
            cpu,
            fixed_pc: None,
            events: (self.pending.swap(0, Relaxed) | event | if migrate { MIGRATE } else { 0 })
                & (PREEMPT | SIGNAL | MIGRATE),
            copies: Default::default(),
        })
    }
}
