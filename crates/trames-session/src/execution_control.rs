// SPDX-License-Identifier: GPL-3.0-or-later
//! Execution admission and one-way session completion.
//!
//! A legacy handoff can suspend admission, but can never turn a closing session
//! back into work for its caller. Physical CPU interruption is not guest dispatch.
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};

const RUNNING: u8 = 0;
const HANDOFF: u8 = 1;
const CLOSING: u8 = 2;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum End {
    Budget = 2,
    Cancelled = 3,
    Exited = 4,
    Failed = 5,
}
pub(crate) struct Control {
    phase: AtomicU8,
    pub(crate) remaining: AtomicU64,
    terminal_budget: bool,
}
impl Control {
    #[cfg(all(test, trames_interpreter_conformance))]
    pub(crate) fn new(budget: u64) -> Self {
        Self::with_budget(budget, false)
    }
    pub(crate) fn with_budget(budget: u64, terminal_budget: bool) -> Self {
        Self {
            phase: AtomicU8::new(RUNNING),
            remaining: AtomicU64::new(budget),
            terminal_budget: terminal_budget && budget != u64::MAX,
        }
    }
    /// Existing compatibility admission boundary, never session completion.
    /// Kept distinct so closing cannot re-enter the guest on the waiting host.
    pub(crate) fn handoff(&self) {
        let _ = self
            .phase
            .compare_exchange(RUNNING, HANDOFF, Ordering::Release, Ordering::Relaxed);
    }
    pub(crate) fn close(&self, reason: End) {
        let _ = self
            .phase
            .try_update(Ordering::Release, Ordering::Relaxed, |phase| {
                (phase < CLOSING).then_some(reason as u8)
            });
    }
    pub(crate) fn end(&self) -> Option<End> {
        match self.phase.load(Ordering::Acquire) {
            0 | 1 => None,
            2 => Some(End::Budget),
            3 => Some(End::Cancelled),
            4 => Some(End::Exited),
            5 => Some(End::Failed),
            _ => unreachable!(),
        }
    }
    pub(crate) fn closing(&self) -> bool {
        self.phase.load(Ordering::Acquire) >= CLOSING
    }
    pub(crate) fn stopped(&self) -> bool {
        self.phase.load(Ordering::Acquire) != RUNNING
    }
    pub(crate) fn refund(&self, instructions: u64) {
        self.remaining.fetch_add(instructions, Ordering::Relaxed);
    }
    pub(crate) fn claim(&self) -> Option<u64> {
        if self.stopped() {
            return None;
        }
        match self
            .remaining
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                (left != 0).then(|| left.saturating_sub(super::workers::POLL_INSTRUCTIONS))
            }) {
            Ok(left) => Some(left.min(super::workers::POLL_INSTRUCTIONS)),
            Err(_) => {
                if !self.terminal_budget {
                    self.handoff();
                }
                None
            }
        }
    }
    /// Zero unallocated credit may still belong to a running CPU. Only the
    /// queue's real quiescence boundary can declare a finite budget exhausted.
    pub(crate) fn budget_ready(&self) -> bool {
        !self.terminal_budget || self.remaining.load(Ordering::Relaxed) != 0
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub(crate) fn stop(&self) {
        self.handoff();
    }
}
