// SPDX-License-Identifier: GPL-3.0-or-later
//! Completion of original task resource work, independent of PID/CPU custody.
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use trames_vfs::{IoSignal, IoSubscription};

pub struct Completion {
    finished: AtomicBool,
    ready: Arc<trames_shared::Readiness>,
}
impl Default for Completion {
    fn default() -> Self {
        Self {
            finished: AtomicBool::new(false),
            ready: Default::default(),
        }
    }
}
impl Completion {
    pub fn finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }
    pub fn finish(&self) {
        // Actual task synchronization: consumers observe the completed mm
        // release or execution departure before continuing on their executor.
        if !self.finished.swap(true, Ordering::Release) {
            self.ready.notify_atomic();
        }
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.ready.subscribe(signal)
    }
}
