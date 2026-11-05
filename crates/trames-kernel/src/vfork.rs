// SPDX-License-Identifier: GPL-3.0-or-later
//! The original vfork child's mm-release event, independent of PID/CPU custody.
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use trames_vfs::{IoSignal, IoSubscription};

pub struct Release {
    finished: AtomicBool,
    ready: Arc<trames_shared::Readiness>,
}
impl Default for Release {
    fn default() -> Self {
        Self {
            finished: AtomicBool::new(false),
            ready: Default::default(),
        }
    }
}
impl Release {
    pub fn finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }
    pub fn finish(&self) {
        // This is an actual child/parent synchronization event. A resumed
        // parent observes writes made before the child released their old mm.
        if !self.finished.swap(true, Ordering::Release) {
            self.ready.notify_atomic();
        }
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.ready.subscribe(signal)
    }
}
