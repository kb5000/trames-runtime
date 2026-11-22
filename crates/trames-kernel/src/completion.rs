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
    vfork: Option<(u32, Option<trames_vfs::PidReference>)>,
}
impl Default for Completion {
    fn default() -> Self {
        Self {
            finished: AtomicBool::new(false),
            ready: Default::default(),
            vfork: None,
        }
    }
}
impl Completion {
    /// Keep the child's PID translation alive until the original waiter consumes
    /// the mm release, including when an ignored SIGCHLD auto-reaps the child.
    pub fn for_vfork(child: u32, namespace: &trames_vfs::PidNamespace) -> Self {
        Self {
            vfork: Some((child, namespace.retain(child))),
            ..Self::default()
        }
    }
    pub fn vfork_child(&self) -> Option<u32> {
        self.vfork.as_ref().map(|(id, _)| *id)
    }
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
