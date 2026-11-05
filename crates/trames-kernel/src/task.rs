// SPDX-License-Identifier: GPL-3.0-or-later
//! PID visibility is independent of the executor that later drops its projection.
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
/// A directory may retain this bit, never the actual task lifetime owner.
#[derive(Clone, Default)]
pub struct Visibility(Arc<AtomicBool>);
impl Visibility {
    pub(crate) fn identity(&self) -> usize {
        Arc::as_ptr(&self.0) as usize
    }
    pub fn present(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
    pub fn reap(&self) {
        self.0.store(false, Ordering::Relaxed);
    }
}
pub struct Presence(Visibility);
impl Default for Presence {
    fn default() -> Self {
        Self(Visibility(Arc::new(AtomicBool::new(true))))
    }
}
impl Presence {
    pub fn present(&self) -> bool {
        self.0.present()
    }
    pub fn visibility(&self) -> Visibility {
        self.0.clone()
    }
}
impl Drop for Presence {
    fn drop(&mut self) {
        self.0.reap();
    }
}
