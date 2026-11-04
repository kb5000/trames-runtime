// SPDX-License-Identifier: GPL-3.0-or-later
//! Process resource-policy fields shared with the original enforcement objects.
use std::sync::{
    atomic::{AtomicU32, AtomicU64, Ordering},
    Arc,
};
#[derive(Clone)]
pub struct FileSizeLimit(Arc<AtomicU64>);
impl Default for FileSizeLimit {
    fn default() -> Self {
        Self(Arc::new(AtomicU64::new(u64::MAX)))
    }
}
impl FileSizeLimit {
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
    pub fn set(&self, value: u64) {
        self.0.store(value, Ordering::Relaxed);
    }
    pub(super) fn fork(&self) -> Self {
        Self(Arc::new(AtomicU64::new(self.get())))
    }
    pub(super) fn identity(&self) -> usize {
        Arc::as_ptr(&self.0) as usize
    }
}
#[derive(Clone)]
pub struct DescriptorLimit(pub(super) Arc<AtomicU32>);
impl DescriptorLimit {
    pub fn get(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }
    pub fn set(&self, value: u32) {
        self.0.store(value.min(super::MAX_FDS), Ordering::Relaxed);
    }
}
