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
/// Per-process Linux VM policy. Limits do not reserve or commit guest pages.
#[derive(Clone)]
pub struct MemoryResourceLimits(Arc<[AtomicU64; 2]>);
impl Default for MemoryResourceLimits {
    fn default() -> Self {
        Self(Arc::new([
            AtomicU64::new(u64::MAX),
            AtomicU64::new(u64::MAX),
        ]))
    }
}
impl MemoryResourceLimits {
    pub fn data(&self) -> u64 {
        self.0[0].load(Ordering::Relaxed)
    }
    pub fn address_space(&self) -> u64 {
        self.0[1].load(Ordering::Relaxed)
    }
    pub fn set(&self, resource: u64, value: u64) {
        self.0[usize::from(resource == 9)].store(value, Ordering::Relaxed);
    }
    pub(super) fn fork(&self) -> Self {
        Self(Arc::new([
            AtomicU64::new(self.data()),
            AtomicU64::new(self.address_space()),
        ]))
    }
}
#[derive(Clone)]
pub struct DescriptorCeiling(Arc<AtomicU32>);
impl Default for DescriptorCeiling {
    fn default() -> Self {
        Self(Arc::new(AtomicU32::new(super::DEFAULT_MAX_FDS)))
    }
}
impl DescriptorCeiling {
    pub fn get(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }
    pub(super) fn set(&self, value: u32) {
        self.0.store(value, Ordering::Relaxed);
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
