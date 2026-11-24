// SPDX-License-Identifier: GPL-3.0-or-later
//! Process resource-policy fields shared with the original enforcement objects.
use std::sync::{
    atomic::{AtomicU32, AtomicU64, Ordering},
    Arc,
};
/// One original environment's task ceiling. Binding and the value share one
/// relaxed atomic so proc snapshots cannot overwrite a live sysctl update.
#[derive(Clone)]
pub struct TaskLimit(Arc<AtomicU32>);
impl Default for TaskLimit {
    fn default() -> Self {
        Self(Arc::new(AtomicU32::new(super::MAX_TASKS as u32)))
    }
}
impl TaskLimit {
    const BOUND: u32 = 1 << 31;
    pub const MAX: u32 = 0x3fff_ffff;
    pub fn new(value: usize) -> Self {
        Self(Arc::new(AtomicU32::new(
            Self::BOUND | value.clamp(1, Self::MAX as usize) as u32,
        )))
    }
    pub fn get(&self) -> usize {
        (self.0.load(Ordering::Relaxed) & Self::MAX) as usize
    }
    pub fn set(&self, value: u32) -> Result<(), super::Errno> {
        if !(1..=Self::MAX).contains(&value) {
            return Err(super::Errno(22));
        }
        self.0.store(Self::BOUND | value, Ordering::Relaxed);
        Ok(())
    }
    pub fn bind_initial(&self, value: usize) {
        let value = value.clamp(1, Self::MAX as usize) as u32;
        let _ = self
            .0
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                (old & Self::BOUND == 0).then_some(Self::BOUND | value)
            });
    }
    pub(super) fn snapshot(&self, value: usize) {
        if value == 0 {
            return;
        }
        let value = value.min(Self::MAX as usize) as u32;
        let _ = self
            .0
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                (old & Self::BOUND == 0).then_some(value)
            });
    }
}
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
pub struct MemoryResourceLimits(Arc<[AtomicU64; 4]>);
impl Default for MemoryResourceLimits {
    fn default() -> Self {
        Self(Arc::new([
            AtomicU64::new(u64::MAX),
            AtomicU64::new(u64::MAX),
            AtomicU64::new(64 * 1024),
            AtomicU64::new(super::posix_mq::DEFAULT_BYTES),
        ]))
    }
}
impl MemoryResourceLimits {
    pub fn data(&self) -> u64 {
        self.0[0].load(Ordering::Relaxed)
    }
    pub fn locked(&self) -> u64 {
        self.0[2].load(Ordering::Relaxed)
    }
    pub fn message_queue(&self) -> u64 {
        self.0[3].load(Ordering::Relaxed)
    }
    pub fn address_space(&self) -> u64 {
        self.0[1].load(Ordering::Relaxed)
    }
    pub fn set(&self, resource: u64, value: u64) {
        let index = match resource {
            2 => 0,
            9 => 1,
            8 => 2,
            12 => 3,
            _ => unreachable!("memory resource"),
        };
        self.0[index].store(value, Ordering::Relaxed);
    }
    pub(super) fn fork(&self) -> Self {
        Self(Arc::new([
            AtomicU64::new(self.data()),
            AtomicU64::new(self.address_space()),
            AtomicU64::new(self.locked()),
            AtomicU64::new(self.message_queue()),
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

/// Current mutable pairs from one original process-limit transaction.
#[derive(Clone, Copy, Debug)]
pub struct MutableLimits(pub [(u64, u64); 9]);
impl MutableLimits {
    pub fn index(resource: u64) -> Option<usize> {
        match resource {
            1 => Some(0),
            4 => Some(1),
            7 => Some(2),
            13 => Some(3),
            2 => Some(4),
            9 => Some(5),
            8 => Some(6),
            12 => Some(7),
            0 => Some(8),
            _ => None,
        }
    }

    pub fn get(&self, resource: u64) -> Option<(u64, u64)> {
        Self::index(resource).map(|index| self.0[index])
    }
}
#[derive(Clone, Copy)]
pub struct FixedLimits {
    pub address_space: u64,
    pub stack: u64,
    pub tasks: u64,
}
impl FixedLimits {
    pub fn value(self, resource: u64) -> Result<u64, crate::Errno> {
        Ok(match resource {
            0 | 1 | 8 | 10 | 15 => u64::MAX,
            2 | 5 | 9 => self.address_space,
            3 => self.stack,
            4 | 14 => 0,
            12 => super::posix_mq::DEFAULT_BYTES,
            13 => 40,
            6 => self.tasks,
            7 => crate::MAX_FDS as u64,
            11 => 64,
            _ => return Err(crate::Errno(22)),
        })
    }
}
