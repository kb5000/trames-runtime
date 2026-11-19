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
pub struct MutableLimits(pub [(u64, u64); 8]);
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
