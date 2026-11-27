// SPDX-License-Identifier: GPL-3.0-or-later
//! Optional actor-local cold-fault accounting. No observer enters a page lock.
use std::{
    cell::RefCell,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};
#[derive(Default)]
pub struct FaultCounts {
    counts: [AtomicU64; 4],
    kernel: AtomicBool,
}
impl FaultCounts {
    pub fn kernel(&self, kernel: bool) {
        self.kernel.store(kernel, Ordering::Relaxed);
    }
    pub fn take(&self) -> [u64; 4] {
        std::array::from_fn(|i| self.counts[i].swap(0, Ordering::Relaxed))
    }
}
thread_local! {static CURRENT:RefCell<Option<Arc<FaultCounts>>>=const {RefCell::new(None)};}
pub struct FaultScope(Option<Arc<FaultCounts>>, std::marker::PhantomData<*mut ()>);
impl FaultScope {
    pub fn enter(counts: Option<Arc<FaultCounts>>) -> Self {
        Self(
            CURRENT.with(|current| current.replace(counts)),
            Default::default(),
        )
    }
    pub fn install(&self, counts: Arc<FaultCounts>) {
        CURRENT.with(|current| *current.borrow_mut() = Some(counts));
    }
}
impl Drop for FaultScope {
    fn drop(&mut self) {
        CURRENT.with(|current| *current.borrow_mut() = self.0.take());
    }
}
pub(crate) fn fault(major: bool) {
    CURRENT.with(|current| {
        if let Some(counts) = current.borrow().as_ref() {
            let i = usize::from(major) + usize::from(counts.kernel.load(Ordering::Relaxed)) * 2;
            counts.counts[i].fetch_add(1, Ordering::Relaxed);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Memory, Permissions, PAGE_SIZE};

    #[test]
    fn first_write_and_child_cow_count_but_resident_accesses_do_not() {
        let mut memory = Memory::default();
        memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
        let counts = Arc::new(FaultCounts::default());
        let _scope = FaultScope::enter(Some(counts.clone()));
        memory.write(0x10000, &[1]).unwrap();
        assert_eq!(counts.take(), [1, 0, 0, 0]);
        memory.write(0x10000, &[2]).unwrap();
        assert_eq!(memory.read_array::<1>(0x10000).unwrap(), [2]);
        assert_eq!(counts.take(), [0; 4]);
        let mut child = memory.try_fork().unwrap();
        counts.kernel(true);
        child.write(0x10000, &[3]).unwrap();
        assert_eq!(counts.take(), [0, 0, 1, 0]);
        assert_eq!(memory.read_array::<1>(0x10000).unwrap(), [2]);
        assert_eq!(child.read_array::<1>(0x10000).unwrap(), [3]);
        assert_eq!(counts.take(), [0; 4]);
    }
}
