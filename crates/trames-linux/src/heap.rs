// SPDX-License-Identifier: GPL-3.0-or-later
//! Allocation metadata follows the actual VM ownership domain. Mapping edits
//! still join the VM; a worker may only read the current program break.
use std::cell::Cell;
use std::rc::Rc;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

#[derive(Clone, Default)]
pub struct ProgramBreak(Arc<AtomicU64>);
impl ProgramBreak {
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

pub(crate) struct Heap(Rc<State>);
struct State {
    base: u64,
    current: ProgramBreak,
    next: Cell<u64>,
}
impl Clone for Heap {
    fn clone(&self) -> Self {
        Self::from_values(self.base(), self.current(), self.cursor())
    }
}
impl Heap {
    pub(crate) fn new(base: u64) -> Self {
        Self::from_values(base, base, 0x1000_0000)
    }
    fn from_values(base: u64, current: u64, next: u64) -> Self {
        Self(Rc::new(State {
            base,
            current: ProgramBreak(Arc::new(AtomicU64::new(current))),
            next: Cell::new(next),
        }))
    }
    pub(crate) fn shared(&self) -> Self {
        Self(self.0.clone())
    }
    pub(crate) fn base(&self) -> u64 {
        self.0.base
    }
    pub(crate) fn current(&self) -> u64 {
        self.0.current.get()
    }
    pub(crate) fn cursor(&self) -> u64 {
        self.0.next.get()
    }
    pub(crate) fn set_current(&self, value: u64) {
        // Query value only. Existing VM commit/join publishes mappings; this
        // scalar is not a page-table synchronization primitive.
        self.0.current.0.store(value, Ordering::Relaxed);
    }
    pub(crate) fn set_cursor(&self, value: u64) {
        self.0.next.set(value);
    }
    pub(crate) fn break_capability(&self) -> ProgramBreak {
        self.0.current.clone()
    }
}
