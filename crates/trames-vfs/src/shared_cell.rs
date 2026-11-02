// SPDX-License-Identifier: GPL-3.0-or-later
//! Object-local state; no lock spans unrelated CPU or native execution.
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
#[derive(Default)]
pub(super) struct SharedCell<T>(RwLock<T>);
impl<T> SharedCell<T> {
    pub fn new(value: T) -> Self {
        Self(RwLock::new(value))
    }
    pub fn borrow(&self) -> RwLockReadGuard<'_, T> {
        self.0.read().unwrap()
    }
    pub fn borrow_mut(&self) -> RwLockWriteGuard<'_, T> {
        self.0.write().unwrap()
    }
}

impl<T: Copy> SharedCell<T> {
    pub fn get(&self) -> T {
        *self.borrow()
    }
    pub fn set(&self, value: T) {
        *self.borrow_mut() = value;
    }
}
