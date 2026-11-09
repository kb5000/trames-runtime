// SPDX-License-Identifier: GPL-3.0-or-later
//! Original per-thread comm bytes. Only actual updates/observers synchronize.
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Default)]
pub struct TaskName(Arc<Mutex<[u8; 16]>>);
impl TaskName {
    pub fn set(&self, bytes: &[u8]) {
        let mut value = [0; 16];
        let count = bytes.len().min(15);
        value[..count].copy_from_slice(&bytes[..count]);
        *self.0.lock().unwrap() = value;
    }
    pub fn bytes(&self) -> [u8; 16] {
        *self.0.lock().unwrap()
    }
    pub fn get(&self) -> Vec<u8> {
        let value = self.bytes();
        value[..value.iter().position(|b| *b == 0).unwrap_or(15)].to_vec()
    }
    /// Linux clone/fork inherits comm's value, including CLONE_THREAD/CLONE_VM;
    /// a new task never shares future name changes with its creator.
    pub fn fork(&self) -> Self {
        Self(Arc::new(Mutex::new(self.bytes())))
    }
}
