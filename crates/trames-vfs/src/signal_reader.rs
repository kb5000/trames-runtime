// SPDX-License-Identifier: GPL-3.0-or-later
//! Reading-task signal authority. The OFD owns its mask; the current syscall
//! supplies pending queues. No creator-task authority is stored in shared FDs.
use crate::{IoSignal, IoSubscription};
use std::sync::Arc;
pub trait SignalReader: Send + Sync {
    fn poll(&self, mask: u64) -> (u16, [u64; 2]);
    fn take(&self, mask: u64) -> Option<[u8; 128]>;
    fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription>;
}
