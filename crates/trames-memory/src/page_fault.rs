// SPDX-License-Identifier: GPL-3.0-or-later
//! An accepted asynchronous page resource, independent of its virtual aliases.
use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use trames_shared::{IoSignal, IoSubscription, Readiness};

/// Completion belongs to the original page request. All faulting actors may
/// subscribe independently; cancelling one actor removes only its subscription.
#[derive(Default)]
pub struct PageWait {
    complete: AtomicBool,
    changed: Arc<Readiness>,
}
impl PageWait {
    pub fn ready(&self) -> bool {
        self.complete.load(Ordering::Acquire)
    }
    /// Publish the provider's result before waking actors. A provider calls
    /// this after releasing its own page/request transaction.
    pub fn finish(&self) {
        if !self.complete.swap(true, Ordering::AcqRel) {
            self.changed.notify_atomic();
        }
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.changed.subscribe(signal)
    }
    pub fn fault(self: &Arc<Self>, address: u64) -> crate::MemoryError {
        crate::MemoryError::Pending(PageFault {
            address,
            wait: self.clone(),
        })
    }
}
#[derive(Clone)]
pub struct PageFault {
    pub address: u64,
    pub wait: Arc<PageWait>,
}
impl PageFault {
    pub(super) fn at(mut self, address: u64) -> Self {
        self.address = address;
        self
    }
}
impl fmt::Debug for PageFault {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("PageFault")
            .field("address", &self.address)
            .field("ready", &self.wait.ready())
            .finish()
    }
}
impl PartialEq for PageFault {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address && Arc::ptr_eq(&self.wait, &other.wait)
    }
}
impl Eq for PageFault {}
