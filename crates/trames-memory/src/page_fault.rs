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
    resource: Option<Arc<dyn trames_shared::ResourceWait>>,
}
impl PageWait {
    pub fn resource(resource: Arc<dyn trames_shared::ResourceWait>) -> Arc<Self> {
        Arc::new(Self {
            resource: Some(resource),
            ..Self::default()
        })
    }
    pub fn ready(&self) -> bool {
        self.complete.load(Ordering::Acquire)
            || self
                .resource
                .as_ref()
                .is_some_and(|resource| resource.ready())
    }
    /// Publish the provider's result before waking actors. A provider calls
    /// this after releasing its own page/request transaction.
    pub fn finish(&self) {
        if !self.complete.swap(true, Ordering::AcqRel) {
            self.changed.notify_atomic();
        }
    }
    /// A completion provider knows this wait has a single completion source.
    /// Fault consumers subscribe to every resource source with subscribe().
    pub fn subscribe_completion(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        assert!(self.resource.is_none());
        self.changed.subscribe(signal)
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        let mut subscriptions = self
            .resource
            .as_ref()
            .map_or_else(Vec::new, |resource| resource.subscribe(signal));
        let mut completion = self.changed.subscribe(signal);
        if let Some(resource) = &self.resource {
            completion = completion.with_resource_wait(resource.clone());
        }
        subscriptions.push(completion);
        subscriptions
    }
    /// Observe later resource transitions even when it is currently ready.
    /// This does not attach an already-ready late native-source driver while
    /// another independent dependency still keeps the original work parked.
    pub fn subscribe_changes(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        let mut subscriptions = self
            .resource
            .as_ref()
            .map_or_else(Vec::new, |resource| resource.subscribe(signal));
        subscriptions.push(self.changed.subscribe(signal));
        subscriptions
    }
    pub fn deadline(&self) -> Option<std::time::Instant> {
        self.resource
            .as_ref()
            .and_then(|resource| resource.deadline())
    }
    pub fn fault(self: &Arc<Self>, address: u64) -> crate::MemoryError {
        crate::MemoryError::Pending(PageFault {
            address,
            wait: self.clone(),
        })
    }
}
impl trames_shared::ResourceWait for PageWait {
    fn ready(&self) -> bool {
        self.ready()
    }
    fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        self.subscribe(signal)
    }
    fn deadline(&self) -> Option<std::time::Instant> {
        self.deadline()
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
