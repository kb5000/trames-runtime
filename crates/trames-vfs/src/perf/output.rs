// SPDX-License-Identifier: GPL-3.0-or-later
//! A perf event points at an accepted ring, never at another event/OFD graph.
use super::*;
use std::sync::Weak;

pub(super) struct Output {
    pub(super) ring: parking_lot::Mutex<Weak<ring::Ring>>,
    pub(super) buffer: AtomicU64,
    pub(super) owned: AtomicU64,
    pub(super) changed: Arc<Readiness>,
    pending_hup: std::sync::atomic::AtomicBool,
    epoch: AtomicU64,
}
impl Output {
    pub(super) fn new(changed: Arc<Readiness>) -> Arc<Self> {
        Arc::new(Self {
            ring: Default::default(),
            buffer: Default::default(),
            owned: Default::default(),
            changed,
            pending_hup: Default::default(),
            epoch: Default::default(),
        })
    }
    pub(super) fn capture(&self) -> Option<Arc<ring::Ring>> {
        if self.buffer.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let state = self.ring.lock();
        state
            .upgrade()
            .filter(|ring| self.buffer.load(Ordering::Relaxed) == ring.identity && ring.mapped())
    }
    pub(super) fn capture_owned(&self) -> Option<Arc<ring::Ring>> {
        let ring = self.capture()?;
        (self.owned.load(Ordering::Relaxed) == ring.identity).then_some(ring)
    }
    pub(super) fn hangup(&self) {
        self.pending_hup.store(true, Ordering::Relaxed);
        self.epoch.fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn poll(&self, events: u16, consume: bool) -> (u16, [u64; 2]) {
        let mut result = self
            .capture()
            .map_or((16, [0; 2]), |ring| ring.poll(events, consume));
        let hup = if consume {
            self.pending_hup.swap(false, Ordering::Relaxed)
        } else {
            self.pending_hup.load(Ordering::Relaxed)
        };
        if hup {
            result.0 |= 16;
        }
        result.1[0] = result.1[0].wrapping_add(self.epoch.load(Ordering::Relaxed));
        result
    }
    /// Pair only original output objects, ordered by their stable allocation.
    /// The ring's mapping transaction serializes attachment with final unmap.
    pub(super) fn redirect(self: &Arc<Self>, target: Option<&Arc<Self>>) -> Result<()> {
        let assign = |own: &mut Weak<ring::Ring>, target: Option<&Weak<ring::Ring>>| {
            if self.owned.load(Ordering::Relaxed) != 0 {
                return Err(Errno(22));
            }
            if let Some(target) = target {
                let ring = target.upgrade().ok_or(Errno(22))?;
                ring.attach(self, own)
            } else {
                *own = Weak::new();
                self.buffer.store(0, Ordering::Relaxed);
                self.epoch.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        };
        let Some(target) = target else {
            return assign(&mut self.ring.lock(), None);
        };
        if Arc::ptr_eq(self, target) {
            return Err(Errno(22));
        }
        if Arc::as_ptr(self) < Arc::as_ptr(target) {
            let mut own = self.ring.lock();
            let into = target.ring.lock();
            assign(&mut own, Some(&into))
        } else {
            let into = target.ring.lock();
            let mut own = self.ring.lock();
            assign(&mut own, Some(&into))
        }
    }
}
impl Event {
    pub fn set_output(&self, target: Option<&Arc<Event>>) -> Result<u64> {
        if target.is_some_and(|target| {
            self.id == target.id || !self.clock.output_compatible(&target.clock)
        }) {
            return Err(Errno(22));
        }
        self.output.redirect(target.map(|target| &target.output))?;
        self.changed.notify_atomic();
        Ok(0)
    }
}
