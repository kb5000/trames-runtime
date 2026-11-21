// SPDX-License-Identifier: GPL-3.0-or-later
//! Existing socket bounds, reserved before effects and released by actual leases.
use crate::{NetError, MAX_SOCKETS};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
type Result<T> = std::result::Result<T, NetError>;

/// Packet-stack endpoints are allocated on demand and do not reserve BSD descriptors.
pub const GUEST_SOCKET_LIMIT: usize = 1024;
pub(crate) struct Quota<const LIMIT: usize = MAX_SOCKETS> {
    live: AtomicUsize,
    limit: usize,
}
impl<const LIMIT: usize> Default for Quota<LIMIT> {
    fn default() -> Self {
        Self::with_limit(LIMIT)
    }
}
impl<const LIMIT: usize> Quota<LIMIT> {
    pub(crate) fn with_limit(limit: usize) -> Self {
        Self {
            live: AtomicUsize::new(0),
            limit,
        }
    }
    pub(crate) fn live(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }
    pub(crate) fn reserve(self: &Arc<Self>) -> Result<Reservation<LIMIT>> {
        // Accounting does not publish socket data. Reserve before host creation
        // or accept, and return the slot on every failure and final close.
        self.live
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < self.limit).then_some(n + 1)
            })
            .map_err(|_| NetError(24))?;
        Ok(Reservation(self.clone()))
    }
}
pub(crate) struct Reservation<const LIMIT: usize = MAX_SOCKETS>(Arc<Quota<LIMIT>>);
impl<const LIMIT: usize> Drop for Reservation<LIMIT> {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concurrent_reservations_obey_the_bound_and_release_on_the_worker() {
        let quota = Arc::new(Quota::<MAX_SOCKETS>::default());
        let ready = std::sync::Barrier::new(9);
        let release = std::sync::Barrier::new(9);
        std::thread::scope(|s| {
            for _ in 0..8 {
                let quota = &quota;
                let ready = &ready;
                let release = &release;
                s.spawn(move || {
                    let leases: Vec<_> = (0..16)
                        .filter_map(|_| match quota.reserve() {
                            Ok(lease) => Some(lease),
                            Err(e) => {
                                assert_eq!(e, NetError(24));
                                None
                            }
                        })
                        .collect();
                    ready.wait();
                    release.wait();
                    drop(leases);
                });
            }
            ready.wait();
            assert_eq!(quota.live(), MAX_SOCKETS);
            assert!(matches!(quota.reserve(), Err(NetError(24))));
            release.wait();
        });
        assert_eq!(quota.live(), 0);
        let slot = quota.reserve().unwrap();
        assert_eq!(quota.live(), 1);
        drop(slot);
        assert_eq!(quota.live(), 0);
    }
}
