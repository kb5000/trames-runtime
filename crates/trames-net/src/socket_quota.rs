// SPDX-License-Identifier: GPL-3.0-or-later
//! Existing socket bounds, reserved before effects and released by actual leases.
use crate::{NetError, MAX_SOCKETS};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
type Result<T> = std::result::Result<T, NetError>;

#[derive(Default)]
pub(crate) struct Quota(AtomicUsize);
impl Quota {
    pub(crate) fn live(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
    pub(crate) fn reserve(self: &Arc<Self>) -> Result<Reservation> {
        // Accounting does not publish socket data. Reserve before host creation
        // or accept, and return the slot on every failure and final close.
        self.0
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < MAX_SOCKETS).then_some(n + 1)
            })
            .map_err(|_| NetError(24))?;
        Ok(Reservation(self.clone()))
    }
}
pub(crate) struct Reservation(Arc<Quota>);
impl Drop for Reservation {
    fn drop(&mut self) {
        self.0 .0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concurrent_reservations_obey_the_bound_and_release_on_the_worker() {
        let quota = Arc::new(Quota::default());
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
