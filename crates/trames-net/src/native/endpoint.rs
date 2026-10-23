// SPDX-License-Identifier: GPL-3.0-or-later
//! Actual host transport ownership, without namespace/path Rc projections.
use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

#[derive(Default)]
pub(super) struct Quota(AtomicUsize);
impl Quota {
    #[cfg(test)]
    pub(super) fn live(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
    pub(super) fn reserve(self: &Arc<Self>) -> Result<Reservation> {
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
pub(super) struct Reservation(Arc<Quota>);
impl Drop for Reservation {
    fn drop(&mut self) {
        self.0 .0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(super) struct Endpoint {
    // Drop the observer before the watched descriptor, then return its quota.
    // This entire lifetime can end on the executing worker.
    events: Mutex<Option<edge::Events>>,
    pub(super) socket: NativeSocket,
    _reservation: Reservation,
}
impl Endpoint {
    pub(super) fn new(native: RawNativeSocket, kind: u32, reservation: Reservation) -> Arc<Self> {
        Arc::new(Self {
            events: Mutex::default(),
            socket: if kind == 1 {
                NativeSocket::Tcp(native.into())
            } else {
                NativeSocket::Udp(native.into())
            },
            _reservation: reservation,
        })
    }
    pub(super) fn poll_epoch(&self) -> Option<[u64; 2]> {
        let mut events = self.events.lock().unwrap();
        if events.is_none() {
            *events = Some(edge::Events::new(self.as_fd().as_raw_fd())?);
        }
        Some(events.as_mut().unwrap().sample())
    }
}
impl std::ops::Deref for Endpoint {
    type Target = NativeSocket;
    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

/// An accepted connected-TCP operation may outlive its original FD/owner.
/// Capability snapshots never hold this lease. No owner-only control or guest
/// namespace authority is made Send by keeping the host transport alive.
#[derive(Clone)]
pub struct TcpLease(pub(super) Arc<Endpoint>);
impl TcpLease {
    /// Transfer the existing Arc to a host wait registry without allocating a
    /// wrapper or granting the registry socket/namespace control.
    pub fn into_keepalive(self) -> Arc<dyn Send + Sync> {
        self.0
    }
    /// Compare actual transport lifetime, independently of numeric guest FDs.
    pub fn shares_socket(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
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
