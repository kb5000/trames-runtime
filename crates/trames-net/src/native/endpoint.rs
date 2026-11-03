// SPDX-License-Identifier: GPL-3.0-or-later
//! Actual host transport ownership, without namespace/path Arc projections.
use super::*;
use crate::socket_quota::Reservation;
use std::sync::Mutex;

pub(super) struct Endpoint {
    // Drop the observer before the watched descriptor, then return its quota.
    // This entire lifetime can end on the executing worker.
    events: Mutex<Option<edge::Events>>,
    pub(super) socket: NativeSocket,
    pub(super) state: state::State,
    pub(super) completion: Mutex<()>,
    pub(super) keepalive: Mutex<()>,
    _reservation: Reservation,
}
impl Endpoint {
    pub(super) fn poll_event_fd(&self) -> io::Result<std::os::fd::OwnedFd> {
        let mut events = self.events.lock().unwrap();
        if events.is_none() {
            *events = Some(
                edge::Events::new(self.as_fd().as_raw_fd())
                    .ok_or_else(|| io::Error::other("native edge observer unavailable"))?,
            );
        }
        events.as_ref().unwrap().duplicate()
    }
    pub(super) fn new(
        native: RawNativeSocket,
        kind: u32,
        reservation: Reservation,
        connection: Connection,
    ) -> Arc<Self> {
        Arc::new(Self {
            events: Mutex::default(),
            state: state::State::new(connection),
            completion: Mutex::default(),
            keepalive: Mutex::default(),
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

/// An accepted connected-TCP operation retains its original shared socket,
/// including live namespace policy, across close/reuse and parked retries.
/// Capability/poll snapshots stay weak; no owner-only projection is retained.
#[derive(Clone)]
pub struct TcpLease(pub(super) Arc<Socket>);
impl TcpLease {
    /// Transfer the existing Arc to a host wait registry without allocating a
    /// wrapper or granting the registry socket/namespace control.
    pub fn into_keepalive(self) -> Arc<dyn Send + Sync> {
        self.0
    }
    /// Compare actual transport lifetime, independently of numeric guest FDs.
    pub fn shares_socket(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0.native, &other.0.native)
    }
}
