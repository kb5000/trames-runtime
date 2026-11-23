// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest FUSE device endpoints and their daemon transport.
use super::*;
use std::sync::OnceLock;

mod mount;
pub(crate) use mount::{option_fd, prepare, File, Metadata, Mounted, PathOperation};
mod control;
pub(super) use control::{Abort, Controller};
mod transport;
pub use transport::{Caller, Connection, Request};

/// Only attached daemon file descriptions hold this reference. Outstanding
/// filesystem requests must wake up when the final daemon closes its device.
struct Daemon {
    connection: Arc<Connection>,
    mounted: std::sync::Weak<Mounted>,
}
impl Drop for Daemon {
    fn drop(&mut self) {
        self.connection.abort();
    }
}
pub struct Device {
    namespace: UserNamespace,
    daemon: OnceLock<Arc<Daemon>>,
    attached: Arc<Readiness>,
    relay: OnceLock<(Arc<IoSignal>, IoSubscription)>,
    reserved: std::sync::atomic::AtomicBool,
}
impl Device {
    pub(super) fn new(namespace: UserNamespace) -> Arc<Self> {
        Arc::new(Self {
            namespace,
            daemon: OnceLock::new(),
            attached: Arc::default(),
            relay: OnceLock::new(),
            reserved: Default::default(),
        })
    }
    fn reserve(&self) -> Result<()> {
        self.reserved
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| Errno(16))
    }
    fn install(self: &Arc<Self>, daemon: Arc<Daemon>) {
        let target: Arc<dyn IoWake> = self.clone();
        let wake = IoSignal::new(0, Arc::downgrade(&target));
        let sub = daemon.connection.subscribe(&wake);
        assert!(self.relay.set((wake, sub)).is_ok());
        assert!(self.daemon.set(daemon).is_ok());
        self.attached.notify_atomic();
    }
    #[cfg(test)]
    fn connect(self: &Arc<Self>, caller: Caller) -> Result<Arc<Connection>> {
        self.reserve()?;
        let connection = Connection::new(caller);
        self.install(Arc::new(Daemon {
            connection: connection.clone(),
            mounted: Default::default(),
        }));
        Ok(connection)
    }
    pub(super) fn attach_clone(self: &Arc<Self>, original: &Self) -> Result<()> {
        if self.daemon.get().is_some() || self.namespace != original.namespace {
            return Err(Errno(22));
        }
        let daemon = original.daemon.get().ok_or(Errno(22))?.clone();
        self.reserve().map_err(|_| Errno(22))?;
        self.install(daemon);
        Ok(())
    }
    pub(super) fn connection(&self) -> Result<&Connection> {
        self.daemon
            .get()
            .map(|d| d.connection.as_ref())
            .ok_or(Errno(1))
    }
    pub(super) fn poll(&self, events: u16) -> (u16, [u64; 2]) {
        self.connection().map_or((8, [0; 2]), |c| c.poll(events))
    }
    pub(super) fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.attached.subscribe(signal)
    }
}
impl IoWake for Device {
    fn wake_io(&self, signal: &Arc<IoSignal>) {
        signal.reset();
        self.attached.notify_atomic();
    }
}
impl Vfs {
    pub fn fuse_device(&self, fd: u32) -> Result<Option<Arc<Device>>> {
        let desc = self.descriptor(fd)?;
        let open = desc.open.borrow();
        Ok(match &open.control {
            Some(events::SharedControl::Fuse(device)) => Some(device.clone()),
            _ => None,
        })
    }
}

pub const CLONE: u32 = 0x8004_e500;
impl Vfs {
    pub fn fuse_clone(
        &self,
        fd: u32,
        address: u64,
        memory: &impl trames_memory::CpuMemory,
    ) -> Result<u64> {
        let descriptor = self.descriptor(fd)?;
        let open = descriptor.open.borrow();
        open.check_device_ioctl(CLONE)?;
        let Some(events::SharedControl::Fuse(to)) = &open.control else {
            return Err(Errno(25));
        };
        let to = to.clone();
        drop(open);
        let source = u32::from_le_bytes(memory.read_array(address).map_err(|_| Errno(14))?);
        let from = self.fuse_device(source)?.ok_or(Errno(22))?;
        to.attach_clone(&from)?;
        Ok(0)
    }
}

#[cfg(test)]
mod tests;
