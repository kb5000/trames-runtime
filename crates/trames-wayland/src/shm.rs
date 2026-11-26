// SPDX-License-Identifier: GPL-3.0-or-later
//! Retained native SHM imports. Only the original protocol client's parsing
//! pauses; its buffered messages/FDs and every other client keep their ownership.
use crate::{scene::BufferData, Compositor, ShmBuffer};
#[cfg(test)]
use std::os::fd::AsRawFd;
use std::{io, sync::Arc, time::Instant};
use trames_shared::{IoSignal, IoSubscription, ResourcePending, ResourceWait, SharedFile};
use wayland_server::{
    backend::{ClientId, DisconnectReason, Handle},
    protocol::{wl_buffer::WlBuffer, wl_shm_pool::WlShmPool},
    Client, Resource,
};

pub(crate) struct Import {
    pub id: u64,
    pub file: SharedFile,
    pub offset: usize,
    pub length: usize,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub alpha: bool,
}
impl Import {
    pub fn map(&self) -> io::Result<Arc<ShmBuffer>> {
        // SharedFile retains the original export's resource context. Neither
        // the compositor nor its wakeup callback acquires guest task authority.
        Ok(Arc::new(ShmBuffer {
            id: self.id,
            file: self.file.clone(),
            mapping: self.file.map(self.offset, self.length)?,
            width: self.width,
            height: self.height,
            stride: self.stride,
            alpha: self.alpha,
        }))
    }
}
pub(crate) struct Pending {
    request: Import,
    buffer: WlBuffer,
    pool: WlShmPool,
    client: ClientId,
    connection: u64,
    wait: Arc<dyn ResourceWait>,
    subscriptions: Vec<IoSubscription>,
}
impl Pending {
    pub fn new(
        request: Import,
        buffer: WlBuffer,
        pool: WlShmPool,
        client: &Client,
        wait: Arc<dyn ResourceWait>,
    ) -> Self {
        Self {
            request,
            buffer,
            pool,
            client: client.id(),
            connection: client
                .get_data::<crate::ClientIdentity>()
                .unwrap()
                .connection,
            wait,
            subscriptions: Vec::new(),
        }
    }
    fn subscribe(&mut self, signal: Option<&Arc<IoSignal>>) {
        self.subscriptions = signal.map_or_else(Vec::new, |signal| self.wait.subscribe(signal));
        // Subscribe before checking. A resource may become ready before the
        // original callback returns and the existing event loop goes to sleep.
        if self.wait.ready() {
            if let Some(signal) = signal {
                signal.notify();
            }
        }
    }
}
#[derive(Default)]
pub(crate) struct Imports {
    pending: Vec<Pending>,
    signal: Option<Arc<IoSignal>>,
}
impl Imports {
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
    pub fn set_signal(&mut self, signal: Arc<IoSignal>) {
        for pending in &mut self.pending {
            pending.subscribe(Some(&signal));
        }
        self.signal = Some(signal);
    }
    pub fn reset_signal(&self) {
        if let Some(signal) = &self.signal {
            signal.reset();
        }
    }
    pub fn defer(&mut self, handle: &Handle, mut pending: Pending) -> io::Result<()> {
        handle.set_client_dispatch_enabled(pending.client.clone(), false)?;
        pending.subscribe(self.signal.as_ref());
        self.pending.push(pending);
        Ok(())
    }
    pub fn progress(&mut self, handle: &Handle) -> Vec<ClientId> {
        let mut resumed = Vec::new();
        let mut retained = Vec::new();
        for mut pending in std::mem::take(&mut self.pending) {
            if handle.get_client_data(pending.client.clone()).is_err() {
                continue;
            }
            if !pending.wait.ready() {
                retained.push(pending);
                continue;
            }
            match pending.request.map() {
                Ok(pixels) => {
                    let data = pending
                        .buffer
                        .data::<BufferData>()
                        .expect("original SHM buffer");
                    assert!(data.pixels.set(pixels).is_ok(), "one original SHM import");
                }
                Err(error) => {
                    if let Some(wait) = ResourcePending::from_io(&error) {
                        pending.wait = wait;
                        pending.subscribe(self.signal.as_ref());
                        retained.push(pending);
                        continue;
                    }
                    pending
                        .pool
                        .post_error(1u32, "shared memory mapping failed");
                }
            }
            if handle
                .set_client_dispatch_enabled(pending.client.clone(), true)
                .is_err()
            {
                // A failed native registration retires this connection. Never
                // drop other suspended originals or leave this client parked.
                handle.kill_client(pending.client.clone(), DisconnectReason::ConnectionClosed);
            }
            resumed.push(pending.client);
        }
        self.pending = retained;
        resumed
    }
    pub fn deadline(&self) -> Option<Instant> {
        self.pending.iter().filter_map(|p| p.wait.deadline()).min()
    }
    pub fn retain_clients(&mut self, handle: &Handle) {
        self.pending
            .retain(|p| handle.get_client_data(p.client.clone()).is_ok());
    }
}

impl Compositor {
    fn shm_wait_sources(&self) -> impl Iterator<Item = (ClientId, libc::pollfd)> + '_ {
        // A suspended client is absent from the display's readable set. Watch
        // only peer close/error here, never its queued input (which must wait).
        self.state.shm.pending.iter().filter_map(|pending| {
            let socket = self.client_sockets.get(&pending.connection)?;
            let (fd, events) = socket.wait_fd().ok()?;
            Some((
                pending.client.clone(),
                libc::pollfd {
                    fd,
                    events,
                    revents: 0,
                },
            ))
        })
    }
    pub(crate) fn shm_wait_fds(&self) -> impl Iterator<Item = libc::pollfd> + '_ {
        self.shm_wait_sources().map(|(_, fd)| fd)
    }
    pub(crate) fn cancel_closed_shm(&mut self) {
        let closed: Vec<_> = self
            .state
            .shm
            .pending
            .iter()
            .filter_map(|pending| {
                let socket = self.client_sockets.get(&pending.connection)?;
                socket
                    .closed()
                    .unwrap_or(true)
                    .then(|| pending.client.clone())
            })
            .collect();
        let handle = self.display.handle().backend_handle();
        for client in closed {
            handle.kill_client(client.clone(), DisconnectReason::ConnectionClosed);
            // Run the backend's existing destruction/FD cleanup even though
            // this suspended connection has no readable registration anymore.
            let _ = self
                .display
                .backend()
                .dispatch_single_client(&mut self.state, client);
        }
        self.state.shm.retain_clients(&handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{scene::ImageBuffer, ClientIdentity};
    use std::{
        io::{Read, Write},
        os::{fd::AsFd, unix::net::UnixStream},
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed},
            Mutex,
        },
        time::Duration,
    };
    use trames_shared::{
        NativeSocket, Readiness, SharedFileAccess, SharedFileAccounting, SharedFileCharge,
    };

    #[derive(Default)]
    struct Wait {
        ready: AtomicBool,
        changed: Arc<Readiness>,
        deadline: Mutex<Option<Instant>>,
    }
    impl ResourceWait for Wait {
        fn ready(&self) -> bool {
            self.ready.load(Relaxed)
                || self
                    .deadline()
                    .is_some_and(|deadline| deadline <= Instant::now())
        }
        fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
            vec![self.changed.subscribe(signal)]
        }
        fn deadline(&self) -> Option<Instant> {
            *self.deadline.lock().unwrap()
        }
    }
    impl Wait {
        fn finish(&self) {
            self.ready.store(true, Relaxed);
            self.changed.notify_atomic();
        }
    }
    #[derive(Default)]
    struct Account {
        first: Arc<Wait>,
        second: Arc<Wait>,
        attempts: AtomicUsize,
        pins: Arc<AtomicUsize>,
        fail: AtomicBool,
    }
    struct Loan(Arc<AtomicUsize>);
    struct Pin(Arc<AtomicUsize>);
    impl Drop for Pin {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Relaxed);
        }
    }
    impl SharedFileCharge for Loan {
        fn changed(&self) -> bool {
            true
        }
        fn commit(self: Box<Self>, _: usize) -> Arc<dyn Send + Sync> {
            self.0.fetch_add(1, Relaxed);
            Arc::new(Pin(self.0.clone()))
        }
    }
    impl SharedFileAccounting for Account {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
        fn reserve(
            &self,
            _: usize,
            _: usize,
            access: SharedFileAccess,
        ) -> io::Result<Box<dyn SharedFileCharge>> {
            assert!(access == SharedFileAccess::Map);
            self.attempts.fetch_add(1, Relaxed);
            for wait in [&self.first, &self.second] {
                if !wait.ready() {
                    return Err(ResourcePending::io_error(wait.clone()));
                }
            }
            if self.fail.load(Relaxed) {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            Ok(Box::new(Loan(self.pins.clone())))
        }
        fn truncate(&self, _: usize) {}
    }
    #[derive(Default)]
    struct Wake(AtomicUsize);
    impl trames_shared::IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {
            self.0.fetch_add(1, Relaxed);
        }
    }
    fn message(id: u32, opcode: u32, words: &[u32]) -> Vec<u8> {
        [id, (((words.len() + 2) * 4) as u32) << 16 | opcode]
            .into_iter()
            .chain(words.iter().copied())
            .flat_map(u32::to_ne_bytes)
            .collect()
    }
    fn bind(global: u32, interface: &str, version: u32, id: u32) -> Vec<u8> {
        let mut string = interface.as_bytes().to_vec();
        string.push(0);
        let mut words = vec![global, string.len() as u32];
        string.resize(string.len().next_multiple_of(4), 0);
        words.extend(
            string
                .chunks_exact(4)
                .map(|b| u32::from_ne_bytes(b.try_into().unwrap())),
        );
        words.extend([version, id]);
        message(2, 0, &words)
    }
    fn read(client: &mut UnixStream) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut chunk = [0; 4096];
        loop {
            match client.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => bytes.extend_from_slice(&chunk[..n]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                    ) =>
                {
                    break
                }
                Err(error) => panic!("native protocol read: {error}"),
            }
        }
        bytes
    }
    fn callback_received(bytes: &[u8], callback: u32) -> bool {
        let mut cursor = 0;
        while cursor < bytes.len() {
            let id = u32::from_ne_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
            let header = u32::from_ne_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap());
            let size = (header >> 16) as usize;
            assert!(size >= 8 && cursor + size <= bytes.len());
            if id == callback && header & 0xffff == 0 {
                return true;
            }
            cursor += size;
        }
        false
    }
    fn connect(compositor: &mut Compositor, connection: u64) -> UnixStream {
        let (client, socket) = UnixStream::pair().unwrap();
        client.set_nonblocking(true).unwrap();
        compositor
            .connect(
                socket,
                ClientIdentity {
                    connection,
                    pid: 7,
                    uid: 0,
                    gid: 0,
                },
            )
            .unwrap();
        client
    }
    fn setup(compositor: &mut Compositor) -> UnixStream {
        let mut client = connect(compositor, 42);
        client.write_all(&message(1, 1, &[2])).unwrap();
        compositor.dispatch().unwrap();
        assert!(!read(&mut client).is_empty());
        client
            .write_all(&[bind(2, "wl_shm", 1, 3), bind(1, "wl_compositor", 6, 4)].concat())
            .unwrap();
        compositor.dispatch().unwrap();
        assert!(!read(&mut client).is_empty());
        client
    }
    fn send_import(compositor: &mut Compositor, client: &UnixStream, account: &Arc<Account>) {
        let file = SharedFile::anonymous().unwrap();
        file.set_len(4096).unwrap();
        file.write_at(16, &[1, 2, 3, 4]).unwrap();
        file.set_accounting(account.clone()).unwrap();
        let next_file = SharedFile::anonymous().unwrap();
        next_file.set_len(4096).unwrap();
        let (first, first_lease) = file.export().unwrap();
        let (second, second_lease) = next_file.export().unwrap();
        let stream = NativeSocket::from(client.try_clone().unwrap());
        // A second FD is already in the original transport when the first
        // buffer map suspends it. Its CreatePool must not be parsed early.
        let bytes = [
            message(3, 0, &[5, 4096]),
            message(5, 0, &[6, 16, 1, 1, 4, 1]),
            message(4, 0, &[7]),
            message(7, 1, &[6, 0, 0]),
            message(7, 6, &[]),
            message(1, 0, &[8]),
            message(3, 0, &[9, 4096]),
        ]
        .concat();
        assert_eq!(
            stream.send_msg(&bytes, &[first, second]).unwrap(),
            bytes.len()
        );
        compositor.retain_exports(42, vec![first_lease, second_lease]);
    }

    #[test]
    fn original_import_preserves_buffered_fds_and_surface_commit_without_blocking_other_clients() {
        let mut compositor = Compositor::new().unwrap();
        let mut client = setup(&mut compositor);
        let account = Arc::new(Account::default());
        let wake = Arc::new(Wake::default());
        let target: Arc<dyn trames_shared::IoWake> = wake.clone();
        compositor
            .state
            .shm
            .set_signal(IoSignal::new(0, Arc::downgrade(&target)));
        send_import(&mut compositor, &client, &account);
        compositor.dispatch().unwrap();
        assert_eq!(account.attempts.load(Relaxed), 1);
        assert_eq!(compositor.state.shm.pending.len(), 1);
        assert!(compositor.state.surfaces.is_empty());
        assert!(read(&mut client).is_empty());
        assert_eq!(
            compositor.exports.len(),
            1,
            "the second FD is still unconsumed"
        );
        let mut display = libc::pollfd {
            fd: compositor.display.as_fd().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: a retained display descriptor and one initialized poll entry.
        assert_eq!(
            unsafe { libc::poll(&mut display, 1, 0) },
            0,
            "suspended input must not spin the display poller"
        );
        let mut other = connect(&mut compositor, 43);
        other.write_all(&message(1, 0, &[2])).unwrap();
        compositor.dispatch().unwrap();
        assert_eq!(&read(&mut other)[..4], &2u32.to_ne_bytes());
        assert!(read(&mut client).is_empty());
        assert_eq!(
            account.attempts.load(Relaxed),
            1,
            "a nonready map is not retried"
        );

        account.first.finish();
        assert_eq!(wake.0.load(Relaxed), 1);
        assert_eq!(
            account.attempts.load(Relaxed),
            1,
            "the notification does no mapping"
        );
        compositor.dispatch().unwrap();
        assert_eq!(account.attempts.load(Relaxed), 2);
        assert!(compositor.state.surfaces.is_empty());
        assert!(read(&mut client).is_empty());
        let deadline = Instant::now() + Duration::from_secs(10);
        *account.second.deadline.lock().unwrap() = Some(deadline);
        assert_eq!(compositor.state.shm.deadline(), Some(deadline));
        // A changed deadline is read from the original resource, with no
        // completion notification and no retry of already completed stages.
        *account.second.deadline.lock().unwrap() = Some(Instant::now());
        compositor.dispatch().unwrap();
        assert_eq!(account.attempts.load(Relaxed), 3);
        assert!(callback_received(&read(&mut client), 8));
        assert!(compositor.state.shm.pending.is_empty());
        assert!(
            compositor.exports.is_empty(),
            "the original buffered second FD was imported"
        );
        let surface = compositor.state.surfaces.values().next().unwrap();
        let Some(ImageBuffer::Shm(lease)) = &surface.current else {
            panic!("original commit was lost")
        };
        assert_eq!(
            (lease.pixels.width, lease.pixels.height, lease.pixels.stride),
            (1, 1, 4)
        );
        // SAFETY: the test client has stopped writing its original buffer.
        assert_eq!(
            unsafe { lease.pixels.mapping.with_read(0, 4, |bytes| bytes.to_vec()) },
            [1, 2, 3, 4]
        );
        assert_eq!(account.pins.load(Relaxed), 1);
        drop(compositor);
        assert_eq!(account.pins.load(Relaxed), 0);
    }

    #[test]
    fn disconnect_cancels_a_nonready_import_and_its_buffered_fd_without_retry() {
        let mut compositor = Compositor::new().unwrap();
        let client = setup(&mut compositor);
        let account = Arc::new(Account::default());
        send_import(&mut compositor, &client, &account);
        compositor.dispatch().unwrap();
        assert_eq!(compositor.state.shm.pending.len(), 1);
        drop(client);
        compositor.dispatch().unwrap();
        assert!(compositor.state.shm.pending.is_empty());
        assert!(compositor.clients.is_empty());
        assert!(compositor.client_sockets.is_empty());
        assert!(compositor.exports.is_empty());
        assert_eq!(account.attempts.load(Relaxed), 1);
        assert_eq!(account.pins.load(Relaxed), 0);
    }

    #[test]
    fn terminal_mapping_error_disconnects_only_its_original_client() {
        let mut compositor = Compositor::new().unwrap();
        let mut client = setup(&mut compositor);
        let account = Arc::new(Account::default());
        send_import(&mut compositor, &client, &account);
        compositor.dispatch().unwrap();
        let mut other = connect(&mut compositor, 43);
        account.fail.store(true, Relaxed);
        account.first.finish();
        account.second.finish();
        compositor.dispatch().unwrap();
        let bytes = read(&mut client);
        assert_eq!(&bytes[..4], &1u32.to_ne_bytes());
        assert!(bytes
            .windows(28)
            .any(|s| s == b"shared memory mapping failed"));
        assert!(compositor.state.shm.pending.is_empty());
        assert!(!compositor.clients.contains_key(&42));
        other.write_all(&message(1, 0, &[2])).unwrap();
        compositor.dispatch().unwrap();
        assert_eq!(&read(&mut other)[..4], &2u32.to_ne_bytes());
        assert_eq!(account.attempts.load(Relaxed), 2);
        assert_eq!(account.pins.load(Relaxed), 0);
    }
}
