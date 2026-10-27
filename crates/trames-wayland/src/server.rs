// SPDX-License-Identifier: GPL-3.0-or-later
//! A native event loop independent of guest scheduling and UIKit's main thread.
use crate::*;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    os::fd::{AsFd, AsRawFd},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc, Mutex,
    },
    thread,
};

#[derive(Clone, Default)]
pub struct Snapshot {
    pub revision: u64,
    pub text: Option<TextContext>,
    pub windows: Vec<WindowSnapshot>,
    /// Connection-scoped protocol IDs, never guest pointers or host layer IDs.
    pub surfaces: BTreeMap<(u64, u32), SurfaceInfo>,
    /// Live shared-inode capabilities delivered through the actual protocol
    /// connection, including transparent byte/SCM_RIGHTS relays.
    pub wsi_connections: BTreeMap<(u64, u64), crate::WsiConnection>,
}
#[derive(Clone, Debug)]
pub struct SurfaceInfo {
    pub id: u64,
    pub width: u32,
    pub height: u32,
    pub scale: i32,
    pub configured: bool,
    pub owner: Arc<AtomicU64>,
    pub gpu_budget: GpuBudget,
}
enum Command {
    Connect(UnixStream, ClientIdentity),
    ConnectXwm(UnixStream, crate::xwm::Identity),
    Resize(u64, u32, u32),
    Mode(u64, WindowMode),
    Close(u64),
    Presented(u64, u64, u32),
    Input(InputEvent),
    Text(TextEdit),
    Gpu(u64, Arc<dyn GpuImage>),
    Exports(u64, Vec<trames_shared::ExportLease>),
    HostClipboard(Arc<dyn HostClipboard>),
    ClipboardChanged,
    Stop,
}
struct Control {
    sender: mpsc::SyncSender<Command>,
    wake: UnixStream,
    snapshot: Arc<Mutex<Snapshot>>,
    changes: Arc<trames_shared::Readiness>,
    next: AtomicU64,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}
impl Control {
    fn send(&self, command: Command) -> io::Result<()> {
        self.sender.try_send(command).map_err(|e| match e {
            mpsc::TrySendError::Full(_) => io::Error::from(io::ErrorKind::WouldBlock),
            mpsc::TrySendError::Disconnected(_) => io::Error::from(io::ErrorKind::BrokenPipe),
        })?;
        match (&self.wake).write(&[1]) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        // Teardown is outside GPU/frame callbacks and holds no guest byte guard.
        let _ = self.sender.send(Command::Stop);
        let _ = (&self.wake).write(&[1]);
        if let Some(worker) = self.worker.get_mut().ok().and_then(Option::take) {
            let _ = worker.join();
        }
    }
}
#[derive(Clone)]
pub struct Server(Arc<Control>);
impl Server {
    /// Paired with Xwayland's -wm descriptor by the guest launcher. The VFS
    /// supplies credentials; the native XWM never opens a guest path itself.
    pub fn connect_xwm(&self, pid: u32, uid: u32, gid: u32) -> io::Result<UnixStream> {
        let (guest, native) = UnixStream::pair()?;
        guest.set_nonblocking(true)?;
        self.0.send(Command::ConnectXwm(native, (pid, uid, gid)))?;
        Ok(guest)
    }
    pub fn new() -> io::Result<Self> {
        let compositor = Compositor::new()?;
        let (wake, read) = UnixStream::pair()?;
        wake.set_nonblocking(true)?;
        read.set_nonblocking(true)?;
        let (sender, receiver) = mpsc::sync_channel(1024);
        let snapshot = Arc::new(Mutex::new(Snapshot::default()));
        let output = snapshot.clone();
        let changes = Arc::new(trames_shared::Readiness::default());
        let notifications = changes.clone();
        let worker = thread::Builder::new()
            .name("trames-wayland".into())
            .spawn(move || run(compositor, read, receiver, output, notifications))?;
        Ok(Self(Arc::new(Control {
            sender,
            wake,
            snapshot,
            changes,
            next: AtomicU64::new(1),
            worker: Mutex::new(Some(worker)),
        })))
    }
    /// The guest VFS retains this socket; native peer credentials are not used.
    pub fn connect(&self, pid: u32, uid: u32, gid: u32) -> io::Result<(u64, UnixStream)> {
        let (guest, server) = UnixStream::pair()?;
        guest.set_nonblocking(true)?;
        #[cfg(target_vendor = "apple")]
        {
            let enabled = 1i32;
            // SAFETY: a live owned Unix socket and a scoped i32 option value.
            // C client peers on Darwin use SO_NOSIGPIPE instead of MSG_NOSIGNAL.
            if unsafe {
                libc::setsockopt(
                    guest.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    (&enabled as *const i32).cast(),
                    std::mem::size_of_val(&enabled) as libc::socklen_t,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        let connection = self.0.next.fetch_add(1, Ordering::Relaxed);
        self.0.send(Command::Connect(
            server,
            ClientIdentity {
                connection,
                pid,
                uid,
                gid,
            },
        ))?;
        Ok((connection, guest))
    }
    pub fn attach_clipboard(&self, host: Arc<dyn HostClipboard>) -> io::Result<()> {
        self.0.send(Command::HostClipboard(host))
    }
    pub fn clipboard_changed(&self) -> io::Result<()> {
        self.0.send(Command::ClipboardChanged)
    }
    /// Subscribe before reading snapshot, then reset the coalesced signal before
    /// each retry. Notifications run after publication and outside snapshot locks.
    pub fn subscribe(
        &self,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> trames_shared::IoSubscription {
        self.0.changes.subscribe(signal)
    }
    pub fn snapshot(&self) -> Snapshot {
        self.0
            .snapshot
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default()
    }
    pub fn resize(&self, id: u64, w: u32, h: u32) -> io::Result<()> {
        self.0.send(Command::Resize(id, w, h))
    }
    pub fn set_mode(&self, id: u64, mode: WindowMode) -> io::Result<()> {
        self.0.send(Command::Mode(id, mode))
    }
    pub fn input(&self, event: InputEvent) -> io::Result<()> {
        self.0.send(Command::Input(event))
    }
    pub fn edit_text(&self, edit: TextEdit) -> io::Result<()> {
        self.0.send(Command::Text(edit))
    }
    pub fn retain_exports(
        &self,
        connection: u64,
        leases: Vec<trames_shared::ExportLease>,
    ) -> io::Result<()> {
        self.0.send(Command::Exports(connection, leases))
    }
    pub fn present_gpu(&self, surface: u64, image: Arc<dyn GpuImage>) -> io::Result<()> {
        self.0.send(Command::Gpu(surface, image))
    }
    pub fn close(&self, id: u64) -> io::Result<()> {
        self.0.send(Command::Close(id))
    }
    pub fn presented(&self, window: u64, revision: u64, milliseconds: u32) -> io::Result<()> {
        self.0
            .send(Command::Presented(window, revision, milliseconds))
    }
}
fn run(
    mut compositor: Compositor,
    mut wake: UnixStream,
    receiver: mpsc::Receiver<Command>,
    output: Arc<Mutex<Snapshot>>,
    changes: Arc<trames_shared::Readiness>,
) {
    let mut stopped = false;
    let mut published = u64::MAX;
    while !stopped {
        while let Ok(command) = receiver.try_recv() {
            match command {
                Command::ConnectXwm(socket, key) => {
                    if compositor.state.xwayland.managers.len() < 4
                        && !compositor.state.xwayland.managers.contains_key(&key)
                    {
                        if let Ok(wm) = crate::xwm::Manager::new(socket) {
                            if let Ok(mut allowed) = compositor.state.xwayland.authorized.lock() {
                                allowed.insert(key);
                            }
                            compositor.state.xwayland.managers.insert(key, wm);
                            compositor.state.xclipboard_sync();
                        }
                    }
                }
                Command::Connect(stream, identity) => {
                    let _ = compositor.connect(stream, identity);
                }
                Command::Resize(id, w, h) => {
                    compositor.resize(id, w, h);
                }
                Command::Mode(id, mode) => compositor.set_mode(id, mode),
                Command::Close(id) => compositor.close(id),
                Command::Presented(id, revision, time) => compositor.presented(id, revision, time),
                Command::Input(event) => compositor.state.input(event),
                Command::Text(edit) => compositor.state.text_edit(edit),
                Command::Gpu(id, image) => compositor.state.enqueue_gpu(id, image),
                Command::Exports(connection, leases) => {
                    compositor.retain_exports(connection, leases)
                }
                Command::HostClipboard(host) => {
                    compositor.state.selection.host = Some(host);
                    compositor.state.selection_focus_changed();
                    compositor.state.xclipboard_sync();
                }
                Command::ClipboardChanged => compositor.state.host_clipboard_changed(),
                Command::Stop => stopped = true,
            }
        }
        if stopped {
            break;
        }
        // A deferred callback belongs to an already displayed commit. It must
        // progress even when UIKit has paused drawing an unchanged texture.
        if compositor.dispatch().is_err() {
            break;
        }
        let callback_timeout = compositor.callback_timeout;
        let waiting_for_gpu = compositor.state.poll_gpu();
        if compositor.state.revision != published {
            let surfaces = compositor
                .state
                .surfaces
                .iter()
                .map(|(&id, s)| {
                    (
                        (s.connection, s.resource.id().protocol_id()),
                        SurfaceInfo {
                            id,
                            width: s.size.0,
                            height: s.size.1,
                            scale: s.scale,
                            configured: s.acknowledged,
                            owner: s.gpu_owner.clone(),
                            gpu_budget: s.gpu_budget.clone(),
                        },
                    )
                })
                .collect();
            let snapshot = Snapshot {
                revision: compositor.state.revision,
                windows: compositor.windows(),
                text: compositor.state.text_context(),
                surfaces,
                wsi_connections: compositor.state.wsi.connections(),
            };
            published = snapshot.revision;
            if let Ok(mut output) = output.lock() {
                *output = snapshot;
            }
            changes.notify_locked();
        }
        let mut fds = [
            libc::pollfd {
                fd: compositor.display.as_fd().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: two live native descriptors and a fixed initialized array.
        // A producer wakeup can precede fence completion. Sleeping a full 16ms
        // then misses a display refresh even when rendering itself was fast.
        // Keep the idle/backpressure timeout; only retry pending fences at 1ms.
        let mut timeout = if waiting_for_gpu { 1 } else { 16 };
        if let Some(left) = callback_timeout {
            timeout = timeout.min(left.as_millis().saturating_add(1).min(16) as i32);
        }
        let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            break;
        }
        let mut bytes = [0; 256];
        loop {
            match wake.read(&mut bytes) {
                Ok(0) => {
                    stopped = true;
                    break;
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    }
}
