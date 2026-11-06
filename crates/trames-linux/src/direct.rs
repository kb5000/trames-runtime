// SPDX-License-Identifier: GPL-3.0-or-later
//! Worker-local syscalls on retained shared resources. All byte ABI helpers are
//! the original Linux implementations; only resource ownership differs.
use crate::state::Linux;
use std::cell::{Cell, RefCell};
use std::{
    sync::{Arc, Weak},
    time::{Duration, Instant},
};
use trames_memory::{Access, CpuMemory};
use trames_vfs::{DirectFds, Errno};
use trames_vfs::{IoSignal, IoSubscription, IoWake};
mod aio;
pub(crate) mod file;
pub use aio::{Aio, RetainedAio};
mod ip_message;
mod local_message;
pub(crate) mod namespace;
#[cfg(test)]
mod netlink;
pub(crate) mod signal_read;
mod socket_wait;
pub use file::{FileBoundary, FileCheckpoint, FileExecutor, FileOutput, FilePending, FileResult};
pub(crate) mod uring;
pub use socket_wait::RetainedSocket;
pub use uring::{
    UringActor, UringBackground, UringEnter, UringEpoch, UringFileLayout, UringSnapshot,
};

fn tcp_wait_fd(tcp: &trames_net::DirectTcp) -> std::io::Result<trames_vfs::HostFd> {
    let (fd, lease) = tcp.readiness_fd()?;
    Ok(trames_vfs::HostFd::retained(fd, lease.into_keepalive()))
}

/// A stopped syscall, not a re-executed SVC. Subscriptions do not retain guest
/// FD table entries or count as additional pipe endpoints.
pub struct PendingIo {
    pub aio: Option<RetainedAio>,
    pub number: u32,
    pub args: [u64; 6],
    pub deadline: Option<Instant>,
    pub signal: Arc<IoSignal>,
    pub flock: Option<trames_vfs::FlockRequest>,
    pub retained_byte: Option<RetainedByte>,
    pub retained_socket: Option<RetainedSocket>,
    // Cohort-local accepted TCP authority. Joined policy/signal transitions
    // keep their original owner restart path, rather than exporting this lease.
    native_tcp: Option<trames_vfs::DirectTcpFd>,
    resource_deadline: Option<Instant>,
    pub retained_poll: Option<Arc<crate::RetainedWait>>,
    epoll_revision: Option<u64>,
    _subscriptions: Vec<IoSubscription>,
    host_subscription: Option<trames_vfs::HostSubscription>,
    socket_subscriptions: Vec<trames_vfs::HostSubscription>,
    uring: Option<Box<uring::Wait>>,
    poll_uring: Option<Box<uring::PollWait>>,
    target: Weak<dyn IoWake>,
    file: Option<FilePending>,
}
/// Authority accepted for one byte syscall. The complete OFD lease, rather
/// than its numeric table slot or a copied pipe counter, owns the endpoint.
#[derive(Clone)]
pub struct RetainedByte {
    fd: trames_vfs::DirectFd,
    operation: ByteOperation,
}
#[derive(Clone)]
enum ByteOperation {
    Plain,
    Message(Arc<local_message::AcceptedMessage>),
    Signal(Arc<signal_read::SignalRead>),
}
impl RetainedByte {
    fn message(&self) -> Option<&Arc<local_message::AcceptedMessage>> {
        if let ByteOperation::Message(m) = &self.operation {
            Some(m)
        } else {
            None
        }
    }
    pub fn is_unix(&self) -> bool {
        self.fd.is_unix()
    }
    pub fn pty_endpoint(&self) -> Option<(Arc<trames_vfs::PtyEnd>, u32)> {
        self.fd.retained_pty()
    }
    pub fn local_owner_identity(&self) -> Option<trames_vfs::OfdIdentity> {
        self.message().map(|_| self.fd.ofd_identity())
    }
    pub fn local_owner(&self) -> Option<trames_vfs::RetainedFd> {
        self.message()?;
        Some(self.fd.shared_file()?.retained())
    }
    pub fn shares_resources(&self, fds: &DirectFds) -> bool {
        fds.shares_with(std::iter::once(&self.fd))
            || self
                .datagram_target()
                .is_some_and(|target| target.shares_resources(fds))
            || self.batch_shares_resources(fds)
    }
}
impl PendingIo {
    /// Passive original-socket lifetime across a cohort handoff. Accepted TCP
    /// retries observe that socket's live policy, independently of numeric reuse.
    pub fn tcp_liveness(&self) -> Option<trames_net::TcpLease> {
        self.native_tcp
            .as_ref()
            .map(|fd| fd.tcp.retain().expect("accepted TCP transport"))
    }
    pub fn native_wait_fds(&self) -> Vec<trames_vfs::HostFd> {
        let mut fds = self
            .retained_byte
            .as_ref()
            .map_or_else(Vec::new, |file| file.fd.native_wait_fds());
        if let Some(file) = &self.file {
            fds.extend(file.native_wait_fds());
        }
        fds
    }
    pub fn notification_external(&self) -> bool {
        // Native file jobs notify the existing source target directly. Joined
        // execution must park on that notification, rather than sleep/poll.
        self.file.as_ref().is_some_and(|p| !p.interruptible())
            || self
                ._subscriptions
                .iter()
                .any(|s| s.notification_external())
    }
    pub fn file_pending(&self) -> Option<FilePending> {
        self.file.clone()
    }
    pub fn external_wait(&self) -> bool {
        if self.file.as_ref().is_some_and(|p| !p.interruptible())
            || DirectSyscalls::aio_call(self.number)
        {
            return true;
        }
        self.retained_socket
            .as_ref()
            .is_some_and(RetainedSocket::external_wait)
            || self.host_subscription.is_some()
            || !self.socket_subscriptions.is_empty()
            || self
                .file
                .as_ref()
                .is_some_and(|file| !file.native_wait_fds().is_empty())
            || self._subscriptions.iter().any(|s| s.external())
            || self.uring.as_ref().is_some_and(|w| w.external())
            || self.poll_uring.as_ref().is_some_and(|w| w.external())
    }
    pub fn wake_deadline(&self) -> Option<Instant> {
        [self.deadline, self.resource_deadline]
            .into_iter()
            .flatten()
            .min()
    }
}
// Ready attempts must remain allocation-free. A parked PendingIo moves into an
// existing boxed task/job; boxing this variant would add a separate wait allocation.
#[allow(clippy::large_enum_variant)]
pub enum IoAttempt {
    WaitCheckpoint(Arc<crate::RetainedWait>),
    Complete(Result<u64, Errno>),
    Blocked(PendingIo),
    Checkpoint,
    SocketCheckpoint(RetainedSocket),
    ByteCheckpoint(RetainedByte),
    FileCheckpoint(FileCheckpoint),
}
/// Shared epoll ABI for both joined and worker-local implementations.
pub fn epoll_parameters(
    memory: &impl CpuMemory,
    number: u32,
    a: [u64; 6],
) -> Result<Option<Duration>, Errno> {
    epoll_buffer(memory, a)?;
    if number == 441 {
        if a[3] == 0 {
            return Ok(None);
        }
        let bytes = memory.read_array::<16>(a[3]).map_err(|_| Errno(14))?;
        let sec = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let ns = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        if sec > i64::MAX as u64 || ns >= 1_000_000_000 {
            return Err(Errno(22));
        }
        Ok(Some(Duration::new(sec, ns as u32)))
    } else {
        let ms = a[3] as i32;
        Ok((ms >= 0).then(|| Duration::from_millis(ms as u64)))
    }
}
pub(crate) fn epoll_buffer(memory: &impl CpuMemory, a: [u64; 6]) -> Result<(), Errno> {
    if a[2] == 0 || a[2] > (crate::MAX_WRITE / 16) as u64 {
        return Err(Errno(22));
    }
    Linux::check(memory, a[1], a[2] as usize * 16, Access::Write)
}
pub fn epoll_scatter(
    memory: &mut impl CpuMemory,
    address: u64,
    events: &[(u32, u64)],
) -> Result<u64, Errno> {
    for (i, (events, data)) in events.iter().enumerate() {
        let mut bytes = [0; 16];
        bytes[..4].copy_from_slice(&events.to_le_bytes());
        bytes[8..].copy_from_slice(&data.to_le_bytes());
        memory
            .write_array(address + i as u64 * 16, bytes)
            .map_err(|_| Errno(14))?;
    }
    Ok(events.len() as u64)
}

#[derive(Default)]
pub struct DirectSyscalls {
    signal_reader: Option<Arc<dyn trames_vfs::SignalReader>>,
    task_signal: Option<Arc<dyn trames_vfs::TaskSignal>>,
    aio: Option<(Aio, trames_vfs::NativeEvents)>,
    paths: Option<trames_vfs::PathQueries>,
    file_prepared: RefCell<Option<file::PreparedFileCall>>,
    resources: Option<trames_vfs::DescriptorFactory>,
    urings: UringSnapshot,
    file_executor: Option<Arc<dyn FileExecutor>>,
    file_layouts: Option<Arc<crate::FileLayouts>>,
    descriptors: DirectFds,
    network: trames_vfs::DirectNetwork,
    terminal: Option<trames_vfs::TerminalAccess>,
    kernel_log: Option<trames_vfs::KernelLogAccess>,
    files: trames_vfs::DirectFiles,
    membership: Option<trames_vfs::SharedFiles>,
    lock_context: Option<trames_vfs::RecordLockContext>,
    local_identity: Option<[u32; 3]>,
    disk_cache: RefCell<trames_vfs::DiskReadCache>,
    file_completed: Cell<u64>,
    socket_completed: Cell<u64>,
    timer_completed: Cell<u64>,
    poll_completed: Cell<u64>,
    fd_control_completed: Cell<u64>,
    started: Option<Instant>,
    boot_clock: Option<trames_shared::boottime::Boottime>,
    scratch: RefCell<Vec<u8>>,
    completed: Cell<u64>,
}
impl DirectSyscalls {
    /// Change only future syscall/SQE acceptance. Accepted async work owns its
    /// old paths, descriptors and execution context until it completes.
    pub fn refresh_namespaces(&mut self, resources: trames_vfs::TaskNamespaceResources) {
        if let Some(identity) = &mut self.local_identity {
            identity[1] = resources.credentials.uid;
            identity[2] = resources.credentials.gid;
        }
        self.kernel_log = Some(resources.kernel_log);
        self.descriptors = resources
            .descriptors
            .with_signal_reader(self.signal_reader.clone());
        self.network = resources.network;
        self.membership = Some(resources.files.clone());
        self.files = resources.direct_files;
        self.paths = Some(resources.paths);
        let mut factory = resources.factory;
        if let Some(identity) = self.local_identity {
            factory = factory.with_local_identity(identity);
        }
        self.resources = Some(factory);
        if let Some((_, events)) = &mut self.aio {
            *events = events.with_files(resources.files.clone());
        }
        self.urings.refresh_namespaces(
            resources.files,
            &self.files,
            self.descriptors.clone(),
            resources.uring_files,
        );
    }
    /// The original task's ring roots remain usable after FD close/reuse.
    pub fn cancel_task_uring(&self, owner: u64, task: u32) {
        self.urings.cancel_task(owner, task);
    }
    pub fn release_process_locks(&self) {
        if let Some(context) = &self.lock_context {
            context.release();
        }
    }
    pub fn with_signal_reader(mut self, reader: Arc<dyn trames_vfs::SignalReader>) -> Self {
        self.signal_reader = Some(reader.clone());
        self.descriptors = self.descriptors.with_signal_reader(Some(reader.clone()));
        if let Some(descriptors) = self.urings.descriptors.take() {
            self.urings.descriptors = Some(descriptors.with_signal_reader(Some(reader)));
        }
        self
    }
    pub fn with_task_signal(mut self, task: Arc<dyn trames_vfs::TaskSignal>) -> Self {
        self.task_signal = Some(task);
        self
    }
    pub fn descriptors(&self) -> DirectFds {
        self.descriptors.clone()
    }
    pub fn new(descriptors: DirectFds) -> Self {
        let membership = descriptors.shared_files();
        Self {
            signal_reader: None,
            task_signal: None,
            aio: None,
            paths: None,
            file_prepared: Default::default(),
            resources: None,
            urings: Default::default(),
            file_executor: None,
            file_layouts: None,
            descriptors,
            network: Default::default(),
            terminal: None,
            kernel_log: None,
            files: Default::default(),
            membership,
            lock_context: None,
            local_identity: None,
            disk_cache: Default::default(),
            file_completed: Cell::new(0),
            socket_completed: Cell::new(0),
            timer_completed: Cell::new(0),
            poll_completed: Cell::new(0),
            fd_control_completed: Cell::new(0),
            started: None,
            boot_clock: None,
            scratch: RefCell::new(Vec::new()),
            completed: Cell::new(0),
        }
    }
    pub fn with_resources(mut self, mut resources: trames_vfs::DescriptorFactory) -> Self {
        if let Some(identity) = self.local_identity {
            resources = resources.with_local_identity(identity);
        }
        self.resources = Some(resources);
        self
    }
    pub fn supports_creation(&self, number: u32) -> bool {
        if number == 425 {
            self.paths.is_some()
        } else {
            matches!(number, 19 | 26 | 59 | 74 | 85 | 198 | 199 | 280) && self.resources.is_some()
        }
    }
    pub fn invoke_creation(
        &self,
        number: u32,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        if number == 425 {
            let paths = self.paths.as_ref()?;
            let result = (|| {
                let (entries, cq_entries, output) = crate::uring::setup_parameters(a, memory)?;
                paths
                    .uring_create_with_output(entries, cq_entries, || {
                        memory.write(a[1], &output).map_err(|_| Errno(14))
                    })
                    .map(u64::from)
            })();
            self.urings.record_completed();
            return Some(result);
        }
        let result = crate::descriptor_create::call(self.resources.as_ref()?, number, a, memory)?;
        self.record_fd_control();
        Some(result)
    }
    pub fn supports_epoll_control(&self, number: u32) -> bool {
        number == 21 && self.membership.is_some()
    }
    pub fn invoke_epoll_control(
        &self,
        number: u32,
        a: [u64; 6],
        memory: &impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        if !self.supports_epoll_control(number) {
            return None;
        }
        let (events, data) = match Linux::epoll_control_parameters(a, memory) {
            Ok(value) => value,
            Err(error) => return Some(Err(error)),
        };
        let result =
            self.descriptors
                .epoll_control(a[0] as u32, a[1] as u32, a[2] as u32, events, data)?;
        self.record_fd_control();
        Some(result.map(|()| 0))
    }
    pub fn supports_socket_control(&self, number: u32) -> bool {
        (crate::network::control_number(number) || ip_message::number(number))
            && self.resources.is_some()
    }
    pub fn supports_local_message(&self, number: u32, fd: u32) -> bool {
        self.resources.is_some()
            && (matches!(number, 211 | 212 | 269)
                || matches!(number, 63..=66 | 206 | 207)
                    && self
                        .descriptors
                        .get(fd)
                        .is_some_and(|fd| fd.is_unix() && fd.local_kind() != 1))
    }
    pub fn invoke_socket_control(
        &self,
        number: u32,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        if self.resources.is_none() {
            // Retain compatibility for explicitly native-only captures. Product
            // workers carry DescriptorFactory and use the full socket ABI below.
            if !matches!(number, 204 | 205 | 208..=210) {
                return None;
            }
            let refresh = number == 209 && (a[1] as u32, a[2] as u32) == (1, 4);
            let result = self
                .network
                .with_control_refresh(a[0] as u32, refresh, |control| {
                    control
                        .supports_operation(number, a[1] as u32, a[2] as u32)
                        .then(|| crate::network::direct_control(control, number, a, memory))
                })??;
            self.completed.set(self.completed.get() + 1);
            self.socket_completed.set(self.socket_completed.get() + 1);
            return Some(result);
        }
        if !crate::network::control_number(number) {
            return None;
        }
        let factory = self.resources.as_ref()?;
        let socket = match factory.socket_control_operation(a[0] as u32)? {
            Ok(trames_vfs::SocketControlOperation::Network(socket)) => socket,
            Err(error) => return Some(Err(error)),
            Ok(trames_vfs::SocketControlOperation::Unix(socket)) => {
                let result = crate::network::unix::control(factory, &socket, number, a, memory)?;
                self.completed.set(self.completed.get() + 1);
                self.socket_completed.set(self.socket_completed.get() + 1);
                return Some(result);
            }
        };
        // Blocking connect/accept will use the retained event-wait entry.
        if socket.flags() & trames_vfs::O_NONBLOCK == 0
            && (matches!(number, 202 | 242)
                || number == 203 && socket.info().is_some_and(|info| info.kind == 1))
        {
            return None;
        }
        let result = if crate::network::control_publishes(number, a) {
            socket.with_tcp_publication(|| {
                crate::network::control(factory, &socket, number, a, memory)
                    .expect("socket control ABI")
            })
        } else {
            crate::network::control(factory, &socket, number, a, memory)?
        };
        self.completed.set(self.completed.get() + 1);
        self.socket_completed.set(self.socket_completed.get() + 1);
        Some(result)
    }
    pub fn with_paths(mut self, paths: trames_vfs::PathQueries) -> Self {
        self.paths = Some(paths);
        self
    }
    pub fn supports_path_query(&self, number: u32) -> bool {
        (namespace::supported(number)
            || matches!(number, 27 | 48 | 56 | 61 | 62 | 78..=80 | 291 | 437 | 439))
            && self.paths.is_some()
    }
    pub fn invoke_path(
        &self,
        number: u32,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        if namespace::supported(number) {
            return self.invoke_namespace(number, a, memory);
        }
        let paths = self.paths.as_ref()?;
        if self.file_prepared(number, a) {
            return None;
        }
        let result = if matches!(number, 56 | 437) {
            let parameters = (|| {
                let (flags, mode, policy) = if number == 437 {
                    Linux::decode_open_how(memory, a[2], a[3])?
                } else {
                    (a[2] as u32, a[3] as u32, 0)
                };
                Ok((Linux::path(memory, a[1])?, flags, mode, policy))
            })();
            match parameters {
                Ok((path, flags, mode, policy)) => {
                    match paths.open_at_resolve(
                        a[0] as i32,
                        &path,
                        flags,
                        mode,
                        policy,
                        &self.files,
                    ) {
                        Some(result) => result.map(u64::from),
                        None => {
                            return self.prepare_open_work(
                                number,
                                a,
                                paths.take_open_work()?,
                                memory,
                            )
                        }
                    }
                }
                Err(e) => Err(e),
            }
        } else {
            crate::path_queries::call(paths, number, a, memory)?
        };
        self.completed.set(self.completed.get() + 1);
        self.file_completed.set(self.file_completed.get() + 1);
        Some(result)
    }
    pub fn with_lock_context(mut self, context: trames_vfs::RecordLockContext) -> Self {
        self.lock_context = Some(context);
        self
    }
    pub fn with_local_identity(mut self, identity: [u32; 3]) -> Self {
        self.local_identity = Some(identity);
        if let Some(resources) = self.resources.take() {
            self.resources = Some(resources.with_local_identity(identity));
        }
        self
    }
    pub fn published_file(&self, fd: u32) -> bool {
        self.files.published(fd)
    }
    pub fn with_files(mut self, files: trames_vfs::DirectFiles) -> Self {
        self.files = files;
        self
    }
    pub fn with_membership(mut self, files: trames_vfs::SharedFiles) -> Self {
        self.membership = Some(files);
        self
    }
    /// Shared operations use actual membership. Retained calls/mappings own
    /// their original OFDs; excluded owner controls checkpoint before effects.
    pub fn invoke_membership(&self, number: u32, args: [u64; 6]) -> Option<Result<u64, Errno>> {
        let files = self.membership.as_ref()?;
        let result = match number {
            436 if args[2] as u32 & 2 == 0 => Some(
                files
                    .close_range(
                        args[0] as u32,
                        args[1] as u32,
                        args[2] as u32,
                        self.lock_context.as_ref()?.owner,
                    )
                    .map(|()| 0),
            ),
            23 => files.duplicate(args[0] as u32, 0, false),
            24 => files.duplicate_to(
                args[0] as u32,
                args[1] as u32,
                args[2] as u32,
                self.lock_context.as_ref()?.owner,
            ),
            57 => files
                .close(args[0] as u32, self.lock_context.as_ref()?.owner)
                .map(|r| r.map(|()| 0)),
            25 if matches!(args[1], 0 | 1030) => {
                if args[2] >= files.descriptor_limit() as u64 {
                    return files.lookup(args[0] as u32).map(|r| r.and(Err(Errno(22))));
                }
                files.duplicate(args[0] as u32, args[2] as u32, args[1] == 1030)
            }
            _ => return None,
        }?;
        self.record_fd_control();
        Some(result.map(u64::from))
    }
    pub fn with_terminal(mut self, access: trames_vfs::TerminalAccess) -> Self {
        self.terminal = Some(access);
        self
    }
    pub fn with_kernel_log(mut self, log: trames_vfs::KernelLogAccess) -> Self {
        self.kernel_log = Some(log);
        self
    }
    pub fn socket_descriptor(&self, fd: u32) -> bool {
        self.network.is_socket(fd)
    }
    pub fn with_network(mut self, network: trames_vfs::DirectNetwork) -> Self {
        self.network = network;
        self
    }
    pub fn with_file_executor(mut self, disk: Arc<dyn FileExecutor>) -> Self {
        self.file_executor = Some(disk);
        self
    }
    pub fn with_file_layouts(mut self, layouts: Arc<crate::FileLayouts>) -> Self {
        self.file_layouts = Some(layouts);
        self
    }
    pub fn with_urings(mut self, snapshot: UringSnapshot) -> Self {
        if let Some(descriptors) = &snapshot.descriptors {
            self.descriptors = descriptors.clone();
        }
        self.urings = snapshot;
        self
    }
    pub fn uring_completed(&self) -> u64 {
        self.urings.completed()
    }
    pub fn file_completed(&self) -> u64 {
        self.file_completed.get()
    }
    pub fn socket_completed(&self) -> u64 {
        self.socket_completed.get()
    }
    pub fn timer_completed(&self) -> u64 {
        self.timer_completed.get()
    }
    pub fn poll_completed(&self) -> u64 {
        self.poll_completed.get()
    }
    pub fn fd_control_completed(&self) -> u64 {
        self.fd_control_completed.get()
    }
    pub fn record_fd_control(&self) {
        self.fd_control_completed
            .set(self.fd_control_completed.get() + 1);
    }
    pub fn with_boot_clock(mut self, clock: trames_shared::boottime::Boottime) -> Self {
        self.boot_clock = Some(clock);
        self
    }
    pub fn boot_clock(&self) -> Option<trames_shared::boottime::Boottime> {
        self.boot_clock
    }
    pub fn with_clock(mut self, started: Instant) -> Self {
        self.started = Some(started);
        self.urings.clock = Some(started);
        self
    }
    /// File operations use their original resource authority. Blocking native
    /// work and genuine mapping-layout changes retain the accepted operation.
    pub fn invoke_file(
        &self,
        number: u32,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        // Legacy dispatch defers blocking flock before effects. In particular,
        // a failed conversion may already have released the old lock: it must
        // not be attempted speculatively and then replayed on fallback.
        if number == 32 && (a[1] as u32 & 4 != 0 || a[1] as u32 == 8) {
            let result = self.files.get(a[0] as u32)?.flock(a[1] as u32).map(|()| 0);
            self.record_fd_control();
            return Some(result);
        }
        if number == 25 && matches!(a[1], 5 | 6 | 36 | 37) {
            let context = self.lock_context.as_ref()?;
            let file = self.files.get(a[0] as u32)?;
            let result = if !file.allows_record_locks() {
                Err(Errno(9))
            } else {
                crate::record_locks::call(
                    memory,
                    a[1],
                    a[2],
                    |kind, whence, start, length| {
                        if a[1] >= 36 {
                            file.normalize_ofd_lock(kind, whence, start, length)
                        } else {
                            file.normalize_lock(kind, whence, start, length, context.owner)
                        }
                    },
                    |requested| Ok(file.record_lock_conflict(requested)),
                    |requested| file.record_lock_set(requested),
                    |owner| context.visible_pid(owner),
                )?
            };
            self.record_fd_control();
            return Some(result);
        }
        self.invoke_file_io(number, a, memory)
    }
    pub fn supports(&self, number: u32, fd: u32) -> bool {
        // Classify the ABI before resolving an FD. Creation, pathname, clock
        // and other non-I/O calls must not look up argument zero as a number.
        if !matches!(number,22|28|29|62..=70|86|87|206|207|210..=212|269|441) {
            return false;
        }
        if self.network.get(fd).is_some() {
            return matches!(number, 63..=66);
        }
        if let Some(fd) = self.descriptors.get(fd) {
            return Self::supports_fd(number, &fd) || matches!(number, 63..=66) && fd.is_netlink();
        }
        matches!(number, 63..=66) && self.raw_ip_socket(fd).is_some()
    }
    fn supports_fd(number: u32, fd: &trames_vfs::DirectFd) -> bool {
        if number == 62 {
            fd.is_kmsg() || fd.positioned_bytes()
        } else if matches!(number, 67..=70) {
            fd.positioned_bytes()
        } else if matches!(number, 22 | 441) {
            fd.is_epoll()
        } else if matches!(number, 86 | 87) {
            fd.timer().is_some()
        } else if number == 28 {
            fd.is_inotify()
        } else if matches!(number, 206 | 207 | 210..=212 | 269) {
            fd.is_unix()
        } else if number == 29 {
            fd.has_readable_bytes()
        } else {
            matches!(number, 63..=66) && !fd.is_epoll() && !fd.is_poll_only()
        }
    }
    fn supports_fd_call(number: u32, args: [u64; 6], fd: &trames_vfs::DirectFd) -> bool {
        Self::supports_fd(number, fd)
            && (number != 29
                || args[1] as u32 == 0x541b
                || fd.is_pty() && matches!(args[1] as u32, 0x5401 | 0x5413)
                || fd.pty_endpoint().is_some()
                    && (crate::pty_control_request(args[1] as u32) || args[1] as u32 == 0x5441))
    }
    fn invoke_control(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        // Acceptance, type validation, execution and accounting use one OFD.
        // Another CLONE_FILES task may close or replace its numeric slot.
        let fd = self.descriptors.get(args[0] as u32)?;
        let result = self.transfer_fd(&fd, number, args, memory)?;
        self.completed.set(self.completed.get() + 1);
        if number == 28 {
            self.record_fd_control();
        }
        if fd.timer().is_some() {
            self.timer_completed.set(self.timer_completed.get() + 1);
        }
        Some(result)
    }
    pub fn swap_disk_cache(&self, cache: &mut trames_vfs::DiskReadCache) {
        std::mem::swap(&mut *self.disk_cache.borrow_mut(), cache);
    }
    pub fn completed(&self) -> u64 {
        self.completed.get() + self.urings.completed()
    }
    /// Move the persistent worker's bounded byte buffer into/out of a dispatch.
    /// No borrow or partially executed operation survives this ownership swap.
    pub fn swap_scratch(&self, buffer: &mut Vec<u8>) {
        std::mem::swap(&mut *self.scratch.borrow_mut(), buffer);
    }
    pub fn supports_call(&self, number: u32, args: [u64; 6]) -> bool {
        if Self::aio_call(number) {
            return self.aio.is_some();
        }
        if self.file_prepared(number, args) {
            return true;
        }
        if number == 116 {
            return self.kernel_log.is_some();
        }
        if number == 32 {
            return self.files.get(args[0] as u32).is_some();
        }
        if number == 426 {
            return self.urings.available();
        }
        if number == 427 {
            return self.urings.supports_register(args);
        }
        if matches!(number, 72 | 73) {
            return true;
        }
        self.supports(number, args[0] as u32)
            && (number != 29
                || args[1] as u32 == 0x541b
                || self
                    .descriptors
                    .get(args[0] as u32)
                    .is_some_and(|fd| fd.is_pty())
                    && (matches!(args[1] as u32, 0x5401 | 0x5413)
                        || crate::pty_control_request(args[1] as u32)
                        || args[1] as u32 == 0x5441 && self.resources.is_some()))
    }
    fn transfer(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        if number == 116 {
            return Some(crate::syslog(self.kernel_log.as_ref()?, args, memory));
        }
        let fd = self.descriptors.get(args[0] as u32)?;
        self.transfer_fd(&fd, number, args, memory)
    }
    fn transfer_tcp(
        &self,
        fd: &trames_vfs::DirectTcpFd,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Result<u64, Errno> {
        let read = |count| {
            if fd.flags & trames_vfs::O_PATH != 0 || fd.flags & 3 == 1 {
                return Err(Errno(9));
            }
            fd.tcp.recv(count, 0).map_err(|e| Errno(e.0))
        };
        let write = |bytes: &[u8]| {
            if fd.flags & trames_vfs::O_PATH != 0 || fd.flags & 3 == 0 {
                return Err(Errno(9));
            }
            fd.tcp
                .send(bytes, 0)
                .map(|n| n as u64)
                .map_err(|e| Errno(e.0))
        };
        match number {
            63 => Linux::read_transport(args, memory, read),
            64 => Linux::write_transport(args, memory, &mut self.scratch.borrow_mut(), write),
            65 => Linux::readv_transport_mode(args, memory, false, read),
            66 => Linux::writev_transport_mode(
                args,
                memory,
                &mut self.scratch.borrow_mut(),
                false,
                write,
            ),
            _ => unreachable!("native TCP byte call"),
        }
    }
    fn complete_tcp(&self, result: Result<u64, Errno>) -> IoAttempt {
        self.completed.set(self.completed.get() + 1);
        self.socket_completed.set(self.socket_completed.get() + 1);
        IoAttempt::Complete(result)
    }
    #[allow(clippy::too_many_arguments)]
    fn start_tcp(
        &self,
        fd: trames_vfs::DirectTcpFd,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
        saved_deadline: Option<Instant>,
    ) -> IoAttempt {
        match self.transfer_tcp(&fd, number, args, memory) {
            Err(Errno(11)) if !fd.nonblocking() => {}
            Err(Errno(32)) if signals_pipe(number, args) => return IoAttempt::Checkpoint,
            result => return self.complete_tcp(result),
        }
        let deadline = saved_deadline.or_else(|| {
            fd.timeouts[usize::from(matches!(number, 63 | 65))]
                .and_then(|d| Instant::now().checked_add(d))
        });
        let signal = IoSignal::new(pid, target.clone());
        let subscription = (|| {
            target
                .upgrade()?
                .host_events()?
                .subscribe(
                    tcp_wait_fd(&fd.tcp).ok()?,
                    matches!(number, 64 | 66),
                    &signal,
                )
                .ok()
        })();
        let Some(subscription) = subscription else {
            return IoAttempt::Checkpoint;
        };
        self.resume(
            PendingIo {
                aio: None,
                number,
                args,
                deadline,
                signal,
                native_tcp: Some(fd),
                retained_socket: None,
                retained_byte: None,
                flock: None,
                resource_deadline: None,
                epoll_revision: None,
                retained_poll: None,
                _subscriptions: Vec::new(),
                socket_subscriptions: Vec::new(),
                host_subscription: Some(subscription),
                uring: None,
                poll_uring: None,
                file: None,
                target: target.clone(),
            },
            memory,
        )
    }
    fn transfer_fd(
        &self,
        fd: &trames_vfs::DirectFd,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        if !Self::supports_fd_call(number, args, fd) {
            return None;
        }
        // Addressed packet calls bind their target/input once at the retained
        // entry, before any queue effect, rather than probing then re-resolving.
        if fd.is_unix() && fd.local_kind() != 1 && matches!(number, 63..=66 | 206 | 207)
            || fd.is_addressed_datagram() && matches!(number, 211 | 212)
            || number == 269
        {
            return None;
        }
        if matches!(number, 211 | 212) && self.resources.is_some() {
            return self.local_message(fd, number, args, memory);
        }
        if number == 29 && args[1] as u32 == 0x5441 {
            return Some(
                self.resources
                    .as_ref()?
                    .open_pty_peer(fd.pty_endpoint()?, args[2] as u32)
                    .map(u64::from),
            );
        }
        let deferred = Cell::new(false);
        let flags = socket_flags(number, args);
        let read = |count| {
            let result = if fd.is_pty() {
                fd.terminal_read(count, self.terminal)
            } else if matches!(number, 207 | 212) {
                fd.recv(count, flags | if fd.nonblocking() { 0x40 } else { 0 })
            } else {
                fd.read_attempt(count)
            };
            result.unwrap_or_else(|| {
                deferred.set(true);
                Err(Errno(11))
            })
        };
        let write = |bytes: &[u8]| {
            let result = if fd.is_pty() {
                fd.terminal_write(bytes, self.terminal)
            } else if fd.is_unix() {
                Some(fd.send_credentials(
                    bytes,
                    if matches!(number, 206 | 211) {
                        flags
                    } else {
                        0
                    },
                    self.local_identity,
                ))
            } else {
                Some(fd.write(bytes))
            };
            result
                .unwrap_or_else(|| {
                    deferred.set(true);
                    Err(Errno(11))
                })
                .map(|n| n as u64)
        };
        let result = match number {
            62 => fd.byte_seek(args[1] as i64, args[2] as u32),
            28 => fd.inotify_remove(args[1] as i32),
            86 | 87 => crate::timer::timerfd_control_with_boot(
                fd.timer().expect("timerfd resource"),
                number,
                args,
                memory,
                self.started.unwrap_or_else(Instant::now),
                self.boot_clock,
            ),
            29 => (|| {
                if crate::pty_control_request(args[1] as u32) {
                    return crate::pty_control(
                        fd.pty_endpoint().expect("accepted PTY endpoint"),
                        args[1] as u32,
                        args[2],
                        memory,
                    );
                }
                if args[1] as u32 != 0x541b {
                    let bytes = fd.terminal_query(args[1] as u32).expect("terminal query");
                    Linux::check(memory, args[2], bytes.len(), Access::Write)?;
                    memory.write(args[2], &bytes).map_err(|_| Errno(14))?;
                    return Ok(0);
                }
                Linux::check(memory, args[2], 4, Access::Write)?;
                memory
                    .write_array(
                        args[2],
                        (fd.readable_bytes().min(i32::MAX as usize) as i32).to_le_bytes(),
                    )
                    .map_err(|_| Errno(14))?;
                Ok(0)
            })(),
            67 => Linux::read_transport(args, memory, |count| fd.device_pread(count, args[3])),
            68 => Linux::write_transport(args, memory, &mut self.scratch.borrow_mut(), |bytes| {
                fd.device_pwrite(bytes, args[3]).map(|n| n as u64)
            }),
            69 | 70 => (|| {
                let (parts, total) = Linux::positioned_vector_parts(memory, args, number == 70)?;
                if number == 70 {
                    let mut scratch = self.scratch.borrow_mut();
                    Linux::gather_parts(memory, &parts, total, &mut scratch)?;
                    fd.device_pwrite(&scratch, args[3]).map(|n| n as u64)
                } else {
                    let bytes = fd.device_pread(total, args[3])?;
                    Linux::scatter(memory, &parts, &bytes)?;
                    Ok(bytes.len() as u64)
                }
            })(),
            63 => Linux::read_transport(args, memory, read),
            64 => Linux::write_transport(args, memory, &mut self.scratch.borrow_mut(), |bytes| {
                write(bytes)
            }),
            65 => Linux::readv_transport_mode(args, memory, fd.readv_records(), read),
            66 => Linux::writev_transport_mode(
                args,
                memory,
                &mut self.scratch.borrow_mut(),
                fd.is_eventfd(),
                write,
            ),
            206 => crate::network::local::send(args, memory, &mut self.scratch.borrow_mut(), write),
            207 => crate::network::local::recv(args, memory, read),
            210 => fd.shutdown(args[1] as u32).map(|()| 0),
            211 | 212 => crate::network::local::message(
                number,
                args,
                memory,
                &mut self.scratch.borrow_mut(),
                read,
                write,
            )?,
            _ => unreachable!(),
        };
        if deferred.get() {
            None
        } else {
            Some(result)
        }
    }
    fn nonblocking(&self, number: u32, args: [u64; 6]) -> bool {
        if number == 116 {
            return false;
        }
        if let Some(fd) = self.network.get(args[0] as u32) {
            return fd.nonblocking();
        }
        self.descriptors.get(args[0] as u32).unwrap().nonblocking()
            || socket_flags(number, args) & 0x40 != 0
    }
    fn complete(&self, number: u32, args: [u64; 6], result: Result<u64, Errno>) -> IoAttempt {
        self.completed.set(self.completed.get() + 1);
        if matches!(number, 28 | 32) {
            self.record_fd_control();
        }
        if matches!(number, 32 | 116) {
            return IoAttempt::Complete(result);
        }
        if crate::event_wait(number) {
            self.poll_completed.set(self.poll_completed.get() + 1);
            return IoAttempt::Complete(result);
        }
        let fd = self.descriptors.get(args[0] as u32);
        if fd.as_ref().is_some_and(|fd| fd.timer().is_some()) {
            self.timer_completed.set(self.timer_completed.get() + 1);
        }
        if fd.as_ref().is_some_and(|fd| fd.is_unix()) || self.network.get(args[0] as u32).is_some()
        {
            self.socket_completed.set(self.socket_completed.get() + 1);
        }
        IoAttempt::Complete(result)
    }
    fn complete_byte(&self, file: &RetainedByte, result: Result<u64, Errno>) -> IoAttempt {
        // Accepted shared byte calls already own their complete authority.
        // Accounting must not re-resolve the numeric FD after close/reuse.
        self.completed.set(self.completed.get() + 1);
        if file.fd.is_unix() {
            self.socket_completed.set(self.socket_completed.get() + 1);
        }
        if file.fd.timer().is_some() {
            self.timer_completed.set(self.timer_completed.get() + 1);
        }
        IoAttempt::Complete(result)
    }
    fn complete_pending(
        &self,
        pending: &PendingIo,
        result: Result<u64, Errno>,
        memory: &mut impl CpuMemory,
    ) -> IoAttempt {
        let result = if let Some(wait) = &pending.retained_poll {
            wait.finish(memory, result)
        } else {
            result
        };
        if pending.native_tcp.is_some() {
            self.complete_tcp(result)
        } else if let Some(file) = &pending.retained_byte {
            self.complete_byte(file, result)
        } else {
            self.complete(pending.number, pending.args, result)
        }
    }
    /// Subscribe before the deciding resource check. No notification can be lost
    /// between an EAGAIN result and publishing the parked task to its run queue.
    pub fn start(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
        saved_deadline: Option<Instant>,
    ) -> Option<IoAttempt> {
        if Self::aio_call(number) {
            return self.start_aio(number, args, memory, pid, target, saved_deadline);
        }
        if matches!(number, 206 | 207 | 211 | 212 | 269) && self.resources.is_some() {
            if let Some(attempt) = self.start_local_message(number, args, memory, pid, target) {
                return Some(attempt);
            }
        }
        if matches!(number, 63..=66) {
            if let Some(fd) = self.network.get(args[0] as u32) {
                return Some(self.start_tcp(fd, number, args, memory, pid, target, saved_deadline));
            }
        }
        if let Some(attempt) = self.start_prepared_file(number, args, memory, pid, target) {
            return Some(attempt);
        }
        if let Some(file) = self.retain_byte(number, args) {
            return Some(match file {
                Ok(file) => self.start_retained_byte(file, number, args, memory, pid, target),
                Err(error) => self.complete(number, args, Err(error)),
            });
        }
        if let Some(attempt) = self.start_raw_ip(number, args, memory, pid, target) {
            return Some(attempt);
        }
        if matches!(number, 28 | 86 | 87) {
            return self
                .invoke_control(number, args, memory)
                .map(IoAttempt::Complete);
        }
        if number == 32 {
            let request = match self
                .files
                .get(args[0] as u32)?
                .flock_request(args[1] as u32)
            {
                Ok(request) => request,
                Err(error) => return Some(self.complete(number, args, Err(error))),
            };
            return Some(self.start_flock(request, args, memory, pid, target));
        }
        if number == 427 {
            return self.urings.register(args, memory, pid);
        }
        if number == 426 {
            self.urings.ensure_context(
                self.paths.as_ref(),
                self.resources.as_ref(),
                &self.files,
                self.file_executor.as_ref(),
                self.file_layouts.as_ref(),
                self.task_signal.as_ref(),
            );
            let attempt = self.urings.start(args, memory, pid, target)?;
            return Some(attempt);
        }
        if !self.supports_call(number, args) {
            return None;
        }
        if crate::event_wait(number) {
            return Some(
                match crate::RetainedWait::prepare_worker(
                    &self.descriptors,
                    memory,
                    number,
                    args,
                    saved_deadline,
                ) {
                    Some(Ok(wait)) => self.start_event_wait(wait, memory, pid, target),
                    Some(Err(error)) => self.complete(number, args, Err(error)),
                    None => IoAttempt::Checkpoint,
                },
            );
        }
        let deadline = {
            let Some(result) = self.transfer(number, args, memory) else {
                return Some(IoAttempt::Checkpoint);
            };
            match result {
                Err(Errno(11)) if !self.nonblocking(number, args) => {}
                Err(Errno(32)) if signals_pipe(number, args) => return Some(IoAttempt::Checkpoint),
                result => return Some(self.complete(number, args, result)),
            }
            if number == 116 {
                None
            } else {
                saved_deadline.or_else(|| {
                    self.network
                        .get(args[0] as u32)
                        .and_then(|fd| fd.timeouts[usize::from(matches!(number, 63 | 65))])
                        .and_then(|d| Instant::now().checked_add(d))
                })
            }
        };
        let signal = IoSignal::new(pid, target.clone());
        let mut host_subscription = None;
        let subscriptions = if number == 116 {
            vec![self.kernel_log.as_ref().unwrap().subscribe(&signal)]
        } else if let Some(fd) = self
            .network
            .get(args[0] as u32)
            .filter(|_| matches!(number, 63..=66))
        {
            let subscription = (|| {
                let events = target.upgrade()?.host_events()?;
                events
                    .subscribe(
                        tcp_wait_fd(&fd.tcp).ok()?,
                        matches!(number, 64 | 66),
                        &signal,
                    )
                    .ok()
            })();
            let Some(subscription) = subscription else {
                return Some(IoAttempt::Checkpoint);
            };
            host_subscription = Some(subscription);
            Vec::new()
        } else {
            self.descriptors
                .get(args[0] as u32)
                .unwrap()
                .subscribe(&signal)
        };
        Some(self.resume(
            PendingIo {
                aio: None,
                number,
                args,
                deadline,
                signal,
                epoll_revision: None,
                retained_poll: None,
                resource_deadline: None,
                flock: None,
                retained_socket: None,
                retained_byte: None,
                native_tcp: None,
                _subscriptions: subscriptions,
                socket_subscriptions: Vec::new(),
                host_subscription,
                uring: None,
                poll_uring: None,
                file: None,
                target: target.clone(),
            },
            memory,
        ))
    }
    fn retain_byte(&self, number: u32, args: [u64; 6]) -> Option<Result<RetainedByte, Errno>> {
        if !matches!(number, 63..=70) {
            return None;
        }
        let file = match self.membership.as_ref()?.lookup(args[0] as u32)? {
            Ok(file) => file,
            Err(error) => return Some(Err(error)),
        };
        let fd = self.descriptors.byte_file(file)?;
        if matches!(number, 67..=70) && !fd.positioned_bytes() {
            return None;
        }
        Some(Ok(RetainedByte {
            fd,
            operation: ByteOperation::Plain,
        }))
    }
    pub fn start_retained_poll(
        &self,
        poll: Arc<crate::RetainedWait>,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
        deadline: Option<Instant>,
    ) -> IoAttempt {
        let _ = (args, deadline); // Original accepted ABI/deadline belongs to poll.
        let Some(poll) = poll.rearm(&self.descriptors) else {
            return IoAttempt::WaitCheckpoint(poll);
        };
        self.start_event_wait(poll, memory, pid, target)
    }
    fn start_event_wait<
        W: std::borrow::Borrow<crate::RetainedWait> + Into<Arc<crate::RetainedWait>>,
    >(
        &self,
        accepted: W,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let wait = accepted.borrow();
        if !self.urings.poll_pump(&wait.poll_resources(), memory) {
            return IoAttempt::WaitCheckpoint(accepted.into());
        }
        match wait.check(memory) {
            Err(Errno(11)) => {}
            result => {
                let result = wait.finish(memory, result);
                return self.complete(wait.number, wait.args, result);
            }
        }
        let signal = IoSignal::new(pid, target.clone());
        let subscriptions = wait.subscribe(&signal);
        let revision = wait.epoll_revision();
        let wait = accepted.into();
        self.resume(
            PendingIo {
                aio: None,
                number: wait.number,
                args: wait.args,
                deadline: wait.deadline,
                signal,
                retained_poll: Some(wait),
                epoll_revision: revision,
                retained_socket: None,
                retained_byte: None,
                native_tcp: None,
                flock: None,
                resource_deadline: None,
                _subscriptions: subscriptions,
                socket_subscriptions: Vec::new(),
                host_subscription: None,
                uring: None,
                poll_uring: None,
                file: None,
                target: target.clone(),
            },
            memory,
        )
    }
    /// Joined execution uses the same ABI and resource wait, but owns SIGPIPE
    /// delivery itself. Only complete shared byte OFDs enter.
    pub fn start_owned_byte(
        &self,
        retained: Option<RetainedByte>,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<IoAttempt> {
        let retained = retained
            .map(Ok)
            .or_else(|| self.retain_byte(number, args))?;
        Some(match retained {
            Ok(file)
                if file.fd.is_unix() && file.fd.local_kind() != 1 && file.message().is_none() =>
            {
                IoAttempt::ByteCheckpoint(file)
            }
            Ok(file) => self.start_byte(file, number, args, memory, pid, target, false),
            Err(error) => self.complete(number, args, Err(error)),
        })
    }
    pub fn start_retained_byte(
        &self,
        file: RetainedByte,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        if file.fd.is_unix() && file.fd.local_kind() != 1 && file.message().is_none() {
            return match self.prepare_packet_byte(&file, number, args, memory) {
                Some(Ok(prepared)) => {
                    self.start_byte(prepared, number, args, memory, pid, target, true)
                }
                Some(Err(error)) => self.complete_byte(&file, Err(error)),
                None => IoAttempt::ByteCheckpoint(file),
            };
        }
        self.start_byte(file, number, args, memory, pid, target, true)
    }
    #[allow(clippy::too_many_arguments)]
    fn start_byte(
        &self,
        file: RetainedByte,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
        checkpoint_pipe: bool,
    ) -> IoAttempt {
        let mut file = file;
        let result = if matches!(number, 63 | 65)
            && file.fd.is_signalfd()
            && matches!(file.operation, ByteOperation::Plain)
        {
            if let Err(e) = file.fd.check_read_access() {
                return self.complete_byte(&file, Err(e));
            }
            let read = match signal_read::SignalRead::prepare(number, args, memory) {
                Ok(r) => r,
                Err(e) => return self.complete_byte(&file, Err(e)),
            };
            let result = read.check(&file.fd, memory);
            if result == Err(Errno(11)) && !file.fd.nonblocking() {
                file.operation = ByteOperation::Signal(Arc::new(read));
            }
            Some(result)
        } else {
            self.transfer_retained(&file, number, args, memory)
        };
        match result {
            Some(Err(Errno(11)))
                if !file.fd.nonblocking() && socket_flags(number, args) & 0x40 == 0 => {}
            Some(Err(Errno(32))) if checkpoint_pipe && signals_pipe(number, args) => {
                return if file.message().is_some() {
                    IoAttempt::ByteCheckpoint(file)
                } else {
                    IoAttempt::Checkpoint
                }
            }
            Some(result) => return self.complete_byte(&file, result),
            None => {
                return if file.message().is_some() || file.fd.is_pty() || file.fd.is_unix() {
                    IoAttempt::ByteCheckpoint(file)
                } else {
                    IoAttempt::Checkpoint
                }
            }
        }
        let signal = IoSignal::new(pid, target.clone());
        let subscriptions = file.subscribe(&signal);
        self.resume_inner(
            PendingIo {
                aio: None,
                number,
                args,
                deadline: None,
                signal,
                flock: None,
                retained_socket: None,
                retained_byte: Some(file),
                native_tcp: None,
                resource_deadline: None,
                epoll_revision: None,
                retained_poll: None,
                _subscriptions: subscriptions,
                socket_subscriptions: Vec::new(),
                host_subscription: None,
                uring: None,
                poll_uring: None,
                file: None,
                target: target.clone(),
            },
            memory,
            checkpoint_pipe,
        )
    }
    /// Retry the retained request, never the numeric FD. Subscribe only after
    /// contention, then recheck so unlock-before-park cannot be lost.
    pub fn start_flock(
        &self,
        request: trames_vfs::FlockRequest,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        match request.try_lock() {
            Err(Errno(11)) if !request.nonblocking() => {}
            result => return self.complete(32, args, result.map(|()| 0)),
        }
        let signal = IoSignal::new(pid, target.clone());
        let subscriptions = vec![request.subscribe(&signal)];
        self.resume(
            PendingIo {
                aio: None,
                number: 32,
                args,
                deadline: None,
                signal,
                flock: Some(request),
                retained_socket: None,
                retained_byte: None,
                native_tcp: None,
                resource_deadline: None,
                epoll_revision: None,
                retained_poll: None,
                _subscriptions: subscriptions,
                socket_subscriptions: Vec::new(),
                host_subscription: None,
                uring: None,
                poll_uring: None,
                file: None,
                target: target.clone(),
            },
            memory,
        )
    }
    fn epoll_once(
        &self,
        args: [u64; 6],
        deadline: Option<Instant>,
        memory: &mut impl CpuMemory,
    ) -> Result<u64, Errno> {
        let events = self
            .descriptors
            .get(args[0] as u32)
            .unwrap()
            .epoll_wait(args[2] as usize)?;
        if events.is_empty() && !deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(Errno(11));
        }
        epoll_scatter(memory, args[1], &events)
    }
    pub fn resume(&self, pending: PendingIo, memory: &mut impl CpuMemory) -> IoAttempt {
        self.resume_inner(pending, memory, true)
    }
    pub fn resume_owned_byte(&self, pending: PendingIo, memory: &mut impl CpuMemory) -> IoAttempt {
        assert!(pending.retained_byte.is_some());
        self.resume_inner(pending, memory, false)
    }
    fn resume_inner(
        &self,
        mut pending: PendingIo,
        memory: &mut impl CpuMemory,
        checkpoint_pipe: bool,
    ) -> IoAttempt {
        if Self::aio_call(pending.number) {
            return self.start_retained_aio(
                pending.aio.take().expect("accepted AIO"),
                memory,
                pending.signal.pid,
                &pending.target,
            );
        }
        if pending.retained_socket.is_some() {
            return self.resume_socket(pending, memory);
        }
        if let Some(file) = pending.file.take() {
            return self.resume_file(
                file,
                pending.number,
                pending.args,
                pending.signal,
                pending._subscriptions,
                memory,
                &pending.target,
            );
        }
        if pending.uring.is_some() {
            return self.urings.resume(pending, memory);
        }
        pending.signal.reset();
        if let Some(wait) = &pending.retained_poll {
            let revision = wait.epoll_revision();
            if pending.epoll_revision != revision {
                pending._subscriptions = wait.subscribe(&pending.signal);
                pending.poll_uring = None;
                pending.epoll_revision = revision;
            }
        }
        if pending
            ._subscriptions
            .iter()
            .any(|s| s.rearm_host().is_err())
        {
            return IoAttempt::Checkpoint;
        }

        if let Some(request) = &pending.flock {
            return match request.try_lock() {
                Err(Errno(11)) => IoAttempt::Blocked(pending),
                result => self.complete(32, pending.args, result.map(|()| 0)),
            };
        }
        if pending.poll_uring.is_none() {
            let ids = if let Some(poll) = &pending.retained_poll {
                poll.poll_resources()
            } else if matches!(pending.number, 22 | 441) {
                self.descriptors
                    .get(pending.args[0] as u32)
                    .unwrap()
                    .poll_resources()
            } else {
                Vec::new()
            };
            pending.poll_uring = self
                .urings
                .poll_wait(ids, pending.target.clone())
                .map(Box::new);
        }
        if let Some(wait) = &mut pending.poll_uring {
            if !wait.refresh(&pending.signal, memory) {
                return pending
                    .retained_poll
                    .clone()
                    .map_or(IoAttempt::Checkpoint, IoAttempt::WaitCheckpoint);
            }
        }
        if pending
            .host_subscription
            .as_ref()
            .is_some_and(|s| s.rearm().is_err())
        {
            return pending
                .retained_poll
                .clone()
                .map_or(IoAttempt::Checkpoint, IoAttempt::WaitCheckpoint);
        }
        let result = if let Some(fd) = &pending.native_tcp {
            self.transfer_tcp(fd, pending.number, pending.args, memory)
        } else if let Some(file) = &pending.retained_byte {
            let Some(result) = self.transfer_retained(file, pending.number, pending.args, memory)
            else {
                if file.fd.is_pty() || file.fd.is_unix() {
                    return IoAttempt::ByteCheckpoint(pending.retained_byte.take().unwrap());
                }
                return IoAttempt::Checkpoint;
            };
            result
        } else if let Some(poll) = &pending.retained_poll {
            poll.check(memory)
        } else if matches!(pending.number, 22 | 441) {
            epoll_buffer(memory, pending.args)
                .and_then(|()| self.epoll_once(pending.args, pending.deadline, memory))
        } else {
            let Some(result) = self.transfer(pending.number, pending.args, memory) else {
                return IoAttempt::Checkpoint;
            };
            result
        };
        match result {
            Err(Errno(11)) => {
                if (matches!(pending.number, 63..=66 | 206 | 207 | 210..=212 | 269)
                    && pending.retained_byte.as_ref().map_or_else(
                        || {
                            pending.native_tcp.as_ref().map_or_else(
                                || self.nonblocking(pending.number, pending.args),
                                |fd| fd.nonblocking(),
                            )
                        },
                        |file| file.fd.nonblocking(),
                    ))
                    || pending.external_wait()
                        && pending.deadline.is_some_and(|d| Instant::now() >= d)
                {
                    return self.complete_pending(&pending, Err(Errno(11)), memory);
                }
                let resource_deadline = if pending.native_tcp.is_some() {
                    None
                } else if let Some(file) = &pending.retained_byte {
                    file.fd.next_deadline()
                } else if pending.number == 116 {
                    None
                } else if let Some(poll) = &pending.retained_poll {
                    poll.next_deadline()
                } else {
                    self.descriptors
                        .get(pending.args[0] as u32)
                        .and_then(|fd| fd.next_deadline())
                };
                pending.resource_deadline = [
                    resource_deadline,
                    pending.poll_uring.as_ref().and_then(|w| w.deadline),
                ]
                .into_iter()
                .flatten()
                .min();
                IoAttempt::Blocked(pending)
            }
            Err(Errno(32)) if checkpoint_pipe && signals_pipe(pending.number, pending.args) => {
                IoAttempt::Checkpoint
            }
            result => self.complete_pending(&pending, result, memory),
        }
    }
    /// Legacy single-assignment entry. None means no effects and the caller must
    /// use its scheduling/signal path; completed transfers are never replayed.
    pub fn invoke(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        if matches!(number, 28 | 86 | 87) {
            return self.invoke_control(number, args, memory);
        }
        if let Some(file) = self.retain_byte(number, args) {
            let file = match file {
                Ok(file) => file,
                Err(error) => {
                    self.complete(number, args, Err(error));
                    return Some(Err(error));
                }
            };
            return match self.transfer_fd(&file.fd, number, args, memory)? {
                Err(Errno(11)) if !file.fd.nonblocking() => None,
                Err(Errno(32)) if signals_pipe(number, args) => None,
                result => {
                    self.complete_byte(&file, result);
                    Some(result)
                }
            };
        }
        if matches!(number, 63..=66) {
            if let Some(fd) = self.network.get(args[0] as u32) {
                return match self.transfer_tcp(&fd, number, args, memory) {
                    Err(Errno(11)) if !fd.nonblocking() => None,
                    Err(Errno(32)) if signals_pipe(number, args) => None,
                    result => {
                        self.complete_tcp(result);
                        Some(result)
                    }
                };
            }
        }
        if matches!(number, 22 | 32 | 441) || !self.supports_call(number, args) {
            return None;
        }
        if number == 73 {
            let result = match poll_deadline(memory, args[2], None) {
                Ok(deadline) => {
                    let poll = crate::poll::Poll::prepare(&self.descriptors, memory, args)?;
                    if poll.as_ref().is_ok_and(|p| !p.poll_resources().is_empty()) {
                        return None;
                    }
                    poll.and_then(|p| p.check(memory, deadline))
                }
                Err(error) => Err(error),
            };
            if result == Err(Errno(11)) {
                return None;
            }
            self.complete(number, args, result);
            return Some(result);
        }
        match self.transfer(number, args, memory)? {
            Err(Errno(11)) if !self.nonblocking(number, args) => None,
            Err(Errno(32)) if signals_pipe(number, args) => None,
            result => {
                self.complete(number, args, result);
                Some(result)
            }
        }
    }
}

fn poll_deadline(
    memory: &impl CpuMemory,
    address: u64,
    saved: Option<Instant>,
) -> Result<Option<Instant>, Errno> {
    if address == 0 {
        return Ok(saved);
    }
    let timeout = crate::timer::duration(memory, address)?;
    if saved.is_some() {
        Ok(saved)
    } else {
        Instant::now()
            .checked_add(timeout)
            .map(Some)
            .ok_or(Errno(22))
    }
}

fn socket_flags(number: u32, args: [u64; 6]) -> u32 {
    match number {
        206 | 207 | 269 => args[3] as u32,
        211 | 212 => args[2] as u32,
        _ => 0,
    }
}
fn signals_pipe(number: u32, args: [u64; 6]) -> bool {
    matches!(number, 64 | 66)
        || matches!(number, 206 | 211 | 269) && socket_flags(number, args) & 0x4000 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    use trames_vfs::{Vfs, O_NONBLOCK};
    #[test]
    fn membership_changes_resolve_live_slots_and_final_close_before_owner_handoff() {
        let mut v = Vfs::default();
        let [reader, writer] = v.pipe(O_NONBLOCK).unwrap();
        let direct =
            DirectSyscalls::new(v.direct_descriptors()).with_lock_context(v.record_lock_context(1));
        assert_eq!(
            direct.invoke_membership(25, [writer as u64, 1030, 160, 0, 0, 0]),
            Some(Ok(160))
        );
        assert_eq!(
            direct.invoke_membership(24, [160, 200, 0, 0, 0, 0]),
            Some(Ok(200))
        );
        assert_ne!(v.flags(160).unwrap() & trames_vfs::O_CLOEXEC, 0);
        assert_eq!(v.flags(200).unwrap() & trames_vfs::O_CLOEXEC, 0);
        v.write(200, b"live").unwrap();
        assert_eq!(v.read(reader, 4).unwrap(), b"live");
        assert_eq!(
            direct.invoke_membership(24, [writer as u64, reader as u64, 0, 0, 0, 0]),
            Some(Ok(reader as u64))
        );
        assert_eq!(v.write(200, b"x"), Err(Errno(32))); // cached DirectFds did not pin reader
        assert_eq!(
            direct.invoke_membership(57, [writer as u64, 0, 0, 0, 0, 0]),
            Some(Ok(0))
        );
        assert_eq!(v.flags(writer), Err(Errno(9)));
        assert_eq!(direct.fd_control_completed(), 4);
        let (owner, _ring) = v.uring_create(2, 4).unwrap();
        assert_eq!(
            direct.invoke_membership(24, [reader as u64, owner as u64, 0, 0, 0, 0]),
            Some(Ok(owner as u64))
        );
        assert_eq!(v.fd_kind(owner), Ok(trames_vfs::FdKind::PipeWrite));
        assert_eq!(
            direct.invoke_membership(57, [owner as u64, 0, 0, 0, 0, 0]),
            Some(Ok(0))
        );
        assert_eq!(v.fd_kind(owner), Err(Errno(9)));
        assert_eq!(direct.fd_control_completed(), 6);
    }
    #[test]
    fn shared_anonymous_waits_keep_original_event_timer_and_inotify_after_fd_reuse() {
        for kind in 0..3 {
            let mut v = Vfs::default();
            let fd = match kind {
                0 => v.eventfd(0, 0).unwrap(),
                1 => v.timerfd(1, 0).unwrap(),
                _ => {
                    let fd = v.inotify_init(0).unwrap();
                    v.inotify_add(fd, b"/", 0x100).unwrap();
                    fd
                }
            };
            let alias = v.dup(fd, 0, false).unwrap();
            let direct = DirectSyscalls::new(v.direct_descriptors());
            let mut m = memory();
            let target: Arc<dyn IoWake> = Arc::new(Target);
            let wait = pending(
                direct
                    .start(
                        63,
                        [fd as u64, 0x1100, 128, 0, 0, 0],
                        &mut m,
                        1,
                        &Arc::downgrade(&target),
                        None,
                    )
                    .unwrap(),
            );
            assert!(wait.retained_byte.is_some());
            assert_eq!(v.shared_files().close(fd, 1), Some(Ok(())));
            assert_eq!(v.eventfd(9, O_NONBLOCK).unwrap(), fd);
            match kind {
                0 => assert_eq!(v.write(alias, &5u64.to_le_bytes()), Ok(8)),
                1 => {
                    v.timerfd_set(alias, Duration::ZERO, Some(Instant::now()))
                        .unwrap();
                }
                _ => v.mkdir_at(-100, b"/new", 0o700).unwrap(),
            }
            assert_eq!(v.shared_files().close(alias, 1), Some(Ok(())));
            assert!(wait.signal.ready());
            let bytes = complete(direct.resume(wait, &mut m)).unwrap();
            if kind == 2 {
                assert!(bytes >= 16);
                assert_eq!(
                    m.read_array::<4>(0x1104).unwrap(),
                    0x40000100u32.to_le_bytes()
                );
            } else {
                assert_eq!(bytes, 8);
                assert_eq!(m.read_u64(0x1100).unwrap(), if kind == 0 { 5 } else { 1 });
            }
            assert_eq!(v.read(fd, 8).unwrap(), 9u64.to_le_bytes());
            assert_eq!(direct.completed(), 1);
            assert_eq!(direct.timer_completed(), u64::from(kind == 1));
        }
    }
    #[test]
    fn shared_anonymous_completion_uses_accepted_type_when_callbacks_replace_the_slot() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Replace {
            files: trames_vfs::SharedFiles,
            fd: u32,
            replacement: u32,
            called: AtomicBool,
        }
        impl IoWake for Replace {
            fn wake_io(&self, _: &Arc<IoSignal>) {
                if !self.called.swap(true, Ordering::Relaxed) {
                    assert_eq!(
                        self.files.duplicate_to(self.replacement, self.fd, 0, 1),
                        Some(Ok(self.fd))
                    );
                }
            }
        }
        for worker in [false, true] {
            for kind in 0..3 {
                let mut v = Vfs::default();
                let fd = match kind {
                    0 => v.eventfd(0, 0).unwrap(),
                    1 => v.timerfd(1, 0).unwrap(),
                    _ => v.inotify_init(0).unwrap(),
                };
                let wd = (kind == 2).then(|| v.inotify_add(fd, b"/", 0x100).unwrap());
                let replacement = v.eventfd(9, O_NONBLOCK).unwrap();
                let direct = DirectSyscalls::new(v.direct_descriptors());
                let target = Arc::new(Replace {
                    files: v.shared_files(),
                    fd,
                    replacement,
                    called: AtomicBool::new(false),
                });
                let wake: Arc<dyn IoWake> = target.clone();
                let signal = IoSignal::new(1, Arc::downgrade(&wake));
                let _subscriptions = direct.descriptors.get(fd).unwrap().subscribe(&signal);
                let mut m = memory();
                let (number, args, expected) = match kind {
                    0 => {
                        m.write_array(0x1100, 5u64.to_le_bytes()).unwrap();
                        (64, [fd as u64, 0x1100, 8, 0, 0, 0], 8)
                    }
                    1 => (86, [fd as u64, 0, 0x1100, 0, 0, 0], 0),
                    _ => (28, [fd as u64, wd.unwrap() as u64, 0, 0, 0, 0], 0),
                };
                let result = if worker {
                    complete(
                        direct
                            .start(number, args, &mut m, 1, &Arc::downgrade(&wake), None)
                            .unwrap(),
                    )
                } else {
                    direct.invoke(number, args, &mut m).unwrap()
                };
                assert_eq!(result, Ok(expected));
                assert!(target.called.load(Ordering::Relaxed));
                assert_eq!(v.read(fd, 8).unwrap(), 9u64.to_le_bytes());
                assert_eq!(direct.completed(), 1);
                assert_eq!(direct.timer_completed(), u64::from(kind == 1));
                assert_eq!(direct.fd_control_completed(), u64::from(kind == 2));
                // A stale scheduling hint must defer before effects when the
                // actual replacement no longer supports this control syscall.
                if kind != 0 {
                    assert!(direct.invoke(number, args, &mut m).is_none());
                    assert_eq!(direct.completed(), 1);
                }
            }
        }
    }
    #[test]
    fn worker_close_releases_process_locks_then_final_flock_and_close_notification() {
        let mut v = Vfs::default();
        v.set_lock_owner(11);
        let file = v.open_at(-100, b"/file", 0x42, 0o600).unwrap();
        let alias = v.dup(file, 0, false).unwrap();
        let contender = v.open_at(-100, b"/file", 2, 0).unwrap();
        let notify = v.inotify_init(O_NONBLOCK).unwrap();
        v.inotify_add(notify, b"/file", 8).unwrap();
        let close = Arc::downgrade(
            &v.retain_uring_fd(file)
                .unwrap()
                .close_notification()
                .unwrap(),
        );
        let requested = v.normalize_lock(file, 1, 0, 0, 8).unwrap();
        v.record_lock_set(file, requested).unwrap();
        let mut other = requested;
        other.owner = 22;
        assert!(v.record_lock_conflict(contender, other).unwrap().is_some());
        v.flock(file, 6).unwrap();
        let mut epoch = trames_vfs::FileEpoch::default();
        let direct = DirectSyscalls::new(v.direct_descriptors())
            .with_files(epoch.capture(&v, true))
            .with_lock_context(v.record_lock_context(11));
        assert_eq!(
            direct.invoke_membership(57, [alias as u64, 0, 0, 0, 0, 0]),
            Some(Ok(0))
        );
        assert_eq!(v.record_lock_conflict(contender, other).unwrap(), None);
        assert_eq!(v.flock(contender, 6), Err(Errno(11)));
        assert_eq!(v.read(notify, 1024), Err(Errno(11)));
        assert_eq!(
            direct.invoke_membership(57, [file as u64, 0, 0, 0, 0, 0]),
            Some(Ok(0))
        );
        assert!(close.upgrade().is_none());
        assert_eq!(v.flock(contender, 6), Ok(()));
        let event = v.read(notify, 1024).unwrap();
        assert_eq!(u32::from_le_bytes(event[4..8].try_into().unwrap()), 8);
        assert_eq!(v.read(notify, 1024), Err(Errno(11)));
        epoch.finish();
    }
    #[test]
    fn shared_named_fifo_read_keeps_original_ofd_when_replaced_during_the_wait() {
        let mut v = Vfs::default();
        v.mknod_at(-100, b"/fifo", 0o10666, 0).unwrap();
        let reader = v.open_at(-100, b"/fifo", O_NONBLOCK, 0).unwrap();
        let writer = v.open_at(-100, b"/fifo", 1 | O_NONBLOCK, 0).unwrap();
        v.set_status_flags(reader, 0).unwrap();
        let [new_reader, new_writer] = v.pipe(0).unwrap();
        let direct = DirectSyscalls::new(v.direct_descriptors());
        let mut m = memory();
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let wait = pending(
            direct
                .start(
                    63,
                    [reader as u64, 0x1100, 1, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None,
                )
                .unwrap(),
        );
        v.shared_files()
            .duplicate_to(new_reader, reader, 0, 1)
            .unwrap()
            .unwrap();
        assert_eq!(v.write(writer, b"o"), Ok(1));
        v.write(new_writer, b"n").unwrap();
        assert_eq!(complete(direct.resume(wait, &mut m)), Ok(1));
        assert_eq!(m.read_array::<1>(0x1100).unwrap(), *b"o");
        assert_eq!(v.read(reader, 1).unwrap(), b"n");
        assert_eq!(v.write(writer, b"x"), Err(Errno(32)));
    }
    #[test]
    fn shared_named_fifo_ppoll_waits_for_real_data_then_reports_the_original_hangup() {
        let mut v = Vfs::default();
        v.mknod_at(-100, b"/fifo", 0o10666, 0).unwrap();
        let reader = v.open_at(-100, b"/fifo", O_NONBLOCK, 0).unwrap();
        let direct = DirectSyscalls::new(v.direct_descriptors());
        let mut m = memory();
        m.write_array(0x1000, reader.to_le_bytes()).unwrap();
        m.write_array(0x1004, 1u32.to_le_bytes()).unwrap();
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let args = [0x1000, 1, 0, 0, 0, 0];
        let wait = pending(
            direct
                .start(73, args, &mut m, 1, &Arc::downgrade(&target), None)
                .unwrap(),
        );
        assert!(!wait.signal.ready());
        let writer = v.open_at(-100, b"/fifo", 1 | O_NONBLOCK, 0).unwrap();
        v.write(writer, b"x").unwrap();
        assert!(wait.signal.ready());
        assert_eq!(complete(direct.resume(wait, &mut m)), Ok(1));
        assert_eq!(m.read_array::<2>(0x1006).unwrap(), 1u16.to_le_bytes());
        assert_eq!(v.read(reader, 1).unwrap(), b"x");
        v.close(writer).unwrap();
        assert_eq!(
            complete(
                direct
                    .start(73, args, &mut m, 1, &Arc::downgrade(&target), None)
                    .unwrap()
            ),
            Ok(1)
        );
        assert_eq!(m.read_array::<2>(0x1006).unwrap(), 16u16.to_le_bytes());
    }
    #[test]
    fn syslog_subscription_retries_without_lost_wake_and_cancel_drops_listener() {
        use std::sync::atomic::{AtomicU64, Ordering};
        struct Wake {
            log: trames_vfs::KernelLogAccess,
            count: AtomicU64,
        }
        impl IoWake for Wake {
            fn wake_io(&self, _: &Arc<IoSignal>) {
                // Callback must run outside the log lock.
                assert!(self.log.size(9).unwrap() > 0);
                self.count.fetch_add(1, Ordering::Relaxed);
            }
        }
        let mut v = Vfs::default();
        v.set_runtime_info(1, trames_vfs::RuntimeInfo::default());
        let fd = v.open_at(-100, b"/dev/kmsg", 1, 0).unwrap();
        let direct =
            DirectSyscalls::new(v.direct_descriptors()).with_kernel_log(v.kernel_log_capability());
        let target = Arc::new(Wake {
            log: v.kernel_log_capability(),
            count: AtomicU64::new(0),
        });
        let wake: Arc<dyn IoWake> = target.clone();
        let mut m = memory();
        let args = [2, 0x1000, 1024, 0, 0, 0];
        for _ in 0..3 {
            let pending = pending(
                direct
                    .start(116, args, &mut m, 1, &Arc::downgrade(&wake), None)
                    .unwrap(),
            );
            assert!(!pending.signal.ready());
            assert_eq!(
                direct.descriptors.get(fd).unwrap().write(b"wake-reader"),
                Ok(11)
            );
            assert!(pending.signal.ready());
            assert!(matches!(direct.resume(pending, &mut m), IoAttempt::Complete(Ok(n)) if n > 0));
        }
        assert_eq!(target.count.load(Ordering::Relaxed), 3);
        let cancelled = pending(
            direct
                .start(116, args, &mut m, 1, &Arc::downgrade(&wake), None)
                .unwrap(),
        );
        drop(cancelled);
        v.log(4, "cancelled waiter");
        assert_eq!(target.count.load(Ordering::Relaxed), 3);
        assert!(
            matches!(direct.start(116, args, &mut m, 1, &Arc::downgrade(&wake), None), Some(IoAttempt::Complete(Ok(n))) if n > 0)
        );
        assert!(matches!(
            direct.start(
                116,
                [2, 0x1fff, 2, 0, 0, 0],
                &mut m,
                1,
                &Arc::downgrade(&wake),
                None
            ),
            Some(IoAttempt::Complete(Err(Errno(14))))
        ));
    }
    fn memory() -> Memory {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m
    }
    #[test]
    fn native_tcp_vectors_faults_and_blocking_checkpoint_preserve_stream_bytes() {
        use std::{
            io::{Read, Write},
            net::{Ipv4Addr, TcpListener},
        };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut v = Vfs::default();
        v.configure_network(trames_vfs::NetworkMode::Loopback)
            .unwrap();
        let fd = v.socket(2, 1, 0).unwrap();
        let socket = v.socket_fd(fd).unwrap();
        assert!(matches!(
            socket.connect(listener.local_addr().unwrap()),
            Ok(()) | Err(trames_net::NetError(115))
        ));
        let (mut peer, _) = listener.accept().unwrap();
        assert_eq!(socket.connect_complete(), Ok(true));
        let direct = DirectSyscalls::new(v.direct_descriptors()).with_network(v.direct_network());
        let mut m = memory();
        let target: Arc<dyn IoWake> = Arc::new(Target);
        assert!(matches!(
            direct.start(
                63,
                [fd as u64, 0x1100, 4, 0, 0, 0],
                &mut m,
                1,
                &Arc::downgrade(&target),
                None
            ),
            Some(IoAttempt::Checkpoint)
        ));
        assert_eq!(direct.completed(), 0);
        assert_eq!(
            direct.invoke(64, [fd as u64, 0x1fff, 2, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        m.write(0x1100, b"abcd").unwrap();
        for (address, value) in [
            (0x1200, 0x1100u64),
            (0x1208, 1),
            (0x1210, 0x1101),
            (0x1218, 3),
        ] {
            m.write_array(address, value.to_le_bytes()).unwrap();
        }
        assert_eq!(
            direct.invoke(66, [fd as u64, 0x1200, 2, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        let mut actual = [0; 4];
        peer.read_exact(&mut actual).unwrap();
        assert_eq!(&actual, b"abcd");
        peer.write_all(b"wxyz").unwrap();
        trames_net::wait(&[(socket.clone(), 1)], Duration::from_secs(2)).unwrap();
        assert_eq!(
            direct.invoke(63, [fd as u64, 0x1fff, 4, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert_eq!(
            direct.invoke(65, [fd as u64, 0x1200, 2, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        assert_eq!(m.read_array::<4>(0x1100).unwrap(), *b"wxyz");
        assert!(!direct.supports(22, fd));
        assert!(!direct.supports(206, fd));
        let before = direct.socket_completed();
        v.set_status_flags(fd, v.flags(fd).unwrap() | O_NONBLOCK)
            .unwrap();
        assert_eq!(
            direct.invoke(63, [fd as u64, 0x1100, 1, 0, 0, 0], &mut m),
            Some(Err(Errno(11)))
        );
        assert_eq!(direct.socket_completed(), before + 1);
    }
    #[test]
    fn pty_vectors_queries_and_faults_preserve_bytes_and_original_abi() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, Default::default());
        let master = v
            .open_at(trames_vfs::AT_FDCWD, b"/dev/ptmx", 2 | O_NONBLOCK, 0)
            .unwrap();
        v.pty(master)
            .unwrap()
            .unwrap()
            .pair
            .locked
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let slave = v.open_pty_peer(master, 2 | O_NONBLOCK).unwrap();
        let direct =
            DirectSyscalls::new(v.direct_descriptors()).with_terminal(trames_vfs::TerminalAccess {
                session: 0,
                group: 0,
                controlling: None,
                ignore_ttou: false,
            });
        let mut m = memory();
        m.write(0x1100, b"ab\nc").unwrap();
        for (at, value) in [
            (0x1200, 0x1100u64),
            (0x1208, 2),
            (0x1210, 0x1102),
            (0x1218, 2),
        ] {
            m.write_array(at, value.to_le_bytes()).unwrap();
        }
        assert_eq!(
            direct.invoke(66, [slave as u64, 0x1200, 2, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        assert_eq!(
            direct.invoke(29, [master as u64, 0x541b, 0x1300, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        assert_eq!(m.read_array::<4>(0x1300).unwrap(), 5u32.to_le_bytes());
        assert_eq!(
            direct.invoke(63, [master as u64, 0x1ffe, 5, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert_eq!(
            direct.invoke(65, [master as u64, 0x1200, 2, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        assert_eq!(m.read_array::<4>(0x1100).unwrap(), *b"ab\r\n");
        assert_eq!(
            direct.invoke(63, [master as u64, 0x1100, 1, 0, 0, 0], &mut m),
            Some(Ok(1))
        );
        assert_eq!(m.read_array::<1>(0x1100).unwrap(), *b"c");
        let queries = {
            let end = v.pty(slave).unwrap().unwrap();
            let tty = end.pair.terminal.borrow();
            [
                (0x5401, tty.attributes.to_vec()),
                (0x5413, tty.window.to_vec()),
            ]
        };
        for (request, expected) in queries {
            assert_eq!(
                direct.invoke(29, [slave as u64, request, 0x1fff, 0, 0, 0], &mut m),
                Some(Err(Errno(14)))
            );
            assert_eq!(
                direct.invoke(29, [slave as u64, request, 0x1400, 0, 0, 0], &mut m),
                Some(Ok(0))
            );
            let mut out = vec![0; expected.len()];
            m.read(0x1400, &mut out).unwrap();
            assert_eq!(out, expected);
        }
        assert!(!direct.supports_call(29, [slave as u64, 0x5402, 0, 0, 0, 0]));
        m.write(0x1100, b"safe\x03").unwrap();
        assert_eq!(
            direct.invoke(64, [master as u64, 0x1100, 5, 0, 0, 0], &mut m),
            None
        );
        assert_eq!(
            direct.invoke(63, [slave as u64, 0x1100, 1, 0, 0, 0], &mut m),
            Some(Err(Errno(11)))
        );
    }
    #[test]
    fn pty_peer_creation_preserves_type_flags_lock_limit_and_permission_order() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, Default::default());
        let master = v.open_at(trames_vfs::AT_FDCWD, b"/dev/ptmx", 2, 0).unwrap();
        let pair = v.pty(master).unwrap().unwrap().pair.clone();
        let mut m = memory();
        let invoke = |v: &Vfs, fd, flags, m: &mut Memory| {
            DirectSyscalls::new(v.direct_descriptors())
                .with_resources(v.descriptor_factory())
                .invoke(29, [fd as u64, 0x5441, flags as u64, 0, 0, 0], m)
        };
        v.set_descriptor_limit(master + 1);
        assert_eq!(invoke(&v, master, 0, &mut m), Some(Err(Errno(22))));
        assert_eq!(invoke(&v, master, 2, &mut m), Some(Err(Errno(5))));
        pair.locked
            .store(false, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(invoke(&v, master, 2, &mut m), Some(Err(Errno(24))));
        v.set_descriptor_limit(master + 4);
        let slave = invoke(&v, master, 2 | trames_vfs::O_CLOEXEC | O_NONBLOCK, &mut m)
            .unwrap()
            .unwrap() as u32;
        assert_eq!(
            v.flags(slave).unwrap() & (trames_vfs::O_CLOEXEC | O_NONBLOCK),
            trames_vfs::O_CLOEXEC | O_NONBLOCK
        );
        assert_eq!(invoke(&v, slave, 0, &mut m), Some(Err(Errno(25))));
        v.close(slave).unwrap();
        v.credentials = trames_vfs::Credentials::user(1000, 1000);
        assert_eq!(invoke(&v, master, 2, &mut m), Some(Err(Errno(13))));
        assert_eq!(v.eventfd(0, 0).unwrap(), slave);
    }

    #[test]
    fn pty_short_controls_keep_original_endpoint_fault_order_and_shared_state() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, Default::default());
        let master = v.open_at(trames_vfs::AT_FDCWD, b"/dev/ptmx", 2, 0).unwrap();
        let pair = v.pty(master).unwrap().unwrap().pair.clone();
        pair.locked
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let slave = v.open_pty_peer(master, 2).unwrap();
        let alias = v.dup(master, 0, false).unwrap();
        let direct = DirectSyscalls::new(v.direct_descriptors());
        let mut m = memory();
        for request in [0x80045430, 0x40045431, 0x80045439, 0x5420, 0x80045438] {
            assert_eq!(
                direct.invoke(29, [slave as u64, request, 0, 0, 0, 0], &mut m),
                Some(Err(Errno(25)))
            );
            assert_eq!(
                direct.invoke(29, [alias as u64, request, 0x1fff, 0, 0, 0], &mut m),
                Some(Err(Errno(14)))
            );
        }
        assert!(!pair.locked.load(std::sync::atomic::Ordering::Relaxed));
        assert!(!pair.packet.load(std::sync::atomic::Ordering::Relaxed));
        for (set, get) in [(0x40045431, 0x80045439), (0x5420, 0x80045438)] {
            m.write_array(0x1100, 7u32.to_le_bytes()).unwrap();
            assert_eq!(
                direct.invoke(29, [alias as u64, set, 0x1100, 0, 0, 0], &mut m),
                Some(Ok(0))
            );
            assert_eq!(
                direct.invoke(29, [master as u64, get, 0x1200, 0, 0, 0], &mut m),
                Some(Ok(0))
            );
            assert_eq!(m.read_array::<4>(0x1200).unwrap(), 1u32.to_le_bytes());
        }
        v.close(alias).unwrap();
        assert_eq!(
            v.open_at(trames_vfs::AT_FDCWD, b"/replacement", 0x42, 0o600)
                .unwrap(),
            alias
        );
        assert_eq!(
            direct.invoke(29, [alias as u64, 0x80045430, 0x1200, 0, 0, 0], &mut m),
            None
        );
        assert_eq!(
            direct.invoke(29, [master as u64, 0x80045430, 0x1200, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        assert_eq!(
            m.read_array::<4>(0x1200).unwrap(),
            pair.number.to_le_bytes()
        );
        assert!(!direct.supports_call(29, [master as u64, 0x5441, 2, 0, 0, 0]));
    }
    #[test]
    fn timer_control_preflights_outputs_and_keeps_relative_and_absolute_state() {
        let mut vfs = Vfs::default();
        let fd = vfs.timerfd(1, 0).unwrap();
        let started = Instant::now();
        let direct = DirectSyscalls::new(vfs.direct_descriptors()).with_clock(started);
        let mut m = memory();
        m.write_array(0x1110, 3600u64.to_le_bytes()).unwrap();
        assert_eq!(
            direct.invoke(86, [fd as u64, 0, 0x1100, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        assert_eq!(
            direct.invoke(87, [fd as u64, 0x1200, 0, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        assert!(m.read_u64(0x1210).unwrap() >= 3599);
        assert_eq!(
            direct.invoke(86, [fd as u64, 0, 0x1100, 0x2000, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert!(vfs.timerfd_get(fd).unwrap().1.as_secs() >= 3599);
        assert_eq!(
            direct.invoke(86, [fd as u64, 2, 0x1100, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        assert_eq!(
            direct.invoke(86, [fd as u64, 1, 0x1100, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        let old_deadline = vfs.timerfd_resource(fd).unwrap().update(None).1;
        assert!(old_deadline.as_secs() >= 3599);
        vfs.timerfd_set(fd, Duration::ZERO, Some(Instant::now()))
            .unwrap();
        assert_eq!(
            direct.invoke(63, [fd as u64, 0x1300, 7, 0, 0, 0], &mut m),
            Some(Err(Errno(22)))
        );
        assert_eq!(
            direct.invoke(63, [fd as u64, 0x1300, 8, 0, 0, 0], &mut m),
            Some(Ok(8))
        );
        assert_eq!(m.read_u64(0x1300).unwrap(), 1);
    }
    #[test]
    fn worker_created_resources_wait_on_the_original_ofd_after_close_and_reuse() {
        for kind in 0..4 {
            let mut v = Vfs::default();
            let direct =
                DirectSyscalls::new(v.direct_descriptors()).with_resources(v.descriptor_factory());
            let mut m = memory();
            let mut writer = None;
            let fd = match kind {
                0 => direct.invoke_creation(19, [0; 6], &mut m).unwrap().unwrap() as u32,
                1 => direct
                    .invoke_creation(85, [1, 0, 0, 0, 0, 0], &mut m)
                    .unwrap()
                    .unwrap() as u32,
                2 => {
                    assert_eq!(
                        direct.invoke_creation(59, [0x1100, 0, 0, 0, 0, 0], &mut m),
                        Some(Ok(0))
                    );
                    let r = m.read_array::<8>(0x1100).unwrap();
                    writer = Some(u32::from_le_bytes(r[4..].try_into().unwrap()));
                    u32::from_le_bytes(r[..4].try_into().unwrap())
                }
                _ => direct.invoke_creation(26, [0; 6], &mut m).unwrap().unwrap() as u32,
            };
            if kind == 3 {
                v.inotify_add(fd, b"/", 0x100).unwrap();
            }
            let target: Arc<dyn IoWake> = Arc::new(Target);
            let wait = pending(
                direct
                    .start(
                        63,
                        [fd as u64, 0x1200, if kind == 3 { 128 } else { 8 }, 0, 0, 0],
                        &mut m,
                        1,
                        &Arc::downgrade(&target),
                        None,
                    )
                    .unwrap(),
            );
            let alias = v.dup(fd, 0, false).unwrap();
            v.close(fd).unwrap();
            assert_eq!(
                direct.invoke_creation(19, [9, trames_vfs::O_NONBLOCK as u64, 0, 0, 0, 0], &mut m),
                Some(Ok(fd as u64))
            );
            m.write_array(0x1100, 7u64.to_le_bytes()).unwrap();
            match kind {
                0 => assert_eq!(
                    direct.invoke(64, [alias as u64, 0x1100, 8, 0, 0, 0], &mut m),
                    Some(Ok(8))
                ),
                1 => {
                    assert_eq!(v.next_timerfd_deadline(), None);
                    v.timerfd_set(alias, Duration::ZERO, Some(Instant::now()))
                        .unwrap();
                    assert!(v.next_timerfd_deadline().is_some());
                }
                2 => assert_eq!(
                    direct.invoke(64, [writer.unwrap() as u64, 0x1100, 1, 0, 0, 0], &mut m),
                    Some(Ok(1))
                ),
                _ => v.import_file(b"/created", vec![]).unwrap(),
            }
            assert!(wait.signal.ready());
            let IoAttempt::Complete(result) = direct.resume(wait, &mut m) else {
                panic!("new resource wait did not wake")
            };
            assert!(result.unwrap() > 0);
            v.close(alias).unwrap();
            v.close(fd).unwrap();
            if let Some(writer) = writer {
                v.close(writer).unwrap();
            }
        }
    }
    #[test]
    fn timer_rearm_and_disarm_refresh_a_parked_reads_resource_deadline() {
        let mut v = Vfs::default();
        let fd = v.timerfd(1, 0).unwrap();
        let direct = DirectSyscalls::new(v.direct_descriptors());
        let first = Instant::now() + Duration::from_secs(3600);
        v.timerfd_set(fd, Duration::ZERO, Some(first)).unwrap();
        let mut m = memory();
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let wait = pending(
            direct
                .start(
                    63,
                    [fd as u64, 0x1100, 8, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None,
                )
                .unwrap(),
        );
        assert_eq!(wait.deadline, None);
        assert_eq!(wait.wake_deadline(), Some(first));
        let next = first + Duration::from_secs(3600);
        v.timerfd_set(fd, Duration::ZERO, Some(next)).unwrap();
        assert!(wait.signal.ready());
        let wait = pending(direct.resume(wait, &mut m));
        assert_eq!(wait.wake_deadline(), Some(next));
        v.timerfd_set(fd, Duration::ZERO, None).unwrap();
        assert!(wait.signal.ready());
        let wait = pending(direct.resume(wait, &mut m));
        assert_eq!(wait.wake_deadline(), None);
        drop(wait);
        assert_eq!(direct.timer_completed(), 0);
    }
    #[test]
    fn ppoll_mixed_resources_preflight_defer_and_preserve_timeout_and_mask_boundaries() {
        let mut v = Vfs::default();
        let [r, w] = v.pipe(0).unwrap();
        let event = v.eventfd(1, 0).unwrap();
        let [a, b] = v.socketpair(1, 1, 0).unwrap();
        let direct = DirectSyscalls::new(v.direct_descriptors());
        let mut m = memory();
        for (i, fd) in [r, event, a, u32::MAX].into_iter().enumerate() {
            let at = 0x1100 + i as u64 * 8;
            m.write_array(at, fd.to_le_bytes()).unwrap();
            m.write_array(at + 4, 0xaabb0001u32.to_le_bytes()).unwrap();
        }
        v.write(w, b"p").unwrap();
        v.write(b, b"s").unwrap();
        let args = [0x1100, 4, 0, 0, 0, 0];
        assert_eq!(direct.invoke(73, args, &mut m), Some(Ok(3)));
        for i in 0..4 {
            assert_eq!(
                m.read_array::<2>(0x1106 + i * 8).unwrap(),
                (if i < 3 { 1u16 } else { 0 }).to_le_bytes()
            );
        }
        let before = m.read_array::<32>(0x1100).unwrap();
        m.write_array(0x1118, 999u32.to_le_bytes()).unwrap();
        assert_eq!(direct.invoke(73, args, &mut m), None);
        assert_eq!(m.read_array::<24>(0x1100).unwrap(), before[..24]);
        assert_eq!(
            direct.invoke(73, [0x1ffc, 1, 0, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert!(direct.supports_call(73, [0, 0, 0, 0x1200, 8, 0]));
        assert_eq!(
            direct.invoke(73, [0, 0, 0x1200, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        assert_eq!(v.read(r, 1).unwrap(), b"p");
        assert_eq!(v.read(a, 1).unwrap(), b"s");
    }
    #[test]
    fn accepted_ppoll_keeps_original_pipe_after_close_and_numeric_reuse() {
        let mut v = Vfs::default();
        let [reader, writer] = v.pipe(0).unwrap();
        let direct = DirectSyscalls::new(v.direct_descriptors());
        let mut m = memory();
        m.write_array(0x1100, reader.to_le_bytes()).unwrap();
        m.write_array(0x1104, 1u32.to_le_bytes()).unwrap();
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let wait = pending(
            direct
                .start(
                    73,
                    [0x1100, 1, 0, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None,
                )
                .unwrap(),
        );
        v.close(reader).unwrap();
        let [replacement, new_writer] = v.pipe(0).unwrap();
        assert_eq!(replacement, reader);
        v.write(new_writer, b"new").unwrap();
        let wait = pending(direct.resume(wait, &mut m));
        v.write(writer, b"old").unwrap();
        assert!(wait.signal.ready());
        assert_eq!(complete(direct.resume(wait, &mut m)), Ok(1));
        assert_eq!(m.read_array::<2>(0x1106).unwrap(), 1u16.to_le_bytes());
        assert_eq!(v.write(writer, b"x"), Err(Errno(32)));
        assert_eq!(v.read(replacement, 3).unwrap(), b"new");
    }
    #[test]
    fn ppoll_checkpoint_rearms_original_set_without_reimporting_changed_guest_buffers() {
        let mut v = Vfs::default();
        let [reader, writer] = v.pipe(0).unwrap();
        let direct = DirectSyscalls::new(v.direct_descriptors());
        let mut m = memory();
        m.map(0x3000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write_array(0x3000, 60u64.to_le_bytes()).unwrap();
        m.write_array(0x3008, 0u64.to_le_bytes()).unwrap();
        m.write_array(0x1100, reader.to_le_bytes()).unwrap();
        m.write_array(0x1104, 1u32.to_le_bytes()).unwrap();
        let args = [0x1100, 1, 0x3000, 0, 0, 0];
        let first: Arc<dyn IoWake> = Arc::new(Target);
        let wait = pending(
            direct
                .start(73, args, &mut m, 1, &Arc::downgrade(&first), None)
                .unwrap(),
        );
        let original_signal = wait.signal.clone();
        let deadline = wait.deadline;
        let accepted = wait.retained_poll.clone().unwrap();
        drop(wait);
        v.close(reader).unwrap();
        let [replacement, new_writer] = v.pipe(0).unwrap();
        assert_eq!(replacement, reader);
        v.write(new_writer, b"new").unwrap();
        m.write_array(0x1100, writer.to_le_bytes()).unwrap();
        m.write_array(0x1104, 4u32.to_le_bytes()).unwrap();
        m.unmap(0x3000, PAGE_SIZE).unwrap();
        let fresh = DirectSyscalls::new(v.direct_descriptors());
        let next: Arc<dyn IoWake> = Arc::new(Target);
        let wait = pending(fresh.start_retained_poll(
            accepted,
            args,
            &mut m,
            1,
            &Arc::downgrade(&next),
            deadline,
        ));
        assert_eq!(wait.deadline, deadline);
        assert!(!wait.signal.ready());
        v.write(writer, b"old").unwrap();
        assert!(wait.signal.ready());
        assert!(!original_signal.ready());
        assert_eq!(complete(fresh.resume(wait, &mut m)), Ok(1));
        assert_eq!(m.read_array::<4>(0x1100).unwrap(), writer.to_le_bytes());
        assert_eq!(m.read_array::<2>(0x1104).unwrap(), 4u16.to_le_bytes());
        assert_eq!(m.read_array::<2>(0x1106).unwrap(), 1u16.to_le_bytes());
        assert_eq!(v.write(writer, b"x"), Err(Errno(32)));
        assert_eq!(v.read(replacement, 3).unwrap(), b"new");
    }

    #[test]
    fn epoll_wait_retains_original_epoll_after_close_reuse_and_new_epoch() {
        let mut v = Vfs::default();
        let event = v.eventfd(0, 0).unwrap();
        let ep = v.epoll_create(0).unwrap();
        v.epoll_ctl(ep, 1, event, 1, 42).unwrap();
        let mut m = memory();
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let direct = DirectSyscalls::new(v.direct_descriptors());
        let args = [ep as u64, 0x1100, 1, u64::MAX, 0, 0];
        let wait = pending(
            direct
                .start(22, args, &mut m, 1, &Arc::downgrade(&target), None)
                .unwrap(),
        );
        v.close(ep).unwrap();
        let replacement = v.epoll_create(0).unwrap();
        assert_eq!(replacement, ep);
        let ready = v.eventfd(1, 0).unwrap();
        v.epoll_ctl(replacement, 1, ready, 1, 999).unwrap();
        assert!(!wait.signal.ready());
        v.write(event, &1u64.to_le_bytes()).unwrap();
        assert!(wait.signal.ready());
        let fresh = DirectSyscalls::new(v.direct_descriptors());
        assert_eq!(complete(fresh.resume(wait, &mut m)), Ok(1));
        assert_eq!(m.read_u64(0x1108).unwrap(), 42);
        assert_eq!(
            v.epoll_wait(replacement, 1, |_, _| Ok(None)).unwrap(),
            vec![(1, 999)]
        );
    }
    #[test]
    fn eventless_regular_file_poll_retains_the_complete_accepted_ofd_until_cancel() {
        let mut v = Vfs::default();
        let fd = v.open_at(-100, b"/poll-file", 0x42, 0o600).unwrap();
        let contender = v.open_at(-100, b"/poll-file", 2, 0).unwrap();
        v.flock(fd, 6).unwrap();
        let direct = DirectSyscalls::new(v.direct_descriptors());
        let mut m = memory();
        m.write_array(0x1100, fd.to_le_bytes()).unwrap();
        m.write_array(0x1104, 0u32.to_le_bytes()).unwrap();
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let wait = pending(
            direct
                .start(
                    73,
                    [0x1100, 1, 0, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None,
                )
                .unwrap(),
        );
        v.close(fd).unwrap();
        assert_eq!(v.flock(contender, 6), Err(Errno(11)));
        drop(wait);
        v.flock(contender, 6).unwrap();
    }
    fn unix_message(memory: &mut Memory, control_size: u64) {
        for (address, value) in [
            (0x1010, 0x1080u64),
            (0x1018, 2),
            (0x1020, 0x1300),
            (0x1028, control_size),
            (0x1080, 0x1100),
            (0x1088, 2),
            (0x1090, 0x1102),
            (0x1098, 2),
        ] {
            memory.write_array(address, value.to_le_bytes()).unwrap();
        }
        memory.write(0x1100, b"abcd").unwrap();
    }
    #[test]
    fn unix_scalar_and_message_bytes_match_the_original_socket_abi() {
        for number in [206, 207, 211, 212] {
            for flags in [
                0,
                if matches!(number, 207 | 212) {
                    2
                } else {
                    0x4000
                },
            ] {
                let mut results = Vec::new();
                for worker in [false, true] {
                    let mut linux = Linux::new(0x10000);
                    let [fd, peer] = linux.vfs.socketpair(1, 1, 0).unwrap();
                    let mut m = memory();
                    let receive = matches!(number, 207 | 212);
                    unix_message(&mut m, if receive { 32 } else { 0 });
                    m.write_array(0x1260, 2u32.to_le_bytes()).unwrap();
                    if receive {
                        linux.vfs.write(peer, b"wxyz").unwrap();
                    }
                    let args = if number < 210 {
                        [
                            fd as u64,
                            0x1100,
                            4,
                            flags,
                            if receive { 0x1250 } else { 0 },
                            0x1260,
                        ]
                    } else {
                        [fd as u64, 0x1000, flags, 0, 0, 0]
                    };
                    let result = if worker {
                        let direct = DirectSyscalls::new(linux.vfs.direct_descriptors());
                        let result = direct.invoke(number, args, &mut m).expect("byte-only call");
                        assert_eq!(direct.socket_completed(), 1);
                        result
                    } else {
                        linux.network_syscall(number as u64, args, &mut m)
                    };
                    assert_eq!(result, Ok(4));
                    let queued = if receive {
                        linux.vfs.readable_bytes(fd).unwrap().unwrap() as u64
                    } else {
                        assert_eq!(linux.vfs.read(peer, 4).unwrap(), b"abcd");
                        0
                    };
                    results.push((m.read_array::<1024>(0x1000).unwrap(), queued));
                }
                assert_eq!(results[0], results[1], "number={number} flags={flags}");
            }
        }
    }
    #[test]
    fn unix_preflight_waitall_nonblocking_shutdown_and_sigpipe_keep_their_boundaries() {
        let mut vfs = Vfs::default();
        let [fd, peer] = vfs.socketpair(1, 1, 0).unwrap();
        let direct = DirectSyscalls::new(vfs.direct_descriptors());
        let mut m = memory();
        unix_message(&mut m, 0);
        vfs.write(peer, b"ab").unwrap();
        m.write_array(0x1090, 0x2000u64.to_le_bytes()).unwrap();
        assert_eq!(
            direct.invoke(212, [fd as u64, 0x1000, 0, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert_eq!(vfs.readable_bytes(fd).unwrap(), Some(2));
        assert_eq!(
            direct.invoke(207, [fd as u64, 0x1100, 4, 0x100, 0, 0], &mut m),
            None
        );
        assert_eq!(vfs.readable_bytes(fd).unwrap(), Some(2));
        assert_eq!(
            direct.invoke(29, [fd as u64, 0x541b, 0x1180, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        assert_eq!(m.read_array::<4>(0x1180).unwrap(), 2u32.to_le_bytes());
        assert!(!direct.supports_call(29, [fd as u64, 0x1234, 0, 0, 0, 0]));
        assert_eq!(
            direct.invoke(207, [fd as u64, 0x1100, 4, 0x140, 0, 0], &mut m),
            Some(Ok(2))
        );
        assert_eq!(
            direct.invoke(207, [fd as u64, 0x1100, 4, 0x40, 0, 0], &mut m),
            Some(Err(Errno(11)))
        );
        assert_eq!(
            direct.invoke(210, [peer as u64, 1, 0, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        assert_eq!(
            direct.invoke(207, [fd as u64, 0x1100, 4, 0x100, 0, 0], &mut m),
            Some(Ok(0))
        );
        vfs.close(peer).unwrap();
        assert_eq!(
            direct.invoke(206, [fd as u64, 0x1100, 1, 0, 0, 0], &mut m),
            None
        );
        assert_eq!(
            direct.invoke(206, [fd as u64, 0x1100, 1, 0x4000, 0, 0], &mut m),
            Some(Err(Errno(32)))
        );
    }
    #[test]
    fn unix_message_rights_defer_before_bytes_and_use_the_original_owner_once() {
        let mut linux = Linux::new(0x10000);
        let [fd, peer] = linux.vfs.socketpair(1, 1, 0).unwrap();
        let [reader, writer] = linux.vfs.pipe(0).unwrap();
        let direct = DirectSyscalls::new(linux.vfs.direct_descriptors());
        let mut m = memory();
        unix_message(&mut m, 24);
        m.write_array(0x1300, 20u64.to_le_bytes()).unwrap();
        m.write_array(0x1308, 1u32.to_le_bytes()).unwrap();
        m.write_array(0x130c, 1u32.to_le_bytes()).unwrap();
        m.write_array(0x1310, writer.to_le_bytes()).unwrap();
        let args = [fd as u64, 0x1000, 0, 0, 0, 0];
        assert_eq!(direct.invoke(211, args, &mut m), None);
        assert_eq!(linux.vfs.readable_bytes(peer).unwrap(), Some(0));
        let receive = [peer as u64, 0x1000, 0x40000000, 0, 0, 0];
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let pending = pending(
            direct
                .start(212, receive, &mut m, 7, &Arc::downgrade(&target), None)
                .unwrap(),
        );
        assert_eq!(linux.network_syscall(211, args, &mut m), Ok(4));
        assert!(pending.signal.ready());
        assert!(matches!(
            direct.resume(pending, &mut m),
            IoAttempt::Checkpoint
        ));
        assert_eq!(linux.vfs.readable_bytes(peer).unwrap(), Some(4));
        assert_eq!(linux.network_syscall(212, receive, &mut m), Ok(4));
        let received = u32::from_le_bytes(m.read_array(0x1310).unwrap());
        assert_ne!(
            linux.vfs.flags(received).unwrap() & trames_vfs::O_CLOEXEC,
            0
        );
        linux.vfs.close(writer).unwrap();
        linux.vfs.write(received, b"still alive").unwrap();
        assert_eq!(linux.vfs.read(reader, 16).unwrap(), b"still alive");
        assert_eq!(direct.socket_completed(), 0);
    }
    #[test]
    fn file_scalar_vector_positioned_seek_and_stat_share_the_original_abi() {
        for number in 63..=70 {
            let mut vfs = Vfs::default();
            vfs.import_file(b"/data", b"abcdefgh".to_vec()).unwrap();
            let fd = vfs.open_at(trames_vfs::AT_FDCWD, b"/data", 2, 0).unwrap();
            let mut epoch = trames_vfs::FileEpoch::default();
            let direct =
                DirectSyscalls::new(vfs.direct_descriptors()).with_files(epoch.capture(&vfs, true));
            let mut m = memory();
            m.write(0x1100, b"1234").unwrap();
            for (address, value) in [(0x1000, 0x1100), (0x1008, 2), (0x1010, 0x1102), (0x1018, 2)] {
                m.write_array(address, (value as u64).to_le_bytes())
                    .unwrap();
            }
            let vector = matches!(number, 65 | 66 | 69 | 70);
            let args = [
                fd as u64,
                if vector { 0x1000 } else { 0x1100 },
                if vector { 2 } else { 4 },
                2,
                0,
                0,
            ];
            assert_eq!(direct.invoke_file(number, args, &mut m), Some(Ok(4)));
            assert_eq!(vfs.seek(fd, 0, 1).unwrap(), if number < 67 { 4 } else { 0 });
            if number % 2 == 0 {
                assert_eq!(
                    vfs.pread(fd, 8, 0).unwrap(),
                    if number < 67 {
                        b"1234efgh"
                    } else {
                        b"ab1234gh"
                    }
                );
            } else {
                assert_eq!(
                    m.read_array::<4>(0x1100).unwrap(),
                    if number < 67 { *b"abcd" } else { *b"cdef" }
                );
            }
            assert_eq!(
                direct.invoke_file(80, [fd as u64, 0x1200, 0, 0, 0, 0], &mut m),
                Some(Ok(0))
            );
            assert_eq!(
                m.read_array::<128>(0x1200).unwrap(),
                vfs.stat_fd(fd).unwrap()
            );
            assert_eq!(
                direct.invoke_file(62, [fd as u64, 0, 1, 0, 0, 0], &mut m),
                Some(Ok(if number < 67 { 4 } else { 0 }))
            );
            assert_eq!(direct.file_completed(), 3);
            epoch.finish();
        }
    }
    #[test]
    fn file_preflight_and_source_growth_never_consume_a_partial_vector() {
        let mut vfs = Vfs::default();
        vfs.import_file(b"/data", b"abcd".to_vec()).unwrap();
        let fd = vfs.open_at(trames_vfs::AT_FDCWD, b"/data", 2, 0).unwrap();
        let mut epoch = trames_vfs::FileEpoch::default();
        let direct =
            DirectSyscalls::new(vfs.direct_descriptors()).with_files(epoch.capture(&vfs, true));
        let mut m = memory();
        m.write(0x1100, b"12345678").unwrap();
        for (address, value) in [(0x1000, 0x1100), (0x1008, 2), (0x1010, 0x2000), (0x1018, 2)] {
            m.write_array(address, (value as u64).to_le_bytes())
                .unwrap();
        }
        assert_eq!(
            direct.invoke_file(70, [fd as u64, 0x1000, 2, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert_eq!(vfs.pread(fd, 8, 0).unwrap(), b"abcd");
        assert_eq!(
            direct.invoke_file(64, [fd as u64, 0x1100, 8, 0, 0, 0], &mut m),
            Some(Ok(8))
        );
        assert_eq!(vfs.seek(fd, 0, 1).unwrap(), 8);
        assert_eq!(vfs.pread(fd, 8, 0).unwrap(), b"12345678");
        vfs.seek(fd, 0, 0).unwrap();
        assert_eq!(
            direct.invoke_file(63, [fd as u64, 0x1100, 8, 0, 0, 0], &mut m),
            Some(Ok(8))
        );
        assert_eq!(m.read_array::<8>(0x1100).unwrap(), *b"12345678");
        assert_eq!(
            direct.invoke_file(67, [fd as u64, 0x2000, 8, u64::MAX, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert_eq!(
            direct.invoke_file(69, [fd as u64, 0x2000, 2, u64::MAX, 0, 0], &mut m),
            Some(Err(Errno(22)))
        );
        epoch.finish();
    }
    #[test]
    fn blocking_flock_notification_and_retry_keep_original_lease_after_fd_reuse() {
        let mut v = Vfs::default();
        let a = v.open_at(-100, b"/lock", 0x42, 0o600).unwrap();
        let b = v.open_at(-100, b"/lock", 2, 0).unwrap();
        v.flock(a, 5).unwrap();
        v.flock(b, 5).unwrap();
        let mut files = trames_vfs::FileEpoch::default();
        let direct =
            DirectSyscalls::new(v.direct_descriptors()).with_files(files.capture(&v, true));
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let mut m = memory();
        let args = [a as u64, 2, 0, 0, 0, 0];
        // Legacy dispatch cannot speculatively release a conversion's old SH.
        assert!(direct.invoke_file(32, args, &mut m).is_none());
        assert_eq!(v.flock(b, 6), Err(Errno(11)));
        v.flock(b, 5).unwrap();
        let wait = pending(
            direct
                .start(32, args, &mut m, 1, &Arc::downgrade(&target), None)
                .unwrap(),
        );
        assert!(!wait.signal.ready());
        // The failed EX conversion released a's SH, allowing b to convert.
        v.flock(b, 6).unwrap();
        let request = wait.flock.as_ref().unwrap().clone();
        let (_, retained) = v.retain_flock(a, 2).unwrap();
        v.close(a).unwrap();
        let reused = v.open_at(-100, b"/new", 0x42, 0o600).unwrap();
        assert_eq!(reused, a);
        v.flock(reused, 6).unwrap();
        v.flock(b, 8).unwrap();
        assert!(wait.signal.ready());
        assert_eq!(complete(direct.resume(wait, &mut m)), Ok(0));
        assert_eq!(v.flock(b, 6), Err(Errno(11)));
        assert_eq!(direct.fd_control_completed(), 1);
        drop(retained);
        drop(request); // last original reference unlocks /lock.
        assert_eq!(v.flock(b, 6), Ok(()));
        files.finish();
    }

    struct TcpTarget(Arc<trames_vfs::HostEvents>);
    impl IoWake for TcpTarget {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
        fn host_events(&self) -> Option<Arc<trames_vfs::HostEvents>> {
            Some(self.0.clone())
        }
    }
    #[test]
    fn pending_tcp_uses_original_transport_until_completion_and_releases_close() {
        use std::{
            io::{Read, Write},
            net::{Ipv4Addr, TcpListener},
        };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut v = Vfs::default();
        v.configure_network(trames_vfs::NetworkMode::Loopback)
            .unwrap();
        let fd = v.socket(2, 1, 0).unwrap();
        let socket = v.socket_fd(fd).unwrap();
        assert!(matches!(
            socket.connect(listener.local_addr().unwrap()),
            Ok(()) | Err(trames_net::NetError(115))
        ));
        let (mut peer, _) = listener.accept().unwrap();
        assert_eq!(socket.connect_complete(), Ok(true));
        drop(socket);
        let direct = DirectSyscalls::default().with_network(v.direct_network());
        let mut m = memory();
        let hub = trames_vfs::HostEvents::new().unwrap();
        let target: Arc<dyn IoWake> = Arc::new(TcpTarget(hub.clone()));
        let wait = pending(
            direct
                .start(
                    63,
                    [fd as u64, 0x1100, 1, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None,
                )
                .unwrap(),
        );
        assert!(wait.native_tcp.is_some());
        assert_eq!(v.close_quiescent_tcp(fd), None);
        assert!(v.socket_fd(fd).is_ok());
        // Force the old joined teardown in this component test. A same-epoch
        // retry still uses its original accepted transport, never the reused FD.
        v.close(fd).unwrap();
        let replacement = v.eventfd(7, 0).unwrap();
        assert_eq!(replacement, fd);
        peer.write_all(b"o").unwrap();
        hub.wait(Some(Instant::now() + Duration::from_secs(2)))
            .unwrap();
        assert_eq!(complete(direct.resume(wait, &mut m)), Ok(1));
        assert_eq!(m.read_array::<1>(0x1100).unwrap(), *b"o");
        assert_eq!(v.read(replacement, 8).unwrap(), 7u64.to_le_bytes());
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        assert_eq!(direct.socket_completed(), 1);
    }
    #[test]
    fn tcp_timeout_and_cancellation_drop_all_accepted_transport_leases() {
        use std::{
            io::Read,
            net::{Ipv4Addr, TcpListener},
        };
        for expired in [false, true] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let mut v = Vfs::default();
            v.configure_network(trames_vfs::NetworkMode::Loopback)
                .unwrap();
            let fd = v.socket(2, 1, 0).unwrap();
            let socket = v.socket_fd(fd).unwrap();
            assert!(matches!(
                socket.connect(listener.local_addr().unwrap()),
                Ok(()) | Err(trames_net::NetError(115))
            ));
            let (mut peer, _) = listener.accept().unwrap();
            assert_eq!(socket.connect_complete(), Ok(true));
            drop(socket);
            let direct = DirectSyscalls::default().with_network(v.direct_network());
            let mut m = memory();
            let target: Arc<dyn IoWake> =
                Arc::new(TcpTarget(trames_vfs::HostEvents::new().unwrap()));
            let result = direct
                .start(
                    63,
                    [fd as u64, 0x1100, 1, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    expired.then(Instant::now),
                )
                .unwrap();
            if expired {
                assert_eq!(complete(result), Err(Errno(11)));
            } else {
                let wait = pending(result);
                assert_eq!(v.close_quiescent_tcp(fd), None);
                drop(wait);
            }
            assert_eq!(v.close_quiescent_tcp(fd), Some(Ok(())));
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        }
    }

    struct Target;
    impl IoWake for Target {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }

    #[test]
    fn native_tcp_epoll_and_ppoll_park_on_edges_without_delaying_last_close() {
        use std::{
            io::{Read, Write},
            net::{Ipv4Addr, TcpListener},
        };
        for epoll in [false, true] {
            let mut vfs = trames_vfs::Vfs::default();
            vfs.configure_network(trames_net::NetworkMode::Loopback)
                .unwrap();
            let fd = vfs.socket(2, 1, 0).unwrap();
            let ep = vfs.epoll_create(0).unwrap();
            // Real clients commonly register before connect completes. Capture
            // promotes this original interest, rather than requiring re-ADD.
            vfs.epoll_ctl(ep, 1, fd, 1, 42).unwrap();
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let socket = vfs.socket_fd(fd).unwrap();
            assert!(matches!(
                socket.connect(listener.local_addr().unwrap()),
                Ok(()) | Err(trames_net::NetError(115))
            ));
            let (mut peer, _) = listener.accept().unwrap();
            assert_eq!(socket.connect_complete(), Ok(true));
            drop(socket);
            vfs.direct_network();
            let direct = DirectSyscalls::new(vfs.direct_descriptors());
            let mut m = memory();
            let (number, args) = if epoll {
                (22, [ep as u64, 0x1100, 1, 2000, 0, 0])
            } else {
                m.write_array(0x1100, (fd as u64 | (1u64 << 32)).to_le_bytes())
                    .unwrap();
                m.write_array(0x1200, 2u64.to_le_bytes()).unwrap();
                m.write_array(0x1208, 0u64.to_le_bytes()).unwrap();
                (73, [0x1100, 1, 0x1200, 0, 0, 0])
            };
            let hub = trames_vfs::HostEvents::new().unwrap();
            let target: Arc<dyn IoWake> = Arc::new(TcpTarget(hub.clone()));
            let weak = Arc::downgrade(&target);
            let wait = pending(
                direct
                    .start(number, args, &mut m, 1, &weak, None)
                    .expect("worker TCP poll admission"),
            );
            hub.wait(Some(Instant::now() + Duration::from_millis(10)))
                .unwrap();
            assert!(
                !wait.signal.ready(),
                "read-only wait must ignore a writable level"
            );
            peer.write_all(b"x").unwrap();
            hub.wait(Some(Instant::now() + Duration::from_secs(2)))
                .unwrap();
            assert!(wait.signal.ready());
            assert_eq!(complete(direct.resume(wait, &mut m)), Ok(1));
            if epoll {
                assert_eq!(m.read_u64(0x1108).unwrap(), 42);
            } else {
                assert_eq!(m.read_array::<2>(0x1106).unwrap(), 1u16.to_le_bytes());
            }
            assert_eq!(vfs.read(fd, 1).unwrap(), b"x");
            let wait = pending(direct.start(number, args, &mut m, 1, &weak, None).unwrap());
            assert_eq!(
                vfs.close_quiescent_tcp(fd),
                Some(Ok(())),
                "poll subscriptions must not retain TCP I/O leases"
            );
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
            assert_eq!(vfs.eventfd(1, 0).unwrap(), fd);
            if epoll {
                assert!(
                    direct
                        .descriptors
                        .get(ep)
                        .unwrap()
                        .epoll_wait(1)
                        .unwrap()
                        .is_empty(),
                    "reused FD must not retarget the interest"
                );
            }
            drop(wait);
        }
    }

    #[test]
    fn worker_epoll_control_matches_owner_event_layout_flags_and_fault_order() {
        for (op, address, events) in [
            (1, 0x1200, 1),
            (2, u64::MAX, 1),
            (3, 0x1200, 0xc0000001u32),
            (3, 0x1200, 0x10000),
            (0, 0x1200, 1),
            (3, 0x9000, 1),
            (0x100000002, u64::MAX, 1),
        ] {
            let mut outcomes = Vec::new();
            for worker in [false, true] {
                let mut linux = Linux::new(0x10000);
                let ep = linux.vfs.epoll_create(0).unwrap();
                let event = linux.vfs.eventfd(1, 0).unwrap();
                linux.vfs.epoll_ctl(ep, 1, event, 1, 7).unwrap();
                let mut m = memory();
                m.write_array(0x1200, events.to_le_bytes()).unwrap();
                m.write_array(0x1208, 99u64.to_le_bytes()).unwrap();
                let args = [ep as u64, op, event as u64, address, 0, 0];
                let result = if worker {
                    DirectSyscalls::new(linux.vfs.direct_descriptors())
                        .invoke_epoll_control(21, args, &m)
                        .expect("admitted epoll control")
                } else {
                    linux.syscall(21, args, &mut m, &mut crate::CapturedOutput::default())
                };
                outcomes.push((
                    result,
                    linux.vfs.epoll_wait(ep, 1, |_, _| Ok(None)).unwrap(),
                ));
            }
            assert_eq!(outcomes[0], outcomes[1], "op {op} addr {address:x}");
        }
    }
    #[test]
    fn parked_epoll_subscribes_to_a_new_interest_without_a_cohort_restart() {
        let mut vfs = Vfs::default();
        let ep = vfs.epoll_create(0).unwrap();
        let direct = DirectSyscalls::new(vfs.direct_descriptors());
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let weak = Arc::downgrade(&target);
        let mut m = memory();
        let args = [ep as u64, 0x1100, 1, 2000, 0, 0];
        let IoAttempt::Blocked(wait) = direct.start(22, args, &mut m, 1, &weak, None).unwrap()
        else {
            panic!("empty epoll must park");
        };
        let event = vfs.eventfd(0, 0).unwrap();
        m.write_array(0x1200, 1u32.to_le_bytes()).unwrap();
        m.write_array(0x1208, 42u64.to_le_bytes()).unwrap();
        assert_eq!(
            direct.invoke_epoll_control(21, [ep as u64, 1, event as u64, 0x1200, 0, 0], &m),
            Some(Ok(0))
        );
        assert!(wait.signal.ready());
        let IoAttempt::Blocked(wait) = direct.resume(wait, &mut m) else {
            panic!("new unready source must remain parked");
        };
        assert!(!wait.signal.ready());
        vfs.write(event, &1u64.to_le_bytes()).unwrap();
        assert!(
            wait.signal.ready(),
            "new source is subscribed after ctl notification"
        );
        assert_eq!(complete(direct.resume(wait, &mut m)), Ok(1));
        assert_eq!(m.read_array::<8>(0x1108).unwrap(), 42u64.to_le_bytes());
        // DEL ignores its guest event pointer, including an invalid one.
        assert_eq!(
            direct.invoke_epoll_control(21, [ep as u64, 2, event as u64, u64::MAX, 0, 0], &m),
            Some(Ok(0))
        );
    }
    #[test]
    fn shared_byte_wait_and_fresh_dispatch_keep_original_ofd_after_close_and_reuse() {
        let mut vfs = Vfs::default();
        let [reader, writer] = vfs.pipe(0).unwrap();
        let direct = DirectSyscalls::default().with_membership(vfs.shared_files());
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let mut m = memory();
        let args = [reader as u64, 0x1100, 1, 0, 0, 0];
        let wait = pending(
            direct
                .start(63, args, &mut m, 1, &Arc::downgrade(&target), None)
                .unwrap(),
        );
        assert!(wait.retained_byte.is_some());
        assert!(!wait.signal.ready());
        vfs.close(reader).unwrap();
        let [replacement, replacement_writer] = vfs.pipe(0).unwrap();
        assert_eq!(replacement, reader);
        vfs.write(replacement_writer, b"n").unwrap();
        assert!(!wait.signal.ready());
        let retained = wait.retained_byte.clone().unwrap();
        drop(wait); // checkpoint drops subscriptions, not accepted authority.
        let fresh = DirectSyscalls::default();
        let wait = pending(fresh.start_retained_byte(
            retained,
            63,
            args,
            &mut m,
            1,
            &Arc::downgrade(&target),
        ));
        vfs.write(writer, b"o").unwrap();
        assert!(wait.signal.ready());
        assert_eq!(complete(fresh.resume(wait, &mut m)), Ok(1));
        assert_eq!(m.read_array::<1>(0x1100).unwrap(), *b"o");
        assert_eq!(vfs.read(replacement, 1).unwrap(), b"n");
        assert_eq!(vfs.write(writer, b"x"), Err(Errno(32))); // completed lease released.
    }

    #[test]
    fn shared_blocked_writer_keeps_original_endpoint_and_reports_epipe_to_owner() {
        let mut vfs = Vfs::default();
        let [reader, writer] = vfs.pipe(0).unwrap();
        vfs.write(writer, &vec![0; 65536]).unwrap();
        let direct = DirectSyscalls::default().with_membership(vfs.shared_files());
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let mut m = memory();
        m.write(0x1100, b"x").unwrap();
        let args = [writer as u64, 0x1100, 1, 0, 0, 0];
        let wait = pending(
            direct
                .start_owned_byte(None, 64, args, &mut m, 1, &Arc::downgrade(&target))
                .unwrap(),
        );
        vfs.close(writer).unwrap();
        let [replacement, _] = vfs.pipe(0).unwrap();
        assert_eq!(replacement, writer);
        vfs.close(reader).unwrap();
        assert!(wait.signal.ready());
        assert_eq!(
            complete(direct.resume_owned_byte(wait, &mut m)),
            Err(Errno(32))
        );
    }

    #[test]
    fn parked_byte_retry_reads_live_nonblock_but_poll_ignores_status_flags() {
        let mut vfs = Vfs::default();
        let [read, _write] = vfs.pipe(0).unwrap();
        let alias = vfs.dup(read, 0, false).unwrap();
        let direct = DirectSyscalls::new(vfs.direct_descriptors());
        let flags = vfs.fd_flags_snapshot();
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let mut m = memory();
        let wait = pending(
            direct
                .start(
                    63,
                    [read as u64, 0x1100, 1, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None,
                )
                .unwrap(),
        );
        flags.set_nonblocking(alias, true).unwrap();
        assert!(!wait.signal.ready(), "FIONBIO is not a resource wake");
        assert_eq!(complete(direct.resume(wait, &mut m)), Err(Errno(11)));
        m.write_array(0x1200, [0u8; 8]).unwrap();
        m.write_array(0x1200, read.to_le_bytes()).unwrap();
        m.write_array(0x1204, 1u16.to_le_bytes()).unwrap();
        let wait = pending(
            direct
                .start(
                    73,
                    [0x1200, 1, 0, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None,
                )
                .unwrap(),
        );
        drop(pending(direct.resume(wait, &mut m)));
    }
    fn pending(attempt: IoAttempt) -> PendingIo {
        match attempt {
            IoAttempt::Blocked(pending) => pending,
            _ => panic!("expected blocked I/O"),
        }
    }
    fn complete(attempt: IoAttempt) -> Result<u64, Errno> {
        match attempt {
            IoAttempt::Complete(result) => result,
            _ => panic!("expected completed I/O"),
        }
    }
    #[test]
    fn pipe_backpressure_rechecks_pipe_buf_and_broken_pipe_keeps_signal_path() {
        let mut vfs = Vfs::default();
        let [read, write] = vfs.pipe(0).unwrap();
        let direct = DirectSyscalls::new(vfs.direct_descriptors());
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let mut m = memory();
        let bytes = [42; 4096];
        while vfs.write(write, &bytes).is_ok() {}
        m.write(0x1000, &bytes).unwrap();
        let wait = pending(
            direct
                .start(
                    64,
                    [write as u64, 0x1000, 4096, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None,
                )
                .unwrap(),
        );
        assert_eq!(vfs.read(read, 1).unwrap(), [42]);
        assert!(wait.signal.ready());
        let wait = pending(direct.resume(wait, &mut m));
        assert!(!wait.signal.ready());
        assert_eq!(vfs.read(read, 4095).unwrap(), [42; 4095]);
        assert!(wait.signal.ready());
        assert_eq!(complete(direct.resume(wait, &mut m)), Ok(4096));
        let wait = pending(
            direct
                .start(
                    64,
                    [write as u64, 0x1000, 4096, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None,
                )
                .unwrap(),
        );
        vfs.close(read).unwrap();
        assert!(wait.signal.ready());
        assert!(matches!(direct.resume(wait, &mut m), IoAttempt::Checkpoint));
        assert_eq!(direct.completed(), 1);
    }
    #[test]
    fn blocked_eventfd_writer_and_pipe_eof_resume_without_replaying_completed_transfers() {
        let mut vfs = Vfs::default();
        let event = vfs.eventfd(0, 0).unwrap();
        vfs.write(event, &(u64::MAX - 1).to_le_bytes()).unwrap();
        let [read, write] = vfs.pipe(0).unwrap();
        let direct = DirectSyscalls::new(vfs.direct_descriptors());
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let mut m = memory();
        m.write_array(0x1000, 1u64.to_le_bytes()).unwrap();
        let wait = pending(
            direct
                .start(
                    64,
                    [event as u64, 0x1000, 8, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None,
                )
                .unwrap(),
        );
        assert!(!wait.signal.ready());
        assert_eq!(vfs.read(event, 8).unwrap(), (u64::MAX - 1).to_le_bytes());
        assert!(wait.signal.ready());
        assert_eq!(complete(direct.resume(wait, &mut m)), Ok(8));
        assert_eq!(vfs.read(event, 8).unwrap(), 1u64.to_le_bytes());
        let wait = pending(
            direct
                .start(
                    63,
                    [read as u64, 0x1000, 8, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None,
                )
                .unwrap(),
        );
        vfs.close(write).unwrap();
        assert!(wait.signal.ready());
        assert_eq!(complete(direct.resume(wait, &mut m)), Ok(0));
        assert_eq!(direct.completed(), 2);
    }
    #[test]
    fn epoll_deadline_preflight_event_layout_and_mask_validation() {
        let mut vfs = Vfs::default();
        let event = vfs.eventfd(0, 0).unwrap();
        let ep = vfs.epoll_create(0).unwrap();
        vfs.epoll_ctl(ep, 1, event, 0x40000001, 0x123456789abcdef0)
            .unwrap();
        let direct = DirectSyscalls::new(vfs.direct_descriptors());
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let mut m = memory();
        let args = [ep as u64, 0x1100, 1, 1000, 0, 0];
        let wait = pending(
            direct
                .start(22, args, &mut m, 1, &Arc::downgrade(&target), None)
                .unwrap(),
        );
        let deadline = wait.deadline.unwrap();
        let wait = pending(direct.resume(wait, &mut m));
        assert_eq!(wait.deadline, Some(deadline));
        vfs.write(event, &1u64.to_le_bytes()).unwrap();
        assert!(wait.signal.ready());
        // Failed output validation must not consume ONESHOT.
        let bad = wait;
        // Invalidate the actual accepted destination, rather than rewriting
        // checkpoint metadata (which must no longer retarget the syscall).
        m.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        assert_eq!(complete(direct.resume(bad, &mut m)), Err(Errno(14)));
        m.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        assert_eq!(
            complete(
                direct
                    .start(22, args, &mut m, 1, &Arc::downgrade(&target), None)
                    .unwrap()
            ),
            Ok(1)
        );
        assert_eq!(
            m.read_array::<16>(0x1100).unwrap(),
            [1, 0, 0, 0, 0, 0, 0, 0, 0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12]
        );
        let mut args = args;
        args[3] = 0;
        assert_eq!(
            complete(
                direct
                    .start(22, args, &mut m, 1, &Arc::downgrade(&target), None)
                    .unwrap()
            ),
            Ok(0)
        );
        args[4] = 0x1000;
        assert_eq!(
            complete(
                direct
                    .start(22, args, &mut m, 1, &Arc::downgrade(&target), None)
                    .unwrap()
            ),
            Err(Errno(22))
        );
        args[4] = 0;
        m.write_array(0x1000, 0u64.to_le_bytes()).unwrap();
        m.write_array(0x1008, 1_000_000_000u64.to_le_bytes())
            .unwrap();
        args[3] = 0x1000;
        assert_eq!(
            complete(
                direct
                    .start(441, args, &mut m, 1, &Arc::downgrade(&target), None)
                    .unwrap()
            ),
            Err(Errno(22))
        );
        m.write_array(0x1008, 0u64.to_le_bytes()).unwrap();
        assert_eq!(
            complete(
                direct
                    .start(441, args, &mut m, 1, &Arc::downgrade(&target), None)
                    .unwrap()
            ),
            Ok(0)
        );
    }
    #[test]
    fn blocking_and_sigpipe_defer_without_effects_or_retrying_completed_io() {
        let mut vfs = Vfs::default();
        let [read, write] = vfs.pipe(0).unwrap();
        let direct = DirectSyscalls::new(vfs.direct_descriptors());
        let mut m = memory();
        assert_eq!(
            direct.invoke(63, [read as u64, 0x1000, 8, 0, 0, 0], &mut m),
            None
        );
        assert_eq!(direct.completed(), 0);
        m.write(0x1000, b"hello").unwrap();
        assert_eq!(
            direct.invoke(64, [write as u64, 0x1000, 5, 0, 0, 0], &mut m),
            Some(Ok(5))
        );
        assert_eq!(vfs.read(read, 8).unwrap(), b"hello");
        vfs.close(read).unwrap();
        assert_eq!(
            direct.invoke(64, [write as u64, 0x1000, 5, 0, 0, 0], &mut m),
            None
        );
        assert_eq!(direct.completed(), 1);
        vfs.set_status_flags(write, O_NONBLOCK).unwrap();
    }
    #[test]
    fn scalar_and_vector_preflight_does_not_consume_eventfd_or_pipe_bytes() {
        let mut vfs = Vfs::default();
        let event = vfs.eventfd(7, O_NONBLOCK).unwrap();
        let [read, write] = vfs.pipe(O_NONBLOCK).unwrap();
        let direct = DirectSyscalls::new(vfs.direct_descriptors());
        let mut m = memory();
        assert_eq!(
            direct.invoke(63, [event as u64, 0x1ffc, 8, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert_eq!(vfs.read(event, 8).unwrap(), 7u64.to_le_bytes());
        // Two readv destinations: the first is valid but the second is not.
        for (address, value) in [(0x1000, 0x1100), (0x1008, 4), (0x1010, 0x2000), (0x1018, 4)] {
            m.write_array(address, (value as u64).to_le_bytes())
                .unwrap();
        }
        vfs.write(write, b"abcdefgh").unwrap();
        assert_eq!(
            direct.invoke(65, [read as u64, 0x1000, 2, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert_eq!(vfs.read(read, 8).unwrap(), b"abcdefgh");
        assert_eq!(
            direct.invoke(66, [write as u64, 0x1000, 2, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert_eq!(vfs.read(read, 8), Err(Errno(11)));
        assert_eq!(
            direct.invoke(63, [read as u64, 0x1100, 8, 0, 0, 0], &mut m),
            Some(Err(Errno(11)))
        );
    }
    #[test]
    fn inotify_read_vectors_queries_and_waits_use_the_shared_queue_without_replay() {
        let mut vfs = Vfs::default();
        let fd = vfs.inotify_init(0).unwrap();
        let wd = vfs.inotify_add(fd, b"/", 0x100).unwrap();
        let direct = DirectSyscalls::new(vfs.direct_descriptors());
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let mut m = memory();
        let wait = pending(
            direct
                .start(
                    63,
                    [fd as u64, 0x1100, 32, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None,
                )
                .unwrap(),
        );
        vfs.mkdir_at(-100, b"/a", 0o700).unwrap();
        assert!(wait.signal.ready());
        assert_eq!(complete(direct.resume(wait, &mut m)), Ok(32));
        assert_eq!(
            u32::from_le_bytes(m.read_array::<4>(0x1100).unwrap()) as i32,
            wd
        );
        assert_eq!(
            u32::from_le_bytes(m.read_array::<4>(0x1104).unwrap()),
            0x40000100
        );
        assert_eq!(vfs.inotify_available(fd).unwrap(), Some(0));
        vfs.mkdir_at(-100, b"/b", 0o700).unwrap();
        assert_eq!(
            direct.invoke(63, [fd as u64, 0x1ff0, 32, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert_eq!(
            direct.invoke(63, [fd as u64, 0x1100, 31, 0, 0, 0], &mut m),
            Some(Err(Errno(22)))
        );
        assert_eq!(
            direct.invoke(29, [fd as u64, 0x541b, 0x1200, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        assert_eq!(u32::from_le_bytes(m.read_array::<4>(0x1200).unwrap()), 32);
        for (address, value) in [
            (0x1000, 0x1100u64),
            (0x1008, 7),
            (0x1010, 0x1107),
            (0x1018, 25),
        ] {
            m.write_array(address, value.to_le_bytes()).unwrap();
        }
        assert_eq!(
            direct.invoke(65, [fd as u64, 0x1000, 2, 0, 0, 0], &mut m),
            Some(Err(Errno(22)))
        );
        assert_eq!(vfs.inotify_available(fd).unwrap(), Some(32));
        vfs.mkdir_at(-100, b"/c", 0o700).unwrap();
        m.write_array(0x1008, 32u64.to_le_bytes()).unwrap();
        m.write_array(0x1010, 0x1180u64.to_le_bytes()).unwrap();
        m.write_array(0x1018, 8u64.to_le_bytes()).unwrap();
        assert_eq!(
            direct.invoke(65, [fd as u64, 0x1000, 2, 0, 0, 0], &mut m),
            Some(Ok(32))
        );
        assert_eq!(m.read_array::<2>(0x1110).unwrap(), *b"b\0");
        assert_eq!(vfs.inotify_available(fd).unwrap(), Some(32));
        assert_eq!(
            direct.invoke(63, [fd as u64, 0x1100, 32, 0, 0, 0], &mut m),
            Some(Ok(32))
        );
        assert_eq!(m.read_array::<2>(0x1110).unwrap(), *b"c\0");
        assert_eq!(vfs.inotify_available(fd).unwrap(), Some(0));
        assert_eq!(
            direct.invoke(64, [fd as u64, 0x1100, 1, 0, 0, 0], &mut m),
            Some(Err(Errno(9)))
        );
        assert_eq!(
            direct.invoke(28, [fd as u64, wd as u64, 0, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        assert_eq!(
            direct.invoke(28, [fd as u64, wd as u64, 0, 0, 0, 0], &mut m),
            Some(Err(Errno(22)))
        );
        assert_eq!(direct.fd_control_completed(), 2);
        assert_eq!(
            direct.invoke(63, [fd as u64, 0x1100, 16, 0, 0, 0], &mut m),
            Some(Ok(16))
        );
        assert_eq!(
            u32::from_le_bytes(m.read_array::<4>(0x1104).unwrap()),
            0x8000
        );
        assert_eq!(vfs.inotify_remove(fd, wd), Err(Errno(22)));
        let replacement = vfs.inotify_add(fd, b"/", 0x100).unwrap();
        assert_ne!(replacement, wd);
    }
    #[test]
    fn vector_eventfd_obeys_record_sizes_and_commits_partial_progress_once() {
        let mut vfs = Vfs::default();
        let fd = vfs.eventfd(0, O_NONBLOCK).unwrap();
        let direct = DirectSyscalls::new(vfs.direct_descriptors());
        let mut m = memory();
        for (address, value) in [(0x1000, 0x1100), (0x1008, 3), (0x1010, 0x1103), (0x1018, 5)] {
            m.write_array(address, (value as u64).to_le_bytes())
                .unwrap();
        }
        m.write_array(0x1100, 42u64.to_le_bytes()).unwrap();
        assert_eq!(
            direct.invoke(66, [fd as u64, 0x1000, 2, 0, 0, 0], &mut m),
            Some(Err(Errno(22)))
        );
        assert_eq!(vfs.read(fd, 8), Err(Errno(11)));
        m.write_array(0x1008, 8u64.to_le_bytes()).unwrap();
        m.write_array(0x1010, 0x1108u64.to_le_bytes()).unwrap();
        m.write_array(0x1018, 8u64.to_le_bytes()).unwrap();
        m.write_array(0x1108, 1u64.to_le_bytes()).unwrap();
        assert_eq!(
            direct.invoke(66, [fd as u64, 0x1000, 2, 0, 0, 0], &mut m),
            Some(Ok(16))
        );
        m.write_array(0x1100, 0u64.to_le_bytes()).unwrap();
        assert_eq!(
            direct.invoke(65, [fd as u64, 0x1000, 2, 0, 0, 0], &mut m),
            Some(Ok(8))
        );
        assert_eq!(m.read_u64(0x1100).unwrap(), 43);
        assert_eq!(m.read_u64(0x1108).unwrap(), 1);
        assert_eq!(
            direct.invoke(64, [fd as u64, 0x1100, 7, 0, 0, 0], &mut m),
            Some(Err(Errno(22)))
        );
        assert_eq!(vfs.read(fd, 8), Err(Errno(11)));
    }
    #[test]
    fn device_scalar_vector_and_positioned_abi_preserves_faults_access_and_original_ofd() {
        for (path, full, zeros) in [
            (b"/dev/null".as_slice(), false, false),
            (b"/dev/zero", false, true),
            (b"/dev/full", true, true),
        ] {
            for flags in [0, 1, 2, trames_vfs::O_PATH] {
                let mut v = Vfs::default();
                v.set_runtime_info(1, trames_vfs::RuntimeInfo::default());
                let fd = v.open_at(-100, path, flags, 0).unwrap();
                let d = DirectSyscalls::new(v.direct_descriptors());
                let mut m = memory();
                for (at, value) in [
                    (0x1000, 0x1100u64),
                    (0x1008, 1),
                    (0x1010, 0x1101),
                    (0x1018, 3),
                ] {
                    m.write_array(at, value.to_le_bytes()).unwrap();
                }
                for number in 63..=70 {
                    m.write(0x1100, b"data").unwrap();
                    let vector = matches!(number, 65 | 66 | 69 | 70);
                    let writing = matches!(number, 64 | 66 | 68 | 70);
                    let args = [
                        fd as u64,
                        if vector { 0x1000 } else { 0x1100 },
                        if vector { 2 } else { 4 },
                        23,
                        0,
                        0,
                    ];
                    let expected = if flags & trames_vfs::O_PATH != 0
                        || writing && flags == 0
                        || !writing && flags == 1
                    {
                        Err(Errno(9))
                    } else if writing && full {
                        Err(Errno(28))
                    } else {
                        Ok(if writing || zeros { 4 } else { 0 })
                    };
                    assert_eq!(
                        d.invoke(number, args, &mut m),
                        Some(expected),
                        "{path:?} flags={flags} number={number}"
                    );
                    if !writing && flags != 1 && flags & trames_vfs::O_PATH == 0 {
                        assert_eq!(
                            m.read_array::<4>(0x1100).unwrap(),
                            if zeros { [0; 4] } else { *b"data" }
                        );
                    }
                }
                if flags == 2 {
                    let bad = [fd as u64, 0x9000, 4, u64::MAX, 0, 0];
                    assert_eq!(d.invoke(67, bad, &mut m), Some(Err(Errno(14))));
                    m.write_array(0x1000, 0x9000u64.to_le_bytes()).unwrap();
                    assert_eq!(
                        d.invoke(69, [fd as u64, 0x1000, 2, 0, 0, 0], &mut m),
                        Some(Err(Errno(14)))
                    );
                    assert_eq!(
                        d.invoke(69, [fd as u64, 0x1000, 2, u64::MAX, 0, 0], &mut m),
                        Some(Err(Errno(22)))
                    );
                    m.write_array(0x1000, 0x1100u64.to_le_bytes()).unwrap();
                    let args = [fd as u64, 0x1000, 2, 0, 0, 0];
                    let file = d.retain_byte(69, args).unwrap().unwrap();
                    v.close(fd).unwrap();
                    assert_eq!(v.eventfd(91, 0).unwrap(), fd);
                    let target: Arc<dyn IoWake> = Arc::new(Target);
                    assert!(
                        matches!(d.start_retained_byte(file,69,args,&mut m,1,&Arc::downgrade(&target)),IoAttempt::Complete(Ok(n)) if n==if zeros{4}else{0})
                    );
                    assert_eq!(v.read(fd, 8).unwrap(), 91u64.to_le_bytes());
                }
            }
        }
    }
}

#[cfg(test)]
mod socket_control_tests;
