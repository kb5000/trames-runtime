// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux io_uring shared queues and retained open descriptions. Execution lives
//! in trames-linux; no guest FD or guest-selected path becomes a host FD/path.
use super::*;
use std::time::Instant;
use trames_memory::PAGE_SIZE;
pub const URING_MAX_ENTRIES: u32 = 4096;
pub const URING_SQ_ARRAY: usize = 128;
pub const URING_CQES: usize = 128 + URING_MAX_ENTRIES as usize * 4;
pub const URING_OPS: &[u8] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 22, 23, 26, 27, 28, 31, 32, 34,
    45, 55, 56, 57,
];
#[derive(Clone)]
pub struct RetainedFd(pub(super) Descriptor);
impl RetainedFd {
    pub fn ofd_identity(&self) -> OfdIdentity {
        OfdIdentity::new(&self.0.open.borrow().shared)
    }
    pub fn local_socket(&self, vfs: &Vfs) -> Option<Rc<LocalSocket>> {
        self.0
            .open
            .borrow()
            .local
            .clone()
            .map(|core| vfs.local_view(core))
    }
    /// Actual close-notification lease, independent of owner inode/path anchors.
    /// Capture only for accepted operations, never every capability snapshot.
    pub fn close_notification(&self) -> Option<Arc<FileClose>> {
        self.0.open.borrow().notification.clone()
    }
    /// Retain the actual inotify instance, independently of its queue snapshot.
    pub fn inotify_instance(&self) -> Option<Arc<InotifyInstance>> {
        match &self.0.open.borrow().anonymous {
            Some(events::Anonymous::Inotify(i)) => Some(i.clone()),
            _ => None,
        }
    }
    /// Opaque owner-side OFD key; never exposed as a guest address.
    pub fn identity(&self) -> usize {
        self.0.open.identity()
    }
    /// An accepted request can hold the real pipe end on its executing worker.
    /// Poll/byte snapshots by themselves remain non-owning endpoint capabilities.
    pub fn pipe_endpoint(&self) -> Option<Arc<PipeEndpoint>> {
        self.0
            .open
            .borrow()
            .pipe
            .as_ref()
            .map(|end| end.endpoint.clone())
    }
    pub fn shared_file(&self) -> Option<SharedFd> {
        match &self.0.open {
            OpenHandle::Shared(open) => Some(SharedFd::new(open.clone())),
            OpenHandle::Owner(_) => None,
        }
    }
    pub fn direct_byte(&self) -> Option<DirectFd> {
        if let Some(file) = self.shared_file() {
            return file.direct_byte();
        }
        DirectFd::snapshot_uring(&self.0.open.borrow()).filter(|fd| !fd.is_epoll() && !fd.is_pty())
    }
    /// Real connected native transport lease; never capture for all FD snapshots.
    pub fn tcp_lease(&self) -> Option<trames_net::TcpLease> {
        self.direct_tcp()?.tcp.retain().ok()
    }
    pub fn direct_tcp(&self) -> Option<DirectTcpFd> {
        let open = self.0.open.borrow();
        Some(DirectTcpFd {
            lease: None,
            tcp: open.socket.as_ref()?.direct_tcp()?,
            flags: open.flags.get(),
            status: open.flags.clone(),
            timeouts: [false, true]
                .map(|receive| open.socket.as_ref().unwrap().io_timeout(receive)),
        })
    }
    pub fn kind(&self) -> FdKind {
        self.0.open.borrow().kind.clone()
    }
    pub fn same_file(&self, other: &Self) -> bool {
        OpenHandle::ptr_eq(&self.0.open, &other.0.open)
    }
    pub fn stream(&self) -> bool {
        let o = self.0.open.borrow();
        o.pipe.is_some()
            || o.socket.is_some()
            || o.local.is_some()
            || o.bridge.is_some()
            || o.kernel_log.is_some()
            || o.anonymous.is_some()
    }
    pub fn poll(&self, events: u16) -> u16 {
        Vfs::poll_open(&self.0.open.borrow(), events, 0, None)
    }
    pub fn datagram(&self) -> bool {
        let open = self.0.open.borrow();
        open.local.as_ref().is_some_and(|s| s.kind() == 2)
            || open
                .socket
                .as_ref()
                .and_then(|s| s.info())
                .is_some_and(|s| matches!(s.kind, 2 | 3))
    }
    pub fn readiness(&self, events: u16) -> (u16, [u64; 2]) {
        let open = self.0.open.borrow();
        (
            Vfs::poll_open(&open, events, 0, None),
            Vfs::poll_epoch(&open),
        )
    }
    pub fn socket(&self) -> Option<Arc<NetSocket>> {
        self.0.open.borrow().socket.clone()
    }
}
/// A complete accepted shared OFD, independent of its numeric descriptor.
/// No owner-local descriptor projection is stored in a shared ring.
#[derive(Clone)]
pub struct UringFile {
    lease: Option<Arc<ipc::ownership::Link>>,
    file: SharedFd,
    owner: Option<(u64, Arc<()>)>,
}
impl UringFile {
    pub fn socket_control(&self) -> Option<Result<SocketControlOperation>> {
        let file = self.shared_file()?;
        Some(if file.open.local.is_some() {
            LocalOperation::from_shared(file).map(SocketControlOperation::Unix)
        } else {
            SocketOperation::from_shared(file).map(SocketControlOperation::Network)
        })
    }
    pub fn shared_file(&self) -> Option<SharedFd> {
        self.owner.is_none().then(|| self.file.clone())
    }
    pub fn is_eventfd(&self) -> bool {
        matches!(
            self.file.open.control,
            Some(events::SharedControl::Event(_))
        )
    }
    pub fn is_signalfd(&self) -> bool {
        self.owner.is_none()
            && matches!(
                self.file.open.control,
                Some(events::SharedControl::Signal(_))
            )
    }
    pub fn identity(&self) -> usize {
        self.file.identity()
    }
    pub fn ofd_identity(&self) -> OfdIdentity {
        self.file.ofd_identity()
    }
    pub fn retained(&self) -> RetainedFd {
        assert!(self.owner.is_none(), "owner control needs its original VFS");
        self.file.clone().retained()
    }
    fn retained_in(&self, vfs: &Vfs) -> RetainedFd {
        if let Some((id, _)) = &self.owner {
            vfs.local_rights
                .uring
                .borrow()
                .get(id)
                .expect("original owner control ledger")
                .1
                .clone()
        } else {
            self.retained()
        }
    }
    pub fn same_file(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }
    pub fn local_socket(&self, vfs: &Vfs) -> Option<Rc<LocalSocket>> {
        self.retained_in(vfs).local_socket(vfs)
    }
    pub fn close_notification(&self) -> Option<Arc<FileClose>> {
        self.shared_file()?.retained().close_notification()
    }
    pub fn inotify_instance(&self) -> Option<Arc<InotifyInstance>> {
        self.shared_file()?.retained().inotify_instance()
    }
    pub fn pipe_endpoint(&self) -> Option<Arc<PipeEndpoint>> {
        self.shared_file()?.retained().pipe_endpoint()
    }
    pub fn direct_byte(&self) -> Option<DirectFd> {
        self.shared_file()?.retained().direct_byte()
    }
    pub fn tcp_lease(&self) -> Option<trames_net::TcpLease> {
        self.shared_file()?.retained().tcp_lease()
    }
    pub fn socket(&self) -> Option<Arc<NetSocket>> {
        self.file.open.socket.clone()
    }
    pub fn direct_tcp(&self) -> Option<DirectTcpFd> {
        self.shared_file()?.retained().direct_tcp()
    }
    pub fn kind(&self) -> FdKind {
        self.file.open.kind.clone()
    }
    pub fn stream(&self) -> bool {
        self.file.clone().retained().stream()
    }
    pub fn poll(&self, events: u16) -> u16 {
        self.file.clone().retained().poll(events)
    }
    pub fn datagram(&self) -> bool {
        self.file.clone().retained().datagram()
    }
    pub fn readiness(&self, events: u16) -> (u16, [u64; 2]) {
        self.file.clone().retained().readiness(events)
    }
    pub fn native_wait_fds(&self) -> Vec<HostFd> {
        self.file.clone().retained().native_wait_fds()
    }
}
impl RetainedFd {
    fn uring_supported(open: &OpenDescription) -> Result<()> {
        // Retaining another ring could form an uncollectable RC cycle. These
        // descriptor classes need additional process/signal/terminal authority.
        if open.anonymous.as_ref().is_some_and(|a| {
            matches!(
                a,
                events::Anonymous::Uring(_) | events::Anonymous::Epoll { .. }
            )
        }) || matches!(
            open.kind,
            FdKind::Stdin | FdKind::Stdout | FdKind::Stderr | FdKind::Terminal
        ) {
            return Err(Errno(95));
        }
        Ok(())
    }
    pub fn uring_file(&self) -> Result<UringFile> {
        Self::uring_supported(&self.0.open.borrow())?;
        self.shared_file()
            .map(|file| UringFile {
                lease: None,
                file,
                owner: None,
            })
            .ok_or(Errno(95))
    }
}
pub trait UringFileView {
    fn with_retained<T>(&self, vfs: &Vfs, operation: impl FnOnce(&RetainedFd) -> T) -> T;
}
impl UringFileView for RetainedFd {
    fn with_retained<T>(&self, _vfs: &Vfs, operation: impl FnOnce(&RetainedFd) -> T) -> T {
        operation(self)
    }
}
impl UringFileView for UringFile {
    fn with_retained<T>(&self, vfs: &Vfs, operation: impl FnOnce(&RetainedFd) -> T) -> T {
        operation(&self.retained_in(vfs))
    }
}
#[derive(Clone)]
pub struct UringSqe(pub [u8; 64]);
impl UringSqe {
    pub fn opcode(&self) -> u8 {
        self.0[0]
    }
    pub fn flags(&self) -> u8 {
        self.0[1]
    }
    pub fn ioprio(&self) -> u16 {
        u16::from_le_bytes(self.0[2..4].try_into().unwrap())
    }
    pub fn buffer_group(&self) -> u16 {
        u16::from_le_bytes(self.0[40..42].try_into().unwrap())
    }
    pub fn multishot(&self) -> bool {
        match self.opcode() {
            6 => self.length() & 1 != 0,
            11 => self.op_flags() & 64 != 0,
            13 => self.ioprio() & 1 != 0,
            27 => self.ioprio() & 2 != 0,
            _ => false,
        }
    }
    pub fn fd(&self) -> i32 {
        self.u32(4) as i32
    }
    pub fn offset(&self) -> u64 {
        self.u64(8)
    }
    pub fn address(&self) -> u64 {
        self.u64(16)
    }
    pub fn length(&self) -> u32 {
        self.u32(24)
    }
    pub fn op_flags(&self) -> u32 {
        self.u32(28)
    }
    pub fn user_data(&self) -> u64 {
        self.u64(32)
    }
    pub fn u32(&self, offset: usize) -> u32 {
        u32::from_le_bytes(self.0[offset..offset + 4].try_into().unwrap())
    }
    pub fn u64(&self, offset: usize) -> u64 {
        u64::from_le_bytes(self.0[offset..offset + 8].try_into().unwrap())
    }
}
#[derive(Clone)]
pub enum UringObject {
    Byte(DirectFd),
    Tcp(DirectTcpFd),
    File(DirectFile),
}
#[derive(Clone)]
pub struct UringResource {
    pub object: UringObject,
    pub identity: usize,
}

/// Lifetime hook for source-task execution state. The ring never owns the task,
/// Files root, path island or factory; only this weak cleanup token crosses it.
pub trait UringExecutionLease: Send + Sync {}
pub trait UringSource: Send + Sync {}
#[derive(Clone)]
pub struct UringRequest {
    pub owner: u64,
    pub task: u32,
    pub sequence: u64,
    pub sqe: UringSqe,
    pub resource: Option<UringResource>,
    pub execution: Option<Arc<dyn UringExecutionLease>>,
    pub source: Option<std::sync::Weak<dyn UringSource>>,
    pub file: Option<UringFile>,
    pub buffer: Option<Arc<trames_memory::PinnedBuffer>>,
    pub selection: Option<UringSelection>,
    pub selected_identity: Option<u64>,
    pub error: Option<Errno>,
    pub dependency: Option<(u64, bool)>,
    pub deadline: Option<Instant>,
    pub parts: Option<Vec<(u64, usize)>>,
    pub requested: u64,
    pub path: Option<Vec<u8>>,
    pub how: Option<(u32, u32, u64)>,
    pub started: bool,
    pub timeout_count: Option<u64>,
    pub timeout_target: Option<u64>,
    pub timeout_duration: Option<std::time::Duration>,
    pub shots: u64,
    pub poll_ready: u16,
    pub poll_epoch: [u64; 2],
}
#[derive(Clone)]
pub struct UringSelection {
    pub buffer: UringProvidedBuffer,
    pub group: u16,
    pub identity: u64,
    pub lease: Arc<dyn UringExecutionLease>,
}
#[derive(Clone, Copy)]
pub struct UringProvidedBuffer {
    pub address: u64,
    pub length: u32,
    pub id: u16,
}
pub enum UringBufferSource {
    Classic(VecDeque<UringProvidedBuffer>),
    Ring {
        memory: Arc<trames_memory::PinnedBuffer>,
        head: u16,
        entries: u16,
    },
}
pub struct UringBufferGroup {
    pub identity: u64,
    pub owner: u64,
    pub source: UringBufferSource,
}
impl UringBufferGroup {
    pub fn new(owner: u64, source: UringBufferSource) -> Self {
        Self {
            identity: trames_memory::new_backing_identity(),
            owner,
            source,
        }
    }

    pub fn slots(&self) -> usize {
        match &self.source {
            UringBufferSource::Classic(b) => b.len(),
            UringBufferSource::Ring { entries, .. } => *entries as usize,
        }
    }
}
pub struct UringRunning {
    pub owner: u64,
    pub key: Option<usize>,
    pub data: u64,
    pub opcode: u8,
}
#[derive(Default)]
pub struct UringState {
    pub active: std::collections::BTreeSet<u64>,
    pub drains: std::collections::BTreeSet<u64>,
    pub dependencies: BTreeMap<u64, usize>,
    pub inflight: usize,
    pub inflight_metadata: usize,
    pub waits: BTreeMap<u32, (u32, Option<Instant>)>,
    pub scratch: Vec<u8>,
    pub cache: DiskReadCache,
    pub busy_groups: std::collections::BTreeSet<u64>,
    pub contended_groups: std::collections::BTreeSet<u64>,
    pub running: BTreeMap<u64, UringRunning>,
    pub shot_reservations: usize,
    pub head: u32,
    pub tail: u32,
    pub dropped: u32,
    pub next: u64,
    pub completion_count: u64,
    pub pending: VecDeque<UringRequest>,
    pub completed: BTreeMap<u64, bool>,
    pub overflow: VecDeque<(u64, i32, u32)>,
    pub provided: BTreeMap<u16, UringBufferGroup>,
    pub retired_groups: BTreeMap<u64, UringBufferGroup>,
    pub multishot_cursor: u64,
    pub files: Option<Vec<Option<UringFile>>>,
    pub buffers: Option<Vec<Arc<trames_memory::PinnedBuffer>>>,
    pub eventfd: Option<UringFile>,
}
/// Opaque traversal lifetimes, retired after the caller releases ring metadata.
pub struct UringRetirement(ipc::ownership::Retirement);
impl UringRetirement {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
pub struct Uring {
    pub entries: u32,
    pub cq_entries: u32,
    pub ring_bytes: u64,
    pub sqe_bytes: u64,
    pages: Vec<Arc<trames_memory::SharedPage>>,
    _file_pages: Vec<Arc<mapped::FilePage>>,
    pub state: std::sync::Mutex<UringState>,
    pub readiness: Arc<Readiness>,
    pub(crate) ownership: std::sync::Weak<ipc::ownership::Ownership>,
}
impl Uring {
    pub fn bind_file(self: &Arc<Self>, file: &UringFile) -> Result<UringFile> {
        self.bind_file_deferred(file).0
    }
    pub fn bind_file_deferred(
        self: &Arc<Self>,
        file: &UringFile,
    ) -> (Result<UringFile>, UringRetirement) {
        if file
            .lease
            .as_ref()
            .is_some_and(|link| link.belongs_to_ring(self))
        {
            return (Ok(file.clone()), UringRetirement(Default::default()));
        }
        let (lease, retired) = ipc::ownership::Ownership::ring(self, &file.file.open);
        (
            lease.map(|lease| UringFile {
                lease,
                file: file.file.clone(),
                owner: file.owner.clone(),
            }),
            UringRetirement(retired),
        )
    }

    pub fn queue_pages(&self) -> Vec<Arc<trames_memory::SharedPage>> {
        self.pages.clone()
    }
    pub fn read_queue<const N: usize>(&self, offset: usize) -> [u8; N] {
        let mut bytes = [0; N];
        self.pages[offset / PAGE_SIZE as usize].copy_read(offset % PAGE_SIZE as usize, &mut bytes);
        bytes
    }
    pub fn write_queue(&self, offset: usize, bytes: &[u8]) {
        self.pages[offset / PAGE_SIZE as usize].copy_write(offset % PAGE_SIZE as usize, bytes);
    }
    pub fn load_queue(&self, offset: usize) -> u32 {
        if matches!(offset, 4 | 64) {
            // SAFETY: fixed aligned publication cells in the original queue.
            unsafe { self.pages[0].load_acquire_u32(offset) }
        } else {
            u32::from_le_bytes(self.read_queue(offset))
        }
    }
    pub fn store_queue(&self, offset: usize, value: u32) {
        if matches!(offset, 0 | 68) {
            // SAFETY: the same fixed publication cells, under the ring lock.
            unsafe {
                self.pages[0].store_release_u32(offset, value);
            }
        } else {
            self.write_queue(offset, &value.to_le_bytes());
        }
    }
    pub fn completion_event(&self, state: &UringState, count: u64) -> Option<(UringFile, u64)> {
        if count == 0 || !self.eventfd_enabled() {
            return None;
        }
        state.eventfd.clone().map(|file| (file, count))
    }
    pub fn notify_completion(&self, event: Option<(UringFile, u64)>) {
        if let Some((file, count)) = event {
            if let Some(fd) = file.direct_byte() {
                let _ = fd.write(&count.to_le_bytes());
            }
        }
        self.readiness.notify_locked();
    }
    pub fn outstanding_limit(&self) -> usize {
        (self.entries as usize * 8).min(8192)
    }
    pub fn sq_tail(&self) -> u32 {
        self.load_queue(4)
    }
    pub fn cq_epoch(&self) -> [u64; 2] {
        [self.state.lock().unwrap().tail as u64, 0]
    }
    pub fn eventfd_enabled(&self) -> bool {
        self.load_queue(84) & 1 == 0
    }
    pub fn cq_ready(&self) -> u32 {
        self.state
            .lock()
            .unwrap()
            .tail
            .wrapping_sub(self.load_queue(64))
            .min(self.cq_entries)
    }
    pub fn cq_head(&self, state: &UringState) -> Result<u32> {
        let head = self.load_queue(64);
        if state.tail.wrapping_sub(head) > self.cq_entries {
            return Err(Errno(22));
        }
        Ok(head)
    }
    pub fn sqe(&self, head: u32) -> Option<UringSqe> {
        let index = self.load_queue(URING_SQ_ARRAY + (head & (self.entries - 1)) as usize * 4);
        if index >= self.entries {
            return None;
        }
        Some(UringSqe(
            self.read_queue(self.ring_bytes as usize + index as usize * 64),
        ))
    }
    pub fn publish_head(&self, state: &UringState) {
        self.store_queue(0, state.head);
        self.store_queue(20, state.dropped);
    }
    pub fn flush(&self, state: &mut UringState) -> Result<u64> {
        let head = self.cq_head(state)?;
        let mut count = 0;
        while state.tail.wrapping_sub(head) < self.cq_entries {
            let Some((data, result, flags)) = state.overflow.pop_front() else {
                break;
            };
            let offset = URING_CQES + (state.tail & (self.cq_entries - 1)) as usize * 16;
            let mut bytes = [0; 16];
            bytes[..8].copy_from_slice(&data.to_le_bytes());
            bytes[8..12].copy_from_slice(&result.to_le_bytes());
            bytes[12..16].copy_from_slice(&flags.to_le_bytes());
            self.write_queue(offset, &bytes);
            state.tail = state.tail.wrapping_add(1);
            count += 1;
        }
        self.store_queue(68, state.tail);
        self.store_queue(16, if state.overflow.is_empty() { 0 } else { 2 });
        Ok(count)
    }
    pub fn mapping_offset(&self, offset: u64, len: u64, shared: bool) -> Result<u64> {
        if !shared {
            return Err(Errno(22));
        }
        match offset {
            0 | 0x0800_0000 if len <= self.ring_bytes => Ok(0),
            0x1000_0000 if len <= self.sqe_bytes => Ok(self.ring_bytes),
            _ => Err(Errno(22)),
        }
    }
    fn backpressured(&self, state: &UringState) -> bool {
        self.cq_head(state).map_or(true, |head| {
            state.pending.len() + state.overflow.len() + state.tail.wrapping_sub(head) as usize
                >= self.outstanding_limit()
        })
    }
    pub fn next_deadline(&self) -> Option<Instant> {
        let state = self.state.lock().unwrap();
        let blocked = self.backpressured(&state);
        state
            .pending
            .iter()
            .filter(|r| {
                matches!(r.sqe.opcode(), 11 | 15) && r.started && !(blocked && r.sqe.multishot())
            })
            .filter_map(|r| r.deadline)
            .min()
    }
    pub fn native_wait_fds(&self) -> Vec<HostFd> {
        let state = self.state.lock().unwrap();
        let blocked = self.backpressured(&state);
        state
            .pending
            .iter()
            .filter(|r| {
                r.started
                    && !(blocked && r.sqe.multishot())
                    && !(r.sqe.opcode() == 6 && r.sqe.multishot() && r.poll_ready != 0)
            })
            .filter_map(|r| r.file.as_ref())
            .flat_map(|file| file.native_wait_fds())
            .collect()
    }
    pub fn sockets(&self) -> Vec<(Arc<NetSocket>, u16)> {
        let state = self.state.lock().unwrap();
        let blocked = self.backpressured(&state);
        state
            .pending
            .iter()
            .filter(|r| {
                r.started && !(blocked && r.sqe.multishot())
                // A reported edge that remains level-ready would wake host
                // poll continuously. Existing joined checkpoints sample its
                // epoch again; no new polling thread or busy wait is added.
                && !(r.sqe.opcode()==6 && r.sqe.multishot() && r.poll_ready!=0)
            })
            .filter_map(|r| {
                Some((
                    r.file.as_ref()?.socket()?,
                    if matches!(r.sqe.opcode(), 2 | 5 | 16 | 23 | 26) {
                        4
                    } else if r.sqe.opcode() == 6 {
                        r.sqe.op_flags() as u16
                    } else {
                        1
                    },
                ))
            })
            .collect()
    }
}
impl Vfs {
    /// Read-only admission hint for a CQ observer. Actual capabilities are
    /// rebuilt at dispatch; no owner state is moved during scheduler queries.
    pub fn uring_poll_rings(&self, fd: u32) -> Option<Vec<Arc<Uring>>> {
        fn visit(open: &OpenDescription, rings: &mut Vec<Arc<Uring>>) -> Option<()> {
            match &open.anonymous {
                Some(events::Anonymous::Uring(r)) => rings.push(r.clone()),
                Some(events::Anonymous::Epoll { watches, .. }) => {
                    for watch in watches.borrow().values() {
                        if watch.state.lock().unwrap().armed {
                            if let Some(target) = watch.open.upgrade() {
                                visit(&target.borrow(), rings)?;
                            }
                        }
                    }
                }
                _ => {
                    DirectFd::snapshot(open)?;
                }
            }
            Some(())
        }
        let mut rings = Vec::new();
        visit(&self.descriptor(fd).ok()?.open.borrow(), &mut rings)?;
        Some(rings)
    }
    /// Retain the exact CPU byte domain of both ring mappings for one frozen
    /// cohort. Providers retain original OFDs; queue access shares their canonical
    /// SharedPage allocation. Even malformed concurrent guest writes remain under
    /// the interpreter's existing region guards, never bare Mapping copies.
    pub fn uring_queue_pages(&self, fd: u32) -> Result<Vec<Arc<dyn trames_memory::PageBacking>>> {
        let ring = self.uring(fd)?;
        let mut pages = self.mapping_pages(fd, 0, ring.ring_bytes, true, true)?;
        pages.extend(self.mapping_pages(fd, 0x1000_0000, ring.sqe_bytes, true, true)?);
        Ok(pages)
    }
    pub fn uring_descriptors(&self) -> Vec<(u32, Arc<Uring>)> {
        // Reuse the lazy ring index to avoid scanning unrelated FD tables.
        if self.urings().is_empty() {
            return Vec::new();
        }
        self.fds
            .entries()
            .iter()
            .filter_map(|(&fd, d)| match &d.open.borrow().anonymous {
                Some(events::Anonymous::Uring(r)) => Some((fd, r.clone())),
                _ => None,
            })
            .collect()
    }
    pub fn uring_create(&mut self, entries: u32, cq_entries: u32) -> Result<(u32, Arc<Uring>)> {
        self.uring_create_with_output(entries, cq_entries, || Ok(()))
    }
    pub fn uring_create_with_output(
        &mut self,
        entries: u32,
        cq_entries: u32,
        output: impl FnOnce() -> Result<()>,
    ) -> Result<(u32, Arc<Uring>)> {
        if entries == 0
            || entries > URING_MAX_ENTRIES
            || !entries.is_power_of_two()
            || cq_entries < entries
            || cq_entries > URING_MAX_ENTRIES * 2
            || !cq_entries.is_power_of_two()
        {
            return Err(Errno(22));
        }
        let page = PAGE_SIZE;
        let ring_bytes = (URING_CQES as u64 + cq_entries as u64 * 16).div_ceil(page) * page;
        let sqe_bytes = (entries as u64 * 64).div_ceil(page) * page;
        let files = self
            .query
            .as_ref()
            .map_or_else(|| self.shared_files(), |q| q.files.clone());
        let reservation = files.reserve()?;
        let mut open = self.memfd_open(b"io_uring", 1)?;
        let file = Self::shared_file_open(&open)?;
        if ring_bytes + sqe_bytes > self.file_size_limit.get() {
            return Err(Errno(27));
        }
        file.set_len((ring_bytes + sqe_bytes) as usize)
            .map_err(storage::host_errno)?;
        let (_file_pages, pages) =
            mapped::uring_pages(open.node.as_ref().unwrap(), ring_bytes + sqe_bytes)?;
        let ring = Arc::new(Uring {
            entries,
            cq_entries,
            ring_bytes,
            sqe_bytes,
            pages,
            _file_pages,
            state: Default::default(),
            readiness: Arc::default(),
            ownership: Arc::downgrade(&files.0.local_ownership),
        });
        for (offset, value) in [
            (8, entries - 1),
            (12, entries),
            (72, cq_entries - 1),
            (76, cq_entries),
        ] {
            ring.store_queue(offset, value);
        }
        let shared = Arc::get_mut(&mut open.shared).unwrap();
        shared.kind = FdKind::Anonymous;
        shared.control = Some(events::SharedControl::Uring(ring.clone()));
        open.anonymous = Some(events::Anonymous::Uring(ring.clone()));
        let descriptor = Descriptor {
            open: OpenHandle::new(open),
            cloexec: true.into(),
        };
        output()?;
        let fd = reservation.publish(descriptor, self.query.is_none().then_some(&self.fds))?;
        Ok((fd, ring))
    }
    pub fn uring(&self, fd: u32) -> Result<Arc<Uring>> {
        match &self.descriptor(fd)?.open.borrow().anonymous {
            Some(events::Anonymous::Uring(ring)) => Ok(ring.clone()),
            _ => Err(Errno(9)),
        }
    }
    pub fn urings(&self) -> Vec<Arc<Uring>> {
        self.fds
            .cache()
            .urings
            .get_or_init(|| {
                let mut rings = Vec::new();
                for d in self.fds.entries().values() {
                    if let Some(events::Anonymous::Uring(ring)) = &d.open.borrow().anonymous {
                        if !rings
                            .iter()
                            .any(|r: &std::sync::Weak<Uring>| r.ptr_eq(&Arc::downgrade(ring)))
                        {
                            rings.push(Arc::downgrade(ring));
                        }
                    }
                }
                rings.into()
            })
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .collect()
    }
    pub fn retain_uring_file(&self, fd: u32) -> Result<UringFile> {
        let retained = self.retain_uring_fd(fd)?;
        if retained.shared_file().is_some() {
            return retained.uring_file();
        }
        self.reap_uring_files();
        let id = trames_memory::new_backing_identity();
        let token = Arc::new(());
        let file = SharedFd::new(retained.0.open.borrow().shared.clone());
        self.local_rights.retain_uring(id, &token, retained);
        Ok(UringFile {
            lease: None,
            file,
            owner: Some((id, token)),
        })
    }
    pub fn reap_uring_files(&self) {
        self.local_rights.reap_uring();
    }
    pub fn retain_uring_fd(&self, fd: u32) -> Result<RetainedFd> {
        let descriptor = self.descriptor(fd)?;
        let open = descriptor.open.borrow();
        RetainedFd::uring_supported(&open)?;
        Ok(RetainedFd(descriptor.clone()))
    }
    /// A private descriptor view lets existing VFS operations act on the exact
    /// retained OFD after close/dup/reuse, without installing a guest-visible FD.
    /// The original table/identity is restored even if a host operation panics.
    /// Only joined resource operations run here; no guest code/callback runs.
    pub fn with_uring_fd<T>(
        &mut self,
        file: &impl UringFileView,
        f: impl FnOnce(&mut Self, u32) -> T,
    ) -> T {
        {
            let retained = file.with_retained(self, Clone::clone);
            self.with_uring_view(&retained, false, f)
        }
    }
    /// Path resolution must still see the original /proc/self/fd namespace.
    /// Only metadata/path operations pay for cloning that private table.
    pub fn with_uring_path_fd<T>(
        &mut self,
        file: &impl UringFileView,
        f: impl FnOnce(&mut Self, u32) -> T,
    ) -> T {
        {
            let retained = file.with_retained(self, Clone::clone);
            self.with_uring_view(&retained, true, f)
        }
    }
    fn with_uring_view<T>(
        &mut self,
        file: &RetainedFd,
        paths: bool,
        f: impl FnOnce(&mut Self, u32) -> T,
    ) -> T {
        struct Restore<'a> {
            vfs: &'a mut Vfs,
            saved: DescriptorTable,
            retained: Option<(u32, SharedFd)>,
        }
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                self.vfs.fds = std::mem::take(&mut self.saved);
                if let Some(query) = &mut self.vfs.query {
                    query.retained = self.retained.take();
                }
            }
        }
        let saved = std::mem::take(&mut self.fds);
        let alias = if paths {
            self.fds = saved.clone();
            MAX_FDS
        } else {
            0
        };
        self.fds.insert(alias, file.0.clone());
        let retained = if let Some(query) = &mut self.query {
            let old = query.retained.take();
            query.retained = Some((
                alias,
                file.shared_file()
                    .expect("query has shared retained authority"),
            ));
            old
        } else {
            None
        };
        let guard = Restore {
            vfs: self,
            saved,
            retained,
        };
        f(guard.vfs, alias)
    }
    /// Install a descriptor produced by an operation on a retained OFD into
    /// the original guest table, rather than losing it with the private view.
    pub fn with_uring_install(
        &mut self,
        file: &impl UringFileView,
        f: impl FnOnce(&mut Self, u32) -> Result<u32>,
    ) -> Result<u32> {
        let retained = file.with_retained(self, Clone::clone);
        let file = &retained;
        {
            let target = self.available(0)?;
            let operation = |v: &mut Self, fd| {
                let created = f(v, fd)?;
                v.descriptor(created)
            };
            let descriptor = if matches!(file.kind(), FdKind::Node(_)) {
                self.with_uring_path_fd(file, operation)
            } else {
                self.with_uring_fd(file, operation)
            }?;
            self.fds.insert(target, descriptor);
            Ok(target)
        }
    }
    pub fn uring_eventfd(&self, fd: u32) -> Result<RetainedFd> {
        let file = self.retain_uring_fd(fd)?;
        if !matches!(
            file.0.open.borrow().anonymous,
            Some(events::Anonymous::Event(_))
        ) {
            return Err(Errno(22));
        }
        Ok(file)
    }
}

impl DirectPoll for Uring {
    fn into_uring(self: Arc<Self>) -> Option<Arc<Uring>> {
        Some(self)
    }
    fn identity(&self) -> usize {
        self as *const Self as usize
    }
    fn poll(&self, events: u16) -> (u16, [u64; 2]) {
        let state = self.state.lock().unwrap();
        let ready = state
            .tail
            .wrapping_sub(self.load_queue(64))
            .min(self.cq_entries);
        (
            if ready != 0 { events & 1 } else { 0 },
            [state.tail as u64, 0],
        )
    }
    fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.readiness.subscribe(signal)
    }
}

impl Drop for Uring {
    fn drop(&mut self) {
        self.readiness.notify_locked();
    }
}
