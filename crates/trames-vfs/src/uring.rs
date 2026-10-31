// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux io_uring shared queues and retained open descriptions. Execution lives
//! in trames-linux; no guest FD or guest-selected path becomes a host FD/path.
use super::*;
use std::{sync::atomic::AtomicU32, time::Instant};
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
        Vfs::poll_open(&self.0.open.borrow(), events, 0)
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
        (Vfs::poll_open(&open, events, 0), Vfs::poll_epoch(&open))
    }
    pub fn socket(&self) -> Option<Rc<NetSocket>> {
        self.0.open.borrow().socket.clone()
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
pub struct UringRequest {
    pub owner: u64,
    pub task: u32,
    pub sequence: u64,
    pub sqe: UringSqe,
    pub file: Option<RetainedFd>,
    pub buffer: Option<Arc<trames_memory::PinnedBuffer>>,
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
    pub owner: u64,
    pub source: UringBufferSource,
}
impl UringBufferGroup {
    pub fn slots(&self) -> usize {
        match &self.source {
            UringBufferSource::Classic(b) => b.len(),
            UringBufferSource::Ring { entries, .. } => *entries as usize,
        }
    }
}
#[derive(Default)]
pub struct UringState {
    pub head: u32,
    pub tail: u32,
    pub dropped: u32,
    pub next: u64,
    pub completion_count: u64,
    pub pending: VecDeque<UringRequest>,
    pub completed: BTreeMap<u64, bool>,
    pub overflow: VecDeque<(u64, i32, u32)>,
    pub provided: BTreeMap<u16, UringBufferGroup>,
    pub multishot_cursor: u64,
    pub files: Option<Vec<Option<RetainedFd>>>,
    pub buffers: Option<Vec<Arc<trames_memory::PinnedBuffer>>>,
    pub eventfd: Option<RetainedFd>,
}
pub struct Uring {
    pub entries: u32,
    pub cq_entries: u32,
    pub ring_bytes: u64,
    pub sqe_bytes: u64,
    memory: trames_shared::Mapping,
    pub state: RefCell<UringState>,
}
impl Uring {
    fn load(&self, offset: usize) -> u32 {
        // SAFETY: owned, page-aligned mapping and fixed aligned u32 offsets.
        // Acquire pairs with the guest's queue publication. This object is
        // coordinator-local; SQE copies happen only after all workers joined.
        unsafe { (&*self.memory.pointer().add(offset).cast::<AtomicU32>()).load(Ordering::Acquire) }
    }
    fn store(&self, offset: usize, value: u32) {
        unsafe {
            (&*self.memory.pointer().add(offset).cast::<AtomicU32>())
                .store(value, Ordering::Release);
        }
    }
    pub fn outstanding_limit(&self) -> usize {
        (self.entries as usize * 8).min(8192)
    }
    pub fn sq_tail(&self) -> u32 {
        self.load(4)
    }
    pub fn cq_epoch(&self) -> [u64; 2] {
        [self.state.borrow().tail as u64, 0]
    }
    pub fn eventfd_enabled(&self) -> bool {
        self.load(84) & 1 == 0
    }
    pub fn cq_ready(&self) -> u32 {
        self.state
            .borrow()
            .tail
            .wrapping_sub(self.load(64))
            .min(self.cq_entries)
    }
    pub fn cq_head(&self, state: &UringState) -> Result<u32> {
        let head = self.load(64);
        if state.tail.wrapping_sub(head) > self.cq_entries {
            return Err(Errno(22));
        }
        Ok(head)
    }
    pub fn sqe(&self, head: u32) -> Option<UringSqe> {
        let index = self.load(URING_SQ_ARRAY + (head & (self.entries - 1)) as usize * 4);
        if index >= self.entries {
            return None;
        }
        let mut bytes = [0; 64];
        // SAFETY: kernel-private queue sizes bound the slot. Guest CPUs are
        // joined, so no Rust slice or concurrent copy of mutable SQEs exists.
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.memory
                    .pointer()
                    .add(self.ring_bytes as usize + index as usize * 64),
                bytes.as_mut_ptr(),
                64,
            );
        }
        Some(UringSqe(bytes))
    }
    pub fn publish_head(&self, state: &UringState) {
        self.store(0, state.head);
        self.store(20, state.dropped);
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
            // SAFETY: retained mapping, bounded slot; joined guest CPUs. CQ
            // bytes precede the release tail store and remain valid after FD close.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    self.memory.pointer().add(offset),
                    16,
                );
            }
            state.tail = state.tail.wrapping_add(1);
            count += 1;
        }
        self.store(68, state.tail);
        self.store(16, if state.overflow.is_empty() { 0 } else { 2 });
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
        let state = self.state.borrow();
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
        let state = self.state.borrow();
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
    pub fn sockets(&self) -> Vec<(Rc<NetSocket>, u16)> {
        let state = self.state.borrow();
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
    pub fn uring_poll_rings(&self, fd: u32) -> Option<Vec<Rc<Uring>>> {
        fn visit(open: &OpenDescription, rings: &mut Vec<Rc<Uring>>) -> Option<()> {
            match &open.anonymous {
                Some(events::Anonymous::Uring(r)) => rings.push(r.clone()),
                Some(events::Anonymous::Epoll { watches, .. }) => {
                    for watch in watches.values() {
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
    /// cohort. The Rc page backings stay on the owner; only SharedPage Arcs
    /// cross the boundary. Even malformed concurrent guest writes remain under
    /// the interpreter's existing region guards, never bare Mapping copies.
    pub fn uring_queue_pages(&self, fd: u32) -> Result<Vec<Rc<dyn trames_memory::PageBacking>>> {
        let ring = self.uring(fd)?;
        let mut pages = self.mapping_pages(fd, 0, ring.ring_bytes, true, true)?;
        pages.extend(self.mapping_pages(fd, 0x1000_0000, ring.sqe_bytes, true, true)?);
        Ok(pages)
    }
    pub fn uring_descriptors(&self) -> Vec<(u32, Rc<Uring>)> {
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
    pub fn uring_create(&mut self, entries: u32, cq_entries: u32) -> Result<(u32, Rc<Uring>)> {
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
        let fd = self.memfd_create(b"io_uring", 1)?;
        let result = (|| {
            self.truncate_fd(fd, ring_bytes + sqe_bytes)?;
            let memory = self
                .shared_file(fd)?
                .map(0, (ring_bytes + sqe_bytes) as usize)
                .map_err(storage::host_errno)?;
            let ring = Rc::new(Uring {
                entries,
                cq_entries,
                ring_bytes,
                sqe_bytes,
                memory,
                state: RefCell::default(),
            });
            for (offset, value) in [
                (8, entries - 1),
                (12, entries),
                (72, cq_entries - 1),
                (76, cq_entries),
            ] {
                ring.store(offset, value);
            }
            let open_descriptor = self.descriptor(fd)?;
            let mut open = open_descriptor.open.borrow_mut();
            Arc::get_mut(&mut open.shared)
                .expect("owner-local io_uring setup")
                .kind = FdKind::Anonymous;
            open.anonymous = Some(events::Anonymous::Uring(ring.clone()));
            Ok((fd, ring))
        })();
        if result.is_err() {
            let _ = self.close(fd);
        }
        result
    }
    pub fn uring(&self, fd: u32) -> Result<Rc<Uring>> {
        match &self.descriptor(fd)?.open.borrow().anonymous {
            Some(events::Anonymous::Uring(ring)) => Ok(ring.clone()),
            _ => Err(Errno(9)),
        }
    }
    pub fn urings(&self) -> Vec<Rc<Uring>> {
        self.fds
            .identity()
            .urings
            .get_or_init(|| {
                let mut rings = Vec::new();
                for d in self.fds.entries().values() {
                    if let Some(events::Anonymous::Uring(ring)) = &d.open.borrow().anonymous {
                        if !rings
                            .iter()
                            .any(|r: &Weak<Uring>| r.ptr_eq(&Rc::downgrade(ring)))
                        {
                            rings.push(Rc::downgrade(ring));
                        }
                    }
                }
                rings
            })
            .iter()
            .filter_map(Weak::upgrade)
            .collect()
    }
    pub fn retain_uring_fd(&self, fd: u32) -> Result<RetainedFd> {
        let descriptor = self.descriptor(fd)?;
        let open = descriptor.open.borrow();
        // Retaining another ring could form an uncollectable RC cycle. These
        // descriptor classes need additional process/signal/terminal authority.
        if open.anonymous.as_ref().is_some_and(|a| {
            matches!(
                a,
                events::Anonymous::Uring(_)
                    | events::Anonymous::Signal { .. }
                    | events::Anonymous::Epoll { .. }
            )
        }) || matches!(
            open.kind,
            FdKind::Stdin | FdKind::Stdout | FdKind::Stderr | FdKind::Terminal
        ) {
            return Err(Errno(95));
        }
        Ok(RetainedFd(descriptor.clone()))
    }
    /// A private descriptor view lets existing VFS operations act on the exact
    /// retained OFD after close/dup/reuse, without installing a guest-visible FD.
    /// The original table/identity is restored even if a host operation panics.
    /// Only joined resource operations run here; no guest code/callback runs.
    pub fn with_uring_fd<T>(
        &mut self,
        file: &RetainedFd,
        f: impl FnOnce(&mut Self, u32) -> T,
    ) -> T {
        self.with_uring_view(file, false, f)
    }
    /// Path resolution must still see the original /proc/self/fd namespace.
    /// Only metadata/path operations pay for cloning that private table.
    pub fn with_uring_path_fd<T>(
        &mut self,
        file: &RetainedFd,
        f: impl FnOnce(&mut Self, u32) -> T,
    ) -> T {
        self.with_uring_view(file, true, f)
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
        }
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                self.vfs.fds = std::mem::take(&mut self.saved);
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
        let guard = Restore { vfs: self, saved };
        f(guard.vfs, alias)
    }
    /// Install a descriptor produced by an operation on a retained OFD into
    /// the original guest table, rather than losing it with the private view.
    pub fn with_uring_install(
        &mut self,
        file: &RetainedFd,
        f: impl FnOnce(&mut Self, u32) -> Result<u32>,
    ) -> Result<u32> {
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
