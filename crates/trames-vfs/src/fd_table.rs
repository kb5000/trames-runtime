// SPDX-License-Identifier: GPL-3.0-or-later
//! One membership object per Linux files_struct, with stable lookup leases.
use super::open_handle::OpenView;
use super::*;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize},
    Mutex,
};

#[derive(Clone)]
pub(super) enum SlotOpen {
    Shared(Arc<SharedOpenDescription>),
    Owner(
        OpenHandle,
        Option<std::sync::Weak<SharedOpenDescription>>,
        Option<std::sync::Weak<SharedOpenDescription>>,
    ),
}
#[derive(Clone)]
pub(super) struct Slot {
    pub(super) open: SlotOpen,
    pub(super) cloexec: CloseOnExec,
    pub(super) proc: Option<ProcMetadata>,
}
#[derive(Clone)]
pub(super) struct ProcMetadata {
    open: std::sync::Weak<SharedOpenDescription>,
    label: Option<Vec<u8>>,
    namespace: bool,
    mount: Option<std::sync::Weak<mounts::MountData>>,
}
pub(super) struct ProcDescriptor {
    pub fd: u32,
    pub descriptor: Descriptor,
    pub label: Option<Vec<u8>>,
    pub namespace: bool,
    pub mount: Option<Arc<mounts::MountData>>,
}
impl Slot {
    fn release_record_locks(&self, owner: u32) {
        match &self.open {
            SlotOpen::Shared(open) => open.release_record_locks(owner),
            SlotOpen::Owner(..) => {
                if let Some(open) = self.proc.as_ref().and_then(|p| p.open.upgrade()) {
                    open.release_record_locks(owner);
                }
            }
        }
    }
    pub(super) fn shared_open(&self) -> Option<Result<&Arc<SharedOpenDescription>>> {
        let SlotOpen::Shared(open) = &self.open else {
            return None;
        };
        Some(
            if open.pipe.as_ref().is_some_and(|pipe| pipe.has_waiter()) {
                Err(Errno(9))
            } else {
                Ok(open)
            },
        )
    }
    pub(super) fn from_descriptor(d: &Descriptor) -> Self {
        Self {
            proc: matches!(d.open, OpenHandle::Owner(_)).then(|| {
                let open = d.open.borrow();
                ProcMetadata {
                    open: Arc::downgrade(&open.shared),
                    label: open
                        .namespace
                        .as_ref()
                        .map(linux_namespace::NamespaceHandle::label)
                        .or_else(|| open.anonymous.as_ref().map(|a| a.name().to_vec())),
                    namespace: open.namespace.is_some(),
                    mount: open.mount.as_ref().map(|m| match m {
                        OpenMount::Owner(m) => Arc::downgrade(&m.shared),
                        OpenMount::Shared(m) => Arc::downgrade(m),
                    }),
                }
            }),
            open: match &d.open {
                OpenHandle::Shared(open) => SlotOpen::Shared(open.clone()),
                OpenHandle::Owner(_) => {
                    SlotOpen::Owner(d.open.clone(), d.open.borrow().query_metadata(), {
                        let open = d.open.borrow();
                        (open.socket.is_some()
                            || matches!(open.control, Some(events::SharedControl::Epoll(_))))
                        .then(|| Arc::downgrade(&open.shared))
                    })
                }
            },
            cloexec: d.cloexec.clone(),
        }
    }
}
pub(super) struct Membership {
    pub(super) entries: Mutex<MembershipEntries>,
    pub(super) local_ownership: Arc<ipc::ownership::Ownership>,
    revision: AtomicU64,
    owners: AtomicUsize,
}
impl Default for Membership {
    fn default() -> Self {
        Self {
            entries: Mutex::default(),
            local_ownership: Arc::default(),
            revision: AtomicU64::new(0),
            owners: AtomicUsize::new(1),
        }
    }
}
#[derive(Default)]
pub(super) struct MembershipEntries {
    slots: BTreeMap<u32, Slot>,
    free: crate::fd_allocator::FreeFds,
    reserved: std::collections::BTreeSet<u32>,
}
impl std::ops::Deref for MembershipEntries {
    type Target = BTreeMap<u32, Slot>;
    fn deref(&self) -> &Self::Target {
        &self.slots
    }
}
impl MembershipEntries {
    pub(super) fn available(&self, min: u32) -> Option<u32> {
        self.free.next(min)
    }
    pub(super) fn insert(&mut self, fd: u32, slot: Slot) -> Option<Slot> {
        let old = self.slots.insert(fd, slot);
        if old.is_none() {
            self.free.reserve(fd);
        }
        old
    }
    pub(super) fn remove(&mut self, fd: &u32) -> Option<Slot> {
        let old = self.slots.remove(fd);
        if old.is_some() {
            self.free.release(*fd);
        }
        old
    }
    fn clear(&mut self) {
        self.slots.clear();
        self.free.clear();
    }
}
/// Actual membership, not a snapshot. Every slot retains its complete OFD.
/// Cold controls have object-local synchronization; weak metadata capabilities
/// still do not grant their callers permission to execute a control body.
#[derive(Clone)]
pub struct SharedFiles(
    pub(super) Arc<Membership>,
    Arc<std::sync::atomic::AtomicU32>,
);
impl Default for SharedFiles {
    fn default() -> Self {
        Self(
            Arc::default(),
            Arc::new(std::sync::atomic::AtomicU32::new(MAX_FDS)),
        )
    }
}

/// One actual Linux task's reference to files_struct. Cloning this capability
/// retains that same reference, not another task or another table owner.
#[derive(Clone)]
pub struct FileTableOwner(Arc<TaskFiles>);
struct TaskFiles {
    membership: Arc<Membership>,
    active: AtomicBool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileTableRetirement {
    pub last_owner: bool,
}
impl FileTableOwner {
    fn initial(files: &SharedFiles) -> Self {
        Self(Arc::new(TaskFiles {
            membership: files.0.clone(),
            active: AtomicBool::new(true),
        }))
    }
    fn shared(files: &SharedFiles) -> Self {
        let active = files
            .0
            .owners
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count != 0).then(|| count + 1)
            })
            .is_ok();
        Self(Arc::new(TaskFiles {
            membership: files.0.clone(),
            active: AtomicBool::new(active),
        }))
    }
    pub(super) fn observation(files: &SharedFiles) -> Self {
        Self(Arc::new(TaskFiles {
            membership: files.0.clone(),
            active: AtomicBool::new(false),
        }))
    }
    pub(super) fn detach(&self) {
        self.retire_inner(None);
    }
    pub fn retire(&self, lock_owner: u32) -> Option<FileTableRetirement> {
        self.retire_inner(Some(lock_owner))
    }
    pub(super) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    fn retire_inner(&self, lock_owner: Option<u32>) -> Option<FileTableRetirement> {
        self.0.retire(lock_owner)
    }
}
impl Drop for TaskFiles {
    fn drop(&mut self) {
        self.retire(None);
    }
}
impl TaskFiles {
    fn retire(&self, lock_owner: Option<u32>) -> Option<FileTableRetirement> {
        if !self.active.swap(false, Ordering::Relaxed) {
            return None;
        }
        let files = &self.membership;
        if files.owners.fetch_sub(1, Ordering::Relaxed) != 1 {
            return Some(FileTableRetirement { last_owner: false });
        }
        let removed = {
            let mut entries = files.entries.lock().unwrap();
            let removed = std::mem::take(&mut entries.slots);
            for fd in removed.keys() {
                entries.free.release(*fd);
            }
            if !removed.is_empty() {
                files.revision.fetch_add(1, Ordering::Relaxed);
            }
            removed
        };
        // Last-close can wake another executor or enter a native callback.
        // Neither an owner projection nor the membership mutex is borrowed.
        if let Some(owner) = lock_owner {
            for slot in removed.values() {
                slot.release_record_locks(owner);
            }
        }
        drop(removed);
        Some(FileTableRetirement { last_owner: true })
    }
}
/// An unpublished numeric slot. Rollback releases only this reservation.
pub(super) struct ReservedFd {
    files: SharedFiles,
    fd: u32,
    pending: bool,
}
impl ReservedFd {
    pub(super) fn publish(
        mut self,
        descriptor: Descriptor,
        owner: Option<&DescriptorTable>,
    ) -> Result<u32> {
        let mut entries = self.files.0.entries.lock().unwrap();
        if self.files.closed() {
            return Err(Errno(9));
        }
        assert!(entries.reserved.remove(&self.fd));
        if let Some(owner) = owner {
            assert!(owner.install(self.fd, descriptor, &mut entries).is_none());
        } else {
            let OpenHandle::Shared(open) = descriptor.open else {
                unreachable!("worker open admits only complete shared descriptions")
            };
            assert!(entries
                .insert(
                    self.fd,
                    Slot {
                        open: SlotOpen::Shared(open),
                        proc: None,
                        cloexec: descriptor.cloexec
                    }
                )
                .is_none());
            self.files.changed(&mut entries);
        }
        self.pending = false;
        Ok(self.fd)
    }
}
impl Drop for ReservedFd {
    fn drop(&mut self) {
        if self.pending {
            let mut entries = self.files.0.entries.lock().unwrap();
            assert!(entries.reserved.remove(&self.fd));
            entries.free.release(self.fd);
        }
    }
}
pub(super) struct ReservedPair {
    files: SharedFiles,
    fds: [u32; 2],
    pending: bool,
}
impl ReservedPair {
    pub(super) fn numbers(&self) -> [u32; 2] {
        self.fds
    }
    pub(super) fn publish(mut self, descriptions: [Descriptor; 2]) -> Result<[u32; 2]> {
        let mut entries = self.files.0.entries.lock().unwrap();
        if self.files.closed() {
            return Err(Errno(9));
        }
        for (fd, descriptor) in self.fds.into_iter().zip(descriptions) {
            let OpenHandle::Shared(open) = descriptor.open else {
                unreachable!("pipe descriptions are shared")
            };
            let reserved = entries.reserved.remove(&fd);
            debug_assert!(reserved);
            let previous = entries.insert(
                fd,
                Slot {
                    open: SlotOpen::Shared(open),
                    proc: None,
                    cloexec: descriptor.cloexec,
                },
            );
            debug_assert!(previous.is_none());
        }
        self.files.changed(&mut entries);
        self.pending = false;
        Ok(self.fds)
    }
}
impl Drop for ReservedPair {
    fn drop(&mut self) {
        if self.pending {
            let mut entries = self.files.0.entries.lock().unwrap();
            for fd in self.fds {
                let reserved = entries.reserved.remove(&fd);
                debug_assert!(reserved);
                entries.free.release(fd);
            }
        }
    }
}
pub(super) enum PollOpen {
    Tcp(Arc<SharedOpenDescription>, trames_net::TcpPoll),
    Shared(SharedFd),
    Epoll(Arc<SharedOpenDescription>),
}
impl SharedFiles {
    /// Retain the complete original OFD for an observation, including control
    /// descriptions whose byte operations have a separate implementation.
    pub(super) fn observation_descriptor(&self, fd: u32) -> Result<Descriptor> {
        let slot = self
            .0
            .entries
            .lock()
            .unwrap()
            .get(&fd)
            .cloned()
            .ok_or(Errno(9))?;
        let open = match slot.open {
            SlotOpen::Shared(open) => OpenHandle::Shared(open),
            SlotOpen::Owner(open, ..) => open,
        };
        if open
            .borrow()
            .pipe
            .as_ref()
            .is_some_and(|pipe| pipe.has_waiter())
        {
            return Err(Errno(9));
        }
        Ok(Descriptor {
            open,
            cloexec: slot.cloexec,
        })
    }
    pub(super) fn proc_descriptions(&self) -> Vec<ProcDescriptor> {
        let entries = self.0.entries.lock().unwrap();
        entries
            .iter()
            .filter_map(|(&fd, slot)| {
                let (open, label, namespace, mount) = match &slot.open {
                    SlotOpen::Shared(open) => (open.clone(), None, false, None),
                    SlotOpen::Owner(..) => {
                        let metadata = slot.proc.as_ref()?;
                        (
                            metadata.open.upgrade()?,
                            metadata.label.clone(),
                            metadata.namespace,
                            metadata.mount.as_ref().and_then(std::sync::Weak::upgrade),
                        )
                    }
                };
                let descriptor = Descriptor {
                    open: OpenHandle::Shared(open),
                    cloexec: slot.cloexec.clone(),
                };
                descriptor.ready().is_ok().then_some(ProcDescriptor {
                    fd,
                    descriptor,
                    label,
                    namespace,
                    mount,
                })
            })
            .collect()
    }
    pub(super) fn task_shared(&self) -> bool {
        self.0.owners.load(Ordering::Relaxed) > 1
    }
    fn closed(&self) -> bool {
        self.0.owners.load(Ordering::Relaxed) == 0
    }
    pub(super) fn control_open(&self, fd: u32) -> Option<Arc<SharedOpenDescription>> {
        let entries = self.0.entries.lock().unwrap();
        let open = match &entries.get(&fd)?.open {
            SlotOpen::Shared(open) => open.clone(),
            SlotOpen::Owner(_, _, open) => open.as_ref()?.upgrade()?,
        };
        Some(open)
    }
    /// Preserve a known descriptor/type error separately from absent legacy
    /// metadata. The returned original epoll core is accepted under membership.
    pub(super) fn epoll_open(&self, fd: u32) -> Option<Result<Arc<SharedOpenDescription>>> {
        let entries = self.0.entries.lock().unwrap();
        let Some(slot) = entries.get(&fd) else {
            return Some(Err(Errno(9)));
        };
        let open = match &slot.open {
            SlotOpen::Shared(open) => open.clone(),
            SlotOpen::Owner(_, _, metadata) => metadata.as_ref()?.upgrade()?,
        };
        Some(SharedFd::new(open.clone()).ready().and_then(|()| {
            if matches!(&open.control, Some(events::SharedControl::Epoll(_))) {
                Ok(open)
            } else {
                Err(Errno(22))
            }
        }))
    }
    /// Poll admission may use an epoll's complete shared interest core without
    /// promoting its owner projection into a transferable/shared descriptor.
    pub(super) fn poll_lookup(&self, fd: u32) -> Option<Result<PollOpen>> {
        let entries = self.0.entries.lock().unwrap();
        let Some(slot) = entries.get(&fd) else {
            return Some(Err(Errno(9)));
        };
        let open = match &slot.open {
            SlotOpen::Shared(open) => open.clone(),
            SlotOpen::Owner(_, _, metadata) => metadata.as_ref()?.upgrade()?,
        };
        if open.kind == FdKind::Socket
            && open.local.is_none()
            && !open.socket.as_ref().is_some_and(|s| s.is_netlink())
        {
            let tcp = open
                .tcp_publication
                .lock()
                .unwrap()
                .as_ref()
                .map(|publication| publication.tcp.poll_only());
            return Some(Ok(if let Some(tcp) = tcp {
                PollOpen::Tcp(open, tcp)
            } else {
                PollOpen::Shared(SharedFd::new(open))
            }));
        }
        match &slot.open {
            SlotOpen::Shared(_) => Some(Ok(PollOpen::Shared(SharedFd::new(open)))),
            SlotOpen::Owner(_, _, _)
                if matches!(&open.control, Some(events::SharedControl::Epoll(_))) =>
            {
                Some(Ok(PollOpen::Epoll(open)))
            }
            _ => None,
        }
    }

    pub(super) fn socket_control(&self, fd: u32) -> Option<Arc<SharedOpenDescription>> {
        let open = self.control_open(fd)?;
        open.socket_control.as_ref()?;
        Some(open)
    }
    pub(super) fn is_socket(&self, fd: u32) -> bool {
        self.control_open(fd)
            .is_some_and(|open| open.kind == FdKind::Socket && open.local.is_none())
    }
    pub(super) fn tcp_lookup(&self, fd: u32) -> Option<DirectTcpFd> {
        let entries = self.0.entries.lock().unwrap();
        let open = match &entries.get(&fd)?.open {
            SlotOpen::Shared(open) => open.clone(),
            SlotOpen::Owner(_, _, open) => open.as_ref()?.upgrade()?,
        };
        let mut tcp = open.tcp_publication.lock().unwrap().clone()?;
        // Accepted I/O retains its transport while membership is locked. The
        // stored capability remains weak, so snapshots do not delay FIN.
        tcp.lease = Some(tcp.tcp.retain().ok()?);
        Some(tcp)
    }
    pub(super) fn reserve_pair(&self) -> Result<ReservedPair> {
        let mut entries = self.0.entries.lock().unwrap();
        if self.closed() {
            return Err(Errno(9));
        }
        let free = entries.free.first(2);
        let fds: [u32; 2] = free.try_into().map_err(|_| Errno(24))?;
        if fds[1] >= self.descriptor_limit() {
            return Err(Errno(24));
        }
        for fd in fds {
            entries.free.reserve(fd);
            entries.reserved.insert(fd);
        }
        Ok(ReservedPair {
            files: self.clone(),
            fds,
            pending: true,
        })
    }
    pub(super) fn reserve(&self) -> Result<ReservedFd> {
        let mut entries = self.0.entries.lock().unwrap();
        if self.closed() {
            return Err(Errno(9));
        }
        let fd = entries
            .available(0)
            .filter(|&fd| fd < self.descriptor_limit())
            .ok_or(Errno(24))?;
        entries.free.reserve(fd);
        entries.reserved.insert(fd);
        Ok(ReservedFd {
            files: self.clone(),
            fd,
            pending: true,
        })
    }
    pub fn limit_handle(&self) -> super::DescriptorLimit {
        super::DescriptorLimit(self.1.clone())
    }
    pub fn descriptor_limit(&self) -> u32 {
        self.1.load(Ordering::Relaxed)
    }
    fn copy_limit(&self) -> Self {
        Self(
            self.0.clone(),
            Arc::new(std::sync::atomic::AtomicU32::new(self.descriptor_limit())),
        )
    }
}
#[derive(Clone)]
pub struct SharedFd {
    pub(super) open: Arc<SharedOpenDescription>,
}
impl SharedFd {
    pub fn uring(&self) -> Option<Arc<Uring>> {
        match &self.open.control {
            Some(events::SharedControl::Uring(ring)) => Some(ring.clone()),
            _ => None,
        }
    }
    pub(super) fn native_image(&self) -> Option<Arc<dyn trames_graphics::Image>> {
        self.open.native_image.clone()
    }
    pub(super) fn new(open: Arc<SharedOpenDescription>) -> Self {
        Self { open }
    }
    fn from_slot(slot: &Slot) -> Option<Self> {
        let SlotOpen::Shared(open) = &slot.open else {
            return None;
        };
        Some(Self { open: open.clone() })
    }
    fn ready(&self) -> Result<()> {
        if self.open.pipe.as_ref().is_some_and(|p| p.has_waiter()) {
            Err(Errno(9))
        } else {
            Ok(())
        }
    }
    pub fn identity(&self) -> usize {
        Arc::as_ptr(&self.open) as usize
    }
    /// Reconstruct the joined control view of this same accepted OFD.
    pub fn retained(self) -> RetainedFd {
        RetainedFd(Descriptor {
            open: OpenHandle::Shared(self.open),
            cloexec: false.into(),
        })
    }
    /// Accepted native I/O owns a real transport lease; poll snapshots stay weak.
    pub fn direct_tcp(&self) -> Option<DirectTcpFd> {
        let mut tcp = self.open.tcp_publication.lock().unwrap().clone()?;
        tcp.lease = Some(tcp.tcp.retain().ok()?);
        Some(tcp)
    }
    pub fn direct_byte(self) -> Option<DirectFd> {
        let fd = DirectFd::shared_byte(&self.open)?;
        if fd.is_poll_only() {
            return None;
        }
        Some(fd.with_ofd(self))
    }
    pub(super) fn direct_poll(self) -> Option<DirectFd> {
        if let Some(ring) = self.uring() {
            return Some(DirectFd::uring_poll(&self.open, ring).with_ofd(self));
        }

        if self.open.kind == FdKind::Socket && self.open.local.is_none() {
            let tcp = self
                .open
                .tcp_publication
                .lock()
                .unwrap()
                .as_ref()
                .map(|publication| publication.tcp.poll_only());
            let mut fd = if let Some(tcp) = tcp {
                DirectFd::tcp_poll(&self.open, tcp)
            } else {
                DirectFd::socket_poll(&self.open)?
            };
            fd.origin = Some(OfdIdentity::new(&self.open));
            return Some(fd);
        }
        // Named FIFO descriptions keep their pathname kind, but their poll
        // state and subscriptions still belong to the real pipe resource.
        let fd = DirectFd::shared_byte(&self.open).or_else(|| {
            (self.open.native_image.is_some() || matches!(self.open.kind, FdKind::Node(_)))
                .then(|| DirectFd::regular_poll(&self.open))
        })?;
        Some(fd.with_ofd(self))
    }
    pub(super) fn ofd_identity(&self) -> OfdIdentity {
        OfdIdentity::new(&self.open)
    }
}
impl SharedFiles {
    // Cold preparation key: captures retain this membership allocation, so its
    // address cannot be reused while a matching cache entry remains alive.
    pub(super) fn capture_identity(&self) -> (usize, u64) {
        (
            Arc::as_ptr(&self.0) as usize,
            self.0.revision.load(Ordering::Relaxed),
        )
    }
    pub(super) fn byte_descriptions(&self) -> Vec<SharedFd> {
        let entries = self.0.entries.lock().unwrap();
        entries
            .values()
            .filter_map(SharedFd::from_slot)
            .filter(|file| file.ready().is_ok())
            .collect()
    }
    pub(super) fn with_flags<T>(
        &self,
        fd: u32,
        access: &impl Fn(&StatusFlags, &CloseOnExec) -> Result<T>,
    ) -> Option<Result<T>> {
        let entries = self.0.entries.lock().unwrap();
        let Some(slot) = entries.get(&fd) else {
            return Some(Err(Errno(9)));
        };
        let retained;
        let open = match &slot.open {
            SlotOpen::Shared(_) => match slot.shared_open()? {
                Ok(open) => open,
                Err(error) => return Some(Err(error)),
            },
            // Socket/epoll slots publish this weak shared OFD. Expose
            // its existing atomic FD bits, never endpoint/namespace control.
            SlotOpen::Owner(_, _, open) => {
                retained = open.as_ref()?.upgrade()?;
                &retained
            }
        };
        Some(access(&open.flags, &slot.cloexec))
    }
    pub(super) fn cloexec_range(&self, first: u32, last: u32) -> Result<u64> {
        let entries = self.0.entries.lock().unwrap();
        fd_status::mark_cloexec_range(
            first,
            last,
            entries.iter().map(|(&fd, slot)| (fd, &slot.cloexec)),
        )?;
        Ok(0)
    }
    pub(super) fn changed(&self, _entries: &mut MembershipEntries) {
        self.0.revision.fetch_add(1, Ordering::Relaxed);
    }
    /// None means owner control is required, before any effects. A missing FD
    /// is an ordinary guest EBADF, not a concurrency-specific error.
    pub fn lookup(&self, fd: u32) -> Option<Result<SharedFd>> {
        let entries = self.0.entries.lock().unwrap();
        let Some(slot) = entries.get(&fd) else {
            return Some(Err(Errno(9)));
        };
        let file = SharedFd::from_slot(slot)?;
        Some(file.ready().map(|()| file))
    }
    /// Current membership, with read-only metadata admission for owner OFDs.
    pub(super) fn query_lookup(&self, fd: u32) -> Option<Result<SharedFd>> {
        let entries = self.0.entries.lock().unwrap();
        let Some(slot) = entries.get(&fd) else {
            return Some(Err(Errno(9)));
        };
        let file = match &slot.open {
            SlotOpen::Shared(open) => SharedFd::new(open.clone()),
            SlotOpen::Owner(_, metadata, _) => SharedFd::new(metadata.as_ref()?.upgrade()?),
        };
        Some(file.ready().map(|()| file))
    }
    pub fn duplicate(&self, old: u32, min: u32, cloexec: bool) -> Option<Result<u32>> {
        let mut entries = self.0.entries.lock().unwrap();
        let Some(slot) = entries.get(&old) else {
            return Some(Err(Errno(9)));
        };
        let open = match slot.shared_open()? {
            Ok(open) => open.clone(),
            Err(error) => return Some(Err(error)),
        };
        if min >= MAX_FDS {
            return Some(Err(Errno(22)));
        }
        let Some(fd) = entries
            .available(min)
            .filter(|&fd| fd < self.descriptor_limit())
        else {
            return Some(Err(Errno(24)));
        };
        entries.insert(
            fd,
            Slot {
                open: SlotOpen::Shared(open),
                proc: None,
                cloexec: cloexec.into(),
            },
        );
        self.changed(&mut entries);
        Some(Ok(fd))
    }
    pub fn duplicate_to(
        &self,
        old: u32,
        new: u32,
        flags: u32,
        lock_owner: u32,
    ) -> Option<Result<u32>> {
        if old == new || flags & !O_CLOEXEC != 0 {
            return Some(Err(Errno(22)));
        }
        if new >= self.descriptor_limit() {
            return Some(Err(Errno(9)));
        }
        let removed = {
            let mut entries = self.0.entries.lock().unwrap();
            let Some(slot) = entries.get(&old) else {
                return Some(Err(Errno(9)));
            };
            let open = match slot.shared_open()? {
                Ok(open) => open.clone(),
                Err(error) => return Some(Err(error)),
            };
            if entries.reserved.contains(&new) {
                return Some(Err(Errno(16))); // Linux dup/open reservation collision
            }
            if let Some(target) = entries.get(&new) {
                if let Err(error) = target.shared_open()? {
                    return Some(Err(error));
                }
            }
            let old = entries.insert(
                new,
                Slot {
                    open: SlotOpen::Shared(open),
                    proc: None,
                    cloexec: (flags & O_CLOEXEC != 0).into(),
                },
            );
            self.changed(&mut entries);
            old
        };
        if let Some(Slot {
            open: SlotOpen::Shared(open),
            ..
        }) = removed
        {
            open.release_record_locks(lock_owner);
        }
        Some(Ok(new))
    }
    pub fn close_range(&self, first: u32, last: u32, flags: u32, owner: u32) -> Result<()> {
        if first > last || flags & !6 != 0 {
            return Err(Errno(22));
        }
        let removed = {
            let mut entries = self.0.entries.lock().unwrap();
            if flags & 4 != 0 {
                for (_, slot) in entries.range(first..=last) {
                    slot.cloexec.set(true);
                }
                return Ok(());
            }
            let fds: Vec<_> = entries.range(first..=last).map(|(&fd, _)| fd).collect();
            let removed: Vec<_> = fds
                .into_iter()
                .filter_map(|fd| entries.remove(&fd))
                .collect();
            if !removed.is_empty() {
                self.changed(&mut entries);
            }
            removed
        };
        for slot in &removed {
            slot.release_record_locks(owner);
        }
        // Complete controls and native callbacks release outside Files' mutex.
        drop(removed);
        Ok(())
    }
    pub fn close(&self, fd: u32, lock_owner: u32) -> Option<Result<()>> {
        let removed = {
            let mut entries = self.0.entries.lock().unwrap();
            let Some(slot) = entries.get(&fd) else {
                return Some(Err(Errno(9)));
            };
            // Closing consumes membership/lifetime, not byte/control authority.
            // The published weak metadata is complete enough for FIFO readiness;
            // no opaque OFD lock or last-close callback runs under Files.
            let retained;
            let open = match &slot.open {
                SlotOpen::Shared(open) => open,
                SlotOpen::Owner(..) => {
                    retained = slot.proc.as_ref()?.open.upgrade()?;
                    &retained
                }
            };
            if open.pipe.as_ref().is_some_and(|pipe| pipe.has_waiter()) {
                return Some(Err(Errno(9)));
            }
            let old = entries.remove(&fd).expect("validated membership");
            self.changed(&mut entries);
            old
        };
        removed.release_record_locks(lock_owner);
        drop(removed); // Final original close runs outside membership.
        Some(Ok(()))
    }
}

#[derive(Clone)]
pub(super) struct Descriptor {
    pub(super) open: OpenHandle,
    pub(super) cloexec: CloseOnExec,
}
pub(super) struct Entry<'a> {
    pub(super) open: OpenView<'a>,
    pub(super) cloexec: &'a CloseOnExec,
}
impl Entry<'_> {
    pub(super) fn ready(&self) -> Result<()> {
        if self
            .open
            .borrow()
            .pipe
            .as_ref()
            .is_some_and(|p| p.has_waiter())
        {
            Err(Errno(9))
        } else {
            Ok(())
        }
    }
}
/// A bounded metadata inspection, with no allocation or extra OFD ownership.
/// Resource I/O and callbacks must use a separate retained lookup lease.
pub(super) struct Entries<'a> {
    membership: std::sync::MutexGuard<'a, MembershipEntries>,
}
impl Entries<'_> {
    fn entry<'a>(&'a self, slot: &'a Slot) -> Entry<'a> {
        Entry {
            open: match &slot.open {
                SlotOpen::Shared(open) => OpenView::Shared(open),
                SlotOpen::Owner(open, _, _) => OpenView::Owner(open),
            },
            cloexec: &slot.cloexec,
        }
    }
    pub(super) fn iter(&self) -> impl Iterator<Item = (&u32, Entry<'_>)> {
        self.membership
            .iter()
            .map(|(fd, slot)| (fd, self.entry(slot)))
    }
    pub(super) fn values(&self) -> impl Iterator<Item = Entry<'_>> {
        self.iter().map(|(_, entry)| entry)
    }
    pub(super) fn last_key_value(&self) -> Option<(&u32, Entry<'_>)> {
        self.membership
            .last_key_value()
            .map(|(fd, slot)| (fd, self.entry(slot)))
    }
    #[cfg(test)]
    pub(super) fn contains_key(&self, fd: &u32) -> bool {
        self.membership.contains_key(fd)
    }
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.membership.len()
    }
}
impl Descriptor {
    fn ready(&self) -> Result<()> {
        if self
            .open
            .borrow()
            .pipe
            .as_ref()
            .is_some_and(|p| p.has_waiter())
        {
            Err(Errno(9))
        } else {
            Ok(())
        }
    }
}
/// CLONE_FILES retains original membership; fork copies membership/CLOEXEC only.
/// Private caches never own descriptions; every lifetime belongs to membership.
pub(super) struct DescriptorTable(RefCell<TableState>, SharedFiles, FileTableOwner);
impl Default for DescriptorTable {
    fn default() -> Self {
        let files = SharedFiles::default();
        Self(
            RefCell::default(),
            files.clone(),
            FileTableOwner::initial(&files),
        )
    }
}
/// Per-VFS memoization: never shared mutably by CLONE_FILES or fork.
/// The version marker and populated immutable arrays can be retained cheaply.
#[derive(Clone, Default)]
pub(super) struct TableState {
    pub(super) console_bound: bool,
    observed: u64,
    identity: Arc<DescriptorVersion>,
    pub(super) flags: Option<(u64, FdFlags)>,
    pub(super) io: OnceCell<(FdMask, FdMask)>,
    pub(super) direct: Option<(u64, PreparedBytes)>,
    pub(super) urings: OnceCell<Arc<[std::sync::Weak<Uring>]>>,
    pub(super) timers: OnceCell<Arc<[std::sync::Weak<TimerFd>]>>,
}
type PreparedBytes = Arc<[Option<DirectFd>]>;
#[derive(Default)]
pub(super) struct DescriptorVersion;
impl DescriptorTable {
    pub(super) fn observe(files: SharedFiles) -> Self {
        let owner = FileTableOwner::observation(&files);
        Self(RefCell::default(), files, owner)
    }
    pub(super) fn adopt(files: SharedFiles, owner: FileTableOwner) -> Self {
        debug_assert!(Arc::ptr_eq(&files.0, &owner.0.membership));
        Self(RefCell::default(), files, owner)
    }
    pub(super) fn disown(&mut self) {
        self.2 = FileTableOwner::observation(&self.1);
    }

    pub(super) fn bind_limit(&mut self, limit: Arc<std::sync::atomic::AtomicU32>) {
        self.1 .1 = limit;
    }
    pub(super) fn available(&self, min: u32) -> Option<u32> {
        self.1
             .0
            .entries
            .lock()
            .unwrap()
            .available(min)
            .filter(|&fd| fd < self.1.descriptor_limit())
    }
    pub(super) fn available_fds(&self, count: usize) -> Vec<u32> {
        self.1
             .0
            .entries
            .lock()
            .unwrap()
            .free
            .first(count)
            .into_iter()
            .take_while(|&fd| fd < self.1.descriptor_limit())
            .collect()
    }
    #[cfg(test)]
    pub(super) fn set_test_capacity(&self, limit: u32) {
        let mut entries = self.1 .0.entries.lock().unwrap();
        let mut free = crate::fd_allocator::FreeFds::new(limit);
        for &fd in entries.keys() {
            assert!(fd < limit);
            free.reserve(fd);
        }
        entries.free = free;
    }
    pub(super) fn set_limit(&self, limit: u32) {
        self.1 .1.store(limit, Ordering::Relaxed);
    }
    pub(super) fn limit(&self) -> u32 {
        self.1.descriptor_limit()
    }
    pub(super) fn share_limit(&mut self, other: &Self) {
        self.1 .1 = other.1 .1.clone();
    }
    pub(super) fn membership(&self) -> &SharedFiles {
        &self.1
    }
    pub(super) fn worker_membership(&self) -> SharedFiles {
        self.1.clone()
    }
    pub(super) fn shared(&self) -> Self {
        let files = self.1.copy_limit();
        Self(
            RefCell::new(self.sync_cache().clone()),
            files.clone(),
            FileTableOwner::shared(&files),
        )
    }
    pub(super) fn shares_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.1 .0, &other.1 .0)
    }
    pub(super) fn task_owner(&self) -> FileTableOwner {
        self.2.clone()
    }
    pub(super) fn retire(&self, lock_owner: u32) {
        self.2.retire(lock_owner);
    }
    fn descriptor(&self, slot: &Slot) -> Descriptor {
        let open = match &slot.open {
            SlotOpen::Shared(open) => OpenHandle::Shared(open.clone()),
            SlotOpen::Owner(open, _, _) => open.clone(),
        };
        Descriptor {
            open,
            cloexec: slot.cloexec.clone(),
        }
    }
    pub(super) fn entries(&self) -> Entries<'_> {
        Entries {
            membership: self.1 .0.entries.lock().unwrap(),
        }
    }
    /// Lookup retains the original OFD independently of FD removal or reuse.
    /// No table borrow survives into resource I/O or last-close callbacks.
    pub(super) fn get(&self, fd: &u32) -> Option<Descriptor> {
        let entries = self.1 .0.entries.lock().unwrap();
        entries.get(fd).map(|slot| self.descriptor(slot))
    }
    pub(super) fn lookup(&self, fd: u32) -> Result<Descriptor> {
        let descriptor = self.get(&fd).ok_or(Errno(9))?;
        descriptor.ready()?;
        Ok(descriptor)
    }
    fn sync_cache(&self) -> std::cell::RefMut<'_, TableState> {
        let mut state = self.0.borrow_mut();
        let revision = self.1 .0.revision.load(Ordering::Relaxed);
        if state.observed != revision {
            state.changed();
            state.observed = revision;
        }
        state
    }
    pub(super) fn identity(&self) -> Arc<DescriptorVersion> {
        self.sync_cache().identity.clone()
    }
    pub(super) fn cache(&self) -> std::cell::RefMut<'_, TableState> {
        self.sync_cache()
    }
    pub(super) fn insert(&mut self, fd: u32, descriptor: Descriptor) -> Option<Descriptor> {
        self.install(fd, descriptor, &mut self.1 .0.entries.lock().unwrap())
    }
    // The returned lease keeps teardown/notifications outside the table lock.
    fn install(
        &self,
        fd: u32,
        descriptor: Descriptor,
        entries: &mut MembershipEntries,
    ) -> Option<Descriptor> {
        let old = entries.get(&fd).map(|slot| self.descriptor(slot));
        let slot = Slot::from_descriptor(&descriptor);
        entries.insert(fd, slot);
        self.1.changed(entries);
        old
    }
    pub(super) fn remove(&mut self, fd: &u32) -> Option<Descriptor> {
        let mut entries = self.1 .0.entries.lock().unwrap();
        let descriptor = entries.get(fd).map(|slot| self.descriptor(slot))?;
        entries.remove(fd);
        self.1.changed(&mut entries);
        Some(descriptor)
    }
    pub(super) fn close(&mut self, fd: u32) -> Result<Descriptor> {
        Ok(self.close_if(fd, |_| true)?.expect("unconditional close"))
    }
    /// Admission and removal share the lookup transaction. The predicate may
    /// inspect owner metadata only; resource teardown/callbacks occur afterward.
    pub(super) fn close_if(
        &mut self,
        fd: u32,
        allow: impl FnOnce(&Descriptor) -> bool,
    ) -> Result<Option<Descriptor>> {
        let mut entries = self.1 .0.entries.lock().unwrap();
        let descriptor = self.descriptor(entries.get(&fd).ok_or(Errno(9))?);
        descriptor.ready()?;
        if !allow(&descriptor) {
            return Ok(None);
        }
        entries.remove(&fd);
        self.1.changed(&mut entries);
        Ok(Some(descriptor))
    }
    pub(super) fn duplicate(&mut self, old: u32, min: u32, cloexec: bool) -> Result<u32> {
        let mut entries = self.1 .0.entries.lock().unwrap();
        let mut descriptor = self.descriptor(entries.get(&old).ok_or(Errno(9))?);
        descriptor.ready()?;
        if min >= MAX_FDS {
            return Err(Errno(22));
        }
        let fd = entries
            .available(min)
            .filter(|&fd| fd < self.1.descriptor_limit())
            .ok_or(Errno(24))?;
        descriptor.cloexec = cloexec.into();
        assert!(self.install(fd, descriptor, &mut entries).is_none());
        Ok(fd)
    }
    /// Publish the replacement in one table transaction, then return the old
    /// lease for lock release/last-close notifications outside the table borrow.
    pub(super) fn duplicate_to(
        &mut self,
        old: u32,
        new: u32,
        flags: u32,
    ) -> Result<Option<Descriptor>> {
        if old == new || flags & !O_CLOEXEC != 0 {
            return Err(Errno(22));
        }
        if new >= self.1.descriptor_limit() {
            return Err(Errno(9));
        }
        let mut entries = self.1 .0.entries.lock().unwrap();
        let mut descriptor = self.descriptor(entries.get(&old).ok_or(Errno(9))?);
        descriptor.ready()?;
        if entries.reserved.contains(&new) {
            return Err(Errno(16));
        }
        if let Some(target) = entries.get(&new) {
            self.descriptor(target).ready()?;
        }
        descriptor.cloexec = (flags & O_CLOEXEC != 0).into();
        Ok(self.install(new, descriptor, &mut entries))
    }
    pub(super) fn drain(&mut self) -> BTreeMap<u32, Descriptor> {
        let mut entries = self.1 .0.entries.lock().unwrap();
        let descriptors = entries
            .iter()
            .map(|(&fd, slot)| (fd, self.descriptor(slot)))
            .collect();
        if !entries.is_empty() {
            self.1.changed(&mut entries);
        }
        entries.clear();
        descriptors
    }
}
impl Drop for DescriptorTable {
    fn drop(&mut self) {
        self.2.retire_inner(None);
    }
}
impl TableState {
    fn changed(&mut self) {
        // A captured immutable marker keeps its old identity. All memoization
        // lives on this exclusively owned VFS, without a shared cache lock.
        if Arc::get_mut(&mut self.identity).is_none() {
            self.identity = Arc::default();
        }
        self.io.take();
        self.direct = None;
        self.urings.take();
        self.timers.take();
        self.flags = None;
    }
}
impl SharedFiles {
    /// Copy files_struct membership on the caller. Original descriptions,
    /// including cold controls, retain their own lifetime; CLOEXEC is private.
    /// In-flight numeric reservations are not open descriptors in the new table.
    pub fn fork(&self) -> (Self, FileTableOwner) {
        let (files, owner, _) = self.fork_with_revision();
        (files, owner)
    }
    fn fork_with_revision(&self) -> (Self, FileTableOwner, u64) {
        let source = self.0.entries.lock().unwrap();
        let mut free = source.free.clone();
        for fd in &source.reserved {
            free.release(*fd);
        }
        let slots = source
            .iter()
            .map(|(&fd, slot)| {
                let mut copy = slot.clone();
                copy.cloexec = slot.cloexec.fork();
                (fd, copy)
            })
            .collect();
        let revision = self.0.revision.load(Ordering::Relaxed);
        drop(source);
        let files = Self(
            Arc::new(Membership {
                local_ownership: self.0.local_ownership.clone(),
                entries: Mutex::new(MembershipEntries {
                    slots,
                    free,
                    reserved: Default::default(),
                }),
                revision: AtomicU64::new(0),
                owners: AtomicUsize::new(1),
            }),
            self.1.clone(),
        );
        let owner = FileTableOwner::initial(&files);
        (files, owner, revision)
    }
}
impl Clone for DescriptorTable {
    fn clone(&self) -> Self {
        let mut cache = self.sync_cache().clone();
        let (files, owner, revision) = self.1.copy_limit().fork_with_revision();
        // Membership may change on a peer between cache capture and fork.
        // Only memoization of the actual copied version can cross this fork.
        if cache.observed != revision {
            cache = TableState::default();
        }
        cache.observed = 0;
        cache.flags = None; // CLOEXEC and live Files now belong to the child.
        Self(RefCell::new(cache), files, owner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_fork_retains_control_identity_and_skips_unpublished_reservations() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<OpenHandle>();
        send_sync::<SharedFiles>();
        let mut v = Vfs::default();
        let epoll = v.epoll_create(O_CLOEXEC).unwrap();
        let [reader, writer] = v.pipe(O_NONBLOCK).unwrap();
        v.epoll_ctl(epoll, 1, reader, 1, 123).unwrap();
        let control = v.descriptor(epoll).unwrap().open.downgrade();
        let files = v.shared_files();
        let reservation = files.reserve().unwrap();
        let reserved = reservation.fd;
        let (copy, owner) = std::thread::spawn(move || files.fork()).join().unwrap();
        assert_eq!(copy.reserve().unwrap().fd, reserved);
        let mut child = Vfs {
            fds: DescriptorTable(RefCell::default(), copy.clone(), owner),
            ..Vfs::default()
        };
        assert_eq!(child.flags(epoll).unwrap() & O_CLOEXEC, O_CLOEXEC);
        child
            .fds
            .membership()
            .cloexec_range(reader, reader)
            .unwrap();
        assert_eq!(v.flags(reader).unwrap() & O_CLOEXEC, 0);
        v.close_all();
        drop(v);
        assert!(control.upgrade().is_some());
        child.write(writer, b"x").unwrap();
        assert_eq!(
            child.epoll_wait(epoll, 8, |_, _| Ok(None)).unwrap(),
            vec![(1, 123)]
        );
        let child_owner = child.file_table_owner();
        std::thread::spawn(move || child_owner.retire(1))
            .join()
            .unwrap();
        assert!(control.upgrade().is_none());
        assert!(matches!(copy.lookup(reader), Some(Err(Errno(9)))));
        drop(reservation);
    }

    #[test]
    fn source_task_retires_real_membership_before_owner_projection_collection() {
        let mut v = Vfs::default();
        let [reader, writer] = v.pipe(O_NONBLOCK).unwrap();
        let mut peer = v.clone_with_files(true);
        let files = v.shared_files();
        let accepted = files
            .lookup(reader)
            .unwrap()
            .unwrap()
            .direct_byte()
            .unwrap();
        let first = v.file_table_owner();
        let repeated = first.clone();
        let last = peer.file_table_owner();
        let result = std::thread::spawn(move || first.retire(1))
            .join()
            .unwrap()
            .unwrap();
        assert!(!result.last_owner);
        assert!(files.lookup(writer).unwrap().is_ok());
        assert_eq!(
            repeated.retire(1),
            None,
            "a capability clone is not a second Linux owner"
        );
        let result = std::thread::spawn(move || last.retire(1))
            .join()
            .unwrap()
            .unwrap();
        assert_eq!(result, FileTableRetirement { last_owner: true });
        assert!(matches!(files.lookup(writer), Some(Err(Errno(9)))));
        assert_eq!(
            accepted.read(1).unwrap(),
            b"",
            "writer is closed while both owner projections still exist"
        );
        v.release_descriptors();
        peer.release_descriptors();
        assert_eq!(accepted.read(1).unwrap(), b"");
        assert!(
            v.eventfd(0, 0).is_ok(),
            "the detached VFS can start a fresh table"
        );
    }
    #[test]
    fn volatile_file_lifetime_and_offset_are_shared_without_granting_worker_byte_authority() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, Default::default());
        let fd = v.open_at(AT_FDCWD, b"/proc/version", 0, 0).unwrap();
        let full = v.pread(fd, 128, 0).unwrap();
        assert!(full.len() > 4);
        let alias = v.dup(fd, 0, false).unwrap();
        let files = v.shared_files();
        let identity = Arc::downgrade(&files.lookup(fd).unwrap().unwrap().open);
        assert_eq!(v.read(fd, 1).unwrap(), &full[..1]);
        assert_eq!(v.read(alias, 3).unwrap(), &full[1..4]);
        assert_eq!(v.seek(fd, 0, 1), Ok(4));
        assert!(
            files.lookup(fd).unwrap().unwrap().direct_byte().is_none(),
            "dynamic contents retain their real admission boundary"
        );
        let task = v.file_table_owner();
        let result = std::thread::spawn(move || task.retire(1))
            .join()
            .unwrap()
            .unwrap();
        assert!(result.last_owner);
        assert!(identity.upgrade().is_none());
        assert_eq!(v.flags(alias), Err(Errno(9)));
    }
    #[test]
    fn concurrent_task_retirements_have_one_final_close_and_preserve_accepted_operations() {
        let mut v = Vfs::default();
        let [reader, writer] = v.pipe(O_NONBLOCK).unwrap();
        let peers: Vec<_> = (0..31).map(|_| v.clone_with_files(true)).collect();
        let read = v
            .shared_files()
            .lookup(reader)
            .unwrap()
            .unwrap()
            .direct_byte()
            .unwrap();
        let write = v
            .shared_files()
            .lookup(writer)
            .unwrap()
            .unwrap()
            .direct_byte()
            .unwrap();
        let owners: Vec<_> = std::iter::once(v.file_table_owner())
            .chain(peers.iter().map(Vfs::file_table_owner))
            .collect();
        let barrier = Arc::new(std::sync::Barrier::new(owners.len()));
        let last = std::thread::scope(|scope| {
            let workers: Vec<_> = owners
                .into_iter()
                .map(|owner| {
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        barrier.wait();
                        owner.retire(1).unwrap().last_owner
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| usize::from(worker.join().unwrap()))
                .sum::<usize>()
        });
        assert_eq!(last, 1);
        assert!(matches!(
            v.shared_files().lookup(writer),
            Some(Err(Errno(9)))
        ));
        assert_eq!(write.write(b"x"), Ok(1));
        assert_eq!(read.read(1).unwrap(), b"x");
        assert_eq!(read.read(1), Err(Errno(11)));
        drop(write);
        assert_eq!(read.read(1).unwrap(), b"");
        drop(peers);
        assert_eq!(read.read(1).unwrap(), b"");
    }
    #[test]
    fn late_factory_and_reserved_publication_cannot_resurrect_a_retired_table() {
        let v = Vfs::default();
        let files = v.shared_files();
        let factory = v.descriptor_factory();
        let reserved = files.reserve().unwrap();
        let pair = files.reserve_pair().unwrap();
        let descriptor = events::anonymous_descriptor(
            900,
            0,
            events::Anonymous::Event(Arc::new(direct_io::EventCounter::new(0, false))),
        );
        let other = descriptor.clone();
        let owner = v.file_table_owner();
        std::thread::spawn(move || owner.retire(1)).join().unwrap();
        assert_eq!(factory.eventfd(0, 0), Err(Errno(9)));
        assert!(matches!(files.reserve(), Err(Errno(9))));
        assert!(matches!(files.reserve_pair(), Err(Errno(9))));
        assert_eq!(reserved.publish(descriptor, None), Err(Errno(9)));
        assert_eq!(pair.publish([other.clone(), other]), Err(Errno(9)));
        assert!(files.0.entries.lock().unwrap().reserved.is_empty());
        assert!(files.0.entries.lock().unwrap().slots.is_empty());
        let mut closed_view = v.clone_with_files(true);
        assert_eq!(
            closed_view.eventfd(0, 0),
            Err(Errno(9)),
            "cloning a retired view cannot revive membership"
        );
    }
    #[test]
    fn control_retirement_releases_original_object_on_the_source() {
        let mut v = Vfs::default();
        let epoll = v.epoll_create(0).unwrap();
        let open = Arc::downgrade(&v.descriptor(epoll).unwrap().open.borrow().shared);
        let control = v.descriptor(epoll).unwrap().open.downgrade();
        let mut epoch = crate::FileEpoch::default();
        let captured = epoch.capture(&v, true);
        let bytes = v.direct_descriptors();
        let files = v.shared_files();
        let owner = v.file_table_owner();
        let result = std::thread::spawn(move || owner.retire(1))
            .join()
            .unwrap()
            .unwrap();
        assert_eq!(result, FileTableRetirement { last_owner: true });
        assert!(open.upgrade().is_none());
        assert!(control.upgrade().is_none());
        assert!(matches!(files.lookup(epoll), Some(Err(Errno(9)))));
        // Execution observations may retain shared poll resources, never the
        // complete control. Collection is only the task projection cleanup.
        v.collect_retired_descriptors();
        assert!(control.upgrade().is_none());
        drop((captured, bytes));
        epoch.finish();
        assert!(open.upgrade().is_none());
    }
    #[test]
    fn unpublished_reservations_are_invisible_and_dup_collision_matches_linux() {
        let mut owner = Vfs::default();
        owner.import_file(b"/file", b"x".to_vec()).unwrap();
        let fd = owner.open_at(AT_FDCWD, b"/file", 0, 0).unwrap();
        let files = owner.shared_files();
        let reservation = files.reserve().unwrap();
        let reserved = reservation.fd;
        assert!(matches!(files.lookup(reserved), Some(Err(Errno(9)))));
        assert_eq!(files.duplicate_to(fd, reserved, 0, 1), Some(Err(Errno(16))));
        assert_eq!(files.close(reserved, 1), Some(Err(Errno(9))));
        drop(reservation);
        assert_eq!(files.duplicate(fd, 0, false), Some(Ok(reserved)));
        owner.close(fd).unwrap();
        owner.close(reserved).unwrap();
    }

    #[test]
    fn nofile_is_per_process_even_with_shared_files_and_threads_can_share_it() {
        let mut parent = Vfs::default();
        let [old, writer] = parent.pipe(O_NONBLOCK).unwrap();
        let mut child = parent.clone_with_files(true);
        child.set_descriptor_limit(old);
        assert_eq!(child.open_at(AT_FDCWD, b"/dev/null", 0, 0), Err(Errno(24)));
        assert_eq!(child.dup(old, 0, false), Err(Errno(24)));
        assert_eq!(
            child.shared_files().duplicate(old, 0, false),
            Some(Err(Errno(24)))
        );
        assert_eq!(
            child.shared_files().duplicate_to(old, old + 1, 0, 1),
            Some(Err(Errno(9)))
        );
        parent.write(writer, b"x").unwrap();
        assert_eq!(child.read(old, 1).unwrap(), b"x");
        assert!(parent.open_at(AT_FDCWD, b"/dev/null", 0, 0).is_ok());
        child.share_descriptor_limit(&parent);
        child.set_descriptor_limit(old + 8);
        assert_eq!(parent.descriptor_limit(), old + 8);
        assert!(parent.open_at(AT_FDCWD, b"/dev/null", 0, 0).is_ok());
    }
    #[test]
    fn forked_byte_cache_keeps_each_actual_membership_when_reusing_owner_capabilities() {
        let mut parent = Vfs::default();
        let [reader, writer] = parent.pipe(0).unwrap();
        let original = parent.direct_descriptors();
        let mut child = parent.clone();
        let child_bytes = child.direct_descriptors();
        let parent_bytes = parent.direct_descriptors(); // cache hit after child capture
        child.close(reader).unwrap();
        assert!(child_bytes.get(reader).is_none());
        assert!(parent_bytes.get(reader).is_some());
        parent.write(writer, b"p").unwrap();
        assert_eq!(original.get(reader).unwrap().read(1), Ok(b"p".to_vec()));
        let [replacement, new_writer] = child.pipe(0).unwrap();
        assert_eq!(replacement, reader);
        child.write(new_writer, b"c").unwrap();
        parent.write(writer, b"p").unwrap();
        assert_eq!(parent_bytes.get(reader).unwrap().read(1), Ok(b"p".to_vec()));
        assert_eq!(child_bytes.get(reader).unwrap().read(1), Ok(b"c".to_vec()));
    }
    #[test]
    fn worker_membership_retains_original_ofd_across_close_and_numeric_reuse() {
        fn shared<T: Send + Sync>() {}
        shared::<SharedFiles>();
        shared::<SharedFd>();
        let mut v = Vfs::default();
        let [reader, writer] = v.pipe(O_NONBLOCK).unwrap();
        let files = v.shared_files();
        let accepted = files.lookup(writer).unwrap().unwrap();
        let alias = std::thread::scope(|scope| {
            let peer = files.clone();
            scope
                .spawn(move || {
                    for _ in 0..256 {
                        let fd = peer.duplicate(writer, 160, true).unwrap().unwrap();
                        assert_eq!(fd, 160);
                        assert_eq!(peer.duplicate_to(fd, 200, 0, 0), Some(Ok(200)));
                        assert_eq!(peer.close(fd, 0), Some(Ok(())));
                        assert_eq!(peer.close(200, 0), Some(Ok(())));
                    }
                    let alias = peer.duplicate(writer, 160, false).unwrap().unwrap();
                    assert_eq!(peer.close(writer, 0), Some(Ok(())));
                    alias
                })
                .join()
                .unwrap()
        });
        let [replacement, _] = v.pipe(O_NONBLOCK).unwrap();
        assert_eq!(replacement, writer);
        assert_ne!(
            accepted.identity(),
            files.lookup(replacement).unwrap().unwrap().identity()
        );
        assert_eq!(accepted.clone().direct_byte().unwrap().write(b"old"), Ok(3));
        assert_eq!(v.read(reader, 3).unwrap(), b"old");
        assert_eq!(files.close(alias, 0), Some(Ok(())));
        assert_eq!(v.read(reader, 1), Err(Errno(11)));
        drop(accepted);
        assert_eq!(v.read(reader, 1).unwrap(), b"");
    }
    #[test]
    fn shared_ring_slots_support_structural_effects_without_owner_projections() {
        let mut v = Vfs::default();
        let [_, writer] = v.pipe(O_NONBLOCK).unwrap();
        let (owner, _ring) = v.uring_create(2, 4).unwrap();
        let files = v.shared_files();
        assert_eq!(files.duplicate(owner, 160, false), Some(Ok(160)));
        assert_eq!(files.duplicate_to(writer, owner, 0, 0), Some(Ok(owner)));
        assert_eq!(v.fd_kind(owner), Ok(FdKind::PipeWrite));
        assert_eq!(files.close(160, 0), Some(Ok(())));
        assert_eq!(v.flags(160), Err(Errno(9)));
    }
    #[test]
    fn shared_anonymous_ofds_release_at_the_last_actual_lease_not_cache_refresh() {
        let mut v = Vfs::default();
        let event = v.eventfd(7, O_NONBLOCK).unwrap();
        let timer = v.timerfd(1, O_NONBLOCK).unwrap();
        let notify = v.inotify_init(O_NONBLOCK).unwrap();
        let files = v.shared_files();
        let cache = v.direct_descriptors();
        for fd in [event, timer, notify] {
            let accepted = files.lookup(fd).unwrap().unwrap();
            let lifetime = Arc::downgrade(&accepted.open);
            let cap = accepted.direct_byte().unwrap();
            let alias = files.duplicate(fd, 160, true).unwrap().unwrap();
            assert_eq!(alias, 160);
            assert_ne!(v.flags(alias).unwrap() & O_CLOEXEC, 0);
            assert_eq!(files.close(fd, 0), Some(Ok(())));
            assert!(cache.get(fd).is_none());
            assert_eq!(files.close(alias, 0), Some(Ok(())));
            assert!(lifetime.upgrade().is_some());
            // A real accepted operation is the only remaining complete OFD.
            let worker = std::thread::spawn(move || {
                if cap.is_eventfd() {
                    assert_eq!(cap.read(8).unwrap(), 7u64.to_le_bytes());
                } else {
                    assert_eq!(cap.read(8), Err(Errno(11)));
                }
            });
            worker.join().unwrap();
            assert!(lifetime.upgrade().is_none());
        }
        // The same prepared map sees additions without a joined recapture.
        let reused = v.eventfd(11, O_NONBLOCK).unwrap();
        assert_eq!(reused, event);
        assert_eq!(
            cache.get(reused).unwrap().read(8).unwrap(),
            11u64.to_le_bytes()
        );
    }
    #[test]
    fn execution_map_does_not_keep_table_membership_after_last_owner_exit() {
        let mut v = Vfs::default();
        let [reader, writer] = v.pipe(O_NONBLOCK).unwrap();
        let files = v.shared_files();
        let accepted = files.lookup(reader).unwrap().unwrap();
        drop(v);
        assert!(matches!(files.lookup(writer), Some(Err(Errno(9)))));
        assert_eq!(accepted.direct_byte().unwrap().read(1).unwrap(), b"");
    }
    #[test]
    fn simultaneous_worker_edits_and_owner_enumeration_use_the_same_membership() {
        let mut v = Vfs::default();
        let [_, writer] = v.pipe(O_NONBLOCK).unwrap();
        let files = v.shared_files();
        std::thread::scope(|scope| {
            for worker in 0..4 {
                let files = files.clone();
                scope.spawn(move || {
                    for _ in 0..128 {
                        let fd = files
                            .duplicate(writer, 32 + worker * 16, true)
                            .unwrap()
                            .unwrap();
                        assert_eq!(
                            files.duplicate_to(fd, 200 + worker, 0, 0),
                            Some(Ok(200 + worker))
                        );
                        assert_eq!(files.close(fd, 0), Some(Ok(())));
                        assert_eq!(files.close(200 + worker, 0), Some(Ok(())));
                    }
                });
            }
            for _ in 0..256 {
                assert_eq!(
                    v.fd_flags_snapshot().get(writer).unwrap() & O_NONBLOCK,
                    O_NONBLOCK
                );
                assert!(v.fds.entries().contains_key(&writer));
            }
        });
        assert_eq!(v.fds.entries().len(), 5);
    }
    #[test]
    fn captured_flags_follow_dynamic_membership_and_new_cloexec_bits() {
        let mut v = Vfs::default();
        let [_, writer] = v.pipe(O_NONBLOCK).unwrap();
        let files = v.shared_files();
        let flags = v.fd_flags_snapshot();
        let alias = files.duplicate(writer, 160, true).unwrap().unwrap();
        assert_eq!(flags.get(alias), Ok(1 | O_NONBLOCK | O_CLOEXEC));
        flags.fcntl(alias, 2, 0).unwrap();
        assert_eq!(v.flags(alias), Ok(1 | O_NONBLOCK));
        assert_eq!(files.close(writer, 0), Some(Ok(())));
        assert_eq!(flags.get(writer), Err(Errno(9)));
        let [reused, _] = v.pipe(0).unwrap();
        assert_eq!(reused, writer);
        assert_eq!(flags.get(reused), Ok(0));
        flags.fcntl(reused, 4, O_NONBLOCK as u64).unwrap();
        assert_eq!(v.flags(reused), Ok(O_NONBLOCK));
    }
    #[test]
    fn shared_ofd_releases_process_locks_and_last_worker_flock_immediately() {
        let mut v = Vfs::default();
        v.set_lock_owner(11);
        let file = v.open_at(AT_FDCWD, b"/worker-close", 0x42, 0o600).unwrap();
        let alias = v.dup(file, 64, false).unwrap();
        let contender = v.open_at(AT_FDCWD, b"/worker-close", 2, 0).unwrap();
        let lock = v.normalize_lock(file, 1, 0, 0, 8).unwrap();
        v.record_lock_set(file, lock).unwrap();
        v.flock(file, 6).unwrap();
        assert_eq!(v.flock(contender, 6), Err(Errno(11)));
        let mut peer = v.clone();
        peer.set_lock_owner(22);
        let requested = peer.normalize_lock(contender, 1, 0, 0, 8).unwrap();
        assert!(peer
            .record_lock_conflict(contender, requested)
            .unwrap()
            .is_some());
        // The copied table legitimately retains the original OFD too.
        peer.close(file).unwrap();
        peer.close(alias).unwrap();
        let ofd = v.descriptor(file).unwrap().open.borrow().shared.clone();
        std::thread::scope(|scope| {
            scope.spawn(|| ofd.release_record_locks(11)).join().unwrap();
        });
        assert_eq!(
            peer.record_lock_conflict(contender, requested).unwrap(),
            None
        );
        assert_eq!(v.flock(contender, 6), Err(Errno(11)));
        v.close(file).unwrap();
        v.close(alias).unwrap();
        assert_eq!(v.flock(contender, 6), Err(Errno(11)));
        std::thread::spawn(move || drop(ofd)).join().unwrap();
        v.flock(contender, 6).unwrap();
    }
    #[test]
    fn clone_files_owns_one_map_and_mutations_need_no_peer_propagation() {
        let mut parent = Vfs::default();
        let [reader, writer] = parent.pipe(O_NONBLOCK).unwrap();
        let lease = parent.descriptor(writer).unwrap();
        let refs = lease.open.strong_count();
        let peers: Vec<_> = (0..32).map(|_| parent.clone_with_files(true)).collect();
        // No temporary private map survives, and peer tables do not multiply
        // OFD refs. One shared files_struct owns each installed descriptor.
        assert_eq!(lease.open.strong_count(), refs);
        let fork = parent.clone();
        let alias = parent.dup(writer, 64, true).unwrap();
        for peer in &peers {
            assert!(peer.fds.shares_with(&parent.fds));
            assert!(peer.flags(alias).is_ok());
        }
        parent.close(writer).unwrap();
        assert!(fork.flags(writer).is_ok());
        assert_eq!(fork.flags(alias), Err(Errno(9)));
        for peer in &peers {
            assert_eq!(peer.flags(writer), Err(Errno(9)));
            assert!(peer.flags(reader).is_ok());
        }
    }
    #[test]
    fn lookup_lease_survives_shared_close_and_numeric_fd_reuse() {
        let mut parent = Vfs::default();
        let [reader, writer] = parent.pipe(O_NONBLOCK).unwrap();
        let mut peer = parent.clone_with_files(true);
        let lease = RetainedFd(parent.descriptor(writer).unwrap());
        peer.close(writer).unwrap();
        assert_eq!(parent.flags(writer), Err(Errno(9)));
        let [replacement, _] = peer.pipe(O_NONBLOCK).unwrap();
        assert_eq!(replacement, writer);
        assert!(!lease.same_file(&parent.retain_uring_fd(replacement).unwrap()));
        assert_eq!(parent.read(reader, 1), Err(Errno(11)));
        assert_eq!(
            parent.with_uring_fd(&lease, |v, fd| v.write(fd, b"a")),
            Ok(1)
        );
        assert_eq!(parent.read(reader, 1).unwrap(), b"a");
        drop(lease);
        assert!(parent.read(reader, 1).unwrap().is_empty());
        assert!(peer.flags(replacement).is_ok());
    }
    #[test]
    fn dup3_replaces_before_retiring_target_and_does_not_hold_a_table_borrow() {
        let mut v = Vfs::default();
        let [reader, writer] = v.pipe(O_NONBLOCK).unwrap();
        let [other_reader, other_writer] = v.pipe(O_NONBLOCK).unwrap();
        let peer = v.clone_with_files(true);
        let replaced = v.fds.duplicate_to(other_writer, writer, O_CLOEXEC).unwrap();
        // Target lookup already names the new OFD while the retired endpoint
        // remains alive. Closing effects can reenter membership without a gap
        // or a RefCell borrow held by duplicate_to.
        assert!(peer
            .retain_uring_fd(writer)
            .unwrap()
            .same_file(&peer.retain_uring_fd(other_writer).unwrap()));
        assert_eq!(v.read(reader, 1), Err(Errno(11)));
        drop(replaced);
        assert!(v.read(reader, 1).unwrap().is_empty());
        v.write(writer, b"b").unwrap();
        assert_eq!(v.read(other_reader, 1).unwrap(), b"b");
        assert_ne!(peer.flags(writer).unwrap() & O_CLOEXEC, 0);
        assert_eq!(peer.flags(other_writer).unwrap() & O_CLOEXEC, 0);
    }
    #[test]
    fn task_detach_keeps_shared_ends_until_the_final_table_owner_exits() {
        let mut v = Vfs::default();
        let [reader, writer] = v.pipe(O_NONBLOCK).unwrap();
        let bytes = v.direct_descriptors();
        let mut peer = v.clone_with_files(true);
        v.detach_file_table();
        assert_eq!(v.flags(reader), Err(Errno(9)));
        assert!(peer.flags(writer).is_ok());
        assert_eq!(bytes.get(reader).unwrap().read(1), Err(Errno(11)));
        let accepted = bytes.get(reader).unwrap();
        peer.close_all();
        assert!(bytes.get(reader).is_none());
        assert!(accepted.read(1).unwrap().is_empty());
    }
    #[test]
    fn shared_table_bits_are_live_but_fork_and_dup_have_independent_cloexec() {
        let mut parent = Vfs::default();
        let [fd, _] = parent.pipe(0).unwrap();
        let alias = parent.dup(fd, 0, false).unwrap();
        let mut shared = parent.clone();
        shared.share_descriptors_from(&parent);
        let child = parent.clone();
        let old = parent.fds.identity();
        let flags = parent.fd_flags_snapshot();
        let peer = shared.fd_flags_snapshot();
        std::thread::scope(|scope| {
            scope
                .spawn(|| flags.fcntl(fd, 2, 1).unwrap())
                .join()
                .unwrap()
        });
        assert_eq!(peer.fcntl(fd, 1, 0), Ok(1));
        assert_eq!(child.fd_flags_snapshot().fcntl(fd, 1, 0), Ok(0));
        assert_eq!(flags.fcntl(alias, 1, 0), Ok(0));
        assert!(Arc::ptr_eq(&parent.fds.identity(), &old));
        // Owner updates also reach existing snapshots without synchronizing maps.
        shared.set_cloexec(fd, false).unwrap();
        assert_eq!(flags.fcntl(fd, 1, 0), Ok(0));
        flags.fcntl(fd, 4, O_NONBLOCK as u64).unwrap();
        assert_ne!(child.flags(alias).unwrap() & O_NONBLOCK, 0);
    }
    #[test]
    fn range_bits_handle_holes_empty_ranges_and_preserve_fd_lifetime() {
        let mut v = Vfs::default();
        let [fd, writer] = v.pipe(0).unwrap();
        let high = v.dup(fd, 20, false).unwrap();
        let flags = v.fd_flags_snapshot();
        assert_eq!(flags.cloexec_range(20, 19), Err(Errno(22)));
        assert_eq!(flags.fcntl(high, 1, 0), Ok(0));
        assert_eq!(flags.cloexec_range(writer, u32::MAX), Ok(0));
        assert_eq!(v.flags(fd).unwrap() & O_CLOEXEC, 0);
        assert_ne!(v.flags(writer).unwrap() & O_CLOEXEC, 0);
        assert_ne!(v.flags(high).unwrap() & O_CLOEXEC, 0);
        v.write(writer, b"x").unwrap();
        assert_eq!(v.read(high, 1).unwrap(), b"x");
        assert_eq!(flags.cloexec_range(MAX_FDS, u32::MAX), Ok(0));
        assert_eq!(flags.fcntl(u32::MAX, 2, 1), Err(Errno(9)));
    }
    #[test]
    fn unshare_detaches_bits_and_live_flags_follow_numeric_reuse() {
        let mut parent = Vfs::default();
        let [fd, _] = parent.pipe(0).unwrap();
        let flags = parent.fd_flags_snapshot();
        let mut shared = parent.clone();
        shared.share_descriptors_from(&parent);
        shared.unshare_descriptors();
        flags.fcntl(fd, 2, 1).unwrap();
        assert_eq!(shared.flags(fd).unwrap() & O_CLOEXEC, 0);
        let original = parent.descriptor(fd).unwrap();
        original.cloexec.set(false);
        parent.close(fd).unwrap();
        let [replacement, _] = parent.pipe(0).unwrap();
        assert_eq!(replacement, fd);
        flags.fcntl(fd, 2, 1).unwrap();
        assert_eq!(parent.flags(replacement).unwrap() & O_CLOEXEC, O_CLOEXEC);
        assert!(!original.cloexec.get());
    }
}
