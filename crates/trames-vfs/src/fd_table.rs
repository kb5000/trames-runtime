// SPDX-License-Identifier: GPL-3.0-or-later
//! One membership object per Linux files_struct, with stable lookup leases.
use super::open_handle::OpenView;
use super::*;
use std::sync::Mutex;

#[derive(Clone)]
enum SlotOpen {
    Shared(Arc<SharedOpenDescription>),
    Owner(usize),
}
#[derive(Clone)]
struct Slot {
    open: SlotOpen,
    cloexec: CloseOnExec,
}
impl Slot {
    fn shared_open(&self) -> Option<Result<&Arc<SharedOpenDescription>>> {
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
    fn from_descriptor(d: &Descriptor) -> Self {
        Self {
            open: match &d.open {
                OpenHandle::Shared(open) => SlotOpen::Shared(open.clone()),
                OpenHandle::Owner(_) => SlotOpen::Owner(d.open.identity()),
            },
            cloexec: d.cloexec.clone(),
        }
    }
}
#[derive(Default)]
struct Membership {
    entries: Mutex<BTreeMap<u32, Slot>>,
    revision: AtomicU64,
}
/// Actual membership, not a snapshot. Shared slots own complete admitted OFDs;
/// owner slots carry no worker endpoint/control authority.
#[derive(Clone, Default)]
pub struct SharedFiles(Arc<Membership>);
#[derive(Clone)]
pub struct SharedFd {
    open: Arc<SharedOpenDescription>,
}
impl SharedFd {
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
    pub fn direct_byte(self) -> Option<DirectFd> {
        let fd = DirectFd::shared_byte(&self.open)?;
        Some(fd.with_ofd(self))
    }
    pub(super) fn direct_poll(self) -> Option<DirectFd> {
        // Named FIFO descriptions keep their pathname kind, but their poll
        // state and subscriptions still belong to the real pipe resource.
        let fd = DirectFd::shared_pipe(&self.open).or_else(|| {
            matches!(self.open.kind, FdKind::Node(_)).then(|| DirectFd::regular_poll(&self.open))
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
        let open = match slot.shared_open()? {
            Ok(open) => open,
            Err(error) => return Some(Err(error)),
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
    fn changed(&self) {
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
        let Some(fd) = (min..MAX_FDS).find(|fd| !entries.contains_key(fd)) else {
            return Some(Err(Errno(24)));
        };
        entries.insert(
            fd,
            Slot {
                open: SlotOpen::Shared(open),
                cloexec: cloexec.into(),
            },
        );
        self.changed();
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
        if new >= MAX_FDS {
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
            if let Some(target) = entries.get(&new) {
                if let Err(error) = target.shared_open()? {
                    return Some(Err(error));
                }
            }
            let old = entries.insert(
                new,
                Slot {
                    open: SlotOpen::Shared(open),
                    cloexec: (flags & O_CLOEXEC != 0).into(),
                },
            );
            self.changed();
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
    pub fn close(&self, fd: u32, lock_owner: u32) -> Option<Result<()>> {
        let removed = {
            let mut entries = self.0.entries.lock().unwrap();
            let Some(slot) = entries.get(&fd) else {
                return Some(Err(Errno(9)));
            };
            if let Err(error) = slot.shared_open()? {
                return Some(Err(error));
            }
            let old = entries.remove(&fd).expect("validated membership");
            self.changed();
            old
        };
        if let SlotOpen::Shared(open) = removed.open {
            open.release_record_locks(lock_owner);
        }
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
    fn owned(&self) -> Descriptor {
        Descriptor {
            open: self.open.owned(),
            cloexec: self.cloexec.clone(),
        }
    }
}
/// A bounded metadata inspection, with no allocation or extra OFD ownership.
/// Resource I/O and callbacks must use a separate retained lookup lease.
pub(super) struct Entries<'a> {
    membership: std::sync::MutexGuard<'a, BTreeMap<u32, Slot>>,
    owners: std::cell::Ref<'a, TableState>,
}
impl Entries<'_> {
    fn entry<'a>(&'a self, fd: u32, slot: &'a Slot) -> Entry<'a> {
        Entry {
            open: match &slot.open {
                SlotOpen::Shared(open) => OpenView::Shared(open),
                SlotOpen::Owner(identity) => {
                    let descriptor = self
                        .owners
                        .entries
                        .get(&fd)
                        .expect("owner membership has its control");
                    assert_eq!(descriptor.open.identity(), *identity);
                    OpenView::Owner(&descriptor.open)
                }
            },
            cloexec: &slot.cloexec,
        }
    }
    pub(super) fn iter(&self) -> impl Iterator<Item = (&u32, Entry<'_>)> {
        self.membership
            .iter()
            .map(|(fd, slot)| (fd, self.entry(*fd, slot)))
    }
    pub(super) fn values(&self) -> impl Iterator<Item = Entry<'_>> {
        self.iter().map(|(_, entry)| entry)
    }
    pub(super) fn range(
        &self,
        range: std::ops::RangeInclusive<u32>,
    ) -> impl Iterator<Item = (&u32, Entry<'_>)> {
        self.membership
            .range(range)
            .map(|(fd, slot)| (fd, self.entry(*fd, slot)))
    }
    pub(super) fn last_key_value(&self) -> Option<(&u32, Entry<'_>)> {
        self.membership
            .last_key_value()
            .map(|(fd, slot)| (fd, self.entry(*fd, slot)))
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
/// CLONE_FILES retains this exact table; fork copies membership/CLOEXEC only.
/// The owner index retains only excluded controls, never shared endpoint OFDs.
#[derive(Default)]
pub(super) struct DescriptorTable(Rc<RefCell<TableState>>, SharedFiles);
#[derive(Default)]
struct TableState {
    // Only SlotOpen::Owner entries have a descriptor in this index.
    entries: BTreeMap<u32, Descriptor>,
    observed: u64,
    pub(super) identity: Rc<DescriptorVersion>,
    pub(super) metadata: Rc<DescriptorMetadata>,
}
#[derive(Clone, Default)]
pub(super) struct DescriptorMetadata {
    pub(super) flags: RefCell<Option<(u64, FdFlags)>>,
}
type PreparedBytes = Arc<[Option<DirectFd>]>;
#[derive(Clone, Default)]
pub(super) struct DescriptorVersion {
    pub(super) io: OnceCell<(FdMask, FdMask)>,
    pub(super) direct: RefCell<Option<(u64, PreparedBytes)>>,
    pub(super) urings: OnceCell<Vec<Weak<Uring>>>,
}
impl DescriptorTable {
    pub(super) fn membership(&self) -> &SharedFiles {
        &self.1
    }
    pub(super) fn worker_membership(&self) -> SharedFiles {
        self.1.clone()
    }
    pub(super) fn shared(&self) -> Self {
        Self(self.0.clone(), self.1.clone())
    }
    pub(super) fn shares_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.1 .0, &other.1 .0)
    }
    pub(super) fn last_owner(&self) -> bool {
        Rc::strong_count(&self.0) == 1
    }
    fn descriptor(&self, fd: u32, slot: &Slot) -> Descriptor {
        let open = match &slot.open {
            SlotOpen::Shared(open) => OpenHandle::Shared(open.clone()),
            SlotOpen::Owner(identity) => {
                let state = self.0.borrow();
                let descriptor = state
                    .entries
                    .get(&fd)
                    .expect("owner membership has its control");
                assert_eq!(descriptor.open.identity(), *identity);
                descriptor.open.clone()
            }
        };
        Descriptor {
            open,
            cloexec: slot.cloexec.clone(),
        }
    }
    pub(super) fn entries(&self) -> Entries<'_> {
        Entries {
            membership: self.1 .0.entries.lock().unwrap(),
            owners: self.0.borrow(),
        }
    }
    /// Lookup retains the original OFD independently of FD removal or reuse.
    /// No table borrow survives into resource I/O or last-close callbacks.
    pub(super) fn get(&self, fd: &u32) -> Option<Descriptor> {
        let entries = self.1 .0.entries.lock().unwrap();
        entries.get(fd).map(|slot| self.descriptor(*fd, slot))
    }
    pub(super) fn lookup(&self, fd: u32) -> Result<Descriptor> {
        let descriptor = self.get(&fd).ok_or(Errno(9))?;
        descriptor.ready()?;
        Ok(descriptor)
    }
    pub(super) fn contains_key(&self, fd: &u32) -> bool {
        self.1 .0.entries.lock().unwrap().contains_key(fd)
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
    pub(super) fn identity(&self) -> Rc<DescriptorVersion> {
        self.sync_cache().identity.clone()
    }
    pub(super) fn metadata(&self) -> Rc<DescriptorMetadata> {
        self.sync_cache().metadata.clone()
    }
    pub(super) fn insert(&mut self, fd: u32, descriptor: Descriptor) -> Option<Descriptor> {
        self.install(fd, descriptor, &mut self.1 .0.entries.lock().unwrap())
    }
    // The returned lease keeps teardown/notifications outside the table lock.
    fn install(
        &self,
        fd: u32,
        descriptor: Descriptor,
        entries: &mut BTreeMap<u32, Slot>,
    ) -> Option<Descriptor> {
        let old = entries.get(&fd).map(|slot| self.descriptor(fd, slot));
        let slot = Slot::from_descriptor(&descriptor);
        let mut state = self.0.borrow_mut();
        if matches!(descriptor.open, OpenHandle::Owner(_)) {
            state.entries.insert(fd, descriptor);
        } else {
            state.entries.remove(&fd);
        }
        entries.insert(fd, slot);
        self.1.changed();
        old
    }
    pub(super) fn remove(&mut self, fd: &u32) -> Option<Descriptor> {
        let mut entries = self.1 .0.entries.lock().unwrap();
        let descriptor = entries.get(fd).map(|slot| self.descriptor(*fd, slot))?;
        entries.remove(fd);
        self.0.borrow_mut().entries.remove(fd);
        self.1.changed();
        Some(descriptor)
    }
    pub(super) fn close(&mut self, fd: u32) -> Result<Descriptor> {
        let mut entries = self.1 .0.entries.lock().unwrap();
        let descriptor = self.descriptor(fd, entries.get(&fd).ok_or(Errno(9))?);
        descriptor.ready()?;
        entries.remove(&fd);
        self.0.borrow_mut().entries.remove(&fd);
        self.1.changed();
        Ok(descriptor)
    }
    pub(super) fn duplicate(&mut self, old: u32, min: u32, cloexec: bool) -> Result<u32> {
        let mut entries = self.1 .0.entries.lock().unwrap();
        let mut descriptor = self.descriptor(old, entries.get(&old).ok_or(Errno(9))?);
        descriptor.ready()?;
        if min >= MAX_FDS {
            return Err(Errno(22));
        }
        let fd = (min..MAX_FDS)
            .find(|fd| !entries.contains_key(fd))
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
        if new >= MAX_FDS {
            return Err(Errno(9));
        }
        let mut entries = self.1 .0.entries.lock().unwrap();
        let mut descriptor = self.descriptor(old, entries.get(&old).ok_or(Errno(9))?);
        descriptor.ready()?;
        if let Some(target) = entries.get(&new) {
            self.descriptor(new, target).ready()?;
        }
        descriptor.cloexec = (flags & O_CLOEXEC != 0).into();
        Ok(self.install(new, descriptor, &mut entries))
    }
    pub(super) fn drain(&mut self) -> BTreeMap<u32, Descriptor> {
        let mut entries = self.1 .0.entries.lock().unwrap();
        let descriptors = entries
            .iter()
            .map(|(&fd, slot)| (fd, self.descriptor(fd, slot)))
            .collect();
        if !entries.is_empty() {
            self.1.changed();
        }
        entries.clear();
        self.0.borrow_mut().entries.clear();
        descriptors
    }
}
impl Drop for DescriptorTable {
    fn drop(&mut self) {
        if self.last_owner() {
            // Retaining an execution map is not another Linux table owner.
            // Already accepted operations retain their own original OFD.
            drop(self.drain());
        }
    }
}
impl TableState {
    fn changed(&mut self) {
        // An owner capture can still borrow the old cache while another worker
        // edits membership. Do not clone a borrowed RefCell merely to clear it.
        if let Some(version) = Rc::get_mut(&mut self.identity) {
            version.io.take();
            version.direct.get_mut().take();
            version.urings.take();
        } else {
            self.identity = Rc::default();
        }
        if let Some(metadata) = Rc::get_mut(&mut self.metadata) {
            metadata.flags.get_mut().take();
        } else {
            self.metadata = Rc::default();
        }
    }
}
impl Clone for DescriptorTable {
    fn clone(&self) -> Self {
        let source = self.entries();
        let mut owners = BTreeMap::new();
        let entries = source
            .iter()
            .map(|(&fd, entry)| {
                let mut descriptor = entry.owned();
                descriptor.cloexec = descriptor.cloexec.fork();
                let slot = Slot::from_descriptor(&descriptor);
                if matches!(descriptor.open, OpenHandle::Owner(_)) {
                    owners.insert(fd, descriptor);
                }
                (fd, slot)
            })
            .collect();
        drop(source);
        // Resource identities are unchanged by fork. Reuse prepared owner
        // capabilities/masks, but bind live lookups to each new membership.
        // Per-descriptor metadata also gets a new ownership domain.
        Self(
            Rc::new(RefCell::new(TableState {
                entries: owners,
                observed: 0,
                identity: self.identity(),
                metadata: Rc::default(),
            })),
            SharedFiles(Arc::new(Membership {
                entries: Mutex::new(entries),
                revision: AtomicU64::new(0),
            })),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn owner_control_slots_are_excluded_before_structural_effects() {
        let mut v = Vfs::default();
        let [_, writer] = v.pipe(O_NONBLOCK).unwrap();
        let owner = v.eventfd(0, 0).unwrap();
        let files = v.shared_files();
        assert!(files.close(owner, 0).is_none());
        assert!(files.duplicate(owner, 160, false).is_none());
        assert!(files.duplicate_to(writer, owner, 0, 0).is_none());
        assert!(v.flags(owner).is_ok());
        assert_eq!(v.flags(160), Err(Errno(9)));
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
            assert!(Rc::ptr_eq(&peer.fds.0, &parent.fds.0));
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
        assert!(Rc::ptr_eq(&parent.fds.identity(), &old));
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
