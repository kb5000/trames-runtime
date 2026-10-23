// SPDX-License-Identifier: GPL-3.0-or-later
//! One membership object per Linux files_struct, with stable lookup leases.
use super::*;

#[derive(Clone)]
pub(super) struct Descriptor {
    pub(super) open: Rc<RefCell<OpenDescription>>,
    pub(super) cloexec: CloseOnExec,
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
/// OFDs still contain owner-local metadata. Do not send this table to a worker
/// until that metadata and the remaining endpoint lifetimes have been split.
#[derive(Default)]
pub(super) struct DescriptorTable(Rc<RefCell<TableState>>);
#[derive(Default)]
struct TableState {
    entries: BTreeMap<u32, Descriptor>,
    pub(super) identity: Rc<DescriptorVersion>,
    pub(super) metadata: Rc<DescriptorMetadata>,
}
#[derive(Clone, Default)]
pub(super) struct DescriptorMetadata {
    pub(super) flags: RefCell<Option<(u64, FdFlags)>>,
}
#[derive(Clone, Default)]
pub(super) struct DescriptorVersion {
    pub(super) io: OnceCell<(FdMask, FdMask)>,
    pub(super) direct: RefCell<Option<(u64, DirectFds)>>,
    pub(super) urings: OnceCell<Vec<Weak<Uring>>>,
}
impl DescriptorTable {
    pub(super) fn shared(&self) -> Self {
        Self(self.0.clone())
    }
    pub(super) fn shares_with(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
    pub(super) fn last_owner(&self) -> bool {
        Rc::strong_count(&self.0) == 1
    }
    pub(super) fn entries(&self) -> std::cell::Ref<'_, BTreeMap<u32, Descriptor>> {
        std::cell::Ref::map(self.0.borrow(), |s| &s.entries)
    }
    /// Lookup retains the original OFD independently of FD removal or reuse.
    /// No table borrow survives into resource I/O or last-close callbacks.
    pub(super) fn get(&self, fd: &u32) -> Option<Descriptor> {
        self.0.borrow().entries.get(fd).cloned()
    }
    pub(super) fn lookup(&self, fd: u32) -> Result<Descriptor> {
        let descriptor = self.get(&fd).ok_or(Errno(9))?;
        descriptor.ready()?;
        Ok(descriptor)
    }
    pub(super) fn contains_key(&self, fd: &u32) -> bool {
        self.0.borrow().entries.contains_key(fd)
    }
    pub(super) fn identity(&self) -> Rc<DescriptorVersion> {
        self.0.borrow().identity.clone()
    }
    pub(super) fn metadata(&self) -> Rc<DescriptorMetadata> {
        self.0.borrow().metadata.clone()
    }
    pub(super) fn insert(&mut self, fd: u32, descriptor: Descriptor) -> Option<Descriptor> {
        let mut state = self.0.borrow_mut();
        state.changed();
        state.entries.insert(fd, descriptor)
    }
    pub(super) fn remove(&mut self, fd: &u32) -> Option<Descriptor> {
        let mut state = self.0.borrow_mut();
        let removed = state.entries.remove(fd);
        if removed.is_some() {
            state.changed();
        }
        removed
    }
    pub(super) fn close(&mut self, fd: u32) -> Result<Descriptor> {
        let mut state = self.0.borrow_mut();
        state.entries.get(&fd).ok_or(Errno(9))?.ready()?;
        let descriptor = state.entries.remove(&fd).expect("validated descriptor");
        state.changed();
        Ok(descriptor)
    }
    pub(super) fn duplicate(&mut self, old: u32, min: u32, cloexec: bool) -> Result<u32> {
        let mut state = self.0.borrow_mut();
        let mut descriptor = state.entries.get(&old).ok_or(Errno(9))?.clone();
        descriptor.ready()?;
        if min >= MAX_FDS {
            return Err(Errno(22));
        }
        let fd = (min..MAX_FDS)
            .find(|fd| !state.entries.contains_key(fd))
            .ok_or(Errno(24))?;
        descriptor.cloexec = cloexec.into();
        state.changed();
        state.entries.insert(fd, descriptor);
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
        let mut state = self.0.borrow_mut();
        let mut descriptor = state.entries.get(&old).ok_or(Errno(9))?.clone();
        descriptor.ready()?;
        if let Some(target) = state.entries.get(&new) {
            target.ready()?;
        }
        descriptor.cloexec = (flags & O_CLOEXEC != 0).into();
        state.changed();
        Ok(state.entries.insert(new, descriptor))
    }
    pub(super) fn drain(&mut self) -> BTreeMap<u32, Descriptor> {
        let mut state = self.0.borrow_mut();
        if !state.entries.is_empty() {
            state.changed();
        }
        std::mem::take(&mut state.entries)
    }
}
impl TableState {
    fn changed(&mut self) {
        let version = Rc::make_mut(&mut self.identity);
        version.io.take();
        Rc::make_mut(&mut self.metadata).flags.get_mut().take();
        version.direct.get_mut().take();
        version.urings.take();
    }
}
impl Clone for DescriptorTable {
    fn clone(&self) -> Self {
        let state = self.0.borrow();
        let entries = state
            .entries
            .iter()
            .map(|(&fd, d)| {
                (
                    fd,
                    Descriptor {
                        open: d.open.clone(),
                        cloexec: d.cloexec.fork(),
                    },
                )
            })
            .collect();
        // Structural resources/OFDs are unchanged by fork. Reuse their cache
        // identity; only descriptor metadata gets a new ownership domain.
        Self(Rc::new(RefCell::new(TableState {
            entries,
            identity: state.identity.clone(),
            metadata: Rc::default(),
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clone_files_owns_one_map_and_mutations_need_no_peer_propagation() {
        let mut parent = Vfs::default();
        let [reader, writer] = parent.pipe(O_NONBLOCK).unwrap();
        let lease = parent.descriptor(writer).unwrap();
        let refs = Rc::strong_count(&lease.open);
        let peers: Vec<_> = (0..32).map(|_| parent.clone_with_files(true)).collect();
        // No temporary private map survives, and peer tables do not multiply
        // OFD refs. One shared files_struct owns each installed descriptor.
        assert_eq!(Rc::strong_count(&lease.open), refs);
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
        peer.close_all();
        assert!(bytes.get(reader).unwrap().read(1).unwrap().is_empty());
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
    fn unshare_and_fd_reuse_detach_bits_without_rebinding_old_capabilities() {
        let mut parent = Vfs::default();
        let [fd, _] = parent.pipe(0).unwrap();
        let flags = parent.fd_flags_snapshot();
        let mut shared = parent.clone();
        shared.share_descriptors_from(&parent);
        shared.unshare_descriptors();
        flags.fcntl(fd, 2, 1).unwrap();
        assert_eq!(shared.flags(fd).unwrap() & O_CLOEXEC, 0);
        parent.close(fd).unwrap();
        let [replacement, _] = parent.pipe(0).unwrap();
        assert_eq!(replacement, fd);
        flags.fcntl(fd, 2, 1).unwrap();
        assert_eq!(parent.flags(replacement).unwrap() & O_CLOEXEC, 0);
    }
}
