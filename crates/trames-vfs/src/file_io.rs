// SPDX-License-Identifier: GPL-3.0-or-later
//! Prepared file authority is weak; accepted operations retain the original OFD.
use super::*;
use file_data::{FilePosition, PlainFile};
use std::sync::Mutex;

/// One accepted operation. Prepared caches carry no inode, data or OFD lease.
#[derive(Clone)]
pub struct DirectFile {
    data: Arc<PlainFile>,
    position: Arc<Mutex<FilePosition>>,
    locks: Arc<locks::Records>,
    prepared: PreparedFile,
    file: Option<SharedFd>,
}
/// Joined admission records policy and weak resource identities once. Promoting
/// this capability never borrows an inode or repeats a pathname/stat lookup.
#[derive(Clone)]
pub struct PreparedFile(Arc<FileAuthority>);
struct FileAuthority {
    data: std::sync::Weak<PlainFile>,
    position: std::sync::Weak<Mutex<FilePosition>>,
    locks: std::sync::Weak<locks::Records>,
    origin: OfdIdentity,
    flock: std::sync::Weak<flock::Owner>,
    stat: [u8; 128],
    flags: u32,
    status: StatusFlags,
    notifications: inotify::Notifications,
    write_error: Option<Errno>,
    unlimited: bool,
    clear_setid: bool,
    readonly: bool,
    relatime: bool,
}
impl PreparedFile {
    fn accept(&self, file: Option<SharedFd>) -> Option<DirectFile> {
        Some(DirectFile {
            data: self.0.data.upgrade()?,
            position: self.0.position.upgrade()?,
            locks: self.0.locks.upgrade()?,
            prepared: self.clone(),
            file,
        })
    }
    /// io_uring's accepted/fixed file may outlive its original numeric slot.
    pub fn retain(&self, file: &RetainedFd) -> Option<DirectFile> {
        let open = file.0.open.borrow();
        if !self.0.origin.matches(&open.shared) {
            return None;
        }
        let shared = match &file.0.open {
            OpenHandle::Shared(open) => Some(SharedFd::new(open.clone())),
            OpenHandle::Owner(_) => None,
        };
        self.accept(shared)
    }
}
#[derive(Clone, Default)]
pub struct DirectFiles(
    Arc<[Option<PreparedFile>]>,
    Arc<BTreeMap<usize, PreparedFile>>,
    Option<SharedFiles>,
);
impl DirectFiles {
    pub fn get(&self, fd: u32) -> Option<DirectFile> {
        if let Some(result) = self.2.as_ref().and_then(|files| files.lookup(fd)) {
            return self.accept(result.ok()?);
        }
        self.0.get(fd as usize)?.as_ref()?.accept(None)
    }
    /// Resolve prepared authority for an already accepted shared lookup.
    /// Do not look up its numeric FD again while constructing a request.
    pub fn accept(&self, file: SharedFd) -> Option<DirectFile> {
        let prepared = self.1.get(&file.identity())?;
        debug_assert!(prepared.0.origin == file.ofd_identity());
        prepared.accept(Some(file))
    }
    /// Cold preparation of fixed or already-accepted io_uring descriptions.
    pub fn retain(&self, file: &RetainedFd) -> Option<DirectFile> {
        if let Some(shared) = file.shared_file() {
            return self.accept(shared);
        }
        self.0
            .iter()
            .flatten()
            .find_map(|prepared| prepared.retain(file))
    }
}
#[derive(Default)]
pub struct FileEpoch {
    nodes: BTreeMap<usize, (std::sync::Weak<Inode>, std::sync::Weak<PlainFile>)>,
    prepared: BTreeMap<(usize, bool, bool), PreparedFile>,
    captures: BTreeMap<(usize, u64, bool, bool, u64), DirectFiles>,
}
impl FileEpoch {
    pub fn capture(&mut self, vfs: &Vfs, unlimited: bool) -> DirectFiles {
        let mask = vfs.file_descriptors();
        if mask.iter().all(|word| *word == 0) {
            return DirectFiles::default();
        }
        let clear_setid = !vfs.credentials.has_cap(capabilities::FSETID);
        let membership = vfs.shared_files();
        let (identity, revision) = membership.capture_identity();
        let key = (
            identity,
            revision,
            clear_setid,
            unlimited,
            FD_FLAGS_REVISION.load(Ordering::Relaxed),
        );
        if let Some(capture) = self.captures.get(&key) {
            return capture.clone();
        }
        let descriptors = vfs.fds.entries();
        let mut entries = vec![
            None;
            descriptors
                .last_key_value()
                .map_or(0, |(&fd, _)| fd as usize + 1)
        ];
        let mut shared = BTreeMap::new();
        for (&fd, descriptor) in descriptors.iter() {
            if mask[fd as usize / 64] & (1 << (fd % 64)) == 0 {
                continue;
            }
            let open = descriptor.open.borrow();
            let Some(prepared) = self.capture_open(vfs, &open, unlimited) else {
                continue;
            };
            if matches!(descriptor.open, open_handle::OpenView::Shared(_)) {
                shared.insert(Arc::as_ptr(&open.shared) as usize, prepared);
            } else {
                entries[fd as usize] = Some(prepared);
            }
        }
        let capture = DirectFiles(entries.into(), Arc::new(shared), Some(membership));
        self.captures.insert(key, capture.clone());
        capture
    }
    /// Snapshot retained io_uring OFDs even after their numeric descriptors
    /// were closed/reused. Use the same file authority/algorithms as normal FDs.
    pub fn capture_uring(&mut self, vfs: &Vfs, unlimited: bool) -> BTreeMap<usize, PreparedFile> {
        let mut files = BTreeMap::new();
        for ring in vfs.urings() {
            let state = ring.state.borrow();
            let retained = state
                .files
                .iter()
                .flatten()
                .flatten()
                .chain(state.pending.iter().filter_map(|r| r.file.as_ref()));
            for file in retained {
                if let std::collections::btree_map::Entry::Vacant(slot) =
                    files.entry(file.identity())
                {
                    if let Some(cap) = self.capture_open(vfs, &file.0.open.borrow(), unlimited) {
                        slot.insert(cap);
                    }
                }
            }
        }
        files
    }
    fn capture_open(
        &mut self,
        vfs: &Vfs,
        o: &OpenDescription,
        unlimited: bool,
    ) -> Option<PreparedFile> {
        let clear_setid = !vfs.credentials.has_cap(capabilities::FSETID);
        let prepared_key = (Arc::as_ptr(&o.shared) as usize, clear_setid, unlimited);
        if let Some(prepared) = self.prepared.get(&prepared_key) {
            return Some(prepared.clone());
        }
        if o.read_node.is_some() {
            return None;
        }
        let node = Vfs::ordinary_file(o, false)?;
        let n = node.borrow();
        let Content::File(storage::FileData::Plain(data)) = &n.content else {
            return None;
        };
        if n.seals.is_some() {
            return None;
        }
        let data = data.clone();
        let key = Arc::as_ptr(&node) as usize;
        if let std::collections::btree_map::Entry::Vacant(entry) = self.nodes.entry(key) {
            data.activate(n.mode, n.times);
            entry.insert((Arc::downgrade(&node), Arc::downgrade(&data)));
        }
        let notifications =
            inotify::capture_node(&n, o.notification.as_ref().and_then(|c| c.link.as_ref()));
        let stat = vfs.stat_node_fields(&n, o.mount.as_ref()).ok()?;
        let write_error = o
            .mount
            .as_ref()
            .map_or(Ok(()), |m| m.writable())
            .and_then(|()| Vfs::pseudo_immutable_node(&n))
            .err();
        let prepared = PreparedFile(Arc::new(FileAuthority {
            data: Arc::downgrade(&data),
            position: Arc::downgrade(&o.file_position),
            locks: Arc::downgrade(&vfs.inode_record_locks(&n)),
            origin: OfdIdentity::new(&o.shared),
            flock: o.flock_capability(),
            stat,
            flags: o.flags.get(),
            status: o.flags.clone(),
            notifications,
            write_error,
            unlimited,
            clear_setid,
            readonly: o.mount.as_ref().is_some_and(|m| m.readonly()),
            relatime: o
                .mount
                .as_ref()
                .is_some_and(|m| m.flags.get() & mounts::MS_RELATIME != 0),
        }));
        self.prepared.insert(prepared_key, prepared.clone());
        Some(prepared)
    }
    /// All workers/requests must have returned first. This touches only the
    /// captured inodes, never scans the filesystem or adds a compute fast-path lock.
    pub fn finish(self) {
        for (_, (node, data)) in self.nodes {
            if let (Some(node), Some(data)) = (node.upgrade(), data.upgrade()) {
                let Some(meta) = data.finish_metadata() else {
                    continue;
                };
                let mut node = node.borrow_mut();
                node.mode = meta.mode;
                node.times = meta.times;
            }
        }
    }
}
impl DirectFile {
    pub fn shared_file(&self) -> Option<SharedFd> {
        self.file.clone()
    }
    /// Accepted flock keeps the same full OFD as this file operation.
    pub fn flock(&self, operation: u32) -> Result<()> {
        self.flock_request(operation)?.try_lock()
    }
    pub fn flock_request(&self, operation: u32) -> Result<FlockRequest> {
        flock::validate(operation)?;
        Ok(
            FlockRequest::new(self.prepared.0.flock.upgrade().ok_or(Errno(9))?, operation)
                .with_file(self.file.clone()),
        )
    }

    pub fn allows_record_locks(&self) -> bool {
        self.prepared.0.flags & O_PATH == 0
    }
    pub fn normalize_lock(
        &self,
        kind: u16,
        whence: u16,
        start: i64,
        length: i64,
        owner: u32,
    ) -> Option<Result<RecordLock>> {
        if kind > 2 {
            return Some(Err(Errno(22)));
        }
        let base = match whence {
            0 => 0,
            1 => {
                let position = self.position.lock().unwrap();
                if position.pending != 0 {
                    return None;
                }
                position.value
            }
            2 => self.data.len(),
            _ => return Some(Err(Errno(22))),
        };
        Some(locks::normalize(kind, start, length, base, owner))
    }
    pub fn normalize_ofd_lock(
        &self,
        kind: u16,
        whence: u16,
        start: i64,
        length: i64,
    ) -> Option<Result<RecordLock>> {
        let file = self.file.as_ref()?;
        let mut requested = match self.normalize_lock(kind, whence, start, length, 0)? {
            Ok(r) => r,
            Err(e) => return Some(Err(e)),
        };
        requested.owner = file.open.ofd_record_owner(&self.locks);
        Some(Ok(requested))
    }
    pub fn record_lock_conflict(&self, requested: RecordLock) -> Option<RecordLock> {
        self.locks.conflict(requested)
    }
    pub fn record_lock_set(&self, requested: RecordLock) -> Result<()> {
        if (requested.kind == 0 && self.prepared.0.flags & 3 == 1)
            || (requested.kind == 1 && self.prepared.0.flags & 3 == 0)
        {
            return Err(Errno(9));
        }
        self.locks.set(requested)
    }
    pub fn read(
        &self,
        count: usize,
        offset: Option<u64>,
        cache: &mut DiskReadCache,
    ) -> Option<Result<Vec<u8>>> {
        if offset.is_some_and(|n| n > i64::MAX as u64) {
            return Some(Err(Errno(22)));
        }
        if self.prepared.0.flags & O_PATH != 0 || self.prepared.0.flags & 3 == 1 {
            return Some(Err(Errno(9)));
        }
        if count == 0 {
            return Some(Ok(Vec::new()));
        }
        if count >= 16 * 1024 && self.data.disk_backed() {
            return None;
        }
        let result = if let Some(offset) = offset {
            self.data.epoch_read_at(offset, count, cache)?
        } else {
            let mut position = self.position.lock().unwrap();
            if position.pending != 0 {
                return None;
            }
            let result = self.data.epoch_read_at(position.value, count, cache)?;
            if let Ok(bytes) = &result {
                position.value += bytes.len() as u64;
            }
            result
        };
        if result.is_ok() && count != 0 && self.prepared.0.status.get() & O_NOATIME == 0 {
            self.data
                .accessed(self.prepared.0.readonly, self.prepared.0.relatime);
        }
        if result.as_ref().is_ok_and(|bytes| !bytes.is_empty()) {
            self.prepared.0.notifications.send(inotify::ACCESS);
        }
        Some(result)
    }
    pub fn write(
        &self,
        bytes: &[u8],
        offset: Option<u64>,
        cache: &mut DiskReadCache,
    ) -> Option<Result<usize>> {
        if offset.is_some_and(|n| n > i64::MAX as u64) {
            return Some(Err(Errno(22)));
        }
        if offset.is_some() {
            if let Some(error) = self.prepared.0.write_error {
                return Some(Err(error));
            }
        }
        if self.prepared.0.flags & O_PATH != 0 || self.prepared.0.flags & 3 == 0 {
            return Some(Err(Errno(9)));
        }
        if let Some(error) = self.prepared.0.write_error {
            return Some(Err(error));
        }
        if bytes.is_empty() {
            return Some(Ok(0));
        }
        if !self.prepared.0.unlimited || self.prepared.0.flags & 0x1000 != 0 {
            return None;
        }
        // Append growth/quotas/manifest retain the original owner path. No
        // partial vector or append transfer is performed before deferring.
        if self.prepared.0.status.get() & 0x400 != 0 {
            return None;
        }
        let result = if let Some(offset) = offset {
            self.data.write_in_place(offset, bytes, cache)?
        } else {
            let mut position = self.position.lock().unwrap();
            if position.pending != 0 {
                return None;
            }
            let result = self.data.write_in_place(position.value, bytes, cache)?;
            if let Ok(n) = result {
                position.value += n as u64;
            }
            result
        };
        if result.is_ok_and(|n| n != 0) {
            self.data.modified(self.prepared.0.clear_setid);
            self.prepared.0.notifications.send(inotify::MODIFY);
        }
        Some(result)
    }
    pub fn seek(&self, offset: i64, whence: u32) -> Option<Result<u64>> {
        if self.prepared.0.flags & O_PATH != 0 {
            return Some(Err(Errno(9)));
        }
        let mut position = self.position.lock().unwrap();
        if position.pending != 0 {
            return None;
        }
        let base = match whence {
            0 => 0,
            1 => position.value as i64,
            2 => self.data.len() as i64,
            _ => return Some(Err(Errno(22))),
        };
        let value = base
            .checked_add(offset)
            .filter(|n| *n >= 0)
            .ok_or(Errno(22));
        Some(value.map(|n| {
            position.value = n as u64;
            n as u64
        }))
    }
    pub fn stat(&self) -> Result<[u8; 128]> {
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(result) = self.data.host_stat() {
            return result;
        }
        let mut out = self.prepared.0.stat;
        out[48..56].copy_from_slice(&self.data.len().to_le_bytes());
        out[64..72].copy_from_slice(&self.data.blocks()?.to_le_bytes());
        if let Some(meta) = self.data.metadata() {
            out[16..20].copy_from_slice(&meta.mode.to_le_bytes());
            for (offset, t) in [72, 88, 104].into_iter().zip(meta.times) {
                out[offset..offset + 8].copy_from_slice(&t.seconds.to_le_bytes());
                out[offset + 8..offset + 16].copy_from_slice(&(t.nanos as u64).to_le_bytes());
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn memory_file(bytes: Vec<u8>) -> (Vfs, u32) {
        let mut vfs = Vfs::default();
        vfs.import_file(b"/data", bytes).unwrap();
        let fd = vfs.open_at(AT_FDCWD, b"/data", 2, 0).unwrap();
        (vfs, fd)
    }
    #[test]
    fn prepared_file_cache_keeps_fork_membership_separate_and_clone_files_shared() {
        let (mut parent, fd) = memory_file(b"old".to_vec());
        let mut child = parent.clone();
        let mut shared = parent.clone();
        shared.share_descriptors_from(&parent);
        let mut epoch = FileEpoch::default();
        let a = epoch.capture(&parent, true);
        let b = epoch.capture(&child, true);
        let c = epoch.capture(&shared, true);
        child.close(fd).unwrap();
        assert!(b.get(fd).is_none());
        assert!(a.get(fd).is_some());
        assert!(c.get(fd).is_some());
        parent.import_file(b"/new", b"new".to_vec()).unwrap();
        let replacement = child.open_at(AT_FDCWD, b"/new", 2, 0).unwrap();
        assert_eq!(replacement, fd);
        let fresh = epoch.capture(&child, true);
        let mut cache = DiskReadCache::default();
        assert!(b.get(fd).is_none()); // new OFD needs fresh joined admission
        assert_eq!(
            fresh.get(fd).unwrap().read(3, Some(0), &mut cache),
            Some(Ok(b"new".to_vec()))
        );
        assert_eq!(
            a.get(fd).unwrap().read(3, Some(0), &mut cache),
            Some(Ok(b"old".to_vec()))
        );
        shared.close(fd).unwrap();
        assert!(a.get(fd).is_none());
        assert!(c.get(fd).is_none());
        assert!(fresh.get(fd).is_some());
        epoch.finish();
    }
    #[test]
    fn live_file_membership_resolves_new_aliases_and_reuse_but_accepted_io_stays_original() {
        let (mut v, fd) = memory_file(b"old".to_vec());
        v.import_file(b"/other", b"new".to_vec()).unwrap();
        let other = v.open_at(AT_FDCWD, b"/other", 2, 0).unwrap();
        for _ in 0..96 {
            v.dup(fd, 0, false).unwrap();
        }
        let mut epoch = FileEpoch::default();
        let files = epoch.capture(&v, true);
        assert_eq!(files.1.len(), 2); // one policy per OFD, not per alias
        assert!(files.0.iter().all(Option::is_none));
        let accepted = files.get(fd).unwrap();
        let membership = v.shared_files();
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let alias = membership.duplicate(fd, 200, false).unwrap().unwrap();
                    assert_eq!(alias, 200);
                    membership.duplicate_to(other, fd, 0, 1).unwrap().unwrap();
                })
                .join()
                .unwrap();
        });
        let mut cache = DiskReadCache::default();
        assert_eq!(
            files.get(200).unwrap().read(3, None, &mut cache),
            Some(Ok(b"old".to_vec()))
        );
        assert_eq!(accepted.seek(0, 1), Some(Ok(3)));
        assert_eq!(
            files.get(fd).unwrap().read(3, None, &mut cache),
            Some(Ok(b"new".to_vec()))
        );
        assert_eq!(
            accepted.read(3, Some(0), &mut cache),
            Some(Ok(b"old".to_vec()))
        );
        membership.close(fd, 1).unwrap().unwrap();
        assert!(files.get(fd).is_none());
        let [replacement, _] = v.pipe(0).unwrap();
        assert_eq!(replacement, fd);
        assert!(files.get(fd).is_none()); // no stale ordinary-file authority
        epoch.finish();
    }
    fn weak_file(v: &Vfs, fd: u32) -> (std::sync::Weak<Inode>, std::sync::Weak<PlainFile>) {
        let descriptor = v.descriptor(fd).unwrap();
        let node = descriptor.open.borrow().node.clone().unwrap();
        let n = node.borrow();
        let Content::File(storage::FileData::Plain(data)) = &n.content else {
            panic!("plain file")
        };
        (Arc::downgrade(&node), Arc::downgrade(data))
    }
    #[test]
    fn prepared_file_caches_release_actual_unlinked_storage_at_last_close_without_a_join() {
        let (mut v, fd) = memory_file(b"old".to_vec());
        let notify = v.inotify_init(O_NONBLOCK).unwrap();
        v.inotify_add(notify, b"/", 8).unwrap();
        let (node, data) = weak_file(&v, fd);
        let mut epoch = FileEpoch::default();
        let files = epoch.capture(&v, true);
        let flags = v.fd_flags_snapshot();
        v.unlink_at(AT_FDCWD, b"/data", false).unwrap();
        let membership = v.shared_files();
        std::thread::spawn(move || membership.close(fd, 1).unwrap().unwrap())
            .join()
            .unwrap();
        assert!(node.upgrade().is_none());
        assert!(data.upgrade().is_none()); // actual bytes, not only accounting
        assert_eq!(v.allocated_bytes(), 0);
        assert!(files.get(fd).is_none());
        assert_eq!(flags.get(fd), Err(Errno(9)));
        let event = v.read(notify, 1024).unwrap();
        assert_eq!(u32::from_le_bytes(event[4..8].try_into().unwrap()), 8);
        assert_eq!(v.read(notify, 1024), Err(Errno(11)));
        epoch.finish();
    }
    #[test]
    fn accepted_file_and_flock_keep_complete_original_ofd_until_last_worker_release() {
        let (mut v, fd) = memory_file(b"old".to_vec());
        let notify = v.inotify_init(O_NONBLOCK).unwrap();
        v.inotify_add(notify, b"/", 8).unwrap();
        let (node, data) = weak_file(&v, fd);
        let mut epoch = FileEpoch::default();
        let files = epoch.capture(&v, true);
        let accepted = files.get(fd).unwrap();
        let request = accepted.flock_request(6).unwrap();
        assert!(request.retains_file());
        request.try_lock().unwrap();
        v.unlink_at(AT_FDCWD, b"/data", false).unwrap();
        v.close(fd).unwrap();
        assert!(files.get(fd).is_none());
        assert_eq!(v.read(notify, 1024), Err(Errno(11)));
        let mut cache = DiskReadCache::default();
        assert_eq!(
            accepted.read(3, None, &mut cache),
            Some(Ok(b"old".to_vec()))
        );
        std::thread::spawn(move || drop(accepted)).join().unwrap();
        assert!(node.upgrade().is_some());
        assert!(data.upgrade().is_some());
        assert_eq!(v.read(notify, 1024), Err(Errno(11)));
        std::thread::spawn(move || drop(request)).join().unwrap();
        assert!(node.upgrade().is_none());
        assert!(data.upgrade().is_none());
        assert_eq!(v.allocated_bytes(), 0);
        let event = v.read(notify, 1024).unwrap();
        assert_eq!(u32::from_le_bytes(event[4..8].try_into().unwrap()), 8);
        epoch.finish();
    }
    #[test]
    fn readonly_bind_and_policy_changes_are_separate_capabilities() {
        let mut vfs = Vfs::default();
        vfs.import_file(b"/src/data", vec![42; 64]).unwrap();
        vfs.mkdir_at(AT_FDCWD, b"/dst", 0o755).unwrap();
        vfs.mount(Some(b"/src"), b"/dst", None, 4096, None).unwrap();
        let fd = vfs.open_at(AT_FDCWD, b"/dst/data", 2, 0).unwrap();
        vfs.mount(None, b"/dst", None, 4096 | 32 | 1, None).unwrap();
        let node = vfs
            .descriptor(fd)
            .unwrap()
            .open
            .borrow()
            .node
            .clone()
            .unwrap();
        node.borrow_mut().times = [storage::Timestamp {
            seconds: 1,
            nanos: 0,
        }; 3];
        let mut epoch = FileEpoch::default();
        let a = epoch.capture(&vfs, true);
        let b = epoch.capture(&vfs, false);
        assert!(!Arc::ptr_eq(&a.0, &b.0));
        let mut cache = DiskReadCache::default();
        let file = a.get(fd).unwrap();
        assert_eq!(file.write(b"X", Some(0), &mut cache), Some(Err(Errno(30))));
        assert_eq!(file.write(&[], None, &mut cache), Some(Err(Errno(30))));
        assert_eq!(file.read(1, Some(0), &mut cache).unwrap().unwrap(), [42]);
        assert_eq!(
            i64::from_le_bytes(file.stat().unwrap()[72..80].try_into().unwrap()),
            1
        );
        epoch.finish();
        assert_eq!(node.borrow().times[0].seconds, 1);
    }
    #[test]
    fn mapping_change_rechecks_file_capability_without_an_fd_table_change() {
        let (vfs, fd) = memory_file(vec![0; 4096]);
        let old_flags = vfs.fd_flags_snapshot();
        let mut epoch = FileEpoch::default();
        assert!(epoch.capture(&vfs, true).get(fd).is_some());
        epoch.finish();
        let pages = vfs.mapping_pages(fd, 0, 4096, true, true).unwrap();
        assert_eq!(vfs.fd_flags_snapshot().get(fd), old_flags.get(fd));
        let mut epoch = FileEpoch::default();
        assert!(epoch.capture(&vfs, true).get(fd).is_none());
        epoch.finish();
        drop(pages);
    }
    #[test]
    fn persistent_file_capability_defers_without_effects_after_mapping_takes_byte_authority() {
        use trames_memory::{parallel::Registry, CpuMemory, Memory, Permissions};
        let (mut vfs, fd) = memory_file(vec![0; 4096]);
        let mut epoch = FileEpoch::default();
        let file = epoch.capture(&vfs, true).get(fd).unwrap();
        let mut cache = DiskReadCache::default();
        assert_eq!(file.read(1, Some(0), &mut cache).unwrap().unwrap(), [0]);
        let pages = vfs.mapping_pages(fd, 0, 4096, true, true).unwrap();
        let mut memory = Memory::default();
        memory
            .map_backed(0x1000, pages, true, Permissions::RW, false)
            .unwrap();
        let mut registry = Registry::default();
        let mut view = memory.parallel_view(&mut registry).unwrap();
        view.write_array(0x1000, *b"mapped").unwrap();
        // This capability predates mmap. Its original OFD remains valid, but
        // touching the plain backing would bypass the live mapped page.
        assert!(file.read(6, None, &mut cache).is_none());
        assert!(file.write(b"stale!", None, &mut cache).is_none());
        assert_eq!(file.seek(0, 1).unwrap().unwrap(), 0);
        assert_eq!(view.read_array::<6>(0x1000).unwrap(), *b"mapped");
        drop(view);
        memory.commit_parallel().unwrap();
        epoch.finish();
        assert_eq!(vfs.read(fd, 6).unwrap(), b"mapped");
    }
    #[test]
    fn dup_fork_and_joined_io_use_one_atomic_offset_transaction() {
        let bytes: Vec<_> = (0..1024u64).flat_map(u64::to_le_bytes).collect();
        let (mut parent, fd) = memory_file(bytes);
        let duplicate = parent.dup(fd, 0, false).unwrap();
        let child = parent.clone();
        let mut epoch = FileEpoch::default();
        let a = epoch.capture(&parent, true);
        let b = epoch.capture(&child, true);
        // Fork has distinct live membership while sharing this OFD's policy.
        assert!(Arc::ptr_eq(
            &a.get(fd).unwrap().prepared.0,
            &b.get(fd).unwrap().prepared.0,
        ));
        assert_eq!(parent.read(fd, 8).unwrap(), 0u64.to_le_bytes());
        let seen = Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for file in [
                a.get(fd).unwrap(),
                a.get(duplicate).unwrap(),
                b.get(fd).unwrap(),
                b.get(duplicate).unwrap(),
            ] {
                let seen = &seen;
                scope.spawn(move || {
                    let mut cache = DiskReadCache::default();
                    loop {
                        let bytes = file.read(8, None, &mut cache).unwrap().unwrap();
                        if bytes.is_empty() {
                            break;
                        }
                        seen.lock()
                            .unwrap()
                            .push(u64::from_le_bytes(bytes.try_into().unwrap()));
                    }
                });
            }
        });
        let mut seen = seen.into_inner().unwrap();
        seen.sort_unstable();
        assert_eq!(seen, (1..1024u64).collect::<Vec<_>>());
        assert_eq!(parent.seek(fd, 0, 1).unwrap(), 8192);
        assert_eq!(a.get(fd).unwrap().seek(-8, 2), Some(Ok(8184)));
        assert_eq!(parent.read(duplicate, 8).unwrap(), 1023u64.to_le_bytes());
        epoch.finish();
    }
    #[test]
    fn writes_share_bytes_and_metadata_with_stat_and_persistence() {
        let path = std::env::temp_dir().join(format!(
            "trames-direct-file-{}-{}",
            std::process::id(),
            storage::Timestamp::now().nanos
        ));
        let mut vfs = Vfs::open_disk(&path, Default::default()).unwrap();
        vfs.import_file(b"/data", vec![0; 64]).unwrap();
        let fd = vfs.open_at(AT_FDCWD, b"/data", 2, 0).unwrap();
        let node = vfs
            .descriptor(fd)
            .unwrap()
            .open
            .borrow()
            .node
            .clone()
            .unwrap();
        {
            let mut n = node.borrow_mut();
            n.mode = 0o106755;
            n.times = [storage::Timestamp {
                seconds: 1,
                nanos: 0,
            }; 3];
        }
        vfs.credentials.caps = capabilities::Capabilities::for_uid(1000);
        let mut epoch = FileEpoch::default();
        let files = epoch.capture(&vfs, true);
        let file = files.get(fd).unwrap();
        let mut cache = DiskReadCache::default();
        assert_eq!(file.write(b"hello", None, &mut cache), Some(Ok(5)));
        let stat = file.stat().unwrap();
        assert_eq!(
            u32::from_le_bytes(stat[16..20].try_into().unwrap()),
            0o100755
        );
        assert!(i64::from_le_bytes(stat[88..96].try_into().unwrap()) > 1);
        assert_eq!(vfs.stat_fd(fd).unwrap(), stat);
        assert_eq!(vfs.seek(fd, 0, 1).unwrap(), 5);
        assert_eq!(vfs.pread(fd, 5, 0).unwrap(), b"hello");
        // Owner-side writes touch the same active metadata mirror.
        vfs.pwrite(fd, b"world", 5).unwrap();
        assert_eq!(
            file.read(10, Some(0), &mut cache).unwrap().unwrap(),
            b"helloworld"
        );
        vfs.sync_fd(fd, false).unwrap();
        let expected = vfs.stat_fd(fd).unwrap();
        epoch.finish();
        assert_eq!(vfs.stat_fd(fd).unwrap(), expected);
        drop(file); // accepted operation also retains the real disk filesystem
        drop(files);
        drop(cache);
        drop(node);
        drop(vfs);
        let mut reopened = Vfs::open_disk(&path, Default::default()).unwrap();
        assert_eq!(
            u32::from_le_bytes(
                reopened.stat_at(AT_FDCWD, b"/data").unwrap()[16..20]
                    .try_into()
                    .unwrap()
            ),
            0o100755
        );
        let reopened_fd = reopened.open_at(AT_FDCWD, b"/data", 0, 0).unwrap();
        assert_eq!(reopened.pread(reopened_fd, 10, 0).unwrap(), b"helloworld");
        drop(reopened);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn growth_append_finite_limit_and_synchronous_writes_defer_without_effects() {
        let (mut vfs, fd) = memory_file(b"abcdefgh".to_vec());
        let mut epoch = FileEpoch::default();
        let files = epoch.capture(&vfs, true);
        let file = files.get(fd).unwrap();
        let mut cache = DiskReadCache::default();
        assert_eq!(file.seek(7, 0), Some(Ok(7)));
        assert_eq!(file.write(b"XY", None, &mut cache), None);
        assert_eq!(vfs.seek(fd, 0, 1).unwrap(), 7);
        assert_eq!(vfs.pread(fd, 8, 0).unwrap(), b"abcdefgh");
        epoch.finish();
        for (flags, unlimited) in [(0x400, true), (0x1000, true), (0, false)] {
            let other = vfs.open_at(AT_FDCWD, b"/data", 2 | flags, 0).unwrap();
            let mut epoch = FileEpoch::default();
            let files = epoch.capture(&vfs, unlimited);
            assert_eq!(
                files.get(other).unwrap().write(b"X", Some(0), &mut cache),
                None
            );
            assert_eq!(vfs.pread(fd, 8, 0).unwrap(), b"abcdefgh");
            epoch.finish();
        }
    }
    #[test]
    fn worker_file_io_delivers_inode_and_parent_notifications_without_owner_handoff() {
        for path in [b"/data".as_slice(), b"/".as_slice()] {
            let (mut vfs, fd) = memory_file(b"abcdefgh".to_vec());
            let notify = vfs.inotify_init(O_NONBLOCK).unwrap();
            vfs.inotify_add(notify, path, inotify::ACCESS | inotify::MODIFY)
                .unwrap();
            let mut epoch = FileEpoch::default();
            let files = epoch.capture(&vfs, true);
            let file = files.get(fd).unwrap();
            std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        let mut cache = DiskReadCache::default();
                        assert_eq!(file.read(1, None, &mut cache), Some(Ok(b"a".to_vec())));
                        assert_eq!(file.write(b"X", None, &mut cache), Some(Ok(1)));
                        assert_eq!(file.read(1, Some(99), &mut cache), Some(Ok(Vec::new())));
                        assert_eq!(file.read(0, None, &mut cache), Some(Ok(Vec::new())));
                        assert_eq!(file.write(b"", None, &mut cache), Some(Ok(0)));
                        assert_eq!(file.write(b"grow", Some(99), &mut cache), None);
                    })
                    .join()
                    .unwrap();
            });
            assert!(file.stat().is_ok());
            let bytes = vfs.read(notify, 1024).unwrap();
            let length = if path == b"/" { 32 } else { 16 };
            assert_eq!(bytes.len(), length * 2);
            for (event, mask) in bytes.chunks(length).zip([inotify::ACCESS, inotify::MODIFY]) {
                assert_eq!(u32::from_le_bytes(event[4..8].try_into().unwrap()), mask);
                if path == b"/" {
                    assert_eq!(&event[16..21], b"data\0");
                }
            }
            assert_eq!(vfs.read(notify, 1024), Err(Errno(11)));
            epoch.finish();
        }
    }
    #[test]
    fn asynchronous_reads_block_conflicting_worker_writes_and_offset_changes() {
        let path = std::env::temp_dir().join(format!(
            "trames-direct-lease-{}-{}",
            std::process::id(),
            storage::Timestamp::now().nanos
        ));
        let mut vfs = Vfs::open_disk(&path, Default::default()).unwrap();
        vfs.import_file(b"/data", vec![42; 32768]).unwrap();
        let fd = vfs.open_at(AT_FDCWD, b"/data", 2, 0).unwrap();
        let mut epoch = FileEpoch::default();
        let files = epoch.capture(&vfs, true);
        let file = files.get(fd).unwrap();
        let mut cache = DiskReadCache::default();
        let (read, job) = vfs.prepare_disk_read(fd, 16384, None).unwrap().unwrap();
        assert_eq!(file.seek(0, 1), None);
        assert_eq!(file.read(1, None, &mut cache), None);
        assert_eq!(file.write(b"X", Some(0), &mut cache), None);
        assert_eq!(file.read(1, Some(0), &mut cache).unwrap().unwrap(), [42]);
        assert_eq!(read.finish(job.run()).unwrap().len(), 16384);
        assert_eq!(file.seek(0, 1), Some(Ok(16384)));
        assert_eq!(file.write(b"X", Some(0), &mut cache), Some(Ok(1)));
        assert_eq!(vfs.pread(fd, 1, 0).unwrap(), b"X");
        epoch.finish();
        drop(files);
        drop(cache);
        drop(vfs);
        std::fs::remove_dir_all(path).unwrap();
    }
}
