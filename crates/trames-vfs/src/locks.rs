// SPDX-License-Identifier: GPL-3.0-or-later
//! POSIX byte-range advisory locks. Inode-owned state, process-owned ranges.
use super::*;
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordLock {
    pub kind: u16,
    pub start: u64,
    pub end: u64,
    pub owner: u64,
}

/// Only inode registration and process exit visit the registry. Ordinary lock
/// queries/changes/close use the individual inode object, never this mutex.
#[derive(Default)]
pub(super) struct Registry(Mutex<RegistryEntries>, Mutex<WaitGraph>);
type WaitGraph = BTreeMap<u32, Vec<std::sync::Weak<Waiting>>>;
struct Waiting {
    records: Arc<Records>,
    requested: RecordLock,
}
struct WaitRegistration {
    registry: std::sync::Weak<Registry>,
    edge: Arc<Waiting>,
}
impl Drop for WaitRegistration {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            let mut graph = registry.1.lock().unwrap();
            let owner = self.edge.requested.owner as u32;
            if let Some(edges) = graph.get_mut(&owner) {
                edges.retain(|edge| {
                    edge.strong_count() != 0
                        && !std::ptr::eq(edge.as_ptr(), Arc::as_ptr(&self.edge))
                });
                if edges.is_empty() {
                    graph.remove(&owner);
                }
            }
        }
    }
}
struct RegistryEntries {
    live: Vec<std::sync::Weak<Records>>,
    next_gc: usize,
}
impl Default for RegistryEntries {
    fn default() -> Self {
        Self {
            live: Vec::new(),
            next_gc: 64,
        }
    }
}
impl Registry {
    fn wait(
        self: &Arc<Self>,
        records: Arc<Records>,
        requested: RecordLock,
    ) -> Result<Arc<WaitRegistration>> {
        let mut graph = self.1.lock().unwrap();
        let origin = requested.owner as u32;
        let mut pending = records.holders(requested);
        let mut seen = std::collections::BTreeSet::new();
        while let Some(owner) = pending.pop() {
            if owner == origin {
                return Err(Errno(35));
            }
            if !seen.insert(owner) {
                continue;
            }
            if let Some(edges) = graph.get(&owner) {
                for edge in edges.iter().filter_map(std::sync::Weak::upgrade) {
                    pending.extend(edge.records.holders(edge.requested));
                }
            }
        }
        let edge = Arc::new(Waiting { records, requested });
        graph.entry(origin).or_default().push(Arc::downgrade(&edge));
        Ok(Arc::new(WaitRegistration {
            registry: Arc::downgrade(self),
            edge,
        }))
    }
    fn create(&self) -> Arc<Records> {
        let records = Arc::new(Records::default());
        let mut all = self.0.lock().unwrap();
        if all.live.len() >= all.next_gc {
            all.live.retain(|entry| entry.strong_count() != 0);
            all.next_gc = all.live.len().saturating_mul(2).max(64);
        }
        all.live.push(Arc::downgrade(&records));
        records
    }
    fn release(&self, owner: u32) {
        let live: Vec<_> = {
            let mut all = self.0.lock().unwrap();
            let live = all
                .live
                .iter()
                .filter_map(std::sync::Weak::upgrade)
                .collect();
            all.live.retain(|entry| entry.strong_count() != 0);
            all.next_gc = all.live.len().saturating_mul(2).max(64);
            live
        };
        for records in live {
            records.release(owner as u64);
        }
    }
}
#[derive(Default)]
pub(super) struct Records(
    Mutex<Vec<RecordLock>>,
    std::sync::OnceLock<Arc<readiness::Readiness>>,
);
impl Records {
    fn notify(&self) {
        if let Some(readiness) = self.1.get() {
            readiness.notify_locked();
        }
    }
    fn release(&self, owner: u64) {
        let mut locks = self.0.lock().unwrap();
        let before = locks.len();
        locks.retain(|lock| lock.owner != owner);
        let changed = before != locks.len();
        drop(locks);
        if changed {
            self.notify();
        }
    }
    fn holders(&self, requested: RecordLock) -> Vec<u32> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|lock| conflicts(**lock, requested))
            .filter_map(|lock| u32::try_from(lock.owner).ok())
            .collect()
    }
    pub(super) fn conflict(&self, requested: RecordLock) -> Option<RecordLock> {
        conflict(&self.0.lock().unwrap(), requested)
    }
    pub(super) fn set(&self, requested: RecordLock) -> Result<()> {
        let mut locks = self.0.lock().unwrap();
        // Conflict detection and commit are a single inode transaction. The
        // old owner-only two-step algorithm cannot arbitrate concurrent CPUs.
        if conflict(&locks, requested).is_some() {
            return Err(Errno(11));
        }
        let releases = locks.iter().any(|old| {
            old.owner == requested.owner
                && old.start < requested.end
                && requested.start < old.end
                && (requested.kind == 2 || requested.kind == 0 && old.kind == 1)
        });
        let mut next = Vec::new();
        for &lock in locks.iter() {
            if lock.owner != requested.owner
                || requested.start >= lock.end
                || lock.start >= requested.end
            {
                next.push(lock);
            } else {
                if lock.start < requested.start {
                    next.push(RecordLock {
                        end: requested.start,
                        ..lock
                    });
                }
                if lock.end > requested.end {
                    next.push(RecordLock {
                        start: requested.end,
                        ..lock
                    });
                }
            }
        }
        if requested.kind != 2 {
            next.push(requested);
        }
        next.sort_by_key(|l| (l.owner, l.kind, l.start));
        let mut merged: Vec<RecordLock> = Vec::new();
        for lock in next {
            if let Some(last) = merged
                .last_mut()
                .filter(|l| l.owner == lock.owner && l.kind == lock.kind && l.end >= lock.start)
            {
                last.end = last.end.max(lock.end);
            } else {
                merged.push(lock);
            }
        }
        if merged.len() > 1024 {
            return Err(Errno(37));
        }
        *locks = merged;
        drop(locks);
        if releases {
            self.notify();
        }
        Ok(())
    }
}
fn conflict(locks: &[RecordLock], requested: RecordLock) -> Option<RecordLock> {
    locks
        .iter()
        .filter(|lock| conflicts(**lock, requested))
        .min_by_key(|lock| lock.start)
        .copied()
}
fn conflicts(lock: RecordLock, requested: RecordLock) -> bool {
    lock.owner != requested.owner
        && requested.kind != 2
        && (requested.kind == 1 || lock.kind == 1)
        && requested.start < lock.end
        && lock.start < requested.end
}

pub(super) fn normalize(
    kind: u16,
    start: i64,
    length: i64,
    base: u64,
    owner: u32,
) -> Result<RecordLock> {
    if kind > 2 {
        return Err(Errno(22));
    }
    let mut low = base as i128 + start as i128;
    let high = if length == 0 {
        u64::MAX
    } else {
        let other = low + length as i128;
        if length < 0 {
            let previous = low;
            low = other;
            previous
        } else {
            other
        }
        .try_into()
        .map_err(|_| Errno(75))?
    };
    if low < 0 {
        return Err(Errno(22));
    }
    if low > i64::MAX as i128 || (high != u64::MAX && high - 1 > i64::MAX as u64) {
        return Err(Errno(75));
    }
    Ok(RecordLock {
        kind,
        start: low as u64,
        end: high,
        owner: owner as u64,
    })
}

pub const OFD_LOCK_OWNER: u64 = 1 << 63;
pub(super) struct OfdOwner {
    records: Arc<Records>,
    owner: u64,
}
impl Drop for OfdOwner {
    fn drop(&mut self) {
        self.records.release(self.owner);
    }
}
impl SharedOpenDescription {
    pub(super) fn ofd_record_owner(&self, records: &Arc<Records>) -> u64 {
        self.ofd_records
            .get_or_init(|| OfdOwner {
                records: records.clone(),
                owner: OFD_LOCK_OWNER | self.id,
            })
            .owner
    }
}
/// An accepted blocking fcntl owns the original OFD and normalized range, even
/// when a sibling closes/reuses its descriptor or mutates the input structure.
#[derive(Clone)]
pub struct RecordLockRequest {
    records: Arc<Records>,
    requested: RecordLock,
    _file: SharedFd,
    registry: Arc<Registry>,
}
impl RecordLockRequest {
    pub fn try_lock(&self) -> Result<()> {
        self.records.set(self.requested)
    }
    pub fn holder(&self) -> Option<u32> {
        self.records
            .conflict(self.requested)
            .and_then(|r| u32::try_from(r.owner).ok())
    }
    pub fn wait(self) -> Result<RecordWait> {
        let registration = (self.requested.owner & OFD_LOCK_OWNER == 0)
            .then(|| self.registry.wait(self.records.clone(), self.requested))
            .transpose()?;
        Ok(RecordWait {
            request: self,
            _registration: registration,
        })
    }
}
/// The accepted range, original OFD and optional POSIX deadlock edge. Waiting
/// never reimports a guest flock structure or resolves its numeric FD again.
#[derive(Clone)]
pub struct RecordWait {
    request: RecordLockRequest,
    _registration: Option<Arc<WaitRegistration>>,
}
impl RecordWait {
    pub fn try_lock(&self) -> Result<()> {
        self.request.try_lock()
    }
    pub fn holder(&self) -> Option<u32> {
        self.request.holder()
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.request
            .records
            .1
            .get_or_init(Arc::default)
            .subscribe(signal)
    }
}

/// One original lock file. It owns no Files/namespace/task projection.
#[derive(Clone)]
pub struct RecordFile {
    file: SharedFd,
    context: RecordLockContext,
}
impl RecordFile {
    pub fn visible_pid(&self, owner: u32) -> u32 {
        self.context.visible_pid(owner)
    }
    pub fn flags(&self) -> u32 {
        self.file.open.flags.get()
    }
    fn records(&self) -> Result<Arc<Records>> {
        let node = self.file.open.node.as_ref().ok_or(Errno(9))?.borrow();
        Ok(node
            .record_locks
            .get_or_init(|| {
                self.context
                    .registry
                    .as_ref()
                    .expect("original lock registry")
                    .create()
            })
            .clone())
    }
    pub fn normalize(
        &self,
        kind: u16,
        whence: u16,
        start: i64,
        length: i64,
        ofd: bool,
    ) -> Result<RecordLock> {
        if kind > 2 {
            return Err(Errno(22));
        }
        let open = &self.file.open;
        let node = open.node.as_ref().ok_or(Errno(9))?.borrow();
        let Content::File(data) = &node.content else {
            return Err(Errno(9));
        };
        let base = match whence {
            0 => 0,
            1 => open.file_position.snapshot(),
            2 => data.len(),
            _ => return Err(Errno(22)),
        };
        let mut requested = normalize(kind, start, length, base, self.context.owner)?;
        if ofd {
            let records = node.record_locks.get_or_init(|| {
                self.context
                    .registry
                    .as_ref()
                    .expect("original lock registry")
                    .create()
            });
            requested.owner = open.ofd_record_owner(records);
        }
        Ok(requested)
    }
    pub fn conflict(&self, requested: RecordLock) -> Result<Option<RecordLock>> {
        Ok(self.records()?.conflict(requested))
    }
    fn writable(&self, requested: RecordLock) -> Result<()> {
        let flags = self.flags();
        if requested.kind == 0 && flags & 3 == 1 || requested.kind == 1 && flags & 3 == 0 {
            Err(Errno(9))
        } else {
            Ok(())
        }
    }
    pub fn set(&self, requested: RecordLock) -> Result<()> {
        self.writable(requested)?;
        self.records()?.set(requested)
    }
    pub fn request(&self, requested: RecordLock) -> Result<RecordLockRequest> {
        self.writable(requested)?;
        Ok(RecordLockRequest {
            records: self.records()?,
            requested,
            _file: self.file.clone(),
            registry: self
                .context
                .registry
                .as_ref()
                .expect("original lock registry")
                .clone(),
        })
    }
}
impl Vfs {
    /// Cold admission only, without allocating an inode lock object.
    pub fn shares_record_wait(&self, wait: &RecordWait) -> bool {
        self.fds.entries().values().any(|descriptor| {
            descriptor.open.borrow().node.as_ref().is_some_and(|node| {
                node.borrow()
                    .record_locks
                    .get()
                    .is_some_and(|records| Arc::ptr_eq(records, &wait.request.records))
            })
        })
    }
    pub fn normalize_ofd_lock(
        &self,
        fd: u32,
        kind: u16,
        whence: u16,
        start: i64,
        length: i64,
    ) -> Result<RecordLock> {
        self.record_file(fd)?
            .normalize(kind, whence, start, length, true)
    }
    pub fn retain_record_lock(&self, fd: u32, requested: RecordLock) -> Result<RecordLockRequest> {
        self.record_file(fd)?.request(requested)
    }
}
/// Live original PID visibility across in-epoch task birth. This
/// owns original shared PID/lock resources, never a coordinator Rc namespace or
/// a process/VFS reference.
#[derive(Clone, Default)]
pub struct RecordLockContext {
    pub owner: u32,
    visible: Option<PidNamespace>,
    registry: Option<Arc<Registry>>,
}
/// Original process-owned lock domain; does not retain any file or task.
#[derive(Clone)]
pub struct ProcessRecordLocks {
    registry: Arc<Registry>,
    owner: u32,
}
impl ProcessRecordLocks {
    pub fn release(&self) {
        self.registry.release(self.owner);
    }
}
impl RecordLockContext {
    pub fn supports_waits(&self) -> bool {
        self.registry.is_some()
    }
    pub fn file(&self, file: SharedFd) -> Option<RecordFile> {
        self.registry.as_ref()?;
        Some(RecordFile {
            file,
            context: self.clone(),
        })
    }
    pub fn release(&self) {
        if let Some(registry) = &self.registry {
            registry.release(self.owner);
        }
    }
    pub fn visible_pid(&self, owner: u32) -> u32 {
        self.visible
            .as_ref()
            .map_or(owner, |namespace| namespace.local(owner))
    }
}
impl Vfs {
    pub fn record_file(&self, fd: u32) -> Result<RecordFile> {
        let descriptor = self.descriptor(fd)?;
        let file = SharedFd::new(descriptor.open.borrow().shared.clone());
        Ok(self
            .record_lock_context(self.lock_owner)
            .file(file)
            .expect("original VFS lock registry"))
    }
    pub fn process_record_locks(&self, owner: u32) -> ProcessRecordLocks {
        ProcessRecordLocks {
            registry: self.record_locks.clone(),
            owner,
        }
    }
    pub fn record_lock_context(&self, owner: u32) -> RecordLockContext {
        RecordLockContext {
            owner,
            visible: self.pid_ns.is_nested().then(|| self.pid_ns.clone()),
            registry: Some(self.record_locks.clone()),
        }
    }
    pub(super) fn inode_record_locks(&self, node: &Node) -> Arc<Records> {
        node.record_locks
            .get_or_init(|| self.record_locks.create())
            .clone()
    }
    pub fn set_lock_owner(&mut self, owner: u32) {
        self.lock_owner = owner;
    }
    pub fn release_process_locks(&self) {
        self.process_record_locks(self.lock_owner).release();
    }
    pub(super) fn release_record_locks(&self, descriptor: &Descriptor) {
        let open = descriptor.open.borrow().shared.clone();
        open.release_record_locks(self.lock_owner);
    }
}
impl SharedOpenDescription {
    pub(super) fn release_record_locks(&self, owner: u32) {
        if let Some(node) = &self.node {
            // Do not allocate or lock a registry for an inode that has never
            // acquired a lock object. Close releases this process's locks even
            // when dup/another process retains the open description.
            let records = node.borrow().record_locks.get().cloned();
            if let Some(records) = records {
                records.release(owner as u64);
            }
        }
    }
}
impl Vfs {
    pub fn normalize_lock(
        &self,
        fd: u32,
        kind: u16,
        whence: u16,
        start: i64,
        length: i64,
    ) -> Result<RecordLock> {
        if kind > 2 {
            return Err(Errno(22));
        }
        self.record_file(fd)?
            .normalize(kind, whence, start, length, false)
    }
    pub fn record_lock_conflict(
        &self,
        fd: u32,
        requested: RecordLock,
    ) -> Result<Option<RecordLock>> {
        self.record_file(fd)?.conflict(requested)
    }
    pub fn record_lock_set(&self, fd: u32, requested: RecordLock) -> Result<()> {
        self.record_file(fd)?.set(requested)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_process_lock_domain_releases_on_a_source_executor_with_live_files() {
        let mut v = Vfs::default();
        let fd = v.open_at(AT_FDCWD, b"/locks", 0x42, 0o600).unwrap();
        let requested = v.normalize_lock(fd, 1, 0, 0, 8).unwrap();
        v.record_lock_set(fd, requested).unwrap();
        let mut peer = v.clone_with_files(true);
        peer.set_lock_owner(2);
        let other = peer.normalize_lock(fd, 1, 0, 0, 8).unwrap();
        assert_eq!(
            peer.record_lock_conflict(fd, other).unwrap(),
            Some(requested)
        );
        let locks = v.process_record_locks(1);
        std::thread::spawn(move || locks.release()).join().unwrap();
        assert_eq!(peer.record_lock_conflict(fd, other).unwrap(), None);
        assert!(v.flags(fd).is_ok() && peer.flags(fd).is_ok());
        peer.record_lock_set(fd, other).unwrap();
        v.process_record_locks(1).release();
        assert_eq!(v.record_lock_conflict(fd, requested).unwrap(), Some(other));
    }
    #[test]
    fn ofd_ranges_share_dup_fork_and_retained_lifetime_but_conflict_with_posix() {
        let mut v = Vfs::default();
        let fd = v.open_at(AT_FDCWD, b"/ofd", 0x42, 0o600).unwrap();
        let alias = v.dup(fd, 0, false).unwrap();
        let mut child = v.clone();
        child.set_lock_owner(2);
        let other = v.open_at(AT_FDCWD, b"/ofd", 2, 0).unwrap();
        let lock = v.normalize_ofd_lock(fd, 1, 0, 0, 8).unwrap();
        v.record_lock_set(fd, lock).unwrap();
        assert_eq!(child.normalize_ofd_lock(alias, 1, 0, 0, 8).unwrap(), lock);
        let distinct = v.normalize_ofd_lock(other, 1, 0, 0, 8).unwrap();
        assert_ne!(distinct.owner, lock.owner);
        assert_eq!(v.record_lock_set(other, distinct), Err(Errno(11)));
        let posix = v.normalize_lock(fd, 1, 0, 0, 8).unwrap();
        assert_eq!(v.record_lock_set(fd, posix), Err(Errno(11)));
        v.close(alias).unwrap();
        v.release_process_locks();
        assert_eq!(v.record_lock_conflict(other, distinct).unwrap(), Some(lock));
        let mut epoch = FileEpoch::default();
        let files = epoch.capture(&child, true);
        let accepted = files.get(fd).unwrap();
        v.close(fd).unwrap();
        child.close(fd).unwrap();
        child.close(alias).unwrap();
        assert_eq!(v.record_lock_conflict(other, distinct).unwrap(), Some(lock));
        drop(accepted);
        assert_eq!(v.record_lock_conflict(other, distinct).unwrap(), None);
        v.record_lock_set(other, distinct).unwrap();
        // A prepared weak cache cannot keep a closed OFD's ranges alive.
        v.close(other).unwrap();
        child.close(other).ok();
    }
    #[test]
    fn backward_ranges_readers_and_overflow_are_checked() {
        let mut v = Vfs::default();
        let fd = v.open_at(AT_FDCWD, b"/locks", 0x42, 0o600).unwrap();
        v.write(fd, &[0; 24]).unwrap();
        let lock = v.normalize_lock(fd, 0, 2, -4, -8).unwrap();
        assert_eq!((lock.start, lock.end), (12, 20));
        v.record_lock_set(fd, lock).unwrap();
        let mut child = v.clone();
        child.set_lock_owner(2);
        let reader = child.normalize_lock(fd, 0, 0, 12, 8).unwrap();
        assert_eq!(child.record_lock_conflict(fd, reader).unwrap(), None);
        child.record_lock_set(fd, reader).unwrap();
        let writer = child.normalize_lock(fd, 1, 0, 12, 8).unwrap();
        assert_eq!(
            child
                .record_lock_conflict(fd, writer)
                .unwrap()
                .unwrap()
                .owner,
            1
        );
        assert_eq!(child.record_lock_set(fd, writer), Err(Errno(11)));
        assert_eq!(v.normalize_lock(fd, 1, 0, -1, 0), Err(Errno(22)));
        assert_eq!(v.normalize_lock(fd, 1, 0, i64::MAX, 2), Err(Errno(75)));
        child.close(fd).unwrap();
        assert_eq!(
            v.node(b"/locks")
                .unwrap()
                .borrow()
                .record_locks
                .get()
                .unwrap()
                .0
                .lock()
                .unwrap()
                .len(),
            1
        );
        v.close(fd).unwrap();
        assert_eq!(
            v.node(b"/locks")
                .unwrap()
                .borrow()
                .record_locks
                .get()
                .unwrap()
                .0
                .lock()
                .unwrap()
                .len(),
            0
        );
    }
    #[test]
    fn competing_writers_commit_once_and_readers_can_share() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<Records>();
        send_sync::<Registry>();
        send_sync::<RecordLockContext>();
        let records = Records::default();
        let gate = std::sync::Barrier::new(2);
        let outcomes = [
            std::sync::atomic::AtomicU32::new(0),
            std::sync::atomic::AtomicU32::new(0),
        ];
        std::thread::scope(|scope| {
            for owner in 1..=2 {
                let (records, gate, outcomes) = (&records, &gate, &outcomes);
                scope.spawn(move || {
                    for _ in 0..512 {
                        gate.wait();
                        let lock = RecordLock {
                            kind: 1,
                            start: 4,
                            end: 12,
                            owner,
                        };
                        let result = records.set(lock);
                        assert!(result == Ok(()) || result == Err(Errno(11)));
                        outcomes[owner as usize - 1]
                            .store(u32::from(result.is_ok()), Ordering::Relaxed);
                        gate.wait();
                        if owner == 1 {
                            assert_eq!(
                                outcomes[0].load(Ordering::Relaxed)
                                    + outcomes[1].load(Ordering::Relaxed),
                                1
                            );
                        }
                        gate.wait();
                        records.release(owner);
                    }
                });
            }
        });
        for owner in 1..=2 {
            records
                .set(RecordLock {
                    kind: 0,
                    start: 4,
                    end: 12,
                    owner,
                })
                .unwrap();
        }
        assert_eq!(records.0.lock().unwrap().len(), 2);
    }
    #[test]
    fn ranges_split_merge_and_overflow_leave_existing_locks_intact() {
        let records = Records::default();
        let lock = |kind, start, end| RecordLock {
            kind,
            start,
            end,
            owner: 1,
        };
        records.set(lock(1, 0, 20)).unwrap();
        records.set(lock(2, 5, 10)).unwrap();
        assert_eq!(
            *records.0.lock().unwrap(),
            vec![lock(1, 0, 5), lock(1, 10, 20)]
        );
        records.set(lock(1, 5, 10)).unwrap();
        assert_eq!(*records.0.lock().unwrap(), vec![lock(1, 0, 20)]);
        assert_eq!(normalize(1, i64::MIN, 0, 0, 1), Err(Errno(22)));
        assert_eq!(normalize(1, 0, 2, i64::MAX as u64, 1), Err(Errno(75)));
        assert_eq!(normalize(1, 4, -4, 0, 1).unwrap(), lock(1, 0, 4));
        assert_eq!(
            normalize(1, i64::MAX, 0, 0, 1).unwrap(),
            lock(1, i64::MAX as u64, u64::MAX)
        );
        assert_eq!(*records.0.lock().unwrap(), vec![lock(1, 0, 20)]);
    }
    #[test]
    fn shared_file_locks_release_on_any_process_alias_close_and_exit() {
        let mut parent = Vfs::default();
        let fd = parent.open_at(AT_FDCWD, b"/locks", 0x42, 0o600).unwrap();
        let alias = parent.dup(fd, 0, false).unwrap();
        let mut child = parent.clone();
        child.set_lock_owner(2);
        let mut epoch = FileEpoch::default();
        let files = epoch.capture(&parent, true);
        let file = files.get(fd).unwrap();
        let request = file.normalize_lock(1, 0, 4, 8, 1).unwrap().unwrap();
        let other = RecordLock {
            owner: 2,
            ..request
        };
        std::thread::scope(|scope| {
            scope
                .spawn(|| file.record_lock_set(request))
                .join()
                .unwrap()
        })
        .unwrap();
        assert_eq!(
            child.record_lock_conflict(fd, other).unwrap(),
            Some(request)
        );
        // Closing an inherited FD in another process cannot release parent's lock.
        child.close(alias).unwrap();
        assert_eq!(file.record_lock_conflict(other), Some(request));
        // Any alias in this process releases locks, even though fd/OFD/cap survive.
        parent.close(alias).unwrap();
        assert_eq!(file.record_lock_conflict(other), None);
        child.record_lock_set(fd, other).unwrap();
        parent.release_process_locks();
        assert_eq!(file.record_lock_conflict(request), Some(other));
        child.release_process_locks();
        assert_eq!(file.record_lock_conflict(request), None);
        epoch.finish();
    }
    #[test]
    fn inode_objects_isolate_mounts_but_follow_hardlinks_and_unlink() {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/a", 0o755).unwrap();
        v.mkdir_at(AT_FDCWD, b"/b", 0o755).unwrap();
        for path in [b"/a".as_slice(), b"/b".as_slice()] {
            v.mount(None, path, Some(b"tmpfs"), 0, None).unwrap();
        }
        let a = v.open_at(AT_FDCWD, b"/a/file", 0x42, 0o600).unwrap();
        let b = v.open_at(AT_FDCWD, b"/b/file", 0x42, 0o600).unwrap();
        let inode = |fd| {
            v.descriptor(fd)
                .unwrap()
                .open
                .borrow()
                .node
                .as_ref()
                .unwrap()
                .borrow()
                .inode
        };
        // The present mount allocator prefixes inode numbers. Force a numeric
        // collision to prove that the new key is actual inode object identity.
        let same_number = inode(a);
        v.descriptor(b)
            .unwrap()
            .open
            .borrow()
            .node
            .as_ref()
            .unwrap()
            .borrow_mut()
            .inode = same_number;
        assert_eq!(inode(a), inode(b));
        let request = v.normalize_lock(a, 1, 0, 0, 0).unwrap();
        v.record_lock_set(a, request).unwrap();
        let other = RecordLock {
            owner: 2,
            ..request
        };
        assert_eq!(v.record_lock_conflict(b, other).unwrap(), None);
        v.link_at(AT_FDCWD, b"/a/file", AT_FDCWD, b"/a/link")
            .unwrap();
        let alias = v.open_at(AT_FDCWD, b"/a/link", 2, 0).unwrap();
        assert_eq!(v.record_lock_conflict(alias, other).unwrap(), Some(request));
        v.unlink_at(AT_FDCWD, b"/a/file", false).unwrap();
        v.unlink_at(AT_FDCWD, b"/a/link", false).unwrap();
        assert_eq!(v.record_lock_conflict(alias, other).unwrap(), Some(request));
        v.close(b).unwrap();
        assert_eq!(v.record_lock_conflict(alias, other).unwrap(), Some(request));
        v.release_process_locks();
        assert_eq!(v.record_lock_conflict(alias, other).unwrap(), None);
    }
    #[test]
    fn unrelated_inode_operations_do_not_take_a_global_lock() {
        let registry = Registry::default();
        let a = registry.create();
        let b = registry.create();
        let held = a.0.lock().unwrap();
        let _registry = registry.0.lock().unwrap();
        let _wait_graph = registry.1.lock().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                tx.send(b.set(RecordLock {
                    kind: 1,
                    start: 0,
                    end: 1,
                    owner: 1,
                }))
                .unwrap()
            });
            let result = rx.recv_timeout(std::time::Duration::from_secs(2));
            drop(held);
            assert_eq!(result.unwrap(), Ok(()));
        });
    }
    #[test]
    fn lock_context_uses_tgid_and_frozen_namespace_visibility() {
        let mut root = Vfs::default();
        assert_eq!(root.record_lock_context(41).owner, 41);
        assert_eq!(root.record_lock_context(41).visible_pid(81), 81);
        root.unshare_pid().unwrap();
        root.activate_child_pid(41).unwrap();
        root.activate_child_pid(81).unwrap();
        let context = root.record_lock_context(41);
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    assert_eq!(context.owner, 41);
                    assert_eq!(context.visible_pid(41), 1);
                    assert_eq!(context.visible_pid(81), 2);
                    assert_eq!(context.visible_pid(1), 0);
                })
                .join()
                .unwrap()
        });
    }
    #[test]
    fn record_lock_pid_context_observes_birth_and_reaping_without_recapture() {
        let mut vfs = Vfs::default();
        vfs.unshare_pid().unwrap();
        vfs.activate_child_pid(10).unwrap();
        let context = vfs.record_lock_context(10);
        assert_eq!(context.visible_pid(11), 0);
        let mut child = vfs.clone();
        child.activate_child_pid(11).unwrap();
        assert_eq!(context.visible_pid(11), 2);
        drop(child);
        assert_eq!(context.visible_pid(11), 0);
    }
}

#[cfg(test)]
#[path = "lock_wait_tests.rs"]
mod wait_tests;
