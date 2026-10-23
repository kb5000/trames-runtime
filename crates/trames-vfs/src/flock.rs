// SPDX-License-Identifier: GPL-3.0-or-later
//! Inode-local flock arbitration; the actual OFD lease owns its lock lifetime.
use super::*;
use std::sync::Mutex;

#[derive(Default)]
pub(super) struct Whole {
    owners: Mutex<BTreeMap<u64, u32>>,
    readiness: Arc<readiness::Readiness>,
}
pub(super) struct Owner {
    id: u64,
    whole: Arc<Whole>,
}
pub(super) fn validate(operation: u32) -> Result<u32> {
    if operation & !15 != 0 || !matches!(operation & !4, 1 | 2 | 8) {
        Err(Errno(22))
    } else {
        Ok(operation & !4)
    }
}
/// Accepted lock request. Only the lock lease crosses workers; the complete
/// OFD remains retained by the frozen table or by the parked Process at joins.
#[derive(Clone)]
pub struct FlockRequest {
    owner: Arc<Owner>,
    operation: u32,
}
impl FlockRequest {
    pub(super) fn new(owner: Arc<Owner>, operation: u32) -> Self {
        Self { owner, operation }
    }
    pub fn try_lock(&self) -> Result<()> {
        self.owner.apply(self.operation)
    }
    pub fn nonblocking(&self) -> bool {
        self.operation & 4 != 0
    }
    pub fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.owner, &other.owner)
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.owner.whole.readiness.subscribe(signal)
    }
}
impl RetainedFd {
    pub fn flock_request(&self, operation: u32) -> Result<FlockRequest> {
        validate(operation)?;
        Ok(FlockRequest::new(
            self.0.open.borrow().flock_owner()?.clone(),
            operation,
        ))
    }
}
impl Owner {
    pub(super) fn apply(&self, operation: u32) -> Result<()> {
        let kind = validate(operation)?;
        let mut owners = self.whole.owners.lock().unwrap();
        if owners.get(&self.id) == Some(&kind) {
            return Ok(());
        }
        // Conversion releases the old lock even if the new kind conflicts.
        let removed = owners.remove(&self.id).is_some();
        let result = if kind != 8 && owners.values().any(|other| kind == 2 || *other == 2) {
            Err(Errno(11))
        } else {
            if kind != 8 {
                owners.insert(self.id, kind);
            }
            Ok(())
        };
        drop(owners);
        if removed {
            self.whole.readiness.notify_locked();
        }
        result
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        let removed = self.whole.owners.lock().unwrap().remove(&self.id).is_some();
        // Last-close can run on any worker. Wake after releasing the inode lock;
        // no owner map scan or acknowledgement is needed to unlock the file.
        if removed {
            self.whole.readiness.notify_locked();
        }
    }
}
impl OpenDescription {
    fn flock_owner(&self) -> Result<&Arc<Owner>> {
        if self.flags.get() & O_PATH != 0 {
            return Err(Errno(9));
        }
        let node = self.node.as_ref().ok_or(Errno(9))?.borrow();
        Ok(self.flock.get_or_init(|| {
            Arc::new(Owner {
                id: self.id,
                whole: node.whole_locks.get_or_init(Arc::default).clone(),
            })
        }))
    }
    pub(super) fn flock_capability(&self) -> std::sync::Weak<Owner> {
        self.flock_owner().map(Arc::downgrade).unwrap_or_default()
    }
}
impl Vfs {
    pub fn retain_flock(&self, fd: u32, operation: u32) -> Result<(FlockRequest, RetainedFd)> {
        validate(operation)?;
        let file = RetainedFd(self.descriptor(fd)?);
        Ok((file.flock_request(operation)?, file))
    }
    /// Cold cohort admission only: an unrelated idle waiter must not divert
    /// solo compute off the direct Memory path. No inode/object allocation.
    pub fn shares_flock(&self, request: &FlockRequest) -> bool {
        self.fds.entries().values().any(|d| {
            d.open.borrow().node.as_ref().is_some_and(|n| {
                n.borrow()
                    .whole_locks
                    .get()
                    .is_some_and(|w| Arc::ptr_eq(w, &request.owner.whole))
            })
        })
    }
    pub fn flock(&mut self, fd: u32, operation: u32) -> Result<()> {
        validate(operation)?;
        self.descriptor(fd)?
            .open
            .borrow()
            .flock_owner()?
            .apply(operation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{atomic::AtomicUsize, Barrier};

    fn file(v: &mut Vfs) -> u32 {
        v.open_at(AT_FDCWD, b"/lock", 0x42, 0o600).unwrap()
    }

    #[test]
    fn simultaneous_exclusive_acquisitions_have_one_winner() {
        let mut v = Vfs::default();
        let fds: Vec<_> = (0..8).map(|_| file(&mut v)).collect();
        let mut epoch = FileEpoch::default();
        let files = epoch.capture(&v, true);
        let gate = Barrier::new(fds.len());
        let won = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for fd in fds {
                let cap = files.get(fd).unwrap();
                let gate = &gate;
                let won = &won;
                s.spawn(move || {
                    gate.wait();
                    let result = cap.flock(2 | 4);
                    assert!(result == Ok(()) || result == Err(Errno(11)));
                    if result.is_ok() {
                        won.fetch_add(1, Ordering::Relaxed);
                    }
                    gate.wait();
                    if result.is_ok() {
                        cap.flock(8).unwrap();
                    }
                });
            }
        });
        assert_eq!(won.load(Ordering::Relaxed), 1);
        epoch.finish();
    }

    struct Wake {
        other: Arc<Owner>,
        calls: AtomicUsize,
    }
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {
            // Lock reentry proves the dropping worker released the inode mutex.
            self.other.apply(2 | 4).unwrap();
            self.calls.fetch_add(1, Ordering::Relaxed);
        }
    }
    #[test]
    fn last_worker_lease_releases_lock_and_weak_snapshots_do_not_extend_lifetime() {
        let mut v = Vfs::default();
        let a = file(&mut v);
        let b = file(&mut v);
        let mut epoch = FileEpoch::default();
        let files = epoch.capture(&v, true);
        v.flock(a, 2 | 4).unwrap();
        let lease = v
            .descriptor(a)
            .unwrap()
            .open
            .borrow()
            .flock_owner()
            .unwrap()
            .clone();
        let other = v
            .descriptor(b)
            .unwrap()
            .open
            .borrow()
            .flock_owner()
            .unwrap()
            .clone();
        let wake = Arc::new(Wake {
            other,
            calls: AtomicUsize::new(0),
        });
        let target: Arc<dyn IoWake> = wake.clone();
        let signal = IoSignal::new(1, Arc::downgrade(&target));
        let subscription = lease.whole.readiness.subscribe(&signal);
        v.close(a).unwrap();
        assert_eq!(v.flock(b, 2 | 4), Err(Errno(11)));
        std::thread::spawn(move || drop(lease)).join().unwrap();
        assert_eq!(wake.calls.load(Ordering::Relaxed), 1);
        assert!(signal.ready());
        assert_eq!(files.get(a).unwrap().flock(2 | 4), Err(Errno(9)));
        assert_eq!(v.flock(b, 2 | 4), Ok(()));
        drop(subscription);
        epoch.finish();
    }

    #[test]
    fn invalid_and_path_calls_preserve_locks_but_failed_conversion_releases_old_kind() {
        let mut v = Vfs::default();
        let a = file(&mut v);
        let b = file(&mut v);
        let path = v.open_at(AT_FDCWD, b"/lock", O_PATH, 0).unwrap();
        assert_eq!(v.flock(path, 2 | 4), Err(Errno(9)));
        v.flock(a, 1 | 4).unwrap();
        v.flock(b, 1 | 4).unwrap();
        assert_eq!(v.flock(a, 3 | 4), Err(Errno(22)));
        v.flock(b, 8).unwrap();
        assert_eq!(v.flock(b, 2 | 4), Err(Errno(11)));
        v.flock(b, 1 | 4).unwrap();
        assert_eq!(v.flock(a, 2 | 4), Err(Errno(11)));
        v.flock(b, 2 | 4).unwrap(); // a's old shared lock was dropped.
    }

    #[test]
    fn locks_in_independent_filesystems_do_not_conflict() {
        let mut v = Vfs::default();
        // The locking inode belongs to its resolved mount, while the caller's
        // VFS still has the same root filesystem for both descriptors.
        v.mkdir_at(AT_FDCWD, b"/a", 0o755).unwrap();
        v.mkdir_at(AT_FDCWD, b"/b", 0o755).unwrap();
        v.mount(None, b"/a", Some(b"tmpfs"), 0, None).unwrap();
        v.mount(None, b"/b", Some(b"tmpfs"), 0, None).unwrap();
        let a = v.open_at(AT_FDCWD, b"/a/lock", 0x42, 0o600).unwrap();
        let b = v.open_at(AT_FDCWD, b"/b/lock", 0x42, 0o600).unwrap();
        let first = v.descriptor(a).unwrap();
        let second = v.descriptor(b).unwrap();
        assert_ne!(
            first.open.borrow().node.as_ref().unwrap().borrow().inode,
            second.open.borrow().node.as_ref().unwrap().borrow().inode
        );
        v.flock(a, 6).unwrap();
        v.flock(b, 6).unwrap();
    }
}
