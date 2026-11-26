// SPDX-License-Identifier: GPL-3.0-or-later
//! Real writable OFD/mapping references and mount transition admission.
use super::super::{mounts::MountIdentity, NodeRef, SharedOpenDescription};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[derive(Default)]
pub(crate) struct Writers(AtomicUsize);
const HOLD: usize = 1 << (usize::BITS - 1);

/// The existing per-object mutex serializes transitions and their cold waiters.
/// Its counter bit prevents ordinary admissions without locking every open.
pub(crate) struct Admission<'a> {
    _guard: std::sync::MutexGuard<'a, ()>,
    writers: &'a Writers,
}
impl Drop for Admission<'_> {
    fn drop(&mut self) {
        // Publish the completed mount flag/idmap change before new admissions.
        self.writers.0.fetch_and(!HOLD, Ordering::Release);
    }
}
/// A retained metadata/data operation pins only its original mount's write
/// admission. It does not serialize daemon operations or hold an inode lock.
pub(crate) struct MountWrite(Arc<MountIdentity>);
impl MountWrite {
    pub(crate) fn new(mount: &Arc<MountIdentity>) -> super::super::Result<Self> {
        if mount.fs.writers.try_register() {
            if mount.writers.try_register() {
                if mount.flags.get() & super::super::mounts::MS_RDONLY == 0 {
                    return Ok(Self(mount.clone()));
                }
                mount.writers.unregister();
                mount.fs.writers.unregister();
                return Err(super::super::Errno(30));
            }
            mount.fs.writers.unregister();
        }
        Self::wait(mount)
    }
    #[cold]
    fn wait(mount: &Arc<MountIdentity>) -> super::super::Result<Self> {
        let _super_admission = mount.fs.write_admission.lock().unwrap();
        let _admission = mount.writer_admission.lock().unwrap();
        if mount.flags.get() & super::super::mounts::MS_RDONLY != 0 {
            return Err(super::super::Errno(30));
        }
        mount.writers.0.fetch_add(1, Ordering::Relaxed);
        mount.fs.writers.0.fetch_add(1, Ordering::Relaxed);
        Ok(Self(mount.clone()))
    }
}
impl Drop for MountWrite {
    fn drop(&mut self) {
        self.0.writers.0.fetch_sub(1, Ordering::Relaxed);
        self.0.fs.writers.0.fetch_sub(1, Ordering::Relaxed);
    }
}
impl Writers {
    fn try_register(&self) -> bool {
        // Acquire pairs only with an actual transition's release of HOLD; the
        // counter itself does not publish file contents or strengthen guest IO.
        let old = self.0.fetch_add(1, Ordering::Acquire);
        if old & HOLD == 0 {
            return true;
        }
        self.unregister();
        false
    }
    fn unregister(&self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
    pub(crate) fn hold<'a>(
        &'a self,
        gate: &'a std::sync::Mutex<()>,
    ) -> super::super::Result<Admission<'a>> {
        let guard = gate.lock().unwrap();
        let old = self.0.fetch_or(HOLD, Ordering::Relaxed);
        debug_assert_eq!(old & HOLD, 0, "one transition per original object");
        if old & !HOLD != 0 {
            self.0.fetch_and(!HOLD, Ordering::Release);
            return Err(super::super::Errno(16));
        }
        Ok(Admission {
            _guard: guard,
            writers: self,
        })
    }
    pub(crate) fn active(&self) -> bool {
        self.0.load(Ordering::Relaxed) & !HOLD != 0
    }
}

/// A live mapping or an explicitly retained writable operation owns a lease.
/// Sharing its PageBacking Arc does not create another lease. A retained lease
/// may be released on a worker without a page scan or owner cache invalidation.
#[derive(Clone)]
pub(super) struct WriteLease {
    _lease: Arc<Lease>,
}
struct Lease {
    _node: NodeRef,
    inode: Arc<Writers>,
    mount: Option<Arc<MountIdentity>>,
    _open: Option<Arc<SharedOpenDescription>>,
}
impl WriteLease {
    pub(super) fn new(
        node: &NodeRef,
        inode: &Arc<Writers>,
        mount: Option<&Arc<MountIdentity>>,
        open: Option<&Arc<SharedOpenDescription>>,
    ) -> Self {
        // Lifetime accounting does not publish file bytes. Dirty/writeback and
        // VM mapping commits retain their existing synchronization boundaries.
        inode.0.fetch_add(1, Ordering::Relaxed);
        if let Some(mount) = mount {
            mount.writers.0.fetch_add(1, Ordering::Relaxed);
            mount.fs.writers.0.fetch_add(1, Ordering::Relaxed);
        }
        Self {
            _lease: Arc::new(Lease {
                _node: node.clone(),
                inode: inode.clone(),
                mount: mount.cloned(),
                _open: open.cloned(),
            }),
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(mount) = &self.mount {
            mount.writers.0.fetch_sub(1, Ordering::Relaxed);
            mount.fs.writers.0.fetch_sub(1, Ordering::Relaxed);
        }
        self.inode.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordinary_admission_does_not_wait_on_inactive_transition_mutexes() {
        let v = crate::Vfs::default();
        let mount = v.mounts.as_ref().unwrap().0.borrow().root.identity.clone();
        let super_guard = mount.fs.write_admission.lock().unwrap();
        let mount_guard = mount.writer_admission.lock().unwrap();
        let (done, result) = std::sync::mpsc::channel();
        let worker_mount = mount.clone();
        let worker = std::thread::spawn(move || {
            let writer = MountWrite::new(&worker_mount).unwrap();
            done.send(()).unwrap();
            drop(writer);
        });
        let admitted = result.recv_timeout(std::time::Duration::from_secs(2));
        // Always release the gates before asserting or joining a failed worker.
        drop(mount_guard);
        drop(super_guard);
        worker.join().unwrap();
        admitted.unwrap();
        assert!(!mount.writers.active() && !mount.fs.writers.active());
    }
    #[test]
    fn actual_transition_excludes_new_writers_and_denial_leaks_no_counts() {
        let v = crate::Vfs::default();
        let mount = v.mounts.as_ref().unwrap().0.borrow().root.identity.clone();
        let transition = mount.fs.writers.hold(&mount.fs.write_admission).unwrap();
        let (started, ready) = std::sync::mpsc::channel();
        let worker_mount = mount.clone();
        let worker = std::thread::spawn(move || {
            started.send(()).unwrap();
            MountWrite::new(&worker_mount).err()
        });
        ready.recv().unwrap();
        mount
            .fs
            .super_readonly
            .as_ref()
            .unwrap()
            .store(true, Ordering::Relaxed);
        drop(transition);
        assert_eq!(worker.join().unwrap(), Some(crate::Errno(30)));
        assert!(!mount.writers.active() && !mount.fs.writers.active());
        mount
            .fs
            .super_readonly
            .as_ref()
            .unwrap()
            .store(false, Ordering::Relaxed);
        let writer = MountWrite::new(&mount).unwrap();
        assert!(matches!(
            mount.fs.writers.hold(&mount.fs.write_admission),
            Err(crate::Errno(16))
        ));
        drop(writer);
        let transition = mount.fs.writers.hold(&mount.fs.write_admission).unwrap();
        assert!(!mount.fs.writers.active());
        drop(transition);
        assert!(!mount.fs.writers.active());
    }
    #[test]
    fn worker_clones_hold_each_inode_and_mount_until_its_last_reference() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<WriteLease>();
        let a = Arc::new(Writers::default());
        let b = Arc::new(Writers::default());
        let mut v = crate::Vfs::default();
        v.initialize_mounts().unwrap();
        let afd = v.open_at(crate::AT_FDCWD, b"/a", 0x42, 0o600).unwrap();
        let bfd = v.open_at(crate::AT_FDCWD, b"/b", 0x42, 0o600).unwrap();
        let anode = v
            .descriptor(afd)
            .unwrap()
            .open
            .borrow()
            .node
            .clone()
            .unwrap();
        let bnode = v
            .descriptor(bfd)
            .unwrap()
            .open
            .borrow()
            .node
            .clone()
            .unwrap();
        let mount = v.mounts.as_ref().unwrap().0.borrow().root.identity.clone();
        v.close(afd).unwrap();
        v.close(bfd).unwrap();
        let private_mount = Arc::new(Writers::default());
        let first = WriteLease::new(&anode, &a, Some(&mount), None);
        let second = WriteLease::new(&bnode, &b, Some(&mount), None);
        let aliases: Vec<_> = (0..8).map(|_| first.clone()).collect();
        drop(first);
        assert!(a.active() && b.active() && mount.writers.active());
        assert!(!private_mount.active());
        std::thread::scope(|s| {
            for alias in aliases {
                s.spawn(move || drop(alias));
            }
        });
        assert!(!a.active());
        assert!(b.active() && mount.writers.active());
        std::thread::spawn(move || drop(second)).join().unwrap();
        assert!(!b.active() && !mount.writers.active());
        let detached = WriteLease::new(&anode, &a, None, None);
        assert!(a.active() && !mount.writers.active());
        drop(detached);
        assert!(!a.active());
    }
}
