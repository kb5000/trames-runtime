// SPDX-License-Identifier: GPL-3.0-or-later
//! Real writable-mapping references, independent of owner inode/mount anchors.
use super::super::{mounts::MountIdentity, NodeRef};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[derive(Default)]
pub(crate) struct Writers(AtomicUsize);
impl Writers {
    pub(crate) fn active(&self) -> bool {
        self.0.load(Ordering::Relaxed) != 0
    }
}

/// A live mapping or an explicitly retained writable operation owns a lease.
/// Sharing its PageBacking Rc does not create another lease. A retained lease
/// may be released on a worker without a page scan or owner cache invalidation.
#[derive(Clone)]
pub(super) struct WriteLease {
    _lease: Arc<Lease>,
}
struct Lease {
    _node: NodeRef,
    inode: Arc<Writers>,
    mount: Option<Arc<MountIdentity>>,
}
impl WriteLease {
    pub(super) fn new(
        node: &NodeRef,
        inode: &Arc<Writers>,
        mount: Option<&Arc<MountIdentity>>,
    ) -> Self {
        // Lifetime accounting does not publish file bytes. Dirty/writeback and
        // VM mapping commits retain their existing synchronization boundaries.
        inode.0.fetch_add(1, Ordering::Relaxed);
        if let Some(mount) = mount {
            mount.writers.0.fetch_add(1, Ordering::Relaxed);
        }
        Self {
            _lease: Arc::new(Lease {
                _node: node.clone(),
                inode: inode.clone(),
                mount: mount.cloned(),
            }),
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(mount) = &self.mount {
            mount.writers.0.fetch_sub(1, Ordering::Relaxed);
        }
        self.inode.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let private_mount = Arc::new(Writers::default());
        let first = WriteLease::new(&anode, &a, Some(&mount));
        let second = WriteLease::new(&bnode, &b, Some(&mount));
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
        let detached = WriteLease::new(&anode, &a, None);
        assert!(a.active() && !mount.writers.active());
        drop(detached);
        assert!(!a.active());
    }
}
