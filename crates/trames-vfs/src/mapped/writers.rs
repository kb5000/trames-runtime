// SPDX-License-Identifier: GPL-3.0-or-later
//! Real writable-mapping references, independent of owner inode/mount anchors.
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
pub(super) struct WriteLease {
    inode: Arc<Writers>,
    mount: Option<Arc<Writers>>,
}
impl WriteLease {
    pub(super) fn new(inode: &Arc<Writers>, mount: Option<&Arc<Writers>>) -> Self {
        // Lifetime accounting does not publish file bytes. Dirty/writeback and
        // VM mapping commits retain their existing synchronization boundaries.
        inode.0.fetch_add(1, Ordering::Relaxed);
        if let Some(mount) = mount {
            mount.0.fetch_add(1, Ordering::Relaxed);
        }
        Self {
            inode: inode.clone(),
            mount: mount.cloned(),
        }
    }
}
impl Clone for WriteLease {
    fn clone(&self) -> Self {
        Self::new(&self.inode, self.mount.as_ref())
    }
}
impl Drop for WriteLease {
    fn drop(&mut self) {
        if let Some(mount) = &self.mount {
            mount.0.fetch_sub(1, Ordering::Relaxed);
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
        let mount = Arc::new(Writers::default());
        let private_mount = Arc::new(Writers::default());
        let first = WriteLease::new(&a, Some(&mount));
        let second = WriteLease::new(&b, Some(&mount));
        let aliases: Vec<_> = (0..8).map(|_| first.clone()).collect();
        drop(first);
        assert!(a.active() && b.active() && mount.active());
        assert!(!private_mount.active());
        std::thread::scope(|s| {
            for alias in aliases {
                s.spawn(move || drop(alias));
            }
        });
        assert!(!a.active());
        assert!(b.active() && mount.active());
        std::thread::spawn(move || drop(second)).join().unwrap();
        assert!(!b.active() && !mount.active());
        let detached = WriteLease::new(&a, None);
        assert!(a.active() && !mount.active());
        drop(detached);
        assert!(!a.active());
    }
}
