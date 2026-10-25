// SPDX-License-Identifier: GPL-3.0-or-later
//! One Linux fs_struct per CLONE_FS domain; no per-syscall peer propagation.
use super::*;
use std::sync::atomic::AtomicU32;

/// A shared scalar, also usable by workers without retaining paths or a VFS.
#[derive(Clone)]
pub struct Umask(Arc<AtomicU32>);
impl Default for Umask {
    fn default() -> Self {
        Self(Arc::new(AtomicU32::new(0o022)))
    }
}
impl Umask {
    pub fn get(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }
    pub fn swap(&self, mask: u32) -> u32 {
        self.0.swap(mask & 0o777, Ordering::Relaxed)
    }
    fn fork(&self) -> Self {
        Self(Arc::new(AtomicU32::new(self.get())))
    }
}

#[derive(Clone, Default)]
pub(super) struct Paths {
    pub cwd_node: Option<NodeRef>,
    pub root_node: Option<NodeRef>,
    pub cwd_mount: Option<Rc<Mount>>,
    pub root_mount: Option<Rc<Mount>>,
}
#[derive(Default)]
pub(super) struct FsContext {
    // Path/mount operations still join. This is deliberately not Send, and is
    // separate from the umask capability shared with workers.
    pub paths: Rc<RefCell<Paths>>,
    mask: Umask,
}
impl FsContext {
    pub(super) fn shared(&self) -> Self {
        Self {
            paths: self.paths.clone(),
            mask: self.mask.clone(),
        }
    }
}
impl Clone for FsContext {
    fn clone(&self) -> Self {
        Self {
            paths: Rc::new(RefCell::new(self.paths.borrow().clone())),
            mask: self.mask.fork(),
        }
    }
}
impl Vfs {
    pub fn shares_context_with(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.context.paths, &other.context.paths)
    }
    pub fn unshare_context(&mut self) {
        self.context = self.context.clone();
    }
    pub fn umask(&self) -> u32 {
        self.context.mask.get()
    }
    pub fn set_umask(&self, mask: u32) -> u32 {
        self.context.mask.swap(mask)
    }
    pub fn umask_capability(&self) -> Umask {
        self.context.mask.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_paths_and_mask_are_live_while_fork_copies_the_context() {
        let mut parent = Vfs::default();
        parent.mkdir_at(AT_FDCWD, b"/a", 0o755).unwrap();
        parent.mkdir_at(AT_FDCWD, b"/b", 0o755).unwrap();
        let root = parent.context.paths.borrow().cwd_node.clone().unwrap();
        let refs = Arc::strong_count(&root);
        let mut shared = parent.clone_with_resources(false, true);
        let peers: Vec<_> = (0..32)
            .map(|_| parent.clone_with_resources(true, true))
            .collect();
        assert_eq!(Arc::strong_count(&root), refs);
        let fork = parent.clone();
        shared.chdir(b"/a").unwrap();
        assert_eq!(shared.set_umask(0o1077), 0o022);
        assert_eq!(parent.cwd().unwrap(), b"/a");
        assert_eq!(parent.umask(), 0o077);
        for peer in peers {
            assert!(peer.shares_context_with(&parent));
            assert_eq!(peer.cwd().unwrap(), b"/a");
        }
        assert_eq!(fork.cwd().unwrap(), b"/");
        assert_eq!(fork.umask(), 0o022);
        let directory = parent.open_at(AT_FDCWD, b"/b", 0, 0).unwrap();
        parent.chdir_fd(directory).unwrap();
        assert_eq!(shared.cwd().unwrap(), b"/b");
        assert_eq!(shared.chdir(b"/missing"), Err(Errno(2)));
        assert_eq!(parent.cwd().unwrap(), b"/b");
    }

    #[test]
    fn chroot_and_unshare_keep_paths_mask_and_files_domains_independent() {
        let mut parent = Vfs::default();
        parent.mkdir_at(AT_FDCWD, b"/jail", 0o755).unwrap();
        parent.mkdir_at(AT_FDCWD, b"/jail/inside", 0o755).unwrap();
        let mut shared = parent.clone_with_resources(true, true);
        shared.chroot(b"/jail").unwrap();
        parent.chdir(b"/inside").unwrap();
        assert_eq!(shared.cwd().unwrap(), b"/inside");
        let old_mask = parent.umask_capability();
        shared.unshare_context();
        assert!(!shared.shares_context_with(&parent));
        assert!(shared.shares_descriptors_with(&parent));
        shared.chdir(b"/").unwrap();
        shared.set_umask(0o077);
        assert_eq!(parent.cwd().unwrap(), b"/inside");
        assert_eq!(old_mask.get(), 0o022);
        old_mask.swap(0o027);
        assert_eq!(parent.umask(), 0o027);
        assert_eq!(shared.umask(), 0o077);
        let file = parent
            .open_at(AT_FDCWD, b"/shared-fd", 0x42, 0o666)
            .unwrap();
        assert!(shared.flags(file).is_ok());
    }

    #[test]
    fn mount_unshare_remaps_only_the_callers_context() {
        let parent = Vfs::default();
        let mut child = parent.clone_with_resources(false, true);
        let old = parent.mount_id_at(AT_FDCWD, b"/", false).unwrap();
        child.unshare_mounts().unwrap();
        assert!(!child.shares_context_with(&parent));
        assert_eq!(parent.mount_id_at(AT_FDCWD, b"/", false).unwrap(), old);
        assert_ne!(child.mount_id_at(AT_FDCWD, b"/", false).unwrap(), old);
        child.set_umask(0o077);
        assert_eq!(parent.umask(), 0o022);
        assert_eq!(child.cwd().unwrap(), b"/");
    }

    #[test]
    fn concurrent_umask_exchanges_return_each_predecessor_exactly_once() {
        let mask = Umask::default();
        mask.swap(0);
        let mut results = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..8)
                .map(|thread| {
                    let mask = &mask;
                    scope.spawn(move || {
                        (1..=32)
                            .map(|i| mask.swap(thread * 32 + i))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            threads
                .into_iter()
                .flat_map(|thread| thread.join().unwrap())
                .collect::<Vec<_>>()
        });
        results.push(mask.get());
        results.sort_unstable();
        assert_eq!(results, (0..=256).collect::<Vec<_>>());
    }
}
