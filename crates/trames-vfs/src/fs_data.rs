// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared filesystem data, separated from owner-only overlay orchestration.
use super::*;
use std::ops::{Deref, DerefMut};
use std::sync::{RwLockReadGuard, RwLockWriteGuard};

#[derive(Clone)]
pub(super) struct FsHandle {
    pub shared: Arc<SharedCell<Filesystem>>,
    overlay: Option<Rc<overlay::Overlay>>,
}
pub(super) struct FsBorrow<'a, G> {
    guard: G,
    pub overlay: &'a Option<Rc<overlay::Overlay>>,
}
impl FsHandle {
    pub fn new(data: Filesystem) -> Self {
        Self {
            shared: Arc::new(SharedCell::new(data)),
            overlay: None,
        }
    }
    pub fn with_overlay(data: Filesystem, overlay: Rc<overlay::Overlay>) -> Self {
        Self {
            shared: Arc::new(SharedCell::new(data)),
            overlay: Some(overlay),
        }
    }
    pub fn borrow(&self) -> FsBorrow<'_, RwLockReadGuard<'_, Filesystem>> {
        FsBorrow {
            guard: self.shared.borrow(),
            overlay: &self.overlay,
        }
    }
    pub fn borrow_mut(&self) -> FsBorrow<'_, RwLockWriteGuard<'_, Filesystem>> {
        FsBorrow {
            guard: self.shared.borrow_mut(),
            overlay: &self.overlay,
        }
    }
    pub fn same_data(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared)
    }
    pub fn identity(&self) -> usize {
        Arc::as_ptr(&self.shared) as usize
    }
}
impl<G: Deref<Target = Filesystem>> Deref for FsBorrow<'_, G> {
    type Target = Filesystem;
    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}
impl<G: DerefMut<Target = Filesystem>> DerefMut for FsBorrow<'_, G> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}
impl<G: Deref<Target = Filesystem>> FsBorrow<'_, G> {
    pub fn checkpoint(&self) -> Result<()> {
        self.guard.checkpoint(self.overlay.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_filesystem_retains_live_inode_and_releases_it_on_last_worker_drop() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<Filesystem>();
        send_sync::<SharedCell<Filesystem>>();
        let mut vfs = Vfs::default();
        vfs.import_file(b"/retained", b"bytes".to_vec()).unwrap();
        let fs = vfs.fs.shared.clone();
        let inode = Arc::downgrade(&fs.borrow().paths[b"/retained".as_slice()]);
        drop(vfs);
        assert!(inode.upgrade().is_some());
        std::thread::spawn(move || {
            let node = fs.borrow().paths[b"/retained".as_slice()].clone();
            assert!(matches!(&node.borrow().content, Content::File(data) if data.len() == 5));
            drop(node);
            drop(fs);
        })
        .join()
        .unwrap();
        assert!(inode.upgrade().is_none());
    }
}
