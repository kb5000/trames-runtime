// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared filesystem and overlay resources, independent of namespace topology.
use super::*;
use std::ops::{Deref, DerefMut};
use std::sync::{RwLockReadGuard, RwLockWriteGuard};

#[derive(Clone)]
pub(super) struct FsHandle {
    pub owner: UserNamespace,
    // Logical proc/sysfs superblocks retain their namespace independently of
    // the private volume used for the rest of the guest's inode index.
    pub super_namespace: Option<linux_namespace::SharedNamespace>,
    _super_state: Option<Arc<PseudoSuper>>,
    pub fuse: Option<Arc<fuse::Mounted>>,
    pub shared: Arc<SharedCell<Filesystem>>,
    pub super_readonly: Option<Arc<std::sync::atomic::AtomicBool>>,
    pub write_admission: Arc<std::sync::Mutex<()>>,
    pub writers: Arc<mapped::Writers>,
    pub quota: Arc<file_accounting::FileQuota>,
    pub namespace: Arc<std::sync::Mutex<()>>,
    #[cfg(all(feature = "hostfs", unix))]
    pub host: Option<Arc<hostfs::HostFs>>,
    overlay: Option<Arc<overlay::Overlay>>,
}
pub(super) struct FsBorrow<'a, G> {
    guard: G,
    pub overlay: &'a Option<Arc<overlay::Overlay>>,
    pub quota: &'a Arc<file_accounting::FileQuota>,
}
pub(super) struct PseudoSuper {
    readonly: Arc<std::sync::atomic::AtomicBool>,
    admission: Arc<std::sync::Mutex<()>>,
    writers: Arc<mapped::Writers>,
}
#[derive(Default)]
pub(super) struct SpecialSupers {
    devpts: std::sync::OnceLock<Arc<PseudoSuper>>,
    nsfs: std::sync::OnceLock<Arc<PseudoSuper>>,
}
#[derive(Default)]
pub(super) struct SuperSlot(std::sync::Mutex<std::sync::Weak<PseudoSuper>>);
impl SuperSlot {
    fn get(&self, readonly: bool) -> Arc<PseudoSuper> {
        let mut weak = self.0.lock().unwrap();
        if let Some(state) = weak.upgrade() {
            return state;
        }
        let state = Arc::new(PseudoSuper::new(readonly));
        *weak = Arc::downgrade(&state);
        state
    }
}
impl PseudoSuper {
    pub(super) fn new(readonly: bool) -> Self {
        Self {
            readonly: Arc::new(readonly.into()),
            admission: Arc::default(),
            writers: Arc::default(),
        }
    }
    fn project(
        self: &Arc<Self>,
        backing: &FsHandle,
        namespace: Option<linux_namespace::SharedNamespace>,
        owner: UserNamespace,
    ) -> FsHandle {
        let mut fs = backing.clone();
        fs.owner = owner;
        fs.super_namespace = namespace;
        fs._super_state = Some(self.clone());
        fs.super_readonly = Some(self.readonly.clone());
        fs.write_admission = self.admission.clone();
        fs.writers = self.writers.clone();
        fs
    }
}
impl PidNamespace {
    pub(super) fn proc_filesystem(&self, backing: &FsHandle, readonly: bool) -> FsHandle {
        self.0
            .proc_super
            .get_or_init(|| Arc::new(PseudoSuper::new(readonly)))
            .project(
                backing,
                Some(linux_namespace::SharedNamespace::Pid(self.clone())),
                self.user_namespace().clone(),
            )
    }
}
impl linux_namespace::RootNetwork {
    pub(super) fn sys_filesystem(self: &Arc<Self>, backing: &FsHandle, readonly: bool) -> FsHandle {
        self.sys_super.get(readonly).project(
            backing,
            Some(linux_namespace::SharedNamespace::Net(self.clone())),
            self.user_namespace.clone(),
        )
    }
}
impl Vfs {
    pub(super) fn pseudo_mount_filesystem(
        &self,
        kind: mounts::Kind,
        backing: &FsHandle,
        namespace: Option<&linux_namespace::NamespaceHandle>,
        readonly: bool,
    ) -> FsHandle {
        match kind {
            mounts::Kind::Proc => self.pid_ns.proc_filesystem(backing, readonly),
            mounts::Kind::Sysfs => self.root_network.sys_filesystem(backing, readonly),
            mounts::Kind::Devpts | mounts::Kind::Nsfs => {
                let resources = self.pseudo.borrow().special_supers.clone();
                let slot = if kind == mounts::Kind::Devpts {
                    &resources.devpts
                } else {
                    &resources.nsfs
                };
                slot.get_or_init(|| Arc::new(PseudoSuper::new(false)))
                    .project(
                        backing,
                        namespace.and_then(linux_namespace::SharedNamespace::capture),
                        UserNamespace::default(),
                    )
            }
            _ => backing.clone(),
        }
    }
}
impl FsHandle {
    pub fn new(data: Filesystem) -> Self {
        Self::with_page_accounting(data, false)
    }
    pub fn with_page_accounting(data: Filesystem, tmpfs: bool) -> Self {
        let used = data
            .disk
            .as_ref()
            .map_or_else(|| Arc::new(AtomicU64::new(0)), |d| d.used.clone());
        let quota =
            file_accounting::FileQuota::new(used, data.limits.file_bytes, data.volume, tmpfs);
        for node in data.inodes.iter().filter_map(std::sync::Weak::upgrade) {
            node.bind_quota(&quota)
                .expect("validated initial filesystem");
        }
        Self {
            owner: UserNamespace::default(),
            super_namespace: None,
            _super_state: None,
            #[cfg(all(feature = "hostfs", unix))]
            host: None,
            fuse: None,
            super_readonly: Some(Arc::new(false.into())),
            write_admission: Arc::default(),
            writers: Arc::default(),
            shared: Arc::new(SharedCell::new(data)),
            quota,
            namespace: Arc::default(),
            overlay: None,
        }
    }
    pub fn with_overlay(data: Filesystem, overlay: Arc<overlay::Overlay>) -> Self {
        let quota = overlay.file_quota();
        for node in data.inodes.iter().filter_map(std::sync::Weak::upgrade) {
            node.bind_quota(&quota)
                .expect("validated initial filesystem");
        }
        Self {
            owner: UserNamespace::default(),
            super_namespace: None,
            _super_state: None,
            #[cfg(all(feature = "hostfs", unix))]
            host: None,
            fuse: None,
            super_readonly: Some(Arc::new(false.into())),
            write_admission: Arc::default(),
            writers: Arc::default(),
            shared: Arc::new(SharedCell::new(data)),
            quota,
            namespace: Arc::default(),
            overlay: Some(overlay),
        }
    }
    pub fn borrow(&self) -> FsBorrow<'_, RwLockReadGuard<'_, Filesystem>> {
        FsBorrow {
            guard: self.shared.borrow(),
            overlay: &self.overlay,
            quota: &self.quota,
        }
    }
    pub fn borrow_mut(&self) -> FsBorrow<'_, RwLockWriteGuard<'_, Filesystem>> {
        FsBorrow {
            guard: self.shared.borrow_mut(),
            overlay: &self.overlay,
            quota: &self.quota,
        }
    }
    pub fn same_data(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared)
    }
    pub fn hold_writers(&self) -> Result<mapped::WriterAdmission<'_>> {
        self.writers.hold(&self.write_admission)
    }
    pub fn identity(&self) -> usize {
        Arc::as_ptr(&self.shared) as usize
    }
    pub fn overlay_device(&self) -> Option<u64> {
        self.overlay.as_ref().map(|overlay| overlay.device)
    }
    pub(super) fn overlay_depth(&self) -> usize {
        self.overlay.as_ref().map_or(0, |overlay| overlay.depth)
    }
    /// Persist metadata only on the accepted inode's original filesystem.
    /// A tmpfs/host inode must not checkpoint an unrelated disk root or overlay.
    pub fn checkpoint_metadata(&self, node: &NodeRef) -> Result<()> {
        let n = node.borrow();
        if n.volatile || n.links == 0 {
            return Ok(());
        }
        drop(n);
        self.borrow().checkpoint()
    }
    pub fn has_overlay(&self) -> bool {
        self.overlay.is_some()
    }
    pub(super) fn layer_uses(&self) -> Option<Arc<overlay::LayerUses>> {
        self.overlay.as_ref().map(|overlay| overlay.layer_uses())
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
impl<G: DerefMut<Target = Filesystem>> FsBorrow<'_, G> {
    pub fn track_inode(&mut self, node: &NodeRef) -> Result<()> {
        if self.quota.tmpfs
            && self.overlay.is_none()
            && matches!(&node.borrow().content, Content::Symlink(target) if target.len() >= 128)
            && node.symlink_page.get().is_none()
        {
            // Stored with the inode, including hard links and open-unlinked O_PATH handles.
            // Namespace admission serializes publication on this backing filesystem.
            let charge = file_accounting::FileCharge::admit(self.quota, trames_memory::PAGE_SIZE)?;
            let _ = node.symlink_page.set(charge);
        }
        node.bind_quota(self.quota)?;
        self.inodes.push(Arc::downgrade(node));
        Ok(())
    }
}
impl<G: Deref<Target = Filesystem>> FsBorrow<'_, G> {
    pub fn sync_file_metadata(&self, data_only: bool, node: Option<&NodeRef>) -> Result<()> {
        self.guard
            .sync_file_metadata(data_only, node, self.overlay.as_deref())
    }
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
