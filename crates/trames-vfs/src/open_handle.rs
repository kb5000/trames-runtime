// SPDX-License-Identifier: GPL-3.0-or-later
//! Actual shared OFDs for admitted resources, with explicit owner-only control.
use super::*;

/// A prepared descriptor's weak identity, without retaining its resources.
/// The weak allocation prevents address reuse while an accepted wait compares
/// owner bindings. Capture only after the OFD's constructor has completed.
#[derive(Clone)]
pub struct OfdIdentity(std::sync::Weak<SharedOpenDescription>);
impl OfdIdentity {
    pub(super) fn new(open: &Arc<SharedOpenDescription>) -> Self {
        Self(Arc::downgrade(open))
    }
    pub(super) fn matches(&self, open: &Arc<SharedOpenDescription>) -> bool {
        std::ptr::eq(self.0.as_ptr(), Arc::as_ptr(open))
    }
}
impl PartialEq for OfdIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.0.ptr_eq(&other.0)
    }
}
impl Eq for OfdIdentity {}

#[derive(Clone)]
pub(super) enum OpenMount {
    Owner(Rc<Mount>),
    Shared(Arc<mounts::MountData>),
}
impl std::ops::Deref for OpenMount {
    type Target = mounts::MountData;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owner(mount) => &mount.shared,
            Self::Shared(mount) => mount,
        }
    }
}
impl OpenMount {
    fn shared_resources(&self) -> Option<Arc<mounts::MountData>> {
        match self {
            Self::Owner(mount) => mount.shared_resources(),
            Self::Shared(mount) => Some(mount.clone()),
        }
    }
}

#[derive(Clone)]
pub(super) enum OpenHandle {
    Shared(Arc<SharedOpenDescription>),
    Owner(Rc<RefCell<OpenDescription>>),
}
#[derive(Clone)]
pub(super) enum OpenWeak {
    Shared(std::sync::Weak<SharedOpenDescription>),
    Owner(Weak<RefCell<OpenDescription>>),
}
pub(super) enum OpenView<'a> {
    Shared(&'a Arc<SharedOpenDescription>),
    Owner(&'a OpenHandle),
}
impl OpenView<'_> {
    pub(super) fn borrow(&self) -> OpenRead<'_> {
        match self {
            Self::Shared(open) => {
                OpenRead::Shared(OpenDescription::shared_projection((*open).clone()))
            }
            Self::Owner(open) => open.borrow(),
        }
    }
    pub(super) fn downgrade(&self) -> OpenWeak {
        match self {
            Self::Shared(open) => OpenWeak::Shared(Arc::downgrade(open)),
            Self::Owner(open) => open.downgrade(),
        }
    }
    pub(super) fn owned(&self) -> OpenHandle {
        match self {
            Self::Shared(open) => OpenHandle::Shared((*open).clone()),
            Self::Owner(open) => (*open).clone(),
        }
    }
}
pub(super) enum OpenRead<'a> {
    Shared(OpenDescription),
    Owner(std::cell::Ref<'a, OpenDescription>),
}
pub(super) enum OpenWrite<'a> {
    Shared(OpenDescription),
    Owner(std::cell::RefMut<'a, OpenDescription>),
}
impl OpenDescription {
    pub(super) fn shared_projection(shared: Arc<SharedOpenDescription>) -> Self {
        let mount = shared.mount_resource.get().cloned().map(OpenMount::Shared);
        let anonymous = shared
            .control
            .as_ref()
            .map(events::SharedControl::owner_projection);
        Self {
            shared,
            position: 0,
            socket: None,
            anonymous,
            local: None,
            pty: None,
            namespace: None,
            oom: None,
            network_control: None,
            mount,
        }
    }
    fn shareable(&self) -> bool {
        if self.socket.is_some()
            || self.anonymous.is_some() && self.control.is_none()
            || self.local.is_some()
            || self.pty.is_some()
            || self.namespace.is_some()
            || self.oom.is_some()
            || self.network_control.is_some()
            || self.bridge.is_some()
            || self.kernel_log.is_some()
        {
            return false;
        }
        self.control.is_some()
            || self.pipe.is_some()
            || self.node.as_ref().is_some_and(|node| {
                let node = node.borrow();
                !node.volatile && node.seals.is_none() && matches!(node.content, Content::File(_))
            })
    }
}
impl OpenHandle {
    pub(super) fn new(open: OpenDescription) -> Self {
        if open.shareable() {
            let mount = match &open.mount {
                None => Some(None),
                Some(mount) => mount.shared_resources().map(Some),
            };
            if let Some(mount) = mount {
                if let Some(mount) = mount {
                    let published = open.shared.mount_resource.get_or_init(|| mount.clone());
                    debug_assert!(Arc::ptr_eq(published, &mount));
                }
                return Self::Shared(open.shared.clone());
            }
        }
        Self::Owner(Rc::new(RefCell::new(open)))
    }
    pub(super) fn borrow(&self) -> OpenRead<'_> {
        match self {
            Self::Shared(open) => {
                OpenRead::Shared(OpenDescription::shared_projection(open.clone()))
            }
            Self::Owner(open) => OpenRead::Owner(open.borrow()),
        }
    }
    pub(super) fn borrow_mut(&self) -> OpenWrite<'_> {
        match self {
            Self::Shared(open) => {
                OpenWrite::Shared(OpenDescription::shared_projection(open.clone()))
            }
            Self::Owner(open) => OpenWrite::Owner(open.borrow_mut()),
        }
    }
    pub(super) fn downgrade(&self) -> OpenWeak {
        match self {
            Self::Shared(open) => OpenWeak::Shared(Arc::downgrade(open)),
            Self::Owner(open) => OpenWeak::Owner(Rc::downgrade(open)),
        }
    }
    pub(super) fn ptr_eq(a: &Self, b: &Self) -> bool {
        match (a, b) {
            (Self::Shared(a), Self::Shared(b)) => Arc::ptr_eq(a, b),
            (Self::Owner(a), Self::Owner(b)) => Rc::ptr_eq(a, b),
            _ => false,
        }
    }
    pub(super) fn identity(&self) -> usize {
        match self {
            Self::Shared(open) => Arc::as_ptr(open) as usize,
            Self::Owner(open) => Rc::as_ptr(open) as usize,
        }
    }
    #[cfg(test)]
    pub(super) fn strong_count(&self) -> usize {
        match self {
            Self::Shared(open) => Arc::strong_count(open),
            Self::Owner(open) => Rc::strong_count(open),
        }
    }
}
impl OpenWeak {
    pub(super) fn strong_count(&self) -> usize {
        match self {
            Self::Shared(open) => open.strong_count(),
            Self::Owner(open) => open.strong_count(),
        }
    }
    pub(super) fn upgrade(&self) -> Option<OpenHandle> {
        match self {
            Self::Shared(open) => open.upgrade().map(OpenHandle::Shared),
            Self::Owner(open) => open.upgrade().map(OpenHandle::Owner),
        }
    }
}
impl std::ops::Deref for OpenRead<'_> {
    type Target = OpenDescription;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Shared(open) => open,
            Self::Owner(open) => open,
        }
    }
}
impl std::ops::Deref for OpenWrite<'_> {
    type Target = OpenDescription;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Shared(open) => open,
            Self::Owner(open) => open,
        }
    }
}
impl std::ops::DerefMut for OpenWrite<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Shared(open) => open,
            Self::Owner(open) => open,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pathname_ofd_retains_real_resources_after_detach_and_owner_exit() {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/retained", 0o755).unwrap();
        v.mount(None, b"/retained", Some(b"tmpfs"), 0, None)
            .unwrap();
        let fd = v.open_at(AT_FDCWD, b"/retained/file", 0x42, 0o600).unwrap();
        v.write(fd, b"retained bytes").unwrap();
        let (owner, mount, filesystem, inode) = {
            let descriptor = v.descriptor(fd).unwrap();
            let open = descriptor.open.borrow();
            let mount = open.mount.as_ref().unwrap();
            (
                Rc::downgrade(&v.mount_for_path(Some(mount)).unwrap()),
                Arc::downgrade(open.mount_resource.get().unwrap()),
                Arc::downgrade(&mount.fs.shared),
                Arc::downgrade(open.node.as_ref().unwrap()),
            )
        };
        let accepted = v.shared_files().lookup(fd).unwrap().unwrap();
        assert_eq!(v.umount(b"/retained", 0), Err(Errno(16)));
        v.umount(b"/retained", 2).unwrap();
        assert!(v.detached_mounts.borrow().is_empty());
        assert!(owner.upgrade().is_none());
        assert_eq!(v.pread(fd, 14, 0).unwrap(), b"retained bytes");
        drop(v);
        assert!(mount.upgrade().is_some());
        std::thread::spawn(move || {
            let node = inode.upgrade().unwrap();
            {
                let node = node.borrow();
                let Content::File(data) = &node.content else {
                    panic!("retained file")
                };
                assert_eq!(data.read_at(0, 14).unwrap(), b"retained bytes");
            }
            drop(node);
            drop(accepted);
            assert!(inode.upgrade().is_none());
        })
        .join()
        .unwrap();
        assert!(mount.upgrade().is_none());
        assert!(filesystem.upgrade().is_none());
    }

    #[test]
    fn pathname_ofd_uses_live_mount_flags_and_original_mount_after_unshare() {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/mounted", 0o755).unwrap();
        v.mount(None, b"/mounted", Some(b"tmpfs"), 0, None).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/mounted/file", 0x42, 0o600).unwrap();
        v.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    fds: v.fd_snapshot(),
                    ..ProcessInfo::default()
                }],
                ..RuntimeInfo::default()
            },
        );
        assert!(v.shared_files().lookup(fd).unwrap().is_ok());
        let id = v.mount_id_fd(fd).unwrap();
        let path = format!("/proc/self/fd/{fd}").into_bytes();
        assert_eq!(v.readlink_at(AT_FDCWD, &path).unwrap(), b"/mounted/file");
        v.mount(None, b"/mounted", None, 32 | mounts::MS_RDONLY, None)
            .unwrap();
        assert_eq!(v.write(fd, b"x"), Err(Errno(30)));
        assert_eq!(v.open_at(AT_FDCWD, &path, 2, 0), Err(Errno(30)));
        assert_eq!(
            u64::from_le_bytes(v.statfs_fd(fd).unwrap()[80..88].try_into().unwrap()) & 1,
            1
        );
        v.mount(None, b"/mounted", None, 32, None).unwrap();
        v.unshare_mounts().unwrap();
        v.mount(None, b"/mounted", None, 32 | mounts::MS_RDONLY, None)
            .unwrap();
        assert_eq!(v.open_at(AT_FDCWD, b"/mounted/file", 2, 0), Err(Errno(30)));
        let reopened = v.open_at(AT_FDCWD, &path, 2, 0).unwrap();
        assert_eq!(v.mount_id_fd(reopened).unwrap(), id);
        v.write(reopened, b"old mount").unwrap();
        assert_eq!(v.pread(fd, 9, 0).unwrap(), b"old mount");
        assert_eq!(v.readlink_at(AT_FDCWD, &path).unwrap(), b"/mounted/file");
        v.umount(b"/mounted", 0).unwrap();
        assert_eq!(v.pread(fd, 9, 0).unwrap(), b"old mount");
    }

    #[test]
    fn pathname_shared_close_releases_process_locks_then_final_flock_and_notification() {
        let mut v = Vfs::default();
        v.set_lock_owner(11);
        let fd = v.open_at(AT_FDCWD, b"/shared-close", 0x42, 0o600).unwrap();
        let alias = v.dup(fd, 64, false).unwrap();
        let contender = v.open_at(AT_FDCWD, b"/shared-close", 2, 0).unwrap();
        let notify = v.inotify_init(O_NONBLOCK).unwrap();
        v.inotify_add(notify, b"/shared-close", 8).unwrap();
        let requested = v.normalize_lock(fd, 1, 0, 0, 8).unwrap();
        v.record_lock_set(fd, requested).unwrap();
        v.flock(fd, 6).unwrap();
        let files = v.shared_files();
        let accepted = files.lookup(fd).unwrap().unwrap();
        let lock_set = v
            .descriptor(fd)
            .unwrap()
            .open
            .borrow()
            .node
            .as_ref()
            .unwrap()
            .borrow()
            .record_locks
            .get()
            .unwrap()
            .clone();
        let mut other = requested;
        other.owner = 22;
        assert!(lock_set.conflict(other).is_some());
        std::thread::scope(|scope| {
            scope
                .spawn(|| files.close(fd, 11).unwrap().unwrap())
                .join()
                .unwrap();
        });
        assert_eq!(lock_set.conflict(other), None);
        assert_eq!(v.flock(contender, 6), Err(Errno(11)));
        std::thread::spawn(move || files.close(alias, 11).unwrap().unwrap())
            .join()
            .unwrap();
        assert_eq!(v.read(notify, 4096), Err(Errno(11)));
        assert_eq!(v.flock(contender, 6), Err(Errno(11)));
        std::thread::spawn(move || drop(accepted)).join().unwrap();
        v.flock(contender, 6).unwrap();
        let event = v.read(notify, 4096).unwrap();
        assert_eq!(event.len(), 16);
        assert_eq!(u32::from_le_bytes(event[4..8].try_into().unwrap()), 8);
        assert_eq!(v.read(notify, 4096), Err(Errno(11)));
        assert_eq!(v.fd_kind(fd), Err(Errno(9)));
        assert_eq!(v.fd_kind(alias), Err(Errno(9)));
    }
}
