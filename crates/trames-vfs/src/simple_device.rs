// SPDX-License-Identifier: GPL-3.0-or-later
//! Stateless memory-device behavior, on the original inode/OFD and mount.
use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Null,
    Zero,
    Full,
    Random,
    Urandom,
}
impl Kind {
    pub fn content(content: &Content) -> Option<Self> {
        use pseudo::Device;
        Some(match content {
            Content::Null => Self::Null,
            Content::Device(Device::Zero) => Self::Zero,
            Content::Device(Device::Full) => Self::Full,
            Content::Device(Device::Random) => Self::Random,
            Content::Device(Device::Urandom) => Self::Urandom,
            _ => return None,
        })
    }
    fn device(self) -> Option<pseudo::Device> {
        use pseudo::Device;
        Some(match self {
            Self::Null => return None,
            Self::Zero => Device::Zero,
            Self::Full => Device::Full,
            Self::Random => Device::Random,
            Self::Urandom => Device::Urandom,
        })
    }
    fn read(self, count: usize) -> Result<Vec<u8>> {
        self.device()
            .map_or_else(|| Ok(Vec::new()), |device| device.read(count))
    }
    fn write(self, bytes: &[u8]) -> Result<usize> {
        let bytes = &bytes[..bytes.len().min(storage::MAX_TRANSFER)];
        self.device()
            .map_or_else(|| Ok(bytes.len()), |device| device.write(bytes))
    }
}
pub(super) fn builtin(path: &[u8]) -> Option<(Content, u32)> {
    use pseudo::Device;
    Some((
        Content::Device(match path {
            b"/dev/zero" => Device::Zero,
            b"/dev/full" => Device::Full,
            b"/dev/random" => Device::Random,
            b"/dev/urandom" => Device::Urandom,
            _ => return None,
        }),
        0o20666,
    ))
}
impl SharedOpenDescription {
    pub(super) fn simple_read(&self, kind: Kind, count: usize) -> Result<Vec<u8>> {
        let flags = self.flags.get();
        if flags & O_PATH != 0 || flags & 3 == 1 {
            return Err(Errno(9));
        }
        let result = kind.read(count);
        let node = self.node.as_ref().expect("memory-device inode");
        if count != 0 && result.is_ok() && flags & O_NOATIME == 0 {
            mounts::accessed(
                &mut node.borrow_mut(),
                self.mount_resource.get().map(AsRef::as_ref),
            );
        }
        if result.as_ref().is_ok_and(|bytes| !bytes.is_empty()) {
            inotify::notify(
                node,
                inotify::ACCESS,
                self.notification.as_ref().and_then(|c| c.link.as_ref()),
            );
        }
        result
    }
    pub(super) fn simple_write<const POSITIONED: bool>(
        &self,
        kind: Kind,
        bytes: &[u8],
    ) -> Result<usize> {
        let access = || {
            let flags = self.flags.get();
            if flags & O_PATH != 0 || flags & 3 == 0 {
                Err(Errno(9))
            } else {
                Ok(())
            }
        };
        if !POSITIONED {
            access()?;
        }
        if let Some(mount) = self.mount_resource.get() {
            mount.writable()?;
        }
        if POSITIONED {
            access()?;
        }
        let result = kind.write(bytes);
        if result.is_ok_and(|n| n != 0) {
            let node = self.node.as_ref().expect("memory-device inode");
            {
                let mut n = node.borrow_mut();
                n.times[1] = storage::Timestamp::now();
                n.times[2] = n.times[1];
            }
            inotify::notify(
                node,
                inotify::MODIFY,
                self.notification.as_ref().and_then(|c| c.link.as_ref()),
            );
        }
        if result.is_ok() && self.flags.get() & 0x1000 != 0 {
            return Err(Errno(22));
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setup() -> Vfs {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        v
    }
    fn prepare(v: &Vfs) -> (PathQueries, DirectFiles) {
        let mut epoch = FileEpoch::default();
        (v.path_queries(), epoch.capture(v, true))
    }
    fn open(query: &(PathQueries, DirectFiles), path: &[u8], flags: u32) -> Result<u32> {
        query
            .0
            .open_at_resolve(AT_FDCWD, path, flags, 0, 0, &query.1)
            .expect("admitted device open")
    }
    #[test]
    fn original_device_inodes_and_native_worker_bytes_share_one_behavior() {
        let mut v = setup();
        let query = prepare(&v);
        for (path, kind) in [
            (b"/dev/null".as_slice(), Kind::Null),
            (b"/dev/zero", Kind::Zero),
            (b"/dev/full", Kind::Full),
            (b"/dev/random", Kind::Random),
            (b"/dev/urandom", Kind::Urandom),
        ] {
            let fd = open(&query, path, 2 | O_CLOEXEC).unwrap();
            let shared = v.shared_files().lookup(fd).unwrap().unwrap();
            assert_eq!(shared.open.node.as_ref().unwrap().simple_device, Some(kind));
            let cap = shared.direct_byte().unwrap();
            assert!(cap.is_simple_device());
            assert_eq!(query.0.stat_fd(fd), Some(v.stat_fd(fd)));
            assert_ne!(v.flags(fd).unwrap() & O_CLOEXEC, 0);
            let bytes = cap.read(64).unwrap();
            assert_eq!(bytes.len(), if kind == Kind::Null { 0 } else { 64 });
            if matches!(kind, Kind::Zero | Kind::Full) {
                assert_eq!(bytes, vec![0; 64]);
            }
            assert_eq!(
                cap.write(b"bytes"),
                if kind == Kind::Full {
                    Err(Errno(28))
                } else {
                    Ok(5)
                }
            );
            assert_eq!(
                v.write(fd, b"bytes"),
                if kind == Kind::Full {
                    Err(Errno(28))
                } else {
                    Ok(5)
                }
            );
            assert_eq!(cap.device_pread(64, u64::MAX), Err(Errno(22)));
            assert_eq!(cap.device_pwrite(b"x", u64::MAX), Err(Errno(22)));
            assert_eq!(cap.byte_seek(-123, 999), v.seek(fd, -123, 999));
            assert_eq!(v.read(fd, 0), Ok(Vec::new()));
            assert_eq!(cap.device_pread(0, 0), Ok(Vec::new()));
            let alias = v.dup(fd, 64, false).unwrap();
            v.close(fd).unwrap();
            assert_eq!(cap.read(0), Ok(Vec::new()));
            v.close(alias).unwrap();
        }
        for path in [
            b"/proc/self/status".as_slice(),
            b"/dev/kmsg",
            b"/dev/tty",
            b"/dev/ptmx",
            b"/dev/dri/renderD128",
        ] {
            assert!(
                query
                    .0
                    .open_at_resolve(AT_FDCWD, path, 0, 0, 0, &query.1)
                    .is_none(),
                "{path:?}"
            );
        }
    }
    #[test]
    fn cold_concurrent_device_open_uses_one_original_cache_inode_with_distinct_ofds() {
        let v = setup();
        let mut jobs = Vec::new();
        for _ in 0..8 {
            let query = prepare(&v);
            jobs.push(std::thread::spawn(move || {
                open(&query, b"/dev/zero", 2).unwrap()
            }));
        }
        let fds: Vec<_> = jobs.into_iter().map(|j| j.join().unwrap()).collect();
        let first = v
            .descriptor(fds[0])
            .unwrap()
            .open
            .borrow()
            .node
            .clone()
            .unwrap();
        let mut ids = std::collections::BTreeSet::new();
        for fd in fds {
            let d = v.descriptor(fd).unwrap();
            let o = d.open.borrow();
            assert!(Arc::ptr_eq(o.node.as_ref().unwrap(), &first));
            assert!(ids.insert(o.id));
        }
        assert!(Arc::ptr_eq(&first, &v.node(b"/dev/zero").unwrap()));
    }
    #[test]
    fn renamed_mknod_and_live_original_mount_policy_are_not_pathname_shortcuts() {
        let mut v = setup();
        v.mkdir_at(AT_FDCWD, b"/devices", 0o755).unwrap();
        v.mount(None, b"/devices", Some(b"tmpfs"), 0, None).unwrap();
        v.mknod_at(AT_FDCWD, b"/devices/name", 0o20666, 0x105)
            .unwrap();
        let q = prepare(&v);
        let fd = open(&q, b"/devices/name", 2).unwrap();
        let cap = v.direct_descriptors().get(fd).unwrap();
        assert_eq!(cap.read(3).unwrap(), [0; 3]);
        v.rename_at(AT_FDCWD, b"/devices/name", AT_FDCWD, b"/devices/other", 0)
            .unwrap();
        assert_eq!(cap.read(3).unwrap(), [0; 3]);
        let other = open(&q, b"/devices/other", 2).unwrap();
        assert_eq!(q.0.stat_fd(fd), q.0.stat_fd(other));
        let ro = open(&q, b"/devices/other", 0).unwrap();
        let readonly = v.direct_descriptors().get(ro).unwrap();
        v.mount(None, b"/devices", None, 32 | mounts::MS_RDONLY, None)
            .unwrap();
        assert_eq!(cap.write(b"x"), Err(Errno(30)));
        assert_eq!(readonly.write(b"x"), Err(Errno(9)));
        assert_eq!(readonly.device_pwrite(b"x", 0), Err(Errno(30)));
        assert_eq!(v.pwrite(ro, b"x", 0), Err(Errno(30)));
        assert_eq!(open(&q, b"/devices/other", 2), Err(Errno(30)));
        v.mount(None, b"/devices", None, 32 | mounts::MS_NODEV, None)
            .unwrap();
        assert_eq!(open(&q, b"/devices/other", 0), Err(Errno(13)));
        assert!(open(&q, b"/devices/other", O_PATH).is_ok());
        assert_eq!(cap.read(3).unwrap(), [0; 3]);
        v.mount(None, b"/devices", None, 32, None).unwrap();
        v.unshare_mounts().unwrap();
        v.mount(None, b"/devices", None, 32 | mounts::MS_RDONLY, None)
            .unwrap();
        assert_eq!(cap.write(b"original mount"), Ok(14));
    }
    #[test]
    fn actual_inode_notifications_and_last_worker_close_survive_alias_and_fd_reuse() {
        let mut v = setup();
        let watch = v.inotify_init(O_NONBLOCK).unwrap();
        v.inotify_add(watch, b"/dev/zero", 1 | 2 | 8 | 16 | 32)
            .unwrap();
        let query = prepare(&v);
        let fd = open(&query, b"/dev/zero", 2).unwrap();
        let cap = v.direct_descriptors().get(fd).unwrap();
        assert_eq!(cap.read(4).unwrap(), [0; 4]);
        assert_eq!(cap.write(b"x"), Ok(1));
        let inode = Arc::downgrade(
            v.descriptor(fd)
                .unwrap()
                .open
                .borrow()
                .node
                .as_ref()
                .unwrap(),
        );
        let alias = v.dup(fd, 64, false).unwrap();
        v.close(fd).unwrap();
        assert_eq!(v.eventfd(17, 0).unwrap(), fd);
        v.close(alias).unwrap();
        let first = v.read(watch, 4096).unwrap();
        let masks: Vec<_> = first
            .chunks_exact(16)
            .map(|e| u32::from_le_bytes(e[4..8].try_into().unwrap()))
            .collect();
        assert!(masks.contains(&32));
        assert!(masks.contains(&1));
        assert!(masks.contains(&2));
        assert!(!masks.iter().any(|m| m & (8 | 16) != 0));
        std::thread::spawn(move || {
            assert_eq!(cap.read(4).unwrap(), [0; 4]);
            drop(cap);
        })
        .join()
        .unwrap();
        let last = v.read(watch, 4096).unwrap();
        let masks: Vec<_> = last
            .chunks_exact(16)
            .map(|e| u32::from_le_bytes(e[4..8].try_into().unwrap()))
            .collect();
        assert_eq!(masks.iter().filter(|m| **m & 8 != 0).count(), 1);
        assert!(
            inode.upgrade().is_some(),
            "provider still owns inode, not OFD"
        );
        assert_eq!(v.read(fd, 8).unwrap(), 17u64.to_le_bytes());
    }
    #[test]
    fn access_and_synchronous_error_order_matches_original_device_operations() {
        let mut v = setup();
        let q = prepare(&v);
        for (flags, read, write) in [
            (0, Ok(Vec::new()), Err(Errno(9))),
            (1, Err(Errno(9)), Ok(1)),
            (O_PATH, Err(Errno(9)), Err(Errno(9))),
            (2 | 0x1000, Ok(Vec::new()), Err(Errno(22))),
        ] {
            let fd = open(&q, b"/dev/null", flags).unwrap();
            let cap = v.direct_descriptors().get(fd).unwrap();
            assert_eq!(cap.read(4), read);
            assert_eq!(v.read(fd, 4), read);
            assert_eq!(cap.write(b"x"), write);
            assert_eq!(v.write(fd, b"x"), write);
            assert_eq!(cap.device_pwrite(b"x", 0), write);
            assert_eq!(v.pwrite(fd, b"x", 0), write);
            assert_eq!(cap.device_pread(4, 0), read);
            assert_eq!(v.pread(fd, 4, 0), read);
        }
    }
}
