// SPDX-License-Identifier: GPL-3.0-or-later
//! Memory-only ramfs and the runtime's registered debugfs devices.
use super::*;
use crate::pseudo::Device;

pub(super) fn ramfs(credentials: &Credentials, data: &[u8], readonly: bool) -> Result<FsHandle> {
    let (mode, _, _) = options(data, 0o755, false)?;
    let mut fs = ram_filesystem(
        u64::MAX,
        usize::MAX,
        mode,
        credentials.fsuid,
        credentials.fsgid,
        false,
    )?;
    fs.owner = credentials.user_namespace.clone();
    fs.super_readonly = Some(Arc::new(std::sync::atomic::AtomicBool::new(readonly)));
    Ok(fs)
}

// Both Linux filesystems ignore unknown mount parameters. Recognized parameters
// still require their real numeric format; debugfs alone accepts UID/GID.
pub(super) fn options(
    data: &[u8],
    default: u32,
    debug: bool,
) -> Result<(u32, Option<u32>, Option<u32>)> {
    let (mut mode, mut uid, mut gid) = (default, None, None);
    for item in data.split(|b| *b == b',').filter(|item| !item.is_empty()) {
        let (key, value) = item
            .iter()
            .position(|b| *b == b'=')
            .map_or((item, &[][..]), |at| (&item[..at], &item[at + 1..]));
        if key == b"mode" || debug && matches!(key, b"uid" | b"gid") {
            let value = std::str::from_utf8(value).map_err(|_| Errno(22))?;
            let value = u32::from_str_radix(value, if key == b"mode" { 8 } else { 10 })
                .map_err(|_| Errno(22))?;
            match key {
                b"mode" => mode = value & 0o7777,
                b"uid" if value != u32::MAX => uid = Some(value),
                b"gid" if value != u32::MAX => gid = Some(value),
                _ => return Err(Errno(22)),
            }
        }
    }
    Ok((mode, uid, gid))
}

impl Vfs {
    pub(super) fn debug_filesystem(&self, data: &[u8]) -> Result<FsHandle> {
        if !self.credentials.has_cap(capabilities::SYS_ADMIN) {
            return Err(Errno(1));
        }
        let (mode, uid, gid) = options(data, 0o700, true)?;
        let resource = self.pseudo.borrow().debug_fs.clone();
        let mut shared = resource.lock().unwrap();
        if shared.is_none() {
            let fs = ram_filesystem(
                0,
                usize::MAX,
                mode,
                uid.unwrap_or(0),
                gid.unwrap_or(0),
                false,
            )?;
            {
                let mut files = fs.borrow_mut();
                let root = files.paths[b"/".as_slice()].clone();
                let device = root.borrow().device;
                let mut node = |content, mode| {
                    let inode = files.next_inode;
                    files.next_inode = inode.checked_add(1).ok_or(Errno(28))?;
                    Ok::<_, Errno>(Arc::new(Inode::new(Node {
                        identity: 0,
                        record_locks: Default::default(),
                        whole_locks: Default::default(),
                        notifications: Default::default(),
                        path_hint: Default::default(),
                        inode,
                        device,
                        mode,
                        uid: 0,
                        gid: 0,
                        content,
                        volatile: false,
                        links: 1,
                        times: [storage::Timestamp::now(); 3],
                        xattrs: Default::default(),
                        seals: None,
                    })))
                };
                let sync = node(Content::Directory, 0o40555)?;
                let sw = node(Content::Device(Device::SwSync), 0o20666)?;
                inotify::link(&sync, &root, b"sync");
                inotify::link(&sw, &sync, b"sw_sync");
                files
                    .inodes
                    .extend([Arc::downgrade(&sync), Arc::downgrade(&sw)]);
                files.paths.insert(b"/sync".to_vec(), sync);
                files.paths.insert(b"/sync/sw_sync".to_vec(), sw);
            }
            *shared = Some(fs);
        }
        let fs = shared.as_ref().unwrap().clone();
        let root = fs.borrow().paths[b"/".as_slice()].clone();
        let mut root = root.borrow_mut();
        root.mode = 0o40000 | mode;
        if let Some(uid) = uid {
            root.uid = uid;
        }
        if let Some(gid) = gid {
            root.gid = gid;
        }
        Ok(fs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ramfs_is_private_memory_without_tmpfs_size_limits_and_retains_unlinked_files() {
        let mut vfs = Vfs::default();
        vfs.mkdir_at(AT_FDCWD, b"/ram", 0o755).unwrap();
        vfs.mount(
            None,
            b"/ram",
            Some(b"ramfs"),
            0,
            Some(b"mode=0700,size=1,unknown"),
        )
        .unwrap();
        assert_eq!(
            u64::from_le_bytes(vfs.statfs_at(b"/ram").unwrap()[..8].try_into().unwrap()),
            0x858458f6
        );
        let file = vfs.open_at(AT_FDCWD, b"/ram/file", 0x42, 0o600).unwrap();
        assert_eq!(vfs.write(file, &vec![7; 8192]), Ok(8192));
        vfs.unlink_at(AT_FDCWD, b"/ram/file", false).unwrap();
        vfs.umount(b"/ram", 2).unwrap();
        vfs.seek(file, 0, 0).unwrap();
        assert_eq!(vfs.read(file, 8192).unwrap(), vec![7; 8192]);
        assert_eq!(vfs.open_at(AT_FDCWD, b"/ram/file", 0, 0), Err(Errno(2)));
    }

    #[test]
    fn debugfs_mounts_share_registered_devices_without_creating_unknown_features() {
        let mut vfs = Vfs::default();
        for path in [b"/debug".as_slice(), b"/alias"] {
            vfs.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
        }
        vfs.mount(
            None,
            b"/debug",
            Some(b"debugfs"),
            MS_NOSUID | MS_NOEXEC,
            None,
        )
        .unwrap();
        vfs.mount(None, b"/alias", Some(b"debugfs"), 0, None)
            .unwrap();
        assert_eq!(
            u64::from_le_bytes(vfs.statfs_at(b"/debug").unwrap()[..8].try_into().unwrap()),
            0x64626720
        );
        let file = vfs.open_at(AT_FDCWD, b"/debug/sync/sw_sync", 2, 0).unwrap();
        assert!(vfs.sync_file(file).unwrap().is_some());
        assert_eq!(
            vfs.stat_at(AT_FDCWD, b"/debug/sync/sw_sync").unwrap()[8..16],
            vfs.stat_at(AT_FDCWD, b"/alias/sync/sw_sync").unwrap()[8..16]
        );
        assert_eq!(vfs.open_at(AT_FDCWD, b"/debug/kcov", 0, 0), Err(Errno(2)));
        assert_eq!(
            vfs.open_at(AT_FDCWD, b"/debug/new", 0x42, 0o600),
            Err(Errno(1))
        );
        vfs.mount(None, b"/debug", None, 32, Some(b"mode=0750,uid=10"))
            .unwrap();
        assert_eq!(
            u32::from_le_bytes(
                vfs.stat_at(AT_FDCWD, b"/alias").unwrap()[16..20]
                    .try_into()
                    .unwrap()
            ) & 0o7777,
            0o750
        );
        vfs.unshare_user().unwrap();
        assert!(matches!(vfs.debug_filesystem(b""), Err(Errno(1))));
    }

    #[test]
    fn detached_ramfs_and_debugfs_use_the_same_filesystem_construction() {
        use fd::MountFdCall;
        for (kind, magic) in [
            (b"ramfs".as_slice(), 0x858458f6u64),
            (b"debugfs", 0x64626720),
        ] {
            let mut vfs = Vfs::default();
            let ctx = MountFdCall::Open {
                kind: kind.to_vec(),
                flags: 1,
            }
            .run(&mut vfs)
            .unwrap() as u32;
            MountFdCall::Config {
                fd: ctx,
                cmd: 1,
                key: Some(b"mode".to_vec()),
                value: Some(b"0750".to_vec()),
            }
            .run(&mut vfs)
            .unwrap();
            MountFdCall::Config {
                fd: ctx,
                cmd: 6,
                key: None,
                value: None,
            }
            .run(&mut vfs)
            .unwrap();
            let tree = MountFdCall::Mount {
                fd: ctx,
                flags: 0,
                attrs: 0,
            }
            .run(&mut vfs)
            .unwrap() as u32;
            assert_eq!(
                u64::from_le_bytes(vfs.statfs_fd(tree).unwrap()[..8].try_into().unwrap()),
                magic
            );
            assert_eq!(
                u32::from_le_bytes(vfs.stat_fd(tree).unwrap()[16..20].try_into().unwrap()) & 0o7777,
                0o750
            );
        }
    }
}
