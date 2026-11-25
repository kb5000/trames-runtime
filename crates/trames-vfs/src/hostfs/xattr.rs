// SPDX-License-Identifier: GPL-3.0-or-later
//! Native attributes retain the accepted inode, never a guest pathname.
use super::*;

pub(crate) struct XattrTarget {
    node: NodeRef,
    file: Arc<OpenFile>,
    link: Option<Arc<inotify::Link>>,
    _writer: Option<mapped::MountWrite>,
    _usage: Option<mounts::MountUse>,
}
impl XattrTarget {
    pub(crate) fn new(
        node: NodeRef,
        file: Arc<OpenFile>,
        mount: Option<&mounts::MountData>,
        link: Option<Arc<inotify::Link>>,
        write: bool,
    ) -> Result<Self> {
        let writer = if write {
            file.root.writable()?;
            mount
                .map(|m| mapped::MountWrite::new(&m.identity))
                .transpose()?
        } else {
            None
        };
        Ok(Self {
            node,
            file,
            link,
            _writer: writer,
            _usage: mount.map(|m| mounts::MountUse::new(m.identity.clone())),
        })
    }
    fn allowed(&self, v: &Vfs, name: &[u8], write: bool) -> Result<()> {
        self.file.refresh_permissions(&self.node)?;
        let node = self.node.borrow();
        if name.starts_with(b"user.")
            || name.starts_with(b"trusted.")
            || acl::name(name)
            || name == file_caps::NAME
        {
            v.xattr_allowed(&node, name, write)?;
        } else if !name.starts_with(b"security.")
            && !name.starts_with(b"system.")
            && !v.allowed(&node, if write { 2 } else { 4 })
        {
            return Err(Errno(13));
        }
        // Native capability grants never inherit guest SETFCAP authority.
        // Darwin's ACE ACL is not a Linux POSIX ACL; retain that format gate.
        if name == file_caps::NAME {
            return Err(Errno(95));
        }
        #[cfg(not(target_os = "linux"))]
        if acl::name(name) {
            return Err(Errno(95));
        }
        Ok(())
    }
    pub(crate) fn read(&self, v: &Vfs, name: Option<&[u8]>, capacity: u64) -> Result<FileValue> {
        if let Some(name) = name {
            self.allowed(v, name, false)?;
            #[cfg(target_os = "linux")]
            if acl::name(name) {
                return super::posix_acl::read(&self.file, v, name, capacity);
            }
        }
        let native = Native::new(&self.file)?;
        let name = name.map(CString::new).transpose().map_err(|_| Errno(22))?;
        let capacity = capacity.min(65536) as usize;
        let filter = name.is_none() && !v.credentials.has_cap(capabilities::SYS_ADMIN);
        if capacity == 0 && !filter {
            return native
                .read(name.as_ref(), &mut [])
                .map(|n| FileValue::Count(n.min(65536) as u64));
        }
        let limit = if filter { 65536 } else { capacity };
        let mut bytes = vec![0; limit];
        let count = match native.read(name.as_ref(), &mut bytes) {
            Err(Errno(34)) if limit == 65536 => return Err(Errno(7)),
            other => other?,
        };
        if count > bytes.len() {
            return Err(Errno(5));
        }
        bytes.truncate(count);
        if name.is_none() {
            let mut offset = 0;
            let mut kept = 0;
            while offset < bytes.len() {
                let end = offset
                    + bytes[offset..]
                        .iter()
                        .position(|&b| b == 0)
                        .ok_or(Errno(5))?;
                if end == offset {
                    return Err(Errno(5));
                }
                if !filter || !bytes[offset..end].starts_with(b"trusted.") {
                    bytes.copy_within(offset..end + 1, kept);
                    kept += end + 1 - offset;
                }
                offset = end + 1;
            }
            bytes.truncate(kept);
        }
        if capacity == 0 {
            return Ok(FileValue::Count(bytes.len() as u64));
        }
        if bytes.len() > capacity {
            return Err(Errno(34));
        }
        Ok(FileValue::Bytes(bytes))
    }
    pub(crate) fn write(
        &self,
        v: &Vfs,
        name: &[u8],
        value: Option<&[u8]>,
        flags: u32,
    ) -> Result<()> {
        let _metadata = acl::name(name).then(|| self.node.metadata.lock().unwrap());
        self.allowed(v, name, true)?;
        #[cfg(target_os = "linux")]
        if acl::name(name) {
            super::posix_acl::write(&self.file, &self.node, v, name, value)?;
            self.node.borrow_mut().times[2] = storage::Timestamp::now();
            inotify::notify(&self.node, inotify::ATTRIB, self.link.as_ref());
            return Ok(());
        }
        let native = Native::new(&self.file)?;
        let name = CString::new(name).map_err(|_| Errno(22))?;
        // CREATE|REPLACE cannot succeed. Darwin rejects the combined bits;
        // Linux gives the existing/missing result. No read-modify-write lock.
        if value.is_some() && flags == 3 {
            return match native.read(Some(&name), &mut []) {
                Ok(_) => Err(Errno(17)),
                Err(error) => Err(error),
            };
        }
        native.write(&name, value, flags)?;
        self.node.borrow_mut().times[2] = storage::Timestamp::now();
        inotify::notify(&self.node, inotify::ATTRIB, self.link.as_ref());
        Ok(())
    }
}

fn xattr_error() -> Errno {
    let error = std::io::Error::last_os_error();
    let code = match error.raw_os_error() {
        #[cfg(target_vendor = "apple")]
        Some(libc::ENOATTR) => 61,
        #[cfg(not(target_vendor = "apple"))]
        Some(libc::ENODATA) => 61,
        Some(libc::ERANGE) => 34,
        Some(libc::E2BIG) => 7,
        Some(libc::EPERM) => 1,
        _ => return errno(error),
    };
    Errno(code)
}
pub(super) struct Native<'a> {
    file: &'a File,
    #[cfg(not(target_vendor = "apple"))]
    path: Option<CString>,
}
impl<'a> Native<'a> {
    pub(super) fn new(file: &'a OpenFile) -> Result<Self> {
        Self::from_file(&file.file)
    }
    pub(super) fn from_file(file: &'a File) -> Result<Self> {
        #[cfg(not(target_vendor = "apple"))]
        let path = {
            // O_PATH metadata descriptors are not accepted by f*xattr. A proc
            // magic link jumps to the retained inode, including a symlink: the
            // pure jump ends path walking instead of following its link text.
            // The live OpenFile prevents native descriptor reuse throughout.
            metadata_path(file)?
        };
        Ok(Self {
            file,
            #[cfg(not(target_vendor = "apple"))]
            path,
        })
    }
    pub(super) fn read(&self, name: Option<&CString>, bytes: &mut [u8]) -> Result<usize> {
        let fd = self.file.as_raw_fd();
        let data = if bytes.is_empty() {
            std::ptr::null_mut()
        } else {
            bytes.as_mut_ptr()
        };
        // SAFETY: retained native descriptor (or internally constructed proc
        // capability), optional NUL-terminated name and live bounded output.
        #[cfg(target_vendor = "apple")]
        let count = unsafe {
            match name {
                Some(name) => libc::fgetxattr(fd, name.as_ptr(), data.cast(), bytes.len(), 0, 0),
                None => libc::flistxattr(fd, data.cast(), bytes.len(), 0),
            }
        };
        #[cfg(not(target_vendor = "apple"))]
        let count = unsafe {
            match (&self.path, name) {
                (Some(path), Some(name)) => {
                    libc::getxattr(path.as_ptr(), name.as_ptr(), data.cast(), bytes.len())
                }
                (Some(path), None) => libc::listxattr(path.as_ptr(), data.cast(), bytes.len()),
                (None, Some(name)) => libc::fgetxattr(fd, name.as_ptr(), data.cast(), bytes.len()),
                (None, None) => libc::flistxattr(fd, data.cast(), bytes.len()),
            }
        };
        if count < 0 {
            Err(xattr_error())
        } else {
            Ok(count as usize)
        }
    }
    pub(super) fn write(&self, name: &CString, value: Option<&[u8]>, flags: u32) -> Result<()> {
        let fd = self.file.as_raw_fd();
        #[cfg(target_vendor = "apple")]
        let flags = if flags & 1 != 0 {
            libc::XATTR_CREATE
        } else if flags & 2 != 0 {
            libc::XATTR_REPLACE
        } else {
            0
        };
        #[cfg(not(target_vendor = "apple"))]
        let flags = flags as libc::c_int;
        // SAFETY: retained native inode, valid C name and borrowed value; no
        // native pathname originates from guest text or inode lock spans I/O.
        #[cfg(target_vendor = "apple")]
        let result = unsafe {
            match value {
                Some(value) => libc::fsetxattr(
                    fd,
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                    flags,
                ),
                None => libc::fremovexattr(fd, name.as_ptr(), 0),
            }
        };
        #[cfg(not(target_vendor = "apple"))]
        let result = unsafe {
            match (&self.path, value) {
                (Some(path), Some(value)) => libc::setxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    flags,
                ),
                (Some(path), None) => libc::removexattr(path.as_ptr(), name.as_ptr()),
                (None, Some(value)) => {
                    libc::fsetxattr(fd, name.as_ptr(), value.as_ptr().cast(), value.len(), flags)
                }
                (None, None) => libc::fremovexattr(fd, name.as_ptr()),
            }
        };
        if result < 0 {
            Err(xattr_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::Fixture;
    use super::*;
    fn set(v: &mut Vfs, value: Option<&[u8]>, flags: u32) -> Result<()> {
        v.set_xattr(
            AT_FDCWD,
            Some(b"/host/file"),
            true,
            b"user.native",
            value,
            flags,
        )
    }
    #[test]
    fn native_xattr_values_flags_queries_and_empty_values_do_not_enter_private_storage() {
        let root = Fixture::new();
        std::fs::write(root.0.join("file"), b"data").unwrap();
        let mut v = root.vfs(false);
        assert_eq!(set(&mut v, Some(&[0, 255]), 1), Ok(()));
        let fd = v.open_at(AT_FDCWD, b"/host/file", 0, 0).unwrap();
        let file = v
            .descriptor(fd)
            .unwrap()
            .open
            .borrow()
            .host_file
            .clone()
            .unwrap();
        let mut bytes = [0; 8];
        assert_eq!(
            Native::new(&file)
                .unwrap()
                .read(Some(&CString::new("user.native").unwrap()), &mut bytes)
                .unwrap(),
            2
        );
        assert_eq!(&bytes[..2], &[0, 255]);
        assert!(v
            .node(&v.resolve_final(AT_FDCWD, b"/host/file", true).unwrap())
            .unwrap()
            .borrow()
            .xattrs
            .is_empty());
        assert!(matches!(
            v.read_xattrs(fd as i32, None, true, Some(b"user.native"), 0),
            Ok(FileValue::Count(2))
        ));
        assert!(matches!(
            v.read_xattrs(fd as i32, None, true, Some(b"user.native"), 1),
            Err(Errno(34))
        ));
        assert_eq!(set(&mut v, Some(b"new"), 1), Err(Errno(17)));
        assert_eq!(set(&mut v, Some(b"new"), 3), Err(Errno(17)));
        assert_eq!(set(&mut v, Some(b""), 2), Ok(()));
        assert_eq!(
            v.get_xattr(fd as i32, None, true, b"user.native"),
            Ok(vec![])
        );
        let listed = v.list_xattrs(fd as i32, None, true).unwrap();
        assert!(listed.split(|&b| b == 0).any(|n| n == b"user.native"));
        assert_eq!(set(&mut v, None, 0), Ok(()));
        assert_eq!(set(&mut v, Some(b"new"), 2), Err(Errno(61)));
        assert_eq!(set(&mut v, Some(b"new"), 3), Err(Errno(61)));
        assert_eq!(
            v.get_xattr(fd as i32, None, true, b"user.native"),
            Err(Errno(61))
        );
        assert_eq!(set(&mut v, None, 0), Err(Errno(61)));
        let opath = v.open_at(AT_FDCWD, b"/host/file", O_PATH, 0).unwrap();
        assert_eq!(
            v.get_xattr(opath as i32, None, true, b"user.native"),
            Err(Errno(9))
        );
    }
    #[test]
    fn readonly_guest_permissions_symlink_policy_and_host_namespace_boundaries_apply() {
        use std::os::unix::fs::PermissionsExt;
        let root = Fixture::new();
        std::fs::write(root.0.join("file"), b"data").unwrap();
        std::fs::set_permissions(root.0.join("file"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        std::os::unix::fs::symlink("file", root.0.join("link")).unwrap();
        let mut v = root.vfs(false);
        set(&mut v, Some(b"original"), 0).unwrap();
        let mut ro = root.vfs(true);
        assert_eq!(set(&mut ro, Some(b"changed"), 0), Err(Errno(30)));
        assert_eq!(
            ro.get_xattr(AT_FDCWD, Some(b"/host/file"), true, b"user.native"),
            Ok(b"original".to_vec())
        );
        assert_eq!(
            v.get_xattr(AT_FDCWD, Some(b"/host/link"), false, b"user.native"),
            Err(Errno(61))
        );
        assert_eq!(
            v.set_xattr(
                AT_FDCWD,
                Some(b"/host/link"),
                false,
                b"user.native",
                Some(b"x"),
                0
            ),
            Err(Errno(1))
        );
        assert_eq!(
            v.get_xattr(AT_FDCWD, Some(b"/host/file"), true, acl::ACCESS),
            Err(Errno(if cfg!(target_os = "linux") { 61 } else { 95 }))
        );
        v.credentials = Credentials::user(1000, 1000);
        assert_eq!(
            v.get_xattr(AT_FDCWD, Some(b"/host/file"), true, b"user.native"),
            Err(Errno(13))
        );
        assert_eq!(set(&mut v, Some(b"changed"), 0), Err(Errno(13)));
        assert_eq!(
            v.get_xattr(AT_FDCWD, Some(b"/host/file"), true, b"trusted.secret"),
            Err(Errno(61))
        );
        assert_eq!(
            v.set_xattr(
                AT_FDCWD,
                Some(b"/host/file"),
                true,
                b"trusted.secret",
                Some(b"x"),
                0
            ),
            Err(Errno(1))
        );
    }
    #[test]
    fn accepted_native_inode_and_mount_writer_survive_close_reuse_rename_and_unlink() {
        let root = Fixture::new();
        std::fs::write(root.0.join("file"), b"original").unwrap();
        std::fs::write(root.0.join("replacement"), b"other").unwrap();
        let mut v = root.vfs(false);
        let fd = v.open_at(AT_FDCWD, b"/host/file", 0, 0).unwrap();
        let open = v.descriptor(fd).unwrap().open;
        let target = {
            let original = open.borrow();
            XattrTarget::new(
                original.node.clone().unwrap(),
                original.host_file.clone().unwrap(),
                original.mount.as_deref(),
                None,
                true,
            )
            .unwrap()
        };
        drop(open);
        v.close(fd).unwrap();
        assert_eq!(v.open_at(AT_FDCWD, b"/host/replacement", 0, 0).unwrap(), fd);
        std::fs::rename(root.0.join("file"), root.0.join("old")).unwrap();
        std::fs::write(root.0.join("file"), b"replacement").unwrap();
        assert_eq!(
            v.mount(None, b"/host", None, 32 | 4096 | mounts::MS_RDONLY, None),
            Err(Errno(16))
        );
        target
            .write(&v, b"user.original", Some(b"held"), 0)
            .unwrap();
        assert_eq!(
            v.get_xattr(AT_FDCWD, Some(b"/host/old"), true, b"user.original"),
            Ok(b"held".to_vec())
        );
        assert_eq!(
            v.get_xattr(fd as i32, None, true, b"user.original"),
            Err(Errno(61))
        );
        assert_eq!(
            v.get_xattr(AT_FDCWD, Some(b"/host/file"), true, b"user.original"),
            Err(Errno(61))
        );
        std::fs::remove_file(root.0.join("old")).unwrap();
        target
            .write(&v, b"user.original", Some(b"unlinked"), 2)
            .unwrap();
        assert!(
            matches!(target.read(&v, Some(b"user.original"), 32), Ok(FileValue::Bytes(b)) if b==b"unlinked")
        );
        drop(target);
        v.mount(None, b"/host", None, 32 | 4096 | mounts::MS_RDONLY, None)
            .unwrap();
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn opath_symlink_native_xattrs_address_the_link_and_never_its_text_target() {
        let root = Fixture::new();
        std::fs::write(root.0.join("file"), b"target").unwrap();
        std::os::unix::fs::symlink("file", root.0.join("link")).unwrap();
        let mut v = root.vfs(false);
        set(&mut v, Some(b"target attribute"), 0).unwrap();
        let fd = v
            .open_at(AT_FDCWD, b"/host/link", O_PATH | O_NOFOLLOW, 0)
            .unwrap();
        let file = v
            .descriptor(fd)
            .unwrap()
            .open
            .borrow()
            .host_file
            .clone()
            .unwrap();
        let native = Native::new(&file).unwrap();
        let name = CString::new("user.native").unwrap();
        let mut bytes = [0; 4096];
        assert_eq!(native.read(Some(&name), &mut bytes), Err(Errno(61)));
        let count = native.read(None, &mut bytes).unwrap();
        assert!(!bytes[..count]
            .split(|&b| b == 0)
            .any(|n| n == b"user.native"));
        assert_eq!(native.write(&name, Some(b"wrong target"), 0), Err(Errno(1)));
        assert_eq!(
            v.get_xattr(AT_FDCWD, Some(b"/host/file"), true, b"user.native"),
            Ok(b"target attribute".to_vec())
        );
        assert!(!v
            .list_xattrs(AT_FDCWD, Some(b"/host/link"), false)
            .unwrap()
            .split(|&b| b == 0)
            .any(|n| n == b"user.native"));
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn opath_symlink_xattr_capability_survives_rename_unlink_and_guest_fd_reuse() {
        let root = Fixture::new();
        std::fs::write(root.0.join("file"), b"target").unwrap();
        std::os::unix::fs::symlink("file", root.0.join("link")).unwrap();
        let mut v = root.vfs(false);
        set(&mut v, Some(b"target attribute"), 0).unwrap();
        let fd = v
            .open_at(AT_FDCWD, b"/host/link", O_PATH | O_NOFOLLOW, 0)
            .unwrap();
        let file = v
            .descriptor(fd)
            .unwrap()
            .open
            .borrow()
            .host_file
            .clone()
            .unwrap();
        let inode = file.native_stat().unwrap().st_ino;
        let native = Native::new(&file).unwrap();
        v.close(fd).unwrap();
        assert_eq!(v.open_at(AT_FDCWD, b"/host/file", 0, 0).unwrap(), fd);
        std::fs::rename(root.0.join("link"), root.0.join("old-link")).unwrap();
        std::fs::write(root.0.join("link"), b"replacement inode").unwrap();
        v.set_xattr(
            AT_FDCWD,
            Some(b"/host/link"),
            true,
            b"user.native",
            Some(b"replacement"),
            0,
        )
        .unwrap();
        std::fs::remove_file(root.0.join("old-link")).unwrap();
        let mut bytes = [0; 4096];
        assert_eq!(file.native_stat().unwrap().st_ino, inode);
        assert_eq!(
            native.read(Some(&CString::new("user.native").unwrap()), &mut bytes),
            Err(Errno(61))
        );
        let count = native.read(None, &mut bytes).unwrap();
        assert!(!bytes[..count]
            .split(|&b| b == 0)
            .any(|n| n == b"user.native"));
        assert_eq!(
            v.get_xattr(fd as i32, None, true, b"user.native"),
            Ok(b"target attribute".to_vec())
        );
        assert_eq!(
            v.get_xattr(AT_FDCWD, Some(b"/host/link"), true, b"user.native"),
            Ok(b"replacement".to_vec())
        );
    }
    #[cfg(target_vendor = "apple")]
    #[test]
    fn darwin_names_remain_native_and_trusted_names_are_filtered_for_guest_readers() {
        let root = Fixture::new();
        std::fs::write(root.0.join("file"), b"data").unwrap();
        let mut v = root.vfs(false);
        for name in [b"trusted.secret".as_slice(), b"com.trames.attribute"] {
            v.set_xattr(AT_FDCWD, Some(b"/host/file"), true, name, Some(b"x"), 0)
                .unwrap();
        }
        v.credentials = Credentials::user(1000, 1000);
        let names = v.list_xattrs(AT_FDCWD, Some(b"/host/file"), true).unwrap();
        assert!(!names.split(|&b| b == 0).any(|n| n == b"trusted.secret"));
        assert!(names
            .split(|&b| b == 0)
            .any(|n| n == b"com.trames.attribute"));
        assert!(
            matches!(v.read_xattrs(AT_FDCWD, Some(b"/host/file"), true, None, 0), Ok(FileValue::Count(n)) if n == names.len() as u64)
        );
    }
    #[test]
    fn fd_xattr_permissions_refresh_after_independent_host_mode_changes() {
        use std::os::unix::fs::PermissionsExt;
        let root = Fixture::new();
        std::fs::write(root.0.join("file"), b"data").unwrap();
        std::fs::set_permissions(root.0.join("file"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        let mut v = root.vfs(false);
        set(&mut v, Some(b"original"), 0).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/host/file", 0, 0).unwrap();
        v.credentials = Credentials::user(1000, 1000);
        assert_eq!(
            v.get_xattr(fd as i32, None, true, b"user.native"),
            Ok(b"original".to_vec())
        );
        std::fs::set_permissions(root.0.join("file"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        assert_eq!(
            v.get_xattr(fd as i32, None, true, b"user.native"),
            Err(Errno(13))
        );
        std::fs::set_permissions(root.0.join("file"), std::fs::Permissions::from_mode(0o666))
            .unwrap();
        assert_eq!(
            v.set_xattr(fd as i32, None, true, b"user.native", Some(b"changed"), 2),
            Ok(())
        );
    }
    #[cfg(target_vendor = "apple")]
    #[test]
    fn native_symlink_xattrs_use_the_link_inode_without_following_its_target() {
        let root = Fixture::new();
        std::fs::write(root.0.join("file"), b"target").unwrap();
        std::os::unix::fs::symlink("file", root.0.join("link")).unwrap();
        let mut v = root.vfs(false);
        v.set_xattr(
            AT_FDCWD,
            Some(b"/host/link"),
            false,
            b"security.trames",
            Some(b"link"),
            0,
        )
        .unwrap();
        assert_eq!(
            v.get_xattr(AT_FDCWD, Some(b"/host/link"), false, b"security.trames"),
            Ok(b"link".to_vec())
        );
        assert_eq!(
            v.get_xattr(AT_FDCWD, Some(b"/host/link"), true, b"security.trames"),
            Err(Errno(61))
        );
        assert!(v
            .list_xattrs(AT_FDCWD, Some(b"/host/link"), false)
            .unwrap()
            .split(|&b| b == 0)
            .any(|n| n == b"security.trames"));
        v.set_xattr(
            AT_FDCWD,
            Some(b"/host/link"),
            false,
            b"security.trames",
            None,
            0,
        )
        .unwrap();
        assert_eq!(
            v.get_xattr(AT_FDCWD, Some(b"/host/link"), false, b"security.trames"),
            Err(Errno(61))
        );
    }
}
