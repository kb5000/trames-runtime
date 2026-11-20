// SPDX-License-Identifier: GPL-3.0-or-later
//! Exec resolves an inode capability, never a proc magic-link display string.
use super::*;

/// A file being loaded or retained by a guest executable image. Cloning the
/// image across fork shares the lease. Procfs observers retain only file identity.
pub struct ExecutingFile(Arc<ExecutableFile>);
impl ExecutingFile {
    pub fn file(&self) -> &Arc<ExecutableFile> {
        &self.0
    }
}
pub(super) struct WriteAccess(NodeRef);

impl Inode {
    fn claim_text_access(&self, writer: bool) -> Result<()> {
        use std::sync::atomic::Ordering;
        self.text_users
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |users| {
                if writer && users >= 0 {
                    users.checked_add(1)
                } else if !writer && users <= 0 {
                    users.checked_sub(1)
                } else {
                    None
                }
            })
            .map(|_| ())
            .map_err(|_| Errno(26))
    }
}
impl WriteAccess {
    pub(super) fn acquire(node: &NodeRef) -> Result<Self> {
        node.claim_text_access(true)?;
        Ok(Self(node.clone()))
    }
}
impl Drop for WriteAccess {
    fn drop(&mut self) {
        self.0
            .text_users
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}
impl Drop for ExecutingFile {
    fn drop(&mut self) {
        self.0
            .node
            .text_users
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

pub struct ExecutableFile {
    notification: Arc<FileClose>,
    _mount_use: Option<mounts::MountUse>,
    #[cfg(all(feature = "hostfs", unix))]
    _host_file: Option<Arc<hostfs::OpenFile>>,
    pub(super) node: NodeRef,
    pub(super) label: Vec<u8>,
    pub(super) mount: Option<Arc<mounts::MountData>>,
}

impl Vfs {
    pub fn executable_file_at(
        &self,
        dirfd: i32,
        path: &[u8],
        flags: u32,
    ) -> Result<Arc<ExecutableFile>> {
        Ok(self
            .executable_file_inner(dirfd, path, flags, true)?
            .expect("native executable opening enabled"))
    }
    /// Private-store namespace metadata is resident even when file bytes are
    /// on disk. Resolve its inode/errno here without queueing a disk operation.
    /// Host/overlay lookup and foreign native executable handles stay deferred.
    pub fn executable_file_from_resident_namespace(
        &self,
        dirfd: i32,
        path: &[u8],
        flags: u32,
    ) -> Result<Option<Arc<ExecutableFile>>> {
        let external = |fs: &FsHandle| {
            #[cfg(all(feature = "hostfs", unix))]
            if fs.host.is_some() {
                return true;
            }
            fs.has_overlay()
        };
        if external(&self.fs)
            || self
                .mount_resources
                .borrow()
                .iter()
                .filter_map(std::sync::Weak::upgrade)
                .any(|mount| external(&mount.fs))
        {
            return Ok(None);
        }
        self.executable_file_inner(dirfd, path, flags, false)
    }
    fn executable_file_inner(
        &self,
        dirfd: i32,
        path: &[u8],
        flags: u32,
        _open_host: bool,
    ) -> Result<Option<Arc<ExecutableFile>>> {
        if path.is_empty() && flags & 0x1000 == 0 {
            return Err(Errno(2));
        }
        if flags & !0x1100 != 0 {
            return Err(Errno(22));
        }
        let mut path_link = None;
        let accepted = if path.is_empty() {
            if flags & 0x1000 == 0 {
                return Err(Errno(2));
            }
            if dirfd == AT_FDCWD {
                return Err(Errno(13));
            }
            let open_descriptor = self.descriptor(dirfd as u32)?;
            let open = open_descriptor.open.borrow();
            let node = open.node.clone().ok_or(Errno(13))?;
            let label = match &open.kind {
                FdKind::Node(path) => path.clone(),
                _ => Vec::new(),
            };
            ResolvedInode {
                node,
                label,
                mount: self.mount_for_path(open.mount.as_ref()),
                file: Some(open.shared.clone()),
                _image: None,
                _directory: None,
            }
        } else {
            let (resolved, magic) = self.resolve_entry(dirfd, path, flags & 0x100 == 0, true)?;
            match magic {
                Some(ResolvedTarget::Inode(file)) => file,
                Some(ResolvedTarget::Descriptor(open)) => self.proc_open_node(&open, &resolved)?,
                None => {
                    let node = self.node(&resolved)?;
                    path_link = self.event_link(&resolved, &node);
                    ResolvedInode {
                        node,
                        label: self
                            .path_visible(&resolved)
                            .unwrap_or_else(|_| resolved.key.clone()),
                        mount: resolved.mount,
                        file: None,
                        _image: None,
                        _directory: None,
                    }
                }
            }
        };
        let (node, label, mount) = (&accepted.node, &accepted.label, &accepted.mount);
        let n = node.borrow();
        if matches!(n.content, Content::Symlink(_)) {
            return Err(Errno(40));
        }
        if mount
            .as_ref()
            .is_some_and(|m| m.flags.get() & mounts::MS_NOEXEC != 0)
        {
            return Err(Errno(13));
        }
        if !matches!(n.content, Content::File(_)) || !self.allowed(&n, 1) {
            return Err(Errno(13));
        }
        drop(n);
        #[cfg(all(feature = "hostfs", unix))]
        if !_open_host && node.host.get().is_some() {
            return Ok(None);
        }
        #[cfg(all(feature = "hostfs", unix))]
        let host_file = node.host.get().map(|file| file.file(false)).transpose()?;
        let mount_use = mount
            .as_ref()
            .map(|mount| mounts::MountUse::new(mount.identity.clone()));
        let link = path_link
            .or_else(|| accepted.file.as_ref()?.notification.as_ref()?.link.clone())
            .or_else(|| accepted._image.as_ref()?.notification.link.clone());
        let notification = FileClose::open::<false>(node, 0, link);
        Ok(Some(Arc::new(ExecutableFile {
            notification,
            _mount_use: mount_use,
            #[cfg(all(feature = "hostfs", unix))]
            _host_file: host_file,
            node: node.clone(),
            label: label.clone(),
            mount: mount.as_ref().map(|mount| mount.shared.clone()),
        })))
    }
    pub fn executable_mapping(&self, file: &ExecutableFile) -> trames_memory::MappingFileInfo {
        let path = self.executable_display(file).into();
        let node = file.node.borrow();
        let device = file
            .mount
            .as_ref()
            .filter(|m| m.kind == mounts::Kind::Overlay)
            .map_or(node.device, |m| m.device);
        trames_memory::MappingFileInfo {
            path,
            device,
            inode: node.inode,
        }
    }
    pub fn executable_display(&self, file: &ExecutableFile) -> Vec<u8> {
        let mount = file.mount.as_ref().map(|mount| {
            self.mount_for_path(Some(&OpenMount::Shared(mount.clone())))
                .expect("retained executable mount")
        });
        self.location(&file.node, &mount)
            .map(|p| self.path_visible(&p).unwrap_or(p.key))
            .unwrap_or_else(|_| {
                let mut label = file.label.clone();
                label.extend_from_slice(b" (deleted)");
                label
            })
    }
}

/// Linux shebang argument rules shared by initial launch and execve/execveat.
pub type ScriptInterpreter = (Vec<u8>, Option<Vec<u8>>);
pub fn script_interpreter(bytes: &[u8]) -> Result<Option<ScriptInterpreter>> {
    let Some(bytes) = bytes.strip_prefix(b"#!") else {
        return Ok(None);
    };
    const HEADER: usize = 256 - 2;
    let prefix = &bytes[..bytes.len().min(HEADER)];
    let separator = |c: &u8| matches!(c, b' ' | b'\t');
    let terminator = prefix.iter().position(|c| matches!(c, b'\n' | 0));
    let complete = terminator.is_some() || bytes.len() < HEADER;
    let line = &prefix[..terminator.unwrap_or(prefix.len())];
    let name_start = line.iter().position(|c| !separator(c)).ok_or(Errno(8))?;
    let name = &line[name_start..];
    let sep = name.iter().position(separator);
    if !complete && sep.is_none() {
        return Err(Errno(8));
    }
    let interpreter = name[..sep.unwrap_or(name.len())].to_vec();
    // Linux reserves the final byte of a full binprm buffer for termination.
    let argument = sep.and_then(|i| {
        let end = if complete { name.len() } else { name.len() - 1 };
        let tail = &name[i..end];
        let first = tail.iter().position(|c| !separator(c))?;
        let last = tail.iter().rposition(|c| !separator(c)).unwrap();
        Some(tail[first..=last].to_vec())
    });
    Ok(Some((interpreter, argument)))
}

impl ExecutableFile {
    pub fn begin_execution(self: &Arc<Self>) -> Result<Arc<ExecutingFile>> {
        self.node.claim_text_access(false)?;
        Ok(Arc::new(ExecutingFile(self.clone())))
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        let bytes = match &self.node.borrow().content {
            Content::File(data) => Vfs::executable_data(data)?,
            _ => return Err(Errno(13)),
        };
        if !bytes.is_empty() {
            self.notification.path_event(inotify::ACCESS);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn text_busy_follows_inode_and_last_open_description() {
        let mut v = Vfs::default();
        v.import_executable(b"/image", b"binary".to_vec()).unwrap();
        v.link_at(AT_FDCWD, b"/image", AT_FDCWD, b"/alias").unwrap();
        let file = v.executable_file_at(AT_FDCWD, b"/image", 0).unwrap();
        let writer = v.open_at(AT_FDCWD, b"/alias", 2, 0).unwrap();
        let duplicate = v.dup(writer, 0, false).unwrap();
        v.close(writer).unwrap();
        assert!(matches!(file.begin_execution(), Err(Errno(26))));
        v.close(duplicate).unwrap();

        let image = file.begin_execution().unwrap();
        let forked = image.clone();
        drop(image);
        v.unlink_at(AT_FDCWD, b"/image", false).unwrap();
        for flags in [1, 2, O_TRUNC] {
            assert_eq!(v.open_at(AT_FDCWD, b"/alias", flags, 0), Err(Errno(26)));
        }
        assert_eq!(v.truncate_at(b"/alias", 0), Err(Errno(26)));
        let reader = v.open_at(AT_FDCWD, b"/alias", 0, 0).unwrap();
        assert_eq!(v.read(reader, 6).unwrap(), b"binary");
        drop(forked);
        v.truncate_at(b"/alias", 0).unwrap();
        assert!(file.bytes().unwrap().is_empty());
    }
    #[test]
    fn resident_exec_lookup_accepts_private_inodes_and_reports_missing_files() {
        let path = std::env::temp_dir().join(format!(
            "trames-resident-exec-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut v = Vfs::open_disk(&path, Default::default()).unwrap();
        assert!(v.namespace_host_work());
        assert!(matches!(
            v.executable_file_from_resident_namespace(AT_FDCWD, b"/missing", 0),
            Err(Errno(2))
        ));
        v.import_executable(b"/image", b"payload".to_vec()).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/image", O_CLOEXEC, 0).unwrap();
        let file = v
            .executable_file_from_resident_namespace(fd as i32, b"", 0x1000)
            .unwrap()
            .unwrap();
        v.close(fd).unwrap();
        v.unlink_at(AT_FDCWD, b"/image", false).unwrap();
        assert_eq!(file.bytes().unwrap(), b"payload");
        drop(file);
        drop(v);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[cfg(all(feature = "hostfs", unix))]
    #[test]
    fn native_exec_namespace_defers_lookup_including_missing_names() {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/host", 0o755).unwrap();
        v.mount_host(b"/host", std::env::temp_dir(), true).unwrap();
        assert!(v
            .executable_file_from_resident_namespace(AT_FDCWD, b"/host/missing", 0)
            .unwrap()
            .is_none());
    }
    #[test]
    fn shebang_parser_keeps_one_optional_argument_and_rejects_invalid_headers() {
        assert_eq!(script_interpreter(b"ELF").unwrap(), None);
        assert_eq!(
            script_interpreter(b"#! /bin/env  python -u\r\nbody").unwrap(),
            Some((b"/bin/env".to_vec(), Some(b"python -u\r".to_vec())))
        );
        assert_eq!(
            script_interpreter(b"#!/bin/sh\n").unwrap(),
            Some((b"/bin/sh".to_vec(), None))
        );
        assert_eq!(
            script_interpreter(b"#!\t/bin/sh    one two \t\0unused").unwrap(),
            Some((b"/bin/sh".to_vec(), Some(b"one two".to_vec())))
        );
        let long = [b"#!/bin/sh ".as_slice(), &[b'x'; 512]].concat();
        assert_eq!(
            script_interpreter(&long).unwrap().unwrap().1.unwrap().len(),
            245
        );
        assert_eq!(script_interpreter(b"#! \n"), Err(Errno(8)));
        assert_eq!(
            script_interpreter(&[b"#!".as_slice(), &[b'x'; 255]].concat()),
            Err(Errno(8))
        );
    }
    fn snapshot(v: &mut Vfs) {
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
    }
    #[test]
    fn anonymous_exec_reference_survives_last_fd_close_and_retains_ram_accounting() {
        let mut v = Vfs::default();
        let fd = v.memfd_create(b"penguin", 1).unwrap(); // MFD_CLOEXEC
        v.write(fd, b"payload").unwrap();
        let file = v.executable_file_at(fd as i32, b"", 0x1000).unwrap();
        snapshot(&mut v);
        assert_eq!(
            v.readlink_at(AT_FDCWD, format!("/proc/self/fd/{fd}").as_bytes())
                .unwrap(),
            b"/memfd:penguin (deleted)"
        );
        v.close(fd).unwrap();
        assert_eq!(file.bytes().unwrap(), b"payload");
        assert_eq!(v.executable_display(&file), b"/memfd:penguin (deleted)");
        assert_eq!(
            v.memfd_available(),
            crate::memfd::MEMFD_BYTES - trames_shared::SharedFile::required_capacity(7).unwrap()
        );
        drop(file);
        assert_eq!(v.memfd_available(), crate::memfd::MEMFD_BYTES);
    }
    #[test]
    fn symlink_to_proc_magic_link_uses_the_deleted_inode_and_preserves_permissions() {
        let mut v = Vfs::default();
        v.import_executable(b"/original", b"payload".to_vec())
            .unwrap();
        let fd = v.open_at(AT_FDCWD, b"/original", O_PATH, 0).unwrap();
        v.unlink_at(AT_FDCWD, b"/original", false).unwrap();
        v.symlink_at(
            format!("/proc/self/fd/{fd}").as_bytes(),
            AT_FDCWD,
            b"/alias",
        )
        .unwrap();
        snapshot(&mut v);
        assert_eq!(v.executable(b"/alias").unwrap(), b"payload");
        assert!(matches!(
            v.executable_file_at(AT_FDCWD, b"/alias", 0x100),
            Err(Errno(40))
        ));
        let file = v.executable_file_at(fd as i32, b"", 0x1000).unwrap();
        file.node.borrow_mut().mode &= !0o111;
        assert!(matches!(
            v.executable_file_at(fd as i32, b"", 0x1000),
            Err(Errno(13))
        ));
    }
    #[test]
    fn reopen_exec_magic_link_after_memfd_exec_and_last_descriptor_close() {
        let mut v = Vfs::default();
        let fd = v.memfd_create(b"runc_cloned:/proc/self/exe", 3).unwrap();
        v.write(fd, b"payload").unwrap();
        let file = v.executable_file_at(fd as i32, b"", 0x1000).unwrap();
        v.close(fd).unwrap();
        v.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    executable: v.executable_display(&file),
                    executable_file: Some(Arc::downgrade(&file)),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        v.symlink_at(b"/proc/self/exe", AT_FDCWD, b"/exec-alias")
            .unwrap();
        for path in [b"/proc/self/exe".as_slice(), b"/exec-alias"] {
            let reopened = v.open_at(AT_FDCWD, path, O_CLOEXEC, 0).unwrap();
            assert_eq!(v.read(reopened, 7).unwrap(), b"payload");
            assert_eq!(
                v.stat_fd(reopened).unwrap()[8..16],
                file.node.borrow().inode.to_le_bytes()
            );
            v.close(reopened).unwrap();
        }
        assert_eq!(
            v.open_at(AT_FDCWD, b"/proc/self/exe", O_NOFOLLOW, 0),
            Err(Errno(40))
        );
    }
}
