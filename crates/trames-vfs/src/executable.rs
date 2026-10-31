// SPDX-License-Identifier: GPL-3.0-or-later
//! Exec resolves an inode capability, never a proc magic-link display string.
use super::*;

pub struct ExecutableFile {
    #[cfg(all(feature = "hostfs", unix))]
    _host_file: Option<Arc<hostfs::OpenFile>>,
    pub(super) node: NodeRef,
    pub(super) label: Vec<u8>,
    pub(super) mount: Option<Rc<Mount>>,
}

impl Vfs {
    pub fn executable_file_at(
        &self,
        dirfd: i32,
        path: &[u8],
        flags: u32,
    ) -> Result<Rc<ExecutableFile>> {
        if path.is_empty() && flags & 0x1000 == 0 {
            return Err(Errno(2));
        }
        if flags & !0x1100 != 0 {
            return Err(Errno(22));
        }
        let (node, label, mount) = if path.is_empty() {
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
            (node, label, self.mount_for_path(open.mount.as_ref()))
        } else {
            let (resolved, magic) = self.resolve_entry(dirfd, path, flags & 0x100 == 0, true)?;
            match magic {
                Some(file) => file,
                None => (
                    self.node(&resolved)?,
                    self.path_visible(&resolved)
                        .unwrap_or_else(|_| resolved.key.clone()),
                    resolved.mount,
                ),
            }
        };
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
        let host_file = node.host.get().map(|file| file.file(false)).transpose()?;
        Ok(Rc::new(ExecutableFile {
            #[cfg(all(feature = "hostfs", unix))]
            _host_file: host_file,
            node,
            label,
            mount,
        }))
    }
    pub fn executable_display(&self, file: &ExecutableFile) -> Vec<u8> {
        self.location(&file.node, &file.mount)
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
    let line = bytes.split(|&b| b == b'\n').next().ok_or(Errno(8))?;
    if line.len() > 254 {
        return Err(Errno(8));
    }
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let start = line
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .ok_or(Errno(8))?;
    let mut parts = line[start..].splitn(2, |b| b.is_ascii_whitespace());
    let interpreter = parts.next().unwrap_or_default().to_vec();
    let argument = parts.next().and_then(|tail| {
        tail.iter()
            .position(|b| !b.is_ascii_whitespace())
            .map(|i| tail[i..].to_vec())
    });
    Ok(Some((interpreter, argument)))
}

impl ExecutableFile {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        match &self.node.borrow().content {
            Content::File(data) => Vfs::executable_data(data),
            _ => Err(Errno(13)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shebang_parser_keeps_one_optional_argument_and_rejects_invalid_headers() {
        assert_eq!(script_interpreter(b"ELF").unwrap(), None);
        assert_eq!(
            script_interpreter(b"#! /bin/env  python -u\r\nbody").unwrap(),
            Some((b"/bin/env".to_vec(), Some(b"python -u".to_vec())))
        );
        assert_eq!(
            script_interpreter(b"#!/bin/sh\n").unwrap(),
            Some((b"/bin/sh".to_vec(), None))
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
}
