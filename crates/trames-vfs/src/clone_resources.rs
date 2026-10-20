// SPDX-License-Identifier: GPL-3.0-or-later
//! Coordinator-local change detection for CLONE_FILES and CLONE_FS resources.
use super::*;

/// Retained identities across one syscall/control callback. Keeping the old
/// identities alive prevents pointer reuse (ABA); no paths or FD entries are
/// copied. Open descriptions and inode contents already share their own state.
pub struct CloneResources {
    files: Rc<DescriptorVersion>,
    cwd: Option<Rc<RefCell<Node>>>,
    root: Option<Rc<RefCell<Node>>>,
    cwd_mount: Option<Rc<Mount>>,
    root_mount: Option<Rc<Mount>>,
    umask: u32,
}

fn same<T>(a: &Option<Rc<T>>, b: &Option<Rc<T>>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => Rc::ptr_eq(a, b),
        (None, None) => true,
        _ => false,
    }
}

impl Vfs {
    pub fn clone_resources(&self) -> CloneResources {
        CloneResources {
            files: self.fds.identity.clone(),
            cwd: self.cwd_node.clone(),
            root: self.root_node.clone(),
            cwd_mount: self.cwd_mount.clone(),
            root_mount: self.root_mount.clone(),
            umask: self.umask,
        }
    }

    /// (descriptor table changed, filesystem context changed). This also
    /// detects partial mutations before a syscall returns an error. A failed
    /// lookup/poll/read normally leaves both identities unchanged.
    pub fn changed_clone_resources(&self, old: &CloneResources) -> (bool, bool) {
        (
            !Rc::ptr_eq(&self.fds.identity, &old.files),
            self.umask != old.umask
                || !same(&self.cwd_node, &old.cwd)
                || !same(&self.root_node, &old.root)
                || !same(&self.cwd_mount, &old.cwd_mount)
                || !same(&self.root_mount, &old.root_mount),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changes_track_tables_context_and_shared_open_descriptions_separately() {
        let mut v = Vfs::default();
        let fd = v.open_at(AT_FDCWD, b"/file", 0x42, 0o600).unwrap();
        let old = v.clone_resources();
        assert_eq!(v.changed_clone_resources(&old), (false, false));
        v.write(fd, b"abc").unwrap();
        v.seek(fd, 0, 0).unwrap();
        assert_eq!(v.read(fd, 3).unwrap(), b"abc");
        assert_eq!(v.open_at(AT_FDCWD, b"/missing", 0, 0), Err(Errno(2)));
        assert_eq!(v.changed_clone_resources(&old), (false, false));
        v.close(fd).unwrap();
        assert_eq!(v.changed_clone_resources(&old), (true, false));
        let old = v.clone_resources();
        v.mkdir_at(AT_FDCWD, b"/dir", 0o700).unwrap();
        assert_eq!(v.changed_clone_resources(&old), (false, false));
        v.chdir(b"/dir").unwrap();
        assert_eq!(v.changed_clone_resources(&old), (false, true));
        let old = v.clone_resources();
        v.umask = 0o077;
        assert_eq!(v.changed_clone_resources(&old), (false, true));
    }
}
