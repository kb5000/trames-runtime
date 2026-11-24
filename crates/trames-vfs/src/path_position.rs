// SPDX-License-Identifier: GPL-3.0-or-later
//! Accepted directory positions in the shared guest namespace index.
use super::*;

enum Base {
    Inode(NodeRef),
    Child(NodeRef, Vec<u8>),
}

pub(super) struct Position {
    base: Base,
    selected: std::sync::OnceLock<NodeRef>,
    original: Option<Arc<ResolvedInode>>,
}
impl Position {
    pub(super) fn inode(node: NodeRef) -> Arc<Self> {
        Arc::new(Self {
            base: Base::Inode(node),
            selected: Default::default(),
            original: None,
        })
    }
    pub(super) fn magic(file: ResolvedInode) -> Arc<Self> {
        Arc::new(Self {
            base: Base::Inode(file.node.clone()),
            selected: Default::default(),
            original: Some(Arc::new(file)),
        })
    }
    pub(super) fn known_node(&self) -> Option<&NodeRef> {
        match &self.base {
            Base::Inode(node) => Some(node),
            Base::Child(_, _) => self.selected.get(),
        }
    }
    fn key_in(&self, paths: &BTreeMap<Vec<u8>, NodeRef>) -> Result<Vec<u8>> {
        let (node, name) = match &self.base {
            Base::Inode(node) => (node, None),
            Base::Child(parent, name) => (parent, Some(name)),
        };
        let mut key = node.borrow().path_in(paths, b"/").ok_or(Errno(2))?;
        if let Some(name) = name {
            if key != b"/" {
                key.push(b'/');
            }
            key.extend_from_slice(name);
            if key.len() >= MAX_PATH {
                return Err(Errno(36));
            }
        }
        Ok(key)
    }
    pub(super) fn key(&self, filesystem: &FsHandle) -> Result<Vec<u8>> {
        self.key_in(&filesystem.borrow().paths)
    }
    pub(super) fn node(&self, filesystem: &FsHandle) -> Result<NodeRef> {
        if let Some(node) = self.known_node() {
            return Ok(node.clone());
        }
        loop {
            let fs = filesystem.borrow();
            let key = self.key_in(&fs.paths)?;
            if let Some(node) = fs.paths.get(&key) {
                let _ = self.selected.set(node.clone());
                return Ok(self.selected.get().unwrap().clone());
            }
            let overlay = fs.overlay.clone().ok_or(Errno(2))?;
            drop(fs);
            let result = overlay.lookup_new(filesystem, &key);
            // Overlay materialization can acquire a write guard. If a rename
            // crossed that gap, restart from the accepted parent, not its old
            // spelling. This is a namespace lookup retry, not a message poll.
            let fs = filesystem.borrow();
            if self.key_in(&fs.paths)? != key {
                continue;
            }
            let node = result?;
            let _ = self.selected.set(node);
            return Ok(self.selected.get().unwrap().clone());
        }
    }
    pub(super) fn child(&self, name: &[u8]) -> Result<Arc<Self>> {
        let parent = self.known_node().ok_or(Errno(5))?.clone();
        Ok(Arc::new(Self {
            base: Base::Child(parent, name.to_vec()),
            selected: Default::default(),
            original: self.original.clone(),
        }))
    }
    pub(super) fn lookup_parent(&self) -> Option<Arc<Self>> {
        let Base::Child(parent, _) = &self.base else {
            return None;
        };
        let mut position = Self::inode(parent.clone());
        Arc::get_mut(&mut position).unwrap().original = self.original.clone();
        Some(position)
    }
    pub(super) fn parent(&self, filesystem: &FsHandle) -> Result<Arc<Self>> {
        let node = self.node(filesystem)?;
        let parent = if let Some(parent) = node.removed_directory_parent.get() {
            parent.clone()
        } else {
            let fs = filesystem.borrow();
            let mut key = node.borrow().path_in(&fs.paths, b"/").ok_or(Errno(2))?;
            key.truncate(key.iter().rposition(|b| *b == b'/').unwrap_or(0).max(1));
            fs.paths.get(&key).cloned().ok_or(Errno(2))?
        };
        let mut position = Self::inode(parent);
        Arc::get_mut(&mut position).unwrap().original = self.original.clone();
        Ok(position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hard_link_rebases_both_accepted_parents_inside_the_namespace_mutation() {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/dir", 0o755).unwrap();
        v.import_file(b"/dir/old", b"original".to_vec()).unwrap();
        let expected = v.stat_at(AT_FDCWD, b"/dir/old").unwrap();
        let fd = v
            .open_at(AT_FDCWD, b"/dir", O_PATH | O_DIRECTORY, 0)
            .unwrap();
        let capture = |name: &[u8]| {
            let walk = v
                .start_path_walk(fd as i32, name, false, false, 0, false, None)
                .unwrap();
            v.resolve_walk(
                walk,
                Some(ResolveOperation::ResumeFuse(
                    fuse::PathOperation::Stat,
                    true,
                )),
            )
            .unwrap()
            .0
        };
        let source = capture(b"old");
        let dest = capture(b"new");
        v.close(fd).unwrap();
        v.rename_at(AT_FDCWD, b"/dir", AT_FDCWD, b"/moved", 0)
            .unwrap();
        v.mkdir_at(AT_FDCWD, b"/dir", 0o755).unwrap();
        v.import_file(b"/dir/old", b"replacement".to_vec()).unwrap();
        v.link_resolved(&source, &dest, None, None).unwrap();
        assert_eq!(
            &v.stat_at(AT_FDCWD, b"/moved/new").unwrap()[..16],
            &expected[..16]
        );
        assert_eq!(v.stat_at(AT_FDCWD, b"/dir/new"), Err(Errno(2)));
    }
    #[test]
    fn accepted_directory_walk_keeps_its_inode_after_fd_reuse_and_rename() {
        for persistent in [false, true] {
            let store = std::env::temp_dir().join(format!(
                "trames-indexed-walk-{}-{}",
                std::process::id(),
                trames_memory::new_backing_identity()
            ));
            let mut v = if persistent {
                Vfs::open_disk(&store, DiskOptions::default()).unwrap()
            } else {
                Vfs::default()
            };
            for path in [b"/dir".as_slice(), b"/dir/leaf", b"/replacement"] {
                v.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
            }
            let expected = v.stat_at(AT_FDCWD, b"/dir/leaf").unwrap();
            let fd = v
                .open_at(AT_FDCWD, b"/dir", O_PATH | O_DIRECTORY, 0)
                .unwrap();
            let replacement = v
                .open_at(AT_FDCWD, b"/replacement", O_PATH | O_DIRECTORY, 0)
                .unwrap();
            let walk = v
                .start_path_walk(fd as i32, b"leaf", true, true, 0, true, None)
                .unwrap();
            v.close(fd).unwrap();
            assert_eq!(
                v.shared_files()
                    .duplicate(replacement, fd, false)
                    .unwrap()
                    .unwrap(),
                fd
            );
            v.rename_at(AT_FDCWD, b"/dir", AT_FDCWD, b"/moved", 0)
                .unwrap();
            v.mkdir_at(AT_FDCWD, b"/dir", 0o755).unwrap();
            v.mkdir_at(AT_FDCWD, b"/dir/leaf", 0o755).unwrap();
            let entry = v
                .resolve_walk(
                    walk,
                    Some(ResolveOperation::ResumeFuse(
                        fuse::PathOperation::Stat,
                        true,
                    )),
                )
                .unwrap();
            assert_eq!(&v.stat_resolved(entry).unwrap().0[..16], &expected[..16]);
            drop(v);
            if persistent {
                std::fs::remove_dir_all(store).unwrap();
            }
        }
    }
}
