// SPDX-License-Identifier: GPL-3.0-or-later
//! Operation-owned native positions. Display keys are hints, never capabilities.
use super::*;

pub(crate) struct Pinned {
    pub node: NodeRef,
    pub file: Arc<OpenFile>,
}
enum Base {
    Inode(NodeRef),
    Child(Arc<Pinned>, Vec<u8>),
}
pub(crate) struct Position {
    base: Base,
    pinned: std::sync::OnceLock<Arc<Pinned>>,
    // A real accepted magic target, not a persistent inode/name cache user.
    original: Option<Arc<ResolvedInode>>,
}
impl Position {
    pub(crate) fn inode(node: NodeRef, file: Arc<OpenFile>) -> Arc<Self> {
        let pinned = Arc::new(Pinned {
            node: node.clone(),
            file,
        });
        Arc::new(Self {
            base: Base::Inode(node),
            pinned: pinned.into(),
            original: None,
        })
    }
    pub(crate) fn magic(file: ResolvedInode) -> Arc<Self> {
        let pinned = std::sync::OnceLock::new();
        if let Some(host) = file
            .host_file
            .clone()
            .or_else(|| file.file.as_ref().and_then(|file| file.host_file.clone()))
        {
            let _ = pinned.set(Arc::new(Pinned {
                node: file.node.clone(),
                file: host,
            }));
        }
        Arc::new(Self {
            base: Base::Inode(file.node.clone()),
            pinned,
            original: Some(Arc::new(file)),
        })
    }
    pub(crate) fn known_node(&self) -> Option<&NodeRef> {
        match &self.base {
            Base::Inode(node) => Some(node),
            Base::Child(_, _) => self.pinned.get().map(|pin| &pin.node),
        }
    }
    pub(crate) fn known_file(&self) -> Option<Arc<OpenFile>> {
        self.pinned.get().map(|pin| pin.file.clone())
    }
    pub(crate) fn pin(&self, host: &HostFs, fs: &FsHandle, key: &[u8]) -> Result<Arc<Pinned>> {
        if let Some(pin) = self.pinned.get() {
            return Ok(pin.clone());
        }
        let pin = match &self.base {
            Base::Inode(node) => Arc::new(Pinned {
                node: node.clone(),
                file: node.host.get().ok_or(Errno(2))?.any_file()?,
            }),
            Base::Child(parent, name) => {
                host.lookup_capability(fs, key, &parent.file.file, &component(name)?)?
            }
        };
        // Concurrent users reconcile one operation-owned result. Failed
        // lookups are not cached: a subsequent CREATE must see its new inode.
        let _ = self.pinned.set(pin);
        Ok(self.pinned.get().unwrap().clone())
    }
    pub(crate) fn child(&self, name: &[u8]) -> Result<Arc<Self>> {
        component(name)?;
        let parent = self.pinned.get().ok_or(Errno(5))?.clone();
        Ok(Arc::new(Self {
            base: Base::Child(parent, name.to_vec()),
            pinned: Default::default(),
            original: self.original.clone(),
        }))
    }
    pub(crate) fn lookup_parent(&self) -> Option<Arc<Self>> {
        let Base::Child(parent, _) = &self.base else {
            return None;
        };
        let mut parent_position = Self::inode(parent.node.clone(), parent.file.clone());
        Arc::get_mut(&mut parent_position).unwrap().original = self.original.clone();
        Some(parent_position)
    }
    pub(crate) fn native_parent(
        &self,
        host: &HostFs,
        fs: &FsHandle,
        key: &[u8],
    ) -> Result<(Parent<'static>, CString)> {
        match &self.base {
            Base::Child(parent, name) => {
                Ok((Parent::Shared(parent.file.clone()), component(name)?))
            }
            Base::Inode(_) => Ok((
                Parent::Shared(self.pin(host, fs, key)?.file.clone()),
                CString::new(".").unwrap(),
            )),
        }
    }
    pub(crate) fn climb(
        &self,
        host: &HostFs,
        fs: &FsHandle,
        key: &[u8],
    ) -> Result<(Vec<u8>, Arc<Self>)> {
        let source = self.pin(host, fs, key)?;
        let file = open_at(
            &source.file.file,
            &CString::new("..").unwrap(),
            directory_flags(),
            0,
        )?;
        let root = native_path(&host.root.directory)?;
        let parent = native_path(&file)?;
        let relative = parent.strip_prefix(root).map_err(|_| Errno(2))?;
        let mut key = b"/".to_vec();
        key.extend_from_slice(relative.as_os_str().as_bytes());
        let file = Arc::new(OpenFile {
            file,
            root: host.root.clone(),
        });
        let node = host.lookup_captured(fs, &key, file.clone(), None)?;
        let mut position = Self::inode(node, file);
        Arc::get_mut(&mut position).unwrap().original = self.original.clone();
        Ok((key, position))
    }
}

impl HostFs {
    pub(crate) fn parent_path<'a>(
        &'a self,
        fs: &FsHandle,
        path: &ResolvedPath,
    ) -> Result<(Parent<'a>, CString)> {
        match &path.host_position {
            Some(position) => position.native_parent(self, fs, &path.key),
            None => self.root.parent(&path.key),
        }
    }
    pub(crate) fn lookup_path(&self, fs: &FsHandle, path: &ResolvedPath) -> Result<NodeRef> {
        match &path.host_position {
            Some(position) => Ok(position.pin(self, fs, &path.key)?.node.clone()),
            None => self.lookup(fs, &path.key),
        }
    }
    #[allow(clippy::unnecessary_cast)]
    fn lookup_capability(
        &self,
        fs: &FsHandle,
        key: &[u8],
        parent: &File,
        name: &CString,
    ) -> Result<Arc<Pinned>> {
        let file = Arc::new(OpenFile {
            file: open_at(parent, name, metadata_flags(), 0)?,
            root: self.root.clone(),
        });
        let meta = file.native_stat()?;
        let file = if meta.st_mode as u32 & 0o170000 == 0o040000 {
            // Darwin O_EVTONLY loses fstat access after rmdir. A search-only
            // directory capability retains Linux O_PATH's directory identity.
            match open_at(
                &file.file,
                &CString::new(".").unwrap(),
                directory_flags(),
                0,
            ) {
                Ok(file) => Arc::new(OpenFile {
                    file,
                    root: self.root.clone(),
                }),
                Err(Errno(13)) => file,
                Err(error) => return Err(error),
            }
        } else {
            file
        };
        let node = self.lookup_metadata(fs, key, meta, Some((parent, name)))?;
        node.host.get().unwrap().state.lock().unwrap().metadata = Arc::downgrade(&file);
        Ok(Arc::new(Pinned { node, file }))
    }
    fn lookup_captured(
        &self,
        fs: &FsHandle,
        key: &[u8],
        file: Arc<OpenFile>,
        link: Option<(&File, &CString)>,
    ) -> Result<NodeRef> {
        let node = self.lookup_metadata(fs, key, file.native_stat()?, link)?;
        node.host.get().unwrap().state.lock().unwrap().metadata = Arc::downgrade(&file);
        Ok(node)
    }
    pub(crate) fn lease_path(
        &self,
        fs: &FsHandle,
        path: &ResolvedPath,
        node: &NodeRef,
        flags: u32,
    ) -> Result<Option<Arc<OpenFile>>> {
        let Some(position) = &path.host_position else {
            return self.lease(node, flags);
        };
        let pin = position.pin(self, fs, &path.key)?;
        if flags & O_PATH != 0 {
            return Ok(Some(pin.file.clone()));
        }
        let access = flags & 3;
        let native = match access {
            0 => libc::O_RDONLY,
            1 => libc::O_WRONLY,
            _ => libc::O_RDWR,
        };
        let (parent, name) = if matches!(node.borrow().content, Content::Directory) {
            (Parent::Shared(pin.file.clone()), CString::new(".").unwrap())
        } else {
            self.parent_path(fs, path)?
        };
        let file = open_at(&parent, &name, native, 0)?;
        node.host
            .get()
            .ok_or(Errno(2))?
            .retain(file, access)
            .map(Some)
    }
}
