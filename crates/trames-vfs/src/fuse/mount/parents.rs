// SPDX-License-Identifier: GPL-3.0-or-later
//! Retained namespace parents use the same resumable VFS walk as file opens.
use super::namespace::Action;
use super::*;

pub(crate) enum NamespaceTarget {
    Fuse(PathPlan),
    Ordinary(ResolvedPath, bool),
    Walk(Box<PathWalk>),
}
impl From<PathPlan> for NamespaceTarget {
    fn from(plan: PathPlan) -> Self {
        Self::Fuse(plan)
    }
}
impl NamespaceTarget {
    pub(crate) fn ordinary(path: ResolvedPath, trailing: bool) -> Self {
        Self::Ordinary(path, trailing)
    }
    pub(crate) fn unresolved(v: &Vfs, fd: i32, path: &[u8]) -> Result<Self> {
        v.start_path_walk(fd, path, true, true, 0, false, None)
            .map(Box::new)
            .map(Self::Walk)
    }
}

struct DirectoryOperand {
    node: NodeRef,
    mount: Option<Arc<Mount>>,
    _usage: Option<mounts::MountUse>,
    position_path: Option<ResolvedPath>,
}
impl DirectoryOperand {
    fn new(path: ResolvedPath, node: NodeRef) -> Self {
        let usage = path
            .mount
            .as_ref()
            .map(|mount| mounts::MountUse::new(mount.identity.clone()));
        Self {
            node,
            mount: path.mount.clone(),
            position_path: (path.host_position_present() || path.indexed_position.is_some())
                .then_some(path),
            _usage: usage,
        }
    }
    fn target(&self, v: &Vfs, name: &[u8]) -> Result<ResolvedPath> {
        let host = self.position_path.as_ref();
        let mut parent = host
            .cloned()
            .map_or_else(|| v.location(&self.node, &self.mount), Ok)?;
        #[cfg(all(feature = "hostfs", unix))]
        let position = parent.host_position.clone();
        let indexed = parent.indexed_position.clone();
        if parent.retained_directory.is_some() {
            return Err(Errno(2));
        }
        if parent.key != b"/" {
            parent.push(b'/');
        }
        parent.extend_from_slice(name);
        if let Some(indexed) = indexed {
            parent.indexed_position = Some(indexed.child(name)?);
        }
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(position) = position {
            parent.host_position = Some(position.child(name)?);
        }
        if parent.len() >= MAX_PATH {
            return Err(Errno(36));
        }
        v.follow_mounts(parent)
    }
}

struct Parent {
    walk: Option<Box<PathWalk>>,
    pending: Option<Box<Metadata>>,
    directory: Option<DirectoryOperand>,
    name: Vec<u8>,
    trailing: bool,
    anchor: Option<SharedFd>,
    origin_use: Option<mounts::MountUse>,
}
impl Parent {
    fn new(v: &Vfs, target: NamespaceTarget) -> Result<Self> {
        let (mut walk, names, trailing, anchor, origin_use, link) = match target {
            NamespaceTarget::Fuse(mut path) => (
                path.walk.take().expect("accepted namespace walk"),
                path.names,
                path.trailing,
                path.anchor,
                Some(path._usage),
                path.link,
            ),
            NamespaceTarget::Walk(mut walk) => {
                let names = std::mem::take(&mut walk.parts);
                let trailing = walk.trailing;
                (walk, names, trailing, None, None, None)
            }
            NamespaceTarget::Ordinary(path, trailing) => {
                let name = path
                    .key
                    .rsplit(|byte| *byte == b'/')
                    .next()
                    .unwrap()
                    .to_vec();
                let parent = path.parent();
                let node = v.node(&parent)?;
                return Ok(Self {
                    walk: None,
                    pending: None,
                    directory: Some(DirectoryOperand::new(parent, node)),
                    name,
                    trailing,
                    anchor: None,
                    origin_use: None,
                });
            }
        };
        let mut names = names;
        let name = names.pop_back().ok_or(Errno(16))?;
        walk.parts = names;
        walk.follow_final = true;
        walk.trailing = true;
        walk.retain_magic = true;
        walk.stop_magic = false;
        walk.credentials = Some(Box::new(v.credentials.clone()));
        let (walk, pending) = if let Some((node, base)) = link {
            (
                None,
                Some(Box::new(Metadata::follow_inode(
                    v,
                    node,
                    *walk,
                    base,
                    PathOperation::ResolveDirectory,
                )?)),
            )
        } else {
            (Some(walk), None)
        };
        let origin_use = origin_use.filter(|_| pending.is_none());
        Ok(Self {
            walk,
            pending,
            directory: None,
            name,
            trailing,
            anchor,
            origin_use,
        })
    }
    fn advance(&mut self, v: &mut Vfs) -> Result<bool> {
        if self.directory.is_some() {
            return Ok(true);
        }
        if let Some(pending) = &mut self.pending {
            let Some(value) = pending.take(v) else {
                return Ok(false);
            };
            value?;
            let (path, node) = *pending.resolved.take().ok_or(Errno(5))?;
            self.directory = Some(DirectoryOperand::new(path, node));
            self.pending = None;
            return Ok(true);
        }
        v.query.as_ref().unwrap().clear_deferred();
        let result = v.resolve_walk(
            *self.walk.take().unwrap(),
            Some(ResolveOperation::Fuse(PathOperation::ResolveDirectory)),
        );
        match result {
            Ok(entry) => {
                let (path, node) = v.directory_resolved(entry)?;
                self.directory = Some(DirectoryOperand::new(path, node));
            }
            Err(error) => {
                self.pending = v.query.as_ref().unwrap().prepared.borrow_mut().fuse.take();
                if self.pending.is_none() {
                    return Err(error);
                }
            }
        }
        // A real current pathname request or final parent pin replaces the
        // initial prefix's use; cold metadata is not a second mount user.
        self.origin_use = None;
        Ok(self.directory.is_some())
    }
    fn directory(&self) -> &DirectoryOperand {
        self.directory.as_ref().unwrap()
    }
    fn fuse_plan(&self) -> Option<PathPlan> {
        let directory = self.directory();
        let mount = directory.mount.as_ref()?;
        let fs = mount.fs.fuse.as_ref()?;
        let mut path = PathPlan::root(
            mount,
            fs,
            VecDeque::from([self.name.clone()]),
            self.trailing,
        )
        .at_directory(directory.node.clone());
        path.anchor = self.anchor.as_ref().filter(|anchor| {
            matches!(&anchor.open.control, Some(events::SharedControl::FuseFile(file))
                if file.reference.directory.as_ref().is_some_and(|node| Arc::ptr_eq(node, &directory.node)))
        }).cloned();
        Some(path)
    }
    fn host_work(&self) -> bool {
        let directory = self.directory();
        let Some(mount) = &directory.mount else {
            return false;
        };
        #[cfg(all(feature = "hostfs", unix))]
        if mount.fs.host.is_some() {
            return true;
        }
        mount.fs.borrow().disk.is_some() || mount.fs.has_overlay()
    }
}

pub(crate) enum ParentStep {
    Waiting,
    Host,
    Mutation(Box<Metadata>),
    Complete(FileValue),
}
pub(crate) struct PendingNamespace {
    source: Parent,
    dest: Option<Parent>,
    action: Option<Action>,
    rights: u64,
    host: bool,
}
impl PendingNamespace {
    pub(crate) fn new(
        v: &Vfs,
        source: NamespaceTarget,
        action: Action,
        dest: Option<NamespaceTarget>,
        rights: u64,
    ) -> Result<Self> {
        Ok(Self {
            source: Parent::new(v, source)?,
            dest: dest.map(|target| Parent::new(v, target)).transpose()?,
            action: Some(action),
            rights,
            host: false,
        })
    }
    pub(crate) fn request(&self) -> Option<&Metadata> {
        self.source
            .pending
            .as_deref()
            .or_else(|| self.dest.as_ref().and_then(|dest| dest.pending.as_deref()))
    }
    pub(crate) fn owner_work(&self) -> bool {
        self.request().is_some_and(Metadata::owner_work)
    }
    pub(crate) fn join_owner(&mut self) {
        if let Some(pending) = self.source.pending.as_deref_mut().or_else(|| {
            self.dest
                .as_mut()
                .and_then(|dest| dest.pending.as_deref_mut())
        }) {
            pending.join_owner();
        }
    }
    pub(crate) fn ready(&self) -> bool {
        self.request().is_none_or(Metadata::ready)
    }
    pub(crate) fn host_work(&self) -> bool {
        self.request().map_or(self.host, Metadata::host_work)
    }
    pub(crate) fn run(&mut self, v: &mut Vfs) -> Result<ParentStep> {
        let native = self.host_work();
        if !self.source.advance(v)? {
            return Ok(ParentStep::Waiting);
        }
        if let Some(dest) = &mut self.dest {
            if !dest.advance(v)? {
                return Ok(ParentStep::Waiting);
            }
        }
        let action = self.action.as_ref().unwrap();
        if self.source.name == b"." || self.source.name == b".." {
            return Err(Errno(match action {
                Action::Unlink { directory: false } => 21,
                Action::Unlink { directory: true } if self.source.name == b".." => 39,
                Action::Unlink { directory: true } => 22,
                Action::Rename { .. } => 16,
                _ => 17,
            }));
        }
        if self.source.name.len() > 255
            || self.dest.as_ref().is_some_and(|dest| dest.name.len() > 255)
        {
            return Err(Errno(36));
        }
        // Resolve native child/mount identities only on the existing native
        // executor, including when the other parent's daemon just replied.
        if !native && (self.source.host_work() || self.dest.as_ref().is_some_and(Parent::host_work))
        {
            self.host = true;
            return Ok(ParentStep::Host);
        }
        let source = self.source.directory().target(v, &self.source.name)?;
        let dest = self
            .dest
            .as_ref()
            .map(|dest| dest.directory().target(v, &dest.name))
            .transpose()?;
        if v.is_mount_root(&source) || dest.as_ref().is_some_and(|dest| v.is_mount_root(dest)) {
            return Err(Errno(
                if matches!(
                    action,
                    Action::Mkdir { .. }
                        | Action::Mknod { .. }
                        | Action::Symlink(_)
                        | Action::Link(_)
                ) {
                    17
                } else {
                    16
                },
            ));
        }
        if matches!(action, Action::Rename { .. })
            && source.mount.as_ref().map(|m| m.id)
                != dest.as_ref().unwrap().mount.as_ref().map(|m| m.id)
        {
            return Err(Errno(18));
        }
        if let Some(path) = self.source.fuse_plan() {
            if v.credentials.landlock.fs_mask() != 0 {
                let root = ResolvedPath {
                    key: path.mount.root_path(),
                    mount: Some(Mount::resource_projection(path.mount.clone())),
                    proc_binding: None,
                    directory_inode: None,
                    indexed_position: None,
                    #[cfg(all(feature = "hostfs", unix))]
                    host_position: None,
                    retained_directory: None,
                };
                v.landlock_check(&root, None, self.rights)?;
            }
            let action = self.action.take().unwrap();
            let dest = self
                .dest
                .as_ref()
                .map(|dest| dest.fuse_plan().ok_or(Errno(18)))
                .transpose()?;
            return Metadata::namespace(v, path, action, dest)
                .map(Box::new)
                .map(ParentStep::Mutation);
        }
        match self.action.take().unwrap() {
            Action::Mkdir { mode, .. } => v.mkdir_resolved(source, mode)?,
            Action::Mknod { mode, device, .. } => {
                v.mknod_resolved(source, mode, device as u64, self.source.trailing)?
            }
            Action::Symlink(target) => v.symlink_resolved(source, &target, self.source.trailing)?,
            Action::Link(original) => {
                v.link_resolved(&original.path, &source, Some(&original.node), None)?
            }
            Action::Unlink { directory } => {
                v.unlink_resolved(source, directory, self.source.trailing)?
            }
            Action::Rename { flags } => v.rename_resolved(
                source,
                dest.unwrap(),
                flags,
                self.source.trailing,
                self.dest.as_ref().unwrap().trailing,
            )?,
        }
        Ok(ParentStep::Complete(FileValue::Count(0)))
    }
}
