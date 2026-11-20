// SPDX-License-Identifier: GPL-3.0-or-later
//! Descriptor-backed mount construction. Detached trees only become visible
//! to namespace observers when the complete tree is attached.
use super::*;

pub enum MountFdCall {
    Open {
        kind: Vec<u8>,
        flags: u32,
    },
    Config {
        fd: u32,
        cmd: u32,
        key: Option<Vec<u8>>,
        value: Option<Vec<u8>>,
    },
    Mount {
        fd: u32,
        flags: u32,
        attrs: u32,
    },
    Tree {
        fd: i32,
        path: Vec<u8>,
        flags: u32,
    },
    Move {
        from: i32,
        source: Vec<u8>,
        to: i32,
        target: Vec<u8>,
        flags: u32,
    },
}
const EMPTY: u32 = 0x1000;
const RECURSIVE: u32 = 0x8000;
impl MountFdCall {
    pub(crate) fn operands(&self) -> Vec<(i32, Option<&[u8]>, bool)> {
        fn operand(fd: i32, path: &[u8], follow: bool) -> (i32, Option<&[u8]>, bool) {
            (fd, (!path.is_empty()).then_some(path), follow)
        }
        match self {
            Self::Open { .. } => vec![],
            Self::Config { fd, .. } | Self::Mount { fd, .. } => vec![(*fd as i32, None, false)],
            Self::Tree { fd, path, flags } => vec![operand(*fd, path, flags & 0x100 == 0)],
            Self::Move {
                from,
                source,
                to,
                target,
                flags,
            } => vec![
                operand(*from, source, flags & 1 != 0),
                operand(*to, target, flags & 0x10 != 0),
            ],
        }
    }
    pub(crate) fn topology(&self) -> bool {
        matches!(
            self,
            Self::Move { .. } | Self::Mount { .. } | Self::Tree { .. }
        )
    }
    pub(crate) fn run(&self, v: &mut Vfs) -> Result<u64> {
        match self {
            Self::Open { kind, flags } => v.fsopen(kind, *flags).map(u64::from),
            Self::Config {
                fd,
                cmd,
                key,
                value,
            } => {
                v.fsconfigure(*fd, *cmd, key.as_deref(), value.as_deref())?;
                Ok(0)
            }
            Self::Mount { fd, flags, attrs } => v.fsmount(*fd, *flags, *attrs).map(u64::from),
            Self::Tree { fd, path, flags } => v.open_tree(*fd, path, *flags).map(u64::from),
            Self::Move {
                from,
                source,
                to,
                target,
                flags,
            } => {
                v.move_mount_fd(*from, source, *to, target, *flags)?;
                Ok(0)
            }
        }
    }
}

pub(crate) struct FsContext {
    creator: Credentials,
    kind: Kind,
    pid: PidNamespace,
    net_owner: UserNamespace,
    state: std::sync::Mutex<ContextState>,
}
enum Phase {
    Parameters,
    Created(Arc<Mount>),
    Mounted(FsHandle),
}
struct ContextState {
    source: Option<Vec<u8>>,
    parameters: BTreeMap<Vec<u8>, Vec<u8>>,
    readonly: bool,
    phase: Phase,
}
/// The originating OFD owns the detached tree. Membership moves to its new
/// parent (or namespace) on attach. Mount identities only point back weakly.
pub(crate) struct TreeOrigin {
    owner: UserNamespace,
    tree: std::sync::Weak<DetachedTree>,
}
pub(crate) struct DetachedTree {
    root: Arc<Mount>,
    namespace: u64,
    members: SharedCell<Vec<Arc<Mount>>>,
}
impl Vfs {
    fn can_mount(&self) -> Result<&MountNamespace> {
        let ns = self.mounts.as_ref().ok_or(Errno(22))?;
        if !self
            .credentials
            .has_ns_cap(&ns.0.borrow().user_namespace, capabilities::SYS_ADMIN)
        {
            return Err(Errno(1));
        }
        Ok(ns)
    }
    fn fsopen(&mut self, kind: &[u8], flags: u32) -> Result<u32> {
        self.can_mount()?;
        if flags & !1 != 0 {
            return Err(Errno(22));
        }
        let kind = match kind {
            b"tmpfs" => Kind::Tmpfs,
            b"proc" => Kind::Proc,
            b"sysfs" => Kind::Sysfs,
            b"cgroup2" | b"mqueue" | b"devpts" | b"overlay" => return Err(Errno(95)),
            _ => return Err(Errno(19)),
        };
        self.anonymous(
            if flags == 1 { O_CLOEXEC } else { 0 },
            events::Anonymous::FsContext(Arc::new(FsContext {
                creator: self.credentials.clone(),
                kind,
                pid: self.pid_ns.clone(),
                net_owner: self.root_network.user_namespace.clone(),
                state: std::sync::Mutex::new(ContextState {
                    source: None,
                    parameters: BTreeMap::new(),
                    readonly: false,
                    phase: Phase::Parameters,
                }),
            })),
        )
    }
    fn fs_context(&self, fd: u32) -> Result<Arc<FsContext>> {
        let desc = self.descriptor(fd)?;
        let o = desc.open.borrow();
        match &o.control {
            Some(events::SharedControl::FsContext(ctx)) if o.flags.get() & O_PATH == 0 => {
                Ok(ctx.clone())
            }
            _ => Err(Errno(22)),
        }
    }
    fn fsconfigure(
        &mut self,
        fd: u32,
        cmd: u32,
        key: Option<&[u8]>,
        value: Option<&[u8]>,
    ) -> Result<()> {
        let ctx = self.fs_context(fd)?;
        let mut state = ctx.state.lock().unwrap();
        if matches!(state.phase, Phase::Created(_))
            || matches!(state.phase, Phase::Mounted(_)) && matches!(cmd, 6 | 8)
            || matches!(state.phase, Phase::Parameters) && cmd == 7
        {
            return Err(Errno(16));
        }
        match (cmd, key, value) {
            (0, Some(key @ (b"ro" | b"rw")), None) => state.readonly = key == b"ro",
            (1, Some(b"source"), Some(src))
                if state.source.is_none() && matches!(state.phase, Phase::Parameters) =>
            {
                state.source = Some(src.to_vec())
            }
            (1, Some(key), Some(value))
                if ctx.kind == Kind::Tmpfs
                    && matches!(
                        key,
                        b"mode" | b"size" | b"nr_blocks" | b"nr_inodes" | b"uid" | b"gid"
                    ) =>
            {
                if matches!(state.phase, Phase::Mounted(_))
                    && matches!(key, b"mode" | b"uid" | b"gid")
                {
                    return Err(Errno(95));
                }
                if value.contains(&b',') {
                    return Err(Errno(22));
                }
                let option = [key, b"=", value].concat();
                tmpfs_options(&option, self.pseudo.borrow().runtime.memory_limit as u64)?;
                // Both size spellings set the same limit; the last call wins.
                if key == b"size" {
                    state.parameters.remove(b"nr_blocks".as_slice());
                }
                if key == b"nr_blocks" {
                    state.parameters.remove(b"size".as_slice());
                }
                state.parameters.insert(key.to_vec(), option);
            }
            (6..=8, None, None) => {
                if !self
                    .credentials
                    .has_ns_cap(&ctx.creator.user_namespace, capabilities::SYS_ADMIN)
                {
                    return Err(Errno(1));
                }
                let owner = match ctx.kind {
                    Kind::Proc => ctx.pid.user_namespace(),
                    Kind::Sysfs => &ctx.net_owner,
                    _ => &ctx.creator.user_namespace,
                };
                if !self.credentials.has_ns_cap(owner, capabilities::SYS_ADMIN) {
                    return Err(Errno(1));
                }
                let options: Vec<_> = state.parameters.values().map(Vec::as_slice).collect();
                let data = options.join(&b',');
                let (limit, nodes, mode, uid, gid) =
                    tmpfs_options(&data, self.pseudo.borrow().runtime.memory_limit as u64)?;
                if cmd == 7 {
                    let Phase::Mounted(fs) = &state.phase else {
                        return Err(Errno(16));
                    };
                    let ro = fs.super_readonly.as_ref().ok_or(Errno(95))?;
                    let mut data = fs.borrow_mut();
                    let capacity = Vfs::filesystem_capacity(&data);
                    if capacity.nodes_used > nodes || capacity.used_bytes > limit {
                        return Err(Errno(22));
                    }
                    data.limits = StorageLimits {
                        file_bytes: limit,
                        nodes,
                    };
                    data.quota.configure(limit, data.volume);
                    ro.store(state.readonly, Ordering::Relaxed);
                    return Ok(());
                }
                let (fs, root, root_key) = match ctx.kind {
                    Kind::Tmpfs => {
                        let mut fs = ram_filesystem(
                            limit,
                            nodes,
                            mode,
                            uid.unwrap_or(ctx.creator.fsuid),
                            gid.unwrap_or(ctx.creator.fsgid),
                            true,
                        )?;
                        fs.super_readonly =
                            Some(Arc::new(std::sync::atomic::AtomicBool::new(state.readonly)));
                        let root = fs.borrow().paths[b"/".as_slice()].clone();
                        (fs, root, b"/".to_vec())
                    }
                    Kind::Proc | Kind::Sysfs => {
                        let key = if ctx.kind == Kind::Proc {
                            b"/proc".as_slice()
                        } else {
                            b"/sys"
                        };
                        (
                            self.fs.clone(),
                            self.pseudo_node(key)?.ok_or(Errno(19))?,
                            key.to_vec(),
                        )
                    }
                    _ => return Err(Errno(19)),
                };
                state.phase = Phase::Created(Arc::new(Mount::new(MountInit {
                    id: new_mount_id()?,
                    fs,
                    root,
                    root_key,
                    kind: ctx.kind,
                    display: MountDisplay {
                        source: Some(Arc::from(
                            state
                                .source
                                .as_deref()
                                .filter(|s| !s.is_empty())
                                .unwrap_or(b"none"),
                        )),
                        tmpfs_mode: (mode != 0o1777).then_some(mode),
                    },
                    namespace: None,
                    pid_namespace: (ctx.kind == Kind::Proc).then(|| ctx.pid.clone()),
                    devpts: None,
                    flags: Cell::new(if state.readonly { MS_RDONLY } else { 0 }),
                    writers: Arc::default(),
                    parent: RefCell::new(None),
                })));
            }
            _ => return Err(Errno(22)),
        }
        Ok(())
    }
    fn fsmount(&mut self, fd: u32, flags: u32, attrs: u32) -> Result<u32> {
        self.can_mount()?;
        if flags & !1 != 0 || attrs & !0xbf != 0 {
            return Err(Errno(22));
        }
        let atime = match attrs & 0x30 {
            0 => MS_RELATIME,
            0x10 => MS_NOATIME,
            0x20 => 0,
            _ => return Err(Errno(22)),
        };
        let ctx = self.fs_context(fd)?;
        let mut state = ctx.state.lock().unwrap();
        let root = match &state.phase {
            Phase::Parameters => return Err(Errno(22)),
            Phase::Mounted(_) => return Err(Errno(16)),
            Phase::Created(root) => copy_mount(root)?,
        };
        let attrs = (attrs & 15) as u64 | atime | if attrs & 0x80 != 0 { MS_NODIRATIME } else { 0 };
        let local = attrs
            | if root.kind == Kind::Sysfs || root.kind != Kind::Tmpfs && state.readonly {
                MS_RDONLY
            } else {
                0
            };
        let locked = self.visible_pseudo_flags(root.kind, local)?;
        root.inherited.store(locked, Ordering::Relaxed);
        root.flags.set(local);
        let fs = root.fs.clone();
        let result = self.tree_descriptor(root.clone(), vec![root], flags == 1)?;
        state.phase = Phase::Mounted(fs);
        Ok(result)
    }
    fn mount_operand(
        &self,
        fd: i32,
        path: &[u8],
        follow: bool,
        empty: bool,
    ) -> Result<ResolvedPath> {
        if !path.is_empty() {
            return self.mount_location_at(fd, path, follow);
        }
        if !empty {
            return Err(Errno(2));
        }
        if fd == AT_FDCWD {
            return self.mount_location(b".", true);
        }
        let desc = self.descriptor(fd as u32)?;
        let o = desc.open.borrow();
        if let Some(events::SharedControl::MountTree(tree)) = &o.control {
            return self.location(&tree.root.root, &Some(tree.root.clone()));
        }
        self.location(
            o.node.as_ref().ok_or(Errno(22))?,
            &self.mount_for_path(o.mount.as_ref()),
        )
    }
    fn mount_path_descriptor(
        &mut self,
        mount: Arc<Mount>,
        node: NodeRef,
        key: Vec<u8>,
        cloexec: bool,
        tree: Option<Arc<DetachedTree>>,
    ) -> Result<u32> {
        let reserved = self.shared_files().reserve()?;
        let d = events::mounted_resource_descriptor(
            self.open_id(),
            O_PATH | if cloexec { O_CLOEXEC } else { 0 },
            FdKind::Node(key),
            Some(node),
            tree.map(events::SharedControl::MountTree),
            None,
            Some(OpenMount::Owner(mount)),
        );
        reserved.publish(d, self.query.is_none().then_some(&self.fds))
    }
    fn tree_descriptor(
        &mut self,
        root: Arc<Mount>,
        members: Vec<Arc<Mount>>,
        cloexec: bool,
    ) -> Result<u32> {
        let tree = Arc::new(DetachedTree {
            root: root.clone(),
            namespace: self.mounts.as_ref().ok_or(Errno(22))?.id(),
            members: SharedCell::new(members),
        });
        self.register_mounts(&tree.members.borrow())?;
        root.anonymous_tree
            .set(TreeOrigin {
                owner: self.credentials.user_namespace.clone(),
                tree: Arc::downgrade(&tree),
            })
            .map_err(|_| Errno(16))?;
        self.mount_path_descriptor(
            root.clone(),
            root.root.clone(),
            root.root_key.clone(),
            cloexec,
            Some(tree),
        )
    }
    fn open_tree(&mut self, fd: i32, path: &[u8], flags: u32) -> Result<u32> {
        if flags & !(1 | O_CLOEXEC | 0x100 | 0x800 | EMPTY | RECURSIVE) != 0
            || flags & RECURSIVE != 0 && flags & 1 == 0
        {
            return Err(Errno(22));
        }
        if flags & 1 != 0 {
            self.can_mount()?;
        }
        let p = self.mount_operand(fd, path, flags & 0x100 == 0, flags & EMPTY != 0)?;
        let node = self.node(&p)?;
        let m = p.mount.as_ref().ok_or(Errno(22))?;
        if flags & 1 == 0 {
            return self.mount_path_descriptor(
                m.clone(),
                node,
                p.key,
                flags & O_CLOEXEC != 0,
                None,
            );
        }
        let ns = self.mounts.as_ref().ok_or(Errno(22))?;
        let is_attached = ns.0.borrow().mounts.iter().any(|src| Arc::ptr_eq(src, m));
        let tree = detached(m, ns.id());
        if !is_attached && tree.is_none() {
            return Err(Errno(22));
        }
        if flags & RECURSIVE == 0
            && tree.as_ref().map_or_else(
                || hides_locked_child(&ns.0.borrow().mounts, m, &p.key),
                |tree| hides_locked_child(&tree.members.borrow(), m, &p.key),
            )
        {
            return Err(Errno(22));
        }
        let root = copy_mount_root(m, node, p.key.clone())?;
        root.inherited
            .fetch_and(!LOCK_ATTACHMENT, Ordering::Relaxed);
        let mut members = vec![root.clone()];
        if flags & RECURSIVE != 0 {
            let source = tree.map_or_else(
                || ns.0.borrow().mounts.clone(),
                |t| t.members.borrow().clone(),
            );
            let mut index = 0;
            let mut originals = vec![m.clone()];
            while index < originals.len() {
                let old = originals[index].clone();
                for child in &source {
                    let Some(link) = child.parent.borrow().clone() else {
                        continue;
                    };
                    if !Arc::ptr_eq(&link.parent, &old) || index == 0 && !below(&link.key(), &p.key)
                    {
                        continue;
                    }
                    let copy = copy_mount(child)?;
                    *copy.parent.borrow_mut() = Some(Attachment {
                        parent: members[index].clone(),
                        node: link.node,
                        fallback: link.fallback,
                    });
                    originals.push(child.clone());
                    members.push(copy);
                }
                index += 1;
            }
        }
        self.tree_descriptor(root, members, flags & O_CLOEXEC != 0)
    }
    fn move_mount_fd(
        &mut self,
        from: i32,
        source: &[u8],
        to: i32,
        target: &[u8],
        flags: u32,
    ) -> Result<()> {
        let ns = self.can_mount()?.clone();
        if flags & !0x77 != 0 {
            return Err(Errno(22));
        }
        let src = self.mount_operand(from, source, flags & 1 != 0, flags & 4 != 0)?;
        let dst = self.mount_operand(to, target, flags & 0x10 != 0, flags & 0x40 != 0)?;
        let moved = src.mount.as_ref().ok_or(Errno(22))?;
        let parent = dst.mount.as_ref().ok_or(Errno(22))?.clone();
        let node = self.node(&dst)?;
        if !self.is_mount_root(&src) {
            return Err(Errno(22));
        }
        let attached = |m: &Arc<Mount>| ns.0.borrow().mounts.iter().any(|old| Arc::ptr_eq(old, m));
        if attached(moved) {
            if !attached(&parent) {
                return Err(Errno(22));
            }
            return self.move_attached(&src, &dst, parent, node);
        }
        let tree = detached(moved, ns.id()).ok_or(Errno(22))?;
        if !Arc::ptr_eq(moved, &tree.root) {
            return Err(Errno(22));
        }
        if matches!(moved.root.borrow().content, Content::Directory)
            != matches!(node.borrow().content, Content::Directory)
        {
            return Err(Errno(22));
        }
        let parent_tree = detached(&parent, ns.id());
        if let Some(t) = &parent_tree {
            if Arc::ptr_eq(t, &tree) {
                return Err(Errno(40));
            }
            if t.members.borrow().len() + tree.members.borrow().len() > self.mount_limit() {
                return Err(Errno(28));
            }
        } else if !attached(&parent) {
            return Err(Errno(22));
        }
        let mut members = tree.members.borrow_mut();
        let link = Attachment {
            parent,
            node,
            fallback: dst.key,
        };
        if let Some(parent_tree) = parent_tree {
            *moved.parent.borrow_mut() = Some(link);
            parent_tree.members.borrow_mut().append(&mut members);
        } else {
            let old = moved.propagation();
            if let Err(e) = self.publish_mounts_at(&ns, members.clone(), link) {
                moved.set_propagation(old);
                return Err(e);
            }
            members.clear();
        }
        Ok(())
    }
}
fn topology_root(mount: &Arc<Mount>) -> Arc<Mount> {
    let mut root = mount.clone();
    loop {
        let parent = root.parent.borrow().as_ref().map(|a| a.parent.clone());
        match parent {
            Some(parent) => root = parent,
            None => break,
        }
    }
    root
}
pub(crate) fn check_overlay_layer(mount: &Arc<Mount>, credentials: &Credentials) -> Result<()> {
    // The layer can outlive the originating FD. Keep its creator's user
    // namespace on the root even after the detached tree owner is released.
    if topology_root(mount)
        .anonymous_tree
        .get()
        .is_some_and(|origin| !credentials.has_ns_cap(&origin.owner, capabilities::SYS_ADMIN))
    {
        return Err(Errno(1));
    }
    Ok(())
}
fn detached(mount: &Arc<Mount>, namespace: u64) -> Option<Arc<DetachedTree>> {
    topology_root(mount)
        .anonymous_tree
        .get()?
        .tree
        .upgrade()
        .filter(|tree| tree.namespace == namespace && !tree.members.borrow().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detached_layer_retains_its_user_namespace_after_close() {
        let mut v = Vfs::default();
        let fd = v.open_tree(AT_FDCWD, b"/", 1).unwrap();
        let desc = v.descriptor(fd).unwrap();
        let mount = v.mount_for_path(desc.open.borrow().mount.as_ref()).unwrap();
        assert_eq!(check_overlay_layer(&mount, &v.credentials), Ok(()));
        drop(desc);
        v.close(fd).unwrap();
        v.unshare_user().unwrap();
        assert_eq!(check_overlay_layer(&mount, &v.credentials), Err(Errno(1)));
    }
    #[test]
    fn descriptor_exhaustion_preserves_context_and_reconfiguration_reaches_bind_aliases() {
        let mut v = Vfs::default();
        let ctx = v.fsopen(b"tmpfs", 1).unwrap();
        let alias = v.dup(ctx, 0, false).unwrap();
        v.close(ctx).unwrap();
        v.fsconfigure(alias, 6, None, None).unwrap();
        let limit = v.descriptor_limit();
        v.set_descriptor_limit(3);
        assert_eq!(v.fsmount(alias, 1, 0), Err(Errno(24)));
        v.set_descriptor_limit(limit);
        let root = v.fsmount(alias, 1, 0).unwrap();
        v.mkdir_at(AT_FDCWD, b"/first", 0o755).unwrap();
        v.mkdir_at(AT_FDCWD, b"/second", 0o755).unwrap();
        v.move_mount_fd(root as i32, b"", AT_FDCWD, b"/first", 4)
            .unwrap();
        v.mount(Some(b"/first"), b"/second", None, 4096, None)
            .unwrap();
        v.fsconfigure(alias, 0, Some(b"ro"), None).unwrap();
        v.fsconfigure(alias, 1, Some(b"nr_inodes"), Some(b"12345"))
            .unwrap();
        v.fsconfigure(alias, 7, None, None).unwrap();
        let flags = |st: [u8; 120]| u64::from_le_bytes(st[80..88].try_into().unwrap());
        for path in [b"/first".as_slice(), b"/second"] {
            assert_ne!(flags(v.statfs_at(path).unwrap()) & MS_RDONLY, 0);
            assert_eq!(
                u64::from_le_bytes(v.statfs_at(path).unwrap()[40..48].try_into().unwrap()),
                12345
            );
        }
        assert_eq!(v.mkdir_at(root as i32, b"blocked", 0o755), Err(Errno(30)));
        v.mount(None, b"/second", None, 4096 | 32 | MS_RDONLY, None)
            .unwrap();
        v.fsconfigure(alias, 0, Some(b"rw"), None).unwrap();
        v.fsconfigure(alias, 7, None, None).unwrap();
        assert_eq!(flags(v.statfs_fd(root).unwrap()) & MS_RDONLY, 0);
        assert_ne!(flags(v.statfs_at(b"/second").unwrap()) & MS_RDONLY, 0);
    }
}
