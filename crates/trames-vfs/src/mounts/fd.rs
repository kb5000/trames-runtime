// SPDX-License-Identifier: GPL-3.0-or-later
//! Descriptor-backed mount construction. Detached trees only become visible
//! to namespace observers when the complete tree is attached.
use super::*;

pub enum MountFdCall {
    Open {
        kind: Vec<u8>,
        flags: u32,
    },
    Pick {
        fd: i32,
        path: Vec<u8>,
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
    SetAttr {
        fd: i32,
        path: Vec<u8>,
        flags: u32,
        attrs: MountAttributes,
    },
}
const EMPTY: u32 = 0x1000;
const RECURSIVE: u32 = 0x8000;

pub struct MountAttributes {
    set: u64,
    clear: u64,
    propagation: u64,
    idmap_requested: bool,
    idmap: Option<Arc<idmap::MountIdmap>>,
}

impl MountAttributes {
    pub fn new(set: u64, clear: u64, propagation: u64) -> Result<Self> {
        const ATTR_ATIME: u64 = 0x70;
        const ATTR_IDMAP: u64 = 0x100000;
        const ATTR_NOSYMFOLLOW: u64 = 0x200000;
        if (set | clear) & !(0xff | ATTR_IDMAP | ATTR_NOSYMFOLLOW) != 0
            || clear & ATTR_IDMAP != 0
            || !matches!(propagation, 0 | 0x20000 | 0x40000 | 0x80000 | 0x100000)
        {
            return Err(Errno(22));
        }
        let atime = match (set & ATTR_ATIME, clear & ATTR_ATIME) {
            (0, 0) => (0, 0),
            (0, ATTR_ATIME) => (MS_RELATIME, MS_NOATIME | MS_RELATIME),
            (0x10, ATTR_ATIME) => (MS_NOATIME, MS_NOATIME | MS_RELATIME),
            (0x20, ATTR_ATIME) => (0, MS_NOATIME | MS_RELATIME),
            _ => return Err(Errno(22)),
        };
        let ordinary = |attrs| {
            attrs & 15
                | if attrs & 0x80 != 0 { MS_NODIRATIME } else { 0 }
                | if attrs & ATTR_NOSYMFOLLOW != 0 {
                    MS_NOSYMFOLLOW
                } else {
                    0
                }
        };
        Ok(Self {
            set: ordinary(set) | atime.0,
            clear: ordinary(clear) | atime.1,
            propagation,
            idmap_requested: set & ATTR_IDMAP != 0,
            idmap: None,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.set == 0 && self.clear == 0 && self.propagation == 0 && !self.idmap_requested
    }
    pub fn needs_idmap(&self) -> bool {
        self.idmap_requested
    }
    pub fn with_idmap(mut self, idmap: Arc<idmap::MountIdmap>) -> Self {
        self.idmap = Some(idmap);
        self
    }
}

impl MountFdCall {
    pub(crate) fn operands(&self) -> Vec<(i32, Option<&[u8]>, bool)> {
        fn operand(fd: i32, path: &[u8], follow: bool) -> (i32, Option<&[u8]>, bool) {
            (fd, (!path.is_empty()).then_some(path), follow)
        }
        match self {
            Self::Open { .. } => vec![],
            Self::Pick { fd, path, flags } => vec![operand(*fd, path, flags & 2 == 0)],
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
            Self::SetAttr {
                fd,
                path,
                flags,
                attrs,
            } => {
                if attrs.is_empty() {
                    return Vec::new();
                }
                let path = if path.is_empty() && *flags & EMPTY != 0 && *fd == AT_FDCWD {
                    b".".as_slice()
                } else {
                    path
                };
                vec![operand(*fd, path, flags & 0x100 == 0)]
            }
        }
    }
    pub(crate) fn topology(&self) -> bool {
        matches!(
            self,
            Self::Move { .. } | Self::Mount { .. } | Self::Tree { .. } | Self::Pick { .. }
        ) || matches!(self, Self::SetAttr { attrs, .. } if !attrs.is_empty())
    }
    pub(crate) fn run(&self, v: &mut Vfs) -> Result<u64> {
        match self {
            Self::Open { kind, flags } => v.fsopen(kind, *flags).map(u64::from),
            Self::Pick { fd, path, flags } => v.fspick(*fd, path, *flags).map(u64::from),
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
            Self::SetAttr {
                fd,
                path,
                flags,
                attrs,
            } => {
                v.mount_setattr(*fd, path, *flags, attrs)?;
                Ok(0)
            }
        }
    }
}

pub(crate) struct FsContext {
    creator: Credentials,
    owner: UserNamespace,
    kind: Kind,
    pid: PidNamespace,
    net: Arc<linux_namespace::RootNetwork>,
    devpts: Option<Arc<pty::Devpts>>,
    ipc: Arc<linux_namespace::IpcNamespace>,
    cgroup: Arc<linux_namespace::CgroupNamespace>,
    cgroup_fs: FsHandle,
    state: std::sync::Mutex<ContextState>,
}
enum Phase {
    Parameters,
    Created(Arc<Mount>),
    Mounted(FsHandle),
    Reconfigure(FsHandle),
}
struct ContextState {
    source: Option<Vec<u8>>,
    parameters: BTreeMap<Vec<u8>, Vec<u8>>,
    readonly: Option<bool>,
    phase: Phase,
    layers: overlay::MountConfig,
    devpts: Option<Arc<pty::Devpts>>,
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
    pub fn check_mount_admin(&self) -> Result<()> {
        self.can_mount().map(|_| ())
    }

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
    fn mount_setattr(
        &self,
        fd: i32,
        path: &[u8],
        flags: u32,
        attrs: &MountAttributes,
    ) -> Result<()> {
        let ns = self.can_mount()?;
        if attrs.is_empty() {
            return Ok(());
        }
        let target = self.mount_operand(fd, path, flags & 0x100 == 0, flags & EMPTY != 0)?;
        if !self.is_mount_root(&target) {
            return Err(Errno(22));
        }
        let root = target.mount.as_ref().ok_or(Errno(22))?;
        let idmap = if attrs.idmap_requested {
            Some(attrs.idmap.as_ref().ok_or(Errno(22))?)
        } else {
            None
        };
        let attached = ns.0.borrow().mounts.iter().any(|m| Arc::ptr_eq(m, root));
        let members = if attached {
            ns.0.borrow().mounts.clone()
        } else {
            let tree = detached(root, ns.id()).ok_or(Errno(22))?;
            if !Arc::ptr_eq(root, &tree.root) {
                return Err(Errno(22));
            }
            let members = tree.members.borrow().clone();
            members
        };
        let mut selected = vec![root.clone()];
        if flags & RECURSIVE != 0 {
            let mut children = BTreeMap::<u64, Vec<Arc<Mount>>>::new();
            for member in members {
                let parent = member.parent.borrow().as_ref().map(|link| link.parent.id);
                if let Some(parent) = parent {
                    children.entry(parent).or_default().push(member);
                }
            }
            let mut i = 0;
            while let Some(mount) = selected.get(i) {
                if let Some(nested) = children.remove(&mount.id) {
                    selected.extend(nested);
                }
                i += 1;
            }
        }

        let mut updates = Vec::new();
        let mut writer_gates = Vec::new();
        for mount in &selected {
            let old = mount.flags.local();
            let new = (old & !attrs.clear) | attrs.set;
            let changed = old ^ new;
            if let Some(idmap) = idmap {
                if idmap.namespace == mount.fs.owner {
                    return Err(Errno(22));
                }
                if mount.idmap.get().is_some() {
                    return Err(Errno(1));
                }
                if !mount.idmap_supported() {
                    return Err(Errno(22));
                }
                if !self
                    .credentials
                    .has_ns_cap(&mount.fs.owner, capabilities::SYS_ADMIN)
                {
                    return Err(Errno(1));
                }
                if attached {
                    return Err(Errno(22));
                }
            }
            if changed == 0 && idmap.is_none() {
                continue;
            }
            if mount.inherited.load(Ordering::Relaxed) & changed != 0 {
                return Err(Errno(1));
            }
            if changed & new & MS_RDONLY != 0 || idmap.is_some() {
                writer_gates.push(mount.hold_mount_writers()?);
                if idmap.is_some() && mount.idmap.get().is_some() {
                    return Err(Errno(1));
                }
            }
            updates.push((mount, new));
        }
        let propagation = if attrs.propagation == 0 {
            Vec::new()
        } else {
            self.plan_propagation(&selected, attrs.propagation)?
        };
        // Validation and peer-group allocation finish before any publication.
        for (mount, new) in updates {
            if let Some(idmap) = idmap {
                assert!(
                    mount.idmap.set(idmap.mapping.clone()).is_ok(),
                    "original mount admitted once"
                );
            }
            mount.flags.set(new);
        }
        for (mount, state) in propagation {
            mount.set_propagation(state);
        }
        if attrs.propagation != 0 {
            self.normalize_propagation();
        }
        ns.0.borrow().events.changed();
        Ok(())
    }
    fn fsopen(&mut self, kind: &[u8], flags: u32) -> Result<u32> {
        self.can_mount()?;
        if flags & !1 != 0 {
            return Err(Errno(22));
        }
        let kind = match kind {
            b"tmpfs" => Kind::Tmpfs,
            b"ramfs" => Kind::Ramfs,
            b"debugfs" => {
                if !self.credentials.has_cap(capabilities::SYS_ADMIN) {
                    return Err(Errno(1));
                }
                Kind::Debugfs
            }
            b"proc" => Kind::Proc,
            b"sysfs" => Kind::Sysfs,
            b"cgroup2" => Kind::Cgroup,
            b"mqueue" => Kind::Mqueue,
            b"devpts" => Kind::Devpts,
            b"overlay" => Kind::Overlay,
            _ => return Err(Errno(19)),
        };
        let cgroup_fs = self.cgroups.borrow().fs.clone();
        self.anonymous(
            if flags == 1 { O_CLOEXEC } else { 0 },
            events::Anonymous::FsContext(Arc::new(FsContext {
                creator: self.credentials.clone(),
                owner: self.credentials.user_namespace.clone(),
                kind,
                pid: self.pid_ns.clone(),
                net: self.root_network.clone(),
                devpts: None,
                ipc: self.ipc_namespace.clone(),
                cgroup: self.cgroup_namespace.clone(),
                cgroup_fs,
                state: std::sync::Mutex::new(ContextState {
                    source: None,
                    parameters: BTreeMap::new(),
                    readonly: None,
                    phase: Phase::Parameters,
                    layers: Default::default(),
                    devpts: None,
                }),
            })),
        )
    }
    fn fspick(&mut self, fd: i32, path: &[u8], flags: u32) -> Result<u32> {
        self.can_mount()?;
        if flags & !15 != 0 {
            return Err(Errno(22));
        }
        let target = self.mount_operand(fd, path, flags & 2 == 0, flags & 8 != 0)?;
        if !self.is_mount_root(&target) {
            return Err(Errno(22));
        }
        let mount = target.mount.as_ref().ok_or(Errno(22))?;
        let pid = match &mount.fs.super_namespace {
            Some(linux_namespace::SharedNamespace::Pid(pid)) => pid.clone(),
            _ => mount
                .pid_namespace
                .clone()
                .unwrap_or_else(|| self.pid_ns.clone()),
        };
        let net = match &mount.fs.super_namespace {
            Some(linux_namespace::SharedNamespace::Net(net)) => net.clone(),
            _ => self.root_network.clone(),
        };
        let cgroup_fs = self.cgroups.borrow().fs.clone();
        self.anonymous(
            if flags & 1 != 0 { O_CLOEXEC } else { 0 },
            events::Anonymous::FsContext(Arc::new(FsContext {
                creator: self.credentials.clone(),
                owner: mount.fs.owner.clone(),
                kind: mount.kind,
                pid,
                net,
                devpts: mount.devpts.clone(),
                ipc: self.ipc_namespace.clone(),
                cgroup: self.cgroup_namespace.clone(),
                cgroup_fs,
                state: std::sync::Mutex::new(ContextState {
                    source: None,
                    parameters: BTreeMap::new(),
                    readonly: None,
                    phase: Phase::Reconfigure(mount.fs.clone()),
                    layers: Default::default(),
                    devpts: mount.devpts.clone(),
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
    fn context_pseudo_root(&mut self, ctx: &FsContext, key: &[u8]) -> Result<NodeRef> {
        struct Restore<'a> {
            view: &'a mut Vfs,
            pid: Option<PidNamespace>,
            net: Option<(Arc<linux_namespace::RootNetwork>, trames_net::Network)>,
        }
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                if let Some(pid) = self.pid.take() {
                    self.view.pid_ns = pid;
                }
                if let Some((net, network)) = self.net.take() {
                    self.view.root_network = net;
                    self.view.network = network;
                }
            }
        }
        let pid =
            (ctx.kind == Kind::Proc).then(|| std::mem::replace(&mut self.pid_ns, ctx.pid.clone()));
        let net = if ctx.kind == Kind::Sysfs {
            let network = ctx.net.network.borrow().clone();
            Some((
                std::mem::replace(&mut self.root_network, ctx.net.clone()),
                std::mem::replace(&mut self.network, network),
            ))
        } else {
            None
        };
        let scope = Restore {
            view: self,
            pid,
            net,
        };
        scope.view.pseudo_node(key)?.ok_or(Errno(19))
    }
    fn reconfigure_context(&self, ctx: &FsContext, state: &mut ContextState) -> Result<()> {
        let fs = match &state.phase {
            Phase::Mounted(fs) | Phase::Reconfigure(fs) => fs,
            _ => return Err(Errno(16)),
        };
        if !self
            .credentials
            .has_ns_cap(&ctx.owner, capabilities::SYS_ADMIN)
        {
            return Err(Errno(1));
        }
        let _writers = state
            .readonly
            .filter(|ro| *ro && !fs.super_readonly.as_ref().unwrap().load(Ordering::Relaxed))
            .map(|_| fs.hold_writers())
            .transpose()?;
        self.reconfigure_filesystem(
            ctx.kind,
            fs,
            state.devpts.as_deref().or(ctx.devpts.as_deref()),
            &state.parameters,
            state.readonly,
        )?;
        state.parameters.clear();
        state.readonly = None;
        Ok(())
    }
    // Caller holds the existing superblock writer gate for a read-only transition.
    pub(super) fn reconfigure_filesystem(
        &self,
        kind: Kind,
        fs: &FsHandle,
        devpts: Option<&pty::Devpts>,
        parameters: &BTreeMap<Vec<u8>, Vec<u8>>,
        readonly_request: Option<bool>,
    ) -> Result<()> {
        if !self
            .credentials
            .has_ns_cap(&fs.owner, capabilities::SYS_ADMIN)
        {
            return Err(Errno(1));
        }
        let readonly = fs.super_readonly.as_ref().ok_or(Errno(95))?;
        if readonly_request == Some(false) {
            if fs.borrow().overlay.as_ref().is_some_and(|o| !o.has_upper()) {
                return Err(Errno(30));
            }
            #[cfg(all(feature = "hostfs", unix))]
            if let Some(host) = &fs.host {
                host.reconfigure_writable()?;
            }
        }
        let options: Vec<_> = parameters.values().map(Vec::as_slice).collect();
        let options = options.join(&b',');
        if kind == Kind::Cgroup {
            if let Some(value) = self.cgroup_mount_options(Some(&options))? {
                self.cgroups
                    .borrow()
                    .nsdelegate
                    .store(value, Ordering::Relaxed);
            }
        } else if kind == Kind::Devpts {
            if let Some(devpts) = devpts {
                devpts.reconfigure(&options)?;
            } else if !options.is_empty() {
                return Err(Errno(95));
            }
        } else if kind == Kind::Tmpfs {
            let (limit, nodes, _, _, _) =
                tmpfs_options(&options, self.pseudo.borrow().runtime.memory_limit as u64)?;
            let mut data = fs.borrow_mut();
            let limit = if parameters.contains_key(b"size".as_slice())
                || parameters.contains_key(b"nr_blocks".as_slice())
            {
                limit
            } else {
                data.limits.file_bytes
            };
            let nodes = if parameters.contains_key(b"nr_inodes".as_slice()) {
                nodes
            } else {
                data.limits.nodes
            };
            let capacity = Vfs::filesystem_capacity(&data);
            if capacity.nodes_used > nodes
                || capacity.used_bytes > limit
                || data.limits.file_bytes == u64::MAX && limit != u64::MAX
                || data.limits.nodes == usize::MAX && nodes != usize::MAX
            {
                return Err(Errno(22));
            }
            data.limits = StorageLimits {
                file_bytes: limit,
                nodes,
            };
            data.quota.configure(limit, data.volume);
        } else if kind == Kind::Debugfs && !parameters.is_empty() {
            let root = fs
                .borrow()
                .paths
                .get(b"/".as_slice())
                .cloned()
                .ok_or(Errno(5))?;
            let _metadata = root.metadata.lock().unwrap();
            let mut node = root.borrow_mut();
            let (mode, uid, gid) = special::options(&options, node.mode & 0o7777, true)?;
            node.mode = (node.mode & !0o7777) | mode;
            if let Some(uid) = uid {
                node.uid = uid;
            }
            if let Some(gid) = gid {
                node.gid = gid;
            }
        }
        // Every parameter and writer constraint has succeeded before the
        // superblock flag is made visible to existing bind/OFD aliases.
        if let Some(value) = readonly_request {
            readonly.store(value, Ordering::Relaxed);
        }
        Ok(())
    }
    pub(super) fn mount_parameters(
        &self,
        kind: Kind,
        data: &[u8],
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        let mut parameters = BTreeMap::new();
        for item in data.split(|b| *b == b',').filter(|s| !s.is_empty()) {
            let key = item.split(|b| *b == b'=').next().unwrap();
            let option = if matches!(kind, Kind::Tmpfs | Kind::Debugfs | Kind::Devpts)
                && matches!(key, b"uid" | b"gid")
            {
                let text = item
                    .get(key.len() + 1..)
                    .and_then(|v| std::str::from_utf8(v).ok())
                    .ok_or(Errno(22))?;
                let local = text.parse().map_err(|_| Errno(22))?;
                let global = self.credentials.mapped_id(key == b"gid", local)?;
                [key, b"=", global.to_string().as_bytes()].concat()
            } else {
                item.to_vec()
            };
            match kind {
                Kind::Tmpfs => {
                    tmpfs_options(&option, self.pseudo.borrow().runtime.memory_limit as u64)?;
                }
                Kind::Ramfs | Kind::Debugfs => {
                    special::options(&option, 0o755, kind == Kind::Debugfs)?;
                }
                Kind::Devpts => pty::Devpts::validate(&option)?,
                Kind::Cgroup => {
                    self.cgroup_mount_options(Some(&option))?;
                }
                _ => return Err(Errno(22)),
            }
            if kind == Kind::Tmpfs {
                if key == b"size" {
                    parameters.remove(b"nr_blocks".as_slice());
                }
                if key == b"nr_blocks" {
                    parameters.remove(b"size".as_slice());
                }
            }
            parameters.insert(key.to_vec(), option);
        }
        Ok(parameters)
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
            || matches!(state.phase, Phase::Mounted(_) | Phase::Reconfigure(_))
                && matches!(cmd, 6 | 8)
            || matches!(state.phase, Phase::Parameters) && cmd == 7
        {
            return Err(Errno(16));
        }
        if cmd == 7 {
            self.landlock_check_mount()?;
            if key.is_some() || value.is_some() {
                return Err(Errno(22));
            }
            return self.reconfigure_context(&ctx, &mut state);
        }
        match (cmd, key, value) {
            (0, Some(key @ (b"ro" | b"rw")), None) => state.readonly = Some(key == b"ro"),
            (1, Some(b"source"), Some(src))
                if state.source.is_none() && matches!(state.phase, Phase::Parameters) =>
            {
                state.source = Some(src.to_vec())
            }
            (1, Some(key), Some(value)) if matches!(ctx.kind, Kind::Ramfs | Kind::Debugfs) => {
                if value.contains(&b',') {
                    return Err(Errno(22));
                }
                let option = if ctx.kind == Kind::Debugfs && matches!(key, b"uid" | b"gid") {
                    let local = std::str::from_utf8(value)
                        .ok()
                        .and_then(|s| s.parse::<u32>().ok())
                        .ok_or(Errno(22))?;
                    let global = self.credentials.mapped_id(key == b"gid", local)?;
                    [key, b"=", global.to_string().as_bytes()].concat()
                } else {
                    [key, b"=", value].concat()
                };
                special::options(&option, 0o755, ctx.kind == Kind::Debugfs)?;
                state.parameters.insert(key.to_vec(), option);
            }
            (0, Some(_), None) if matches!(ctx.kind, Kind::Ramfs | Kind::Debugfs) => (),
            (1, Some(key), Some(value))
                if ctx.kind == Kind::Tmpfs
                    && matches!(
                        key,
                        b"mode" | b"size" | b"nr_blocks" | b"nr_inodes" | b"uid" | b"gid"
                    ) =>
            {
                if value.contains(&b',') {
                    return Err(Errno(22));
                }
                let option = if matches!(key, b"uid" | b"gid") {
                    let local = std::str::from_utf8(value)
                        .ok()
                        .and_then(|s| s.parse::<u32>().ok())
                        .ok_or(Errno(22))?;
                    let global = self.credentials.mapped_id(key == b"gid", local)?;
                    [key, b"=", global.to_string().as_bytes()].concat()
                } else {
                    [key, b"=", value].concat()
                };
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
            (
                1,
                Some(key @ (b"lowerdir" | b"lowerdir+" | b"upperdir" | b"workdir")),
                Some(value),
            ) if ctx.kind == Kind::Overlay && matches!(state.phase, Phase::Parameters) => {
                state.layers.configure(self, key, value)?;
            }
            (0, Some(b"userxattr"), None)
                if ctx.kind == Kind::Overlay && matches!(state.phase, Phase::Parameters) =>
            {
                state
                    .parameters
                    .insert(b"userxattr".to_vec(), b"userxattr".to_vec());
            }
            (1, Some(key), Some(value))
                if ctx.kind == Kind::Overlay && matches!(state.phase, Phase::Parameters) =>
            {
                if !matches!(
                    (key, value),
                    (b"index" | b"metacopy", b"off")
                        | (b"redirect_dir", b"off" | b"nofollow")
                        | (b"xino", b"off" | b"auto")
                ) {
                    return Err(Errno(22));
                }
                state
                    .parameters
                    .insert(key.to_vec(), [key, b"=", value].concat());
            }
            (1, Some(key), Some(value)) if ctx.kind == Kind::Devpts => {
                if value.contains(&b',') {
                    return Err(Errno(22));
                }
                let data = [key, b"=", value].concat();
                state
                    .parameters
                    .extend(self.mount_parameters(ctx.kind, &data)?);
            }
            (0, Some(key), None)
                if matches!(
                    (ctx.kind, key),
                    (Kind::Cgroup, b"nsdelegate") | (Kind::Devpts, b"newinstance")
                ) =>
            {
                state
                    .parameters
                    .extend(self.mount_parameters(ctx.kind, key)?);
            }
            (6..=8, None, None) => {
                if !self
                    .credentials
                    .has_ns_cap(&ctx.owner, capabilities::SYS_ADMIN)
                {
                    return Err(Errno(1));
                }
                let owner = match ctx.kind {
                    Kind::Proc => ctx.pid.user_namespace(),
                    Kind::Sysfs => &ctx.net.user_namespace,
                    Kind::Mqueue => &ctx.ipc.user_namespace,
                    Kind::Cgroup => &ctx.cgroup.user_namespace,
                    _ => &ctx.creator.user_namespace,
                };
                if !self.credentials.has_ns_cap(owner, capabilities::SYS_ADMIN) {
                    return Err(Errno(1));
                }
                let options: Vec<_> = state.parameters.values().map(Vec::as_slice).collect();
                let data = options.join(&b',');
                let (limit, nodes, mode, uid, gid) =
                    if matches!(ctx.kind, Kind::Ramfs | Kind::Debugfs) {
                        let (mode, uid, gid) = special::options(
                            &data,
                            if ctx.kind == Kind::Ramfs {
                                0o755
                            } else {
                                0o700
                            },
                            ctx.kind == Kind::Debugfs,
                        )?;
                        (u64::MAX, usize::MAX, mode, uid, gid)
                    } else if ctx.kind == Kind::Tmpfs {
                        tmpfs_options(&data, self.pseudo.borrow().runtime.memory_limit as u64)?
                    } else {
                        (u64::MAX, usize::MAX, 0o755, None, None)
                    };
                let mut devpts = None;
                let (fs, root, root_key) = match ctx.kind {
                    Kind::Ramfs | Kind::Debugfs => {
                        let fs = if ctx.kind == Kind::Ramfs {
                            special::ramfs(&ctx.creator, &data, state.readonly.unwrap_or(false))?
                        } else {
                            self.debug_filesystem(&data, state.readonly.unwrap_or(false))?
                        };
                        let root = fs.borrow().paths[b"/".as_slice()].clone();
                        (fs, root, b"/".to_vec())
                    }
                    Kind::Tmpfs => {
                        let mut fs = ram_filesystem(
                            limit,
                            nodes,
                            mode,
                            uid.unwrap_or(ctx.creator.fsuid),
                            gid.unwrap_or(ctx.creator.fsgid),
                            true,
                        )?;
                        fs.super_readonly = Some(Arc::new(std::sync::atomic::AtomicBool::new(
                            state.readonly.unwrap_or(false),
                        )));
                        fs.owner = ctx.owner.clone();
                        let root = fs.borrow().paths[b"/".as_slice()].clone();
                        (fs, root, b"/".to_vec())
                    }
                    Kind::Devpts => {
                        let pts = Arc::new(pty::Devpts::new(new_mount_id()?, &data)?);
                        let mut fs = pts.fs.clone();
                        fs.owner = ctx.owner.clone();
                        fs.super_readonly
                            .as_ref()
                            .unwrap()
                            .store(state.readonly.unwrap_or(false), Ordering::Relaxed);
                        let root = fs.borrow().paths[b"/".as_slice()].clone();
                        devpts = Some(pts);
                        (fs, root, b"/".to_vec())
                    }
                    Kind::Mqueue => {
                        let fs = ctx.ipc.mqueue_filesystem()?;
                        let root = fs.borrow().paths[b"/".as_slice()].clone();
                        (fs, root, b"/".to_vec())
                    }
                    Kind::Cgroup => {
                        let fs = ctx.cgroup_fs.clone();
                        let root = ctx
                            .cgroup
                            .root
                            .clone()
                            .unwrap_or_else(|| fs.borrow().paths[b"/".as_slice()].clone());
                        let key = root
                            .borrow()
                            .path_in(&fs.borrow().paths, b"/")
                            .ok_or(Errno(2))?;
                        if let Some(value) = self.cgroup_mount_options(Some(&data))? {
                            self.cgroups
                                .borrow()
                                .nsdelegate
                                .store(value, Ordering::Relaxed);
                        }
                        (fs, root, key)
                    }
                    Kind::Overlay => {
                        let options = state.layers.options(&state.parameters)?;
                        let (mut fs, _) = self.overlay_mount_captured(
                            &options,
                            state.readonly.unwrap_or(false),
                            Some(&state.layers),
                            Some(&ctx.creator),
                        )?;
                        fs.owner = ctx.owner.clone();
                        let root = fs.borrow().paths[b"/".as_slice()].clone();
                        (fs, root, b"/".to_vec())
                    }
                    Kind::Proc | Kind::Sysfs => {
                        let key = if ctx.kind == Kind::Proc {
                            b"/proc".as_slice()
                        } else {
                            b"/sys"
                        };
                        let fs = if ctx.kind == Kind::Proc {
                            ctx.pid
                                .proc_filesystem(&self.fs, state.readonly.unwrap_or(false))
                        } else {
                            ctx.net
                                .sys_filesystem(&self.fs, state.readonly.unwrap_or(false))
                        };
                        (fs, self.context_pseudo_root(&ctx, key)?, key.to_vec())
                    }
                    _ => return Err(Errno(19)),
                };
                state.devpts = devpts.clone();
                state.phase = Phase::Created(Arc::new(Mount::new(MountInit {
                    idmap: None,
                    id: new_mount_id()?,
                    fs,
                    root,
                    root_key,
                    root_entry: None,
                    kind: ctx.kind,
                    display: MountDisplay {
                        nsdelegate: None,
                        source: Some(Arc::from(
                            state
                                .source
                                .as_deref()
                                .filter(|s| !s.is_empty())
                                .unwrap_or(b"none"),
                        )),
                        tmpfs_mode: (ctx.kind == Kind::Tmpfs && mode != 0o1777).then_some(mode),
                    },
                    namespace: None,
                    pid_namespace: (ctx.kind == Kind::Proc).then(|| ctx.pid.clone()),
                    devpts,
                    flags: Cell::new(if state.readonly.unwrap_or(false) {
                        MS_RDONLY
                    } else {
                        0
                    }),
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
        if flags & !1 != 0 || attrs & !(0xbf | 0x200000) != 0 {
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
            Phase::Mounted(_) | Phase::Reconfigure(_) => return Err(Errno(16)),
            Phase::Created(root) => copy_mount(root)?,
        };
        let attrs = (attrs & 15) as u64
            | atime
            | if attrs & 0x80 != 0 { MS_NODIRATIME } else { 0 }
            | if attrs & 0x200000 != 0 {
                MS_NOSYMFOLLOW
            } else {
                0
            };
        let local = attrs;
        let locked = self.visible_pseudo_flags(root.kind, local)?;
        root.inherited.store(locked, Ordering::Relaxed);
        root.flags.set(local);
        let fs = root.fs.clone();
        let result = self.tree_descriptor(root.clone(), vec![root], flags == 1)?;
        state.phase = Phase::Mounted(fs);
        state.parameters.clear();
        state.readonly = None;
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
        if o.node.is_none() && !matches!(o.control, Some(events::SharedControl::FuseFile(_))) {
            return Err(Errno(22));
        }
        drop(o);
        self.mount_inode_location(self.proc_open_node(&desc.open, b"")?)
    }
    fn mount_path_descriptor(
        &mut self,
        mount: Arc<Mount>,
        node: NodeRef,
        key: Vec<u8>,
        cloexec: bool,
        tree: Option<Arc<DetachedTree>>,
        entry: Option<Arc<fuse::Entry>>,
    ) -> Result<u32> {
        let reserved = self.shared_files().reserve()?;
        let control = match tree {
            Some(tree) => Some(events::SharedControl::MountTree(tree)),
            None => fuse::File::path_reference(&mount.shared, &node, entry, O_PATH)
                .map(events::SharedControl::FuseFile),
        };
        let d = events::mounted_resource_descriptor(
            self.open_id(),
            O_PATH | if cloexec { O_CLOEXEC } else { 0 },
            FdKind::Node(key),
            Some(node),
            control,
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
        let admin = self.mount_admin()?;
        let _publication = self
            .mount_registry
            .publishing(&admin, &tree.members.borrow());
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
            root.root_entry.clone(),
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
                p.fuse_entry,
            );
        }
        if m.propagation().unbindable {
            return Err(Errno(22));
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
        let root = copy_mount_root(m, node, p.key.clone(), p.fuse_entry.clone())?;
        root.inherited
            .fetch_and(!LOCK_ATTACHMENT, Ordering::Relaxed);
        let mut members = vec![root.clone()];
        if flags & RECURSIVE != 0 {
            let source = tree.as_ref().map_or_else(
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
                    if child.propagation().unbindable {
                        if child.inherited.load(Ordering::Relaxed) & LOCK_ATTACHMENT != 0 {
                            return Err(Errno(1));
                        }
                        continue;
                    }
                    let copy = copy_mount(child)?;
                    *copy.parent.borrow_mut() = Some(Attachment {
                        parent: members[index].clone(),
                        node: link.node,
                        fuse_entry: link.fuse_entry.clone(),
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
        self.landlock_check_mount()?;
        let src = self.mount_operand(from, source, flags & 1 != 0, flags & 4 != 0)?;
        let dst = self.mount_operand(to, target, flags & 0x10 != 0, flags & 0x40 != 0)?;
        let moved = src.mount.as_ref().ok_or(Errno(22))?;
        let parent = dst.mount.as_ref().ok_or(Errno(22))?.clone();
        let node = self.node(&dst)?;
        if !self.is_mount_root(&src) {
            return Err(Errno(22));
        }
        let attached = |m: &Arc<Mount>| ns.0.borrow().mounts.iter().any(|old| Arc::ptr_eq(old, m));
        let _change = self.path_change();
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
        let admin = self.mount_admin()?;
        let _publication = self.mount_registry.publishing(&admin, &members);
        let link = Attachment {
            parent,
            node,
            fuse_entry: dst.fuse_entry.clone(),
            fallback: dst.key,
        };
        if let Some(parent_tree) = parent_tree {
            let entry = link.fuse_entry.clone();
            fuse::Entry::attach(entry.as_ref(), || {
                *moved.parent.borrow_mut() = Some(link);
                parent_tree.members.borrow_mut().append(&mut members);
                Ok(())
            })?;
        } else {
            let old = moved.propagation();
            if let Err(e) = self.publish_mounts_at(&ns, members.clone(), link, || {}) {
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
fn check_layer_owner(mount: &Arc<Mount>, credentials: &Credentials) -> Result<()> {
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
pub(crate) fn check_overlay_layer(vfs: &Vfs, at: &ResolvedPath) -> Result<()> {
    let mount = at.mount.as_ref().ok_or(Errno(22))?;
    check_layer_owner(mount, &vfs.credentials)?;
    let root = topology_root(mount);
    if let Some(origin) = root.anonymous_tree.get() {
        if let Some(tree) = origin.tree.upgrade() {
            if hides_locked_child(&tree.members.borrow(), mount, &at.key) {
                return Err(Errno(22));
            }
        }
    } else {
        let table = vfs.mounts.as_ref().ok_or(Errno(22))?.0.borrow();
        if !table.mounts.iter().any(|m| Arc::ptr_eq(m, mount))
            || hides_locked_child(&table.mounts, mount, &at.key)
        {
            return Err(Errno(22));
        }
    }
    Ok(())
}
pub(super) fn detached_namespace(
    mount: &Arc<Mount>,
    parents: &BTreeMap<u64, Option<Attachment>>,
) -> Option<u64> {
    let mut at = mount.clone();
    let mut seen = std::collections::BTreeSet::new();
    while seen.insert(at.id) {
        if let Some(tree) = at
            .anonymous_tree
            .get()
            .and_then(|origin| origin.tree.upgrade())
        {
            return Some(tree.namespace);
        }
        at = parents.get(&at.id)?.as_ref()?.parent.clone();
    }
    // A read before namespace admission may straddle two moves. Draft owners
    // and live namespace membership still identify their original admission.
    None
}

pub(super) fn remove_detached_members(
    mounts: &[Arc<Mount>],
    removed: &std::collections::BTreeSet<u64>,
) {
    let trees: BTreeMap<_, _> = mounts
        .iter()
        .filter(|mount| removed.contains(&mount.id))
        .filter_map(|mount| topology_root(mount).anonymous_tree.get()?.tree.upgrade())
        .map(|tree| (Arc::as_ptr(&tree) as usize, tree))
        .collect();
    for tree in trees.into_values() {
        tree.members
            .borrow_mut()
            .retain(|mount| !removed.contains(&mount.id));
    }
}

pub(super) fn restore_detached_members(root: &Arc<Mount>, members: Vec<Arc<Mount>>) {
    if let Some(tree) = root
        .anonymous_tree
        .get()
        .and_then(|origin| origin.tree.upgrade())
    {
        if Arc::ptr_eq(root, &tree.root) {
            let mut original = tree.members.borrow_mut();
            if original.is_empty() {
                *original = members;
            }
        }
    }
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
    fn nosymfollow_is_a_live_mount_attribute_and_keeps_nofollow_capabilities() {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/mnt", 0o755).unwrap();
        v.mount(None, b"/mnt", Some(b"tmpfs"), MS_NOSYMFOLLOW, None)
            .unwrap();
        let fd = v
            .open_at(AT_FDCWD, b"/mnt/file", O_CREAT | 2, 0o600)
            .unwrap();
        v.close(fd).unwrap();
        v.symlink_at(b"file", AT_FDCWD, b"/mnt/link").unwrap();
        assert_eq!(v.open_at(AT_FDCWD, b"/mnt/link", 0, 0), Err(Errno(40)));
        assert_eq!(v.readlink_at(AT_FDCWD, b"/mnt/link").unwrap(), b"file");
        let link = v
            .open_at(AT_FDCWD, b"/mnt/link", O_PATH | O_NOFOLLOW, 0)
            .unwrap();
        let stat = v.statfs_fd(link).unwrap();
        assert_ne!(
            u64::from_le_bytes(stat[80..88].try_into().unwrap()) & 8192,
            0
        );
        v.mount_setattr(
            AT_FDCWD,
            b"/mnt",
            0,
            &MountAttributes::new(0, 0x200000, 0).unwrap(),
        )
        .unwrap();
        assert!(v.open_at(AT_FDCWD, b"/mnt/link", 0, 0).is_ok());
        v.mount_setattr(
            AT_FDCWD,
            b"/mnt",
            0,
            &MountAttributes::new(0x200000, 0, 0).unwrap(),
        )
        .unwrap();
        assert_eq!(v.open_at(AT_FDCWD, b"/mnt/link", 0, 0), Err(Errno(40)));
    }
    #[test]
    fn unbindable_subtrees_are_pruned_from_both_recursive_bind_interfaces() {
        let mut v = Vfs::default();
        for path in [b"/src".as_slice(), b"/dst", b"/tree"] {
            v.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
        }
        v.mount(None, b"/src", Some(b"tmpfs"), 0, None).unwrap();
        v.mkdir_at(AT_FDCWD, b"/src/sub", 0o755).unwrap();
        v.mount(None, b"/src/sub", Some(b"tmpfs"), 0, None).unwrap();
        v.mkdir_at(AT_FDCWD, b"/src/sub/hidden", 0o755).unwrap();
        v.mount_setattr(
            AT_FDCWD,
            b"/src/sub",
            0,
            &MountAttributes::new(0, 0, 1 << 17).unwrap(),
        )
        .unwrap();
        assert_eq!(
            v.mount(Some(b"/src/sub"), b"/dst", None, 4096, None),
            Err(Errno(22))
        );
        assert_eq!(v.open_tree(AT_FDCWD, b"/src/sub", 1), Err(Errno(22)));
        v.mount(Some(b"/src"), b"/dst", None, 4096 | 16384, None)
            .unwrap();
        assert_eq!(v.stat_at(AT_FDCWD, b"/dst/sub/hidden"), Err(Errno(2)));
        let tree = v.open_tree(AT_FDCWD, b"/src", 1 | RECURSIVE).unwrap();
        v.move_mount_fd(tree as i32, b"", AT_FDCWD, b"/tree", 4)
            .unwrap();
        assert_eq!(v.stat_at(AT_FDCWD, b"/tree/sub/hidden"), Err(Errno(2)));
    }
    #[test]
    fn picked_tmpfs_context_retains_original_filesystem_limits_across_aliases() {
        let mut v = Vfs::default();
        for path in [b"/mnt".as_slice(), b"/alias"] {
            v.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
        }
        v.mount(
            None,
            b"/mnt",
            Some(b"tmpfs"),
            0,
            Some(b"size=1048576,nr_inodes=99"),
        )
        .unwrap();
        v.mount(Some(b"/mnt"), b"/alias", None, 4096, None).unwrap();
        let context = v.fspick(AT_FDCWD, b"/alias", 1).unwrap();
        v.fsconfigure(context, 1, Some(b"nr_inodes"), Some(b"123"))
            .unwrap();
        v.fsconfigure(context, 7, None, None).unwrap();
        for path in [b"/mnt".as_slice(), b"/alias"] {
            let stat = v.statfs_at(path).unwrap();
            assert_eq!(
                u64::from_le_bytes(stat[16..24].try_into().unwrap()) * 4096,
                1048576
            );
            assert_eq!(u64::from_le_bytes(stat[40..48].try_into().unwrap()), 123);
        }
        let file = v
            .open_at(AT_FDCWD, b"/mnt/file", O_CREAT | 2, 0o600)
            .unwrap();
        let desc = v.descriptor(file).unwrap();
        let mount = desc.open.borrow().mount.as_ref().unwrap().identity.clone();
        let writer = mapped::MountWrite::new(&mount).unwrap();
        v.fsconfigure(context, 0, Some(b"ro"), None).unwrap();
        assert_eq!(v.fsconfigure(context, 7, None, None), Err(Errno(16)));
        drop(writer);
        v.close(file).unwrap();
        assert_eq!(v.fsconfigure(context, 7, None, None), Err(Errno(16)));
        drop(desc);
        v.fsconfigure(context, 7, None, None).unwrap();
        assert_eq!(v.mkdir_at(AT_FDCWD, b"/mnt/blocked", 0o755), Err(Errno(30)));
        assert_eq!(
            v.mkdir_at(AT_FDCWD, b"/alias/blocked", 0o755),
            Err(Errno(30))
        );
    }

    #[test]
    fn detached_layer_retains_its_user_namespace_after_close() {
        let mut v = Vfs::default();
        let fd = v.open_tree(AT_FDCWD, b"/", 1).unwrap();
        let desc = v.descriptor(fd).unwrap();
        let mount = v.mount_for_path(desc.open.borrow().mount.as_ref()).unwrap();
        assert_eq!(check_layer_owner(&mount, &v.credentials), Ok(()));
        drop(desc);
        v.close(fd).unwrap();
        v.unshare_user().unwrap();
        assert_eq!(check_layer_owner(&mount, &v.credentials), Err(Errno(1)));
    }
    #[test]
    fn sysfs_write_mount_state_is_separate_from_attribute_permissions() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, Default::default());
        let file = b"/sys/devices/system/cpu/online";
        assert_eq!(
            v.rename_at(AT_FDCWD, file, AT_FDCWD, file, 0),
            Err(Errno(30))
        );
        v.mount(
            None,
            b"/sys",
            None,
            32 | MS_NODEV | MS_NOSUID | MS_NOEXEC,
            None,
        )
        .unwrap();
        v.rename_at(AT_FDCWD, file, AT_FDCWD, file, 0).unwrap();
        assert!(v.mkdir_at(AT_FDCWD, b"/sys/devices/new", 0o755).is_err());
        for readonly in [false, true] {
            let ctx = v.fsopen(b"sysfs", 0).unwrap();
            if readonly {
                v.fsconfigure(ctx, 0, Some(b"ro"), None).unwrap();
            }
            v.fsconfigure(ctx, 6, None, None).unwrap();
            let mount = v.fsmount(ctx, 0, 0).unwrap();
            let stat = v.statfs_fd(mount).unwrap();
            // get_tree on existing sysfs does not reconfigure its superblock;
            // fsmount attrs, unlike fsconfig creation flags, are mount-local.
            assert_eq!(
                u64::from_le_bytes(stat[80..88].try_into().unwrap()) & MS_RDONLY,
                0
            );
            v.close(mount).unwrap();
            v.close(ctx).unwrap();
        }
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

#[cfg(test)]
#[path = "idmap_tests.rs"]
mod idmap_tests;

#[cfg(test)]
mod modern_context_tests {
    use super::*;
    #[test]
    fn new_overlay_context_keeps_accepted_directories_after_rename() {
        let mut v = Vfs::default();
        for path in [b"/lower".as_slice(), b"/upper", b"/work", b"/merged"] {
            v.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
        }
        v.import_file(b"/lower/file", b"original".to_vec()).unwrap();
        let ctx = v.fsopen(b"overlay", 0).unwrap();
        for (k, p) in [
            (b"lowerdir+".as_slice(), b"/lower".as_slice()),
            (b"upperdir", b"/upper"),
            (b"workdir", b"/work"),
        ] {
            v.fsconfigure(ctx, 1, Some(k), Some(p)).unwrap();
        }
        v.rename_at(AT_FDCWD, b"/lower", AT_FDCWD, b"/renamed", 0)
            .unwrap();
        v.fsconfigure(ctx, 6, None, None).unwrap();
        let tree = v.fsmount(ctx, 0, 0).unwrap();
        v.move_mount_fd(tree as i32, b"", AT_FDCWD, b"/merged", 4)
            .unwrap();
        let fd = v.open_at(AT_FDCWD, b"/merged/file", 0, 0).unwrap();
        assert_eq!(v.read(fd, 8).unwrap(), b"original");
    }
    #[test]
    fn modern_devpts_and_mqueue_contexts_retain_their_original_instances() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, Default::default());
        for path in [b"/pts".as_slice(), b"/queues"] {
            v.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
        }
        let ctx = v.fsopen(b"devpts", 0).unwrap();
        v.fsconfigure(ctx, 1, Some(b"ptmxmode"), Some(b"0666"))
            .unwrap();
        v.fsconfigure(ctx, 6, None, None).unwrap();
        let tree = v.fsmount(ctx, 0, 0).unwrap();
        v.move_mount_fd(tree as i32, b"", AT_FDCWD, b"/pts", 4)
            .unwrap();
        assert!(v.stat_at(AT_FDCWD, b"/pts/ptmx").is_ok());
        let q = v.mq_open(b"original", 0x42, 0o600, None).unwrap();
        let ctx = v.fsopen(b"mqueue", 0).unwrap();
        v.unshare_ipc().unwrap();
        v.fsconfigure(ctx, 6, None, None).unwrap();
        let tree = v.fsmount(ctx, 0, 0).unwrap();
        v.move_mount_fd(tree as i32, b"", AT_FDCWD, b"/queues", 4)
            .unwrap();
        assert!(v.stat_at(AT_FDCWD, b"/queues/original").is_ok());
        assert_eq!(v.mq_open(b"original", 0, 0, None), Err(Errno(2)));
        v.close(q).unwrap();
    }
}
