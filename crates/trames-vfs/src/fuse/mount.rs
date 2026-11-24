// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

pub(crate) struct Mounted {
    pub connection: Arc<Connection>,
    active: OnceLock<std::sync::Weak<ConnectionUse>>,
    filesystem: FsHandle,
    controller: Arc<Controller>,
    minor: u64,
    namespace: UserNamespace,
    pid_namespace: PidNamespace,
    uid: u32,
    gid: u32,
    allow_other: bool,
    pub(crate) default_permissions: bool,
    access_unsupported: std::sync::atomic::AtomicBool,
    flush_unsupported: std::sync::atomic::AtomicBool,
    sync_unsupported: std::sync::atomic::AtomicU8,
    create_unsupported: std::sync::atomic::AtomicBool,
    rename_unsupported: std::sync::atomic::AtomicBool,
    link_unsupported: std::sync::atomic::AtomicBool,
    xattr_unsupported: std::sync::atomic::AtomicU8,
    directories: Arc<directory::Directories>,
}

impl Drop for Mounted {
    fn drop(&mut self) {
        self.disconnect();
    }
}
/// Actual mount/OFD lifetime; metadata projections hold only Mounted.
/// The weak back-reference cannot revive a disconnected superblock.
pub(crate) struct ConnectionUse(Arc<Mounted>);
impl Drop for ConnectionUse {
    fn drop(&mut self) {
        self.0.disconnect();
    }
}
impl Mounted {
    pub(crate) fn local_permissions(&self) -> bool {
        self.default_permissions || self.posix_acl()
    }
    pub(super) fn posix_acl(&self) -> bool {
        self.connection.option(1 << 20)
    }
    pub(super) fn dont_mask(&self) -> bool {
        self.connection.option(1 << 6)
    }
    pub(crate) fn usage(&self) -> Option<Arc<ConnectionUse>> {
        self.active.get()?.upgrade()
    }
    fn disconnect(&self) {
        self.connection.abort();
        self.controller.remove(self.minor);
    }
    pub(crate) fn check(&self, c: &Credentials) -> Result<()> {
        if !self.namespace.contains(&c.user_namespace)
            || !self.allow_other
                && ([c.uid, c.euid, c.suid].iter().any(|&id| id != self.uid)
                    || [c.gid, c.egid, c.sgid].iter().any(|&id| id != self.gid))
        {
            return Err(Errno(13));
        }
        Ok(())
    }
    fn caller(&self, v: &Vfs) -> Caller {
        Caller {
            uid: self.namespace.visible(false, v.credentials.fsuid),
            gid: self.namespace.visible(true, v.credentials.fsgid),
            pid: self.pid_namespace.local(v.pid),
        }
    }
    /// Page IO takes current fs credentials at the fault, and translates the
    /// current TID through the original connection's PID namespace.
    fn fault_caller(&self) -> Result<Caller> {
        let (state, tid) = crate::file_actor::current().ok_or(Errno(5))?;
        let credentials = state.read();
        self.check(&credentials)?;
        Ok(Caller {
            uid: self
                .namespace
                .from_global(false, credentials.fsuid)
                .ok_or(Errno(75))?,
            gid: self
                .namespace
                .from_global(true, credentials.fsgid)
                .ok_or(Errno(75))?,
            pid: self.pid_namespace.local(tid),
        })
    }
}

struct Options {
    fd: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    allow_other: bool,
    default_permissions: bool,
}
impl Options {
    fn parse(data: &[u8], ns: &UserNamespace) -> Result<Self> {
        let text = std::str::from_utf8(data).map_err(|_| Errno(22))?;
        let (mut fd, mut uid, mut gid, mut mode) = (None, None, None, None);
        let mut allow_other = false;
        let mut default_permissions = false;
        for word in text.split(',') {
            if word == "allow_other" {
                allow_other = true;
                continue;
            }
            if word == "default_permissions" {
                default_permissions = true;
                continue;
            }
            let (key, val) = word.split_once('=').ok_or(Errno(22))?;
            let number = u32::from_str_radix(val, if key == "rootmode" { 8 } else { 10 })
                .map_err(|_| Errno(22))?;
            match key {
                "fd" => fd = Some(number),
                "user_id" => uid = Some(ns.to_global(false, number).ok_or(Errno(22))?),
                "group_id" => gid = Some(ns.to_global(true, number).ok_or(Errno(22))?),
                "rootmode" if number & !0o7777 == 0o40000 => mode = Some(number & 0o7777),
                _ => return Err(Errno(22)),
            }
        }
        Ok(Self {
            fd: fd.ok_or(Errno(22))?,
            mode: mode.ok_or(Errno(22))?,
            uid: uid.ok_or(Errno(22))?,
            gid: gid.ok_or(Errno(22))?,
            allow_other,
            default_permissions,
        })
    }
}
pub(crate) struct Binding {
    device: Option<Arc<Device>>,
    daemon: Option<Arc<Daemon>>,
    _usage: Arc<ConnectionUse>,
}
impl Binding {
    pub(crate) fn publish(mut self) {
        if let Some(daemon) = self.daemon.take() {
            self.device.as_ref().unwrap().install(daemon);
        }
    }
}
impl Drop for Binding {
    fn drop(&mut self) {
        if self.daemon.is_some() {
            self.device
                .as_ref()
                .unwrap()
                .reserved
                .store(false, Ordering::Release);
        }
    }
}
pub(crate) fn option_fd(data: &[u8], ns: &UserNamespace) -> Result<u32> {
    Options::parse(data, ns).map(|o| o.fd)
}
pub(crate) fn prepare(v: &Vfs, data: &[u8]) -> Result<(FsHandle, Option<Binding>)> {
    let ns = &v.credentials.user_namespace;
    let opts = Options::parse(data, ns)?;
    let dev = v.fuse_device(opts.fd)?.ok_or(Errno(22))?;
    if dev.namespace != *ns {
        return Err(Errno(22));
    }
    if let Some(daemon) = dev.daemon.get() {
        let mounted = daemon.mounted.upgrade().ok_or(Errno(16))?;
        let usage = mounted.usage().ok_or(Errno(16))?;
        let mut fs = mounted.filesystem.clone();
        fs.fuse = Some(mounted);
        return Ok((
            fs,
            Some(Binding {
                device: None,
                daemon: None,
                _usage: usage,
            }),
        ));
    }
    let c = Caller {
        uid: ns.visible(false, v.credentials.fsuid),
        gid: ns.visible(true, v.credentials.fsgid),
        pid: v.pid_ns.local(v.pid),
    };
    let mut fs = mounts::ram_filesystem(0, 1, opts.mode, opts.uid, opts.gid, false)?;
    let connection = Connection::new(c);
    dev.reserve()?;
    let root = fs.borrow().paths[b"/".as_slice()].clone();
    let minor = root.borrow().device;
    root.borrow_mut().device = (minor & 0xff) | ((minor & !0xff) << 12);
    let controller = v.pseudo.borrow().fuse_control.clone();
    let mounted = Arc::new(Mounted {
        connection: connection.clone(),
        active: Default::default(),
        filesystem: fs.clone(),
        controller,
        minor,
        namespace: ns.clone(),
        pid_namespace: v.pid_ns.clone(),
        uid: opts.uid,
        gid: opts.gid,
        allow_other: opts.allow_other,
        default_permissions: opts.default_permissions,
        access_unsupported: Default::default(),
        flush_unsupported: Default::default(),
        sync_unsupported: Default::default(),
        create_unsupported: Default::default(),
        rename_unsupported: Default::default(),
        link_unsupported: Default::default(),
        xattr_unsupported: Default::default(),
        directories: Default::default(),
    });
    assert!(connection.mounted.set(Arc::downgrade(&mounted)).is_ok());
    let mut root_attr = [0; 88];
    root_attr[..8].copy_from_slice(&1u64.to_le_bytes());
    root_attr[60..64].copy_from_slice(&(0o040000 | opts.mode).to_le_bytes());
    root_attr[68..72].copy_from_slice(&ns.visible(false, opts.uid).to_le_bytes());
    root_attr[72..76].copy_from_slice(&ns.visible(true, opts.gid).to_le_bytes());
    let _ = root.fuse_directory.set(Arc::new(Directory {
        node: 1,
        attr: Arc::new(inode::Attr::new(root_attr, 0, (0, 0))),
        // The root is created before INIT establishes the ACL access model.
        acl: posix::Cache::uncached(),
        _lookup: Arc::new(LookupLease {
            connection: connection.clone(),
            caller: c,
            node: 1,
        }),
        linked: std::sync::atomic::AtomicBool::new(true),
        cache: None,
        location: std::sync::Mutex::new(None),
    }));
    let usage = Arc::new(ConnectionUse(mounted.clone()));
    assert!(mounted.active.set(Arc::downgrade(&usage)).is_ok());
    let binding = Binding {
        device: Some(dev),
        _usage: usage,
        daemon: Some(Arc::new(Daemon {
            connection,
            mounted: Arc::downgrade(&mounted),
        })),
    };
    mounted
        .controller
        .add(minor, opts.uid, opts.gid, &mounted.connection)?;
    fs.fuse = Some(mounted);
    Ok((fs, Some(binding)))
}

// Wire offsets below are the Linux ARM64 fuse_attr_out and struct stat ABIs.
#[derive(Clone, Copy)]
pub(crate) enum PathOperation {
    Stat,
    Statfs,
    Readlink,
    Open(u32),
    Truncate(u64),
    Access(u32),
    Chdir,
    Chroot,
    ResolveDirectory,
    ResolveEntry,
}
struct LookupLease {
    connection: Arc<Connection>,
    caller: Caller,
    node: u64,
}
impl Drop for LookupLease {
    fn drop(&mut self) {
        if self.node != 1 {
            self.connection.forget(self.node, self.caller);
        }
    }
}
#[derive(Clone)]
struct LookupRef {
    fs: Arc<Mounted>,
    lease: Arc<LookupLease>,
    directory: Option<NodeRef>,
    leaf: Option<NodeRef>,
}
impl LookupRef {
    fn retained(fs: &Arc<Mounted>, directory: NodeRef) -> Self {
        let lease = directory
            .fuse_directory
            .get()
            .map(|d| d._lookup.clone())
            .or_else(|| directory.fuse_leaf.get().map(|f| f._lookup.clone()))
            .unwrap();
        let leaf = (!directory.directory).then(|| directory.clone());
        Self {
            fs: fs.clone(),
            lease,
            directory: directory.directory.then_some(directory),
            leaf,
        }
    }
    fn new(fs: &Arc<Mounted>, caller: Caller, node: u64) -> Self {
        Self {
            fs: fs.clone(),
            lease: Arc::new(LookupLease {
                connection: fs.connection.clone(),
                caller,
                node,
            }),
            directory: None,
            leaf: None,
        }
    }
}
impl std::ops::Deref for LookupRef {
    type Target = LookupLease;
    fn deref(&self) -> &LookupLease {
        &self.lease
    }
}
struct Lookup {
    fs: Arc<Mounted>,
    caller: Caller,
    continuation: Option<Box<PathWalk>>,
    base: Option<ResolvedPath>,
    follow: bool,
    directory: bool,
    flags: Arc<mounts::MountFlags>,
    root: bool,
    operation: PathOperation,
    parent: u64,
    parent_directory: NodeRef,
    change: Option<directory::Change>,
    name: Vec<u8>,
}
struct Create {
    _parent_directory: NodeRef,
    fs: Arc<Mounted>,
    caller: Caller,
    parent: u64,
    name: Vec<u8>,
}
struct Link {
    walk: PathWalk,
    base: ResolvedPath,
    operation: PathOperation,
}
enum ResultKind {
    InitWalk(Box<(PathWalk, PathOperation)>, Arc<Mounted>, bool),
    Permission(Box<permissions::Permission>),
    NativeWalk(Box<(PathWalk, PathOperation)>),
    NativeEntry(Box<(ResolvedEntry, PathOperation, Credentials)>),
    OwnerWalk(Box<(PathWalk, PathOperation)>),
    JoinedWalk(Box<(PathWalk, PathOperation)>),
    Mutation(Box<namespace::Mutation>),
    Open([u8; 88]),
    ReopenFile(Arc<File>),
    FileStat(Arc<File>),
    File(FileResult),
    Preparing(Box<killpriv::Preparation>),
    Readlink,
    FollowLink(Box<Link>),
    Lookup(Lookup),
    Stat,
    Statfs(Arc<mounts::MountFlags>),
    Access(access::Access),
    Attributes(Box<attributes::Attributes>),
    Xattr(Box<xattr::Xattr>),
    ChangeDirectory(Arc<Mounted>, directory::Change, NodeRef, bool),
    Create(Create),
    MknodOpen(Create),
    CreatePermission(Box<(Create, posix::Check)>),
}
pub(crate) struct Metadata {
    pub(crate) request: Option<Arc<Request>>,
    kind: ResultKind,
    _usage: Option<mounts::MountUse>,
    resolved: Option<Box<(ResolvedPath, NodeRef)>>,
    pub(crate) resolved_entry: Option<Box<ResolvedEntry>>,
    reference: Option<LookupRef>,
    open: Option<Box<OpenPlan>>,
    mount: StatMount,
    dev: u64,
    owner_ns: UserNamespace,
    reader_ns: UserNamespace,
}
impl Metadata {
    pub(crate) fn retain_output(&mut self) {
        // stat/statfs release their lookup/file references after snapshotting,
        // before copying the already accepted metadata to user memory.
        if matches!(
            self.kind,
            ResultKind::Stat | ResultKind::FileStat(_) | ResultKind::Statfs(_)
        ) {
            return;
        }
        let resources = (
            self.reference.take(),
            self.resolved.take(),
            self._usage.take(),
        );
        crate::output_resources::OutputScope::retain(|| resources);
    }
    pub(crate) fn continuation(v: &Vfs, walk: Box<(PathWalk, PathOperation)>, owner: bool) -> Self {
        let id = walk.0.current.mount.as_ref().map_or(1, |m| m.id);
        let dev = walk.0.current.mount.as_ref().map_or(0, |m| m.device());
        Self {
            request: None,
            kind: if owner {
                ResultKind::OwnerWalk(walk)
            } else {
                ResultKind::NativeWalk(walk)
            },
            _usage: None,
            resolved: None,
            resolved_entry: None,
            reference: None,
            open: None,
            mount: StatMount::mounted(id, false),
            dev,
            owner_ns: v.credentials.user_namespace.clone(),
            reader_ns: v.credentials.user_namespace.clone(),
        }
    }
    pub(crate) fn prepare_open(
        &mut self,
        id: u64,
        mount: Arc<mounts::MountData>,
        path: Vec<u8>,
        flags: u32,
        denied: u64,
        link_credentials: (u64, UserNamespace),
    ) {
        self.open = Some(Box::new(OpenPlan {
            id,
            mount,
            path,
            flags,
            denied,
            link_credentials,
            slot: None,
            mode: 0,
            umask: None,
            writer: None,
            sticky_parent: None,
            publication: None,
            created: false,
        }));
    }
    pub(crate) fn retain_open_parent(&mut self, parent: NodeRef) {
        self.open.as_mut().expect("FUSE open intent").sticky_parent = Some(parent);
    }
    pub(crate) fn reserve_open(
        &mut self,
        slot: fd_table::ReservedFd,
        mode: u32,
        umask: Umask,
        publication: Option<DirectFiles>,
    ) {
        let plan = self.open.as_mut().expect("FUSE open intent");
        plan.slot = Some(slot);
        plan.mode = 0o100000 | (mode & 0o7777);
        plan.umask = Some(umask);
        plan.publication = publication;
    }
    fn publish_open(
        &mut self,
        fh: Option<u64>,
        attr: [u8; 88],
        open_flags: u32,
    ) -> Result<FileValue> {
        let file = self.open_file(fh, attr, open_flags);
        self.publish_file(file)
    }
    fn open_file(&self, fh: Option<u64>, attr: [u8; 88], open_flags: u32) -> Arc<File> {
        let plan = self.open.as_ref().expect("FUSE open operands");
        let reference = self.reference.as_ref().expect("looked-up inode").clone();
        let attributes = reference
            .leaf
            .as_ref()
            .and_then(|n| n.fuse_leaf.get())
            .map(|f| f.attr.clone())
            .or_else(|| {
                reference
                    .directory
                    .as_ref()?
                    .fuse_directory
                    .get()
                    .map(|d| d.attr.clone())
            })
            .unwrap_or_else(|| Arc::new(inode::Attr::new(attr, 0, (0, 0))));
        if fh.is_some() && open_flags & 2 == 0 && attributes.kind_is_regular() {
            attributes.cache.invalidate_all();
        }
        Arc::new(File {
            _usage: reference.fs.usage(),
            reference,
            fh,
            flags: plan.flags & !(O_CLOEXEC | OPEN_ONLY_FLAGS)
                | if fh.is_some() { O_LARGEFILE } else { 0 },
            status: Default::default(),
            open_flags,
            directory: u32::from_le_bytes(attr[60..64].try_into().unwrap()) & 0o170000 == 0o040000,
            attr: attributes,
            position_busy: Default::default(),
            position_changed: Default::default(),
            mount: plan.mount.clone(),
        })
    }
    fn publish_file(&mut self, file: Arc<File>) -> Result<FileValue> {
        let plan = *self.open.take().expect("FUSE open operands");
        self.reference.take();
        let descriptor = events::mounted_resource_descriptor_with_link_credentials(
            plan.id,
            file.flags | plan.flags & O_CLOEXEC,
            FdKind::Node(plan.path),
            file.reference.directory.clone(),
            Some(events::SharedControl::FuseFile(file.clone())),
            None,
            Some(OpenMount::Shared(plan.mount)),
            Some(plan.link_credentials),
        );
        assert!(file
            .status
            .set(descriptor.open.borrow().flags.clone())
            .is_ok());
        Ok(FileValue::Count(
            plan.slot
                .expect("reserved open slot")
                .publish(descriptor, None)? as u64,
        ))
    }
    fn lookup_request(
        fs: &Mounted,
        node: u64,
        caller: Caller,
        mut name: Vec<u8>,
    ) -> Result<Arc<Request>> {
        name.push(0);
        Ok(Arc::new(fs.connection.request(1, node, caller, &name)?))
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn lookup(
        v: &Vfs,
        m: &Arc<mounts::Mount>,
        fs: &Arc<Mounted>,
        parent: NodeRef,
        first: Vec<u8>,
        continuation: PathWalk,
        base: ResolvedPath,
        operation: PathOperation,
    ) -> Result<Self> {
        fs.check(&v.credentials)?;
        let caller = fs.caller(v);
        Ok(Self {
            request: Some(Self::lookup_request(
                fs,
                parent.fuse_directory.get().ok_or(Errno(5))?.node,
                caller,
                first.clone(),
            )?),
            kind: ResultKind::Lookup(Lookup {
                fs: fs.clone(),
                caller,
                follow: continuation.follow_final,
                directory: continuation.trailing,
                continuation: Some(Box::new(continuation)),
                base: Some(base),
                operation,
                flags: m.flags.clone(),
                root: false,
                parent: parent.fuse_directory.get().unwrap().node,
                parent_directory: parent,
                change: matches!(operation, PathOperation::Chdir | PathOperation::Chroot)
                    .then(|| directory::Change::new(v, m.shared.clone())),
                name: first,
            }),
            _usage: Some(mounts::MountUse::new(m.identity.clone())),
            resolved: None,
            resolved_entry: None,
            reference: None,
            open: None,
            mount: StatMount::mounted(m.id, false),
            dev: m.device(),
            owner_ns: fs.namespace.clone(),
            reader_ns: v.credentials.user_namespace.clone(),
        })
    }
    pub(crate) fn open_inode(
        v: &Vfs,
        m: &mounts::MountData,
        fs: &Arc<Mounted>,
        flags: u32,
        directory: NodeRef,
    ) -> Result<Self> {
        Self::directory_operation(v, m, fs, PathOperation::Open(flags), directory, None)
    }
    pub(crate) fn change_directory(
        v: &Vfs,
        m: &Arc<mounts::Mount>,
        fs: &Arc<Mounted>,
        directory: NodeRef,
        root: bool,
    ) -> Result<Self> {
        Self::directory_operation(
            v,
            m,
            fs,
            if root {
                PathOperation::Chroot
            } else {
                PathOperation::Chdir
            },
            directory,
            Some(directory::Change::new(v, m.shared.clone())),
        )
    }
    fn directory_operation(
        v: &Vfs,
        m: &mounts::MountData,
        fs: &Arc<Mounted>,
        operation: PathOperation,
        directory: NodeRef,
        change: Option<directory::Change>,
    ) -> Result<Self> {
        let mut pending = Self::stat_inode(v, m, fs, directory.clone())?;
        let node = pending.reference.as_ref().unwrap().node;
        pending.kind = ResultKind::Lookup(Lookup {
            fs: fs.clone(),
            caller: fs.caller(v),
            continuation: None,
            base: None,
            // Traversal has accepted this inode already. Any link following
            // belongs to the original common walk, not a new open lookup.
            follow: false,
            directory: directory.directory,
            operation,
            flags: m.flags.clone(),
            root: true,
            parent: node,
            parent_directory: directory,
            change,
            name: Vec::new(),
        });
        Ok(pending)
    }
    fn advance_lookup(&mut self, v: &mut Vfs, mut bytes: Vec<u8>) -> Result<Option<FileValue>> {
        let version = self.request.as_ref().map_or(0, |r| r.attr_version);
        let ResultKind::Lookup(walk) = &mut self.kind else {
            unreachable!()
        };
        let credentials = walk
            .continuation
            .as_ref()
            .and_then(|w| w.credentials.as_deref())
            .cloned()
            .unwrap_or_else(|| v.credentials.clone());
        let previous = std::mem::replace(&mut v.credentials, credentials);
        let restore = walk::RestoreCredentials { view: v, previous };
        let v = &mut *restore.view;
        // The lookup reference belongs to the daemon's nodeid; attr.ino is
        // separately chosen by the filesystem for stat(2).
        let root = std::mem::take(&mut walk.root);
        if root {
            if bytes.len() != 104 {
                return Err(Errno(5));
            }
            let mut entry = vec![0; 128];
            entry[..8].copy_from_slice(&walk.parent.to_le_bytes());
            entry[24..32].copy_from_slice(&bytes[..8]);
            entry[36..40].copy_from_slice(&bytes[8..12]);
            entry[40..].copy_from_slice(&bytes[16..]);
            bytes = entry;
        }
        if bytes.len() != 128 {
            return Err(Errno(5));
        }
        let node = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        if !root && node == 0 {
            return Err(Errno(2));
        }
        let mut raw_attr: [u8; 88] = bytes[40..].try_into().unwrap();
        let attr = &mut raw_attr[..];
        let valid = (
            u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
            u32::from_le_bytes(bytes[36..40].try_into().unwrap()),
        );
        let mode = u32::from_le_bytes(attr[60..64].try_into().unwrap());
        let kind = mode & 0o170000;
        if !root && node == 1 {
            walk.fs.apply_root_lookup(attr, version, valid)?;
            return Err(Errno(5));
        }
        if inode::validate(attr).is_err() {
            if root {
                if let Some(node) = self
                    .reference
                    .as_ref()
                    .and_then(|r| r.directory.as_ref().or(r.leaf.as_ref()))
                {
                    inode::attr(node).make_bad();
                }
            }
            return Err(Errno(5));
        }
        if root {
            // GETATTR on an accepted directory does not grant another lookup.
            debug_assert!(self.reference.is_some());
        } else {
            self.reference = Some(LookupRef::new(&walk.fs, walk.caller, node));
        }
        if root
            && self
                .reference
                .as_ref()
                .and_then(|r| r.directory.as_ref().or(r.leaf.as_ref()))
                .is_none_or(|n| n.borrow().mode & 0o170000 != kind)
        {
            if let Some(node) = self
                .reference
                .as_ref()
                .and_then(|r| r.directory.as_ref().or(r.leaf.as_ref()))
            {
                inode::attr(node).make_bad();
            }
            return Err(Errno(5));
        }
        let remaining = walk
            .continuation
            .as_ref()
            .is_some_and(|walk| !walk.parts.is_empty());
        if kind == 0o040000 {
            let reference = self.reference.as_mut().unwrap();
            if root {
                walk.fs.refresh_inode_at(
                    reference.directory.as_ref().unwrap(),
                    attr,
                    version,
                    valid,
                    inode::Update::Read,
                )?;
            } else {
                reference.directory = Some(walk.fs.directory(
                    reference,
                    u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
                    (&walk.parent_directory, &walk.name),
                    attr,
                    version,
                    valid,
                )?);
            }
        } else {
            let reference = self.reference.as_mut().unwrap();
            if root {
                walk.fs.refresh_inode_at(
                    reference.leaf.as_ref().unwrap(),
                    attr,
                    version,
                    valid,
                    inode::Update::Read,
                )?;
            } else {
                reference.leaf = Some(walk.fs.leaf_inode(
                    reference,
                    u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
                    &walk.parent_directory,
                    attr,
                    version,
                    valid,
                )?);
            }
        }
        let retained = self.reference.as_ref().unwrap();
        attr.copy_from_slice(
            &inode::attr(
                retained
                    .leaf
                    .as_ref()
                    .or(retained.directory.as_ref())
                    .unwrap(),
            )
            .lock()
            .unwrap()[..],
        );
        // Exclusive creation rejects any existing final inode before link,
        // access or readonly checks, matching do_open's EEXIST ordering.
        if !remaining
            && matches!(walk.operation, PathOperation::Open(flags)
            if flags & (O_CREAT | 0x80) == O_CREAT | 0x80)
        {
            return Err(Errno(17));
        }
        if kind == 0o120000 && (walk.follow || walk.directory || remaining) {
            let continuation = walk.continuation.as_ref().ok_or(Errno(5))?;
            if continuation.links >= 40 {
                return Err(Errno(40));
            }
            let parent = walk.parent_directory.borrow();
            let owner = walk
                .fs
                .namespace
                .to_global(false, u32::from_le_bytes(attr[68..72].try_into().unwrap()))
                .unwrap_or(u32::MAX);
            if continuation.parts.is_empty()
                && parent.mode & 0o1002 == 0o1002
                && owner != continuation.credentials.as_ref().unwrap().fsuid
                && owner != parent.uid
                && v.namei_policy.get(sysctl::Protection::Symlinks) != 0
            {
                return Err(Errno(13));
            }
            drop(parent);
            if continuation.policy & 4 != 0 || walk.flags.get() & mounts::MS_NOSYMFOLLOW != 0 {
                return Err(Errno(40));
            }
            walk.fs
                .check_inode(self.reference.as_ref().unwrap().leaf.as_ref().unwrap())?;
            let request = Arc::new(walk.fs.connection.request(5, node, walk.caller, &[])?);
            let ResultKind::Lookup(walk) = std::mem::replace(&mut self.kind, ResultKind::Readlink)
            else {
                unreachable!()
            };
            self.kind = ResultKind::FollowLink(Box::new(Link {
                walk: *walk.continuation.unwrap(),
                base: walk.base.unwrap(),
                operation: walk.operation,
            }));
            self.request = Some(request);
            return Ok(None);
        }
        if (walk.directory || remaining) && kind != 0o040000 {
            return Err(Errno(20));
        }
        if remaining {
            let mut continuation = *walk.continuation.take().unwrap();
            continuation.current.directory_inode =
                self.reference.as_ref().unwrap().directory.clone();
            let operation = walk.operation;
            return self.resume_walk(v, continuation, operation);
        }
        match walk.operation {
            PathOperation::ResolveEntry => {
                // Ordinary and magic targets finish through the common walk.
                // A daemon directory already has its canonical inode here.
                let mut path = walk.continuation.take().ok_or(Errno(5))?.current;
                path.directory_inode = self
                    .reference
                    .as_ref()
                    .unwrap()
                    .directory
                    .clone()
                    .or_else(|| self.reference.as_ref().unwrap().leaf.clone());
                self.resolved_entry = Some(Box::new((path, None)));
                return Ok(Some(FileValue::Count(0)));
            }
            PathOperation::ResolveDirectory => {
                if kind != 0o040000 {
                    return Err(Errno(20));
                }
                let mut path = walk.continuation.take().ok_or(Errno(5))?.current;
                path.directory_inode = self.reference.as_ref().unwrap().directory.clone();
                let node = self.reference.as_ref().unwrap().directory.clone().unwrap();
                self.resolved = Some(Box::new((path, node)));
                return Ok(Some(FileValue::Count(0)));
            }
            PathOperation::Chdir | PathOperation::Chroot => {
                if kind != 0o040000 {
                    return Err(Errno(20));
                }
                let directory = self.reference.as_ref().unwrap().directory.clone().unwrap();
                let change = walk.change.take().unwrap();
                let root = matches!(walk.operation, PathOperation::Chroot);
                if walk.fs.local_permissions() {
                    return self.begin_permission(
                        v,
                        v.credentials.clone(),
                        1,
                        permissions::After::Change { change, root },
                    );
                }
                if walk.fs.access_unsupported.load(Ordering::Relaxed) {
                    return Ok(Some(change.publish(directory, root)));
                }
                let mut body = [0; 8];
                body[..4].copy_from_slice(&1u32.to_le_bytes());
                self.request = Some(Arc::new(walk.fs.connection.request(
                    34,
                    node,
                    walk.caller,
                    &body,
                )?));
                self.kind = ResultKind::ChangeDirectory(walk.fs.clone(), change, directory, root);
            }
            PathOperation::Open(flags) => {
                let mount_flags = walk.flags.clone();
                let parent = (!root && walk.fs.local_permissions() && flags & O_CREAT != 0)
                    .then(|| walk.parent_directory.clone());
                if let Some(parent) = parent {
                    self.retain_open_parent(parent);
                }
                return self.begin_open(v, &mount_flags, flags, attr);
            }
            PathOperation::Truncate(length) => {
                let mut path = walk.continuation.take().ok_or(Errno(5))?.current;
                path.directory_inode = self
                    .reference
                    .as_ref()
                    .unwrap()
                    .leaf
                    .clone()
                    .or_else(|| self.reference.as_ref().unwrap().directory.clone());
                let result = v.prepare_path_truncate((path, None), length);
                return self.take_resolution(v, result.map(|_| Some(FileValue::Count(0))));
            }
            PathOperation::Readlink => {
                if kind != 0o120000 {
                    return Err(Errno(22));
                }
                walk.fs
                    .check_inode(self.reference.as_ref().unwrap().leaf.as_ref().unwrap())?;
                self.request = Some(Arc::new(walk.fs.connection.request(
                    5,
                    node,
                    walk.caller,
                    &[],
                )?));
                self.kind = ResultKind::Readlink;
            }
            PathOperation::Statfs => {
                self.request = Some(Arc::new(walk.fs.connection.request(
                    17,
                    node,
                    walk.caller,
                    &[],
                )?));
                self.kind = ResultKind::Statfs(walk.flags.clone());
            }
            PathOperation::Stat => {
                let reference = self.reference.as_ref().unwrap();
                walk.fs.check_inode(
                    reference
                        .leaf
                        .as_ref()
                        .or(reference.directory.as_ref())
                        .unwrap(),
                )?;
                if walk.fs.permission_attr_fresh(
                    self.reference
                        .as_ref()
                        .unwrap()
                        .leaf
                        .as_ref()
                        .or(self.reference.as_ref().unwrap().directory.as_ref())
                        .unwrap(),
                ) {
                    return self.stat_value(attr).map(Some);
                }
                let inode = self
                    .reference
                    .as_ref()
                    .unwrap()
                    .leaf
                    .as_ref()
                    .or(self.reference.as_ref().unwrap().directory.as_ref())
                    .unwrap();
                walk.fs.invalidate_acl(inode);
                self.request = Some(Arc::new(walk.fs.connection.request(
                    3,
                    node,
                    walk.caller,
                    &[0; 16],
                )?));
                self.kind = ResultKind::Stat;
            }
            PathOperation::Access(mask) => {
                let reference = self.reference.as_ref().unwrap();
                walk.fs.check_inode(
                    reference
                        .leaf
                        .as_ref()
                        .or(reference.directory.as_ref())
                        .unwrap(),
                )?;
                if walk.fs.local_permissions() {
                    let flags = walk.flags.clone();
                    if mask & 1 != 0 && kind == 0o100000 && flags.get() & mounts::MS_NOEXEC != 0 {
                        return Err(Errno(13));
                    }
                    return self.begin_permission(
                        v,
                        v.credentials.clone(),
                        mask,
                        permissions::After::Access { mask, flags, kind },
                    );
                }
                if !Self::access_needed(v, &walk.flags, &walk.fs, mask, kind)? {
                    return Ok(Some(FileValue::Count(0)));
                }
                let mut body = [0; 8];
                body[..4].copy_from_slice(&mask.to_le_bytes());
                self.request = Some(Arc::new(walk.fs.connection.request(
                    34,
                    node,
                    walk.caller,
                    &body,
                )?));
                self.kind = ResultKind::Access(access::Access::new(
                    walk.fs.clone(),
                    walk.flags.clone(),
                    mask,
                    kind,
                ));
            }
        }
        Ok(None)
    }
    pub(crate) fn cached_inode(
        v: &Vfs,
        m: &mounts::MountData,
        fs: &Mounted,
        node: &NodeRef,
    ) -> Result<([u8; 128], StatMount)> {
        fs.check(&v.credentials)?;
        fs.check_inode(node)?;
        Ok((
            attribute_stat(
                &inode::attr(node).lock().unwrap()[..],
                m.device(),
                &fs.namespace,
                &v.credentials.user_namespace,
            )?,
            StatMount::mounted(m.id, Arc::ptr_eq(node, &m.root)),
        ))
    }
    pub(crate) fn stat_inode(
        v: &Vfs,
        m: &mounts::MountData,
        fs: &Arc<Mounted>,
        directory: NodeRef,
    ) -> Result<Self> {
        fs.check(&v.credentials)?;
        fs.check_inode(&directory)?;
        let node = directory
            .fuse_directory
            .get()
            .map(|d| d.node)
            .or_else(|| directory.fuse_leaf.get().map(|f| f.node))
            .ok_or(Errno(5))?;
        let is_root = Arc::ptr_eq(&directory, &m.root);
        fs.invalidate_acl(&directory);
        Ok(Self {
            request: Some(Arc::new(fs.connection.request(
                3,
                node,
                fs.caller(v),
                &[0; 16],
            )?)),
            _usage: Some(mounts::MountUse::new(m.identity.clone())),
            resolved: None,
            resolved_entry: None,
            reference: Some(LookupRef::retained(fs, directory)),
            open: None,
            kind: ResultKind::Stat,
            mount: StatMount::mounted(m.id, is_root),
            dev: m.device(),
            owner_ns: fs.namespace.clone(),
            reader_ns: v.credentials.user_namespace.clone(),
        })
    }
    pub(crate) fn readlink_inode(
        v: &Vfs,
        mount: &mounts::MountData,
        fs: &Arc<Mounted>,
        node: NodeRef,
    ) -> Result<Self> {
        fs.check(&v.credentials)?;
        let reference = LookupRef::retained(fs, node);
        Ok(Self {
            request: Some(Arc::new(fs.connection.request(
                5,
                reference.node,
                fs.caller(v),
                &[],
            )?)),
            _usage: Some(mounts::MountUse::new(mount.identity.clone())),
            resolved: None,
            resolved_entry: None,
            reference: Some(reference),
            open: None,
            kind: ResultKind::Readlink,
            mount: StatMount::mounted(mount.id, false),
            dev: mount.device(),
            owner_ns: fs.namespace.clone(),
            reader_ns: v.credentials.user_namespace.clone(),
        })
    }
    pub(crate) fn follow_inode(
        v: &Vfs,
        node: NodeRef,
        walk: PathWalk,
        base: ResolvedPath,
        operation: PathOperation,
    ) -> Result<Self> {
        let mount = walk.current.mount.as_ref().ok_or(Errno(5))?;
        let fs = mount.fs.fuse.as_ref().ok_or(Errno(5))?;
        let mut pending = Self::readlink_inode(v, mount, fs, node)?;
        pending.kind = ResultKind::FollowLink(Box::new(Link {
            walk,
            base,
            operation,
        }));
        Ok(pending)
    }
    pub(crate) fn statfs(
        v: &Vfs,
        m: &mounts::MountData,
        fs: &Arc<Mounted>,
        inode: NodeRef,
    ) -> Result<Self> {
        fs.check(&v.credentials)?;
        let reference = LookupRef::retained(fs, inode);
        Ok(Self {
            request: Some(Arc::new(fs.connection.request(
                17,
                reference.node,
                fs.caller(v),
                &[],
            )?)),
            _usage: Some(mounts::MountUse::new(m.identity.clone())),
            resolved: None,
            resolved_entry: None,
            reference: Some(reference),
            open: None,
            kind: ResultKind::Statfs(m.flags.clone()),
            mount: StatMount::mounted(m.id, true),
            dev: m.device(),
            owner_ns: fs.namespace.clone(),
            reader_ns: v.credentials.user_namespace.clone(),
        })
    }
    pub(crate) fn needs_interrupt(&self) -> bool {
        self.daemon_request()
            .is_some_and(|request| request.needs_interrupt())
    }
    pub(crate) fn host_work(&self) -> bool {
        matches!(
            self.kind,
            ResultKind::NativeWalk(_) | ResultKind::NativeEntry(_)
        )
    }
    pub(crate) fn owner_work(&self) -> bool {
        matches!(self.kind, ResultKind::OwnerWalk(_))
    }
    pub(crate) fn join_owner(&mut self) {
        if self.owner_work() {
            let ResultKind::OwnerWalk(walk) =
                std::mem::replace(&mut self.kind, ResultKind::Readlink)
            else {
                unreachable!()
            };
            self.kind = ResultKind::JoinedWalk(walk);
        }
    }
    pub(crate) fn daemon_request(&self) -> Option<&Arc<Request>> {
        (!matches!(
            self.kind,
            ResultKind::NativeWalk(_)
                | ResultKind::NativeEntry(_)
                | ResultKind::OwnerWalk(_)
                | ResultKind::JoinedWalk(_)
        ))
        .then_some(self.request.as_ref())
        .flatten()
    }
    pub(crate) fn ready(&self) -> bool {
        if let ResultKind::Xattr(operation) = &self.kind {
            if operation.waiting_lock() {
                return operation.lock_ready();
            }
        }
        if let ResultKind::Attributes(operation) = &self.kind {
            if operation.waiting_lock() {
                return operation.lock_ready();
            }
        }
        if let ResultKind::InitWalk(_, fs, _) = &self.kind {
            return fs.connection.initialized();
        }
        self.daemon_request().is_none_or(|request| request.ready())
    }
    pub(crate) fn subscribe(&self, s: &Arc<IoSignal>) -> Option<IoSubscription> {
        if let ResultKind::Xattr(operation) = &self.kind {
            if operation.waiting_lock() {
                return Some(operation.subscribe_lock(s));
            }
        }
        if let ResultKind::Attributes(operation) = &self.kind {
            if operation.waiting_lock() {
                return Some(operation.subscribe_lock(s));
            }
        }
        if let ResultKind::InitWalk(_, fs, _) = &self.kind {
            return Some(fs.connection.subscribe(s));
        }
        self.daemon_request().map(|request| request.subscribe(s))
    }
    pub(crate) fn take(&mut self, v: &mut Vfs) -> Option<Result<FileValue>> {
        if let ResultKind::InitWalk(_, fs, _) = &self.kind {
            if !fs.connection.initialized() {
                return None;
            }
            if let Err(e) = fs.connection.init_result() {
                return Some(Err(e));
            }
            let ResultKind::InitWalk(walk, _, native) =
                std::mem::replace(&mut self.kind, ResultKind::Readlink)
            else {
                unreachable!()
            };
            let (walk, op) = *walk;
            return self.resume_walk_in(v, walk, op, native).transpose();
        }
        if matches!(self.kind, ResultKind::Permission(_)) && self.request.is_none() {
            return self.advance_permission(v, None).transpose();
        }
        if matches!(self.kind, ResultKind::Xattr(_)) && self.request.is_none() {
            if matches!(&self.kind, ResultKind::Xattr(operation) if operation.waiting_lock()) {
                return self.resume_xattr().transpose();
            }
            return Some(self.cached_xattr());
        }
        if matches!(self.kind, ResultKind::Attributes(_)) && self.request.is_none() {
            return self.resume_attributes().transpose();
        }
        if let ResultKind::File(op) = &mut self.kind {
            if self.request.is_none() {
                return Some(op.local_reply());
            }
        }
        if matches!(self.kind, ResultKind::NativeEntry(_)) {
            let ResultKind::NativeEntry(entry) =
                std::mem::replace(&mut self.kind, ResultKind::Readlink)
            else {
                unreachable!()
            };
            let (entry, operation, credentials) = *entry;
            return self
                .resume_entry(v, entry, operation, credentials)
                .transpose();
        }
        if matches!(
            self.kind,
            ResultKind::NativeWalk(_) | ResultKind::JoinedWalk(_)
        ) {
            let native = self.host_work();
            let (ResultKind::NativeWalk(continuation) | ResultKind::JoinedWalk(continuation)) =
                std::mem::replace(&mut self.kind, ResultKind::Readlink)
            else {
                unreachable!()
            };
            let (walk, operation) = *continuation;
            return self.resume_walk_in(v, walk, operation, native).transpose();
        }
        let result = self
            .request
            .as_ref()
            .expect("daemon request phase")
            .take()?;
        if matches!(self.kind, ResultKind::Permission(_)) {
            return self.advance_permission(v, Some(result)).transpose();
        }
        if matches!(self.kind, ResultKind::CreatePermission(_)) {
            return self.advance_create_permission(result).err().map(Err);
        }
        if matches!(result, Err(Errno(2)))
            || matches!(&result, Ok(bytes) if bytes.len()==128 && bytes[..8]==[0;8])
        {
            match self.create_missing() {
                Ok(true) => return None,
                Ok(false) => {}
                Err(error) => return Some(Err(error)),
            }
        }
        if matches!(self.kind, ResultKind::Create(_) | ResultKind::MknodOpen(_)) {
            return self.finish_create(result);
        }
        if let ResultKind::Mutation(mutation) = &mut self.kind {
            return match mutation
                .advance(result, self.request.as_ref().map_or(0, |r| r.attr_version))
            {
                Ok(namespace::Step::Waiting(request)) => {
                    self.request = Some(request);
                    None
                }
                Ok(namespace::Step::Complete(value)) => Some(Ok(value)),
                Err(error) => Some(Err(error)),
            };
        }
        if let ResultKind::ReopenFile(file) = &self.kind {
            let file = file.clone();
            return result
                .and_then(|bytes| {
                    if bytes.len() != 104 {
                        return Err(Errno(5));
                    }
                    let kind = u32::from_le_bytes(bytes[76..80].try_into().unwrap()) & 0o170000;
                    let original =
                        u32::from_le_bytes(file.attr.lock().unwrap()[60..64].try_into().unwrap())
                            & 0o170000;
                    if kind != original {
                        file.attr.make_bad();
                        return Err(Errno(5));
                    }
                    let mut bytes = bytes;
                    if let Some(node) = file.inode() {
                        file.reference.fs.refresh_permission_attr(
                            &node,
                            &mut bytes,
                            self.request.as_ref().map_or(0, |r| r.attr_version),
                            false,
                        )?;
                    }
                    let flags = self.open.as_ref().unwrap().flags;
                    self.begin_open(v, &file.mount.flags, flags, &file.attr.lock().unwrap()[..])
                })
                .transpose();
        }
        if let ResultKind::Open(attr) = self.kind {
            return result
                .and_then(|bytes| {
                    if bytes.len() != 16 {
                        if let Some(fh) = bytes.get(..8) {
                            let r = self.reference.as_ref().unwrap();
                            r.fs.connection.release(
                                r.node,
                                r.caller,
                                u64::from_le_bytes(fh.try_into().unwrap()),
                                self.open.as_ref().unwrap().flags,
                                u32::from_le_bytes(attr[60..64].try_into().unwrap()) & 0o170000
                                    == 0o040000,
                            );
                        }
                        return Err(Errno(5));
                    }
                    let fh = Some(u64::from_le_bytes(bytes[..8].try_into().unwrap()));
                    let open_flags = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
                    if self.open.as_ref().unwrap().flags & O_TRUNC != 0
                        && !self.open.as_ref().unwrap().created
                    {
                        let file = self.open_file(fh, attr, open_flags);
                        let mut operation = Metadata::file_size(v, file, 0, true)?;
                        operation.open = self.open.take();
                        *self = operation;
                        Ok(None)
                    } else {
                        self.publish_open(fh, attr, open_flags).map(Some)
                    }
                })
                .transpose();
        }
        if matches!(self.kind, ResultKind::Xattr(_)) {
            return self.advance_xattr(result).transpose();
        }
        if matches!(self.kind, ResultKind::Attributes(_)) {
            return self.advance_attributes(result).transpose();
        }
        if matches!(self.kind, ResultKind::Preparing(_)) {
            return self.advance_preparation(result).transpose();
        }
        if let ResultKind::File(op) = &mut self.kind {
            let sync = op.after_write_sync();
            let result = op.finish(result);
            if let (Some((file, data_only)), Ok(FileValue::Count(count))) = (sync, &result) {
                if *count == 0 {
                    return Some(result);
                }
                let (position, writer) = op.take_sync_leases();
                let operation = match file.sync(v, data_only, *count, position, writer) {
                    Ok(operation) => operation,
                    Err(error) => return Some(Err(error)),
                };
                *self = operation;
                return None;
            }
            return Some(result);
        }
        if matches!(self.kind, ResultKind::FollowLink(_)) {
            return result
                .and_then(|target| self.follow_link(v, target))
                .transpose();
        }
        if matches!(self.kind, ResultKind::Readlink) {
            return Some(result.and_then(|mut target| {
                if target.len() >= MAX_PATH {
                    return Err(Errno(5));
                }
                if let Some(end) = target.iter().position(|byte| *byte == 0) {
                    target.truncate(end);
                }
                Ok(FileValue::Bytes(target))
            }));
        }
        if matches!(self.kind, ResultKind::Lookup(_)) {
            return result
                .and_then(|bytes| self.advance_lookup(v, bytes))
                .transpose();
        }
        if let ResultKind::ChangeDirectory(fs, change, node, root) = &self.kind {
            return Some(match result {
                Ok(bytes) if bytes.is_empty() => Ok(change.publish(node.clone(), *root)),
                Ok(_) => Err(Errno(5)),
                Err(Errno(38)) => {
                    fs.access_unsupported.store(true, Ordering::Relaxed);
                    Ok(change.publish(node.clone(), *root))
                }
                Err(error) => Err(error),
            });
        }
        if let ResultKind::Access(access) = &self.kind {
            return Some(access.finish(result));
        }
        Some(result.and_then(|bytes| {
            if let ResultKind::Statfs(flags) = &self.kind {
                if bytes.len() != 80 {
                    return Err(Errno(5));
                }
                let mut out = [0; 120];
                out[..8].copy_from_slice(&0x65735546u64.to_le_bytes());
                out[16..56].copy_from_slice(&bytes[..40]);
                for (dst, src) in [(8, 40), (64, 44), (72, 48)] {
                    out[dst..dst + 4].copy_from_slice(&bytes[src..src + 4]);
                }
                out[80..88].copy_from_slice(&flags.statfs().to_le_bytes());
                return Ok(FileValue::Bytes(out.to_vec()));
            }
            if bytes.len() != 104 {
                return Err(Errno(5));
            }
            let mut bytes = bytes;
            let version = self.request.as_ref().map_or(0, |r| r.attr_version);
            let valid = (
                u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            );
            if let ResultKind::FileStat(file) = &self.kind {
                if let Some(node) = file.inode() {
                    file.reference.fs.refresh_inode_at(
                        &node,
                        &mut bytes[16..],
                        version,
                        valid,
                        inode::Update::Read,
                    )?;
                } else {
                    file.attr.refresh(
                        &file.reference.fs,
                        &mut bytes[16..],
                        version,
                        valid,
                        inode::Update::Read,
                    )?;
                }
            } else if let Some(r) = &self.reference {
                if let Some(node) = r.leaf.as_ref().or(r.directory.as_ref()) {
                    r.fs.refresh_inode_at(
                        node,
                        &mut bytes[16..],
                        version,
                        valid,
                        inode::Update::Read,
                    )?;
                }
            }
            self.stat_value(&bytes[16..])
        }))
    }
    fn stat_value(&self, a: &[u8]) -> Result<FileValue> {
        Ok(FileValue::FuseStat(
            attribute_stat(a, self.dev, &self.owner_ns, &self.reader_ns)?,
            self.mount,
        ))
    }
}
fn attribute_stat(
    a: &[u8],
    dev: u64,
    owner_ns: &UserNamespace,
    reader_ns: &UserNamespace,
) -> Result<[u8; 128]> {
    let mut out = [0; 128];
    out[..8].copy_from_slice(&dev.to_le_bytes());
    for (dst, src, len) in [
        (8, 0, 8),
        (16, 60, 4),
        (20, 64, 4),
        (32, 76, 4),
        (48, 8, 8),
        (56, 80, 4),
        (64, 16, 8),
        (72, 24, 8),
        (80, 48, 4),
        (88, 32, 8),
        (96, 52, 4),
        (104, 40, 8),
        (112, 56, 4),
    ] {
        out[dst..dst + len].copy_from_slice(&a[src..src + len]);
    }
    let mode = u32::from_le_bytes(a[60..64].try_into().unwrap()) & 0o177777;
    out[16..20].copy_from_slice(&mode.to_le_bytes());
    for (dst, src, group) in [(24, 68, false), (28, 72, true)] {
        let id = u32::from_le_bytes(a[src..src + 4].try_into().unwrap());
        let global = owner_ns.to_global(group, id).unwrap_or(u32::MAX);
        out[dst..dst + 4].copy_from_slice(&reader_ns.visible(group, global).to_le_bytes());
    }
    Ok(out)
}

struct OpenPlan {
    created: bool,
    sticky_parent: Option<NodeRef>,
    id: u64,
    mount: Arc<mounts::MountData>,
    path: Vec<u8>,
    flags: u32,
    denied: u64,
    link_credentials: (u64, UserNamespace),
    slot: Option<fd_table::ReservedFd>,
    mode: u32,
    umask: Option<Umask>,
    writer: Option<mapped::MountWrite>,
    publication: Option<DirectFiles>,
}

mod access;
mod attributes;
mod cache;
mod inode;
mod permissions;
#[path = "mount/acl.rs"]
mod posix;
mod xattr;
pub(crate) use attributes::AttributeChange;
pub(crate) use xattr::XattrCall;
mod create;
mod directory;
mod leaf;
mod parents;
mod reopen;
pub(crate) use leaf::Leaf;
pub(crate) use parents::ParentStep;
pub(crate) use parents::{NamespaceTarget, PendingNamespace};
mod walk;
pub(crate) use directory::Directory;
mod file;
mod killpriv;
mod namespace;
pub use file::DirectoryReply;
pub(crate) use file::File;
use file::FileResult;
pub(crate) use namespace::{Action as NamespaceAction, PathPlan};
