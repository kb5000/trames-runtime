// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

pub(crate) struct Mounted {
    pub connection: Arc<Connection>,
    filesystem: FsHandle,
    controller: Arc<Controller>,
    minor: u64,
    namespace: UserNamespace,
    uid: u32,
    gid: u32,
    allow_other: bool,
    access_unsupported: std::sync::atomic::AtomicBool,
    flush_unsupported: std::sync::atomic::AtomicBool,
}

impl Drop for Mounted {
    fn drop(&mut self) {
        self.connection.abort();
        self.controller.remove(self.minor);
    }
}
impl Mounted {
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
            pid: v.pid_ns.local(v.pid),
        }
    }
}

struct Options {
    fd: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    allow_other: bool,
}
impl Options {
    fn parse(data: &[u8], ns: &UserNamespace) -> Result<Self> {
        let text = std::str::from_utf8(data).map_err(|_| Errno(22))?;
        let (mut fd, mut uid, mut gid, mut mode) = (None, None, None, None);
        let mut allow_other = false;
        for word in text.split(',') {
            if word == "allow_other" {
                allow_other = true;
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
        })
    }
}
pub(crate) struct Binding {
    device: Arc<Device>,
    daemon: Option<Arc<Daemon>>,
}
impl Binding {
    pub(crate) fn publish(mut self) {
        let daemon = self.daemon.take().expect("reserved binding");
        self.device.install(daemon);
    }
}
impl Drop for Binding {
    fn drop(&mut self) {
        if self.daemon.is_some() {
            self.device.reserved.store(false, Ordering::Release);
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
        let mut fs = mounted.filesystem.clone();
        fs.fuse = Some(mounted);
        return Ok((fs, None));
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
        filesystem: fs.clone(),
        controller,
        minor,
        namespace: ns.clone(),
        uid: opts.uid,
        gid: opts.gid,
        allow_other: opts.allow_other,
        access_unsupported: Default::default(),
        flush_unsupported: Default::default(),
    });
    let binding = Binding {
        device: dev,
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
    Readlink,
    Open(u32),
    Access(u32),
}
struct LookupRef {
    fs: Arc<Mounted>,
    caller: Caller,
    node: u64,
}
impl Drop for LookupRef {
    fn drop(&mut self) {
        self.fs.connection.forget(self.node, self.caller);
    }
}
struct Lookup {
    fs: Arc<Mounted>,
    caller: Caller,
    names: VecDeque<Vec<u8>>,
    follow: bool,
    directory: bool,
    flags: u64,
    operation: PathOperation,
}
enum ResultKind {
    Open([u8; 88]),
    FileStat(Arc<File>),
    File(FileResult),
    Readlink,
    Lookup(Lookup),
    Stat,
    Statfs(u64),
    Access(Arc<Mounted>),
}
pub(crate) struct Metadata {
    pub(crate) request: Arc<Request>,
    kind: ResultKind,
    reference: Option<LookupRef>,
    open: Option<Box<OpenPlan>>,
    mount: StatMount,
    dev: u64,
    owner_ns: UserNamespace,
    reader_ns: UserNamespace,
}
impl Metadata {
    pub(crate) fn prepare_open(
        &mut self,
        id: u64,
        mount: Arc<mounts::MountData>,
        path: Vec<u8>,
        flags: u32,
        denied: u64,
    ) {
        self.open = Some(Box::new(OpenPlan {
            id,
            mount,
            path,
            flags,
            denied,
            slot: None,
        }));
    }
    pub(crate) fn reserve_open(&mut self, slot: fd_table::ReservedFd) {
        self.open.as_mut().expect("FUSE open intent").slot = Some(slot);
    }
    fn publish_open(&mut self, fh: Option<u64>, attr: [u8; 88]) -> Result<FileValue> {
        let plan = *self.open.take().expect("FUSE open operands");
        let file = Arc::new(File {
            reference: self.reference.take().expect("looked-up inode"),
            fh,
            flags: plan.flags & !(O_CLOEXEC | OPEN_ONLY_FLAGS)
                | if fh.is_some() { O_LARGEFILE } else { 0 },
            attr: std::sync::Mutex::new(attr),
            position_busy: Default::default(),
            position_changed: Default::default(),
            mount: plan.mount.clone(),
        });
        let descriptor = events::mounted_resource_descriptor(
            plan.id,
            file.flags | plan.flags & O_CLOEXEC,
            FdKind::Node(plan.path),
            None,
            Some(events::SharedControl::FuseFile(file)),
            None,
            Some(OpenMount::Shared(plan.mount)),
        );
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
        m: &mounts::MountData,
        fs: &Arc<Mounted>,
        first: Vec<u8>,
        names: VecDeque<Vec<u8>>,
        follow: bool,
        directory: bool,
        operation: PathOperation,
    ) -> Result<Self> {
        fs.check(&v.credentials)?;
        let caller = fs.caller(v);
        Ok(Self {
            request: Self::lookup_request(fs, 1, caller, first)?,
            kind: ResultKind::Lookup(Lookup {
                fs: fs.clone(),
                caller,
                names,
                follow,
                directory,
                operation,
                flags: m.flags.get(),
            }),
            reference: None,
            open: None,
            mount: StatMount::mounted(m.id, false),
            dev: m.device(),
            owner_ns: fs.namespace.clone(),
            reader_ns: v.credentials.user_namespace.clone(),
        })
    }
    fn advance_lookup(&mut self, bytes: Vec<u8>) -> Result<Option<FileValue>> {
        let ResultKind::Lookup(walk) = &mut self.kind else {
            unreachable!()
        };
        // The lookup reference belongs to the daemon's nodeid; attr.ino is
        // separately chosen by the filesystem for stat(2).
        if let Some(node) = transport::lookup_id(&bytes) {
            self.reference = Some(LookupRef {
                fs: walk.fs.clone(),
                caller: walk.caller,
                node,
            });
        } else {
            return Err(if bytes.len() == 128 && bytes[..8] == [0; 8] {
                Errno(2)
            } else {
                Errno(5)
            });
        }
        if bytes.len() != 128 {
            return Err(Errno(5));
        }
        let node = self.reference.as_ref().unwrap().node;
        let attr = &bytes[40..];
        let mode = u32::from_le_bytes(attr[60..64].try_into().unwrap());
        let kind = mode & 0o170000;
        if !matches!(
            kind,
            0o010000 | 0o020000 | 0o040000 | 0o060000 | 0o100000 | 0o120000 | 0o140000
        ) {
            return Err(Errno(5));
        }
        if kind == 0o120000 && (walk.follow || walk.directory || !walk.names.is_empty()) {
            return Err(Errno(95));
        }
        if (walk.directory || !walk.names.is_empty()) && kind != 0o040000 {
            return Err(Errno(20));
        }
        if let Some(name) = walk.names.pop_front() {
            self.request = Self::lookup_request(&walk.fs, node, walk.caller, name)?;
            return Ok(None);
        }
        match walk.operation {
            PathOperation::Open(flags) => {
                if flags & O_DIRECTORY != 0 && kind != 0o040000 {
                    return Err(Errno(20));
                }
                if flags & O_PATH != 0 {
                    return self.publish_open(None, attr.try_into().unwrap()).map(Some);
                }
                let access = if kind == 0o040000 {
                    landlock::READ_DIR
                } else {
                    (if fd_can_read(flags) {
                        landlock::READ_FILE
                    } else {
                        0
                    }) | (if fd_can_write(flags) {
                        landlock::WRITE_FILE
                    } else {
                        0
                    }) | (if flags & O_TRUNC != 0 {
                        landlock::TRUNCATE
                    } else {
                        0
                    })
                };
                if self.open.as_ref().expect("FUSE open intent").denied & access != 0 {
                    return Err(Errno(13));
                }
                if kind == 0o120000 {
                    return Err(Errno(40));
                }
                if flags & O_CREAT != 0 && flags & 0x80 != 0 {
                    return Err(Errno(17));
                }
                if fd_can_write(flags) && walk.flags & mounts::MS_RDONLY != 0 {
                    return Err(Errno(30));
                }
                if kind != 0o100000 || flags & (O_TRUNC | O_DIRECT | 0x400) != 0 {
                    return Err(Errno(95));
                }
                let mut body = [0; 8];
                let open_flags = flags & !(O_CLOEXEC | OPEN_ONLY_FLAGS) | O_LARGEFILE;
                body[..4].copy_from_slice(&open_flags.to_le_bytes());
                self.request =
                    Arc::new(walk.fs.connection.request(14, node, walk.caller, &body)?);
                self.kind = ResultKind::Open(attr.try_into().unwrap());
            }
            PathOperation::Readlink => {
                if kind != 0o120000 {
                    return Err(Errno(22));
                }
                self.request = Arc::new(walk.fs.connection.request(5, node, walk.caller, &[])?);
                self.kind = ResultKind::Readlink;
            }
            PathOperation::Stat => {
                if bytes[24..32] != [0; 8] || bytes[36..40] != [0; 4] {
                    return self.stat_value(attr).map(Some);
                }
                self.request =
                    Arc::new(walk.fs.connection.request(3, node, walk.caller, &[0; 16])?);
                self.kind = ResultKind::Stat;
            }
            PathOperation::Access(mask) => {
                if mask & 2 != 0 && walk.flags & mounts::MS_RDONLY != 0 {
                    return Err(Errno(30));
                }
                if mask & 1 != 0 && kind == 0o100000 && walk.flags & mounts::MS_NOEXEC != 0 {
                    return Err(Errno(13));
                }
                if mask == 0 || walk.fs.access_unsupported.load(Ordering::Relaxed) {
                    return Ok(Some(FileValue::Count(0)));
                }
                let mut body = [0; 8];
                body[..4].copy_from_slice(&mask.to_le_bytes());
                self.request =
                    Arc::new(walk.fs.connection.request(34, node, walk.caller, &body)?);
                self.kind = ResultKind::Access(walk.fs.clone());
            }
        }
        Ok(None)
    }
    pub(crate) fn start(v: &Vfs, m: &mounts::MountData, fs: &Mounted) -> Result<Self> {
        fs.check(&v.credentials)?;
        let request = fs.connection.request(3, 1, fs.caller(v), &[0; 16])?;
        Ok(Self {
            request: Arc::new(request),
            reference: None,
            open: None,
            kind: ResultKind::Stat,
            mount: StatMount::mounted(m.id, true),
            dev: m.device(),
            owner_ns: fs.namespace.clone(),
            reader_ns: v.credentials.user_namespace.clone(),
        })
    }
    pub(crate) fn statfs(v: &Vfs, m: &mounts::MountData, fs: &Mounted, flags: u64) -> Result<Self> {
        fs.check(&v.credentials)?;
        Ok(Self {
            request: Arc::new(fs.connection.request(17, 1, fs.caller(v), &[])?),
            reference: None,
            open: None,
            kind: ResultKind::Statfs(flags),
            mount: StatMount::mounted(m.id, true),
            dev: m.device(),
            owner_ns: fs.namespace.clone(),
            reader_ns: v.credentials.user_namespace.clone(),
        })
    }
    pub(crate) fn needs_interrupt(&self) -> bool {
        self.request.needs_interrupt()
    }
    pub(crate) fn access(
        v: &Vfs,
        m: &mounts::MountData,
        fs: &Arc<Mounted>,
        mask: u32,
    ) -> Result<Option<Self>> {
        fs.check(&v.credentials)?;
        if fs.access_unsupported.load(Ordering::Relaxed) || mask == 0 {
            return Ok(None);
        }
        let mut body = [0; 8];
        body[..4].copy_from_slice(&mask.to_le_bytes());
        Ok(Some(Self {
            request: Arc::new(fs.connection.request(34, 1, fs.caller(v), &body)?),
            reference: None,
            open: None,
            kind: ResultKind::Access(fs.clone()),
            mount: StatMount::mounted(m.id, true),
            dev: m.device(),
            owner_ns: fs.namespace.clone(),
            reader_ns: v.credentials.user_namespace.clone(),
        }))
    }
    pub(crate) fn ready(&self) -> bool {
        self.request.ready()
    }
    pub(crate) fn subscribe(&self, s: &Arc<IoSignal>) -> IoSubscription {
        self.request.subscribe(s)
    }
    pub(crate) fn take(&mut self) -> Option<Result<FileValue>> {
        let result = self.request.take()?;
        if let ResultKind::Open(attr) = self.kind {
            return Some(result.and_then(|bytes| {
                if bytes.len() != 16 {
                    if let Some(fh) = bytes.get(..8) {
                        let r = self.reference.as_ref().unwrap();
                        r.fs.connection.release(
                            r.node,
                            r.caller,
                            u64::from_le_bytes(fh.try_into().unwrap()),
                            self.open.as_ref().unwrap().flags,
                        );
                    }
                    return Err(Errno(5));
                }
                self.publish_open(
                    Some(u64::from_le_bytes(bytes[..8].try_into().unwrap())),
                    attr,
                )
            }));
        }
        if let ResultKind::File(op) = &self.kind {
            return Some(op.finish(result));
        }
        if matches!(self.kind, ResultKind::Readlink) {
            return Some(result.and_then(|target| {
                if target.is_empty() || target.len() >= MAX_PATH || target.contains(&0) {
                    Err(Errno(5))
                } else {
                    Ok(FileValue::Bytes(target))
                }
            }));
        }
        if matches!(self.kind, ResultKind::Lookup(_)) {
            return result
                .and_then(|bytes| self.advance_lookup(bytes))
                .transpose();
        }
        if let ResultKind::Access(fs) = &self.kind {
            return Some(match result {
                Ok(bytes) if bytes.is_empty() => Ok(FileValue::Count(0)),
                Ok(_) => Err(Errno(5)),
                Err(Errno(38)) => {
                    fs.access_unsupported.store(true, Ordering::Relaxed);
                    Ok(FileValue::Count(0))
                }
                Err(e) => Err(e),
            });
        }
        Some(result.and_then(|bytes| {
            if let ResultKind::Statfs(flags) = self.kind {
                if bytes.len() != 80 {
                    return Err(Errno(5));
                }
                let mut out = [0; 120];
                out[..8].copy_from_slice(&0x65735546u64.to_le_bytes());
                out[16..56].copy_from_slice(&bytes[..40]);
                for (dst, src) in [(8, 40), (64, 44), (72, 48)] {
                    out[dst..dst + 4].copy_from_slice(&bytes[src..src + 4]);
                }
                out[80..88].copy_from_slice(&flags.to_le_bytes());
                return Ok(FileValue::Bytes(out.to_vec()));
            }
            if bytes.len() != 104 {
                return Err(Errno(5));
            }
            let value = self.stat_value(&bytes[16..])?;
            if let ResultKind::FileStat(file) = &self.kind {
                file.refresh(&bytes[16..])?;
            }
            Ok(value)
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
    for (dst, src, group) in [(24, 68, false), (28, 72, true)] {
        let id = u32::from_le_bytes(a[src..src + 4].try_into().unwrap());
        let global = owner_ns.to_global(group, id).ok_or(Errno(75))?;
        out[dst..dst + 4].copy_from_slice(&reader_ns.visible(group, global).to_le_bytes());
    }
    Ok(out)
}

struct OpenPlan {
    id: u64,
    mount: Arc<mounts::MountData>,
    path: Vec<u8>,
    flags: u32,
    denied: u64,
    slot: Option<fd_table::ReservedFd>,
}

mod file;
pub(crate) use file::File;
use file::FileResult;
