// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

pub(crate) struct Mounted {
    pub connection: Arc<Connection>,
    namespace: UserNamespace,
    uid: u32,
    gid: u32,
    allow_other: bool,
    access_unsupported: std::sync::atomic::AtomicBool,
}

impl Drop for Mounted {
    fn drop(&mut self) {
        self.connection.abort();
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
pub(crate) fn prepare(v: &Vfs, data: &[u8]) -> Result<(FsHandle, Binding)> {
    let ns = &v.credentials.user_namespace;
    let opts = Options::parse(data, ns)?;
    let dev = v.fuse_device(opts.fd)?.ok_or(Errno(22))?;
    if dev.namespace != *ns {
        return Err(Errno(22));
    }
    let c = Caller {
        uid: ns.visible(false, v.credentials.fsuid),
        gid: ns.visible(true, v.credentials.fsgid),
        pid: v.pid_ns.local(v.pid),
    };
    let mut fs = mounts::ram_filesystem(0, 1, opts.mode, opts.uid, opts.gid, false)?;
    let connection = Connection::new(c);
    dev.reserve()?;
    let binding = Binding {
        device: dev,
        daemon: Some(Arc::new(Daemon(connection.clone()))),
    };
    fs.fuse = Some(Arc::new(Mounted {
        connection,
        namespace: ns.clone(),
        uid: opts.uid,
        gid: opts.gid,
        allow_other: opts.allow_other,
        access_unsupported: Default::default(),
    }));
    Ok((fs, binding))
}

// Wire offsets below are the Linux ARM64 fuse_attr_out and struct stat ABIs.
enum ResultKind {
    Stat,
    Statfs(u64),
    Access(Arc<Mounted>),
}
pub(crate) struct Metadata {
    pub(crate) request: Arc<Request>,
    kind: ResultKind,
    mount: StatMount,
    dev: u64,
    owner_ns: UserNamespace,
    reader_ns: UserNamespace,
}
impl Metadata {
    pub(crate) fn start(v: &Vfs, m: &mounts::MountData, fs: &Mounted) -> Result<Self> {
        fs.check(&v.credentials)?;
        let request = fs.connection.request(3, 1, fs.caller(v), &[0; 16])?;
        Ok(Self {
            request: Arc::new(request),
            kind: ResultKind::Stat,
            mount: StatMount {
                id: m.id,
                is_root: true,
            },
            dev: m.device(),
            owner_ns: fs.namespace.clone(),
            reader_ns: v.credentials.user_namespace.clone(),
        })
    }
    pub(crate) fn statfs(v: &Vfs, m: &mounts::MountData, fs: &Mounted, flags: u64) -> Result<Self> {
        fs.check(&v.credentials)?;
        Ok(Self {
            request: Arc::new(fs.connection.request(17, 1, fs.caller(v), &[])?),
            kind: ResultKind::Statfs(flags),
            mount: StatMount {
                id: m.id,
                is_root: true,
            },
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
            kind: ResultKind::Access(fs.clone()),
            mount: StatMount {
                id: m.id,
                is_root: true,
            },
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
    pub(crate) fn take(&self) -> Option<Result<FileValue>> {
        let result = self.request.take()?;
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
            let a = &bytes[16..];
            let mut out = [0; 128];
            out[..8].copy_from_slice(&self.dev.to_le_bytes());
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
                let global = self.owner_ns.to_global(group, id).ok_or(Errno(75))?;
                out[dst..dst + 4]
                    .copy_from_slice(&self.reader_ns.visible(group, global).to_le_bytes());
            }
            Ok(FileValue::FuseStat(out, self.mount))
        }))
    }
}
