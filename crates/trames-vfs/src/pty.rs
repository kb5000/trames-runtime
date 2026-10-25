// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest-owned PTYs. Descriptor aliases share an endpoint; the last close hangs up.
use super::*;
use terminal::Terminal;
mod shared;
pub use shared::{PtyIo, PtySlaveEndpoint, TerminalAccess};

pub struct Pty {
    pub number: u32,
    pub(super) mount: Option<Rc<Mount>>,
    slave: NodeRef,
    pub(super) io: Arc<PtyIo>,
    pub locked: Cell<bool>,
    pub hangup_notified: Cell<bool>,
    pub host_resize_pending: Cell<bool>,
    pub host_signals: Cell<u64>,
}
pub struct PtyEnd {
    pub pair: Rc<Pty>,
    pub master: bool,
    slave: Option<Arc<PtySlaveEndpoint>>,
}
impl PtyEnd {
    pub(super) fn new(pair: Rc<Pty>, master: bool) -> Rc<Self> {
        let slave = (!master).then(|| PtySlaveEndpoint::open(pair.io.clone()));
        Rc::new(Self {
            pair,
            master,
            slave,
        })
    }
    /// Capture only for an accepted operation. The master still requires its
    /// devpts and task/job-control close effects and has no shared lease yet.
    pub fn slave_endpoint(&self) -> Option<Arc<PtySlaveEndpoint>> {
        self.slave.clone()
    }
}
impl Drop for PtyEnd {
    fn drop(&mut self) {
        if self.master {
            self.pair.master_alive.store(false, Ordering::Relaxed);
            self.pair.notify();
            if let Some(mount) = self.pair.mount.as_ref().filter(|m| m.devpts.is_some()) {
                let key = format!("/{}", self.pair.number).into_bytes();
                let mut fs = mount.fs.borrow_mut();
                if fs
                    .paths
                    .get(&key)
                    .is_some_and(|node| Arc::ptr_eq(node, &self.pair.slave))
                {
                    fs.paths.remove(&key);
                    self.pair.slave.borrow_mut().links = 0;
                }
            }
        }
        // Preserve the metadata projection through ordinary final-close
        // callbacks; an explicitly retained slave may finish on a worker later.
        drop(self.slave.take());
    }
}
impl std::ops::Deref for Pty {
    type Target = PtyIo;
    fn deref(&self) -> &PtyIo {
        &self.io
    }
}
impl Pty {
    pub fn resize_from_host(&self, rows: u16, columns: u16) {
        let mut tty = self.terminal.borrow_mut();
        let before = tty.window;
        tty.resize(rows, columns);
        if before != tty.window {
            self.host_resize_pending.set(true);
        }
    }
    pub(super) fn private(&self) -> bool {
        self.mount.as_ref().is_some_and(|m| m.devpts.is_some())
    }
}
impl Vfs {
    pub fn set_controlling_terminal(&mut self, id: Option<u32>) -> Result<()> {
        self.controlling_pair = match id {
            Some(id) if id != 0 => Some(self.pty_by_id(id).ok_or(Errno(6))?),
            _ => None,
        };
        self.controlling_terminal = id;
        Ok(())
    }
    pub fn pty(&self, fd: u32) -> Result<Option<Rc<PtyEnd>>> {
        Ok(self.descriptor(fd)?.open.borrow().pty.clone())
    }
    pub fn pty_by_id(&self, id: u32) -> Option<Rc<Pty>> {
        self.ptys.borrow().get(&id).and_then(Weak::upgrade)
    }
    pub fn live_ptys(&self) -> Vec<Rc<Pty>> {
        self.ptys
            .borrow()
            .values()
            .filter_map(Weak::upgrade)
            .collect()
    }
    pub(super) fn allocate_pty(&mut self, at: &ResolvedPath) -> Result<Rc<PtyEnd>> {
        // A /dev/ptmx device node refers to the devpts mounted beside it;
        // devpts/ptmx and bind mounts retain the filesystem they came from.
        let mount = if at.mount.as_ref().is_some_and(|m| m.devpts.is_some()) {
            at.mount.clone()
        } else {
            let mut path = self.path_visible(&at.parent())?;
            if path != b"/" {
                path.push(b'/');
            }
            path.extend_from_slice(b"pts");
            self.resolve(AT_FDCWD, &path)
                .ok()
                .and_then(|p| p.mount)
                .filter(|m| m.kind == mounts::Kind::Devpts)
        };
        let id = (1..4096)
            .find(|id| self.pty_by_id(*id).is_none())
            .ok_or(Errno(28))?;
        let mut tty = Terminal::default();
        tty.session = 0;
        tty.foreground = 0;
        let (number, slave) = if let Some(pts) = mount.as_ref().and_then(|m| m.devpts.as_ref()) {
            let number = (0..pts.max)
                .find(|n| {
                    !pts.fs
                        .borrow()
                        .paths
                        .contains_key(format!("/{n}").as_bytes())
                })
                .ok_or(Errno(28))?;
            let node = pts.node(
                format!("/{number}").into_bytes(),
                Content::Device(pseudo::Device::Pts(id, number)),
                0o20000 | pts.mode,
                pts.uid.unwrap_or(self.credentials.fsuid),
                pts.gid.unwrap_or(self.credentials.fsgid),
            );
            (number, node)
        } else {
            let path = format!("/dev/pts/{id}").into_bytes();
            let mut pseudo = self.pseudo.borrow_mut();
            pseudo.nodes.remove(&(0, path.clone()));
            let node = pseudo.cache(
                0,
                &path,
                Content::Device(pseudo::Device::Pts(id, id)),
                0o20620,
            )?;
            node.borrow_mut().uid = self.credentials.fsuid;
            node.borrow_mut().gid = 5;
            (id, node)
        };
        let pair = Rc::new(Pty {
            number,
            mount,
            slave,
            io: Arc::new(PtyIo::new(id, tty)),
            locked: Cell::new(true),
            hangup_notified: Cell::new(false),
            host_resize_pending: Cell::new(false),
            host_signals: Cell::new(0),
        });
        self.ptys.borrow_mut().insert(id, Rc::downgrade(&pair));
        Ok(PtyEnd::new(pair, true))
    }
    /// TIOCGPTPEER follows the master's devpts identity even after chroot or
    /// lazy unmount, rather than reopening a path in the caller's namespace.
    pub fn open_pty_peer(&mut self, fd: u32, flags: u32) -> Result<u32> {
        let end = self.pty(fd)?.filter(|end| end.master).ok_or(Errno(25))?;
        if flags & !(3 | 0x100 | O_NONBLOCK | O_CLOEXEC) != 0 || flags & 3 != 2 {
            return Err(Errno(22));
        }
        if end.pair.locked.get() {
            return Err(Errno(5));
        }
        let fd = self.available(0)?;
        let node = end.pair.slave.clone();
        if !self.allowed(&node.borrow(), 6) {
            return Err(Errno(13));
        }
        self.check_device_open(&node.borrow(), flags)?;
        self.fds.insert(
            fd,
            Descriptor {
                open: OpenHandle::new(OpenDescription {
                    shared: Arc::new(SharedOpenDescription {
                        read_node: None,
                        id: self.open_id(),
                        owner: (self.credentials.fsuid, self.credentials.fsgid),
                        kind: FdKind::Terminal,
                        flags: (flags & !O_CLOEXEC).into(),
                        file_position: Arc::default(),
                        flock: std::sync::OnceLock::new(),
                        node: Some(node),
                        pipe: None,
                        bridge: None,
                        kernel_log: None,
                        notification: None,
                    }),
                    position: 0,
                    socket: None,
                    anonymous: None,
                    local: None,
                    namespace: None,
                    network_control: None,
                    oom: None,
                    mount: end.pair.mount.clone(),
                    pty: Some(PtyEnd::new(end.pair.clone(), false)),
                }),
                cloexec: (flags & O_CLOEXEC != 0).into(),
            },
        );
        Ok(fd)
    }
}

/// A mount-owned devpts filesystem. Slave numbers are local; scheduler IDs
/// remain guest-wide so controlling terminals cannot alias across containers.
pub(super) struct Devpts {
    pub fs: FsHandle,
    uid: Option<u32>,
    gid: Option<u32>,
    mode: u32,
    max: u32,
    device: u64,
}
impl Devpts {
    pub fn new(device: u64, data: &[u8]) -> Result<Self> {
        let mut uid = None;
        let mut gid = None;
        let mut mode = 0o600;
        let mut ptmxmode = 0;
        let mut max = 4096;
        for item in data.split(|b| *b == b',').filter(|s| !s.is_empty()) {
            if item == b"newinstance" {
                continue;
            }
            let at = item.iter().position(|b| *b == b'=').ok_or(Errno(22))?;
            let key = &item[..at];
            let text = std::str::from_utf8(&item[at + 1..]).map_err(|_| Errno(22))?;
            let radix = if matches!(key, b"mode" | b"ptmxmode") {
                8
            } else {
                10
            };
            let value = u32::from_str_radix(text, radix).map_err(|_| Errno(22))?;
            match key {
                b"uid" if value != u32::MAX => uid = Some(value),
                b"gid" if value != u32::MAX => gid = Some(value),
                b"mode" => mode = value & 0o777,
                b"ptmxmode" => ptmxmode = value & 0o777,
                b"max" => max = value.min(4096),
                _ => return Err(Errno(22)),
            }
        }
        let out = Self {
            fs: FsHandle::new(Filesystem {
                shared_budget: trames_shared::SharedBudget::new(memfd::MEMFD_BYTES as usize),
                paths: BTreeMap::new(),
                inodes: Vec::new(),
                next_inode: 1,
                limits: StorageLimits::memory(),
                disk: None,
                volume: None,
            }),
            uid,
            gid,
            mode,
            max,
            device,
        };
        out.node(b"/".to_vec(), Content::Directory, 0o40755, 0, 0);
        out.node(
            b"/ptmx".to_vec(),
            Content::Device(pseudo::Device::Ptmx),
            0o20000 | ptmxmode,
            0,
            0,
        );
        Ok(out)
    }
    fn node(&self, path: Vec<u8>, content: Content, mode: u32, uid: u32, gid: u32) -> NodeRef {
        let mut fs = self.fs.borrow_mut();
        // Linux devpts inode numbers are local to st_dev: root=1, ptmx=2,
        // slave=index+3. runc validates ptmx's inode before using the handle.
        let inode = match &content {
            Content::Directory => 1,
            Content::Device(pseudo::Device::Ptmx) => 2,
            Content::Device(pseudo::Device::Pts(_, number)) => u64::from(*number) + 3,
            _ => unreachable!("devpts only contains its root, ptmx and slaves"),
        };
        let node = Arc::new(Inode::new(Node {
            identity: 0,
            record_locks: std::sync::OnceLock::new(),
            whole_locks: std::sync::OnceLock::new(),
            notifications: inotify::Marks::default(),
            path_hint: SharedCell::default(),
            inode,
            device: self.device,
            content,
            mode,
            uid,
            gid,
            volatile: true,
            links: 1,
            times: [storage::Timestamp::now(); 3],
            xattrs: BTreeMap::new(),
            seals: None,
        }));
        fs.inodes.retain(|n| n.strong_count() != 0);
        fs.inodes.push(Arc::downgrade(&node));
        fs.paths.insert(path, node.clone());
        node
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn mount(v: &mut Vfs, path: &[u8]) {
        v.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
        v.mount(
            Some(b"devpts"),
            path,
            Some(b"devpts"),
            0,
            Some(b"newinstance,mode=0620,ptmxmode=0666,gid=5,max=2"),
        )
        .unwrap();
    }
    #[test]
    fn retained_pty_bytes_do_not_keep_guest_endpoints_open() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        mount(&mut v, b"/pts");
        let master = v.open_at(AT_FDCWD, b"/pts/ptmx", 2, 0).unwrap();
        v.pty(master).unwrap().unwrap().pair.locked.set(false);
        let slave = v.open_pty_peer(master, 2).unwrap();
        let direct = v.direct_descriptors();
        let read = direct.get(master).unwrap();
        let write = direct.get(slave).unwrap();
        let access = Some(TerminalAccess {
            session: 0,
            group: 0,
            controlling: None,
            ignore_ttou: false,
        });
        assert_eq!(write.terminal_write(b"buffered\n", access), Some(Ok(9)));
        v.close(slave).unwrap();
        assert_eq!(read.poll_ready(1).unwrap() & 17, 17);
        assert_eq!(read.read(32), Ok(b"buffered\r\n".to_vec()));
        assert_eq!(read.read(1), Err(Errno(5)));
        v.close(master).unwrap();
        assert_eq!(write.terminal_write(b"closed", access), Some(Err(Errno(5))));
        assert_eq!(write.terminal_read(1, access), Some(Ok(vec![])));
        assert_eq!(write.poll_ready(5), Some(25));
    }
    #[test]
    fn accepted_slave_survives_alias_close_and_fd_reuse_then_worker_notifies_hup() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<PtySlaveEndpoint>();
        struct Wake {
            master: DirectFd,
            calls: std::sync::atomic::AtomicUsize,
        }
        impl IoWake for Wake {
            fn wake_io(&self, _: &Arc<IoSignal>) {
                // Reenter terminal locking from the final-close callback.
                assert_eq!(self.master.poll_ready(1), Some(16));
                assert_eq!(self.master.read(1), Err(Errno(5)));
                self.calls.fetch_add(1, Ordering::Relaxed);
            }
        }
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        mount(&mut v, b"/pts");
        let master = v.open_at(AT_FDCWD, b"/pts/ptmx", 2, 0).unwrap();
        let pair = v.pty(master).unwrap().unwrap().pair.clone();
        pair.locked.set(false);
        assert!(v.pty(master).unwrap().unwrap().slave_endpoint().is_none());
        let slave = v.open_pty_peer(master, 2).unwrap();
        let lease = v.pty(slave).unwrap().unwrap().slave_endpoint().unwrap();
        let alias = v.dup(slave, 0, false).unwrap();
        let mut child = v.clone();
        let bytes = v.direct_descriptors();
        v.close(slave).unwrap();
        v.close(alias).unwrap();
        child.close_all();
        assert_eq!(
            v.open_at(AT_FDCWD, b"/replacement", 0x42, 0o600).unwrap(),
            slave
        );
        assert_eq!(pair.slaves.load(Ordering::Relaxed), 1);
        assert_eq!(bytes.get(master).unwrap().read(1), Err(Errno(11)));
        let wake = Arc::new(Wake {
            master: bytes.get(master).unwrap().clone(),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let target: Arc<dyn IoWake> = wake.clone();
        let signal = IoSignal::new(1, Arc::downgrade(&target));
        let subscription = bytes.get(master).unwrap().subscribe(&signal);
        std::thread::spawn(move || drop(lease)).join().unwrap();
        assert!(signal.ready());
        assert_eq!(wake.calls.load(Ordering::Relaxed), 1);
        assert_eq!(pair.slaves.load(Ordering::Relaxed), 0);
        drop(subscription);
        // Closing the last slave does not delete the master's devpts entry;
        // reopening it creates a real new endpoint and clears master HUP.
        assert!(v.stat_at(AT_FDCWD, b"/pts/0").is_ok());
        let reopened = v.open_at(AT_FDCWD, b"/pts/0", 2, 0).unwrap();
        assert_eq!(pair.slaves.load(Ordering::Relaxed), 1);
        assert_eq!(bytes.get(master).unwrap().poll_ready(1), Some(0));
        v.close(reopened).unwrap();
        assert_eq!(bytes.get(master).unwrap().poll_ready(1), Some(16));
    }
    #[test]
    fn independent_slave_opens_and_parallel_alias_drops_preserve_buffered_output() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        mount(&mut v, b"/pts");
        let master = v.open_at(AT_FDCWD, b"/pts/ptmx", 2, 0).unwrap();
        let pair = v.pty(master).unwrap().unwrap().pair.clone();
        pair.locked.set(false);
        let first = v.open_pty_peer(master, 2).unwrap();
        let second = v.open_at(AT_FDCWD, b"/pts/0", 2, 0).unwrap();
        let one = v.pty(first).unwrap().unwrap().slave_endpoint().unwrap();
        let two = v.pty(second).unwrap().unwrap().slave_endpoint().unwrap();
        assert!(!Arc::ptr_eq(&one, &two));
        let aliases: Vec<_> = (0..8).map(|_| one.clone()).collect();
        assert_eq!(pair.slaves.load(Ordering::Relaxed), 2);
        let bytes = v.direct_descriptors();
        let access = Some(TerminalAccess {
            session: 0,
            group: 0,
            controlling: None,
            ignore_ttou: false,
        });
        assert_eq!(
            bytes
                .get(second)
                .unwrap()
                .terminal_write(b"buffered\n", access),
            Some(Ok(9))
        );
        v.close(first).unwrap();
        v.close(second).unwrap();
        std::thread::scope(|s| {
            for alias in aliases {
                s.spawn(move || drop(alias));
            }
            s.spawn(move || drop(one));
        });
        assert_eq!(pair.slaves.load(Ordering::Relaxed), 1);
        assert_eq!(bytes.get(master).unwrap().poll_ready(1), Some(1));
        std::thread::spawn(move || drop(two)).join().unwrap();
        assert_eq!(bytes.get(master).unwrap().poll_ready(1), Some(17));
        assert_eq!(
            bytes.get(master).unwrap().read(32),
            Ok(b"buffered\r\n".to_vec())
        );
        assert_eq!(bytes.get(master).unwrap().read(1), Err(Errno(5)));
    }
    #[test]
    fn master_close_removes_devpts_while_retained_slave_sees_eof_and_write_error() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        mount(&mut v, b"/pts");
        let master = v.open_at(AT_FDCWD, b"/pts/ptmx", 2, 0).unwrap();
        let pair = v.pty(master).unwrap().unwrap().pair.clone();
        pair.locked.set(false);
        let slave = v.open_pty_peer(master, 2).unwrap();
        let lease = v.pty(slave).unwrap().unwrap().slave_endpoint().unwrap();
        let bytes = v.direct_descriptors();
        v.close(slave).unwrap();
        v.close(master).unwrap();
        assert!(matches!(v.stat_at(AT_FDCWD, b"/pts/0"), Err(Errno(2))));
        assert_eq!(pair.slaves.load(Ordering::Relaxed), 1);
        let slave = bytes.get(slave).unwrap().clone();
        std::thread::spawn(move || {
            let access = Some(TerminalAccess {
                session: 0,
                group: 0,
                controlling: None,
                ignore_ttou: false,
            });
            assert_eq!(slave.terminal_read(1, access), Some(Ok(vec![])));
            assert_eq!(slave.terminal_write(b"closed", access), Some(Err(Errno(5))));
            assert_eq!(slave.poll_ready(5), Some(25));
            drop(lease);
        })
        .join()
        .unwrap();
        assert_eq!(pair.slaves.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn devpts_linux_inode_identity_survives_bind_and_path_handles() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        mount(&mut v, b"/pts");
        assert_eq!(
            v.stat_at(AT_FDCWD, b"/pts").unwrap()[8..16],
            1u64.to_le_bytes()
        );
        let path = v.open_at(AT_FDCWD, b"/pts/ptmx", O_PATH, 0).unwrap();
        let master = v.open_at(AT_FDCWD, b"/pts/ptmx", 2, 0).unwrap();
        for fd in [path, master] {
            let st = v.stat_fd(fd).unwrap();
            assert_eq!(st[8..16], 2u64.to_le_bytes());
            assert_eq!(st[32..40], 0x502u64.to_le_bytes());
            assert_eq!(
                u32::from_le_bytes(st[16..20].try_into().unwrap()) & 0o170000,
                0o20000
            );
        }
        v.pty(master).unwrap().unwrap().pair.locked.set(false);
        let slave = v.open_pty_peer(master, 2).unwrap();
        assert_eq!(v.stat_fd(slave).unwrap()[8..16], 3u64.to_le_bytes());
        v.open_at(AT_FDCWD, b"/ptmx-alias", 0x42, 0o600).unwrap();
        v.mount(Some(b"/pts/ptmx"), b"/ptmx-alias", None, 4096, None)
            .unwrap();
        let alias = v.open_at(AT_FDCWD, b"/ptmx-alias", 2, 0).unwrap();
        assert_eq!(
            v.stat_fd(alias).unwrap()[..40],
            v.stat_fd(master).unwrap()[..40]
        );
        assert_eq!(v.pty(alias).unwrap().unwrap().pair.number, 1);
        assert_eq!(
            v.stat_at(AT_FDCWD, b"/pts/1").unwrap()[8..16],
            4u64.to_le_bytes()
        );
    }
    #[test]
    fn devpts_proc_path_reopen_allocates_a_fresh_master_and_opens_slave() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        mount(&mut v, b"/pts");
        let handle = v
            .open_at(AT_FDCWD, b"/pts/ptmx", O_PATH | O_NOFOLLOW, 0)
            .unwrap();
        let snapshot = |v: &mut Vfs| {
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
        };
        snapshot(&mut v);
        assert!(v.live_ptys().is_empty());
        let link = format!("/proc/self/fd/{handle}");
        let master = v.open_at(AT_FDCWD, link.as_bytes(), 2 | 0x100, 0).unwrap();
        let second = v.open_at(AT_FDCWD, link.as_bytes(), 2 | 0x100, 0).unwrap();
        let a = v.pty(master).unwrap().unwrap();
        assert!(a.master);
        assert_ne!(a.pair.id, v.pty(second).unwrap().unwrap().pair.id);
        assert_eq!(a.pair.number, 0);
        assert_eq!(v.stat_fd(master).unwrap()[8..16], 2u64.to_le_bytes());
        let path = v.open_at(AT_FDCWD, b"/pts/0", O_PATH, 0).unwrap();
        snapshot(&mut v);
        let slave_link = format!("/proc/self/fd/{path}");
        assert_eq!(
            v.open_at(AT_FDCWD, slave_link.as_bytes(), 2, 0),
            Err(Errno(5))
        );
        a.pair.locked.set(false);
        let slave = v.open_at(AT_FDCWD, slave_link.as_bytes(), 2, 0).unwrap();
        assert!(!v.pty(slave).unwrap().unwrap().master);
        assert_eq!(a.pair.slaves.load(std::sync::atomic::Ordering::Relaxed), 1);
        v.close(slave).unwrap();
        assert_eq!(a.pair.slaves.load(std::sync::atomic::Ordering::Relaxed), 0);
        v.close(second).unwrap();
        v.umount(b"/pts", 2).unwrap();
        let detached = v.open_at(AT_FDCWD, link.as_bytes(), 2, 0).unwrap();
        assert_eq!(v.pty(detached).unwrap().unwrap().pair.number, 1);
    }
    #[test]
    fn independent_devpts_reuses_local_numbers_but_not_terminal_identity() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        mount(&mut v, b"/pts-a");
        mount(&mut v, b"/pts-b");
        let a = v.open_at(AT_FDCWD, b"/pts-a/ptmx", 2, 0).unwrap();
        let b = v.open_at(AT_FDCWD, b"/pts-b/ptmx", 2, 0).unwrap();
        let pa = v.pty(a).unwrap().unwrap();
        let pb = v.pty(b).unwrap().unwrap();
        assert_eq!((pa.pair.number, pb.pair.number), (0, 0));
        assert_ne!(pa.pair.id, pb.pair.id);
        assert_eq!(v.open_at(AT_FDCWD, b"/pts-a/0", 2, 0), Err(Errno(5)));
        pa.pair.locked.set(false);
        pb.pair.locked.set(false);
        let sa = v.open_pty_peer(a, 2 | O_CLOEXEC).unwrap();
        let sb = v.open_at(AT_FDCWD, b"/pts-b/0", 2, 0).unwrap();
        assert!(Rc::ptr_eq(&v.pty(sa).unwrap().unwrap().pair, &pa.pair));
        assert!(Rc::ptr_eq(&v.pty(sb).unwrap().unwrap().pair, &pb.pair));
        let x = v.stat_fd(sa).unwrap();
        let y = v.stat_fd(sb).unwrap();
        assert_ne!(&x[..8], &y[..8]);
        assert_eq!(&x[32..40], &y[32..40]);
        assert_eq!(
            v.node(&v.resolve(AT_FDCWD, b"/pts-a/0").unwrap())
                .unwrap()
                .borrow()
                .gid,
            5
        );
        assert_eq!(
            v.open_at(AT_FDCWD, b"/pts-a/injected", 0x42, 0o600),
            Err(Errno(1))
        );
        let other = v.open_at(AT_FDCWD, b"/pts-a/ptmx", 2, 0).unwrap();
        assert_eq!(v.open_at(AT_FDCWD, b"/pts-a/ptmx", 2, 0), Err(Errno(28)));
        drop(pa);
        v.close(a).unwrap();
        assert_eq!(v.stat_at(AT_FDCWD, b"/pts-a/0"), Err(Errno(2)));
        let again = v.open_at(AT_FDCWD, b"/pts-a/ptmx", 2, 0).unwrap();
        assert_eq!(v.pty(again).unwrap().unwrap().pair.number, 0);
        assert!(!v
            .pty(sa)
            .unwrap()
            .unwrap()
            .pair
            .master_alive
            .load(std::sync::atomic::Ordering::Relaxed));
        // Linux reuses the slave inode with its local number. Retained FDs
        // still refer to the old, unlinked object, never the replacement PTY.
        assert_eq!(v.stat_fd(sa).unwrap()[8..16], 3u64.to_le_bytes());
        assert_eq!(v.stat_fd(sa).unwrap()[20..24], 0u32.to_le_bytes());
        assert!(!Rc::ptr_eq(
            &v.pty(sa).unwrap().unwrap().pair,
            &v.pty(again).unwrap().unwrap().pair
        ));
        v.close(other).unwrap();
    }
    #[test]
    fn bind_clone_and_detached_master_retain_their_devpts_instance() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        mount(&mut v, b"/pts");
        v.mkdir_at(AT_FDCWD, b"/alias", 0o755).unwrap();
        v.mount(Some(b"/pts"), b"/alias", None, 4096, None).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/alias/ptmx", 2, 0).unwrap();
        v.pty(fd).unwrap().unwrap().pair.locked.set(false);
        let mut child = v.clone();
        child.unshare_mounts().unwrap();
        assert_eq!(
            v.stat_at(AT_FDCWD, b"/pts/0").unwrap(),
            child.stat_at(AT_FDCWD, b"/alias/0").unwrap()
        );
        v.umount(b"/alias", 2).unwrap();
        v.umount(b"/pts", 2).unwrap();
        let peer = v.open_pty_peer(fd, 2).unwrap();
        assert_eq!(&v.stat_fd(peer).unwrap()[32..40], &0x8800u64.to_le_bytes());
        assert!(child.open_at(AT_FDCWD, b"/pts/0", 2, 0).is_ok());
    }
}
