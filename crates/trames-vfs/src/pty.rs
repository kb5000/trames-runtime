// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest-owned PTYs. Descriptor aliases share an endpoint; the last close hangs up.
use super::*;
use terminal::Terminal;
mod shared;
pub use shared::{PtyIo, PtySlaveEndpoint, TerminalAccess};

pub struct Pty {
    pub number: u32,
    pub(super) mount: Option<Arc<mounts::MountData>>,
    pub(super) slave: NodeRef,
    pub(super) io: Arc<PtyIo>,
    pub locked: std::sync::atomic::AtomicBool,
    pub hangup_notified: std::sync::atomic::AtomicBool,
    pub host_resize_pending: std::sync::atomic::AtomicBool,
    pub host_signals: AtomicU64,
}
pub struct PtyEnd {
    pub pair: Arc<Pty>,
    pub master: bool,
    slave: Option<Arc<PtySlaveEndpoint>>,
}
impl PtyEnd {
    pub(super) fn new(pair: Arc<Pty>, master: bool) -> Arc<Self> {
        let slave = (!master).then(|| PtySlaveEndpoint::open(pair.io.clone()));
        Arc::new(Self {
            pair,
            master,
            slave,
        })
    }
    /// Capture only for an accepted operation. Prepared byte snapshots retain
    /// neither endpoint; accepted shared OFDs retain the complete PtyEnd.
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
                let _namespace = mount.fs.namespace.lock().unwrap();
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
            self.host_resize_pending
                .store(true, std::sync::atomic::Ordering::Relaxed);
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
    pub fn pty(&self, fd: u32) -> Result<Option<Arc<PtyEnd>>> {
        Ok(self.descriptor(fd)?.open.borrow().pty.clone())
    }
    pub fn pty_by_id(&self, id: u32) -> Option<Arc<Pty>> {
        self.ptys
            .lock()
            .unwrap()
            .get(&id)
            .and_then(std::sync::Weak::upgrade)
    }
    pub fn live_ptys(&self) -> Vec<Arc<Pty>> {
        self.ptys
            .lock()
            .unwrap()
            .values()
            .filter_map(std::sync::Weak::upgrade)
            .collect()
    }
    pub(super) fn allocate_pty(&mut self, at: &ResolvedPath) -> Result<Arc<PtyEnd>> {
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
        // Only actual devpts resources are admitted by the private query view.
        // Pseudo devpts allocation still needs its owner-side node cache.
        if let Some(query) = &self.query {
            if !mount.as_ref().is_some_and(|m| m.devpts.is_some()) {
                return query.defer();
            }
        }
        let mut registry = self.ptys.lock().unwrap();
        let id = (1..4096)
            .find(|id| registry.get(id).is_none_or(|p| p.strong_count() == 0))
            .ok_or(Errno(28))?;
        let mut tty = Terminal::default();
        tty.session = 0;
        tty.foreground = 0;
        let (number, slave) = if let Some(pts) = mount.as_ref().and_then(|m| m.devpts.as_ref()) {
            pts.allocate_slave(id, &self.credentials)?
        } else {
            let path = format!("/dev/pts/{id}").into_bytes();
            let mut pseudo = self.pseudo.borrow_mut();
            pseudo.nodes.borrow_mut().entries.remove(&(0, path.clone()));
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
        let pair = Arc::new(Pty {
            number,
            mount: mount.map(|m| m.shared.clone()),
            slave,
            io: Arc::new(PtyIo::new(id, tty)),
            locked: std::sync::atomic::AtomicBool::new(true),
            hangup_notified: std::sync::atomic::AtomicBool::new(false),
            host_resize_pending: std::sync::atomic::AtomicBool::new(false),
            host_signals: AtomicU64::new(0),
        });
        registry.insert(id, Arc::downgrade(&pair));
        Ok(PtyEnd::new(pair, true))
    }
    /// TIOCGPTPEER follows the master's devpts identity even after chroot or
    /// lazy unmount, rather than reopening a path in the caller's namespace.
    pub fn open_pty_peer(&mut self, fd: u32, flags: u32) -> Result<u32> {
        let end = self.pty(fd)?.filter(|end| end.master).ok_or(Errno(25))?;
        self.descriptor_factory().open_pty_peer(&end, flags)
    }
}

pub(super) fn peer_descriptor(end: &PtyEnd, flags: u32, id: u64, owner: (u32, u32)) -> Descriptor {
    let node = end.pair.slave.clone();
    Descriptor {
        open: OpenHandle::new(OpenDescription {
            shared: Arc::new(SharedOpenDescription {
                oom: None,
                network_control: None,
                mount_file: None,
                runtime_file: None,
                socket: None,
                _disk_file: None,
                #[cfg(all(feature = "hostfs", unix))]
                host_file: None,
                native_image: None,
                mount_resource: std::sync::OnceLock::new(),
                mount_use: Default::default(),
                directory_mount: Default::default(),
                namespace_resource: None,
                file_authority: Default::default(),
                tcp_publication: Default::default(),
                socket_control: None,
                control: None,
                read_node: None,
                id,
                owner,
                kind: FdKind::Terminal,
                flags: (flags & !O_CLOEXEC).into(),
                file_position: Arc::default(),
                flock: std::sync::OnceLock::new(),
                ofd_records: Default::default(),
                node: Some(node),
                pipe: None,
                pty: Some(PtyEnd::new(end.pair.clone(), false)),
                local: None,
                bridge: None,
                kernel_log: None,
                notification: None,
            }),
            anonymous: None,
            namespace: None,
            mount: end.pair.mount.clone().map(OpenMount::Shared),
        }),
        cloexec: (flags & O_CLOEXEC != 0).into(),
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
    fn allocate_slave(&self, id: u32, credentials: &Credentials) -> Result<(u32, NodeRef)> {
        let _namespace = self.fs.namespace.lock().unwrap();
        let mut fs = self.fs.borrow_mut();
        let number = (0..self.max)
            .find(|number| !fs.paths.contains_key(format!("/{number}").as_bytes()))
            .ok_or(Errno(28))?;
        let node = self.insert_node(
            &mut fs,
            format!("/{number}").into_bytes(),
            Content::Device(pseudo::Device::Pts(id, number)),
            0o20000 | self.mode,
            self.uid.unwrap_or(credentials.fsuid),
            self.gid.unwrap_or(credentials.fsgid),
        );
        Ok((number, node))
    }
    fn node(&self, path: Vec<u8>, content: Content, mode: u32, uid: u32, gid: u32) -> NodeRef {
        self.insert_node(&mut self.fs.borrow_mut(), path, content, mode, uid, gid)
    }
    fn insert_node(
        &self,
        fs: &mut Filesystem,
        path: Vec<u8>,
        content: Content,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> NodeRef {
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
    fn worker_devpts_open_defers_task_transitions_and_rolls_back_failed_creation() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        mount(&mut v, b"/pts");
        let mut epoch = FileEpoch::default();
        let files = epoch.capture(&v, true);
        let query = v.path_queries();
        assert_eq!(
            query.open_at_resolve(AT_FDCWD, b"/dev/ptmx", 2, 0, 0, &files),
            None
        );
        let master = query
            .open_at_resolve(AT_FDCWD, b"/pts/ptmx", 2, 0, 0, &files)
            .unwrap()
            .unwrap();
        let pair = v.pty(master).unwrap().unwrap().pair.clone();
        assert_eq!(
            query.open_at_resolve(AT_FDCWD, b"/pts/0", 2, 0, 0, &files),
            None
        );
        assert_eq!(
            query.open_at_resolve(AT_FDCWD, b"/pts/0", 2 | 0x100, 0, 0, &files),
            Some(Err(Errno(5)))
        );
        assert_eq!(
            query.open_at_resolve(AT_FDCWD, b"/pts/ptmx", O_PATH, 0, 0, &files),
            None
        );
        let second = query
            .open_at_resolve(AT_FDCWD, b"/pts/ptmx", 2, 0, 0, &files)
            .unwrap()
            .unwrap();
        let next = v.available(0).unwrap();
        assert_eq!(
            query.open_at_resolve(AT_FDCWD, b"/pts/ptmx", 2, 0, 0, &files),
            Some(Err(Errno(28)))
        );
        assert_eq!(v.available(0).unwrap(), next);
        let root = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup", O_DIRECTORY, 0)
            .unwrap();
        let deny = v
            .bpf_load_device(&[0xb7, 0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0])
            .unwrap();
        v.bpf_attach_device(root, deny, 2, 0).unwrap();
        assert_eq!(
            query.open_at_resolve(AT_FDCWD, b"/pts/ptmx", 2, 0, 0, &files),
            Some(Err(Errno(1)))
        );
        v.bpf_detach_device(root, deny).unwrap();
        v.close(master).unwrap();
        let replacement = query
            .open_at_resolve(AT_FDCWD, b"/pts/ptmx", 2, 0, 0, &files)
            .unwrap()
            .unwrap();
        let new = v.pty(replacement).unwrap().unwrap().pair.clone();
        assert_eq!(new.number, 0);
        assert_ne!(new.id, pair.id);
        assert!(!pair.master_alive.load(Ordering::Relaxed));
        v.close(replacement).unwrap();
        v.close(second).unwrap();
        epoch.finish();
    }

    #[test]
    fn worker_peer_uses_live_ancestor_device_policy_and_original_credentials() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        let master = v.open_at(AT_FDCWD, b"/dev/ptmx", 2, 0).unwrap();
        let end = v.pty(master).unwrap().unwrap();
        end.pair.locked.store(false, Ordering::Relaxed);
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/child", 0o755)
            .unwrap();
        let root = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup", O_DIRECTORY, 0)
            .unwrap();
        let child = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/child", O_DIRECTORY, 0)
            .unwrap();
        let procs = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/child/cgroup.procs", 1, 0)
            .unwrap();
        v.write(procs, b"0").unwrap();
        let factory = v.descriptor_factory();
        let open = || {
            let factory = factory.clone();
            let end = end.clone();
            std::thread::spawn(move || factory.open_pty_peer(&end, 2 | O_CLOEXEC))
                .join()
                .unwrap()
        };
        let first = open().unwrap();
        assert!(v.flags(first).unwrap() & O_CLOEXEC != 0);
        v.close(first).unwrap();
        let deny = v
            .bpf_load_device(&[0xb7, 0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0])
            .unwrap();
        v.bpf_attach_device(root, deny, 2, 0).unwrap();
        assert_eq!(open(), Err(Errno(1)));
        assert_eq!(v.bpf_query_device(child, true).unwrap().1.len(), 1);
        v.bpf_detach_device(root, deny).unwrap();
        let second = open().unwrap();
        v.close(second).unwrap();
        v.credentials = Credentials::user(1000, 1000);
        // The retained capture is an accepted epoch's original credentials.
        let old = open().unwrap();
        v.close(old).unwrap();
        let user = v.descriptor_factory();
        let next = v.available(0).unwrap();
        assert_eq!(user.open_pty_peer(&end, 2), Err(Errno(13)));
        assert_eq!(end.pair.slaves.load(Ordering::Relaxed), 0);
        assert_eq!(v.descriptor_factory().eventfd(0, 0).unwrap(), next);
    }

    #[test]
    fn concurrent_worker_devpts_creation_publishes_unique_ids_and_original_nodes() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        v.mkdir_at(AT_FDCWD, b"/pts", 0o755).unwrap();
        v.mount(
            Some(b"devpts"),
            b"/pts",
            Some(b"devpts"),
            0,
            Some(b"newinstance,ptmxmode=0666,mode=0620,max=8"),
        )
        .unwrap();
        let mut epoch = FileEpoch::default();
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut release = Vec::new();
        let mut jobs = Vec::new();
        for _ in 0..8 {
            let (tx, rx) = std::sync::mpsc::channel();
            release.push(tx);
            let sender = sender.clone();
            let query = v.path_queries();
            let files = epoch.capture(&v, true);
            let membership = v.shared_files();
            let factory = v.descriptor_factory();
            jobs.push(std::thread::spawn(move || {
                let master = query
                    .open_at_resolve(AT_FDCWD, b"/pts/ptmx", 2, 0, 0, &files)
                    .unwrap()
                    .unwrap();
                let original = membership.lookup(master).unwrap().unwrap();
                let end = original.open.pty.as_ref().unwrap();
                end.pair.locked.store(false, Ordering::Relaxed);
                let slave = factory.open_pty_peer(end, 2).unwrap();
                let path = format!("/pts/{}", end.pair.number);
                let independent = query
                    .open_at_resolve(AT_FDCWD, path.as_bytes(), 2 | 0x100, 0, 0, &files)
                    .unwrap()
                    .unwrap();
                sender
                    .send((end.pair.clone(), master, slave, independent))
                    .unwrap();
                rx.recv().unwrap();
                drop(original);
                for fd in [independent, slave, master] {
                    membership.close(fd, 0).unwrap().unwrap();
                }
            }));
        }
        drop(sender);
        let rows: Vec<_> = (0..8)
            .map(|_| {
                receiver
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap()
            })
            .collect();
        assert_eq!(
            rows.iter()
                .map(|r| r.0.id)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            8
        );
        assert_eq!(
            rows.iter()
                .map(|r| r.0.number)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            8
        );
        for (pair, _, _, _) in &rows {
            assert_eq!(pair.slaves.load(Ordering::Relaxed), 2);
            assert!(v
                .stat_at(AT_FDCWD, format!("/pts/{}", pair.number).as_bytes())
                .is_ok());
        }
        for tx in release {
            tx.send(()).unwrap();
        }
        for job in jobs {
            job.join().unwrap();
        }
        for (pair, _, _, _) in rows {
            assert_eq!(pair.slaves.load(Ordering::Relaxed), 0);
            assert!(!pair.master_alive.load(Ordering::Relaxed));
            assert!(matches!(
                v.stat_at(AT_FDCWD, format!("/pts/{}", pair.number).as_bytes()),
                Err(Errno(2))
            ));
        }
        epoch.finish();
    }

    #[test]
    fn retained_pty_bytes_do_not_keep_guest_endpoints_open() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        mount(&mut v, b"/pts");
        let master = v.open_at(AT_FDCWD, b"/pts/ptmx", 2, 0).unwrap();
        v.pty(master)
            .unwrap()
            .unwrap()
            .pair
            .locked
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let slave = v.open_pty_peer(master, 2).unwrap();
        let direct = v.direct_descriptors();
        let read = DirectFd::snapshot(&v.descriptor(master).unwrap().open.borrow()).unwrap();
        let write = DirectFd::snapshot(&v.descriptor(slave).unwrap().open.borrow()).unwrap();
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
        assert!(direct.get(master).is_none());
        assert!(direct.get(slave).is_none());
    }
    #[test]
    fn accepted_master_pins_devpts_across_close_reuse_and_worker_final_drop() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<Pty>();
        send_sync::<PtyEnd>();
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        mount(&mut v, b"/pts");
        let master = v.open_at(AT_FDCWD, b"/pts/ptmx", 2, 0).unwrap();
        let pair = v.pty(master).unwrap().unwrap().pair.clone();
        pair.locked.store(false, Ordering::Relaxed);
        let slave = v.open_pty_peer(master, 2).unwrap();
        let accepted = v.direct_descriptors().get(master).unwrap();
        let accepted_slave = v.direct_descriptors().get(slave).unwrap();
        v.close(master).unwrap();
        v.close(slave).unwrap();
        assert_eq!(
            v.open_at(AT_FDCWD, b"/replacement", 0x42, 0o600).unwrap(),
            master
        );
        assert!(pair.master_alive.load(Ordering::Relaxed));
        assert_eq!(pair.slaves.load(Ordering::Relaxed), 1);
        assert!(v.stat_at(AT_FDCWD, b"/pts/0").is_ok());
        std::thread::spawn(move || drop(accepted)).join().unwrap();
        assert!(!pair.master_alive.load(Ordering::Relaxed));
        assert!(matches!(v.stat_at(AT_FDCWD, b"/pts/0"), Err(Errno(2))));
        assert_eq!(accepted_slave.poll_ready(5), Some(25));
        std::thread::spawn(move || drop(accepted_slave))
            .join()
            .unwrap();
        assert_eq!(pair.slaves.load(Ordering::Relaxed), 0);
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
        pair.locked
            .store(false, std::sync::atomic::Ordering::Relaxed);
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
        pair.locked
            .store(false, std::sync::atomic::Ordering::Relaxed);
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
        pair.locked
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let slave = v.open_pty_peer(master, 2).unwrap();
        let lease = v.pty(slave).unwrap().unwrap().slave_endpoint().unwrap();
        let bytes = v.direct_descriptors();
        let slave_bytes = bytes.get(slave).unwrap();
        v.close(slave).unwrap();
        v.close(master).unwrap();
        assert!(matches!(v.stat_at(AT_FDCWD, b"/pts/0"), Err(Errno(2))));
        assert_eq!(pair.slaves.load(Ordering::Relaxed), 1);
        assert!(bytes.get(slave).is_none());
        let slave = slave_bytes;
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
        v.pty(master)
            .unwrap()
            .unwrap()
            .pair
            .locked
            .store(false, std::sync::atomic::Ordering::Relaxed);
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
        a.pair
            .locked
            .store(false, std::sync::atomic::Ordering::Relaxed);
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
        pa.pair
            .locked
            .store(false, std::sync::atomic::Ordering::Relaxed);
        pb.pair
            .locked
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let sa = v.open_pty_peer(a, 2 | O_CLOEXEC).unwrap();
        let sb = v.open_at(AT_FDCWD, b"/pts-b/0", 2, 0).unwrap();
        assert!(Arc::ptr_eq(&v.pty(sa).unwrap().unwrap().pair, &pa.pair));
        assert!(Arc::ptr_eq(&v.pty(sb).unwrap().unwrap().pair, &pb.pair));
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
        assert!(!Arc::ptr_eq(
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
        v.pty(fd)
            .unwrap()
            .unwrap()
            .pair
            .locked
            .store(false, std::sync::atomic::Ordering::Relaxed);
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
