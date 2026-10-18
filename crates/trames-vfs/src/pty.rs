// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest-owned PTYs. Descriptor aliases share an endpoint; the last close hangs up.
use super::*;
use terminal::Terminal;

pub struct Pty {
    pub id: u32,
    pub number: u32,
    pub(super) mount: Option<Rc<Mount>>,
    slave: Rc<RefCell<Node>>,
    pub terminal: RefCell<Terminal>,
    pub locked: Cell<bool>,
    pub master_alive: Cell<bool>,
    pub slaves: Cell<u32>,
    slave_opened: Cell<bool>,
    pub packet: Cell<bool>,
    pub packet_status: Cell<u8>,
    pub hangup_notified: Cell<bool>,
    pub host_resize_pending: Cell<bool>,
    pub host_signals: Cell<u64>,
}
pub struct PtyEnd {
    pub pair: Rc<Pty>,
    pub master: bool,
}
impl PtyEnd {
    pub(super) fn new(pair: Rc<Pty>, master: bool) -> Rc<Self> {
        if !master {
            pair.slaves.set(pair.slaves.get() + 1);
            pair.slave_opened.set(true);
        }
        Rc::new(Self { pair, master })
    }
}
impl Drop for PtyEnd {
    fn drop(&mut self) {
        if self.master {
            self.pair.master_alive.set(false);
            if let Some(mount) = self.pair.mount.as_ref().filter(|m| m.devpts.is_some()) {
                let key = format!("/{}", self.pair.number).into_bytes();
                let mut fs = mount.fs.borrow_mut();
                if fs
                    .paths
                    .get(&key)
                    .is_some_and(|node| Rc::ptr_eq(node, &self.pair.slave))
                {
                    fs.paths.remove(&key);
                    self.pair.slave.borrow_mut().links = 0;
                }
            }
        } else {
            self.pair.slaves.set(self.pair.slaves.get() - 1);
        }
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
    pub fn master_read(&self, count: usize) -> Result<Vec<u8>> {
        if count == 0 {
            return Ok(Vec::new());
        }
        if self.packet.get() && self.packet_status.get() != 0 {
            return Ok(vec![self.packet_status.replace(0)]);
        }
        let mut tty = self.terminal.borrow_mut();
        if tty.output_queue.is_empty() {
            return Err(Errno(
                if self.slave_opened.get() && self.slaves.get() == 0 {
                    5
                } else {
                    11
                },
            ));
        }
        let mut bytes = Vec::new();
        if self.packet.get() {
            bytes.push(0);
        }
        let take = (count - bytes.len()).min(tty.output_queue.len());
        bytes.extend(tty.drain_output(take));
        Ok(bytes)
    }
    pub fn poll(&self, master: bool, events: u16) -> u16 {
        let tty = self.terminal.borrow();
        if master {
            let read = !tty.output_queue.is_empty()
                || (self.packet.get() && self.packet_status.get() != 0);
            let hungup = self.slave_opened.get() && self.slaves.get() == 0;
            (if read { events & 1 } else { 0 })
                | (if self.packet.get() && self.packet_status.get() != 0 {
                    events & 2
                } else {
                    0
                })
                | (if tty.input_capacity() != 0 {
                    events & 4
                } else {
                    0
                })
                | (if hungup { 16 } else { 0 })
        } else {
            (if tty.readable() || !self.master_alive.get() {
                events & 1
            } else {
                0
            }) | (if tty.output_queue.len() < PIPE_CAPACITY && self.master_alive.get() {
                events & 4
            } else {
                0
            }) | (if !self.master_alive.get() { 16 | 8 } else { 0 })
        }
    }
    pub(super) fn poll_epoch(&self, master: bool) -> [u64; 2] {
        let tty = self.terminal.borrow();
        if master {
            [tty.output_epoch, tty.input_space_epoch]
        } else {
            [tty.input_epoch, tty.output_space_epoch]
        }
    }
    pub fn flush_echo(&self) {
        let mut tty = self.terminal.borrow_mut();
        let echo = std::mem::take(&mut tty.echo);
        let count = tty.queue_output(&echo).unwrap_or(0);
        tty.echo = echo[count..].to_vec();
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
            id,
            number,
            mount,
            slave,
            terminal: RefCell::new(tty),
            locked: Cell::new(true),
            master_alive: Cell::new(true),
            slaves: Cell::new(0),
            slave_opened: Cell::new(false),
            packet: Cell::new(false),
            packet_status: Cell::new(0),
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
                open: Rc::new(RefCell::new(OpenDescription {
                    read_node: None,
                    id: self.open_id(),
                    owner: (self.credentials.fsuid, self.credentials.fsgid),
                    kind: FdKind::Terminal,
                    flags: flags & !O_CLOEXEC,
                    position: 0,
                    node: Some(node),
                    pipe: None,
                    socket: None,
                    bridge: None,
                    kernel_log: None,
                    anonymous: None,
                    notification: None,
                    local: None,
                    namespace: None,
                    network_control: None,
                    oom: None,
                    mount: end.pair.mount.clone(),
                    pty: Some(PtyEnd::new(end.pair.clone(), false)),
                })),
                cloexec: flags & O_CLOEXEC != 0,
            },
        );
        Ok(fd)
    }
}

/// A mount-owned devpts filesystem. Slave numbers are local; scheduler IDs
/// remain guest-wide so controlling terminals cannot alias across containers.
pub(super) struct Devpts {
    pub fs: Rc<RefCell<Filesystem>>,
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
            fs: Rc::new(RefCell::new(Filesystem {
                overlay: None,
                shared_budget: trames_shared::SharedBudget::new(memfd::MEMFD_BYTES as usize),
                paths: BTreeMap::new(),
                inodes: Vec::new(),
                next_inode: device << 32,
                flock: BTreeMap::new(),
                record_locks: BTreeMap::new(),
                limits: StorageLimits::memory(),
                disk: None,
                volume: None,
            })),
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
    fn node(
        &self,
        path: Vec<u8>,
        content: Content,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Rc<RefCell<Node>> {
        let mut fs = self.fs.borrow_mut();
        let node = Rc::new(RefCell::new(Node {
            notifications: inotify::Marks::default(),
            inode: fs.next_inode,
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
        fs.next_inode += 1;
        fs.inodes.retain(|n| n.strong_count() != 0);
        fs.inodes.push(Rc::downgrade(&node));
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
        assert!(!v.pty(sa).unwrap().unwrap().pair.master_alive.get());
        assert_ne!(
            v.stat_fd(sa).unwrap()[8..16],
            v.stat_at(AT_FDCWD, b"/pts-a/0").unwrap()[8..16]
        );
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
