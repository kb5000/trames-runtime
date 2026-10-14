// SPDX-License-Identifier: GPL-3.0-or-later
//! Runtime-owned pseudo files. These nodes never enter a disk manifest.
use super::*;
use std::time::Duration;

#[derive(Clone)]
pub struct FdInfo {
    pub fd: u32,
    pub target: Vec<u8>,
    pub position: u64,
    pub flags: u32,
    pub inode: u64,
    pub mount_id: u64,
    pub socket: Option<trames_net::SocketInfo>,
    open: Weak<RefCell<OpenDescription>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot(v: &mut Vfs) {
        v.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    state: 'R',
                    command: b"ash".to_vec(),
                    arguments: vec![b"ash".to_vec()],
                    cwd: b"/".to_vec(),
                    terminal: v
                        .fd_kind(0)
                        .is_ok_and(|kind| matches!(kind, FdKind::Terminal)),
                    fds: v.fd_snapshot(),
                    ..ProcessInfo::default()
                }],
                memory_limit: 256 * 1024 * 1024,
                ..RuntimeInfo::default()
            },
        );
    }
    fn read(v: &mut Vfs, path: &[u8]) -> Vec<u8> {
        let fd = v.open_at(AT_FDCWD, path, 0, 0).unwrap();
        let out = v.read(fd, 65536).unwrap();
        v.close(fd).unwrap();
        out
    }
    #[test]
    fn logical_block_identity_agrees_across_mounts_stat_and_sysfs() {
        let mut v = Vfs::default();
        let capacity = v.capacity();
        snapshot(&mut v);
        let root = v.stat_at(AT_FDCWD, b"/").unwrap();
        let block = v.stat_at(AT_FDCWD, b"/dev/vda1").unwrap();
        assert_eq!(&root[..8], &0xfd01u64.to_le_bytes());
        assert_eq!(&block[32..40], &root[..8]);
        assert_eq!(
            u32::from_le_bytes(block[16..20].try_into().unwrap()) & 0o170000,
            0o60000
        );
        for alias in [
            b"/sys/class/block/vda1/dev".as_slice(),
            b"/sys/dev/block/253:1/dev",
        ] {
            assert_eq!(read(&mut v, alias), b"253:1\n");
        }
        assert_eq!(
            read(&mut v, b"/sys/block/vda/size"),
            format!("{}\n", capacity.budget_bytes / 512).as_bytes()
        );
        assert_eq!(
            read(&mut v, b"/sys/class/block/vda1/size"),
            format!("{}\n", capacity.budget_bytes / 512).as_bytes()
        );
        assert_eq!(read(&mut v, b"/sys/class/block/vda1/partition"), b"1\n");
        assert!(read(&mut v, b"/proc/self/mountinfo")
            .starts_with(b"1 1 253:1 / / rw,relatime - rootfs /dev/vda1 rw\n"));
        let fd = v.open_at(AT_FDCWD, b"/dev/vda1", 2, 0).unwrap();
        assert_eq!(v.read(fd, 512), Err(Errno(95)));
        assert_eq!(v.write(fd, &[0; 512]), Err(Errno(95)));
        assert_eq!(
            v.fd_snapshot()
                .into_iter()
                .find(|f| f.fd == fd)
                .unwrap()
                .mount_id,
            1
        );
        assert_eq!(v.capacity().used_bytes, capacity.used_bytes);
    }
    #[test]
    fn directory_links_and_mount_identity_match_live_namespace() {
        let mut v = Vfs::default();
        snapshot(&mut v);
        v.mkdir_at(AT_FDCWD, b"/parent", 0o755).unwrap();
        let links = |v: &Vfs| {
            u32::from_le_bytes(
                v.stat_at(AT_FDCWD, b"/parent").unwrap()[20..24]
                    .try_into()
                    .unwrap(),
            )
        };
        assert_eq!(links(&v), 2);
        v.mkdir_at(AT_FDCWD, b"/parent/child", 0o755).unwrap();
        assert_eq!(links(&v), 3);
        v.unlink_at(AT_FDCWD, b"/parent/child", true).unwrap();
        assert_eq!(links(&v), 2);
        let fd = v.open_at(AT_FDCWD, b"/proc/self/status", 0, 0).unwrap();
        snapshot(&mut v);
        let path = format!("/proc/self/fdinfo/{fd}");
        assert!(read(&mut v, path.as_bytes())
            .windows(10)
            .any(|w| w == b"mnt_id:\t2\n"));
        v.enable_terminal().unwrap();
        snapshot(&mut v);
        snapshot(&mut v);
        let terminal = v.fd_snapshot().into_iter().find(|f| f.fd == 0).unwrap();
        assert_eq!(terminal.mount_id, 4);
        assert_eq!(terminal.inode.to_le_bytes(), v.stat_fd(0).unwrap()[8..16]);
        assert_eq!(&v.stat_fd(0).unwrap()[32..40], &0x8800u64.to_le_bytes());
    }
    #[test]
    fn process_views_are_live_readonly_and_outside_storage_quota() {
        let mut v = Vfs::default();
        let before = v.capacity();
        snapshot(&mut v);
        assert_eq!(v.readlink_at(AT_FDCWD, b"/proc/self").unwrap(), b"1");
        assert_eq!(
            v.readlink_at(AT_FDCWD, b"/proc/thread-self").unwrap(),
            b"1/task/1"
        );
        assert_eq!(read(&mut v, b"/proc/self/cmdline"), b"ash\0");
        assert!(read(&mut v, b"/proc/self/status")
            .windows(8)
            .any(|w| w == b"Tgid:\t1\n"));
        assert_eq!(
            v.open_at(AT_FDCWD, b"/proc/self/status", 2, 0),
            Err(Errno(30))
        );
        assert_eq!(
            v.mkdir_at(AT_FDCWD, b"/proc/injected", 0o777),
            Err(Errno(30))
        );
        let stat = v.stat_at(AT_FDCWD, b"/proc/self/status").unwrap();
        assert_eq!(&stat[..8], &2u64.to_le_bytes());
        assert_eq!(&stat[48..56], &0u64.to_le_bytes());
        assert_eq!(
            &v.statfs_at(b"/proc").unwrap()[..8],
            &0x9fa0u64.to_le_bytes()
        );
        assert_eq!(v.capacity().used_bytes, before.used_bytes);
        v.set_runtime_info(1, RuntimeInfo::default());
        assert_eq!(v.stat_at(AT_FDCWD, b"/proc/1/status"), Err(Errno(2)));
    }
    #[test]
    fn fd_magic_links_keep_deleted_inodes_and_pipe_identity() {
        let mut v = Vfs::default();
        v.import_file(b"/data", b"content".to_vec()).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/data", 0, 0).unwrap();
        let copy = v.dup(fd, 0, false).unwrap();
        let [reader, writer] = v.pipe(0).unwrap();
        assert_eq!(
            &v.stat_fd(reader).unwrap()[8..16],
            &v.stat_fd(writer).unwrap()[8..16]
        );
        v.unlink_at(AT_FDCWD, b"/data", false).unwrap();
        snapshot(&mut v);
        let path = format!("/proc/self/fd/{copy}");
        assert_eq!(
            v.readlink_at(AT_FDCWD, path.as_bytes()).unwrap(),
            b"/data (deleted)"
        );
        assert_eq!(
            v.stat_at(AT_FDCWD, path.as_bytes()).unwrap(),
            v.stat_fd(fd).unwrap()
        );
        assert_eq!(read(&mut v, path.as_bytes()), b"content");
        assert_eq!(
            v.open_at(AT_FDCWD, path.as_bytes(), 0xc0, 0o600),
            Err(Errno(17))
        );
        assert!(v.stat_at(AT_FDCWD, b"/dev/stdout").is_ok());
        let stat = v.stat_at(AT_FDCWD, b"/dev/stdout").unwrap();
        assert_eq!(
            u32::from_le_bytes(stat[16..20].try_into().unwrap()) & 0o170000,
            0o10000
        );
    }
    #[test]
    fn common_devices_and_cross_process_privacy_have_real_behavior() {
        let mut v = Vfs::default();
        snapshot(&mut v);
        let fd = v.open_at(AT_FDCWD, b"/dev/zero", 0, 0).unwrap();
        assert_eq!(v.read(fd, 23).unwrap(), vec![0; 23]);
        let fd = v.open_at(AT_FDCWD, b"/dev/urandom", 0, 0).unwrap();
        assert_eq!(v.read(fd, 32).unwrap().len(), 32);
        let fd = v.open_at(AT_FDCWD, b"/dev/full", 1, 0).unwrap();
        assert_eq!(v.write(fd, b"x"), Err(Errno(28)));
        v.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 2,
                    tgid: 2,
                    credentials: Credentials::user(1000, 1000),
                    environment: vec![b"SECRET=guest-private".to_vec()],
                    ..ProcessInfo::default()
                }],
                ..RuntimeInfo::default()
            },
        );
        v.credentials = Credentials::user(2000, 2000);
        assert_eq!(
            v.open_at(AT_FDCWD, b"/proc/2/environ", 0, 0),
            Err(Errno(13))
        );
    }
}
#[derive(Clone, Default)]
pub struct ProcessInfo {
    pub pid: u32,
    pub processor: u32,
    pub affinity: u64,
    pub tgid: u32,
    pub parent: u32,
    pub group: u32,
    pub session: u32,
    pub state: char,
    pub credentials: Credentials,
    pub command: Vec<u8>,
    pub arguments: Vec<Vec<u8>>,
    pub environment: Vec<Vec<u8>>,
    pub executable: Vec<u8>,
    pub cwd: Vec<u8>,
    pub mapped_bytes: usize,
    pub virtual_bytes: u64,
    pub maps: Vec<u8>,
    pub user_ticks: u64,
    pub start_ticks: u64,
    pub terminal: bool,
    pub terminal_number: u32,
    pub fds: Vec<FdInfo>,
    pub auxiliary: Vec<u8>,
    pub file_size_limits: Option<(u64, u64)>,
    pub pending: u64,
    pub blocked: u64,
    pub ignored: u64,
    pub caught: u64,
}
#[derive(Clone, Default)]
pub struct RuntimeInfo {
    pub cpu_count: usize,
    pub per_cpu_ticks: Vec<u64>,
    pub cpu_features: &'static str,
    pub processes: Vec<ProcessInfo>,
    pub uptime: Duration,
    pub boot_time: u64,
    pub context_switches: u64,
    pub cpu_user_ticks: u64,
    pub idle: Duration,
    pub memory_limit: usize,
    pub load: [f64; 3],
    pub processes_created: u32,
    pub used_memory: usize,
}
#[derive(Default)]
pub(super) struct PseudoFs {
    enabled: bool,
    runtime: RuntimeInfo,
    pub(super) nodes: BTreeMap<Vec<u8>, Rc<RefCell<Node>>>,
    next_inode: u64,
}
impl PseudoFs {
    pub(super) fn path_of(&self, node: &Rc<RefCell<Node>>) -> Option<Vec<u8>> {
        self.nodes
            .iter()
            .find(|(_, n)| Rc::ptr_eq(n, node))
            .map(|(p, _)| p.clone())
    }
    fn cache(&mut self, path: &[u8], content: Content, mode: u32) -> Result<Rc<RefCell<Node>>> {
        if let Some(node) = self.nodes.get(path) {
            node.borrow_mut().content = content;
            return Ok(node.clone());
        }
        if self.nodes.len() >= 32768 {
            return Err(Errno(28));
        }
        self.next_inode = self.next_inode.checked_add(1).ok_or(Errno(28))?;
        let node = Rc::new(RefCell::new(Node {
            content,
            mode,
            uid: 0,
            gid: 0,
            volatile: true,
            device: if path == b"/proc" || path.starts_with(b"/proc/") {
                2
            } else if path == b"/sys" || path.starts_with(b"/sys/") {
                3
            } else if path == b"/dev/pts" || path.starts_with(b"/dev/pts/") {
                4
            } else {
                0xfd01
            },
            inode: (1u64 << 63) + self.next_inode,
            links: 1,
            times: [storage::Timestamp::default(); 3],
            seals: None,
        }));
        self.nodes.insert(path.to_vec(), node.clone());
        Ok(node)
    }
}
#[derive(Clone, Copy)]
pub(super) enum Device {
    Kmsg,
    Zero,
    Full,
    Random,
    Urandom,
    Pts(u32),
    Ptmx,
    Bridge,
    Vda,
    Vda1,
}
impl Device {
    pub(super) fn rdev(self) -> u64 {
        match self {
            Self::Kmsg => 0x10b,
            Self::Zero => 0x105,
            Self::Full => 0x107,
            Self::Random => 0x108,
            Self::Urandom => 0x109,
            Self::Pts(id) => 0x8800 + id as u64,
            Self::Ptmx => 0x502,
            Self::Bridge => 0xf000,
            Self::Vda => 0xfd00,
            Self::Vda1 => 0xfd01,
        }
    }
    pub(super) fn read(self, count: usize) -> Result<Vec<u8>> {
        let mut data = vec![0; count.min(storage::MAX_TRANSFER)];
        match self {
            Self::Zero | Self::Full => {}
            Self::Random | Self::Urandom => getrandom::fill(&mut data).map_err(|_| Errno(5))?,
            Self::Kmsg => return Err(Errno(29)),
            Self::Pts(_) => return Err(Errno(11)),
            Self::Ptmx => return Err(Errno(95)),
            Self::Bridge => return Err(Errno(19)),
            Self::Vda | Self::Vda1 => return Err(Errno(95)),
        }
        Ok(data)
    }
    pub(super) fn write(self, data: &[u8]) -> Result<usize> {
        match self {
            Self::Full if !data.is_empty() => Err(Errno(28)),
            Self::Kmsg => Err(Errno(29)),
            Self::Pts(_) => Err(Errno(11)),
            Self::Ptmx => Err(Errno(95)),
            Self::Bridge => Err(Errno(19)),
            Self::Vda | Self::Vda1 => Err(Errno(95)),
            _ => Ok(data.len()),
        }
    }
}
fn file(data: impl Into<Vec<u8>>) -> Content {
    Content::File(storage::FileData::Memory(data.into()))
}
fn nul_list(values: &[Vec<u8>]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.iter().copied().chain([0]))
        .take(1024 * 1024)
        .collect()
}
fn comm(p: &ProcessInfo) -> Vec<u8> {
    let mut name: Vec<_> = p.command.iter().copied().take(15).collect();
    if name.is_empty() {
        name.extend_from_slice(b"trames");
    }
    name.push(b'\n');
    name
}
fn mounts() -> &'static [u8] {
    b"/dev/vda1 / rootfs rw,relatime 0 0\nproc /proc proc ro,nosuid,nodev,noexec 0 0\nsysfs /sys sysfs ro,nosuid,nodev,noexec 0 0\ndevpts /dev/pts devpts rw,nosuid,noexec 0 0\n"
}
fn mountinfo() -> &'static [u8] {
    b"1 1 253:1 / / rw,relatime - rootfs /dev/vda1 rw\n2 1 0:2 / /proc ro,nosuid,nodev,noexec - proc proc ro\n3 1 0:3 / /sys ro,nosuid,nodev,noexec - sysfs sysfs ro\n4 1 0:4 / /dev/pts rw,nosuid,noexec - devpts devpts rw\n"
}
impl Vfs {
    pub fn set_runtime_info(&mut self, pid: u32, runtime: RuntimeInfo) {
        self.pid = pid;
        let mut pseudo = self.pseudo.borrow_mut();
        pseudo.nodes.retain(|path, _| {
            let parts: Vec<_> = path.split(|b| *b == b'/').collect();
            if !(parts.len() > 2
                && parts[1] == b"proc"
                && parts[2].first().is_some_and(u8::is_ascii_digit))
            {
                return true;
            }
            let pid = std::str::from_utf8(parts[2])
                .ok()
                .and_then(|p| p.parse::<u32>().ok());
            if !runtime.processes.iter().any(|p| Some(p.pid) == pid) {
                return false;
            }
            if parts.len() > 4 && parts[3] == b"task" {
                let tid = std::str::from_utf8(parts[4])
                    .ok()
                    .and_then(|p| p.parse::<u32>().ok());
                return runtime
                    .processes
                    .iter()
                    .any(|p| Some(p.pid) == tid && Some(p.tgid) == pid);
            }
            true
        });
        pseudo.enabled = true;
        pseudo.runtime = runtime;
    }
    pub fn set_process_context(&mut self, pid: u32) {
        self.pid = pid;
    }
    pub fn fd_snapshot(&self) -> Vec<FdInfo> {
        self.fds
            .iter()
            .filter(|(fd, _)| self.descriptor(**fd).is_ok())
            .map(|(&fd, d)| {
                let o = d.open.borrow();
                let node = o.node.clone().or_else(|| {
                    if matches!(o.kind, FdKind::Terminal) {
                        self.node(b"/dev/pts/0").ok()
                    } else {
                        None
                    }
                });
                let inode = node.as_ref().map_or_else(
                    || o.pipe.as_ref().map_or(o.id, |p| p.pipe.borrow().inode),
                    |n| n.borrow().inode,
                );
                let target = match &o.kind {
                    FdKind::Node(path) => o
                        .node
                        .as_ref()
                        .and_then(|n| self.path_of(n).ok())
                        .unwrap_or_else(|| {
                            let mut p = path.clone();
                            p.extend_from_slice(b" (deleted)");
                            p
                        }),
                    FdKind::Terminal if o.pty.is_some() => {
                        let end = o.pty.as_ref().expect("PTY");
                        if end.master {
                            b"/dev/ptmx".to_vec()
                        } else {
                            format!("/dev/pts/{}", end.pair.id).into_bytes()
                        }
                    }
                    FdKind::Terminal => node
                        .as_ref()
                        .and_then(|n| self.path_of(n).ok())
                        .unwrap_or_else(|| b"/dev/pts/0".to_vec()),
                    FdKind::Anonymous => o
                        .anonymous
                        .as_ref()
                        .expect("anonymous description")
                        .name()
                        .to_vec(),
                    FdKind::Socket => format!("socket:[{inode}]").into_bytes(),
                    FdKind::PipeRead | FdKind::PipeWrite => format!("pipe:[{inode}]").into_bytes(),
                    FdKind::Stdin | FdKind::Stdout | FdKind::Stderr => {
                        format!("pipe:[{inode}]").into_bytes()
                    }
                };
                FdInfo {
                    fd,
                    target,
                    position: o.position,
                    flags: o.flags | if d.cloexec { O_CLOEXEC } else { 0 },
                    inode,
                    mount_id: node.as_ref().map_or(1, |n| {
                        if n.borrow().device == 0xfd01 {
                            1
                        } else {
                            n.borrow().device
                        }
                    }),
                    socket: o.socket.as_ref().and_then(|s| s.info()),
                    open: Rc::downgrade(&d.open),
                }
            })
            .collect()
    }
    pub(super) fn pseudo_readonly(&self, path: &[u8]) -> bool {
        self.pseudo.borrow().enabled
            && (path == b"/proc"
                || path.starts_with(b"/proc/")
                || path == b"/sys"
                || path.starts_with(b"/sys/"))
    }
    pub(super) fn pseudo_immutable(&self, node: &Rc<RefCell<Node>>) -> Result<()> {
        let n = node.borrow();
        if n.volatile && !matches!(n.content, Content::Device(_)) {
            Err(Errno(30))
        } else {
            Ok(())
        }
    }
    pub(super) fn proc_fd_description(
        &self,
        dirfd: i32,
        path: &[u8],
    ) -> Result<Option<Rc<RefCell<OpenDescription>>>> {
        if !self.pseudo.borrow().enabled {
            return Ok(None);
        }
        let link_path = self.resolve_final(dirfd, path, false)?;
        let mut actual = link_path;
        if matches!(
            actual.as_slice(),
            b"/dev/stdin" | b"/dev/stdout" | b"/dev/stderr"
        ) {
            let fd = if actual == b"/dev/stdin" {
                0
            } else if actual == b"/dev/stdout" {
                1
            } else {
                2
            };
            actual = format!("/proc/{}/fd/{fd}", self.pid).into_bytes();
        }
        let Some(rest) = actual.strip_prefix(b"/proc/") else {
            return Ok(None);
        };
        let parts: Vec<_> = rest.split(|b| *b == b'/').collect();
        let (pid_part, fd_part) = if parts.len() == 3 && parts[1] == b"fd" {
            (parts[0], parts[2])
        } else if parts.len() == 5 && parts[1] == b"task" && parts[3] == b"fd" {
            let group = std::str::from_utf8(parts[0])
                .ok()
                .and_then(|s| s.parse::<u32>().ok());
            let tid = std::str::from_utf8(parts[2])
                .ok()
                .and_then(|s| s.parse::<u32>().ok());
            if !self
                .pseudo
                .borrow()
                .runtime
                .processes
                .iter()
                .any(|p| Some(p.pid) == tid && Some(p.tgid) == group)
            {
                return Err(Errno(2));
            }
            (parts[2], parts[4])
        } else {
            return Ok(None);
        };
        let pid = std::str::from_utf8(pid_part)
            .ok()
            .and_then(|s| s.parse::<u32>().ok());
        let fd = std::str::from_utf8(fd_part)
            .ok()
            .and_then(|s| s.parse::<u32>().ok());
        let open = {
            let pseudo = self.pseudo.borrow();
            let process = pseudo
                .runtime
                .processes
                .iter()
                .find(|p| Some(p.pid) == pid)
                .ok_or(Errno(2))?;
            if self.credentials.fsuid != 0 && self.credentials.fsuid != process.credentials.euid {
                return Err(Errno(13));
            }
            process
                .fds
                .iter()
                .find(|f| Some(f.fd) == fd)
                .and_then(|f| f.open.upgrade())
                .ok_or(Errno(2))?
        };
        Ok(Some(open))
    }
    pub(super) fn open_proc_fd(
        &mut self,
        dirfd: i32,
        path: &[u8],
        flags: u32,
    ) -> Result<Option<u32>> {
        if flags & O_NOFOLLOW != 0 {
            return Ok(None);
        }
        let Some(open) = self.proc_fd_description(dirfd, path)? else {
            return Ok(None);
        };
        let original = open.borrow();
        if flags & 0xc0 == 0xc0 {
            return Err(Errno(17));
        }
        if original.socket.is_some() || original.local.is_some() || original.anonymous.is_some() {
            return Err(Errno(6));
        }
        if flags & O_DIRECTORY != 0
            && !original
                .node
                .as_ref()
                .is_some_and(|n| matches!(n.borrow().content, Content::Directory))
        {
            return Err(Errno(20));
        }
        if let Some(node) = &original.node {
            let n = node.borrow();
            if (flags & 3 != 1 && !self.allowed(&n, 4)) || (flags & 3 != 0 && !self.allowed(&n, 2))
            {
                return Err(Errno(13));
            }
        } else if (flags & 3 != 1 && original.flags & 3 == 1)
            || (flags & 3 != 0 && original.flags & 3 == 0)
        {
            return Err(Errno(13));
        }
        let descriptor = OpenDescription {
            id: self.open_id(),
            owner: original.owner,
            kind: original.kind.clone(),
            flags: flags & !O_CLOEXEC,
            position: 0,
            node: original.node.clone(),
            pipe: original.pipe.clone(),
            socket: None,
            bridge: original.bridge.clone(),
            kernel_log: None,
            anonymous: None,
            local: None,
            pty: original.pty.clone(),
        };
        drop(original);
        let fd = self.available(0)?;
        self.fds.insert(
            fd,
            Descriptor {
                open: Rc::new(RefCell::new(descriptor)),
                cloexec: flags & O_CLOEXEC != 0,
            },
        );
        if flags & 0x200 != 0
            && self
                .descriptor(fd)?
                .open
                .borrow()
                .node
                .as_ref()
                .is_some_and(|n| matches!(n.borrow().content, Content::File(_)))
        {
            if let Err(error) = self.truncate_fd(fd, 0) {
                self.fds.remove(&fd);
                return Err(error);
            }
        }
        Ok(Some(fd))
    }
    fn statfs_for_path(&self, path: &[u8]) -> [u8; 120] {
        let (magic, id, flags) = if path == b"/proc" || path.starts_with(b"/proc/") {
            (0x9fa0u64, 2u64, 15u64)
        } else if path == b"/sys" || path.starts_with(b"/sys/") {
            (0x62656572, 3, 15)
        } else if path == b"/dev/pts" || path.starts_with(b"/dev/pts/") {
            (0x1cd1, 4, 10)
        } else {
            return self.storage_stat();
        };
        let mut out = [0; 120];
        for (offset, value) in [
            (0, magic),
            (8, 4096),
            (56, id),
            (64, 255),
            (72, 4096),
            (80, flags),
        ] {
            out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        out
    }
    pub fn statfs_at(&self, path: &[u8]) -> Result<[u8; 120]> {
        let path = self.resolve(AT_FDCWD, path)?;
        self.node(&path)?;
        Ok(self.statfs_for_path(&path))
    }
    pub fn statfs_fd(&self, fd: u32) -> Result<[u8; 120]> {
        let o = self.descriptor(fd)?.open.borrow();
        let mut out = if let FdKind::Node(path) = &o.kind {
            self.statfs_for_path(path)
        } else {
            self.storage_stat()
        };
        if o.socket.is_some()
            || o.local.is_some()
            || (o.pipe.is_some() && o.node.is_none())
            || o.anonymous.is_some()
        {
            out.fill(0);
            let magic = if o.anonymous.is_some() {
                0x09041934u64
            } else if o.socket.is_some() || o.local.is_some() {
                0x534f434bu64
            } else {
                0x50495045
            };
            out[..8].copy_from_slice(&magic.to_le_bytes());
            out[8..16].copy_from_slice(&4096u64.to_le_bytes());
        }
        Ok(out)
    }
    pub(super) fn refresh_pseudo_fd(&self, fd: u32) -> Result<()> {
        let kind = self.descriptor(fd)?.open.borrow().kind.clone();
        if let FdKind::Node(path) = kind {
            if self.pseudo_readonly(&path) {
                self.pseudo_node(&path)?;
            }
        }
        Ok(())
    }
    pub(super) fn pseudo_node(&self, path: &[u8]) -> Result<Option<Rc<RefCell<Node>>>> {
        if !self.pseudo.borrow().enabled {
            return Ok(None);
        }
        let content = self.pseudo_content(path)?;
        if let Some((content, mode)) = content {
            let node = self.pseudo.borrow_mut().cache(path, content, mode)?;
            if let Some(rest) = path.strip_prefix(b"/proc/") {
                let pid = rest
                    .split(|b| *b == b'/')
                    .next()
                    .and_then(|s| std::str::from_utf8(s).ok())
                    .and_then(|s| s.parse::<u32>().ok());
                if let Some(p) = self
                    .pseudo
                    .borrow()
                    .runtime
                    .processes
                    .iter()
                    .find(|p| Some(p.pid) == pid)
                {
                    let mut n = node.borrow_mut();
                    n.uid = p.credentials.euid;
                    n.gid = p.credentials.egid;
                    if rest.ends_with(b"/environ")
                        || rest.ends_with(b"/auxv")
                        || rest.ends_with(b"/maps")
                    {
                        n.mode = 0o100400;
                    }
                    if rest.ends_with(b"/fd") || rest.ends_with(b"/fdinfo") {
                        n.mode = 0o40500;
                    }
                }
            }
            return Ok(Some(node));
        }
        if self.pseudo_readonly(path) || path == b"/dev/pts" || path.starts_with(b"/dev/pts/") {
            return Err(Errno(2));
        }
        Ok(None)
    }
    fn pseudo_content(&self, path: &[u8]) -> Result<Option<(Content, u32)>> {
        let pseudo = self.pseudo.borrow();
        let r = &pseudo.runtime;
        let own = r.processes.iter().find(|p| p.pid == self.pid);
        let directory = || Some((Content::Directory, 0o40555));
        let regular = |value: Vec<u8>| Some((file(value), 0o100444));
        let link = |value: Vec<u8>| Some((Content::Symlink(value), 0o120777));
        let info = self.network_info();
        if let Some(tail) = path.strip_prefix(b"/dev/pts/") {
            if let Some(id) = std::str::from_utf8(tail)
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
            {
                if id == 0 && self.embedding_terminal.get()
                    || self.pty_by_id(id).is_some_and(|p| p.master_alive.get())
                {
                    return Ok(Some((Content::Device(Device::Pts(id)), 0o20620)));
                }
                return Ok(None);
            }
        }
        if let Some(tail) = path.strip_prefix(b"/sys/devices/system/cpu/cpu") {
            let parts: Vec<_> = tail.split(|c| *c == b'/').collect();
            if let Some(cpu) = std::str::from_utf8(parts[0])
                .ok()
                .and_then(|n| n.parse::<usize>().ok())
                .filter(|n| *n < r.cpu_count.max(1))
            {
                if parts.len() == 1
                    || parts.as_slice().get(1) == Some(&b"topology".as_slice()) && parts.len() == 2
                {
                    return Ok(directory());
                }
                let value = match parts[1..] {
                    [b"online"] => "1\n".to_string(),
                    [b"topology", b"core_id"] => format!("{cpu}\n"),
                    [b"topology", b"physical_package_id"] => "0\n".to_string(),
                    [b"topology", b"thread_siblings_list"] => format!("{cpu}\n"),
                    [b"topology", b"thread_siblings"] => format!("{:08x}\n", 1u32 << cpu),
                    _ => return Ok(None),
                };
                return Ok(regular(value.into_bytes()));
            }
        }
        match path {
            b"/proc" | b"/sys" | b"/sys/class" | b"/sys/class/net" | b"/sys/devices" |
            b"/sys/devices/system" | b"/sys/devices/system/cpu" | b"/sys/devices/virtual" | b"/sys/devices/virtual/net" | b"/sys/block" |
            b"/sys/class/block" | b"/sys/devices/virtual/block" | b"/sys/devices/virtual/block/vda" |
            b"/sys/devices/virtual/block/vda/vda1" | b"/sys/devices/virtual/block/vda/queue" |
            b"/sys/dev" | b"/sys/dev/block" | b"/dev/block" | b"/proc/sys" |
            b"/proc/sys/kernel" | b"/proc/sys/fs" | b"/proc/sys/vm" | b"/proc/sys/net" |
            b"/proc/sys/net/ipv4" | b"/dev/pts" => return Ok(directory()),
            b"/dev/tty" => return Ok(Some((Content::Terminal, 0o20666))),
            b"/sys/devices/system/cpu/online"|b"/sys/devices/system/cpu/possible"|b"/sys/devices/system/cpu/present"=>return Ok(regular(if r.cpu_count.max(1)==1{b"0\n".to_vec()}else{format!("0-{}\n",r.cpu_count-1).into_bytes()})),
            b"/sys/devices/system/cpu/offline"=>return Ok(regular(b"\n".to_vec())),
            b"/proc/self" => return Ok(link(own.map_or(self.pid, |p| p.tgid).to_string().into_bytes())),
            b"/proc/thread-self" => return Ok(link(format!("{}/task/{}", own.map_or(self.pid, |p| p.tgid), self.pid).into_bytes())),
            b"/proc/mounts" => return Ok(link(b"self/mounts".to_vec())),
            b"/proc/net" => return Ok(link(b"self/net".to_vec())),
            b"/dev/fd" => return Ok(link(b"/proc/self/fd".to_vec())),
            b"/dev/stdin" | b"/dev/stdout" | b"/dev/stderr" => {
                let fd = if path == b"/dev/stdin" { 0 } else if path == b"/dev/stdout" { 1 } else { 2 };
                return Ok(link(format!("/proc/self/fd/{fd}").into_bytes()));
            }
            b"/dev/trames-bridge" if self.bridge.is_some() => return Ok(Some((Content::Device(Device::Bridge), 0o20600))),
            b"/dev/kmsg" => return Ok(Some((Content::Device(Device::Kmsg),0o20600))),
            b"/dev/vda" => return Ok(Some((Content::Device(Device::Vda),0o60600))),
            b"/dev/vda1" => return Ok(Some((Content::Device(Device::Vda1),0o60600))),
            b"/dev/block/253:0" => return Ok(link(b"../vda".to_vec())),
            b"/dev/block/253:1" => return Ok(link(b"../vda1".to_vec())),
            b"/sys/block/vda" => return Ok(link(b"../devices/virtual/block/vda".to_vec())),
            b"/sys/class/block/vda" => return Ok(link(b"../../devices/virtual/block/vda".to_vec())),
            b"/sys/class/block/vda1" => return Ok(link(b"../../devices/virtual/block/vda/vda1".to_vec())),
            b"/sys/dev/block/253:0" => return Ok(link(b"../../devices/virtual/block/vda".to_vec())),
            b"/sys/dev/block/253:1" => return Ok(link(b"../../devices/virtual/block/vda/vda1".to_vec())),
            b"/dev/zero" | b"/dev/full" | b"/dev/random" | b"/dev/urandom" | b"/dev/ptmx" => {
                let d = match path { b"/dev/zero" => Device::Zero, b"/dev/full" => Device::Full,
                    b"/dev/random" => Device::Random, b"/dev/urandom" => Device::Urandom, _ => Device::Ptmx };
                return Ok(Some((Content::Device(d), 0o20666)));
            }
            b"/proc/uptime" => return Ok(regular(format!("{:.2} {:.2}\n", r.uptime.as_secs_f64(), r.idle.as_secs_f64()).into_bytes())),
            b"/proc/meminfo" => {
                let total = r.memory_limit as u64 / 1024;
                let used: u64 = r.used_memory as u64 / 1024;
                let free = total.saturating_sub(used);
                return Ok(regular(format!("MemTotal: {total:8} kB\nMemFree: {free:8} kB\nMemAvailable: {free:8} kB\nBuffers: 0 kB\nCached: 0 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n").into_bytes()));
            }
            b"/proc/cpuinfo" => return Ok(regular((0..r.cpu_count.max(1)).map(|cpu|format!("processor\t: {cpu}\nmodel name\t: Trames AArch64 interpreter\nCPU architecture: 8\nFeatures\t: {}\n\n",r.cpu_features)).collect::<String>().into_bytes())),
            b"/proc/swaps" => return Ok(regular(b"Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n".to_vec())),
            b"/proc/partitions" => return Ok(regular(format!("major minor  #blocks  name\n\n 253 0 {} vda\n 253 1 {} vda1\n",self.capacity().budget_bytes/1024,self.capacity().budget_bytes/1024).into_bytes())),
            b"/proc/devices" => return Ok(regular(b"Character devices:\n  1 mem\n  5 /dev/tty\n136 pts\n\nBlock devices:\n253 virtblk\n".to_vec())),
            b"/proc/diskstats" => return Ok(regular(b"253 0 vda 0 0 0 0 0 0 0 0 0 0 0\n253 1 vda1 0 0 0 0 0 0 0 0 0 0 0\n".to_vec())),
            b"/proc/version" => return Ok(regular(b"Linux version 6.0.0-trames (Trames userspace compatibility runtime)\n".to_vec())),
            b"/proc/filesystems" => return Ok(regular(b"nodev\tproc\nnodev\tsysfs\nnodev\tdevpts\nnodev\trootfs\n".to_vec())),
            b"/proc/stat" => {
                let user = r.cpu_user_ticks;
                let idle = r.idle.as_millis() / 10;
                let running = r.processes.iter().filter(|p| p.state == 'R').count();
                let mut text=format!("cpu {user} 0 0 {idle} 0 0 0 0 0 0\n");
                for cpu in 0..r.cpu_count.max(1){let ticks=r.per_cpu_ticks.get(cpu).copied().unwrap_or(if cpu==0{user}else{0});text.push_str(&format!("cpu{cpu} {ticks} 0 0 {} 0 0 0 0 0 0\n",idle/r.cpu_count.max(1) as u128));}
                text.push_str(&format!("intr 0\nctxt {}\nbtime {}\nprocesses {}\nprocs_running {running}\nprocs_blocked 0\nsoftirq 0 0 0 0 0 0 0 0 0 0 0\n",r.context_switches,r.boot_time,r.processes_created));
                return Ok(regular(text.into_bytes()));
            }
            b"/proc/loadavg" => {
                let running = r.processes.iter().filter(|p| p.state == 'R').count();
                return Ok(regular(format!("{:.2} {:.2} {:.2} {running}/{} {}\n", r.load[0],r.load[1],r.load[2],r.processes.len(),r.processes_created).into_bytes()));
            }
            b"/proc/sys/kernel/ostype" => return Ok(regular(b"Linux\n".to_vec())),
            b"/proc/sys/kernel/osrelease" => return Ok(regular(b"6.0.0-trames\n".to_vec())),
            b"/proc/sys/kernel/version" => return Ok(regular(b"Trames userspace runtime\n".to_vec())),
            b"/proc/sys/kernel/hostname" => return Ok(regular(b"trames\n".to_vec())),
            b"/proc/sys/kernel/domainname" => return Ok(regular(b"(none)\n".to_vec())),
            b"/proc/sys/kernel/pid_max" => return Ok(regular(b"2147483647\n".to_vec())),
            b"/proc/sys/kernel/threads-max" => return Ok(regular(b"32\n".to_vec())),
            b"/proc/sys/fs/file-max" => return Ok(regular(b"8192\n".to_vec())),
            b"/proc/sys/fs/file-nr" => return Ok(regular(format!("{}\t0\t8192\n", r.processes.iter().map(|p| p.fds.len()).sum::<usize>()).into_bytes())),
            b"/proc/sys/vm/overcommit_memory" => return Ok(regular(b"2\n".to_vec())),
            b"/proc/sys/net/ipv4/ip_forward" => return Ok(regular(b"0\n".to_vec())),
            b"/proc/sys/net/ipv4/ip_local_port_range" => return Ok(regular(b"49152\t65535\n".to_vec())),
            b"/proc/sys/net/ipv4/ip_default_ttl" => return Ok(regular(b"64\n".to_vec())),
            b"/proc/sys/net/ipv4/ping_group_range" => return Ok(regular(b"0\t2147483647\n".to_vec())),
            _ => {},
        }
        if let Some(rest) = path.strip_prefix(b"/proc/") {
            let parts: Vec<_> = rest.split(|b| *b == b'/').collect();
            let pid = std::str::from_utf8(parts[0])
                .ok()
                .and_then(|s| s.parse::<u32>().ok());
            if let Some(pid) = pid {
                let Some(mut p) = r.processes.iter().find(|p| p.pid == pid) else {
                    return Ok(None);
                };
                let mut i = 1;
                if parts.get(1) == Some(&b"task".as_slice()) {
                    if parts.len() == 2 {
                        return Ok(directory());
                    }
                    let tid = std::str::from_utf8(parts[2])
                        .ok()
                        .and_then(|s| s.parse::<u32>().ok());
                    let Some(thread) = r
                        .processes
                        .iter()
                        .find(|t| t.tgid == p.tgid && Some(t.pid) == tid)
                    else {
                        return Ok(None);
                    };
                    p = thread;
                    i = 3;
                }
                if parts.len() == i {
                    return Ok(directory());
                }
                let key = parts[i];
                if parts.len() == i + 1 {
                    let value = match key {
                        b"fd" | b"fdinfo" | b"net" => return Ok(directory()),
                        b"cwd" => return Ok(link(p.cwd.clone())),
                        b"root" => return Ok(link(b"/".to_vec())),
                        b"exe" => return Ok(link(p.executable.clone())),
                        b"comm" => comm(p),
                        b"cmdline" => nul_list(&p.arguments),
                        b"environ" => nul_list(&p.environment),
                        b"auxv" => p.auxiliary.clone(),
                        b"maps" => p.maps.clone(),
                        b"mounts" => mounts().to_vec(),
                        b"mountinfo" => mountinfo().to_vec(),
                        b"statm" => format!(
                            "{} {} 0 0 0 0 0\n",
                            p.virtual_bytes / 4096,
                            p.mapped_bytes / 4096
                        )
                        .into_bytes(),
                        b"stat" => {
                            let name = String::from_utf8_lossy(&comm(p))
                                .trim_end()
                                .replace(['\n', ')'], "_");
                            let mut fields = vec!["0".to_string(); 50];
                            fields[0] = p.state.to_string();
                            fields[1] = p.parent.to_string();
                            fields[2] = p.group.to_string();
                            fields[3] = p.session.to_string();
                            fields[4] = if p.terminal {
                                (34816 + p.terminal_number).to_string()
                            } else {
                                "0".into()
                            };
                            fields[5] = p.group.to_string();
                            fields[11] = p.user_ticks.to_string();
                            fields[15] = "20".into();
                            fields[17] = r
                                .processes
                                .iter()
                                .filter(|t| t.tgid == p.tgid)
                                .count()
                                .to_string();
                            fields[19] = p.start_ticks.to_string();
                            fields[20] = p.virtual_bytes.to_string();
                            fields[21] = (p.mapped_bytes / 4096).to_string();
                            fields[22] = u64::MAX.to_string();
                            fields[36] = p.processor.to_string();
                            format!("{} ({name}) {}\n", p.pid, fields.join(" ")).into_bytes()
                        }
                        b"status" => {
                            let c = &p.credentials;
                            let name = String::from_utf8_lossy(&comm(p))
                                .trim_end()
                                .replace('\n', "_");
                            let name = format!(
                                "{name}\nCpus_allowed:\t{:08x}\nCpus_allowed_list:\t{}",
                                p.affinity,
                                (0..32)
                                    .filter(|i| p.affinity & (1u64 << i) != 0)
                                    .map(|i| i.to_string())
                                    .collect::<Vec<_>>()
                                    .join(",")
                            );
                            let threads = r.processes.iter().filter(|t| t.tgid == p.tgid).count();
                            format!("Name:\t{name}\nState:\t{}\nTgid:\t{}\nPid:\t{}\nPPid:\t{}\nTracerPid:\t0\nUid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\nFDSize:\t256\nGroups:\t{}\nVmSize:\t{} kB\nVmRSS:\t{} kB\nThreads:\t{threads}\nSigPnd:\t{:016x}\nShdPnd:\t0000000000000000\nSigBlk:\t{:016x}\nSigIgn:\t{:016x}\nSigCgt:\t{:016x}\n", p.state, p.tgid, p.pid, p.parent,
                                c.uid,c.euid,c.suid,c.fsuid,c.gid,c.egid,c.sgid,c.fsgid,c.groups.iter().map(u32::to_string).collect::<Vec<_>>().join(" "),p.virtual_bytes/1024,p.mapped_bytes/1024,p.pending,p.blocked,p.ignored,p.caught).into_bytes()
                        }
                        b"limits" => {
                            let (soft, hard) = p.file_size_limits.unwrap_or((u64::MAX, u64::MAX));
                            let limit = |v: u64| {
                                if v == u64::MAX {
                                    "unlimited".to_owned()
                                } else {
                                    v.to_string()
                                }
                            };
                            format!("Limit                     Soft Limit           Hard Limit           Units\nMax open files            256                  256                  files\nMax processes             32                   32                   processes\nMax address space         536870912            536870912             bytes\nMax file size             {:<20} {:<20} bytes\n", limit(soft), limit(hard)).into_bytes()
                        }
                        _ => return Ok(None),
                    };
                    return Ok(regular(value));
                }
                if parts.len() == i + 2 && matches!(key, b"fd" | b"fdinfo") {
                    let fd = std::str::from_utf8(parts[i + 1])
                        .ok()
                        .and_then(|s| s.parse::<u32>().ok());
                    let Some(fd) = p.fds.iter().find(|f| Some(f.fd) == fd) else {
                        return Ok(None);
                    };
                    if key == b"fd" {
                        return Ok(link(fd.target.clone()));
                    }
                    return Ok(regular(
                        format!(
                            "pos:\t{}\nflags:\t0{:o}\nmnt_id:\t{}\nino:\t{}\n",
                            fd.position, fd.flags, fd.mount_id, fd.inode
                        )
                        .into_bytes(),
                    ));
                }
                if parts.len() == i + 2 && key == b"net" {
                    return Ok(match parts[i + 1] {
                        b"tcp" | b"tcp6" | b"udp" | b"udp6" | b"raw" | b"raw6" | b"icmp"
                        | b"icmp6" => {
                            let key = parts[i + 1];
                            let family = if key.ends_with(b"6") { 10 } else { 2 };
                            let (kind, protocol) = if key.starts_with(b"tcp") {
                                (1, 6)
                            } else if key.starts_with(b"udp") {
                                (2, 17)
                            } else if key.starts_with(b"raw") {
                                (3, if family == 2 { 1 } else { 58 })
                            } else {
                                (2, if family == 2 { 1 } else { 58 })
                            };
                            let hex = |a: Option<std::net::SocketAddr>, port: Option<u16>| {
                                let (address, p) = a.map_or(
                                    (if family == 2 { vec![0; 4] } else { vec![0; 16] }, 0),
                                    |a| {
                                        (
                                            match a.ip() {
                                                std::net::IpAddr::V4(v) => v.octets().to_vec(),
                                                std::net::IpAddr::V6(v) => v.octets().to_vec(),
                                            },
                                            a.port(),
                                        )
                                    },
                                );
                                format!(
                                    "{}:{:04X}",
                                    address
                                        .chunks_exact(4)
                                        .map(|p| format!(
                                            "{:08X}",
                                            u32::from_le_bytes(p.try_into().unwrap())
                                        ))
                                        .collect::<String>(),
                                    port.unwrap_or(p)
                                )
                            };
                            let mut data=String::from("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n");
                            let mut seen = BTreeMap::new();
                            for process in &r.processes {
                                for fd in &process.fds {
                                    if let Some(s) = fd.socket.as_ref().filter(|s| {
                                        s.family == family
                                            && s.kind == kind
                                            && s.protocol == protocol
                                    }) {
                                        if seen.insert(fd.inode, ()).is_some() {
                                            continue;
                                        }
                                        data.push_str(&format!("{:4}: {} {} {:02X} {:08X}:{:08X} 00:00000000 00000000 {:5} 0 {} 1 0000000000000000\n",seen.len()-1,hex(s.local,(kind==3).then_some(protocol as u16)),hex(s.peer,None),s.state,s.tx_queue.unwrap_or(0),s.rx_queue.unwrap_or(0),process.credentials.euid,fd.inode));
                                    }
                                }
                            }
                            regular(data.into_bytes())
                        }
                        b"unix" => regular(
                            b"Num       RefCount Protocol Flags    Type St Inode Path\n".to_vec(),
                        ),
                        b"dev" => {
                            let mut data=String::from("Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n");
                            if let Some(links) = self.network_links() {
                                for (name, s) in ["lo", "eth0"].into_iter().zip(links) {
                                    data.push_str(&format!(
                                        "{name:>6}: {} {} 0 {} 0 0 0 0 {} {} 0 {} 0 0 0 0\n",
                                        s.rx_bytes,
                                        s.rx_packets,
                                        s.rx_dropped,
                                        s.tx_bytes,
                                        s.tx_packets,
                                        s.tx_dropped
                                    ));
                                }
                            }
                            regular(data.into_bytes())
                        }
                        b"route" => regular(if let Some(n) = info {
                            format!("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t{:08X}\t0003\t0\t0\t0\t00000000\t0\t0\t0\neth0\t0000000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n", u32::from_le_bytes(n.gateway4.octets())).into_bytes()
                        } else {
                            b"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n".to_vec()
                        }),
                        b"if_inet6" => regular(
                            format!(
                                "00000000000000000000000000000001 01 80 10 80 lo\n{}",
                                info.map_or(String::new(), |n| format!(
                                    "{:032x} 02 40 00 80 eth0\n",
                                    u128::from_be_bytes(n.ipv6.octets())
                                ))
                            )
                            .into_bytes(),
                        ),
                        _ => None,
                    });
                }
            }
        }
        if let Some(rest) = path.strip_prefix(b"/sys/devices/virtual/block/vda/") {
            let partition = rest.starts_with(b"vda1/");
            let attribute = if partition { &rest[5..] } else { rest };
            let value = match attribute {
                b"size" => format!("{}\n", self.capacity().budget_bytes / 512),
                b"dev" => format!("253:{}\n", u8::from(partition)),
                b"ro" | b"removable" | b"alignment_offset" | b"discard_alignment" | b"start" => {
                    "0\n".into()
                }
                b"partition" if partition => "1\n".into(),
                b"stat" => "0 0 0 0 0 0 0 0 0 0 0\n".into(),
                b"uevent" => if partition {
                    "MAJOR=253\nMINOR=1\nDEVNAME=vda1\nDEVTYPE=partition\nPARTN=1\n"
                } else {
                    "MAJOR=253\nMINOR=0\nDEVNAME=vda\nDEVTYPE=disk\n"
                }
                .into(),
                b"queue/logical_block_size" => "512\n".into(),
                b"queue/physical_block_size" | b"queue/minimum_io_size" => "4096\n".into(),
                b"queue/optimal_io_size" | b"queue/rotational" => "0\n".into(),
                _ => return Ok(None),
            };
            return Ok(regular(value.into_bytes()));
        }
        if let Some(name) = path.strip_prefix(b"/sys/class/net/") {
            if matches!(name, b"lo" | b"eth0") && (name == b"lo" || info.is_some()) {
                let mut target = b"../../devices/virtual/net/".to_vec();
                target.extend_from_slice(name);
                return Ok(link(target));
            }
        }
        if let Some(rest) = path.strip_prefix(b"/sys/devices/virtual/net/") {
            let parts: Vec<_> = rest.split(|b| *b == b'/').collect();
            if !matches!(parts[0], b"lo" | b"eth0") || (parts[0] == b"eth0" && info.is_none()) {
                return Ok(None);
            }
            if parts.len() == 1 {
                return Ok(directory());
            }
            if parts.get(1) == Some(&b"statistics".as_slice()) {
                if parts.len() == 2 {
                    return Ok(directory());
                }
                if parts.len() == 3 {
                    let Some(links) = self.network_links() else {
                        return Ok(None);
                    };
                    let s = links[usize::from(parts[0] != b"lo")];
                    let count = match parts[2] {
                        b"rx_bytes" => s.rx_bytes,
                        b"rx_packets" => s.rx_packets,
                        b"rx_dropped" => s.rx_dropped,
                        b"tx_bytes" => s.tx_bytes,
                        b"tx_packets" => s.tx_packets,
                        b"tx_dropped" => s.tx_dropped,
                        _ => return Ok(None),
                    };
                    return Ok(regular(format!("{count}\n").into_bytes()));
                }
            }
            if parts.len() == 2 {
                let lo = parts[0] == b"lo";
                let value = match parts[1] {
                    b"ifindex" | b"iflink" => if lo { "1\n" } else { "2\n" }.to_string(),
                    b"type" => if lo { "772\n" } else { "65534\n" }.to_string(),
                    b"mtu" => format!("{}\n", info.map_or(65536, |n| n.mtu)),
                    b"address" | b"broadcast" => "00:00:00:00:00:00\n".to_string(),
                    b"flags" => if lo { "0x9\n" } else { "0x11\n" }.to_string(),
                    b"operstate" => if lo { "unknown\n" } else { "up\n" }.to_string(),
                    b"carrier" => "1\n".to_string(),
                    b"tx_queue_len" => "0\n".to_string(),
                    _ => return Ok(None),
                };
                return Ok(regular(value.into_bytes()));
            }
        }
        Ok(None)
    }
    pub(super) fn pseudo_children(&self, path: &[u8]) -> Result<Vec<Vec<u8>>> {
        if let Some(tail) = path.strip_prefix(b"/sys/devices/system/cpu/cpu") {
            let parts: Vec<_> = tail.split(|c| *c == b'/').collect();
            if std::str::from_utf8(parts[0])
                .ok()
                .and_then(|n| n.parse::<usize>().ok())
                .is_some_and(|n| n < self.pseudo.borrow().runtime.cpu_count.max(1))
            {
                return Ok(if parts.len() == 1 {
                    vec![b"online".to_vec(), b"topology".to_vec()]
                } else if parts.len() == 2 && parts[1] == b"topology" {
                    [
                        "core_id",
                        "physical_package_id",
                        "thread_siblings_list",
                        "thread_siblings",
                    ]
                    .iter()
                    .map(|s| s.as_bytes().to_vec())
                    .collect()
                } else {
                    Vec::new()
                });
            }
        }
        if !self.pseudo.borrow().enabled {
            return Ok(Vec::new());
        }
        let mut names: Vec<Vec<u8>> = match path {
            b"/" => vec![b"proc".to_vec(), b"sys".to_vec()],
            b"/proc" => [
                "self",
                "thread-self",
                "net",
                "mounts",
                "uptime",
                "meminfo",
                "cpuinfo",
                "version",
                "filesystems",
                "stat",
                "loadavg",
                "sys",
                "swaps",
                "partitions",
                "devices",
                "diskstats",
            ]
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect(),
            b"/dev" => [
                "zero",
                "full",
                "random",
                "urandom",
                "kmsg",
                "ptmx",
                "pts",
                "fd",
                "stdin",
                "stdout",
                "trames-bridge",
                "stderr",
                "vda",
                "vda1",
                "block",
            ]
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect(),
            b"/sys" => vec![
                b"class".to_vec(),
                b"devices".to_vec(),
                b"block".to_vec(),
                b"dev".to_vec(),
            ],
            b"/sys/class" => vec![b"net".to_vec(), b"block".to_vec()],
            b"/sys/devices" => vec![b"virtual".to_vec(), b"system".to_vec()],
            b"/sys/devices/system" => vec![b"cpu".to_vec()],
            b"/sys/devices/system/cpu" => {
                let mut names: Vec<_> = ["online", "offline", "possible", "present"]
                    .iter()
                    .map(|s| s.as_bytes().to_vec())
                    .collect();
                names.extend(
                    (0..self.pseudo.borrow().runtime.cpu_count.max(1))
                        .map(|i| format!("cpu{i}").into_bytes()),
                );
                names
            }
            b"/sys/devices/virtual" => vec![b"net".to_vec(), b"block".to_vec()],
            b"/sys/dev" => vec![b"block".to_vec()],
            b"/dev/block" | b"/sys/dev/block" => vec![b"253:0".to_vec(), b"253:1".to_vec()],
            b"/sys/block" | b"/sys/devices/virtual/block" => vec![b"vda".to_vec()],
            b"/sys/class/block" => vec![b"vda".to_vec(), b"vda1".to_vec()],
            b"/sys/devices/virtual/block/vda" => [
                "vda1",
                "queue",
                "dev",
                "size",
                "ro",
                "removable",
                "stat",
                "uevent",
                "alignment_offset",
                "discard_alignment",
            ]
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect(),
            b"/sys/devices/virtual/block/vda/vda1" => [
                "dev",
                "size",
                "ro",
                "stat",
                "uevent",
                "start",
                "partition",
                "alignment_offset",
                "discard_alignment",
            ]
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect(),
            b"/sys/devices/virtual/block/vda/queue" => [
                "logical_block_size",
                "physical_block_size",
                "minimum_io_size",
                "optimal_io_size",
                "rotational",
            ]
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect(),
            b"/sys/class/net" | b"/sys/devices/virtual/net" => {
                let mut n = vec![b"lo".to_vec()];
                if self.network_info().is_some() {
                    n.push(b"eth0".to_vec());
                }
                n
            }
            b"/proc/sys" => ["kernel", "fs", "vm", "net"]
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect(),
            b"/proc/sys/kernel" => [
                "ostype",
                "osrelease",
                "version",
                "hostname",
                "domainname",
                "pid_max",
                "threads-max",
            ]
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect(),
            b"/proc/sys/fs" => vec![b"file-max".to_vec(), b"file-nr".to_vec()],
            b"/proc/sys/vm" => vec![b"overcommit_memory".to_vec()],
            b"/proc/sys/net" => vec![b"ipv4".to_vec()],
            b"/proc/sys/net/ipv4" => [
                "ip_forward",
                "ip_local_port_range",
                "ip_default_ttl",
                "ping_group_range",
            ]
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect(),
            _ => Vec::new(),
        };
        let pseudo = self.pseudo.borrow();
        let r = &pseudo.runtime;
        if path == b"/proc" {
            names.extend(
                r.processes
                    .iter()
                    .filter(|p| p.pid == p.tgid)
                    .map(|p| p.pid.to_string().into_bytes()),
            );
        }
        if path == b"/dev/pts" {
            if self.embedding_terminal.get() {
                names.push(b"0".to_vec());
            }
            names.extend(
                self.live_ptys()
                    .iter()
                    .filter(|p| p.master_alive.get())
                    .map(|p| p.id.to_string().into_bytes()),
            );
        }
        if let Some(rest) = path.strip_prefix(b"/proc/") {
            let parts: Vec<_> = rest.split(|b| *b == b'/').collect();
            let pid = std::str::from_utf8(parts[0])
                .ok()
                .and_then(|s| s.parse::<u32>().ok());
            if let Some(mut p) = r.processes.iter().find(|p| Some(p.pid) == pid) {
                let mut depth = 1;
                if parts.get(1) == Some(&b"task".as_slice()) {
                    if parts.len() == 2 {
                        names.extend(
                            r.processes
                                .iter()
                                .filter(|t| t.tgid == p.tgid)
                                .map(|p| p.pid.to_string().into_bytes()),
                        );
                    }
                    if parts.len() >= 3 {
                        let tid = std::str::from_utf8(parts[2])
                            .ok()
                            .and_then(|s| s.parse::<u32>().ok());
                        if let Some(thread) = r
                            .processes
                            .iter()
                            .find(|t| t.tgid == p.tgid && Some(t.pid) == tid)
                        {
                            p = thread;
                            depth = 3;
                        }
                    }
                }
                if parts.len() == depth {
                    names.extend(
                        [
                            "stat",
                            "status",
                            "statm",
                            "cmdline",
                            "environ",
                            "comm",
                            "maps",
                            "auxv",
                            "cwd",
                            "root",
                            "exe",
                            "mounts",
                            "mountinfo",
                            "limits",
                            "fd",
                            "fdinfo",
                            "net",
                        ]
                        .iter()
                        .map(|s| s.as_bytes().to_vec()),
                    );
                    if depth == 1 {
                        names.push(b"task".to_vec());
                    }
                }
                if parts.len() == depth + 1 {
                    if matches!(parts[depth], b"fd" | b"fdinfo") {
                        names.extend(p.fds.iter().map(|f| f.fd.to_string().into_bytes()));
                    }
                    if parts[depth] == b"net" {
                        names.extend(
                            [
                                "route", "if_inet6", "dev", "tcp", "tcp6", "udp", "udp6", "raw",
                                "raw6", "icmp", "icmp6", "unix",
                            ]
                            .iter()
                            .map(|s| s.as_bytes().to_vec()),
                        );
                    }
                }
            }
        }
        if let Some(rest) = path.strip_prefix(b"/sys/devices/virtual/net/") {
            if matches!(rest, b"lo" | b"eth0") {
                names.extend(
                    [
                        "ifindex",
                        "iflink",
                        "type",
                        "mtu",
                        "address",
                        "broadcast",
                        "flags",
                        "operstate",
                        "carrier",
                        "tx_queue_len",
                    ]
                    .iter()
                    .map(|s| s.as_bytes().to_vec()),
                );
            }
            if matches!(rest, b"lo" | b"eth0") && self.network_links().is_some() {
                names.push(b"statistics".to_vec());
            }
            if matches!(rest, b"lo/statistics" | b"eth0/statistics")
                && self.network_links().is_some()
            {
                names.extend(
                    [
                        "rx_bytes",
                        "rx_packets",
                        "rx_dropped",
                        "tx_bytes",
                        "tx_packets",
                        "tx_dropped",
                    ]
                    .iter()
                    .map(|s| s.as_bytes().to_vec()),
                );
            }
        }
        names.sort();
        names.dedup();
        Ok(names)
    }
}

#[cfg(test)]
mod proc_probe_tests {
    use super::*;
    #[test]
    fn proc_probe_follows_aliases_cwd_and_dirfd_even_for_missing_processes() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        v.mkdir_at(AT_FDCWD, b"/work", 0o755).unwrap();
        v.symlink_at(b"/proc", AT_FDCWD, b"/work/p").unwrap();
        v.symlink_at(b"../proc", AT_FDCWD, b"/alias").unwrap();
        assert!(!v.accesses_proc(AT_FDCWD, b"/work/file"));
        assert!(!v.accesses_proc(AT_FDCWD, b"/missing/proc/file"));
        assert!(v.accesses_proc(AT_FDCWD, b"/proc/12345/status"));
        assert!(v.accesses_proc(AT_FDCWD, b"/work/p/12345/status"));
        assert!(v.accesses_proc(AT_FDCWD, b"/alias/stat"));
        let fd = v.open_at(AT_FDCWD, b"/proc", O_DIRECTORY, 0).unwrap();
        assert!(v.accesses_proc(fd as i32, b"12345/status"));
        v.chdir(b"/proc").unwrap();
        assert!(v.accesses_proc(AT_FDCWD, b"12345/status"));
        assert!(!v.accesses_proc(AT_FDCWD, b"/work/file"));
    }
}
