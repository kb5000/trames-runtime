// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared virtual namespace; host IO is confined to an explicitly selected store.
mod namespace;
mod storage;
#[cfg(test)]
mod storage_tests;
use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    fmt,
    rc::{Rc, Weak},
};
pub use storage::{DiskOptions, StorageCapacity, StorageLimits, VolumeSpace, DEFAULT_DISK_BYTES};
pub const MAX_PATH: usize = 4096;
pub const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_NODES: usize = 1024;
pub const MAX_FDS: u32 = 256;
pub const PIPE_CAPACITY: usize = 65536;
pub const AT_FDCWD: i32 = -100;
pub const O_DIRECTORY: u32 = 0x4000;
pub const O_NOFOLLOW: u32 = 0x8000;
pub const O_LARGEFILE: u32 = 0x20000;
pub const O_CLOEXEC: u32 = 0x80000;
pub const O_NONBLOCK: u32 = 0x800;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Errno(pub u32);
impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "virtual filesystem errno {}", self.0)
    }
}
impl std::error::Error for Errno {}
type Result<T> = std::result::Result<T, Errno>;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FdKind {
    Stdin,
    Stdout,
    Stderr,
    Node(Vec<u8>),
    PipeRead,
    PipeWrite,
    Terminal,
}
struct Pipe {
    bytes: VecDeque<u8>,
    reader: Weak<PipeEnd>,
    writer: Weak<PipeEnd>,
}
struct PipeEnd {
    pipe: Rc<RefCell<Pipe>>,
    read: bool,
}
struct OpenDescription {
    kind: FdKind,
    flags: u32,
    position: u64,
    node: Option<Rc<RefCell<Node>>>,
    pipe: Option<Rc<PipeEnd>>,
}
#[derive(Clone)]
struct Descriptor {
    open: Rc<RefCell<OpenDescription>>,
    cloexec: bool,
}
enum Content {
    Directory,
    File(storage::FileData),
    Null,
    Terminal,
}
struct Node {
    content: Content,
    mode: u32,
    inode: u64,
    links: u32,
    times: [storage::Timestamp; 3],
}
struct Filesystem {
    paths: BTreeMap<Vec<u8>, Rc<RefCell<Node>>>,
    inodes: Vec<Weak<RefCell<Node>>>,
    next_inode: u64,
    limits: StorageLimits,
    disk: Option<Rc<storage::DiskStore>>,
    volume: Option<(VolumeSpace, u64)>,
}
#[derive(Clone)]
pub struct Vfs {
    fs: Rc<RefCell<Filesystem>>,
    fds: BTreeMap<u32, Descriptor>,
    cwd_node: Option<Rc<RefCell<Node>>>,
    pub umask: u32,
}
impl Default for Vfs {
    fn default() -> Self {
        let mut v = Self {
            fs: Rc::new(RefCell::new(Filesystem {
                paths: BTreeMap::new(),
                inodes: Vec::new(),
                next_inode: 1,
                limits: StorageLimits::memory(),
                disk: None,
                volume: None,
            })),
            fds: BTreeMap::new(),
            cwd_node: None,
            umask: 0o022,
        };
        v.insert(b"/".to_vec(), Content::Directory, 0o40755)
            .expect("root");
        v.cwd_node = Some(v.node(b"/").expect("root inode"));
        v.insert(b"/dev".to_vec(), Content::Directory, 0o40755)
            .expect("dev");
        v.insert(b"/dev/null".to_vec(), Content::Null, 0o20666)
            .expect("null");
        for (fd, kind, flags) in [
            (0, FdKind::Stdin, 0),
            (1, FdKind::Stdout, 1),
            (2, FdKind::Stderr, 1),
        ] {
            v.fds.insert(
                fd,
                Descriptor {
                    open: Rc::new(RefCell::new(OpenDescription {
                        kind,
                        flags,
                        position: 0,
                        node: None,
                        pipe: None,
                    })),
                    cloexec: false,
                },
            );
        }
        v
    }
}
impl Vfs {
    pub fn import_executable(&mut self, path: &[u8], bytes: Vec<u8>) -> Result<()> {
        self.import_reader(path, &mut bytes.as_slice(), true)
            .map(|_| ())
    }
    fn check_parent_write(&self, path: &[u8]) -> Result<()> {
        let end = path
            .iter()
            .rposition(|&b| b == b'/')
            .ok_or(Errno(22))?
            .max(1);
        if self.node(&path[..end])?.borrow().mode & 0o300 != 0o300 {
            return Err(Errno(13));
        }
        Ok(())
    }
    pub fn poll(&self, fd: u32, events: u16) -> u16 {
        let Ok(d) = self.descriptor(fd) else {
            return 32;
        };
        let o = d.open.borrow();
        let mut ready = events & 5;
        if let Some(end) = &o.pipe {
            let p = end.pipe.borrow();
            ready = 0;
            if end.read {
                if !p.bytes.is_empty() || p.writer.strong_count() == 0 {
                    ready |= events & 1;
                }
                if p.writer.strong_count() == 0 {
                    ready |= 16;
                }
            } else if p.reader.strong_count() == 0 {
                ready |= 8;
            } else if PIPE_CAPACITY - p.bytes.len() >= 4096 {
                ready |= events & 4;
            }
        }
        ready
    }
    pub fn enable_terminal(&mut self) -> Result<()> {
        if self.node(b"/dev/tty").is_err() {
            self.insert(b"/dev/tty".to_vec(), Content::Terminal, 0o20666)?;
        }
        for fd in 0..=2 {
            self.fds.insert(
                fd,
                Descriptor {
                    open: Rc::new(RefCell::new(OpenDescription {
                        kind: FdKind::Terminal,
                        flags: 2,
                        position: 0,
                        node: None,
                        pipe: None,
                    })),
                    cloexec: false,
                },
            );
        }
        Ok(())
    }
    fn insert(&mut self, path: Vec<u8>, content: Content, mode: u32) -> Result<()> {
        let mut fs = self.fs.borrow_mut();
        fs.inodes.retain(|n| n.strong_count() != 0);
        if fs.inodes.len() >= fs.limits.nodes || fs.paths.len() >= fs.limits.nodes {
            return Err(Errno(28));
        }
        let old_next = fs.next_inode;
        let inode = if let Content::File(data) = &content {
            data.inode().unwrap_or(fs.next_inode)
        } else {
            fs.next_inode
        };
        if inode == fs.next_inode {
            fs.next_inode = fs.next_inode.checked_add(1).ok_or(Errno(28))?;
        }
        if let Content::File(data) = &content {
            data.sync(false)?;
        }
        let node = Rc::new(RefCell::new(Node {
            content,
            mode,
            inode,
            links: 1,
            times: [storage::Timestamp::now(); 3],
        }));
        fs.inodes.push(Rc::downgrade(&node));
        fs.paths.insert(path.clone(), node.clone());
        if let Err(e) = fs.checkpoint() {
            fs.paths.remove(&path);
            fs.inodes.pop();
            fs.next_inode = old_next;
            return Err(e);
        }
        if let Content::File(data) = &mut node.borrow_mut().content {
            data.orphan(false);
        }
        Ok(())
    }
    fn node(&self, path: &[u8]) -> Result<Rc<RefCell<Node>>> {
        self.fs.borrow().paths.get(path).cloned().ok_or(Errno(2))
    }
    fn descriptor(&self, fd: u32) -> Result<&Descriptor> {
        self.fds.get(&fd).ok_or(Errno(9))
    }
    pub fn allocated_bytes(&self) -> u64 {
        self.fs
            .borrow()
            .inodes
            .iter()
            .filter_map(Weak::upgrade)
            .map(|n| match &n.borrow().content {
                Content::File(b) => b.len(),
                _ => 0,
            })
            .sum()
    }
    pub fn cwd(&self) -> Result<Vec<u8>> {
        self.path_of(self.cwd_node.as_ref().ok_or(Errno(2))?)
    }
    fn path_of(&self, node: &Rc<RefCell<Node>>) -> Result<Vec<u8>> {
        self.fs
            .borrow()
            .paths
            .iter()
            .find(|(_, n)| Rc::ptr_eq(n, node))
            .map(|(p, _)| p.clone())
            .ok_or(Errno(2))
    }
    pub fn fd_kind(&self, fd: u32) -> Result<FdKind> {
        Ok(self.descriptor(fd)?.open.borrow().kind.clone())
    }
    fn is_directory(&self, path: &[u8]) -> bool {
        self.node(path)
            .is_ok_and(|n| matches!(n.borrow().content, Content::Directory))
    }
    fn base(&self, dirfd: i32) -> Result<Vec<u8>> {
        if dirfd == AT_FDCWD {
            return self.cwd();
        }
        let o = self.descriptor(dirfd as u32)?.open.borrow();
        let n = o.node.as_ref().ok_or(Errno(20))?;
        if !matches!(n.borrow().content, Content::Directory) {
            return Err(Errno(20));
        }
        self.path_of(n)
    }
    pub fn resolve(&self, dirfd: i32, path: &[u8]) -> Result<Vec<u8>> {
        if path.is_empty() {
            return Err(Errno(2));
        }
        if path.len() >= MAX_PATH || path.contains(&0) {
            return Err(Errno(36));
        }
        let mut current = if path[0] == b'/' {
            b"/".to_vec()
        } else {
            self.base(dirfd)?
        };
        let parts: Vec<_> = path
            .split(|&b| b == b'/')
            .filter(|p| !p.is_empty())
            .collect();
        for (i, part) in parts.iter().enumerate() {
            let n = self.node(&current)?;
            let n = n.borrow();
            if !matches!(n.content, Content::Directory) {
                return Err(Errno(20));
            }
            if n.mode & 0o100 == 0 {
                return Err(Errno(13));
            }
            if *part == b"." {
                continue;
            }
            if *part == b".." {
                if current != b"/" {
                    current.truncate(
                        current
                            .iter()
                            .rposition(|&b| b == b'/')
                            .expect("absolute")
                            .max(1),
                    );
                }
                continue;
            }
            if part.len() > 255 {
                return Err(Errno(36));
            }
            if current != b"/" {
                current.push(b'/');
            }
            current.extend_from_slice(part);
            if current.len() >= MAX_PATH {
                return Err(Errno(36));
            }
            if i + 1 == parts.len() && path.last() == Some(&b'/') {
                let n = self.node(&current)?;
                if !matches!(n.borrow().content, Content::Directory) {
                    return Err(Errno(20));
                }
            }
        }
        Ok(current)
    }
    pub fn import_file(&mut self, path: &[u8], bytes: Vec<u8>) -> Result<()> {
        self.import_reader(path, &mut bytes.as_slice(), false)
            .map(|_| ())
    }
    fn import_data(
        &mut self,
        path: &[u8],
        data: storage::FileData,
        executable: bool,
    ) -> Result<()> {
        let (current, parents) = self.import_plan(path)?;
        self.check_growth(0, data.len())?;
        for parent in parents {
            self.insert(parent, Content::Directory, 0o40755)?;
        }
        self.insert(
            current,
            Content::File(data),
            if executable { 0o100755 } else { 0o100644 },
        )
    }
    fn import_plan(&self, path: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
        if !path.starts_with(b"/")
            || path.contains(&0)
            || path.len() >= MAX_PATH
            || path.ends_with(b"/")
        {
            return Err(Errno(22));
        }
        let parts: Vec<_> = path
            .split(|&b| b == b'/')
            .filter(|p| !p.is_empty())
            .collect();
        if parts
            .iter()
            .any(|p| *p == b"." || *p == b".." || p.len() > 255)
        {
            return Err(Errno(22));
        }
        let mut current = Vec::new();
        let mut parents = Vec::new();
        for (i, part) in parts.iter().enumerate() {
            current.push(b'/');
            current.extend_from_slice(part);
            if i + 1 == parts.len() {
                if self.node(&current).is_ok() {
                    return Err(Errno(17));
                }
            } else if self.node(&current).is_err() {
                parents.push(current.clone());
            } else if !self.is_directory(&current) {
                return Err(Errno(20));
            }
        }
        let live = self
            .fs
            .borrow()
            .inodes
            .iter()
            .filter(|n| n.strong_count() != 0)
            .count();
        if live
            .checked_add(parents.len() + 1)
            .is_none_or(|n| n > self.fs.borrow().limits.nodes)
            || self
                .fs
                .borrow()
                .paths
                .len()
                .saturating_add(parents.len() + 1)
                > self.fs.borrow().limits.nodes
        {
            return Err(Errno(28));
        }
        Ok((current, parents))
    }
    /// Explicit embedding API: install an executable/hard link, without duplicating file data.
    pub fn import_alias(&mut self, existing: &[u8], alias: &[u8], executable: bool) -> Result<()> {
        let source = self.node(existing)?;
        let dest = self.resolve(AT_FDCWD, alias)?;
        if self.node(&dest).is_ok() {
            return Err(Errno(17));
        }
        if !matches!(source.borrow().content, Content::File(_)) {
            return Err(Errno(1));
        }
        if self.fs.borrow().paths.len() >= self.fs.borrow().limits.nodes {
            return Err(Errno(28));
        }
        let old_mode = source.borrow().mode;
        {
            let mut n = source.borrow_mut();
            n.links += 1;
            if executable {
                n.mode |= 0o111;
            }
        }
        let mut fs = self.fs.borrow_mut();
        fs.paths.insert(dest.clone(), source.clone());
        if let Err(e) = fs.checkpoint() {
            fs.paths.remove(&dest);
            let mut n = source.borrow_mut();
            n.links -= 1;
            n.mode = old_mode;
            return Err(e);
        }
        Ok(())
    }
    pub fn executable(&self, path: &[u8]) -> Result<Vec<u8>> {
        let p = self.resolve(AT_FDCWD, path)?;
        let node = self.node(&p)?;
        let n = node.borrow();
        if n.mode & 0o100 == 0 {
            return Err(Errno(13));
        }
        match &n.content {
            Content::File(b) => Self::executable_data(b),
            _ => Err(Errno(13)),
        }
    }
    pub fn mkdir_at(&mut self, dirfd: i32, path: &[u8], mode: u32) -> Result<()> {
        let p = self.resolve(dirfd, path)?;
        if self.node(&p).is_ok() {
            return Err(Errno(17));
        }
        self.check_parent_write(&p)?;
        self.insert(
            p,
            Content::Directory,
            0o40000 | (mode & 0o777 & !self.umask),
        )
    }
    pub fn unlink_at(&mut self, dirfd: i32, path: &[u8], directory: bool) -> Result<()> {
        let p = self.resolve(dirfd, path)?;
        if p == b"/" {
            return Err(Errno(16));
        }
        let node = self.node(&p)?;
        let is_dir = matches!(node.borrow().content, Content::Directory);
        if directory != is_dir {
            return Err(Errno(if is_dir { 21 } else { 20 }));
        }
        self.check_parent_write(&p)?;
        if is_dir {
            let mut prefix = p.clone();
            prefix.push(b'/');
            if self
                .fs
                .borrow()
                .paths
                .keys()
                .any(|n| n.starts_with(&prefix))
            {
                return Err(Errno(39));
            }
        }
        node.borrow_mut().links -= 1;
        let mut fs = self.fs.borrow_mut();
        fs.paths.remove(&p);
        if let Err(e) = fs.checkpoint() {
            node.borrow_mut().links += 1;
            fs.paths.insert(p, node);
            return Err(e);
        }
        let mut n = node.borrow_mut();
        if n.links == 0 {
            if let Content::File(data) = &mut n.content {
                data.orphan(true);
            }
        }
        Ok(())
    }
    fn available(&self, min: u32) -> Result<u32> {
        (min..MAX_FDS)
            .find(|n| !self.fds.contains_key(n))
            .ok_or(Errno(24))
    }
    pub fn open_at(&mut self, dirfd: i32, path: &[u8], flags: u32, mode: u32) -> Result<u32> {
        const ALLOWED: u32 = 3
            | 0x40
            | 0x80
            | 0x100
            | 0x200
            | 0x400
            | 0x800
            | O_DIRECTORY
            | O_NOFOLLOW
            | O_LARGEFILE
            | O_CLOEXEC
            | 0x101000;
        if flags & !ALLOWED != 0 || flags & 3 == 3 || (flags & 0x200 != 0 && flags & 3 == 0) {
            return Err(Errno(22));
        }
        let fd = self.available(0)?;
        let p = self.resolve(dirfd, path)?;
        let existed = self.node(&p).is_ok();
        if existed && flags & 0xc0 == 0xc0 {
            return Err(Errno(17));
        }
        if !existed {
            if flags & O_DIRECTORY != 0 || flags & 0x40 == 0 {
                return Err(Errno(2));
            }
            self.check_parent_write(&p)?;
            self.insert(
                p.clone(),
                Content::File(self.empty_data()?),
                0o100000 | (mode & 0o777 & !self.umask),
            )?;
        }
        let node = self.node(&p)?;
        {
            let mut n = node.borrow_mut();
            if matches!(n.content, Content::Directory) && flags & 3 != 0 {
                return Err(Errno(21));
            }
            if flags & O_DIRECTORY != 0 && !matches!(n.content, Content::Directory) {
                return Err(Errno(20));
            }
            if existed
                && ((flags & 3 != 1 && n.mode & 0o400 == 0)
                    || (flags & 3 != 0 && n.mode & 0o200 == 0))
            {
                return Err(Errno(13));
            }
            if flags & 0x200 != 0 {
                if let Content::File(b) = &mut n.content {
                    b.truncate(0)?;
                    n.times[1] = storage::Timestamp::now();
                    n.times[2] = n.times[1];
                }
            }
        }
        if flags & 0x200 != 0 {
            self.checkpoint()?;
        }
        self.fds.insert(
            fd,
            Descriptor {
                open: Rc::new(RefCell::new(OpenDescription {
                    kind: if matches!(node.borrow().content, Content::Terminal) {
                        FdKind::Terminal
                    } else {
                        FdKind::Node(p)
                    },
                    flags: flags & !O_CLOEXEC,
                    position: 0,
                    node: Some(node),
                    pipe: None,
                })),
                cloexec: flags & O_CLOEXEC != 0,
            },
        );
        Ok(fd)
    }
    pub fn close(&mut self, fd: u32) -> Result<()> {
        self.fds.remove(&fd).map(|_| ()).ok_or(Errno(9))
    }
    pub fn close_all(&mut self) {
        self.fds.clear();
    }
    pub fn close_exec(&mut self) {
        self.fds.retain(|_, d| !d.cloexec);
    }
    pub fn dup(&mut self, old: u32, min: u32, cloexec: bool) -> Result<u32> {
        let mut d = self.descriptor(old)?.clone();
        if min >= MAX_FDS {
            return Err(Errno(22));
        }
        let fd = self.available(min)?;
        d.cloexec = cloexec;
        self.fds.insert(fd, d);
        Ok(fd)
    }
    pub fn dup3(&mut self, old: u32, new: u32, flags: u32) -> Result<u32> {
        if old == new || flags & !O_CLOEXEC != 0 {
            return Err(Errno(22));
        }
        if new >= MAX_FDS {
            return Err(Errno(9));
        }
        let mut d = self.descriptor(old)?.clone();
        d.cloexec = flags & O_CLOEXEC != 0;
        self.fds.insert(new, d);
        Ok(new)
    }
    pub fn flags(&self, fd: u32) -> Result<u32> {
        let d = self.descriptor(fd)?;
        Ok(d.open.borrow().flags | if d.cloexec { O_CLOEXEC } else { 0 })
    }
    pub fn set_cloexec(&mut self, fd: u32, enabled: bool) -> Result<()> {
        self.fds.get_mut(&fd).ok_or(Errno(9))?.cloexec = enabled;
        Ok(())
    }
    pub fn set_status_flags(&mut self, fd: u32, flags: u32) -> Result<()> {
        let d = self.descriptor(fd)?;
        let mut o = d.open.borrow_mut();
        if matches!(o.kind, FdKind::Stdin | FdKind::Stdout | FdKind::Stderr)
            && flags & O_NONBLOCK != 0
        {
            return Err(Errno(38));
        }
        const CHANGEABLE: u32 = 0x400 | O_NONBLOCK;
        if flags & !(CHANGEABLE | 3 | O_DIRECTORY | O_NOFOLLOW | O_LARGEFILE | 0x101000) != 0 {
            return Err(Errno(22));
        }
        o.flags = (o.flags & !CHANGEABLE) | (flags & CHANGEABLE);
        Ok(())
    }
    pub fn pipe(&mut self, flags: u32) -> Result<[u32; 2]> {
        if flags & !(O_NONBLOCK | O_CLOEXEC) != 0 {
            return Err(Errno(22));
        }
        let free: Vec<_> = (0..MAX_FDS)
            .filter(|n| !self.fds.contains_key(n))
            .take(2)
            .collect();
        if free.len() != 2 {
            return Err(Errno(24));
        }
        let p = Rc::new(RefCell::new(Pipe {
            bytes: VecDeque::new(),
            reader: Weak::new(),
            writer: Weak::new(),
        }));
        let read = Rc::new(PipeEnd {
            pipe: p.clone(),
            read: true,
        });
        let write = Rc::new(PipeEnd {
            pipe: p.clone(),
            read: false,
        });
        {
            let mut p = p.borrow_mut();
            p.reader = Rc::downgrade(&read);
            p.writer = Rc::downgrade(&write);
        }
        for (fd, end, kind, access) in [
            (free[0], read, FdKind::PipeRead, 0),
            (free[1], write, FdKind::PipeWrite, 1),
        ] {
            self.fds.insert(
                fd,
                Descriptor {
                    open: Rc::new(RefCell::new(OpenDescription {
                        kind,
                        flags: (flags & O_NONBLOCK) | access,
                        position: 0,
                        node: None,
                        pipe: Some(end),
                    })),
                    cloexec: flags & O_CLOEXEC != 0,
                },
            );
        }
        Ok([free[0], free[1]])
    }
    pub fn read(&mut self, fd: u32, count: usize) -> Result<Vec<u8>> {
        let mut o = self.descriptor(fd)?.open.borrow_mut();
        if o.flags & 3 == 1 {
            return Err(Errno(9));
        }
        if count == 0 {
            return Ok(Vec::new());
        }
        if let Some(end) = &o.pipe {
            if !end.read {
                return Err(Errno(9));
            }
            let mut p = end.pipe.borrow_mut();
            if p.bytes.is_empty() && p.writer.strong_count() != 0 {
                return Err(Errno(11));
            }
            let n = count.min(p.bytes.len());
            return Ok(p.bytes.drain(..n).collect());
        }
        let node = o.node.clone().ok_or(Errno(9))?;
        let mut n = node.borrow_mut();
        let result = match &n.content {
            Content::File(b) => {
                let out = b.read_at(o.position, count)?;
                o.position += out.len() as u64;
                Ok(out)
            }
            Content::Null => Ok(Vec::new()),
            Content::Directory => Err(Errno(21)),
            Content::Terminal => Err(Errno(11)),
        };
        if result.is_ok() {
            n.times[0] = storage::Timestamp::now();
        }
        result
    }
    pub fn write(&mut self, fd: u32, bytes: &[u8]) -> Result<usize> {
        let o = self.descriptor(fd)?.open.borrow();
        if o.flags & 3 == 0 {
            return Err(Errno(9));
        }
        if let Some(end) = &o.pipe {
            if end.read {
                return Err(Errno(9));
            }
            let mut p = end.pipe.borrow_mut();
            if p.reader.strong_count() == 0 {
                return Err(Errno(32));
            }
            if bytes.is_empty() {
                return Ok(0);
            }
            let room = PIPE_CAPACITY - p.bytes.len();
            if room == 0 || (bytes.len() <= 4096 && room < bytes.len()) {
                return Err(Errno(11));
            }
            let n = room.min(bytes.len());
            p.bytes.extend(&bytes[..n]);
            return Ok(n);
        }
        drop(o);
        self.file_write(fd, bytes, None)
    }
    fn file_write(&mut self, fd: u32, bytes: &[u8], offset: Option<u64>) -> Result<usize> {
        let available = self.capacity().available_bytes;
        let mut o = self.descriptor(fd)?.open.borrow_mut();
        if o.flags & 3 == 0 {
            return Err(Errno(9));
        }
        let node = o.node.clone().ok_or(Errno(29))?;
        let mut n = node.borrow_mut();
        let count = bytes.len().min(storage::MAX_TRANSFER);
        let bytes = &bytes[..count];
        let result = match &mut n.content {
            Content::Null => Ok(bytes.len()),
            Content::Directory => Err(Errno(21)),
            Content::Terminal => Err(Errno(11)),
            Content::File(b) => {
                if bytes.is_empty() {
                    return Ok(0);
                }
                let position = if o.flags & 0x400 != 0 {
                    b.len()
                } else {
                    offset.unwrap_or(o.position)
                };
                let end = position
                    .checked_add(bytes.len() as u64)
                    .filter(|&n| n <= i64::MAX as u64)
                    .ok_or(Errno(27))?;
                if end.saturating_sub(b.len()) > available {
                    return Err(Errno(28));
                }
                let written = b.write_at(position, bytes)?;
                if offset.is_none() {
                    o.position = position + written as u64;
                }
                Ok(written)
            }
        };
        if result.is_ok_and(|n| n != 0) {
            n.times[1] = storage::Timestamp::now();
            n.times[2] = n.times[1];
        }
        let synchronous = o.flags & 0x1000 != 0;
        drop(n);
        drop(o);
        if result.is_ok() && synchronous {
            self.sync_fd(fd, false)?;
        }
        result
    }
    pub fn pread(&self, fd: u32, count: usize, offset: u64) -> Result<Vec<u8>> {
        if offset > i64::MAX as u64 {
            return Err(Errno(22));
        }
        let o = self.descriptor(fd)?.open.borrow();
        if o.flags & 3 == 1 {
            return Err(Errno(9));
        }
        let n = o.node.as_ref().ok_or(Errno(29))?.borrow();
        match &n.content {
            Content::File(b) => b.read_at(offset, count),
            Content::Null => Ok(Vec::new()),
            Content::Directory => Err(Errno(21)),
            Content::Terminal => Err(Errno(29)),
        }
    }
    pub fn pwrite(&mut self, fd: u32, bytes: &[u8], offset: u64) -> Result<usize> {
        if offset > i64::MAX as u64 {
            return Err(Errno(22));
        }
        self.file_write(fd, bytes, Some(offset))
    }
    pub fn truncate_fd(&mut self, fd: u32, length: u64) -> Result<()> {
        let available = self.capacity().available_bytes;
        let o = self.descriptor(fd)?.open.borrow();
        if o.flags & 3 == 0 {
            return Err(Errno(22));
        }
        let mut n = o.node.as_ref().ok_or(Errno(22))?.borrow_mut();
        let Content::File(b) = &mut n.content else {
            return Err(Errno(22));
        };
        if length > i64::MAX as u64 {
            return Err(Errno(22));
        }
        if length.saturating_sub(b.len()) > available {
            return Err(Errno(28));
        }
        b.truncate(length)?;
        n.times[1] = storage::Timestamp::now();
        n.times[2] = n.times[1];
        drop(n);
        drop(o);
        self.checkpoint()
    }
    pub fn truncate_at(&mut self, path: &[u8], length: u64) -> Result<()> {
        let fd = self.open_at(AT_FDCWD, path, 1, 0)?;
        let result = self.truncate_fd(fd, length);
        self.close(fd)?;
        result
    }
    pub fn seek(&mut self, fd: u32, offset: i64, whence: u32) -> Result<u64> {
        let mut o = self.descriptor(fd)?.open.borrow_mut();
        let node = o.node.clone().ok_or(Errno(29))?;
        let n = node.borrow();
        let length = match &n.content {
            Content::File(b) => b.len(),
            Content::Directory => 0,
            Content::Null => return Ok(0),
            Content::Terminal => return Err(Errno(29)),
        };
        let base = match whence {
            0 => 0,
            1 => o.position as i64,
            2 => length as i64,
            _ => return Err(Errno(22)),
        };
        let new = base
            .checked_add(offset)
            .filter(|&n| n >= 0)
            .ok_or(Errno(22))?;
        o.position = new as u64;
        Ok(new as u64)
    }
    fn stat_node(node: &Node) -> Result<[u8; 128]> {
        let mut out = [0; 128];
        out[8..16].copy_from_slice(&node.inode.to_le_bytes());
        out[16..20].copy_from_slice(&node.mode.to_le_bytes());
        out[20..24].copy_from_slice(&node.links.to_le_bytes());
        out[24..28].copy_from_slice(&1000u32.to_le_bytes());
        out[28..32].copy_from_slice(&1000u32.to_le_bytes());
        let size = match &node.content {
            Content::File(b) => b.len(),
            _ => 0,
        };
        out[48..56].copy_from_slice(&size.to_le_bytes());
        out[56..60].copy_from_slice(&4096u32.to_le_bytes());
        let blocks = if let Content::File(data) = &node.content {
            data.blocks()?
        } else {
            0
        };
        out[64..72].copy_from_slice(&blocks.to_le_bytes());
        for (offset, t) in [72, 88, 104].into_iter().zip(node.times) {
            out[offset..offset + 8].copy_from_slice(&t.seconds.to_le_bytes());
            out[offset + 8..offset + 16].copy_from_slice(&(t.nanos as u64).to_le_bytes());
        }
        Ok(out)
    }
    pub fn stat_at(&self, dirfd: i32, path: &[u8]) -> Result<[u8; 128]> {
        let p = self.resolve(dirfd, path)?;
        let n = self.node(&p)?;
        let out = Self::stat_node(&n.borrow());
        out
    }
    pub fn stat_fd(&self, fd: u32) -> Result<[u8; 128]> {
        let d = self.descriptor(fd)?;
        let o = d.open.borrow();
        if let Some(n) = &o.node {
            return Self::stat_node(&n.borrow());
        }
        Self::stat_node(&Node {
            content: Content::Null,
            mode: if o.pipe.is_some() { 0o10600 } else { 0o20666 },
            inode: fd as u64 + 0x10000,
            links: 1,
            times: [storage::Timestamp::default(); 3],
        })
    }
    pub fn chdir(&mut self, path: &[u8]) -> Result<()> {
        let p = self.resolve(AT_FDCWD, path)?;
        let n = self.node(&p)?;
        if !matches!(n.borrow().content, Content::Directory) {
            return Err(Errno(20));
        }
        self.cwd_node = Some(n);
        Ok(())
    }
    pub fn getdents(&mut self, fd: u32, count: usize) -> Result<Vec<u8>> {
        let d = self.descriptor(fd)?;
        let mut o = d.open.borrow_mut();
        let node = o.node.as_ref().ok_or(Errno(20))?;
        if !matches!(node.borrow().content, Content::Directory) {
            return Err(Errno(20));
        }
        let p = self.path_of(node)?;
        let fs = self.fs.borrow();
        let inode = fs.paths[&p].borrow().inode;
        let parent_end = p.iter().rposition(|&b| b == b'/').expect("absolute").max(1);
        let parent = fs.paths[&p[..parent_end]].borrow().inode;
        let mut entries = vec![(b".".to_vec(), inode, 4u8), (b"..".to_vec(), parent, 4)];
        let mut prefix = p.clone();
        if prefix != b"/" {
            prefix.push(b'/');
        }
        for (path, node) in fs.paths.range(prefix.clone()..) {
            if !path.starts_with(&prefix) {
                break;
            }
            let name = &path[prefix.len()..];
            if name.is_empty() || name.contains(&b'/') {
                continue;
            }
            let n = node.borrow();
            entries.push((
                name.to_vec(),
                n.inode,
                match n.content {
                    Content::Directory => 4,
                    Content::File(_) => 8,
                    Content::Null | Content::Terminal => 2,
                },
            ));
        }
        let mut out = Vec::new();
        while let Some((name, ino, kind)) = entries.get(o.position as usize) {
            let size = (19 + name.len() + 1 + 7) & !7;
            if out.len() + size > count {
                if out.is_empty() {
                    return Err(Errno(22));
                }
                break;
            }
            let start = out.len();
            out.resize(start + size, 0);
            out[start..start + 8].copy_from_slice(&ino.to_le_bytes());
            out[start + 8..start + 16].copy_from_slice(&(o.position + 1).to_le_bytes());
            out[start + 16..start + 18].copy_from_slice(&(size as u16).to_le_bytes());
            out[start + 18] = *kind;
            out[start + 19..start + 19 + name.len()].copy_from_slice(name);
            o.position += 1;
        }
        Ok(out)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths_cannot_escape_root_or_traverse_regular_files() {
        let mut v = Vfs::default();
        v.import_file(b"/data/file", b"data".to_vec()).unwrap();
        assert_eq!(
            v.resolve(AT_FDCWD, b"/../../data/./file").unwrap(),
            b"/data/file"
        );
        assert_eq!(v.resolve(AT_FDCWD, b"/data/file/../file"), Err(Errno(20)));
        assert_eq!(v.resolve(9, b"relative"), Err(Errno(9)));
        assert_eq!(v.resolve(9, b"/data/file").unwrap(), b"/data/file");
    }
    #[test]
    fn open_read_seek_write_and_fd_reuse() {
        let mut v = Vfs::default();
        v.import_file(b"/file", b"abc".to_vec()).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/file", 2, 0).unwrap();
        assert_eq!(fd, 3);
        assert_eq!(v.read(fd, 2).unwrap(), b"ab");
        v.seek(fd, -1, 1).unwrap();
        v.write(fd, b"Z").unwrap();
        v.seek(fd, 0, 0).unwrap();
        assert_eq!(v.read(fd, 9).unwrap(), b"aZc");
        v.close(0).unwrap();
        assert_eq!(v.open_at(AT_FDCWD, b"/file", 0, 0).unwrap(), 0);
        assert_eq!(
            v.open_at(AT_FDCWD, b"/file", O_DIRECTORY, 0),
            Err(Errno(20))
        );
    }
    #[test]
    fn directory_entries_are_aligned_and_continue_after_small_buffers() {
        let mut v = Vfs::default();
        v.import_file(b"/a/z", vec![1]).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/a", O_DIRECTORY, 0).unwrap();
        assert_eq!(v.getdents(fd, 1), Err(Errno(22)));
        let first = v.getdents(fd, 24).unwrap();
        assert_eq!(first.len(), 24);
        assert_eq!(first[19], b'.');
        let rest = v.getdents(fd, 4096).unwrap();
        assert_eq!(rest.len(), 48);
        assert_eq!(rest[43], b'z');
        assert!(v.getdents(fd, 4096).unwrap().is_empty());
    }
    #[test]
    fn append_null_and_storage_limit() {
        let mut v = Vfs::default();
        let fd = v.open_at(AT_FDCWD, b"/new", 0x441, 0o644).unwrap();
        v.write(fd, b"a").unwrap();
        v.seek(fd, 0, 0).unwrap();
        v.write(fd, b"b").unwrap();
        let read = v.open_at(AT_FDCWD, b"/new", 0, 0).unwrap();
        assert_eq!(v.read(read, 9).unwrap(), b"ab");
        v.seek(fd, MAX_FILE_BYTES as i64, 0).unwrap(); // append resets position, so test a separate descriptor.
        let plain = v.open_at(AT_FDCWD, b"/new", 1, 0).unwrap();
        v.seek(plain, MAX_FILE_BYTES as i64, 0).unwrap();
        assert_eq!(v.write(plain, b"x"), Err(Errno(28)));
        assert_eq!(v.allocated_bytes(), 2);
        let null = v.open_at(AT_FDCWD, b"/dev/null", 2, 0).unwrap();
        assert_eq!(v.write(null, b"abc").unwrap(), 3);
        assert!(v.read(null, 99).unwrap().is_empty());
    }

    #[test]
    fn imports_do_not_leave_partial_directories_at_the_node_limit() {
        let mut v = Vfs::default();
        for index in 0..MAX_NODES - 3 {
            v.import_file(format!("/f{index}").as_bytes(), Vec::new())
                .unwrap();
        }
        assert_eq!(
            v.import_file(b"/new/parent/file", Vec::new()),
            Err(Errno(28))
        );
        assert_eq!(v.stat_at(AT_FDCWD, b"/new"), Err(Errno(2)));
    }

    #[test]
    fn directory_search_permissions_and_zero_length_writes() {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/hidden", 0o400).unwrap();
        assert_eq!(
            v.open_at(AT_FDCWD, b"/hidden/file", 0x41, 0o600),
            Err(Errno(13))
        );
        let fd = v.open_at(AT_FDCWD, b"/empty", 0x41, 0).unwrap();
        v.seek(fd, 1_000_000, 0).unwrap();
        assert_eq!(v.write(fd, b"").unwrap(), 0);
        assert_eq!(v.allocated_bytes(), 0);
    }
}

#[cfg(test)]
mod process_tests {
    use super::*;
    #[test]
    fn fork_shares_storage_and_open_position_but_not_descriptor_table() {
        let mut parent = Vfs::default();
        parent.import_file(b"/file", b"abcd".to_vec()).unwrap();
        let fd = parent.open_at(AT_FDCWD, b"/file", 2, 0).unwrap();
        let mut child = parent.clone();
        assert_eq!(child.read(fd, 1).unwrap(), b"a");
        assert_eq!(parent.read(fd, 1).unwrap(), b"b");
        child.close(fd).unwrap();
        assert_eq!(parent.read(fd, 1).unwrap(), b"c");
        child.open_at(AT_FDCWD, b"/child", 0x41, 0o600).unwrap();
        assert!(parent.stat_at(AT_FDCWD, b"/child").is_ok());
        child.chdir(b"/dev").unwrap();
        assert_eq!(parent.cwd().unwrap(), b"/");
    }
    #[test]
    fn dup_and_fork_share_status_flags_but_cloexec_is_per_descriptor() {
        let mut parent = Vfs::default();
        parent.import_file(b"/file", vec![]).unwrap();
        let fd = parent.open_at(AT_FDCWD, b"/file", 2, 0).unwrap();
        let duplicate = parent.dup(fd, 10, true).unwrap();
        let mut child = parent.clone();
        child.set_status_flags(fd, 2 | 0x400).unwrap();
        assert_ne!(parent.flags(duplicate).unwrap() & 0x400, 0);
        child.set_cloexec(fd, true).unwrap();
        assert_eq!(parent.flags(fd).unwrap() & O_CLOEXEC, 0);
        child.close_exec();
        assert_eq!(child.fd_kind(fd), Err(Errno(9)));
        assert!(parent.fd_kind(fd).is_ok());
        assert_eq!(child.fd_kind(duplicate), Err(Errno(9)));
    }
    #[test]
    fn pipe_eof_waits_for_last_shared_writer_and_broken_pipe_for_last_reader() {
        let mut parent = Vfs::default();
        let [r, w] = parent.pipe(0).unwrap();
        let mut child = parent.clone();
        parent.close(w).unwrap();
        assert_eq!(parent.read(r, 1), Err(Errno(11)));
        child.write(w, b"x").unwrap();
        child.close(w).unwrap();
        assert_eq!(parent.read(r, 1).unwrap(), b"x");
        assert!(parent.read(r, 1).unwrap().is_empty());
        let [r, w] = parent.pipe(0).unwrap();
        let mut child = parent.clone();
        parent.close(r).unwrap();
        assert_eq!(parent.write(w, b"x").unwrap(), 1);
        child.close(r).unwrap();
        assert_eq!(parent.write(w, b"x"), Err(Errno(32)));
    }
    #[test]
    fn pipe_small_writes_are_atomic_under_backpressure() {
        let mut v = Vfs::default();
        let [r, w] = v.pipe(O_NONBLOCK).unwrap();
        assert_eq!(v.write(w, &vec![7; PIPE_CAPACITY]).unwrap(), PIPE_CAPACITY);
        assert_eq!(v.poll(r, 1), 1);
        assert_eq!(v.poll(w, 4), 0);
        assert_eq!(v.read(r, 1).unwrap(), vec![7]);
        assert_eq!(v.write(w, b"ab"), Err(Errno(11)));
        assert_eq!(
            v.read(r, PIPE_CAPACITY).unwrap(),
            vec![7; PIPE_CAPACITY - 1]
        );
        v.close(w).unwrap();
        assert_eq!(v.poll(r, 1), 17);
    }
    #[test]
    fn unlink_keeps_open_file_and_quota_until_last_close() {
        let mut v = Vfs::default();
        v.import_file(b"/file", b"abc".to_vec()).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/file", 0, 0).unwrap();
        v.unlink_at(AT_FDCWD, b"/file", false).unwrap();
        assert_eq!(v.stat_at(AT_FDCWD, b"/file"), Err(Errno(2)));
        assert_eq!(v.allocated_bytes(), 3);
        assert_eq!(v.read(fd, 3).unwrap(), b"abc");
        v.close(fd).unwrap();
        assert_eq!(v.allocated_bytes(), 0);
    }
    #[test]
    fn failed_dup3_does_not_close_the_target() {
        let mut v = Vfs::default();
        let old = v.fd_kind(1).unwrap();
        assert_eq!(v.dup3(200, 1, 0), Err(Errno(9)));
        assert_eq!(v.fd_kind(1).unwrap(), old);
        assert_eq!(v.dup3(1, 1, 0), Err(Errno(22)));
    }
}

#[cfg(test)]
mod permission_tests {
    use super::*;
    #[test]
    fn directory_mutations_require_parent_write_and_import_uses_canonical_path() {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/readonly", 0o555).unwrap();
        assert_eq!(
            v.open_at(AT_FDCWD, b"/readonly/new", 0x41, 0o600),
            Err(Errno(13))
        );
        assert_eq!(
            v.mkdir_at(AT_FDCWD, b"/readonly/sub", 0o755),
            Err(Errno(13))
        );
        v.import_executable(b"/readonly//program", vec![1]).unwrap();
        assert_eq!(v.executable(b"/readonly/program").unwrap(), vec![1]);
        assert_eq!(
            v.unlink_at(AT_FDCWD, b"/readonly/program", false),
            Err(Errno(13))
        );
    }
}
