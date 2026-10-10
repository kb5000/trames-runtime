// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded in-memory filesystem. No guest operation touches a host path.
use std::{collections::BTreeMap, fmt};

pub const MAX_PATH: usize = 4096;
pub const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_NODES: usize = 1024;
pub const MAX_FDS: u32 = 256;
pub const AT_FDCWD: i32 = -100;
// Linux AArch64 differs from x86_64 for these open flags.
pub const O_DIRECTORY: u32 = 0x4000;
pub const O_NOFOLLOW: u32 = 0x8000;
pub const O_LARGEFILE: u32 = 0x20000;
pub const O_CLOEXEC: u32 = 0x80000;

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
}
struct Descriptor {
    kind: FdKind,
    flags: u32,
    position: usize,
}
enum Content {
    Directory,
    File(Vec<u8>),
    Null,
}
struct Node {
    content: Content,
    mode: u32,
    inode: u64,
}

pub struct Vfs {
    nodes: BTreeMap<Vec<u8>, Node>,
    fds: BTreeMap<u32, Descriptor>,
    cwd: Vec<u8>,
    next_inode: u64,
    pub umask: u32,
}
impl Default for Vfs {
    fn default() -> Self {
        let mut v = Self {
            nodes: BTreeMap::new(),
            fds: BTreeMap::new(),
            cwd: b"/".to_vec(),
            next_inode: 1,
            umask: 0o022,
        };
        v.insert(b"/".to_vec(), Content::Directory, 0o40755)
            .expect("root");
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
                    kind,
                    flags,
                    position: 0,
                },
            );
        }
        v
    }
}

impl Vfs {
    fn insert(&mut self, path: Vec<u8>, content: Content, mode: u32) -> Result<()> {
        if self.nodes.len() >= MAX_NODES {
            return Err(Errno(28));
        }
        let inode = self.next_inode;
        self.next_inode += 1;
        self.nodes.insert(
            path,
            Node {
                content,
                mode,
                inode,
            },
        );
        Ok(())
    }
    pub fn allocated_bytes(&self) -> usize {
        self.nodes
            .values()
            .map(|n| match &n.content {
                Content::File(b) => b.len(),
                _ => 0,
            })
            .sum()
    }
    pub fn cwd(&self) -> &[u8] {
        &self.cwd
    }
    pub fn fd_kind(&self, fd: u32) -> Result<&FdKind> {
        Ok(&self.fds.get(&fd).ok_or(Errno(9))?.kind)
    }
    fn is_directory(&self, path: &[u8]) -> bool {
        self.nodes
            .get(path)
            .is_some_and(|n| matches!(n.content, Content::Directory))
    }
    fn base(&self, dirfd: i32) -> Result<&[u8]> {
        if dirfd == AT_FDCWD {
            return Ok(&self.cwd);
        }
        match self.fd_kind(dirfd as u32)? {
            FdKind::Node(p) if self.is_directory(p) => Ok(p),
            _ => Err(Errno(20)),
        }
    }
    /// Resolve components as they are traversed: `file/..` is ENOTDIR, not root.
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
            self.base(dirfd)?.to_vec()
        };
        let components: Vec<_> = path
            .split(|&b| b == b'/')
            .filter(|p| !p.is_empty())
            .collect();
        for (index, component) in components.iter().enumerate() {
            if !self.is_directory(&current) {
                return Err(if self.nodes.contains_key(&current) {
                    Errno(20)
                } else {
                    Errno(2)
                });
            }
            if self.nodes[&current].mode & 0o100 == 0 {
                return Err(Errno(13));
            }
            if *component == b"." {
                continue;
            }
            if *component == b".." {
                if current != b"/" {
                    current.truncate(current.iter().rposition(|&b| b == b'/').unwrap().max(1));
                }
                continue;
            }
            if component.len() > 255 {
                return Err(Errno(36));
            }
            if current != b"/" {
                current.push(b'/');
            }
            current.extend_from_slice(component);
            if current.len() >= MAX_PATH {
                return Err(Errno(36));
            }
            if index + 1 == components.len()
                && path.last() == Some(&b'/')
                && !self.is_directory(&current)
            {
                return Err(if self.nodes.contains_key(&current) {
                    Errno(20)
                } else {
                    Errno(2)
                });
            }
        }
        Ok(current)
    }
    /// Explicit embedding API: import one file's bytes and create its virtual parents.
    pub fn import_file(&mut self, path: &[u8], bytes: Vec<u8>) -> Result<()> {
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
        if self
            .allocated_bytes()
            .checked_add(bytes.len())
            .is_none_or(|n| n > MAX_FILE_BYTES)
        {
            return Err(Errno(28));
        }
        let mut current = Vec::new();
        let mut parents = Vec::new();
        for (index, part) in parts.iter().enumerate() {
            current.push(b'/');
            current.extend_from_slice(part);
            if index + 1 == parts.len() {
                if self.nodes.contains_key(&current) {
                    return Err(Errno(17));
                }
            } else if !self.nodes.contains_key(&current) {
                parents.push(current.clone());
            } else if !self.is_directory(&current) {
                return Err(Errno(20));
            }
        }
        if self
            .nodes
            .len()
            .checked_add(parents.len() + 1)
            .is_none_or(|n| n > MAX_NODES)
        {
            return Err(Errno(28));
        }
        for parent in parents {
            self.insert(parent, Content::Directory, 0o40755)?;
        }
        self.insert(current, Content::File(bytes), 0o100644)
    }
    pub fn mkdir_at(&mut self, dirfd: i32, path: &[u8], mode: u32) -> Result<()> {
        let p = self.resolve(dirfd, path)?;
        if self.nodes.contains_key(&p) {
            return Err(Errno(17));
        }
        self.insert(
            p,
            Content::Directory,
            0o40000 | (mode & 0o777 & !self.umask),
        )
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
            | O_CLOEXEC;
        if flags & !ALLOWED != 0 || flags & 3 == 3 {
            return Err(Errno(22));
        }
        if flags & 0x200 != 0 && flags & 3 == 0 {
            return Err(Errno(22));
        }
        let fd = (0..MAX_FDS)
            .find(|n| !self.fds.contains_key(n))
            .ok_or(Errno(24))?;
        let p = self.resolve(dirfd, path)?;
        let existed = self.nodes.contains_key(&p);
        if existed && flags & 0xc0 == 0xc0 {
            return Err(Errno(17));
        }
        if !existed {
            if flags & O_DIRECTORY != 0 {
                return Err(Errno(2));
            }
            if flags & 0x40 == 0 {
                return Err(Errno(2));
            }
            self.insert(
                p.clone(),
                Content::File(Vec::new()),
                0o100000 | (mode & 0o777 & !self.umask),
            )?;
        }
        let node = self.nodes.get_mut(&p).expect("resolved node");
        if matches!(node.content, Content::Directory) && flags & 3 != 0 {
            return Err(Errno(21));
        }
        if flags & O_DIRECTORY != 0 && !matches!(node.content, Content::Directory) {
            return Err(Errno(20));
        }
        if existed
            && ((flags & 3 != 1 && node.mode & 0o400 == 0)
                || (flags & 3 != 0 && node.mode & 0o200 == 0))
        {
            return Err(Errno(13));
        }
        if flags & 0x200 != 0 {
            if flags & 3 == 0 {
                return Err(Errno(22));
            }
            if let Content::File(b) = &mut node.content {
                b.clear();
            }
        }
        self.fds.insert(
            fd,
            Descriptor {
                kind: FdKind::Node(p),
                flags,
                position: 0,
            },
        );
        Ok(fd)
    }
    pub fn close(&mut self, fd: u32) -> Result<()> {
        self.fds.remove(&fd).map(|_| ()).ok_or(Errno(9))
    }
    pub fn flags(&self, fd: u32) -> Result<u32> {
        Ok(self.fds.get(&fd).ok_or(Errno(9))?.flags)
    }
    pub fn set_cloexec(&mut self, fd: u32, enabled: bool) -> Result<()> {
        let d = self.fds.get_mut(&fd).ok_or(Errno(9))?;
        if enabled {
            d.flags |= O_CLOEXEC;
        } else {
            d.flags &= !O_CLOEXEC;
        }
        Ok(())
    }
    pub fn set_status_flags(&mut self, fd: u32, flags: u32) -> Result<()> {
        let d = self.fds.get_mut(&fd).ok_or(Errno(9))?;
        if !matches!(d.kind, FdKind::Node(_)) && flags & 0x800 != 0 {
            return Err(Errno(38));
        }
        const CHANGEABLE: u32 = 0x400 | 0x800;
        if flags & !(CHANGEABLE | 3 | O_DIRECTORY | O_NOFOLLOW | O_LARGEFILE) != 0 {
            return Err(Errno(22));
        }
        d.flags = (d.flags & !CHANGEABLE) | (flags & CHANGEABLE);
        Ok(())
    }
    pub fn read(&mut self, fd: u32, count: usize) -> Result<Vec<u8>> {
        let d = self.fds.get_mut(&fd).ok_or(Errno(9))?;
        if d.flags & 3 == 1 {
            return Err(Errno(9));
        }
        let p = match &d.kind {
            FdKind::Node(p) => p,
            _ => return Err(Errno(9)),
        };
        match &self.nodes.get(p).ok_or(Errno(2))?.content {
            Content::File(b) => {
                let start = d.position.min(b.len());
                let end = start.saturating_add(count).min(b.len());
                let bytes = b[start..end].to_vec();
                d.position = end;
                Ok(bytes)
            }
            Content::Null => Ok(Vec::new()),
            Content::Directory => Err(Errno(21)),
        }
    }
    pub fn write(&mut self, fd: u32, bytes: &[u8]) -> Result<usize> {
        let allocated = self.allocated_bytes();
        let d = self.fds.get_mut(&fd).ok_or(Errno(9))?;
        if d.flags & 3 == 0 {
            return Err(Errno(9));
        }
        let p = match &d.kind {
            FdKind::Node(p) => p,
            _ => return Err(Errno(9)),
        };
        match &mut self.nodes.get_mut(p).ok_or(Errno(2))?.content {
            Content::Null => Ok(bytes.len()),
            Content::Directory => Err(Errno(21)),
            Content::File(b) => {
                if bytes.is_empty() {
                    return Ok(0);
                }
                if d.flags & 0x400 != 0 {
                    d.position = b.len();
                }
                let end = d.position.checked_add(bytes.len()).ok_or(Errno(27))?;
                if allocated
                    .saturating_sub(b.len())
                    .checked_add(end.max(b.len()))
                    .is_none_or(|n| n > MAX_FILE_BYTES)
                {
                    return Err(Errno(28));
                }
                b.resize(end.max(b.len()), 0);
                b[d.position..end].copy_from_slice(bytes);
                d.position = end;
                Ok(bytes.len())
            }
        }
    }
    pub fn seek(&mut self, fd: u32, offset: i64, whence: u32) -> Result<u64> {
        let d = self.fds.get_mut(&fd).ok_or(Errno(9))?;
        let p = match &d.kind {
            FdKind::Node(p) => p,
            _ => return Err(Errno(29)),
        };
        let length = match &self.nodes.get(p).ok_or(Errno(2))?.content {
            Content::File(b) => b.len(),
            Content::Directory => 0,
            Content::Null => return Ok(0),
        };
        let base = match whence {
            0 => 0,
            1 => d.position as i64,
            2 => length as i64,
            _ => return Err(Errno(22)),
        };
        let new = base
            .checked_add(offset)
            .filter(|&n| n >= 0)
            .ok_or(Errno(22))?;
        d.position = usize::try_from(new).map_err(|_| Errno(22))?;
        Ok(new as u64)
    }
    fn stat_node(node: &Node) -> [u8; 128] {
        let mut out = [0; 128];
        out[8..16].copy_from_slice(&node.inode.to_le_bytes());
        out[16..20].copy_from_slice(&node.mode.to_le_bytes());
        out[20..24].copy_from_slice(&1u32.to_le_bytes());
        out[24..28].copy_from_slice(&1000u32.to_le_bytes());
        out[28..32].copy_from_slice(&1000u32.to_le_bytes());
        let size = match &node.content {
            Content::File(b) => b.len() as u64,
            _ => 0,
        };
        out[48..56].copy_from_slice(&size.to_le_bytes());
        out[56..60].copy_from_slice(&4096u32.to_le_bytes());
        out[64..72].copy_from_slice(&size.div_ceil(512).to_le_bytes());
        out
    }
    pub fn stat_at(&self, dirfd: i32, path: &[u8]) -> Result<[u8; 128]> {
        let p = self.resolve(dirfd, path)?;
        Ok(Self::stat_node(self.nodes.get(&p).ok_or(Errno(2))?))
    }
    pub fn stat_fd(&self, fd: u32) -> Result<[u8; 128]> {
        match self.fd_kind(fd)? {
            FdKind::Node(p) => Ok(Self::stat_node(self.nodes.get(p).ok_or(Errno(2))?)),
            _ => Ok(Self::stat_node(&Node {
                content: Content::Null,
                mode: 0o20666,
                inode: fd as u64 + 0x10000,
            })),
        }
    }
    pub fn chdir(&mut self, path: &[u8]) -> Result<()> {
        let p = self.resolve(AT_FDCWD, path)?;
        if !self.is_directory(&p) {
            return Err(if self.nodes.contains_key(&p) {
                Errno(20)
            } else {
                Errno(2)
            });
        }
        self.cwd = p;
        Ok(())
    }
    pub fn getdents(&mut self, fd: u32, count: usize) -> Result<Vec<u8>> {
        let d = self.fds.get(&fd).ok_or(Errno(9))?;
        let p = match &d.kind {
            FdKind::Node(p) if self.is_directory(p) => p.clone(),
            _ => return Err(Errno(20)),
        };
        let inode = self.nodes[&p].inode;
        let parent_end = p
            .iter()
            .rposition(|&b| b == b'/')
            .expect("absolute path")
            .max(1);
        let parent_inode = self.nodes[&p[..parent_end]].inode;
        let mut entries = vec![
            (b".".to_vec(), inode, 4u8),
            (b"..".to_vec(), parent_inode, 4),
        ];
        let mut prefix = p.clone();
        if prefix != b"/" {
            prefix.push(b'/');
        }
        for (path, node) in self.nodes.range(prefix.clone()..) {
            if !path.starts_with(&prefix) {
                break;
            }
            let name = &path[prefix.len()..];
            if name.is_empty() || name.contains(&b'/') {
                continue;
            }
            entries.push((
                name.to_vec(),
                node.inode,
                match node.content {
                    Content::Directory => 4,
                    Content::File(_) => 8,
                    Content::Null => 2,
                },
            ));
        }
        let mut position = d.position;
        let mut out = Vec::new();
        while let Some((name, ino, kind)) = entries.get(position) {
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
            out[start + 8..start + 16].copy_from_slice(&(position as u64 + 1).to_le_bytes());
            out[start + 16..start + 18].copy_from_slice(&(size as u16).to_le_bytes());
            out[start + 18] = *kind;
            out[start + 19..start + 19 + name.len()].copy_from_slice(name);
            position += 1;
        }
        self.fds.get_mut(&fd).expect("descriptor").position = position;
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
