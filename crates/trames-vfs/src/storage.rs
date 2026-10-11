// SPDX-License-Identifier: GPL-3.0-or-later
//! Private inode objects and an atomic, versioned namespace manifest.
use super::*;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const DEFAULT_DISK_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const DEFAULT_DISK_NODES: usize = 131_072;
pub const MAX_DISK_NODES: usize = 262_144;
pub const MAX_TRANSFER: usize = 1024 * 1024;
const MAX_MANIFEST: u64 = 128 * 1024 * 1024;
const MAX_EXECUTABLE: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageLimits {
    pub file_bytes: u64,
    pub nodes: usize,
}
impl StorageLimits {
    pub fn memory() -> Self {
        Self {
            file_bytes: MAX_FILE_BYTES as u64,
            nodes: MAX_NODES,
        }
    }
    pub fn disk() -> Self {
        Self {
            file_bytes: DEFAULT_DISK_BYTES,
            nodes: DEFAULT_DISK_NODES,
        }
    }
    fn validate(self) -> Result<()> {
        if self.file_bytes == 0
            || self.file_bytes > i64::MAX as u64
            || !(3..=MAX_DISK_NODES).contains(&self.nodes)
        {
            return Err(Errno(22));
        }
        Ok(())
    }
}

/// Supplied by the platform adapter, e.g. the authorized iPad volume.
/// This is a snapshot, not a reservation of host storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VolumeSpace {
    pub total_bytes: u64,
    pub available_bytes: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageCapacity {
    pub budget_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub volume_total_bytes: Option<u64>,
    pub node_limit: usize,
    pub nodes_used: usize,
    pub persistent: bool,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct DiskOptions {
    /// None preserves a reopened store's limits, or selects 16 GiB for a new store.
    pub limits: Option<StorageLimits>,
    pub volume_space: Option<VolumeSpace>,
}

pub(super) fn host_errno(e: io::Error) -> Errno {
    // These Unix descriptor exhaustion codes are shared by Linux and Darwin.
    // ErrorKind does not classify them, so otherwise they become a misleading EIO.
    #[cfg(unix)]
    if let Some(code @ (23 | 24)) = e.raw_os_error() {
        return Errno(code as u32);
    }
    Errno(match e.kind() {
        io::ErrorKind::NotFound => 2,
        io::ErrorKind::Interrupted => 4,
        io::ErrorKind::PermissionDenied => 13,
        io::ErrorKind::AlreadyExists => 17,
        io::ErrorKind::InvalidInput => 22,
        io::ErrorKind::StorageFull => 28,
        io::ErrorKind::FileTooLarge => 27,
        io::ErrorKind::OutOfMemory => 12,
        _ => 5,
    })
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Timestamp {
    pub seconds: i64,
    pub nanos: u32,
}
impl Timestamp {
    pub fn now() -> Self {
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            seconds: d.as_secs() as i64,
            nanos: d.subsec_nanos(),
        }
    }
}

pub(super) enum FileData {
    Memory(Vec<u8>),
    Disk(DiskObject),
}
pub(super) struct DiskObject {
    length: u64,
    path: PathBuf,
    remove_on_drop: bool,
    // An open-unlinked file must keep the store's exclusive lock alive.
    _store: Rc<DiskStore>,
    inode: u64,
}
impl DiskObject {
    // Guest inode lifetime is independent of host descriptor lifetime. A store
    // with thousands of closed files must not consume thousands of iOS handles.
    // Orphans retain their private object path until the last guest reference dies.
    fn open(&self, write: bool) -> Result<File> {
        regular(&self.path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(write);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        options.custom_flags(0x20000); // O_NOFOLLOW
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        options.custom_flags(0x100); // O_NOFOLLOW
        let file = options.open(&self.path).map_err(host_errno)?;
        if !file.metadata().map_err(host_errno)?.is_file() {
            return Err(Errno(22));
        }
        Ok(file)
    }
}
impl Drop for DiskObject {
    fn drop(&mut self) {
        if self.remove_on_drop {
            let _ = fs::remove_file(&self.path);
        }
    }
}
impl FileData {
    pub fn blocks(&self) -> Result<u64> {
        #[cfg(unix)]
        if let Self::Disk(d) = self {
            return Ok(fs::symlink_metadata(&d.path).map_err(host_errno)?.blocks());
        }
        Ok(self.len().div_ceil(512))
    }
    pub fn inode(&self) -> Option<u64> {
        match self {
            Self::Memory(_) => None,
            Self::Disk(d) => Some(d.inode),
        }
    }
    pub fn len(&self) -> u64 {
        match self {
            Self::Memory(b) => b.len() as u64,
            Self::Disk(d) => d.length,
        }
    }
    pub fn read_at(&self, offset: u64, count: usize) -> Result<Vec<u8>> {
        let count = count
            .min(MAX_TRANSFER)
            .min(self.len().saturating_sub(offset) as usize);
        if count == 0 {
            return Ok(Vec::new());
        }
        match self {
            Self::Memory(b) => Ok(b[offset as usize..offset as usize + count].to_vec()),
            Self::Disk(d) => {
                let mut file = d.open(false)?;
                file.seek(SeekFrom::Start(offset)).map_err(host_errno)?;
                let mut bytes = vec![0; count];
                let n = file.read(&mut bytes).map_err(host_errno)?;
                bytes.truncate(n);
                Ok(bytes)
            }
        }
    }
    pub fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<usize> {
        match self {
            Self::Memory(b) => {
                let end = usize::try_from(offset)
                    .ok()
                    .and_then(|n| n.checked_add(bytes.len()))
                    .ok_or(Errno(27))?;
                if end > b.len() {
                    b.try_reserve(end - b.len()).map_err(|_| Errno(12))?;
                    b.resize(end, 0);
                }
                b[offset as usize..end].copy_from_slice(bytes);
                Ok(bytes.len())
            }
            Self::Disk(d) => {
                let mut file = d.open(true)?;
                file.seek(SeekFrom::Start(offset)).map_err(host_errno)?;
                let n = file.write(bytes).map_err(host_errno)?;
                d.length = d.length.max(offset + n as u64);
                Ok(n)
            }
        }
    }
    pub fn truncate(&mut self, length: u64) -> Result<()> {
        match self {
            Self::Memory(b) => {
                let n = usize::try_from(length).map_err(|_| Errno(27))?;
                if n > b.len() {
                    b.try_reserve(n - b.len()).map_err(|_| Errno(12))?;
                }
                b.resize(n, 0);
            }
            Self::Disk(d) => {
                d.open(true)?.set_len(length).map_err(host_errno)?;
                d.length = length;
            }
        }
        Ok(())
    }
    pub fn sync(&self, data_only: bool) -> Result<()> {
        if let Self::Disk(d) = self {
            let file = d.open(false)?;
            if data_only {
                file.sync_data()
            } else {
                file.sync_all()
            }
            .map_err(host_errno)?;
        }
        Ok(())
    }
    pub fn orphan(&mut self, value: bool) {
        if let Self::Disk(d) = self {
            d.remove_on_drop = value;
        }
    }
}

pub(super) struct DiskStore {
    root: PathBuf,
    _lock: File,
}
fn regular(path: &Path) -> Result<()> {
    if !fs::symlink_metadata(path)
        .map_err(host_errno)?
        .file_type()
        .is_file()
    {
        return Err(Errno(22));
    }
    Ok(())
}
impl DiskStore {
    fn open(path: &Path) -> Result<Rc<Self>> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(path).map_err(host_errno)?;
        let root = path.canonicalize().map_err(host_errno)?;
        // Refuse an ordinary host folder accidentally selected as a private store.
        for entry in fs::read_dir(&root).map_err(host_errno)? {
            let entry = entry.map_err(host_errno)?;
            if !["objects", "manifest", "manifest.new", ".lock"]
                .iter()
                .any(|n| entry.file_name() == *n)
            {
                return Err(Errno(22));
            }
        }
        let lock_path = root.join(".lock");
        match fs::symlink_metadata(&lock_path) {
            Ok(_) => regular(&lock_path)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(host_errno(e)),
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        options.mode(0o600);
        let lock = options.open(&lock_path).map_err(host_errno)?;
        lock.try_lock().map_err(|_| Errno(16))?;
        let objects = root.join("objects");
        if !objects.try_exists().map_err(host_errno)? {
            builder.create(&objects).map_err(host_errno)?;
        }
        if !fs::symlink_metadata(&objects)
            .map_err(host_errno)?
            .file_type()
            .is_dir()
        {
            return Err(Errno(22));
        }
        Ok(Rc::new(Self { root, _lock: lock }))
    }
    fn object_path(&self, inode: u64) -> PathBuf {
        self.root.join("objects").join(format!("{inode:016x}.dat"))
    }
    pub fn create(self: &Rc<Self>, inode: u64) -> Result<FileData> {
        let path = self.object_path(inode);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        drop(options.open(&path).map_err(host_errno)?);
        Ok(FileData::Disk(DiskObject {
            length: 0,
            path,
            remove_on_drop: true,
            _store: self.clone(),
            inode,
        }))
    }
    fn load(self: &Rc<Self>, inode: u64) -> Result<FileData> {
        let path = self.object_path(inode);
        regular(&path)?;
        let length = fs::symlink_metadata(&path).map_err(host_errno)?.len();
        Ok(FileData::Disk(DiskObject {
            length,
            path,
            remove_on_drop: false,
            _store: self.clone(),
            inode,
        }))
    }
    fn commit(&self, bytes: &[u8]) -> Result<()> {
        let tmp = self.root.join("manifest.new");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&tmp).map_err(host_errno)?;
        let before_rename = (|| {
            file.write_all(bytes).map_err(host_errno)?;
            file.sync_all().map_err(host_errno)?;
            File::open(self.root.join("objects"))
                .and_then(|f| f.sync_all())
                .map_err(host_errno)?;
            fs::rename(&tmp, self.root.join("manifest")).map_err(host_errno)
        })();
        if let Err(e) = before_rename {
            let _ = fs::remove_file(tmp);
            return Err(e);
        }
        // Rename is the namespace commit point. Never roll back the in-memory tree
        // after it; a later fsync reports directory durability failures explicitly.
        let _ = self.sync_directory();
        Ok(())
    }
    fn sync_directory(&self) -> Result<()> {
        File::open(&self.root)
            .and_then(|f| f.sync_all())
            .map_err(host_errno)
    }
    fn recover(&self, live: &BTreeMap<u64, Rc<RefCell<Node>>>) -> Result<()> {
        let mut garbage = Vec::new();
        for entry in fs::read_dir(self.root.join("objects")).map_err(host_errno)? {
            let e = entry.map_err(host_errno)?;
            let name = e.file_name().into_string().map_err(|_| Errno(22))?;
            if name.len() != 20
                || !name.ends_with(".dat")
                || !name[..16]
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(Errno(22));
            }
            let ino = u64::from_str_radix(&name[..16], 16).map_err(|_| Errno(22))?;
            regular(&e.path())?;
            if !live
                .get(&ino)
                .is_some_and(|n| matches!(n.borrow().content, Content::File(_)))
            {
                garbage.push(e.path());
            }
            if garbage.len() > MAX_DISK_NODES {
                return Err(Errno(28));
            }
        }
        // Do not delete anything until the manifest and every directory entry validate.
        for path in garbage {
            fs::remove_file(path).map_err(host_errno)?;
        }
        let tmp = self.root.join("manifest.new");
        if tmp.try_exists().map_err(host_errno)? {
            regular(&tmp)?;
            fs::remove_file(tmp).map_err(host_errno)?;
        }
        Ok(())
    }
}

impl Filesystem {
    pub(super) fn checkpoint(&self) -> Result<()> {
        let Some(disk) = &self.disk else {
            return Ok(());
        };
        let mut nodes = BTreeMap::new();
        for n in self.paths.values() {
            nodes.insert(n.borrow().inode, n.clone());
        }
        let mut out = b"TRAMESFS".to_vec();
        out.extend(3u32.to_le_bytes());
        out.extend(self.limits.file_bytes.to_le_bytes());
        out.extend((self.limits.nodes as u32).to_le_bytes());
        out.extend(self.next_inode.to_le_bytes());
        out.extend((nodes.len() as u32).to_le_bytes());
        out.extend((self.paths.len() as u32).to_le_bytes());
        for (ino, node) in nodes {
            let n = node.borrow();
            out.extend(ino.to_le_bytes());
            out.extend(n.mode.to_le_bytes());
            out.extend(n.uid.to_le_bytes());
            out.extend(n.gid.to_le_bytes());
            out.extend([
                match n.content {
                    Content::Directory => 0,
                    Content::File(_) => 1,
                    Content::Null => 2,
                    Content::Terminal => 3,
                    Content::Symlink(_) => 4,
                    Content::Device(_) => return Err(Errno(95)),
                },
                0,
                0,
                0,
            ]);
            for t in n.times {
                out.extend(t.seconds.to_le_bytes());
                out.extend(t.nanos.to_le_bytes());
                out.extend([0; 4]);
            }
            if let Content::Symlink(target) = &n.content {
                out.extend((target.len() as u32).to_le_bytes());
                out.extend(target);
            } else {
                out.extend(0u32.to_le_bytes());
            }
        }
        for (path, n) in &self.paths {
            out.extend((path.len() as u32).to_le_bytes());
            out.extend(n.borrow().inode.to_le_bytes());
            out.extend(path);
        }
        out.extend(checksum(&out).to_le_bytes());
        if out.len() as u64 > MAX_MANIFEST {
            return Err(Errno(28));
        }
        disk.commit(&out)
    }
}
struct Decoder<'a> {
    data: &'a [u8],
    at: usize,
}
impl<'a> Decoder<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .filter(|&end| end <= self.data.len())
            .ok_or(Errno(22))?;
        let out = &self.data[self.at..end];
        self.at = end;
        Ok(out)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| Errno(22))?,
        ))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| Errno(22))?,
        ))
    }
}
fn decode(disk: &Rc<DiskStore>, data: &[u8]) -> Result<Filesystem> {
    if data.len() < 48 {
        return Err(Errno(22));
    }
    let (data, hash) = data.split_at(data.len() - 8);
    if checksum(data).to_le_bytes() != hash {
        return Err(Errno(22));
    }
    let mut d = Decoder { data, at: 0 };
    if d.take(8)? != b"TRAMESFS" {
        return Err(Errno(22));
    }
    let version = d.u32()?;
    if version != 3 {
        return Err(Errno(22));
    }
    let limits = StorageLimits {
        file_bytes: d.u64()?,
        nodes: d.u32()? as usize,
    };
    limits.validate()?;
    let next_inode = d.u64()?;
    let count = d.u32()? as usize;
    let path_count = d.u32()? as usize;
    if count == 0 || count > limits.nodes || path_count > limits.nodes {
        return Err(Errno(22));
    }
    let mut nodes = BTreeMap::new();
    let mut used = 0u64;
    for _ in 0..count {
        let ino = d.u64()?;
        let mode = d.u32()?;
        let (uid, gid) = (d.u32()?, d.u32()?);
        let kind = d.take(4)?;
        if ino == 0 || ino >= next_inode || nodes.contains_key(&ino) || kind[1..] != [0, 0, 0] {
            return Err(Errno(22));
        }
        let mut times = [Timestamp::default(); 3];
        for t in &mut times {
            t.seconds = d.u64()? as i64;
            t.nanos = d.u32()?;
            if t.nanos >= 1_000_000_000 || d.u32()? != 0 {
                return Err(Errno(22));
            }
        }
        let size = d.u32()? as usize;
        if size >= MAX_PATH {
            return Err(Errno(22));
        }
        let target = d.take(size)?.to_vec();
        if (kind[0] == 4) == target.is_empty() || target.contains(&0) {
            return Err(Errno(22));
        }
        let (content, type_) = match kind[0] {
            0 => (Content::Directory, 0o40000),
            1 => (Content::File(disk.load(ino)?), 0o100000),
            2 => (Content::Null, 0o20000),
            3 => (Content::Terminal, 0o20000),
            4 => (Content::Symlink(target), 0o120000),
            _ => return Err(Errno(22)),
        };
        if mode & !0o7777 != type_ {
            return Err(Errno(22));
        }
        if let Content::File(b) = &content {
            used = used
                .checked_add(b.len())
                .filter(|&v| v <= limits.file_bytes)
                .ok_or(Errno(28))?;
        }
        nodes.insert(
            ino,
            Rc::new(RefCell::new(Node {
                device: 0xfd01,
                content,
                mode,
                uid,
                gid,
                volatile: false,
                inode: ino,
                links: 0,
                times,
            })),
        );
    }
    let mut paths = BTreeMap::new();
    for _ in 0..path_count {
        let len = d.u32()? as usize;
        let ino = d.u64()?;
        if len == 0 || len >= MAX_PATH {
            return Err(Errno(22));
        }
        let path = d.take(len)?.to_vec();
        if path[0] != b'/'
            || path.contains(&0)
            || (path != b"/"
                && path[1..]
                    .split(|&b| b == b'/')
                    .any(|p| p.is_empty() || p == b"." || p == b".." || p.len() > 255))
        {
            return Err(Errno(22));
        }
        let n = nodes.get(&ino).ok_or(Errno(22))?.clone();
        n.borrow_mut().links += 1;
        if paths.insert(path, n).is_some() {
            return Err(Errno(22));
        }
    }
    if d.at != data.len()
        || !paths
            .get(b"/".as_slice())
            .is_some_and(|n| matches!(n.borrow().content, Content::Directory))
    {
        return Err(Errno(22));
    }
    for (path, n) in &paths {
        let n = n.borrow();
        if n.links == 0 || (matches!(n.content, Content::Directory) && n.links != 1) {
            return Err(Errno(22));
        }
        if path != b"/" {
            let end = path
                .iter()
                .rposition(|&b| b == b'/')
                .ok_or(Errno(22))?
                .max(1);
            if !paths
                .get(&path[..end])
                .is_some_and(|n| matches!(n.borrow().content, Content::Directory))
            {
                return Err(Errno(22));
            }
        }
    }
    if nodes.values().any(|n| n.borrow().links == 0) {
        return Err(Errno(22));
    }
    disk.recover(&nodes)?;
    Ok(Filesystem {
        flock: BTreeMap::new(),
        paths,
        inodes: nodes.values().map(Rc::downgrade).collect(),
        next_inode,
        limits,
        disk: Some(disk.clone()),
        volume: None,
    })
}
pub(super) fn checksum(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| {
        (h ^ b as u64).wrapping_mul(0x100_0000_01b3)
    })
}

impl Vfs {
    /// Native-only destructive reset of an app-owned private store. The caller
    /// must serialize reset with new opens. A live worker/orphan keeps the lock
    /// and returns EBUSY; unsupported/corrupt manifests need not be decoded.
    pub fn reset_disk(path: impl AsRef<Path>) -> Result<()> {
        let disk = DiskStore::open(path.as_ref())?;
        fs::remove_dir_all(&disk.root).map_err(host_errno)
    }
    /// Explicit application installer: replace every alias of this executable in
    /// one namespace commit. Existing open descriptions retain the previous inode.
    pub fn install_executable(&mut self, path: &[u8], mut bytes: &[u8]) -> Result<()> {
        let canonical = match self.resolve(AT_FDCWD, path) {
            Ok(p) => p,
            Err(Errno(2)) => return self.import_reader(path, &mut bytes, true).map(|_| ()),
            Err(e) => return Err(e),
        };
        let old = match self.node(&canonical) {
            Ok(n) => n,
            Err(Errno(2)) => return self.import_reader(path, &mut bytes, true).map(|_| ()),
            Err(e) => return Err(e),
        };
        if !matches!(old.borrow().content, Content::File(_)) {
            return Err(Errno(21));
        }
        let identical = if let Content::File(data) = &old.borrow().content {
            data.len() == bytes.len() as u64 && Self::executable_data(data)? == bytes
        } else {
            false
        };
        if identical {
            if old.borrow().mode != 0o100755 {
                self.chmod_at(AT_FDCWD, &canonical, 0o755)?;
            }
            return Ok(());
        }
        self.check_growth(0, bytes.len() as u64)?;
        let mut data = self.empty_data()?;
        let mut offset = 0;
        while offset < bytes.len() {
            let end = bytes.len().min(offset + MAX_TRANSFER);
            let written = data.write_at(offset as u64, &bytes[offset..end])?;
            if written == 0 {
                return Err(Errno(5));
            }
            offset += written;
        }
        data.sync(false)?;
        let mut fs = self.fs.borrow_mut();
        fs.inodes.retain(|n| n.strong_count() != 0);
        if fs.inodes.len() >= fs.limits.nodes {
            return Err(Errno(28));
        }
        let inode = data.inode().unwrap_or(fs.next_inode);
        if inode == fs.next_inode {
            fs.next_inode = fs.next_inode.checked_add(1).ok_or(Errno(28))?;
        }
        let links = old.borrow().links;
        let new = Rc::new(RefCell::new(Node {
            device: 0xfd01,
            content: Content::File(data),
            mode: 0o100755,
            uid: old.borrow().uid,
            gid: old.borrow().gid,
            volatile: false,
            inode,
            links,
            times: [Timestamp::now(); 3],
        }));
        for n in fs.paths.values_mut() {
            if Rc::ptr_eq(n, &old) {
                *n = new.clone();
            }
        }
        fs.inodes.push(Rc::downgrade(&new));
        old.borrow_mut().links = 0;
        if let Err(e) = fs.checkpoint() {
            for n in fs.paths.values_mut() {
                if Rc::ptr_eq(n, &new) {
                    *n = old.clone();
                }
            }
            fs.inodes.pop();
            old.borrow_mut().links = links;
            return Err(e);
        }
        if let Content::File(data) = &mut new.borrow_mut().content {
            data.orphan(false);
        }
        if let Content::File(data) = &mut old.borrow_mut().content {
            data.orphan(true);
        }
        Ok(())
    }
    /// Open an app-owned store. Guest path bytes never become host file names.
    pub fn open_disk(path: impl AsRef<Path>, options: DiskOptions) -> Result<Self> {
        let disk = DiskStore::open(path.as_ref())?;
        let manifest = disk.root.join("manifest");
        let mut v = Vfs::default();
        if manifest.try_exists().map_err(host_errno)? {
            regular(&manifest)?;
            let mut bytes = Vec::new();
            File::open(manifest)
                .map_err(host_errno)?
                .take(MAX_MANIFEST + 1)
                .read_to_end(&mut bytes)
                .map_err(host_errno)?;
            if bytes.len() as u64 > MAX_MANIFEST {
                return Err(Errno(22));
            }
            v.fs = Rc::new(RefCell::new(decode(&disk, &bytes)?));
        } else {
            disk.recover(&BTreeMap::new())?;
            let mut fs = v.fs.borrow_mut();
            fs.disk = Some(disk);
            fs.limits = StorageLimits::disk();
        }
        v.cwd_node = Some(v.node(b"/")?);
        if let Some(limits) = options.limits {
            v.set_storage_limits(limits)?;
        }
        if let Some(space) = options.volume_space {
            v.set_volume_space(space)?;
        }
        v.checkpoint()?;
        v.fs.borrow()
            .disk
            .as_ref()
            .expect("disk")
            .sync_directory()?;
        Ok(v)
    }
    pub fn set_storage_limits(&mut self, limits: StorageLimits) -> Result<()> {
        limits.validate()?;
        if self.allocated_bytes() > limits.file_bytes || self.capacity().nodes_used > limits.nodes {
            return Err(Errno(28));
        }
        let mut fs = self.fs.borrow_mut();
        if fs.disk.is_none()
            && (limits.file_bytes > MAX_FILE_BYTES as u64 || limits.nodes > MAX_NODES)
        {
            return Err(Errno(22));
        }
        let old = fs.limits;
        fs.limits = limits;
        if let Err(e) = fs.checkpoint() {
            fs.limits = old;
            return Err(e);
        }
        Ok(())
    }
    pub fn set_volume_space(&mut self, space: VolumeSpace) -> Result<()> {
        if space.total_bytes == 0 || space.available_bytes > space.total_bytes {
            return Err(Errno(22));
        }
        let used = self.allocated_bytes();
        if used > space.total_bytes {
            return Err(Errno(28));
        }
        self.fs.borrow_mut().volume = Some((space, used));
        Ok(())
    }
    pub fn capacity(&self) -> StorageCapacity {
        let used = self.allocated_bytes();
        let fs = self.fs.borrow();
        let mut budget = fs.limits.file_bytes;
        let mut available = budget.saturating_sub(used);
        if let Some((volume, at_used)) = fs.volume {
            budget = budget.min(volume.total_bytes);
            let host_free = if used >= at_used {
                volume.available_bytes.saturating_sub(used - at_used)
            } else {
                volume
                    .available_bytes
                    .saturating_add(at_used - used)
                    .min(volume.total_bytes)
            };
            available = budget.saturating_sub(used).min(host_free);
        }
        StorageCapacity {
            budget_bytes: budget,
            used_bytes: used,
            available_bytes: available,
            volume_total_bytes: fs.volume.map(|(v, _)| v.total_bytes),
            node_limit: fs.limits.nodes,
            nodes_used: fs
                .inodes
                .iter()
                .filter(|n| n.strong_count() != 0)
                .count()
                .max(fs.paths.len()),
            persistent: fs.disk.is_some(),
        }
    }
    pub(super) fn check_growth(&self, old: u64, new: u64) -> Result<()> {
        if new > i64::MAX as u64 {
            return Err(Errno(27));
        }
        if new.saturating_sub(old) > self.capacity().available_bytes {
            return Err(Errno(28));
        }
        Ok(())
    }
    pub(super) fn empty_data(&self) -> Result<FileData> {
        let mut fs = self.fs.borrow_mut();
        if let Some(d) = &fs.disk {
            let next = fs.next_inode.checked_add(1).ok_or(Errno(28))?;
            let data = d.create(fs.next_inode)?;
            fs.next_inode = next;
            Ok(data)
        } else {
            Ok(FileData::Memory(Vec::new()))
        }
    }
    pub fn checkpoint(&self) -> Result<()> {
        self.fs.borrow().checkpoint()
    }
    /// Flush every live file, then the namespace and its directory entry.
    pub fn sync(&self) -> Result<()> {
        let fs = self.fs.borrow();
        for node in fs.inodes.iter().filter_map(Weak::upgrade) {
            if let Content::File(data) = &node.borrow().content {
                data.sync(false)?;
            }
        }
        fs.checkpoint()?;
        if let Some(disk) = &fs.disk {
            disk.sync_directory()?;
        }
        Ok(())
    }
    pub fn sync_fd(&self, fd: u32, data_only: bool) -> Result<()> {
        let o = self.descriptor(fd)?.open.borrow();
        let n = o.node.as_ref().ok_or(Errno(22))?.borrow();
        if let Content::File(data) = &n.content {
            data.sync(data_only)?;
        } else if !matches!(n.content, Content::Directory) {
            return Err(Errno(22));
        }
        drop(n);
        drop(o);
        self.checkpoint()?;
        if let Some(disk) = &self.fs.borrow().disk {
            disk.sync_directory()?;
        }
        Ok(())
    }
    /// Copy a platform-authorized stream into private storage using bounded buffers.
    pub fn import_reader(
        &mut self,
        path: &[u8],
        reader: &mut impl Read,
        executable: bool,
    ) -> Result<u64> {
        self.import_plan(path)?;
        let mut data = self.empty_data()?;
        let mut total = 0u64;
        let mut buffer = [0; 65536];
        loop {
            let n = reader.read(&mut buffer).map_err(host_errno)?;
            if n == 0 {
                break;
            }
            let end = total.checked_add(n as u64).ok_or(Errno(27))?;
            self.check_growth(0, end)?;
            let mut at = 0;
            while at < n {
                let written = data.write_at(total + at as u64, &buffer[at..n])?;
                if written == 0 {
                    return Err(Errno(5));
                }
                at += written;
            }
            total = end;
        }
        data.sync(false)?;
        self.import_data(path, data, executable)?;
        Ok(total)
    }
    /// Export through an authorized platform writer; no guest-to-host path mapping.
    pub fn export_writer(&self, path: &[u8], writer: &mut impl Write) -> Result<u64> {
        let canonical = self.resolve(AT_FDCWD, path)?;
        let node = self.node(&canonical)?;
        let n = node.borrow();
        if !self.allowed(&n, 4) {
            return Err(Errno(13));
        }
        let Content::File(data) = &n.content else {
            return Err(Errno(21));
        };
        let mut offset = 0;
        while offset < data.len() {
            let bytes = data.read_at(offset, 65536)?;
            if bytes.is_empty() {
                return Err(Errno(5));
            }
            writer.write_all(&bytes).map_err(host_errno)?;
            offset += bytes.len() as u64;
        }
        writer.flush().map_err(host_errno)?;
        Ok(offset)
    }
    pub fn storage_stat(&self) -> [u8; 120] {
        let c = self.capacity();
        let mut out = [0; 120];
        for (offset, value) in [
            (0, 0x5452414d4553u64),
            (8, 4096),
            (16, c.budget_bytes / 4096),
            (24, c.available_bytes / 4096),
            (32, c.available_bytes / 4096),
            (40, c.node_limit as u64),
            (48, c.node_limit.saturating_sub(c.nodes_used) as u64),
            (64, 255),
            (72, 4096),
        ] {
            out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        out
    }
    pub(super) fn executable_data(data: &FileData) -> Result<Vec<u8>> {
        if data.len() > MAX_EXECUTABLE {
            return Err(Errno(27));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve(data.len() as usize)
            .map_err(|_| Errno(12))?;
        while (bytes.len() as u64) < data.len() {
            let part = data.read_at(bytes.len() as u64, MAX_TRANSFER)?;
            if part.is_empty() {
                return Err(Errno(5));
            }
            bytes.extend(part);
        }
        Ok(bytes)
    }
}
