// SPDX-License-Identifier: GPL-3.0-or-later
//! Private inode objects and an atomic, versioned namespace manifest.
use super::*;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const DEFAULT_DISK_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const DEFAULT_DISK_NODES: usize = 131_072;
pub const MAX_DISK_NODES: usize = 262_144;
pub const MAX_TRANSFER: usize = 1024 * 1024;
const MAX_MANIFEST: u64 = 128 * 1024 * 1024;
// Large Go executables (including the unmodified Docker daemon) exceed 64 MiB.
// This is an input-buffer bound; mapped guest memory retains its own quota.
const MAX_EXECUTABLE: u64 = 256 * 1024 * 1024;

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
    /// Read-through reference; overlay copy-up replaces this before mutation.
    Lower(NodeRef),
    Plain(Arc<crate::file_data::PlainFile>),
    Shared(trames_shared::SharedFile),
    Mapped(Box<mapped::MappedData>),
}
pub(super) struct DiskObject {
    pub(super) length: u64,
    pub(super) backing: Arc<DiskBacking>,
}
// Only immutable host paths/handles and an orphan flag cross the I/O boundary.
// This lease retains both the object and the store lock until the last job ends.
pub(super) struct DiskBacking {
    pub(super) path: PathBuf,
    pub(super) remove_on_drop: std::sync::atomic::AtomicBool,
    // An open-unlinked file must keep the store's exclusive lock alive.
    _store: Arc<DiskStore>,
    pub(super) inode: u64,
}
impl DiskObject {
    // Guest inode lifetime is independent of host descriptor lifetime. A store
    // with thousands of closed files must not consume thousands of iOS handles.
    // Orphans retain their private object path until the last guest reference dies.
    pub(super) fn open(&self, write: bool) -> Result<File> {
        self.backing.open(write)
    }
}
impl DiskBacking {
    pub(super) fn open(&self, write: bool) -> Result<File> {
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
impl Drop for DiskBacking {
    fn drop(&mut self) {
        if self.remove_on_drop.load(Ordering::Relaxed) {
            let _ = fs::remove_file(&self.path);
        }
    }
}
impl FileData {
    pub(super) fn memory(bytes: Vec<u8>) -> Self {
        Self::Plain(crate::file_data::PlainFile::new(
            crate::file_data::Bytes::Memory(bytes),
        ))
    }
    fn disk(data: DiskObject) -> Self {
        Self::Plain(crate::file_data::PlainFile::new(
            crate::file_data::Bytes::Disk(data),
        ))
    }
    pub(super) fn disk_backed(&self) -> bool {
        match self {
            Self::Plain(data) => data.disk_backed(),
            Self::Lower(node) => {
                matches!(&node.borrow().content, Content::File(data) if data.disk_backed())
            }
            _ => false,
        }
    }
    pub(super) fn disk_source(&self) -> Option<(Arc<DiskBacking>, u64)> {
        match self {
            Self::Plain(data) => data.disk_source(),
            Self::Lower(node) => match &node.borrow().content {
                Content::File(data) => data.disk_source(),
                _ => None,
            },
            _ => None,
        }
    }
    pub(super) fn epoch_io_safe(&self, write: bool) -> bool {
        match self {
            Self::Plain(_) => true,
            Self::Shared(_) => false,
            Self::Mapped(data) => data.epoch_io_safe(write),
            Self::Lower(node) => {
                let node = node.borrow();
                !node.volatile
                    && matches!(&node.content, Content::File(data) if data.epoch_io_safe(write))
            }
        }
    }
    pub fn blocks(&self) -> Result<u64> {
        match self {
            Self::Plain(data) => data.blocks(),
            Self::Mapped(data) => data.blocks(),
            Self::Shared(file) => Ok(file.allocated().div_ceil(512) as u64),
            Self::Lower(node) => match &node.borrow().content {
                Content::File(data) => data.blocks(),
                _ => Err(Errno(5)),
            },
        }
    }
    pub fn inode(&self) -> Option<u64> {
        match self {
            Self::Plain(data) => data.inode(),
            Self::Mapped(data) => data.inode(),
            _ => None,
        }
    }
    pub fn len(&self) -> u64 {
        match self {
            Self::Plain(data) => data.len(),
            Self::Shared(file) => file.len() as u64,
            Self::Mapped(data) => data.len(),
            Self::Lower(node) => match &node.borrow().content {
                Content::File(data) => data.len(),
                _ => 0,
            },
        }
    }
    pub(super) fn logical_size(&self) -> trames_shared::LogicalSize {
        match self {
            Self::Plain(data) => data.logical_size(),
            Self::Shared(file) => file.logical_size(),
            Self::Lower(node) => node.logical_size(),
            Self::Mapped(data) => data.logical_size(),
        }
    }
    pub(super) fn shared_file(&self) -> Option<trames_shared::SharedFile> {
        match self {
            Self::Shared(file) => Some(file.clone()),
            Self::Mapped(data) => data.shared_file(),
            _ => None,
        }
    }
    pub(super) fn growth_charge(&self, length: u64) -> u64 {
        if self.shared_file().is_some() {
            0
        } else {
            length.saturating_sub(self.len())
        }
    }
    pub fn read_at(&self, offset: u64, count: usize) -> Result<Vec<u8>> {
        match self {
            Self::Plain(data) => data.read_at(offset, count, None),
            Self::Mapped(data) => data.read_at(offset, count),
            Self::Lower(node) => match &node.borrow().content {
                Content::File(data) => data.read_at(offset, count),
                _ => Err(Errno(5)),
            },
            Self::Shared(file) => {
                let count = count
                    .min(MAX_TRANSFER)
                    .min(self.len().saturating_sub(offset) as usize);
                if count == 0 {
                    Ok(Vec::new())
                } else {
                    file.read_at(offset, count).map_err(host_errno)
                }
            }
        }
    }
    pub fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<usize> {
        match self {
            Self::Plain(data) => data.write_at(offset, bytes),
            Self::Mapped(data) => data.write_at(offset, bytes),
            Self::Lower(_) => Err(Errno(30)),
            Self::Shared(file) => file.write_at(offset, bytes).map_err(host_errno),
        }
    }
    pub fn truncate(&mut self, length: u64) -> Result<()> {
        match self {
            Self::Plain(data) => data.truncate(length),
            Self::Mapped(data) => data.truncate(length),
            Self::Lower(_) => Err(Errno(30)),
            Self::Shared(file) => file
                .set_len(usize::try_from(length).map_err(|_| Errno(27))?)
                .map_err(host_errno),
        }
    }
    pub fn sync(&self, data_only: bool) -> Result<()> {
        match self {
            Self::Plain(data) => data.sync(data_only),
            Self::Mapped(data) => data.sync(data_only),
            _ => Ok(()),
        }
    }
    pub fn orphan(&mut self, value: bool) {
        match self {
            Self::Plain(data) => data.orphan(value),
            Self::Mapped(data) => data.orphan(value),
            _ => {}
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
    fn open(path: &Path, owner_lock: Option<&Path>) -> Result<Arc<Self>> {
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
        let lock_path = owner_lock
            .map(Path::to_path_buf)
            .unwrap_or_else(|| root.join(".lock"));
        if !lock_path.is_absolute() {
            return Err(Errno(22));
        }
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
        Ok(Arc::new(Self { root, _lock: lock }))
    }
    fn object_path(&self, inode: u64) -> PathBuf {
        self.root.join("objects").join(format!("{inode:016x}.dat"))
    }
    pub fn create(self: &Arc<Self>, inode: u64) -> Result<FileData> {
        let path = self.object_path(inode);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        drop(options.open(&path).map_err(host_errno)?);
        Ok(FileData::disk(DiskObject {
            length: 0,
            backing: Arc::new(DiskBacking {
                path,
                remove_on_drop: std::sync::atomic::AtomicBool::new(true),
                _store: self.clone(),
                inode,
            }),
        }))
    }
    fn load(self: &Arc<Self>, inode: u64) -> Result<FileData> {
        let path = self.object_path(inode);
        regular(&path)?;
        let length = fs::symlink_metadata(&path).map_err(host_errno)?.len();
        Ok(FileData::disk(DiskObject {
            length,
            backing: Arc::new(DiskBacking {
                path,
                remove_on_drop: std::sync::atomic::AtomicBool::new(false),
                _store: self.clone(),
                inode,
            }),
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
    fn recover(&self, live: &BTreeMap<u64, NodeRef>) -> Result<()> {
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
    pub(super) fn checkpoint(&self, overlay: Option<&overlay::Overlay>) -> Result<()> {
        if let Some(overlay) = overlay {
            return overlay.checkpoint(self);
        }
        let Some(disk) = &self.disk else {
            return Ok(());
        };
        let mut nodes = BTreeMap::new();
        for n in self.paths.values() {
            nodes.insert(n.borrow().inode, n.clone());
        }
        let mut out = b"TRAMESFS".to_vec();
        out.extend(4u32.to_le_bytes());
        out.extend(self.limits.file_bytes.to_le_bytes());
        out.extend((self.limits.nodes as u32).to_le_bytes());
        out.extend(self.next_inode.to_le_bytes());
        out.extend((nodes.len() as u32).to_le_bytes());
        out.extend((self.paths.len() as u32).to_le_bytes());
        for (ino, node) in nodes {
            let n = node.borrow();
            out.extend(ino.to_le_bytes());
            let metadata = n.file_metadata();
            out.extend(metadata.mode.to_le_bytes());
            out.extend(n.uid.to_le_bytes());
            out.extend(n.gid.to_le_bytes());
            out.extend([
                match n.content {
                    Content::Directory => 0,
                    Content::File(_) => 1,
                    Content::Null => 2,
                    Content::Terminal => 3,
                    Content::Symlink(_) => 4,
                    Content::Fifo(_) => 5,
                    Content::Socket(_) => 8,
                    Content::Device(_) => {
                        if n.mode & 0o170000 == 0o60000 {
                            7
                        } else {
                            6
                        }
                    }
                },
                0,
                0,
                0,
            ]);
            for t in metadata.times {
                out.extend(t.seconds.to_le_bytes());
                out.extend(t.nanos.to_le_bytes());
                out.extend([0; 4]);
            }
            if let Content::Symlink(target) = &n.content {
                out.extend((target.len() as u32).to_le_bytes());
                out.extend(target);
            } else if let Content::Device(device) = n.content {
                // Tags 6/7 extend v3 with a fixed-width guest device number;
                // no host path or live driver state is persisted.
                out.extend(4u32.to_le_bytes());
                out.extend((device.rdev() as u32).to_le_bytes());
            } else {
                out.extend(0u32.to_le_bytes());
            }
        }
        // Version 4 adds an inode-keyed attribute table after the v3 nodes.
        let mut attrs = BTreeMap::new();
        for n in self.paths.values() {
            let n = n.borrow();
            if !n.xattrs.is_empty() {
                attrs.insert(n.inode, n.xattrs.clone());
            }
        }
        out.extend((attrs.len() as u32).to_le_bytes());
        for (ino, entries) in attrs {
            out.extend(ino.to_le_bytes());
            out.extend((entries.len() as u32).to_le_bytes());
            for (name, value) in entries {
                out.extend((name.len() as u32).to_le_bytes());
                out.extend((value.len() as u32).to_le_bytes());
                out.extend(name);
                out.extend(value);
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
fn decode(disk: &Arc<DiskStore>, data: &[u8]) -> Result<Filesystem> {
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
    if !matches!(version, 3 | 4) {
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
        match kind[0] {
            4 if target.is_empty() || target.contains(&0) => return Err(Errno(22)),
            6 | 7 if target.len() != 4 => return Err(Errno(22)),
            4 | 6 | 7 => {}
            _ if !target.is_empty() => return Err(Errno(22)),
            _ => {}
        }
        let (content, type_) = match kind[0] {
            0 => (Content::Directory, 0o40000),
            1 => (Content::File(disk.load(ino)?), 0o100000),
            2 => (Content::Null, 0o20000),
            3 => (Content::Terminal, 0o20000),
            4 => (Content::Symlink(target), 0o120000),
            5 => (Content::Fifo(Pipe::new(ino)), 0o10000),
            8 => (Content::Socket(ipc::PathBinding::default()), 0o140000),
            6 | 7 => (
                pseudo::Device::node(
                    u32::from_le_bytes(target.try_into().map_err(|_| Errno(22))?),
                    kind[0] == 7,
                ),
                if kind[0] == 7 { 0o60000 } else { 0o20000 },
            ),
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
            Arc::new(Inode::new(Node {
                identity: 0,
                record_locks: std::sync::OnceLock::new(),
                whole_locks: std::sync::OnceLock::new(),
                notifications: inotify::Marks::default(),
                path_hint: SharedCell::default(),
                device: 0xfd01,
                content,
                mode,
                uid,
                gid,
                volatile: false,
                inode: ino,
                links: 0,
                times,
                xattrs: BTreeMap::new(),
                seals: None,
            })),
        );
    }
    if version == 4 {
        let count = d.u32()? as usize;
        if count > nodes.len() {
            return Err(Errno(22));
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut total = 0;
        for _ in 0..count {
            let ino = d.u64()?;
            if !seen.insert(ino) {
                return Err(Errno(22));
            }
            let node = nodes.get(&ino).ok_or(Errno(22))?;
            let mut n = node.borrow_mut();
            if !matches!(n.content, Content::File(_) | Content::Directory) {
                return Err(Errno(22));
            }
            let entries = d.u32()?;
            if entries == 0 || entries > 128 {
                return Err(Errno(22));
            }
            for _ in 0..entries {
                let len = d.u32()? as usize;
                let size = d.u32()? as usize;
                if len > 255 || size > 65536 {
                    return Err(Errno(22));
                }
                let name = d.take(len)?.to_vec();
                let value = d.take(size)?.to_vec();
                if !(name.starts_with(b"user.") || super::xattr::overlay_attribute(&name))
                    || name.len() <= 5
                    || name.contains(&0)
                    || n.xattrs.insert(name, value).is_some()
                {
                    return Err(Errno(22));
                }
            }
            let size = super::xattr::xattr_size(&n.xattrs);
            total += size;
            if size > 65536 || total > super::xattr::XATTR_BUDGET {
                return Err(Errno(22));
            }
        }
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
    for (path, node) in &paths {
        if path == b"/" {
            continue;
        }
        let at = path
            .iter()
            .rposition(|&b| b == b'/')
            .expect("absolute path");
        if let Some(parent) = paths.get(&path[..at.max(1)]) {
            inotify::link(node, parent, &path[at + 1..]);
        }
    }
    Ok(Filesystem {
        shared_budget: trames_shared::SharedBudget::new(memfd::MEMFD_BYTES as usize),
        paths,
        inodes: nodes.values().map(Arc::downgrade).collect(),
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
        Self::reset_disk_locked(path.as_ref(), None)
    }
    /// The native adapter must use the same owner lock for every open/reset.
    /// iOS keeps it in the containing app's private container, outside the shared
    /// data container whose file locks cannot survive application suspension.
    pub fn reset_disk_with_owner_lock(path: impl AsRef<Path>, owner_lock: &Path) -> Result<()> {
        Self::reset_disk_locked(path.as_ref(), Some(owner_lock))
    }
    fn reset_disk_locked(path: &Path, owner_lock: Option<&Path>) -> Result<()> {
        let disk = DiskStore::open(path, owner_lock)?;
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
        fs.admit_inode()?;
        let inode = data.inode().unwrap_or(fs.next_inode);
        if inode == fs.next_inode {
            fs.next_inode = fs.next_inode.checked_add(1).ok_or(Errno(28))?;
        }
        let links = old.borrow().links;
        let new = Arc::new(Inode::new(Node {
            identity: 0,
            record_locks: std::sync::OnceLock::new(),
            whole_locks: std::sync::OnceLock::new(),
            notifications: inotify::Marks::default(),
            path_hint: SharedCell::default(),
            device: 0xfd01,
            content: Content::File(data),
            mode: 0o100755,
            uid: old.borrow().uid,
            gid: old.borrow().gid,
            volatile: false,
            inode,
            links,
            times: [Timestamp::now(); 3],
            xattrs: BTreeMap::new(),
            seals: None,
        }));
        for n in fs.paths.values_mut() {
            if Arc::ptr_eq(n, &old) {
                *n = new.clone();
            }
        }
        fs.inodes.push(Arc::downgrade(&new));
        old.borrow_mut().links = 0;
        if let Err(e) = fs.checkpoint() {
            for n in fs.paths.values_mut() {
                if Arc::ptr_eq(n, &new) {
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
        Self::open_disk_locked(path.as_ref(), options, None)
    }
    /// Native single-writer embedding with an app-private owner lock. All opens
    /// and resets of this store must supply the same lock path. Read-only file
    /// providers must read the manifest/objects without opening another VFS.
    pub fn open_disk_with_owner_lock(
        path: impl AsRef<Path>,
        options: DiskOptions,
        owner_lock: &Path,
    ) -> Result<Self> {
        Self::open_disk_locked(path.as_ref(), options, Some(owner_lock))
    }
    fn open_disk_locked(
        path: &Path,
        options: DiskOptions,
        owner_lock: Option<&Path>,
    ) -> Result<Self> {
        let disk = DiskStore::open(path, owner_lock)?;
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
            v.fs = FsHandle::new(decode(&disk, &bytes)?);
        } else {
            disk.recover(&BTreeMap::new())?;
            let mut fs = v.fs.borrow_mut();
            fs.disk = Some(disk);
            fs.limits = StorageLimits::disk();
        }
        v.context.paths.borrow_mut().cwd_node = Some(v.node(b"/")?);
        v.initialize_mounts()?;
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
        Self::filesystem_capacity(&self.fs.borrow())
    }
    pub(super) fn filesystem_capacity(
        fs: &FsBorrow<'_, impl std::ops::Deref<Target = Filesystem>>,
    ) -> StorageCapacity {
        if let Some(overlay) = &fs.overlay {
            return overlay.capacity();
        }
        let used = fs
            .inodes
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .map(|n| {
                let node = n.borrow();
                match &node.content {
                    Content::File(b) if node.seals.is_none() => b.len(),
                    _ => 0,
                }
            })
            .sum::<u64>();
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
        Self::filesystem_empty_data(&mut self.fs.borrow_mut())
    }
    pub(super) fn filesystem_empty_data(
        fs: &mut FsBorrow<'_, impl std::ops::DerefMut<Target = Filesystem>>,
    ) -> Result<FileData> {
        if let Some(overlay) = &fs.overlay {
            return overlay.empty_data();
        }
        if let Some(d) = &fs.disk {
            let next = fs.next_inode.checked_add(1).ok_or(Errno(28))?;
            let data = d.create(fs.next_inode)?;
            fs.next_inode = next;
            Ok(data)
        } else {
            Ok(FileData::memory(Vec::new()))
        }
    }
    pub fn checkpoint(&self) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for mount in self
            .mount_resources
            .borrow()
            .iter()
            .filter_map(std::sync::Weak::upgrade)
        {
            if seen.insert(mount.fs.identity()) && mount.fs.borrow().overlay.is_some() {
                mount.fs.borrow().checkpoint()?;
            }
        }
        self.fs.borrow().checkpoint()
    }
    /// Flush every live file, then the namespace and its directory entry.
    pub fn sync(&self) -> Result<()> {
        let fs = self.fs.borrow();
        for node in fs.inodes.iter().filter_map(std::sync::Weak::upgrade) {
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
        let o_descriptor = self.descriptor(fd)?;
        let o = o_descriptor.open.borrow();
        let n = o.node.as_ref().ok_or(Errno(22))?.borrow();
        if let Content::File(data) = &n.content {
            data.sync(data_only)?;
        } else if !matches!(n.content, Content::Directory) {
            return Err(Errno(22));
        }
        let linked = n.links != 0;
        let filesystem = o.mount.as_ref().map_or(&self.fs, |mount| &mount.fs).clone();
        drop(n);
        drop(o);
        if linked {
            // fsync observes this inode's filesystem, including a retained
            // detached mount. Anonymous/unlinked files have no namespace entry
            // to commit; their data sync above is still required.
            let fs = filesystem.borrow();
            fs.checkpoint()?;
            if let Some(disk) = &fs.disk {
                disk.sync_directory()?;
            }
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
    /// Explicit host import replacement. Stage a complete inode before one
    /// namespace rename; cancellation/short reads never truncate the old file.
    pub fn import_reader_replace(&mut self, path: &[u8], reader: &mut impl Read) -> Result<u64> {
        match self.import_plan(path) {
            Ok(_) => return self.import_reader(path, reader, false),
            Err(Errno(17)) => {}
            Err(error) => return Err(error),
        }
        let old = self.node(path)?;
        if !matches!(old.borrow().content, Content::File(_)) {
            return Err(Errno(21));
        }
        let parent = &path[..path.iter().rposition(|b| *b == b'/').ok_or(Errno(22))?];
        let mut temporary = parent.to_vec();
        for attempt in 0..32 {
            temporary.truncate(parent.len());
            temporary.extend(
                format!(
                    "/.trames-import-{:x}-{attempt}",
                    self.fs.borrow().next_inode
                )
                .as_bytes(),
            );
            if self.node(&temporary).is_err() {
                break;
            }
            if attempt == 31 {
                return Err(Errno(17));
            }
        }
        let count = self.import_reader(&temporary, reader, false)?;
        let result = (|| {
            let staged = self.node(&temporary)?;
            {
                let mut staged = staged.borrow_mut();
                let old = old.borrow();
                staged.mode = old.mode;
                staged.uid = old.uid;
                staged.gid = old.gid;
                staged.xattrs = old.xattrs.clone();
            }
            self.rename_at(AT_FDCWD, &temporary, AT_FDCWD, path, 0)
        })();
        if result.is_err() {
            let _ = self.unlink_at(AT_FDCWD, &temporary, false);
        }
        result.map(|_| count)
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
