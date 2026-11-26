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
mod io_write;
pub(super) mod projection_caps;
#[cfg(test)]
mod resource_tests;

pub const DEFAULT_DISK_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const DEFAULT_DISK_NODES: usize = 131_072;
pub const MAX_DISK_NODES: usize = 262_144;
pub const MAX_TRANSFER: usize = 1024 * 1024;
const MAX_MANIFEST: u64 = 128 * 1024 * 1024;
// Large Go executables (including the unmodified Docker daemon) exceed 64 MiB.
// This is an input-buffer bound; mapped guest memory retains its own quota.
pub(super) const MAX_EXECUTABLE: u64 = 256 * 1024 * 1024;

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
    if let Some(error) = crate::resource_io::host_error(&e) {
        return error;
    }
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
    /// A projected overlay inode retains the original layer provider.
    Layer(Arc<overlay::LayerFile>),
    Plain(Arc<crate::file_data::PlainFile>),
    Shared(trames_shared::SharedFile),
    Mapped(Box<mapped::MappedData>),
}
mod version;
pub(super) use version::{DataVersion, Validation};
pub(super) struct DiskObject {
    pub(super) capabilities: Option<file_caps::FileCaps>,
    pub(super) length: u64,
    pub(super) backing: Arc<DiskBacking>,
}
// Backing identity, weak handles and its scalar charge cross the I/O boundary.
// This lease retains both the object and the store lock until the last job ends.
pub(super) struct DiskBacking {
    pub(super) path: PathBuf,
    pub(super) remove_on_drop: std::sync::atomic::AtomicBool,
    // An open-unlinked file must keep the store's exclusive lock alive.
    pub(super) _store: Option<Arc<DiskStore>>,
    #[cfg(all(feature = "hostfs", unix))]
    pub(super) host: Option<Arc<hostfs::HostFile>>,
    pub(super) inode: u64,
    // Open descriptions own strong leases; closed cached inodes own no FDs.
    pub(super) files: std::sync::Mutex<[std::sync::Weak<File>; 2]>,
    pub(super) charge: std::sync::OnceLock<Arc<file_accounting::FileCharge>>,
    pub(super) preallocated_on_load: u64,
}
pub(super) fn reserve_backing_range(file: &File, offset: u64, end: u64) -> Result<()> {
    #[cfg(target_os = "linux")]
    let result = {
        use std::os::fd::AsRawFd;
        // SAFETY: A retained writable FD and a validated, nonnegative range.
        unsafe { libc::fallocate(file.as_raw_fd(), 1, offset as i64, (end - offset) as i64) }
    };
    #[cfg(target_vendor = "apple")]
    let result = {
        use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
        let _ = offset;
        let allocated = file
            .metadata()
            .map_err(host_errno)?
            .blocks()
            .saturating_mul(512);
        if allocated >= end {
            return Ok(());
        }
        let mut request = libc::fstore_t {
            fst_flags: libc::F_ALLOCATEALL | libc::F_ALLOCATEPERSIST,
            fst_posmode: libc::F_PEOFPOSMODE,
            fst_offset: 0,
            fst_length: (end - allocated) as i64,
            fst_bytesalloc: 0,
        };
        // SAFETY: F_PREALLOCATE takes a mutable fstore_t on this retained FD.
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PREALLOCATE, &mut request) }
    };
    #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
    let result = {
        let _ = (file, offset, end);
        return Err(Errno(95));
    };
    if result < 0 {
        return Err(host_errno(io::Error::last_os_error()));
    }
    Ok(())
}
impl DiskObject {
    // Held under the existing byte lock. Sync revocation before admitting a
    // mutation so reopening a store after a crash cannot restore an old grant.
    pub(super) fn revoke_caps(&mut self) -> Result<()> {
        if self.capabilities.is_none() {
            return Ok(());
        }
        let path = self.backing.path.with_extension("cap");
        match fs::remove_file(&path) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(host_errno(e)),
        }
        File::open(path.parent().unwrap())
            .and_then(|f| f.sync_all())
            .map_err(host_errno)?;
        self.capabilities = None;
        Ok(())
    }
    pub(super) fn set_caps(&mut self, caps: file_caps::FileCaps) -> Result<()> {
        let bytes = caps.encode(&UserNamespace::default())?;
        // Admission precedes the temporary file and the durability barrier.
        // A suspended metadata request can retry without repeating either.
        let permit = cgroup::admit_io(bytes.len() as u64, true).map_err(host_errno)?;
        let path = self.backing.path.with_extension("cap");
        let temp = path.with_extension("new");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temp).map_err(host_errno)?;
        let commit = (|| -> io::Result<()> {
            self.backing
                .file(false)
                .map_err(|e| io::Error::from_raw_os_error(e.0 as i32))?
                .sync_all()?;
            io_write::write_all(&mut file, &bytes, permit)?;
            file.sync_all()?;
            fs::rename(&temp, &path)
        })();
        if let Err(error) = commit {
            let _ = fs::remove_file(&temp);
            return Err(host_errno(error));
        }
        self.capabilities = Some(caps);
        File::open(path.parent().unwrap())
            .and_then(|f| f.sync_all())
            .map_err(host_errno)
    }

    // Guest inode lifetime is independent of host descriptor lifetime. A store
    // with thousands of closed files must not consume thousands of iOS handles.
    // Orphans retain their private object path until the last guest reference dies.
    pub(super) fn open(&self, write: bool) -> Result<Arc<File>> {
        self.backing.file(write)
    }
}
impl DiskBacking {
    pub(super) fn cached_file(&self) -> Option<Arc<File>> {
        let files = self.files.lock().unwrap();
        files[1].upgrade().or_else(|| files[0].upgrade())
    }
    pub(super) fn private_lease(&self, write: bool) -> Result<Option<Arc<File>>> {
        if self._store.is_none() {
            return Ok(None);
        }
        self.file(write).map(Some)
    }
    pub(super) fn file(&self, write: bool) -> Result<Arc<File>> {
        if self._store.is_none() {
            return self.open(write).map(Arc::new);
        }
        let mut files = self.files.lock().unwrap();
        if let Some(file) = files[1]
            .upgrade()
            .or_else(|| (!write).then(|| files[0].upgrade()).flatten())
        {
            return Ok(file);
        }
        let file = Arc::new(self.open(write)?);
        files[usize::from(write)] = Arc::downgrade(&file);
        Ok(file)
    }
    // Called under PlainFile's existing byte ownership. Only length changes
    // update this store-local scalar; ordinary reads and overwrites do not.
    pub(super) fn register_size(&self, length: u64) {
        if let Some(store) = &self._store {
            self.charge.get_or_init(|| {
                let charge = file_accounting::FileCharge::register(
                    store.used.clone(),
                    length.max(self.preallocated_on_load),
                );
                charge.set_preallocated(self.preallocated_on_load);
                charge
            });
        }
    }
    pub(super) fn update_size(&self, length: u64) {
        if let Some(charge) = self.charge.get() {
            charge.publish(length);
        }
    }

    pub(super) fn open(&self, write: bool) -> Result<File> {
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = &self.host {
            return host.file(write)?.file.try_clone().map_err(host_errno);
        }
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
        #[cfg(all(feature = "hostfs", unix))]
        if self.host.is_some() {
            return;
        }
        if self.remove_on_drop.load(Ordering::Relaxed) && fs::remove_file(&self.path).is_ok() {
            if let Some(store) = &self._store {
                store.objects_generation.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}
impl FileData {
    pub(super) fn lower_links(&self) -> Option<u32> {
        match self {
            Self::Layer(file) if !file.upper => Some(file.node.borrow().links),
            Self::Lower(node) => Some(node.borrow().links),
            Self::Mapped(data) => data.lower_links(),
            _ => None,
        }
    }
    pub(super) fn source_node(&self) -> Option<NodeRef> {
        match self {
            Self::Layer(file) => Some(file.node.clone()),
            Self::Lower(node) => Some(node.clone()),
            Self::Mapped(data) => data.source_node(),
            _ => None,
        }
    }
    pub(super) fn layer_mount(&self) -> Option<Arc<mounts::MountIdentity>> {
        match self {
            Self::Layer(file) => Some(file.mount.clone()),
            Self::Mapped(data) => data.layer_mount(),
            _ => None,
        }
    }
    pub(super) fn mapped_work(&self) -> bool {
        matches!(self, Self::Mapped(data) if data.has_live_pages())
    }
    pub(super) fn layout_change(&self, length: u64) -> bool {
        length != self.len() && self.mapped_work()
    }
    pub(super) fn metadata(&self) -> Option<file_data::FileMeta> {
        match self {
            Self::Plain(data) => data.metadata(),
            Self::Mapped(data) => data.metadata(),
            Self::Layer(file) if file.upper => Some(file.node.borrow().file_metadata()),
            _ => None,
        }
    }
    pub(super) fn activate_metadata(&self, mode: u32, times: [Timestamp; 3]) {
        match self {
            Self::Plain(data) => data.activate(mode, times),
            Self::Mapped(data) => data.activate_metadata(mode, times),
            _ => (),
        }
    }
    pub(super) fn patch_metadata(&self, before: file_data::FileMeta, after: file_data::FileMeta) {
        match self {
            Self::Plain(data) => data.patch_metadata(before, after),
            Self::Mapped(data) => data.patch_metadata(before, after),
            Self::Layer(file) if file.upper => {
                let mut n = file.node.borrow_mut();
                if before.mode != after.mode {
                    n.mode = after.mode;
                }
                for i in 0..3 {
                    if before.times[i] != after.times[i] {
                        n.times[i] = after.times[i];
                    }
                }
            }
            _ => (),
        }
    }
    pub(super) fn register_storage(&self) {
        match self {
            Self::Plain(data) => data.register_storage(),
            Self::Mapped(data) => data.register_storage(),
            // Lower data is already charged to its source store; copy-up
            // registers its new private object when the inode changes source.
            _ => (),
        }
    }
    pub(super) fn bind_quota(&self, quota: &Arc<file_accounting::FileQuota>) -> Result<()> {
        match self {
            Self::Plain(data) => data.bind_quota(quota),
            Self::Mapped(data) => data.bind_quota(quota),
            _ => Ok(()), // SharedFile has its original reservation account; Lower retains its own provider.
        }
    }
    pub(super) fn private_lease(&self, write: bool) -> Result<Option<Arc<File>>> {
        match self {
            Self::Plain(data) => data.private_lease(write),
            Self::Mapped(data) => data.private_lease(write),
            Self::Layer(file) => file.read(|data| data.private_lease(write)),
            Self::Lower(node) => match &node.borrow().content {
                Content::File(data) => data.private_lease(write),
                _ => Err(Errno(22)),
            },
            Self::Shared(_) => Ok(None),
        }
    }
    #[cfg(all(feature = "hostfs", unix))]
    pub(super) fn append_host(&self, bytes: &[u8]) -> Option<Result<(usize, u64)>> {
        match self {
            Self::Plain(data) => data.append_host(bytes),
            Self::Layer(file) => file.read(|data| Ok(data.append_host(bytes))).ok().flatten(),
            _ => None,
        }
    }
    pub(super) fn memory(bytes: Vec<u8>) -> Self {
        Self::Plain(crate::file_data::PlainFile::new(
            crate::file_data::Bytes::Memory(bytes),
        ))
    }
    pub(super) fn disk(data: DiskObject) -> Self {
        Self::Plain(crate::file_data::PlainFile::new(
            crate::file_data::Bytes::Disk(data),
        ))
    }
    pub(super) fn disk_backed(&self) -> bool {
        match self {
            Self::Plain(data) => data.disk_backed(),
            Self::Layer(file) => file.read(|data| Ok(data.disk_backed())).unwrap_or(false),
            Self::Lower(node) => {
                matches!(&node.borrow().content, Content::File(data) if data.disk_backed())
            }
            _ => false,
        }
    }
    pub(super) fn disk_source(&self) -> Option<(Arc<DiskBacking>, u64)> {
        match self {
            Self::Plain(data) => data.disk_source(),
            Self::Layer(file) => file.read(|data| Ok(data.disk_source())).ok().flatten(),
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
            Self::Layer(file) => file
                .read(|data| Ok(data.epoch_io_safe(write)))
                .unwrap_or(false),
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
            Self::Layer(file) => file.read(FileData::blocks),
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
            Self::Layer(file) => file.read(|data| Ok(data.inode())).ok().flatten(),
            _ => None,
        }
    }
    pub fn len(&self) -> u64 {
        match self {
            Self::Plain(data) => data.len(),
            Self::Shared(file) => file.len() as u64,
            Self::Mapped(data) => data.len(),
            Self::Layer(file) => file.node.logical_size().load(Ordering::Relaxed),
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
            Self::Layer(file) => file.node.logical_size(),
            Self::Mapped(data) => data.logical_size(),
        }
    }
    pub(super) fn shared_file(&self) -> Option<trames_shared::SharedFile> {
        match self {
            Self::Shared(file) => Some(file.clone()),
            Self::Mapped(data) => data.shared_file(),
            Self::Layer(file) => file.read(|data| Ok(data.shared_file())).ok().flatten(),
            _ => None,
        }
    }
    pub(super) fn tmpfs_file(&self) -> Option<Arc<file_data::PlainFile>> {
        match self {
            Self::Plain(file) if file.tmpfs => Some(file.clone()),
            Self::Mapped(data) => data.tmpfs_file(),
            Self::Layer(file) => file.read(|data| Ok(data.tmpfs_file())).ok().flatten(),
            Self::Lower(node) => match &node.borrow().content {
                Content::File(data) => data.tmpfs_file(),
                _ => None,
            },
            _ => None,
        }
    }
    pub(super) fn reserve_keep_size(&self, offset: u64, end: u64) -> Result<()> {
        match self {
            Self::Plain(file) => file.reserve_keep_size(offset, end),
            Self::Layer(file) => file.read(|data| data.reserve_keep_size(offset, end)),
            Self::Mapped(data) => data
                .plain_file()
                .ok_or(Errno(95))?
                .reserve_keep_size(offset, end),
            _ => Err(Errno(95)),
        }
    }
    pub(super) fn growth_charge(&self, length: u64) -> u64 {
        if self.shared_file().is_some() || self.tmpfs_file().is_some() {
            0
        } else {
            length.saturating_sub(self.len())
        }
    }
    pub fn read_at(&self, offset: u64, count: usize) -> Result<Vec<u8>> {
        match self {
            Self::Plain(data) => data.read_at(offset, count, None),
            Self::Mapped(data) => data.read_at(offset, count),
            Self::Layer(file) => file.read(|data| data.read_at(offset, count)),
            Self::Lower(node) => match &node.borrow().content {
                Content::File(data) => data.read_at(offset, count),
                _ => Err(Errno(5)),
            },
            Self::Shared(file) => {
                let count = count.min(self.len().saturating_sub(offset) as usize);
                if count == 0 {
                    Ok(Vec::new())
                } else {
                    file.read_at(offset, count).map_err(host_errno)
                }
            }
        }
    }
    /// An owned request keeps every appended prefix even if a later page waits.
    /// Legacy errno-only readers still use read_at and do not silently acquire
    /// a continuation they cannot retain.
    pub(super) fn read_into(&self, offset: u64, count: usize, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Plain(data) => data.read_into(offset, count, out),
            Self::Mapped(data) => data.read_into(offset, count, out),
            Self::Layer(file) => file.read(|data| data.read_into(offset, count, out)),
            Self::Lower(node) => match &node.borrow().content {
                Content::File(data) => data.read_into(offset, count, out),
                _ => Err(Errno(5)),
            },
            Self::Shared(file) => {
                let count = count.min(self.len().saturating_sub(offset) as usize);
                if count != 0 {
                    let bytes = file.read_at(offset, count).map_err(host_errno)?;
                    if out.is_empty() {
                        *out = bytes;
                    } else {
                        out.extend(bytes);
                    }
                }
                Ok(())
            }
        }
    }
    pub(super) fn write_transfer(
        &mut self,
        offset: u64,
        bytes: &[u8],
        append: bool,
        limit: u64,
        signal: impl FnOnce(),
    ) -> Result<(usize, u64)> {
        if let Self::Plain(data) = self {
            return data.write_limited(offset, bytes, append, limit, signal);
        }
        if let Self::Layer(file) = self {
            return file.write(|data| data.write_transfer(offset, bytes, append, limit, signal));
        }
        let position = if append { self.len() } else { offset };
        #[cfg(all(feature = "hostfs", unix))]
        if append {
            if let Some(result) = self.append_host(bytes) {
                return result;
            }
        }
        self.write_at(position, bytes)
            .map(|n| (n, position + n as u64))
    }
    pub fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<usize> {
        match self {
            Self::Plain(data) => data.write_at(offset, bytes),
            Self::Mapped(data) => data.write_at(offset, bytes),
            Self::Layer(file) => file.write(|data| data.write_at(offset, bytes)),
            Self::Lower(_) => Err(Errno(30)),
            Self::Shared(file) => crate::resource_io::write_result(file.write_at(offset, bytes)),
        }
    }
    pub(super) fn begin_transaction(
        &mut self,
    ) -> Result<
        std::result::Result<
            Option<trames_shared::FileTransactionLease>,
            Arc<dyn trames_shared::ResourceWait>,
        >,
    > {
        match self {
            Self::Plain(data) => Ok(data.begin_transaction()),
            Self::Shared(file) => Ok(file.begin_transaction()),
            Self::Mapped(data) => data.begin_transaction(),
            Self::Layer(file) => file.write(|data| data.begin_transaction()),
            Self::Lower(_) => Ok(Ok(None)),
        }
    }
    pub fn truncate(&mut self, length: u64) -> Result<()> {
        match self {
            Self::Plain(data) => data.truncate(length),
            Self::Mapped(data) => data.truncate(length),
            Self::Layer(file) => file.write(|data| data.truncate(length)),
            Self::Lower(_) => Err(Errno(30)),
            Self::Shared(file) => file
                .set_len(usize::try_from(length).map_err(|_| Errno(27))?)
                .map_err(host_errno),
        }
    }
    /// The accepted resize already completed its original mapped writeback.
    /// Re-entering a nested provider must not start a second sync wave.
    pub(super) fn truncate_after_sync(&mut self, length: u64) -> Result<()> {
        match self {
            Self::Mapped(data) => data.truncate_after_sync(length),
            Self::Layer(file) => file.write(|data| data.truncate_after_sync(length)),
            _ => self.truncate(length),
        }
    }
    pub(super) fn has_allocated_after(&self, length: u64) -> bool {
        match self {
            Self::Shared(file) => shared_account::has_allocated_after(file, length),
            Self::Plain(data) => data.has_allocated_after(length),
            Self::Mapped(data) => data.has_allocated_after(length),
            Self::Layer(file) => file
                .read(|data| Ok(data.has_allocated_after(length)))
                .unwrap_or(true),
            _ => false,
        }
    }
    pub fn sync(&self, data_only: bool) -> Result<()> {
        match self {
            Self::Plain(data) => data.sync(data_only),
            Self::Mapped(data) => data.sync(data_only),
            Self::Layer(file) => file.read(|data| data.sync(data_only)),
            Self::Lower(node) => match &node.borrow().content {
                Content::File(data) => data.sync(data_only),
                _ => Err(Errno(5)),
            },
            _ => Ok(()),
        }
    }
    pub(super) fn sync_range(&self, offset: u64, length: u64, flags: u32) -> Result<()> {
        match self {
            Self::Mapped(data) => data.sync_range(offset, length, flags),
            Self::Layer(file) => file.read(|data| data.sync_range(offset, length, flags)),
            Self::Plain(data) => data.sync_range(offset, length, flags),
            Self::Lower(_) | Self::Shared(_) => Ok(()),
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

// Apple filesystems expose a file-wide data flush. Keep the stronger wait
// confined to this explicit syscall; guest mapped-page writeback is ranged.
pub(super) fn sync_backing_range(
    file: &std::fs::File,
    offset: u64,
    length: u64,
    flags: u32,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let result =
            unsafe { libc::sync_file_range(file.as_raw_fd(), offset as i64, length as i64, flags) };
        if result < 0 {
            return Err(host_errno(std::io::Error::last_os_error()));
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (offset, length, flags);
        file.sync_data().map_err(host_errno)
    }
}

struct ManifestSnapshot {
    bytes: Vec<u8>,
    // Fixed-width inode header positions in the existing v4 format. Attribute
    // and namespace changes rebuild the snapshot under the same commit lock.
    metadata: Vec<(u64, usize)>,
}
pub(super) struct DiskStore {
    root: PathBuf,
    _lock: File,
    checkpoint: std::sync::Mutex<Option<ManifestSnapshot>>,
    initializing: std::sync::atomic::AtomicBool,
    // Namespace publication only; normal byte reads/writes do not touch these.
    // A generation observed before a successful host flush is covered by it.
    // Concurrent later mutations remain pending; completion never regresses.
    objects_generation: AtomicU64,
    objects_synced: AtomicU64,
    directory_generation: AtomicU64,
    directory_synced: AtomicU64,
    #[cfg(test)]
    sync_trace: std::sync::Mutex<Vec<&'static str>>,
    #[cfg(test)]
    directory_failures: std::sync::atomic::AtomicUsize,
    pub(super) used: Arc<AtomicU64>,
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
        Ok(Arc::new(Self {
            root,
            _lock: lock,
            checkpoint: std::sync::Mutex::new(None),
            initializing: std::sync::atomic::AtomicBool::new(false),
            objects_generation: AtomicU64::new(1),
            objects_synced: AtomicU64::new(0),
            directory_generation: AtomicU64::new(1),
            directory_synced: AtomicU64::new(0),
            #[cfg(test)]
            sync_trace: std::sync::Mutex::new(Vec::new()),
            #[cfg(test)]
            directory_failures: std::sync::atomic::AtomicUsize::new(0),
            used: Arc::new(AtomicU64::new(0)),
        }))
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
        self.objects_generation.fetch_add(1, Ordering::Relaxed);
        Ok(FileData::disk(DiskObject {
            capabilities: None,
            length: 0,
            backing: Arc::new(DiskBacking {
                files: std::sync::Mutex::default(),
                charge: std::sync::OnceLock::new(),
                preallocated_on_load: 0,
                path,
                remove_on_drop: std::sync::atomic::AtomicBool::new(true),
                _store: Some(self.clone()),
                #[cfg(all(feature = "hostfs", unix))]
                host: None,
                inode,
            }),
        }))
    }
    fn load(self: &Arc<Self>, inode: u64) -> Result<FileData> {
        let path = self.object_path(inode);
        regular(&path)?;
        let meta = fs::symlink_metadata(&path).map_err(host_errno)?;
        let length = meta.len();
        #[cfg(unix)]
        let preallocated_on_load = {
            use std::os::unix::fs::MetadataExt;
            let allocated = meta.blocks().saturating_mul(512);
            let block = 4096;
            if allocated > length.div_ceil(block).saturating_mul(block) {
                allocated
            } else {
                0
            }
        };
        #[cfg(not(unix))]
        let preallocated_on_load = 0;
        Ok(FileData::disk(DiskObject {
            capabilities: None,
            length,
            backing: Arc::new(DiskBacking {
                files: std::sync::Mutex::default(),
                charge: std::sync::OnceLock::new(),
                preallocated_on_load,
                path,
                remove_on_drop: std::sync::atomic::AtomicBool::new(false),
                _store: Some(self.clone()),
                #[cfg(all(feature = "hostfs", unix))]
                host: None,
                inode,
            }),
        }))
    }
    fn commit(&self, bytes: &[u8]) -> Result<()> {
        overlay::projection::prepare()?;
        // Namespace callers retain/roll back their original metadata on an
        // admission wait. No temporary manifest exists until credit is ours.
        let permit = cgroup::admit_io(bytes.len() as u64, true).map_err(host_errno)?;
        overlay::projection::publish(|| self.commit_admitted(bytes, permit))
    }
    fn commit_admitted(&self, bytes: &[u8], permit: Option<cgroup::IoPermit>) -> Result<()> {
        let tmp = self.root.join("manifest.new");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&tmp).map_err(host_errno)?;
        let before_rename = (|| {
            io_write::write_all(&mut file, bytes, permit).map_err(host_errno)?;
            file.sync_all().map_err(host_errno)?;
            let generation = self.objects_generation.load(Ordering::Relaxed);
            if self.objects_synced.load(Ordering::Relaxed) < generation {
                #[cfg(test)]
                self.sync_trace.lock().unwrap().push("objects");
                File::open(self.root.join("objects"))
                    .and_then(|f| f.sync_all())
                    .map_err(host_errno)?;
                self.objects_synced.fetch_max(generation, Ordering::Relaxed);
            }
            fs::rename(&tmp, self.root.join("manifest")).map_err(host_errno)
        })();
        if let Err(e) = before_rename {
            let _ = fs::remove_file(tmp);
            return Err(e);
        }
        // Rename is the namespace commit point. Never roll back the in-memory tree
        // after it; a later fsync reports directory durability failures explicitly.
        self.directory_generation.fetch_add(1, Ordering::Relaxed);
        let _ = self.sync_directory();
        Ok(())
    }
    pub(super) fn sync_directory(&self) -> Result<()> {
        let generation = self.directory_generation.load(Ordering::Relaxed);
        if self.directory_synced.load(Ordering::Relaxed) >= generation {
            return Ok(());
        }
        #[cfg(test)]
        {
            self.sync_trace.lock().unwrap().push("directory");
            if self
                .directory_failures
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_ok()
            {
                return Err(Errno(5));
            }
        }
        File::open(&self.root)
            .and_then(|f| f.sync_all())
            .map_err(host_errno)?;
        self.directory_synced
            .fetch_max(generation, Ordering::Relaxed);
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn take_sync_trace(&self) -> Vec<&'static str> {
        std::mem::take(&mut *self.sync_trace.lock().unwrap())
    }
    #[cfg(test)]
    pub(super) fn fail_directory_syncs(&self, count: usize) {
        self.directory_failures.store(count, Ordering::Relaxed);
    }
    fn recover(&self, live: &BTreeMap<u64, NodeRef>) -> Result<()> {
        let mut garbage = Vec::new();
        for entry in fs::read_dir(self.root.join("objects")).map_err(host_errno)? {
            let e = entry.map_err(host_errno)?;
            let name = e.file_name().into_string().map_err(|_| Errno(22))?;
            if projection_caps::temporary_name(&name) {
                regular(&e.path())?;
                garbage.push(e.path());
                if garbage.len() > MAX_DISK_NODES {
                    return Err(Errno(28));
                }
                continue;
            }
            if name.len() != 20
                || !matches!(name.as_bytes().get(16..), Some(b".dat" | b".cap" | b".new"))
                || !name[..16]
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(Errno(22));
            }
            let ino = u64::from_str_radix(&name[..16], 16).map_err(|_| Errno(22))?;
            regular(&e.path())?;
            let node = live
                .get(&ino)
                .filter(|n| matches!(n.borrow().content, Content::File(_)));
            match (node, &name[16..]) {
                (Some(node), ".cap") => {
                    let mut bytes = Vec::with_capacity(25);
                    File::open(e.path())
                        .and_then(|f| f.take(25).read_to_end(&mut bytes))
                        .map_err(host_errno)?;
                    let caps = file_caps::FileCaps::parse(&bytes, &UserNamespace::default())?;
                    let n = node.borrow();
                    let Content::File(FileData::Plain(file)) = &n.content else {
                        return Err(Errno(22));
                    };
                    file.restore_disk_caps(caps)?;
                }
                (Some(_), ".dat") => (),
                _ => garbage.push(e.path()),
            }
            if garbage.len() > MAX_DISK_NODES {
                return Err(Errno(28));
            }
        }
        // Do not delete anything until the manifest and every directory entry validate.
        if !garbage.is_empty() {
            self.objects_generation.fetch_add(1, Ordering::Relaxed);
            for path in garbage {
                fs::remove_file(path).map_err(host_errno)?;
            }
            // Rollback may make old inode numbers available again.
            File::open(self.root.join("objects"))
                .and_then(|f| f.sync_all())
                .map_err(host_errno)?;
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
    pub(super) fn sync_file_metadata(
        &self,
        data_only: bool,
        node: Option<&NodeRef>,
        overlay: Option<&overlay::Overlay>,
    ) -> Result<()> {
        // The v4 manifest contains identity/permissions/timestamps, not file
        // length. Private data length is recovered from the original host
        // object. fdatasync therefore needs that object's existing data sync,
        // not a timestamp-only namespace replacement. Overlay writeback keeps
        // its original checkpoint (it can still need to publish copy-up).
        if !data_only || self.disk.is_none() || overlay.is_some() {
            let patched = match (overlay, node) {
                (None, Some(node)) => self.checkpoint_inode(node)?,
                _ => false,
            };
            if !patched {
                self.checkpoint(overlay)?;
            }
        }
        if let Some(disk) = &self.disk {
            // Retry a previously failed post-rename directory flush. A clean
            // generation is already durable and requires no additional I/O.
            disk.sync_directory()?;
        }
        Ok(())
    }
    fn checkpoint_inode(&self, node: &NodeRef) -> Result<bool> {
        let Some(disk) = &self.disk else {
            return Ok(false);
        };
        if disk.initializing.load(Ordering::Relaxed) {
            return Ok(false);
        }
        let mut commit = disk.checkpoint.lock().unwrap();
        let Some(snapshot) = commit.as_mut() else {
            return Ok(false);
        };
        let n = node.borrow();
        if n.links == 0 {
            return Ok(true);
        }
        let Ok(index) = snapshot
            .metadata
            .binary_search_by_key(&n.inode, |entry| entry.0)
        else {
            return Ok(false);
        };
        let offset = snapshot.metadata[index].1;
        let metadata = inode_metadata_bytes(&n)?;
        drop(n);
        let old: [u8; 64] = snapshot.bytes[offset..offset + 64].try_into().unwrap();
        if old == metadata {
            return Ok(true);
        }
        let checksum_at = snapshot.bytes.len() - 8;
        let old_checksum: [u8; 8] = snapshot.bytes[checksum_at..].try_into().unwrap();
        snapshot.bytes[offset..offset + 64].copy_from_slice(&metadata);
        let hash = checksum(&snapshot.bytes[..checksum_at]);
        snapshot.bytes[checksum_at..].copy_from_slice(&hash.to_le_bytes());
        if let Err(error) = disk.commit(&snapshot.bytes) {
            snapshot.bytes[offset..offset + 64].copy_from_slice(&old);
            snapshot.bytes[checksum_at..].copy_from_slice(&old_checksum);
            return Err(error);
        }
        Ok(true)
    }
    pub(super) fn checkpoint(&self, overlay: Option<&overlay::Overlay>) -> Result<()> {
        if let Some(overlay) = overlay {
            return overlay.checkpoint(self);
        }
        let Some(disk) = &self.disk else {
            overlay::projection::prepare()?;
            return overlay::projection::publish(|| Ok(()));
        };
        if disk.initializing.load(Ordering::Relaxed) {
            return Ok(());
        }
        // One manifest transaction per store, including snapshot construction.
        // Other filesystems and ordinary byte I/O remain independent.
        let mut commit = disk.checkpoint.lock().unwrap();
        let mut nodes = BTreeMap::new();
        for n in self.paths.values() {
            nodes.insert(n.borrow().inode, n.clone());
        }
        let mut out = b"TRAMESFS".to_vec();
        let mut metadata = Vec::with_capacity(nodes.len());
        out.extend(4u32.to_le_bytes());
        out.extend(self.limits.file_bytes.to_le_bytes());
        out.extend((self.limits.nodes as u32).to_le_bytes());
        out.extend(self.next_inode.to_le_bytes());
        out.extend((nodes.len() as u32).to_le_bytes());
        out.extend((self.paths.len() as u32).to_le_bytes());
        for (ino, node) in nodes {
            let n = node.borrow();
            metadata.push((ino, out.len() + 8));
            out.extend(ino.to_le_bytes());
            out.extend(inode_metadata_bytes(&n)?);
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
        disk.commit(&out)?;
        *commit = Some(ManifestSnapshot {
            bytes: out,
            metadata,
        });
        Ok(())
    }
}
fn inode_metadata_bytes(n: &Node) -> Result<[u8; 64]> {
    let mut bytes = [0; 64];
    let metadata = n.file_metadata();
    bytes[..4].copy_from_slice(&metadata.mode.to_le_bytes());
    bytes[4..8].copy_from_slice(&n.uid.to_le_bytes());
    bytes[8..12].copy_from_slice(&n.gid.to_le_bytes());
    bytes[12] = match n.content {
        Content::MessageQueue(_) | Content::Fuse => return Err(Errno(95)),
        Content::Directory => 0,
        Content::File(_) => 1,
        Content::Null => 2,
        Content::Terminal => 3,
        Content::Symlink(_) => 4,
        Content::Fifo(_) => 5,
        Content::Socket(_) => 8,
        Content::Device(_) if n.mode & 0o170000 == 0o60000 => 7,
        Content::Device(_) => 6,
    };
    for (i, time) in metadata.times.into_iter().enumerate() {
        let at = 16 + i * 16;
        bytes[at..at + 8].copy_from_slice(&time.seconds.to_le_bytes());
        bytes[at + 8..at + 12].copy_from_slice(&time.nanos.to_le_bytes());
    }
    Ok(bytes)
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
                let trusted = super::xattr::trusted_attribute(&name);
                if !trusted
                    && !matches!(n.content, Content::File(_) | Content::Directory)
                    && (!super::acl::name(&name) || matches!(n.content, Content::Symlink(_)))
                {
                    return Err(Errno(22));
                }
                if super::acl::name(&name) {
                    super::acl::validate(&value)?;
                    if value.len() == 4
                        || name == super::acl::DEFAULT && !matches!(n.content, Content::Directory)
                    {
                        return Err(Errno(22));
                    }
                }
                if !(name.starts_with(b"user.") || trusted || super::acl::name(&name))
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
        let identical = old.logical_size().load(Ordering::Relaxed) == bytes.len() as u64
            && crate::host_files::read_sync(old.clone())? == bytes;
        if identical {
            if old.borrow().file_metadata().mode != 0o100755 {
                self.chmod_at(AT_FDCWD, &canonical, 0o755)?;
            }
            return Ok(());
        }
        self.check_growth(0, bytes.len() as u64)?;
        let (FileData::Plain(data), _) = self.stage_import(&mut bytes)? else {
            return Err(Errno(5));
        };
        let mut wait = host_sync::Wait::default();
        loop {
            let mut fs = self.fs.borrow_mut();
            if fs
                .paths
                .get(&canonical.key)
                .is_none_or(|node| !Arc::ptr_eq(node, &old))
            {
                return Err(Errno(116));
            }
            let previous_next = fs.next_inode;
            let previous_inodes = fs.inodes.len();
            fs.admit_inode()?;
            let inode = FileData::Plain(data.clone())
                .inode()
                .unwrap_or(fs.next_inode);
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
                content: Content::File(FileData::Plain(data.clone())),
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
            old.borrow_mut().links = 0;
            let scope = resource_io::Scope::enter();
            let result = fs.track_inode(&new).and_then(|_| fs.checkpoint());
            let pending = scope.finish();
            if let Err(e) = result {
                for n in fs.paths.values_mut() {
                    if Arc::ptr_eq(n, &new) {
                        *n = old.clone();
                    }
                }
                fs.next_inode = previous_next;
                fs.inodes.truncate(previous_inodes);
                old.borrow_mut().links = links;
                drop(fs);
                if let Some(pending) = pending {
                    wait.page(&pending.wait)?;
                    continue;
                }
                return Err(e);
            }
            if let Content::File(data) = &mut new.borrow_mut().content {
                data.orphan(false);
            }
            if let Content::File(data) = &mut old.borrow_mut().content {
                data.orphan(true);
            }
            return Ok(());
        }
    }
    /// Populate a private, unpublished staging store before creating a runtime.
    /// The caller must discard the whole store on error. This is not a live
    /// transaction: only the final namespace is published, and no guest may run
    /// or share this VFS until the call returns. File data still uses normal
    /// ownership, capacity and sync rules. The final sync commits every object
    /// before its manifest; unwinding always restores normal checkpoints.
    pub fn populate_staged<T, E: From<Errno>>(
        &mut self,
        populate: impl FnOnce(&mut Self) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        let disk = self.fs.borrow().disk.clone().ok_or(Errno(22))?;
        if disk.initializing.swap(true, Ordering::Relaxed) {
            return Err(Errno(16).into());
        }
        struct Reset(Arc<DiskStore>);
        impl Drop for Reset {
            fn drop(&mut self) {
                self.0.initializing.store(false, Ordering::Relaxed);
            }
        }
        let reset = Reset(disk);
        let result = populate(self);
        drop(reset);
        match result {
            Ok(value) => {
                self.sync()?;
                Ok(value)
            }
            Err(error) => Err(error),
        }
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
        let mut v = Vfs::default();
        let mut disk = DiskStore::open(path, owner_lock)?;
        Arc::get_mut(&mut disk).expect("unpublished store").used = v.fs.quota.used.clone();
        let manifest = disk.root.join("manifest");
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
            fs.quota.configure(fs.limits.file_bytes, fs.volume);
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
        fs.quota.configure(fs.limits.file_bytes, fs.volume);
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
        let mut fs = self.fs.borrow_mut();
        fs.volume = Some((space, used));
        fs.quota.configure(fs.limits.file_bytes, fs.volume);
        Ok(())
    }
    pub fn capacity(&self) -> StorageCapacity {
        Self::filesystem_capacity(&self.fs.borrow())
    }
    pub(super) fn filesystem_used_bytes(
        fs: &FsBorrow<'_, impl std::ops::Deref<Target = Filesystem>>,
    ) -> u64 {
        fs.quota.used.load(Ordering::Relaxed)
    }
    pub(super) fn filesystem_bytes(
        fs: &FsBorrow<'_, impl std::ops::Deref<Target = Filesystem>>,
    ) -> (u64, u64, u64) {
        if let Some(overlay) = &fs.overlay {
            return overlay.capacity_bytes();
        }
        let used = Self::filesystem_used_bytes(fs);
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
        (used, budget, available)
    }
    pub(super) fn filesystem_capacity(
        fs: &FsBorrow<'_, impl std::ops::Deref<Target = Filesystem>>,
    ) -> StorageCapacity {
        if let Some(overlay) = &fs.overlay {
            return overlay.capacity();
        }
        let (used, budget, available) = Self::filesystem_bytes(fs);
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
        if new.saturating_sub(old) > Self::filesystem_bytes(&self.fs.borrow()).2 {
            return Err(Errno(28));
        }
        Ok(())
    }
    pub(super) fn empty_data(&self) -> Result<FileData> {
        Self::filesystem_empty_data(&mut self.fs.borrow_mut())
    }
    pub(super) fn ram_file(quota: &Arc<file_accounting::FileQuota>) -> Result<FileData> {
        if quota.tmpfs {
            Ok(FileData::Plain(file_data::PlainFile::new(
                file_data::Bytes::Tmpfs(Box::new(tmpfs::SparseFile::new(quota)?)),
            )))
        } else {
            Ok(FileData::memory(Vec::new()))
        }
    }
    pub(super) fn filesystem_empty_data(
        fs: &mut FsBorrow<'_, impl std::ops::DerefMut<Target = Filesystem>>,
    ) -> Result<FileData> {
        if let Some(overlay) = &fs.overlay {
            return overlay.empty_data();
        }
        let data = if let Some(d) = &fs.disk {
            let next = fs.next_inode.checked_add(1).ok_or(Errno(28))?;
            let data = d.create(fs.next_inode)?;
            fs.next_inode = next;
            data
        } else {
            Self::ram_file(fs.quota)?
        };
        data.bind_quota(fs.quota)?;
        Ok(data)
    }
    pub fn checkpoint(&self) -> Result<()> {
        if self.query.is_none() {
            let mut filesystems = Vec::new();
            let mut seen = std::collections::BTreeSet::new();
            for mount in self
                .mount_resources
                .borrow()
                .iter()
                .filter_map(std::sync::Weak::upgrade)
            {
                if seen.insert(mount.fs.identity()) && mount.fs.borrow().overlay.is_some() {
                    filesystems.push(mount.fs.clone());
                }
            }
            if !filesystems
                .iter()
                .any(|filesystem| filesystem.same_data(&self.fs))
            {
                filesystems.push(self.fs.clone());
            }
            let mut wait = host_sync::Wait::default();
            for filesystem in filesystems {
                wait.operation(|| filesystem.borrow().checkpoint())?;
            }
            return Ok(());
        }
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
        if self.query.is_none() {
            self.host_file_work(FileWork::sync_all(self.path_queries()))?;
            return Ok(());
        }
        let mut filesystems = BTreeMap::new();
        filesystems.insert(self.fs.identity(), self.fs.clone());
        for mount in self
            .mount_resources
            .borrow()
            .iter()
            .filter_map(std::sync::Weak::upgrade)
        {
            filesystems
                .entry(mount.fs.identity())
                .or_insert_with(|| mount.fs.clone());
        }
        for filesystem in filesystems.into_values() {
            Self::sync_filesystem(&filesystem)?;
        }
        Ok(())
    }
    fn sync_filesystem(filesystem: &FsHandle) -> Result<()> {
        FilesystemSync::new(filesystem.clone()).run()
    }
    pub(super) fn sync_targets(&self, all: bool) -> Vec<FilesystemSync> {
        let mut filesystems = BTreeMap::new();
        filesystems.insert(self.fs.identity(), self.fs.clone());
        if all {
            for mount in self
                .mount_resources
                .borrow()
                .iter()
                .filter_map(std::sync::Weak::upgrade)
            {
                filesystems
                    .entry(mount.fs.identity())
                    .or_insert_with(|| mount.fs.clone());
            }
        }
        filesystems.into_values().map(FilesystemSync::new).collect()
    }
    pub fn sync_file_range(&self, fd: u32, offset: u64, length: u64, flags: u32) -> Result<()> {
        if self.query.is_none() {
            let file = self.shared_files().lookup(fd).ok_or(Errno(9))??;
            self.host_file_work(FileWork::from_vfs(
                self,
                file.filesystem_target(),
                FileCommand::SyncRange {
                    offset,
                    length,
                    flags,
                },
            ))?;
            return Ok(());
        }
        let descriptor = self.descriptor(fd)?;
        let open = descriptor.open.borrow();
        if open.flags.get() & O_PATH != 0 {
            return Err(Errno(9));
        }
        if flags & !7 != 0 || offset > i64::MAX as u64 || length > i64::MAX as u64 - offset {
            return Err(Errno(22));
        }
        if !matches!(
            self.cache_file_type(&open, false)?,
            0o100000 | 0o040000 | 0o120000 | 0o060000
        ) {
            return Err(Errno(29));
        }
        if flags == 0 {
            return Ok(());
        }
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = &open.host_file {
            if let Some(node) = &open.node {
                if let Content::File(FileData::Mapped(data)) = &node.borrow().content {
                    data.flush_requested_range(offset, length, flags)?;
                }
            }
            return sync_backing_range(&host.file, offset, length, flags);
        }
        if let Some(node) = &open.node {
            if let Content::File(data) = &node.borrow().content {
                return data.sync_range(offset, length, flags);
            }
        }
        Ok(())
    }
    pub fn sync_filesystem_fd(&self, fd: u32) -> Result<()> {
        if self.query.is_none() {
            let file = self.shared_files().lookup(fd).ok_or(Errno(9))??;
            self.host_file_work(FileWork::from_vfs(
                self,
                file.filesystem_target(),
                FileCommand::SyncFilesystem,
            ))?;
            return Ok(());
        }
        let descriptor = self.descriptor(fd)?;
        let open = descriptor.open.borrow();
        if open.flags.get() & O_PATH != 0 {
            return Err(Errno(9));
        }
        let filesystem = open.mount.as_ref().map_or(&self.fs, |m| &m.fs).clone();
        drop(open);
        Self::sync_filesystem(&filesystem)
    }
    pub fn sync_fd(&self, fd: u32, data_only: bool) -> Result<()> {
        if self.query.is_none() {
            let file = self.shared_files().lookup(fd).ok_or(Errno(9))??;
            self.host_file_work(FileWork::from_vfs(
                self,
                file.filesystem_target(),
                FileCommand::Sync { data_only },
            ))?;
            return Ok(());
        }
        self.sync_description(&self.descriptor(fd)?, data_only)
    }
    pub(super) fn host_file_work(&self, work: FileWork) -> Result<FileValue> {
        let mut control = self.host_files_context();
        host_sync::Wait::default().file(&mut control, work.run())
    }
    pub(super) fn sync_description(&self, descriptor: &Descriptor, data_only: bool) -> Result<()> {
        let o = descriptor.open.borrow();
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(file) = &o.host_file {
            return if data_only {
                file.file.sync_data()
            } else {
                file.file.sync_all()
            }
            .map_err(host_errno);
        }
        let node = o.node.as_ref().ok_or(Errno(22))?.clone();
        let n = node.borrow();
        if let Content::File(data) = &n.content {
            data.sync(data_only)?;
        } else if !matches!(n.content, Content::Directory) {
            return Err(Errno(22));
        }
        let linked = n.links != 0;
        let regular = matches!(n.content, Content::File(_));
        let filesystem = o.mount.as_ref().map_or(&self.fs, |mount| &mount.fs).clone();
        drop(n);
        drop(o);
        if linked {
            // fsync observes this inode's filesystem, including a retained
            // detached mount. Anonymous/unlinked files have no namespace entry
            // to commit; their data sync above is still required.
            let fs = filesystem.borrow();
            fs.sync_file_metadata(data_only && regular, regular.then_some(&node))?;
        }
        Ok(())
    }
    /// Startup imports into /dev/shm belong to the session tmpfs. Keep raw
    /// archive imports on private storage, including directories hidden at boot.
    pub fn import_session_reader(
        &mut self,
        path: &[u8],
        reader: &mut impl Read,
        executable: bool,
    ) -> Result<u64> {
        if path.len() >= MAX_PATH || !path.starts_with(b"/") {
            return Err(Errno(22));
        }
        let mut parts = path.split(|&b| b == b'/').filter(|part| !part.is_empty());
        if parts.next() == Some(b"dev".as_slice())
            && parts.next() == Some(b"shm".as_slice())
            && parts.clone().next().is_some()
        {
            let shm = self.resolve_final(AT_FDCWD, b"/dev/shm", false)?;
            if let Some(mount) = &shm.mount {
                if mount.kind == mounts::Kind::Tmpfs && shm.key == b"/" {
                    shm.writable()?;
                    if path.ends_with(b"/") {
                        return Err(Errno(22));
                    }
                    let mut relative = Vec::new();
                    for part in parts {
                        relative.push(b'/');
                        relative.extend_from_slice(part);
                    }
                    return Vfs::empty(mount.fs.clone())
                        .import_reader(&relative, reader, executable);
                }
            }
        }
        self.import_reader(path, reader, executable)
    }
    /// Copy a platform-authorized stream into private storage using bounded buffers.
    pub fn import_reader(
        &mut self,
        path: &[u8],
        reader: &mut impl Read,
        executable: bool,
    ) -> Result<u64> {
        self.import_reader_sync(path, reader, false, executable)
    }
    fn import_reader_sync(
        &self,
        path: &[u8],
        reader: &mut impl Read,
        replace: bool,
        executable: bool,
    ) -> Result<u64> {
        let mut work = self.host_import(path, reader, replace, executable);
        let mut wait = host_sync::Wait::default();
        loop {
            if let Some(result) = work.run()? {
                return Ok(result.bytes);
            }
            wait.page(work.wait().expect("retained import wait"))?;
        }
    }
    /// An unpublished object owns its quota and cleanup through cancellation.
    pub(super) fn stage_import(&self, reader: &mut impl Read) -> Result<(FileData, u64)> {
        let mut stage = crate::import_work::StagedImport::new(reader);
        let mut wait = host_sync::Wait::default();
        while !stage.run(self, &|| false)? {
            wait.page(stage.wait().expect("original import staging wait"))?;
        }
        Ok((stage.file(), stage.bytes()))
    }

    /// Explicit host import replacement. Stage a complete inode before one
    /// namespace rename; cancellation/short reads never truncate the old file.
    pub fn import_reader_replace(&mut self, path: &[u8], reader: &mut impl Read) -> Result<u64> {
        self.import_reader_sync(path, reader, true, false)
    }
    /// Export through an authorized platform writer; no guest-to-host path mapping.
    pub fn export_writer(&self, path: &[u8], writer: &mut impl Write) -> Result<u64> {
        let mut work = self.host_export(path)?.into_work(writer);
        let mut wait = host_sync::Wait::default();
        loop {
            let admission = wait.layout(&work.layout())?;
            let result = work.run(&admission, || false);
            drop(admission);
            if let Some(bytes) = result? {
                return Ok(bytes);
            }
            wait.page(work.wait().expect("retained export wait"))?;
        }
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
}

/// The files accepted by one filesystem sync. Native work keeps this snapshot,
/// so a later open does not join its byte locks or durability transaction.
pub(super) struct FilesystemSync {
    filesystem: FsHandle,
    nodes: Vec<NodeRef>,
    active: bool,
    index: usize,
    current: Option<mapped::DataSync>,
    checkpointed: bool,
    done: bool,
}
impl FilesystemSync {
    pub(super) fn new(filesystem: FsHandle) -> Self {
        let nodes = filesystem
            .borrow()
            .inodes
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .filter(|node| node.regular_file)
            .collect();
        Self {
            filesystem,
            nodes,
            active: false,
            index: 0,
            current: None,
            checkpointed: false,
            done: false,
        }
    }
    pub(super) fn queued(mut self) -> Self {
        for node in &self.nodes {
            node.active_file_work.fetch_add(1, Ordering::Relaxed);
        }
        self.active = true;
        self
    }
    pub(super) fn run(&mut self) -> Result<()> {
        if self.done {
            return Ok(());
        }
        let _writeback = trames_shared::FileTransactionScope::writeback();
        while let Some(node) = self.nodes.get(self.index) {
            if self.current.is_none() {
                if let Content::File(data) = &node.borrow().content {
                    self.current = Some(mapped::DataSync::capture(data, false)?);
                }
            }
            if let Some(current) = &mut self.current {
                let result = {
                    let _node = node.borrow();
                    current.run()
                };
                current.notify();
                result?;
            }
            self.current = None;
            self.index += 1;
        }
        let fs = self.filesystem.borrow();
        if !self.checkpointed {
            fs.checkpoint()?;
            self.checkpointed = true;
        }
        if let Some(disk) = &fs.disk {
            disk.sync_directory()?;
        }
        self.done = true;
        Ok(())
    }
}
impl Drop for FilesystemSync {
    fn drop(&mut self) {
        if self.active {
            for node in &self.nodes {
                node.active_file_work.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}
