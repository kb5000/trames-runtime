// SPDX-License-Identifier: GPL-3.0-or-later
//! Plain file bytes are shared independently of namespace and mapping owners.
use super::*;
#[cfg(unix)]
use std::os::unix::fs::{FileExt, MetadataExt};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize},
    Mutex, RwLock,
};
use storage::{DiskObject, Timestamp};

pub(super) enum Bytes {
    Memory(Vec<u8>),
    Disk(DiskObject),
}
pub(super) struct PlainFile {
    #[cfg(all(feature = "hostfs", unix))]
    host: Option<Arc<hostfs::HostFile>>,
    bytes: RwLock<Bytes>,
    length: AtomicU64,
    charge: std::sync::OnceLock<Arc<file_accounting::FileCharge>>,
    logical_size: std::sync::OnceLock<trames_shared::LogicalSize>,
    backing: Option<Arc<storage::DiskBacking>>,
    pending: AtomicUsize,
    mapped: AtomicBool,
    meta: Mutex<Option<FileMeta>>,
}
#[derive(Clone, Copy)]
pub(super) struct FileMeta {
    pub mode: u32,
    pub times: [Timestamp; 3],
}
/// Original offset/pending transaction, with a lock-free committed observation.
/// Proc rendering can observe its own OFD while a read holds the transaction.
/// A relaxed scalar snapshot needs no new guest ordering or mutation authority.
#[derive(Default)]
pub(super) struct FilePosition {
    state: Mutex<PositionState>,
    committed: AtomicU64,
}
#[derive(Default)]
pub(super) struct PositionState {
    pub value: u64,
    pub pending: usize,
}
pub(super) struct PositionGuard<'a> {
    state: std::sync::MutexGuard<'a, PositionState>,
    committed: &'a AtomicU64,
}
impl std::ops::Deref for PositionGuard<'_> {
    type Target = PositionState;
    fn deref(&self) -> &Self::Target {
        &self.state
    }
}
impl std::ops::DerefMut for PositionGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}
impl Drop for PositionGuard<'_> {
    fn drop(&mut self) {
        // Publish before the original mutex unlock. Observers may see the old
        // committed offset during an operation, never wait on their own read.
        self.committed.store(self.state.value, Ordering::Relaxed);
    }
}
impl FilePosition {
    pub fn snapshot(&self) -> u64 {
        self.committed.load(Ordering::Relaxed)
    }
    fn guard<'a>(&'a self, state: std::sync::MutexGuard<'a, PositionState>) -> PositionGuard<'a> {
        PositionGuard {
            state,
            committed: &self.committed,
        }
    }
    pub fn lock(&self) -> std::sync::LockResult<PositionGuard<'_>> {
        self.state
            .lock()
            .map(|state| self.guard(state))
            .map_err(|error| std::sync::PoisonError::new(self.guard(error.into_inner())))
    }
    pub fn try_lock(&self) -> std::sync::TryLockResult<PositionGuard<'_>> {
        match self.state.try_lock() {
            Ok(state) => Ok(self.guard(state)),
            Err(std::sync::TryLockError::WouldBlock) => Err(std::sync::TryLockError::WouldBlock),
            Err(std::sync::TryLockError::Poisoned(error)) => {
                Err(std::sync::TryLockError::Poisoned(
                    std::sync::PoisonError::new(self.guard(error.into_inner())),
                ))
            }
        }
    }
}
pub(super) struct ReadLease {
    data: Arc<PlainFile>,
}
impl Drop for ReadLease {
    fn drop(&mut self) {
        self.data.pending.fetch_sub(1, Ordering::Release);
    }
}
impl PlainFile {
    /// Cold conditional host replacement uses the existing byte lock through
    /// its namespace commit. Ordinary writes gain no additional gate/check.
    pub(super) fn with_reader<T>(&self, call: impl FnOnce(&mut dyn std::io::Read) -> T) -> T {
        let bytes = self.bytes.read().unwrap();
        struct Reader<'a> {
            bytes: &'a Bytes,
            offset: u64,
        }
        impl std::io::Read for Reader<'_> {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                let data = self
                    .bytes
                    .read_at(self.offset, out.len(), None)
                    .map_err(|e| std::io::Error::from_raw_os_error(e.0 as i32))?;
                out[..data.len()].copy_from_slice(&data);
                self.offset += data.len() as u64;
                Ok(data.len())
            }
        }
        let mut reader = Reader {
            bytes: &bytes,
            offset: 0,
        };
        call(&mut reader)
    }
    pub(super) fn private_lease(&self, write: bool) -> Result<Option<Arc<std::fs::File>>> {
        match &self.backing {
            Some(backing) => backing.private_lease(write),
            None => Ok(None),
        }
    }
    pub(super) fn bind_quota(&self, quota: &Arc<file_accounting::FileQuota>) -> Result<()> {
        #[cfg(all(feature = "hostfs", unix))]
        if self.host.is_some() {
            return Ok(());
        }
        if let Some(charge) = self.charge.get() {
            charge.bind(quota);
            return Ok(());
        }
        // The original data lock excludes another first publisher; no double
        // provisional charge or cached admission error can escape a failed bind.
        let _data = self.bytes.write().unwrap();
        if self.charge.get().is_none() {
            let charge = if let Some(backing) = self.backing.as_ref().filter(|b| b._store.is_some())
            {
                backing.register_size(self.length.load(Ordering::Relaxed));
                backing.charge.get().unwrap().clone()
            } else {
                file_accounting::FileCharge::admit(quota, self.length.load(Ordering::Relaxed))?
            };
            charge.bind(quota);
            let _ = self.charge.set(charge);
        }
        Ok(())
    }
    pub(super) fn register_storage(&self) {
        let Some(backing) = self.backing.as_ref().filter(|b| b._store.is_some()) else {
            return;
        };
        if let Some(charge) = backing.charge.get() {
            let _ = self.charge.set(charge.clone());
            return;
        }
        let _data = self.bytes.read().unwrap();
        backing.register_size(self.length.load(Ordering::Relaxed));
        let _ = self.charge.set(backing.charge.get().unwrap().clone());
    }
    #[cfg(all(feature = "hostfs", unix))]
    pub(super) fn append_host(&self, bytes: &[u8]) -> Option<Result<(usize, u64)>> {
        let host = self.host.as_ref()?;
        let _data = self.bytes.write().unwrap();
        let result = host.append(bytes);
        if let Ok((_, end)) = result {
            self.publish_length(end);
        }
        Some(result)
    }
    #[cfg(all(feature = "hostfs", unix))]
    pub(super) fn host_stat(&self) -> Option<Result<[u8; 128]>> {
        self.host.as_ref().map(|host| host.any_file()?.stat())
    }
    pub fn new(bytes: Bytes) -> Arc<Self> {
        let length = match &bytes {
            Bytes::Memory(data) => data.len() as u64,
            Bytes::Disk(data) => data.length,
        };
        let backing = match &bytes {
            Bytes::Disk(d) => Some(d.backing.clone()),
            _ => None,
        };
        Arc::new(Self {
            #[cfg(all(feature = "hostfs", unix))]
            host: backing.as_ref().and_then(|b| b.host.clone()),
            bytes: RwLock::new(bytes),
            length: AtomicU64::new(length),
            charge: std::sync::OnceLock::new(),
            logical_size: std::sync::OnceLock::new(),
            backing,
            pending: AtomicUsize::new(0),
            mapped: AtomicBool::new(false),
            meta: Mutex::new(None),
        })
    }
    pub fn activate(&self, mode: u32, times: [Timestamp; 3]) {
        let mut meta = self.meta.lock().unwrap();
        // A live mirror may survive an aborted cohort; never overwrite its
        // already-completed effects with stale coordinator fields.
        if meta.is_none() {
            *meta = Some(FileMeta { mode, times });
        }
    }
    pub fn metadata(&self) -> Option<FileMeta> {
        *self.meta.lock().unwrap()
    }
    pub(super) fn patch_metadata(&self, before: FileMeta, after: FileMeta) {
        let mut meta = self.meta.lock().unwrap();
        if let Some(meta) = meta.as_mut() {
            if before.mode != after.mode {
                meta.mode = after.mode;
            }
            for i in 0..3 {
                if before.times[i] != after.times[i] {
                    meta.times[i] = after.times[i];
                }
            }
        }
    }
    pub fn accessed(&self, readonly: bool, relatime: bool) -> Option<FileMeta> {
        let mut meta = self.meta.lock().unwrap();
        if let Some(meta) = meta.as_mut() {
            let now = Timestamp::now();
            let atime = meta.times[0];
            if !readonly
                && !(relatime
                    && meta.times[1..]
                        .iter()
                        .all(|t| (t.seconds, t.nanos) < (atime.seconds, atime.nanos))
                    && now.seconds.saturating_sub(atime.seconds) < 86400)
            {
                meta.times[0] = now;
            }
        }
        *meta
    }
    pub fn modified(&self, clear_setid: bool) -> Option<FileMeta> {
        let mut meta = self.meta.lock().unwrap();
        if let Some(meta) = meta.as_mut() {
            if clear_setid {
                meta.mode &= !0o4000;
                if meta.mode & 0o10 != 0 {
                    meta.mode &= !0o2000;
                }
            }
            meta.times[1] = Timestamp::now();
            meta.times[2] = meta.times[1];
        }
        *meta
    }
    // Metadata/quota scans need only a scalar, not a byte-data lock. Relaxed
    // length does not publish file bytes; their access still uses the RwLock.
    pub fn len(&self) -> u64 {
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = &self.host {
            let size = host.len();
            if self.length.load(Ordering::Relaxed) != size {
                self.publish_length(size);
            }
            return size;
        }
        self.length.load(Ordering::Relaxed)
    }
    pub fn logical_size(&self) -> trames_shared::LogicalSize {
        if let Some(size) = self.logical_size.get() {
            return size.clone();
        }
        let _bytes = self.bytes.read().unwrap();
        self.logical_size
            .get_or_init(|| trames_shared::LogicalSize::new(self.len()))
            .clone()
    }
    fn publish_length(&self, length: u64) {
        self.length.store(length, Ordering::Relaxed);
        if let Some(charge) = self.charge.get() {
            charge.publish(length);
        }
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = &self.host {
            host.publish_length(length);
        }
        if let Some(backing) = &self.backing {
            backing.update_size(length);
        }
        if let Some(size) = self
            .logical_size
            .get()
            .filter(|s| s.load(Ordering::Relaxed) != length)
        {
            size.store(length, Ordering::Relaxed);
        }
    }
    pub fn disk_backed(&self) -> bool {
        self.backing.is_some()
    }
    pub fn disk_source(&self) -> Option<(Arc<storage::DiskBacking>, u64)> {
        self.backing
            .as_ref()
            .map(|backing| (backing.clone(), self.len()))
    }
    pub fn blocks(&self) -> Result<u64> {
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = &self.host {
            return Ok(host.metadata()?.blocks());
        }
        #[cfg(unix)]
        if let Some(backing) = &self.backing {
            let metadata = match backing.cached_file() {
                Some(file) => file.metadata(),
                None => std::fs::symlink_metadata(&backing.path),
            };
            return Ok(metadata.map_err(storage::host_errno)?.blocks());
        }
        Ok(self.len().div_ceil(512))
    }
    pub fn inode(&self) -> Option<u64> {
        self.backing.as_ref().map(|backing| backing.inode)
    }
    pub fn read_at(
        &self,
        offset: u64,
        count: usize,
        cache: Option<&mut DiskReadCache>,
    ) -> Result<Vec<u8>> {
        self.bytes.read().unwrap().read_at(offset, count, cache)
    }
    /// Publish the change of byte authority under the same lock as direct I/O.
    /// Existing capabilities must defer once mapped pages can own newer bytes.
    pub fn mark_mapped(&self) {
        let _bytes = self.bytes.write().unwrap();
        self.mapped.store(true, Ordering::Relaxed);
    }
    pub fn epoch_read_at(
        &self,
        offset: u64,
        count: usize,
        cache: &mut DiskReadCache,
    ) -> Option<Result<Vec<u8>>> {
        let data = match self.bytes.try_read() {
            Ok(data) => data,
            Err(std::sync::TryLockError::WouldBlock) => return None,
            Err(error) => panic!("{error}"),
        };
        if self.mapped.load(Ordering::Relaxed) {
            return None;
        }
        Some(data.read_at(offset, count, Some(cache)))
    }
    pub fn write_at(&self, offset: u64, bytes: &[u8]) -> Result<usize> {
        self.write_transfer(offset, bytes, false, None)
            .map(|(n, _)| n)
    }
    pub(super) fn write_transfer(
        &self,
        offset: u64,
        bytes: &[u8],
        append: bool,
        cache: Option<&mut DiskReadCache>,
    ) -> Result<(usize, u64)> {
        let mut data = self.bytes.write().unwrap();
        self.transfer(&mut data, offset, bytes, append, cache, u64::MAX, || ())
    }
    pub(super) fn write_limited(
        &self,
        offset: u64,
        bytes: &[u8],
        append: bool,
        limit: u64,
        signal: impl FnOnce(),
    ) -> Result<(usize, u64)> {
        let mut data = self.bytes.write().unwrap();
        self.transfer(&mut data, offset, bytes, append, None, limit, signal)
    }
    #[allow(clippy::too_many_arguments)] // One original byte transaction plus cache and guest limit/signal policy.
    fn transfer(
        &self,
        data: &mut Bytes,
        offset: u64,
        bytes: &[u8],
        append: bool,
        cache: Option<&mut DiskReadCache>,
        limit: u64,
        signal: impl FnOnce(),
    ) -> Result<(usize, u64)> {
        let position = if append { data.len() } else { offset };
        if position >= limit {
            signal();
            return Err(Errno(27));
        }
        let bytes = &bytes[..bytes
            .len()
            .min(usize::try_from(limit - position).unwrap_or(usize::MAX))];
        let end = position
            .checked_add(bytes.len() as u64)
            .filter(|end| *end <= i64::MAX as u64)
            .ok_or(Errno(27))?;
        let growth = self
            .charge
            .get()
            .map(|c| c.grow(end))
            .transpose()?
            .flatten();
        #[cfg(all(feature = "hostfs", unix))]
        let result = if let Some(host) = self.host.as_ref().filter(|_| append) {
            host.append(bytes)
        } else {
            data.write_at(position, bytes, cache)
                .map(|n| (n, position + n as u64))
        };
        #[cfg(not(all(feature = "hostfs", unix)))]
        let result = data
            .write_at(position, bytes, cache)
            .map(|n| (n, position + n as u64));
        if let Some(growth) = growth {
            growth.commit(data.len());
        }
        self.publish_length(data.len());
        result
    }
    /// None is before effects. Busy native data or long host transfers are
    /// handed to the existing file executor; RAM and cached short writes stay
    /// on their original calling CPU. Growth/append use the same data algorithm.
    pub fn write_local(
        &self,
        offset: u64,
        bytes: &[u8],
        append: bool,
        cache: &mut DiskReadCache,
    ) -> Option<Result<(usize, u64)>> {
        let mut data = match self.bytes.try_write() {
            Ok(data) => data,
            Err(std::sync::TryLockError::WouldBlock) => return None,
            Err(error) => panic!("{error}"),
        };
        if self.mapped.load(Ordering::Relaxed)
            || matches!(&*data, Bytes::Disk(_)) && bytes.len() >= 16 * 1024
        {
            return None;
        }
        Some(self.transfer(
            &mut data,
            offset,
            bytes,
            append,
            Some(cache),
            u64::MAX,
            || (),
        ))
    }
    pub fn register_read(self: &Arc<Self>) -> ReadLease {
        // Register after an in-progress writer releases the original byte
        // lock. The lease tracks this read; later byte access uses that lock.
        let _data = self.bytes.read().unwrap();
        self.pending.fetch_add(1, Ordering::Acquire);
        ReadLease { data: self.clone() }
    }
    pub fn truncate(&self, length: u64) -> Result<()> {
        let mut data = self.bytes.write().unwrap();
        let growth = self
            .charge
            .get()
            .map(|c| c.grow(length))
            .transpose()?
            .flatten();
        match &mut *data {
            Bytes::Memory(b) => {
                let n = usize::try_from(length).map_err(|_| Errno(27))?;
                if n > b.len() {
                    b.try_reserve(n - b.len()).map_err(|_| Errno(12))?;
                }
                b.resize(n, 0);
            }
            Bytes::Disk(d) => {
                d.open(true)?.set_len(length).map_err(storage::host_errno)?;
                d.length = length;
            }
        }
        if let Some(growth) = growth {
            growth.commit(length);
        }
        self.publish_length(length);
        Ok(())
    }
    pub fn sync(&self, data_only: bool) -> Result<()> {
        if let Bytes::Disk(d) = &*self.bytes.read().unwrap() {
            let file = d.open(false)?;
            if data_only {
                file.sync_data()
            } else {
                file.sync_all()
            }
            .map_err(storage::host_errno)?;
        }
        Ok(())
    }
    pub fn orphan(&self, value: bool) {
        #[cfg(all(feature = "hostfs", unix))]
        if self.host.is_some() {
            return;
        }
        if let Bytes::Disk(d) = &*self.bytes.read().unwrap() {
            d.backing.remove_on_drop.store(value, Ordering::Relaxed);
        }
    }
}
impl Bytes {
    fn len(&self) -> u64 {
        match self {
            Self::Memory(b) => b.len() as u64,
            Self::Disk(d) => {
                #[cfg(all(feature = "hostfs", unix))]
                if let Some(host) = &d.backing.host {
                    return host.len();
                }
                d.length
            }
        }
    }
    fn read_at(
        &self,
        offset: u64,
        count: usize,
        cache: Option<&mut DiskReadCache>,
    ) -> Result<Vec<u8>> {
        let count = count
            .min(storage::MAX_TRANSFER)
            .min(self.len().saturating_sub(offset) as usize);
        if count == 0 {
            return Ok(Vec::new());
        }
        match self {
            Self::Memory(b) => Ok(b[offset as usize..offset as usize + count].to_vec()),
            Self::Disk(d) => {
                let mut bytes = vec![0; count];
                #[cfg(unix)]
                let n = if let Some(cache) = cache {
                    cache.file(&d.backing, false)?.read_at(&mut bytes, offset)
                } else {
                    d.open(false)?.read_at(&mut bytes, offset)
                }
                .map_err(storage::host_errno)?;
                #[cfg(not(unix))]
                let n = {
                    use std::io::{Read, Seek};
                    let _ = cache;
                    let mut file = d.open(false)?;
                    file.seek(std::io::SeekFrom::Start(offset))
                        .map_err(storage::host_errno)?;
                    file.read(&mut bytes).map_err(storage::host_errno)?
                };
                bytes.truncate(n);
                Ok(bytes)
            }
        }
    }
    fn write_at(
        &mut self,
        offset: u64,
        bytes: &[u8],
        cache: Option<&mut DiskReadCache>,
    ) -> Result<usize> {
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
                #[cfg(unix)]
                let n = if let Some(cache) = cache {
                    cache.file(&d.backing, true)?.write_at(bytes, offset)
                } else {
                    d.open(true)?.write_at(bytes, offset)
                }
                .map_err(storage::host_errno)?;
                #[cfg(not(unix))]
                let n = {
                    use std::io::{Seek, Write};
                    let _ = cache;
                    let mut file = d.open(true)?;
                    file.seek(std::io::SeekFrom::Start(offset))
                        .map_err(storage::host_errno)?;
                    file.write(bytes).map_err(storage::host_errno)?
                };
                d.length = d.length.max(offset + n as u64);
                Ok(n)
            }
        }
    }
}
