// SPDX-License-Identifier: GPL-3.0-or-later
//! Host-owned shared storage. Mappings retain physical storage while logical
//! truncate/EOF remains a guest file property. No host pathname reaches guests.
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::{File, OpenOptions},
    io,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
        unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    },
    ptr::NonNull,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
};

mod readiness;
pub use readiness::{IoSignal, IoSubscription, IoWake, Readiness};
mod pipe;
pub use pipe::NativePipe;
pub const MAX_SHARED_BYTES: usize = 128 * 1024 * 1024;
/// Sparse logical address space is distinct from the retained working-set quota.
pub const MAX_SHARED_LENGTH: usize = 2 * 1024 * 1024 * 1024;
const MAP_BLOCK: usize = 65536;
static NEXT_FILE: AtomicU64 = AtomicU64::new(1);
type Key = (u64, u64);
struct Entry {
    owner: Weak<Inner>,
    transfers: VecDeque<Weak<Transfer>>,
}
struct Transfer {
    _file: SharedFile,
    claimed: AtomicBool,
}
/// Keeps the original inode, logical EOF and budget through an in-flight FD.
/// The receiving service retains this until import acknowledgement or disconnect.
#[derive(Clone)]
pub struct ExportLease(Arc<Transfer>);
impl ExportLease {
    pub fn claimed(&self) -> bool {
        self.0.claimed.load(Ordering::Acquire)
    }
}
fn registry() -> &'static Mutex<BTreeMap<Key, Entry>> {
    static FILES: OnceLock<Mutex<BTreeMap<Key, Entry>>> = OnceLock::new();
    FILES.get_or_init(Mutex::default)
}
fn invalid() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidInput)
}
fn lock_error<T>(_: std::sync::PoisonError<T>) -> io::Error {
    io::Error::other("shared storage lock poisoned")
}
fn host_page() -> usize {
    static PAGE: OnceLock<usize> = OnceLock::new();
    *PAGE.get_or_init(|| {
        // SAFETY: sysconf reads a process constant and retains no pointer.
        let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(value)
            .ok()
            .filter(|v| v.is_power_of_two() && *v <= MAP_BLOCK)
            .unwrap_or(MAP_BLOCK)
    })
}
fn round(value: usize, alignment: usize) -> io::Result<usize> {
    value
        .checked_add(alignment - 1)
        .map(|v| v & !(alignment - 1))
        .ok_or_else(invalid)
}
/// Physical storage accounting survives descriptor/inode closure and GPU leases.
#[derive(Clone)]
pub struct SharedBudget(Arc<BudgetInner>);
struct BudgetInner {
    limit: usize,
    used: AtomicUsize,
}
impl Default for SharedBudget {
    fn default() -> Self {
        Self::new(MAX_SHARED_BYTES)
    }
}
impl SharedBudget {
    pub fn new(limit: usize) -> Self {
        Self(Arc::new(BudgetInner {
            limit,
            used: AtomicUsize::new(0),
        }))
    }
    pub fn available(&self) -> usize {
        self.0
            .limit
            .saturating_sub(self.0.used.load(Ordering::Acquire))
    }
    fn reserve(&self, bytes: usize) -> io::Result<()> {
        self.0
            .used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.0.limit)
            })
            .map(|_| ())
            .map_err(|_| io::Error::from(io::ErrorKind::StorageFull))
    }
    fn release(&self, bytes: usize) {
        self.0.used.fetch_sub(bytes, Ordering::AcqRel);
    }
}
struct Inner {
    file: File,
    key: Key,
    logical: AtomicUsize,
    capacity: AtomicUsize,
    charged: Mutex<BTreeSet<usize>>,
    allocated: AtomicUsize,
    owned: bool,
    budget: SharedBudget,
    resize: Mutex<()>,
    mappings: Mutex<BTreeMap<(usize, usize), Weak<Region>>>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.budget.release(*self.allocated.get_mut());
    }
}
/// Cloneable inode capability, not a guest descriptor or a borrowed byte slice.
#[derive(Clone)]
pub struct SharedFile(Arc<Inner>);
impl std::fmt::Debug for SharedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedFile")
            .field("key", &self.0.key)
            .field("length", &self.len())
            .finish()
    }
}
impl SharedFile {
    pub fn anonymous() -> io::Result<Self> {
        Self::anonymous_in(SharedBudget::default())
    }
    pub fn anonymous_in(budget: SharedBudget) -> io::Result<Self> {
        for _ in 0..32 {
            let serial = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("trames-shared-{}-{serial}", std::process::id()));
            let file = match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(f) => f,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            };
            // The descriptor alone owns the inode; no cleanup pathname is kept.
            std::fs::remove_file(&path)?;
            return Self::register(file, true, budget);
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "shared inode name collision",
        ))
    }
    fn register(file: File, owned: bool, budget: SharedBudget) -> io::Result<Self> {
        let stat = file.metadata()?;
        if !stat.is_file() || stat.len() > MAX_SHARED_LENGTH as u64 {
            return Err(invalid());
        }
        let key = (stat.dev(), stat.ino());
        let mut registry = registry().lock().map_err(lock_error)?;
        if let Some(entry) = registry.get_mut(&key) {
            if let Some(owner) = entry.owner.upgrade() {
                // One acknowledgement per delivered FD, even when the same inode
                // is exported several times or across independent connections.
                while let Some(weak) = entry.transfers.pop_front() {
                    if let Some(lease) = weak.upgrade() {
                        if !lease.claimed.swap(true, Ordering::AcqRel) {
                            break;
                        }
                    }
                }
                return Ok(Self(owner));
            }
        }
        registry.retain(|_, entry| entry.owner.strong_count() != 0);
        let size = stat.len() as usize;
        let capacity = round(size, host_page())?;
        let owner = Arc::new(Inner {
            file,
            key,
            logical: AtomicUsize::new(size),
            capacity: AtomicUsize::new(capacity),
            charged: Mutex::default(),
            allocated: AtomicUsize::new(0),
            owned,
            budget,
            resize: Mutex::default(),
            mappings: Mutex::default(),
        });
        registry.insert(
            key,
            Entry {
                owner: Arc::downgrade(&owner),
                transfers: VecDeque::new(),
            },
        );
        Ok(Self(owner))
    }
    /// Import an FD delivered by the native bridge. Known inodes recover their
    /// original logical-size/lifetime capability instead of inventing a copy.
    pub fn import(fd: OwnedFd) -> io::Result<Self> {
        Self::register(File::from(fd), false, SharedBudget::default())
    }
    pub fn duplicate_fd(&self) -> io::Result<OwnedFd> {
        self.0.file.as_fd().try_clone_to_owned()
    }
    pub fn export(&self) -> io::Result<(OwnedFd, ExportLease)> {
        let fd = self.duplicate_fd()?;
        let lease = Arc::new(Transfer {
            _file: self.clone(),
            claimed: AtomicBool::new(false),
        });
        let mut registry = registry().lock().map_err(lock_error)?;
        let entry = registry.get_mut(&self.key()).ok_or_else(invalid)?;
        entry.transfers.retain(|weak| weak.strong_count() != 0);
        entry.transfers.push_back(Arc::downgrade(&lease));
        Ok((fd, ExportLease(lease)))
    }
    pub fn key(&self) -> Key {
        self.0.key
    }
    pub fn len(&self) -> usize {
        self.0.logical.load(Ordering::Acquire)
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn required_capacity(length: u64) -> Option<u64> {
        usize::try_from(length)
            .ok()
            .and_then(|n| round(n, host_page()).ok())
            .map(|n| n as u64)
    }
    pub fn capacity(&self) -> usize {
        self.0.capacity.load(Ordering::Acquire)
    }
    pub fn allocated(&self) -> usize {
        self.0.allocated.load(Ordering::Acquire)
    }
    /// Charge only ranges that are mapped, written or explicitly allocated.
    /// Merely extending a sparse memfd does not instantiate its holes.
    pub fn reserve_range(&self, offset: usize, length: usize) -> io::Result<()> {
        let end = offset
            .checked_add(length)
            .filter(|n| *n <= MAX_SHARED_LENGTH)
            .ok_or_else(invalid)?;
        if length == 0 {
            return Ok(());
        }
        let page = host_page();
        let range = offset / page..round(end, page)? / page;
        let mut charged = self.0.charged.lock().map_err(lock_error)?;
        let extra = range.clone().filter(|p| !charged.contains(p)).count() * page;
        self.0.budget.reserve(extra)?;
        charged.extend(range);
        self.0.allocated.fetch_add(extra, Ordering::Release);
        Ok(())
    }
    pub fn set_len(&self, length: usize) -> io::Result<()> {
        if !self.0.owned || length > MAX_SHARED_LENGTH {
            return Err(invalid());
        }
        let _resize = self.0.resize.lock().map_err(lock_error)?;
        let old = self.len();
        let needed = round(length, host_page())?;
        if needed > self.capacity() {
            self.0.file.set_len(needed as u64)?;
            self.0.capacity.store(needed, Ordering::Release);
        }
        if length < old {
            // Never remove physical pages from under native/GPU leases. Zero
            // truncated bytes now, so a later grow cannot resurrect old data.
            self.clear_range(length, old - length)?;
        }
        self.0.logical.store(length, Ordering::Release);
        Ok(())
    }
    fn clear_range(&self, offset: usize, length: usize) -> io::Result<()> {
        fn zeros(file: &File, mut start: usize, end: usize) -> io::Result<()> {
            let zeros = [0; 16384];
            while start < end {
                let count = (end - start).min(zeros.len());
                file.write_all_at(&zeros[..count], start as u64)?;
                start += count;
            }
            Ok(())
        }
        let end = offset.checked_add(length).ok_or_else(invalid)?;
        let first = round(offset, host_page())?.min(end);
        let last = (end & !(host_page() - 1)).max(first);
        zeros(&self.0.file, offset, first)?;
        if last > first {
            #[cfg(target_os = "linux")]
            // SAFETY: retained regular inode and validated nonnegative range.
            let punched = unsafe {
                libc::fallocate(
                    self.0.file.as_raw_fd(),
                    3,
                    first as libc::off_t,
                    (last - first) as libc::off_t,
                )
            } == 0;
            #[cfg(target_vendor = "apple")]
            let punched = {
                #[repr(C)]
                struct Punch {
                    flags: u32,
                    reserved: u32,
                    offset: i64,
                    length: i64,
                }
                let mut punch = Punch {
                    flags: 0,
                    reserved: 0,
                    offset: first as i64,
                    length: (last - first) as i64,
                };
                // SAFETY: Darwin F_PUNCHHOLE (99), a live regular FD, public
                // fpunchhole layout, and host-page-aligned retained extent.
                (unsafe { libc::fcntl(self.0.file.as_raw_fd(), 99, &mut punch) }) == 0
            };
            #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
            let punched = false;
            if !punched {
                zeros(&self.0.file, first, last)?;
            }
        }
        zeros(&self.0.file, last, end)
    }
    pub fn read_at(&self, offset: u64, count: usize) -> io::Result<Vec<u8>> {
        let size = self
            .len()
            .saturating_sub(usize::try_from(offset).unwrap_or(usize::MAX))
            .min(count);
        let mut bytes = vec![0; size];
        self.0.file.read_exact_at(&mut bytes, offset)?;
        Ok(bytes)
    }
    pub fn write_at(&self, offset: u64, bytes: &[u8]) -> io::Result<usize> {
        let offset = usize::try_from(offset).map_err(|_| invalid())?;
        let end = offset.checked_add(bytes.len()).ok_or_else(invalid)?;
        if !bytes.is_empty() {
            self.reserve_range(offset, bytes.len())?;
            if end > self.len() {
                self.set_len(end)?;
            }
            self.0.file.write_all_at(bytes, offset as u64)?;
        }
        Ok(bytes.len())
    }
    /// Map retained physical bytes. Callers separately enforce logical EOF; this
    /// permits page-contained guest mappings and safe retained views at truncate.
    pub fn map(&self, offset: usize, length: usize) -> io::Result<Mapping> {
        let end = offset.checked_add(length).ok_or_else(invalid)?;
        if length == 0 || end > self.capacity() {
            return Err(invalid());
        }
        self.reserve_range(offset, length)?;
        let start = offset & !(MAP_BLOCK - 1);
        let mapped_len = round(end - start, MAP_BLOCK)?.min(self.capacity() - start);
        let mut mappings = self.0.mappings.lock().map_err(lock_error)?;
        let key = (start, mapped_len);
        let region = match mappings.get(&key).and_then(Weak::upgrade) {
            Some(region) => region,
            None => {
                // SAFETY: offset and length are host-page aligned inside this
                // retained inode. Owned storage never physically shrinks.
                let pointer = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        mapped_len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_SHARED,
                        self.0.file.as_raw_fd(),
                        start as libc::off_t,
                    )
                };
                if pointer == libc::MAP_FAILED {
                    return Err(io::Error::last_os_error());
                }
                let region = Arc::new(Region {
                    pointer: NonNull::new(pointer.cast()).expect("non-null mmap"),
                    length: mapped_len,
                    _owner: self.0.clone(),
                });
                mappings.retain(|_, p| p.strong_count() != 0);
                mappings.insert(key, Arc::downgrade(&region));
                region
            }
        };
        Ok(Mapping {
            region,
            offset: offset - start,
            length,
        })
    }
}
impl AsFd for SharedFile {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.file.as_fd()
    }
}
struct Region {
    pointer: NonNull<u8>,
    length: usize,
    _owner: Arc<Inner>,
}
// SAFETY: metadata is immutable; raw mapped bytes have no Rust references here.
// Each user must retain its existing CPU-region or protocol buffer ownership.
unsafe impl Send for Region {}
unsafe impl Sync for Region {}
impl Drop for Region {
    fn drop(&mut self) {
        // SAFETY: the final lease owns this exact complete mmap, with no refs.
        unsafe {
            libc::munmap(self.pointer.as_ptr().cast(), self.length);
        }
    }
}
#[derive(Clone)]
pub struct Mapping {
    region: Arc<Region>,
    offset: usize,
    length: usize,
}
impl Mapping {
    pub fn len(&self) -> usize {
        self.length
    }
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
    pub fn pointer(&self) -> *mut u8 {
        self.region.pointer.as_ptr().wrapping_add(self.offset)
    }
    pub fn allocation_pointer(&self) -> *mut u8 {
        self.region.pointer.as_ptr()
    }
    pub fn allocation_len(&self) -> usize {
        self.region.length
    }
    pub fn allocation_offset(&self) -> usize {
        self.offset
    }
    /// # Safety
    /// The caller excludes overlapping CPU writers for the callback. No borrowed
    /// slice may escape; native GPU users retain Mapping and use raw pointers.
    pub unsafe fn with_read<T>(&self, offset: usize, len: usize, f: impl FnOnce(&[u8]) -> T) -> T {
        assert!(offset <= self.length && len <= self.length - offset);
        // SAFETY: proven range and the caller's scoped region ownership.
        f(unsafe { std::slice::from_raw_parts(self.pointer().add(offset), len) })
    }
    /// # Safety
    /// The caller owns exclusive CPU access to this byte region for the callback.
    /// Protocol-invalid GPU races can change pixels, but must not create Rust refs.
    pub unsafe fn with_write<T>(
        &self,
        offset: usize,
        len: usize,
        f: impl FnOnce(&mut [u8]) -> T,
    ) -> T {
        assert!(offset <= self.length && len <= self.length - offset);
        // SAFETY: same retained range and caller's exclusive byte ownership.
        f(unsafe { std::slice::from_raw_parts_mut(self.pointer().add(offset), len) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn in_flight_fds_preserve_logical_eof_and_budget_before_receiver_import() {
        let budget = SharedBudget::new(host_page());
        let file = SharedFile::anonymous_in(budget.clone()).unwrap();
        file.write_at(0, b"abc").unwrap();
        let (cancelled_fd, cancelled) = file.export().unwrap();
        let (fd, lease) = file.export().unwrap();
        drop(cancelled_fd);
        drop(cancelled);
        drop(file);
        assert_eq!(budget.available(), 0);
        let native = SharedFile::import(fd).unwrap();
        assert!(lease.claimed());
        assert_eq!(native.len(), 3);
        assert_eq!(native.read_at(0, 8).unwrap(), b"abc");
        drop(lease);
        assert_eq!(budget.available(), 0);
        // Import recovers the same managed inode, including its resize ownership.
        native.set_len(4).unwrap();
        let mapping = native.map(0, 4).unwrap();
        drop(native);
        assert_eq!(budget.available(), 0);
        drop(mapping);
        assert_eq!(budget.available(), host_page());
    }
    #[test]
    fn fd_import_and_independent_mappings_share_the_original_inode_bytes() {
        let file = SharedFile::anonymous().unwrap();
        file.set_len(131072).unwrap();
        let guest = file.map(4096, 4096).unwrap();
        let host = SharedFile::import(file.duplicate_fd().unwrap()).unwrap();
        assert_eq!(host.key(), file.key());
        let view = host.map(0, 131072).unwrap();
        // SAFETY: single-thread test; scopes end before the other alias is used.
        unsafe {
            guest.with_write(7, 4, |b| b.copy_from_slice(b"test"));
        }
        assert_eq!(file.read_at(4103, 4).unwrap(), b"test");
        unsafe {
            view.with_read(4103, 4, |b| assert_eq!(b, b"test"));
        }
        file.write_at(4103, b"next").unwrap();
        unsafe {
            guest.with_read(7, 4, |b| assert_eq!(b, b"next"));
        }
    }
    #[test]
    fn truncate_retains_physical_leases_and_regrowth_is_zeroed() {
        let file = SharedFile::anonymous().unwrap();
        file.write_at(0, &vec![9; 8192]).unwrap();
        let lease = file.map(0, 8192).unwrap();
        file.set_len(3).unwrap();
        assert_eq!(file.len(), 3);
        assert!(file.capacity() >= 8192);
        assert_eq!(file.read_at(3, 8).unwrap(), []);
        // SAFETY: single-thread owned physical lease remains accessible at EOF.
        unsafe {
            lease.with_read(0, 8, |b| assert_eq!(b, &[9, 9, 9, 0, 0, 0, 0, 0]));
        }
        file.set_len(8192).unwrap();
        assert_eq!(file.read_at(3, 8189).unwrap(), vec![0; 8189]);
        drop(file);
        unsafe {
            lease.with_read(0, 3, |b| assert_eq!(b, &[9; 3]));
        }
    }
    #[test]
    fn ranges_and_physical_budget_are_bounded() {
        let file = SharedFile::anonymous().unwrap();
        assert!(file.map(0, 1).is_err());
        assert!(file.set_len(MAX_SHARED_LENGTH + 1).is_err());
        file.set_len(4096).unwrap();
        assert!(file.map(usize::MAX, 2).is_err());
        assert!(file.write_at(u64::MAX, b"x").is_err());
    }
}

mod socket;
pub use socket::{NativeSocket, MAX_BYTES_OUT, MAX_FDS_OUT};
