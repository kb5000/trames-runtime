// SPDX-License-Identifier: GPL-3.0-or-later
//! Host-owned shared storage. Mappings retain physical storage while logical
//! truncate/EOF remains a guest file property. No host pathname reaches guests.
use std::{
    collections::{BTreeMap, VecDeque},
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

mod custody;
mod sparse;
use sparse::{Charges, Windows, WINDOW};
mod logical_size;
mod syscall_dispatch;
pub use custody::{Admission, Custody, CustodyRead, CustodyWrite, OwnedRead, OwnedWrite};
pub use logical_size::{LogicalSize, SizeCycle};
mod file_transaction;
mod readiness;
pub use file_transaction::{FileTransaction, FileTransactionLease, FileTransactionScope};
pub use readiness::{
    HostSource, IoSignal, IoSubscription, IoWake, Readiness, ReadinessDriver, ResourcePending,
    ResourceWait,
};
mod host_wait;
pub use host_wait::{HostWait, HostWake};
mod peer_close;
pub use peer_close::PeerClose;
mod host_events;
pub use host_events::{HostEvents, HostFd, HostSubscription};
mod pipe;
pub use pipe::NativePipe;
pub const MAX_SHARED_BYTES: usize = 128 * 1024 * 1024;
/// Sparse logical address space is distinct from the retained working-set quota.
pub const MAX_SHARED_LENGTH: usize = isize::MAX as usize;
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
    readiness: Arc<Readiness>,
    context: Option<Arc<dyn SharedFileContext>>,
}
/// Keeps the original inode, logical EOF and budget through an in-flight FD.
/// The receiving service retains this until import acknowledgement or disconnect.
#[derive(Clone)]
pub struct ExportLease(Arc<Transfer>);
impl ExportLease {
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.0.readiness.subscribe(signal)
    }
    pub fn claimed(&self) -> bool {
        self.0.claimed.load(Ordering::Acquire)
    }
}
fn registry() -> &'static Mutex<BTreeMap<Key, Entry>> {
    static FILES: OnceLock<Mutex<BTreeMap<Key, Entry>>> = OnceLock::new();
    FILES.get_or_init(Mutex::default)
}
/// Staging for a read whose length has already been shortened to EOF.
pub fn read_buffer(size: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    bytes.resize(size, 0);
    Ok(bytes)
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
    limit: AtomicUsize,
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
            limit: AtomicUsize::new(limit),
            used: AtomicUsize::new(0),
        }))
    }
    pub fn available(&self) -> usize {
        self.0
            .limit
            .load(Ordering::Relaxed)
            .saturating_sub(self.0.used.load(Ordering::Acquire))
    }
    /// Host-managed sessions retain accounting/leases without a separate
    /// shared-storage byte ceiling. No storage or mappings are allocated here.
    pub fn use_host_memory(&self) {
        self.0.limit.store(usize::MAX, Ordering::Relaxed);
    }
    fn reserve(&self, bytes: usize) -> io::Result<()> {
        self.0
            .used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= self.0.limit.load(Ordering::Relaxed))
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
    logical_observer: OnceLock<LogicalSize>,
    capacity: AtomicUsize,
    charged: Mutex<Charges>,
    windows: Windows,
    allocated: AtomicUsize,
    owned: bool,
    budget: SharedBudget,
    resize: Mutex<()>,
    mappings: Mutex<BTreeMap<(usize, usize), Weak<Region>>>,
    attachment: OnceLock<Arc<dyn std::any::Any + Send + Sync>>,
    accounting: OnceLock<Arc<dyn SharedFileAccounting>>,
    default_context: OnceLock<Arc<dyn SharedFileContext>>,
    transaction: OnceLock<Arc<FileTransaction>>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SharedFileAccess {
    Allocate,
    Write,
    Map,
}
/// Resource accounting follows the original shared inode across native FD
/// transfer. Implementations contain no guest pointers or borrowed task views.
pub trait SharedFileAccounting: std::any::Any + Send + Sync {
    fn as_any(&self) -> &dyn std::any::Any;
    fn reserve(
        &self,
        offset: usize,
        length: usize,
        access: SharedFileAccess,
    ) -> io::Result<Box<dyn SharedFileCharge>>;
    fn truncate(&self, length: usize);
    fn context(&self) -> Option<Arc<dyn SharedFileContext>> {
        None
    }
    fn write_chunk(&self, _offset: usize, length: usize) -> usize {
        length
    }
}
pub trait SharedFileContext: Send + Sync {
    /// Enter only when the native consumer has no explicit task/resource actor.
    /// The returned thread-local guard is never sent to another executor.
    fn enter(&self) -> Box<dyn std::any::Any>;
}
pub trait SharedFileCharge: Send {
    /// New resource state uses the file's existing allocation transaction.
    /// Existing byte operations retain their original concurrent execution.
    fn changed(&self) -> bool;
    fn commit(self: Box<Self>, used: usize) -> Arc<dyn Send + Sync>;
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.budget.release(*self.allocated.get_mut());
    }
}
/// Cloneable inode capability, not a guest descriptor or a borrowed byte slice.
#[derive(Clone)]
pub struct SharedFile(Arc<Inner>, Option<Arc<dyn SharedFileContext>>);
impl std::fmt::Debug for SharedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedFile")
            .field("key", &self.0.key)
            .field("length", &self.len())
            .finish()
    }
}
fn anonymous_file() -> io::Result<File> {
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
        return Ok(file);
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "shared inode name collision",
    ))
}

impl SharedFile {
    /// Called under the original VFS inode admission; native consumers retain
    /// their existing byte/protocol synchronization responsibility.
    pub fn begin_transaction(&self) -> Result<Option<FileTransactionLease>, Arc<dyn ResourceWait>> {
        let _charges = self.0.charged.lock().unwrap();
        self.0.transaction.get_or_init(Arc::default).try_acquire()
    }
    pub fn transaction_available(&self) -> bool {
        self.0
            .transaction
            .get()
            .is_none_or(|transaction| transaction.available())
    }
    fn check_transaction(&self) -> io::Result<()> {
        if let Some(transaction) = self.0.transaction.get() {
            transaction.check()?;
        }
        Ok(())
    }
    pub fn anonymous() -> io::Result<Self> {
        Self::anonymous_in(SharedBudget::default())
    }
    pub fn anonymous_in(budget: SharedBudget) -> io::Result<Self> {
        Self::register(anonymous_file()?, true, budget)
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
                let mut acknowledged = None;
                while let Some(weak) = entry.transfers.pop_front() {
                    if let Some(lease) = weak.upgrade() {
                        if !lease.claimed.swap(true, Ordering::AcqRel) {
                            acknowledged = Some(lease);
                            break;
                        }
                    }
                }
                drop(registry);
                if let Some(lease) = &acknowledged {
                    lease.readiness.notify_locked();
                }
                let context = acknowledged
                    .as_ref()
                    .and_then(|lease| lease.context.clone())
                    .or_else(|| owner.default_context.get().cloned());
                return Ok(Self(owner, context));
            }
        }
        registry.retain(|_, entry| entry.owner.strong_count() != 0);
        let size = stat.len() as usize;
        let capacity = round(size, host_page())?;
        let owner = Arc::new(Inner {
            file,
            key,
            logical: AtomicUsize::new(size),
            logical_observer: OnceLock::new(),
            capacity: AtomicUsize::new(capacity),
            charged: Mutex::default(),
            windows: Windows::default(),
            allocated: AtomicUsize::new(0),
            owned,
            budget,
            resize: Mutex::default(),
            mappings: Mutex::default(),
            attachment: OnceLock::new(),
            accounting: OnceLock::new(),
            default_context: OnceLock::new(),
            transaction: OnceLock::new(),
        });
        registry.insert(
            key,
            Entry {
                owner: Arc::downgrade(&owner),
                transfers: VecDeque::new(),
            },
        );
        Ok(Self(owner, None))
    }
    /// Import an FD delivered by the native bridge. Known inodes recover their
    /// original logical-size/lifetime capability instead of inventing a copy.
    pub fn import(fd: OwnedFd) -> io::Result<Self> {
        Self::register(File::from(fd), false, SharedBudget::default())
    }
    /// A raw consumer cannot resolve segmented data through our inode registry.
    pub fn duplicate_fd(&self) -> io::Result<OwnedFd> {
        if self.0.owned && self.len() > WINDOW {
            return Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
        }
        self.0.file.as_fd().try_clone_to_owned()
    }
    pub fn export(&self) -> io::Result<(OwnedFd, ExportLease)> {
        let _context = self.context_scope();
        // The receiver imports this identity with its lease and recovers all windows.
        let fd = self.0.file.as_fd().try_clone_to_owned()?;
        let lease = Arc::new(Transfer {
            _file: self.clone(),
            claimed: AtomicBool::new(false),
            readiness: Arc::default(),
            context: self
                .0
                .accounting
                .get()
                .and_then(|accounting| accounting.context()),
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
    /// Cold native-resource metadata follows this exact inode through the
    /// existing export/import lease. Ordinary byte IO never consults it.
    pub fn attach<T: Send + Sync + 'static>(&self, value: T) -> io::Result<()> {
        self.0
            .attachment
            .set(Arc::new(value))
            .map_err(|_| io::Error::from(io::ErrorKind::AlreadyExists))
    }
    pub fn attachment<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.0.attachment.get()?.downcast_ref()
    }
    pub fn set_accounting(&self, accounting: Arc<dyn SharedFileAccounting>) -> io::Result<()> {
        let context = accounting.context();
        self.0
            .accounting
            .set(accounting)
            .map_err(|_| io::Error::from(io::ErrorKind::AlreadyExists))?;
        if let Some(context) = context {
            let _ = self.0.default_context.set(context);
        }
        Ok(())
    }
    pub fn accounting<T: SharedFileAccounting>(&self) -> Option<&T> {
        self.0.accounting.get()?.as_any().downcast_ref()
    }
    fn context_scope(&self) -> Option<Box<dyn std::any::Any>> {
        self.1
            .as_ref()
            .or_else(|| self.0.default_context.get())
            .map(|context| context.enter())
    }
    pub fn len(&self) -> usize {
        self.0.logical.load(Ordering::Acquire)
    }
    pub fn logical_size(&self) -> LogicalSize {
        if let Some(size) = self.0.logical_observer.get() {
            return size.clone();
        }
        let _resize = self.0.resize.lock().unwrap();
        self.0
            .logical_observer
            .get_or_init(|| LogicalSize::new(self.len() as u64))
            .clone()
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
        self.with_charge(offset, length, SharedFileAccess::Allocate, || Ok(()))
    }
    fn with_charge<T>(
        &self,
        offset: usize,
        length: usize,
        access: SharedFileAccess,
        operation: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        self.with_charge_and_pin(offset, length, access, |_| length, operation)
            .map(|(value, _pin)| value)
    }
    fn with_charge_and_pin<T>(
        &self,
        offset: usize,
        length: usize,
        access: SharedFileAccess,
        used: impl FnOnce(&T) -> usize,
        operation: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<(T, Option<Arc<dyn Send + Sync>>)> {
        let _context = self.context_scope();
        let end = offset
            .checked_add(length)
            .filter(|n| *n <= MAX_SHARED_LENGTH + 1)
            .ok_or_else(invalid)?;
        if length == 0 {
            return operation().map(|value| (value, None));
        }
        let page = host_page();
        let range = (offset & !(page - 1))..round(end, page)?;
        let mut charges = self.0.charged.lock().map_err(lock_error)?;
        if access != SharedFileAccess::Map {
            self.check_transaction()?;
        }
        let accounting = self
            .0
            .accounting
            .get()
            .map(|accounting| accounting.reserve(offset, length, access))
            .transpose()?;
        let Some((extent, extra)) = charges.extension(range) else {
            if accounting.as_ref().is_none_or(|charge| !charge.changed()) {
                drop(charges);
            }
            return operation().map(|value| {
                let count = used(&value);
                (value, accounting.map(|charge| charge.commit(count)))
            });
        };
        self.0.budget.reserve(extra)?;
        match operation() {
            Ok(value) => {
                charges.insert(extent);
                self.0.allocated.fetch_add(extra, Ordering::Release);
                let count = used(&value);
                Ok((value, accounting.map(|charge| charge.commit(count))))
            }
            Err(error) => {
                self.0.budget.release(extra);
                Err(error)
            }
        }
    }
    pub fn set_len(&self, length: usize) -> io::Result<()> {
        let _context = self.context_scope();
        if !self.0.owned || length > MAX_SHARED_LENGTH {
            return Err(invalid());
        }
        // Preserve the existing charged -> resize lock order for allocation
        // changes. Never hold an accounting callback lock across host IO.
        let _allocation = (self.0.accounting.get().is_some() || self.0.transaction.get().is_some())
            .then(|| self.0.charged.lock().map_err(lock_error))
            .transpose()?;
        self.check_transaction()?;
        let _resize = self.0.resize.lock().map_err(lock_error)?;
        self.resize_locked(length)
    }
    fn resize_locked(&self, length: usize) -> io::Result<()> {
        let old = self.len();
        self.ensure_capacity(length)?;
        if length < old {
            // Never remove physical pages from under native/GPU leases. Zero
            // truncated bytes now, so a later grow cannot resurrect old data.
            if length < WINDOW {
                Self::clear_file_range(&self.0.file, length, old.min(WINDOW) - length)?;
            }
            if old > WINDOW {
                self.0.windows.clear(length.max(WINDOW), old)?;
            }
        }
        self.publish_len(length);
        if length <= old {
            if let Some(accounting) = self.0.accounting.get() {
                accounting.truncate(length);
            }
        }
        Ok(())
    }
    // Caller holds the resize lock. A failed extending write may leave spare
    // native capacity, but cannot publish unwritten bytes past logical EOF.
    fn ensure_capacity(&self, length: usize) -> io::Result<()> {
        let needed = round(length, host_page())?;
        if needed > self.capacity() {
            if self.capacity() < WINDOW {
                self.0.file.set_len(needed.min(WINDOW) as u64)?;
            }
            self.0.capacity.store(needed, Ordering::Release);
        }
        Ok(())
    }
    fn publish_len(&self, length: usize) {
        self.0.logical.store(length, Ordering::Release);
        if let Some(size) = self
            .0
            .logical_observer
            .get()
            .filter(|s| s.load(Ordering::Relaxed) != length as u64)
        {
            size.store(length as u64, Ordering::Relaxed);
        }
    }
    fn clear_file_range(file: &File, offset: usize, length: usize) -> io::Result<()> {
        fn zeros(file: &File, mut start: usize, end: usize) -> io::Result<()> {
            let zeros = [0; 16384];
            let mut current = [0; 16384];
            while start < end {
                let count = (end - start).min(zeros.len());
                file.read_exact_at(&mut current[..count], start as u64)?;
                if current[..count].iter().any(|byte| *byte != 0) {
                    file.write_all_at(&zeros[..count], start as u64)?;
                }
                start += count;
            }
            Ok(())
        }
        if length == 0 {
            return Ok(());
        }
        let end = offset.checked_add(length).ok_or_else(invalid)?;
        let first = round(offset, host_page())?.min(end);
        let last = (end & !(host_page() - 1)).max(first);
        zeros(file, offset, first)?;
        if last > first {
            #[cfg(target_os = "linux")]
            // SAFETY: retained regular inode and validated nonnegative range.
            let punched = unsafe {
                libc::fallocate(
                    file.as_raw_fd(),
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
                (unsafe { libc::fcntl(file.as_raw_fd(), 99, &mut punch) }) == 0
            };
            #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
            let punched = false;
            if !punched {
                // A filesystem without hole punching must not materialize a
                // sparse window by writing zeroes into every hole.
                zeros(file, first, last)?;
            }
        }
        zeros(file, last, end)
    }
    pub fn read_at(&self, offset: u64, count: usize) -> io::Result<Vec<u8>> {
        let size = self
            .len()
            .saturating_sub(usize::try_from(offset).unwrap_or(usize::MAX))
            .min(count);
        let mut bytes = read_buffer(size)?;
        if size != 0 {
            if self.0.owned && offset + size as u64 > WINDOW as u64 {
                self.read_windows(offset as usize, &mut bytes)?;
            } else {
                self.0.file.read_exact_at(&mut bytes, offset)?;
            }
        }
        Ok(bytes)
    }
    pub fn write_at(&self, offset: u64, bytes: &[u8]) -> io::Result<usize> {
        let _context = self.context_scope();
        let offset = usize::try_from(offset).map_err(|_| invalid())?;
        let end = offset.checked_add(bytes.len()).ok_or_else(invalid)?;
        if bytes.is_empty() {
            return Ok(0);
        }
        if end > MAX_SHARED_LENGTH {
            return Err(invalid());
        }
        let chunk = |offset, length| {
            self.0
                .accounting
                .get()
                .map_or(length, |accounting| accounting.write_chunk(offset, length))
        };
        if (!self.0.owned || end <= WINDOW) && chunk(offset, bytes.len()) >= bytes.len() {
            return self.write_part(offset, bytes.len(), || {
                self.0.file.write_at(bytes, offset as u64)
            });
        }
        // Each completed window is a valid partial write if a later backing
        // allocation or write fails.
        let mut done = 0;
        while done < bytes.len() {
            let at = offset + done;
            let local = if self.0.owned { at % WINDOW } else { at };
            let remaining = bytes.len() - done;
            let n = remaining
                .min(if self.0.owned {
                    WINDOW - local
                } else {
                    remaining
                })
                .min(chunk(at, remaining).max(1));
            let part = &bytes[done..done + n];
            let result = self.write_part(at, n, || {
                if !self.0.owned || at < WINDOW {
                    self.0.file.write_at(part, at as u64)
                } else {
                    let file = self.0.windows.get(at - local, true)?.unwrap();
                    file.write_at(part, local as u64)
                }
            });
            match result {
                Ok(written) if written == n => done += written,
                Ok(written) => return Ok(done + written),
                Err(error) if ResourcePending::from_io(&error).is_some() => {
                    return Err(ResourcePending::add_progress(error, done));
                }
                Err(_) if done != 0 => return Ok(done),
                Err(error) => return Err(error),
            }
        }
        Ok(done)
    }
    fn write_part(
        &self,
        offset: usize,
        length: usize,
        write: impl FnOnce() -> io::Result<usize>,
    ) -> io::Result<usize> {
        self.with_charge_and_pin(
            offset,
            length,
            SharedFileAccess::Write,
            |written| *written,
            || {
                let end = offset + length;
                if end > self.len() {
                    let _resize = self.0.resize.lock().map_err(lock_error)?;
                    if end > self.len() {
                        if !self.0.owned {
                            return Err(invalid());
                        }
                        self.ensure_capacity(end)?;
                        let written = write()?;
                        if written != 0 && offset + written > self.len() {
                            self.publish_len(offset + written);
                        }
                        return Ok(written);
                    }
                }
                write()
            },
        )
        .map(|(written, _pin)| written)
    }
    /// Map retained physical bytes. Callers separately enforce logical EOF; this
    /// permits page-contained guest mappings and safe retained views at truncate.
    pub fn map(&self, offset: usize, length: usize) -> io::Result<Mapping> {
        let end = offset.checked_add(length).ok_or_else(invalid)?;
        if length == 0 || end > self.capacity() {
            return Err(invalid());
        }
        let start = offset & !(MAP_BLOCK - 1);
        let mapped_len = round(end - start, MAP_BLOCK)?.min(self.capacity() - start);
        let mut mappings = self.0.mappings.lock().map_err(lock_error)?;
        let key = (start, mapped_len);
        let (region, accounting) = match mappings.get(&key).and_then(Weak::upgrade) {
            Some(region) => self.with_charge_and_pin(
                offset,
                length,
                SharedFileAccess::Map,
                |_| length,
                || Ok(region),
            )?,
            None => {
                let (region, accounting) = self.with_charge_and_pin(
                    offset,
                    length,
                    SharedFileAccess::Map,
                    |_| length,
                    || self.map_region(start, mapped_len).map(Arc::new),
                )?;
                mappings.retain(|_, p| p.strong_count() != 0);
                mappings.insert(key, Arc::downgrade(&region));
                (region, accounting)
            }
        };
        Ok(Mapping {
            region,
            offset: offset - start,
            length,
            _accounting: accounting,
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
    file_offset: Option<u64>,
    window: Option<Arc<File>>,
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
    _accounting: Option<Arc<dyn Send + Sync>>,
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
    /// Physical alias for an owned file whose retained storage never shrinks.
    /// Logical EOF remains independent. Foreign files and composite windows do
    /// not acquire this capability merely because they have a descriptor.
    pub fn file_alias(&self) -> Option<(BorrowedFd<'_>, u64)> {
        let offset = self.region.file_offset?;
        let file = self
            .region
            .window
            .as_deref()
            .unwrap_or(&self.region._owner.file);
        Some((file.as_fd(), offset))
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
    fn resource_wait_keeps_committed_write_prefix_instead_of_returning_a_short_write() {
        struct Wait {
            ready: AtomicBool,
            changed: Arc<Readiness>,
        }
        impl ResourceWait for Wait {
            fn ready(&self) -> bool {
                self.ready.load(Ordering::Relaxed)
            }
            fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
                vec![self.changed.subscribe(signal)]
            }
        }
        struct Account(Arc<Wait>);
        struct Loan;
        impl SharedFileCharge for Loan {
            fn changed(&self) -> bool {
                true
            }
            fn commit(self: Box<Self>, _: usize) -> Arc<dyn Send + Sync> {
                Arc::new(())
            }
        }
        impl SharedFileAccounting for Account {
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
            fn reserve(
                &self,
                offset: usize,
                _: usize,
                _: SharedFileAccess,
            ) -> io::Result<Box<dyn SharedFileCharge>> {
                if offset != 0 && !self.0.ready() {
                    Err(ResourcePending::io_error(self.0.clone()))
                } else {
                    Ok(Box::new(Loan))
                }
            }
            fn truncate(&self, _: usize) {}
            fn write_chunk(&self, _: usize, _: usize) -> usize {
                1
            }
        }
        let wait = Arc::new(Wait {
            ready: AtomicBool::new(false),
            changed: Arc::default(),
        });
        let file = SharedFile::anonymous().unwrap();
        file.set_accounting(Arc::new(Account(wait.clone())))
            .unwrap();
        let error = file.write_at(0, b"abc").unwrap_err();
        let pending = ResourcePending::detail(&error).unwrap();
        assert_eq!(pending.progress, 1);
        assert!(!pending.wait.ready());
        assert_eq!(file.read_at(0, 3).unwrap(), b"a");
        wait.ready.store(true, Ordering::Relaxed);
        wait.changed.notify_atomic();
        assert_eq!(
            file.write_at(pending.progress as u64, &b"abc"[pending.progress..])
                .unwrap(),
            2
        );
        assert_eq!(file.read_at(0, 3).unwrap(), b"abc");
    }
    #[test]
    fn export_acknowledgement_notifies_after_releasing_the_shared_inode_registry() {
        struct Target {
            file: SharedFile,
            calls: AtomicUsize,
        }
        impl IoWake for Target {
            fn wake_io(&self, _: &Arc<IoSignal>) {
                // Re-entering export needs the same registry as import.
                drop(self.file.export().unwrap());
                self.calls.fetch_add(1, Ordering::Relaxed);
            }
        }
        let file = SharedFile::anonymous().unwrap();
        let (fd, lease) = file.export().unwrap();
        let target = Arc::new(Target {
            file,
            calls: AtomicUsize::new(0),
        });
        let erased: Arc<dyn IoWake> = target.clone();
        let signal = IoSignal::new(1, Arc::downgrade(&erased));
        let _subscription = lease.subscribe(&signal);
        let (send, receive) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            send.send(SharedFile::import(fd).unwrap()).unwrap();
        });
        let imported = receive
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        worker.join().unwrap();
        assert_eq!(imported.key(), target.file.key());
        assert!(lease.claimed());
        assert_eq!(target.calls.load(Ordering::Relaxed), 1);
    }

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
        let (physical, offset) = lease.file_alias().unwrap();
        assert_eq!(offset, 0);
        let physical_length = unsafe {
            let mut stat: libc::stat = std::mem::zeroed();
            assert_eq!(libc::fstat(physical.as_raw_fd(), &mut stat), 0);
            stat.st_size
        };
        file.set_len(3).unwrap();
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(physical.as_raw_fd(), &mut stat) }, 0);
        assert_eq!(stat.st_size, physical_length);
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
    fn max_sparse_eof_aliases_high_pages_and_restarts_with_zeroes() {
        let page = host_page();
        let file = SharedFile::anonymous_in(SharedBudget::new(4 * page)).unwrap();
        file.set_len(MAX_SHARED_LENGTH).unwrap();
        assert_eq!(file.allocated(), 0);
        assert_eq!(
            file.read_at((MAX_SHARED_LENGTH - 3) as u64, 32).unwrap(),
            [0; 3]
        );
        assert!(file.reserve_range(0, MAX_SHARED_LENGTH).is_err());
        assert_eq!(file.allocated(), 0);
        file.write_at((MAX_SHARED_LENGTH - 3) as u64, b"end")
            .unwrap();
        let (token, lease) = file.export().unwrap();
        let peer = SharedFile::import(token).unwrap();
        assert!(lease.claimed());
        assert_eq!(peer.len(), MAX_SHARED_LENGTH);
        assert_eq!(
            peer.read_at((MAX_SHARED_LENGTH - 3) as u64, 5).unwrap(),
            b"end"
        );
        let at = WINDOW - page;
        file.write_at((WINDOW - 1) as u64, b"ab").unwrap();
        let crossing = peer.map(at, 2 * page).unwrap();
        // SAFETY: the test accesses sequentially and retains the mapped views.
        unsafe {
            crossing.with_read(page - 1, 2, |b| assert_eq!(b, b"ab"));
            crossing.with_write(page, 2, |b| b.copy_from_slice(b"xy"));
        }
        assert_eq!(file.read_at((WINDOW - 1) as u64, 3).unwrap(), b"axy");
        assert_eq!(file.allocated(), 3 * page);
        assert!(file.duplicate_fd().is_err());
        peer.set_len(WINDOW).unwrap();
        unsafe {
            crossing.with_read(page - 1, 3, |b| assert_eq!(b, &[b'a', 0, 0]));
        }
        file.set_len(MAX_SHARED_LENGTH).unwrap();
        assert_eq!(
            peer.read_at((MAX_SHARED_LENGTH - 3) as u64, 3).unwrap(),
            [0; 3]
        );
    }
    #[test]
    fn physical_aliases_keep_high_window_offsets_and_reject_composite_or_foreign_files() {
        let page = host_page();
        let file = SharedFile::anonymous().unwrap();
        file.write_at((WINDOW + page + 19) as u64, b"x").unwrap();
        let high = file.map(WINDOW + page, page).unwrap();
        let (fd, offset) = high.file_alias().unwrap();
        let original = File::from(fd.try_clone_to_owned().unwrap());
        assert_eq!(offset + high.allocation_offset() as u64, page as u64);
        let mut byte = [0];
        original.read_exact_at(&mut byte, page as u64 + 19).unwrap();
        assert_eq!(byte, *b"x");
        let composite = file.map(WINDOW - page, 2 * page).unwrap();
        assert!(composite.file_alias().is_none());
        drop(file);
        drop(original);
        // The actual distant inode outlives the logical file handle.
        let original = File::from(high.file_alias().unwrap().0.try_clone_to_owned().unwrap());
        original.read_exact_at(&mut byte, page as u64 + 19).unwrap();
        assert_eq!(byte, *b"x");
        let foreign = anonymous_file().unwrap();
        foreign.set_len(page as u64).unwrap();
        let imported = SharedFile::import(foreign.into()).unwrap();
        assert!(imported.map(0, page).unwrap().file_alias().is_none());
    }

    #[test]
    fn sparse_charges_coalesce_overlaps_and_failed_operations_refund_quota() {
        let page = host_page();
        let budget = SharedBudget::new(7 * page);
        let file = SharedFile::anonymous_in(budget.clone()).unwrap();
        for (start, len) in [(1, 2), (5, 2), (2, 4), (1, 6)] {
            file.reserve_range(start * page, len * page).unwrap();
        }
        assert_eq!(file.allocated(), 6 * page);
        assert!(file.reserve_range(0, 8 * page).is_err());
        assert!(file
            .with_charge(0, page, SharedFileAccess::Allocate, || Err::<(), _>(
                invalid()
            ))
            .is_err());
        assert_eq!(budget.available(), page);
        file.reserve_range(0, page).unwrap();
        assert_eq!(file.allocated(), 7 * page);
    }
    #[test]
    fn write_crossing_quota_boundary_publishes_only_completed_prefix() {
        let file = SharedFile::anonymous_in(SharedBudget::new(host_page())).unwrap();
        assert_eq!(file.write_at((WINDOW - 2) as u64, b"abcd").unwrap(), 2);
        assert_eq!(file.len(), WINDOW);
        assert_eq!(file.read_at((WINDOW - 2) as u64, 4).unwrap(), b"ab");
        assert_eq!(file.allocated(), host_page());
        assert!(file.write_at(WINDOW as u64, b"cd").is_err());
        assert_eq!(file.len(), WINDOW);
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

pub mod boottime;

mod host_protocol;
pub use host_protocol::{HostProtocol, HostProtocols, ProtocolInterests};
