// SPDX-License-Identifier: GPL-3.0-or-later
//! Page-sized virtual backing objects, with no host pointers exposed to guests.
use super::*;
static BACKING_REVISION: AtomicU64 = AtomicU64::new(0);
static EXTERNAL_REVISION: AtomicU64 = AtomicU64::new(0);
pub fn external_memory_changed() {
    EXTERNAL_REVISION.fetch_add(1, Ordering::Relaxed);
}
pub(super) fn external_revision() -> u64 {
    EXTERNAL_REVISION.load(Ordering::Relaxed)
}
/// Notify decoder caches and exclusive monitors about externally visible changes.
pub fn backing_changed() {
    BACKING_REVISION.fetch_add(1, Ordering::Relaxed);
}
pub(super) fn backing_revision() -> u64 {
    BACKING_REVISION.load(Ordering::Relaxed)
}
/// Thread-safe cold page-in capability. Namespace/OFD metadata stays in VFS;
/// this handle retains only the byte resource needed by a reached CPU page.
pub trait PageSource: Send + Sync {
    /// A missing asynchronous page returns MemoryError::Pending with its
    /// original PageWait. Never block a CPU worker or encode a guest errno.
    fn load(&self) -> Result<std::sync::Arc<SharedPage>, MemoryError>;
}
/// A file VMA's cold mremap hook. The caller owns original mm custody and
/// restores moved pages if the provider rejects the destination VMA.
pub trait MappingRemap: Send + Sync {
    fn remapped(&self, mm: u64, address: u64) -> Result<(), MemoryError>;
}

/// One accepted original writeback. A provider may finish on its existing
/// resource reply path; the caller keeps guest pointers and VM custody outside.
pub trait SyncCompletion: Send {
    fn complete(self: Box<Self>, result: Result<(), MemoryError>);
    /// Retry the same accepted resource after an inode transaction becomes
    /// available. Source executors reacquire original layout admission first.
    fn retry(self: Box<Self>) {
        self.complete(Err(MemoryError::BackingIo(5)));
    }
}
pub trait SyncExecutor: Send + Sync {
    fn submit(&self, resource: Arc<dyn SyncResource>, completion: Box<dyn SyncCompletion>);
}

/// A cold, accepted writeback resource, captured before leaving the caller's
/// actor scope. It owns no guest address, VMA lookup or running CPU view.
pub trait SyncResource: Send + Sync {
    fn layout(&self) -> Option<Arc<crate::layout::Layout>>;
    fn sync(&self) -> Result<(), MemoryError>;
    /// The accepted executor ended before this resource could complete. File
    /// providers retain the error on their original mapping/OFD, even for the
    /// void VMA-close path; this never retries a guest syscall.
    /// A provider which has already completed ignores retirement. Its terminal
    /// result and callbacks cannot be replaced or published a second time.
    fn failed(&self, _error: MemoryError) {}
    fn sync_async(
        &self,
        completion: Box<dyn SyncCompletion>,
    ) -> Result<(), Box<dyn SyncCompletion>> {
        Err(completion)
    }
}
struct BackingSync(Arc<dyn PageBacking>);
impl SyncResource for BackingSync {
    fn layout(&self) -> Option<Arc<crate::layout::Layout>> {
        self.0.layout()
    }
    fn sync(&self) -> Result<(), MemoryError> {
        self.0.sync()
    }
}
pub(super) struct BackingClose {
    pub(super) resource: Arc<dyn SyncResource>,
    pub(super) _backing: Arc<dyn PageBacking>,
}
impl SyncResource for BackingClose {
    fn layout(&self) -> Option<Arc<crate::layout::Layout>> {
        self.resource.layout()
    }
    fn sync(&self) -> Result<(), MemoryError> {
        self.resource.sync()
    }
    fn failed(&self, error: MemoryError) {
        self.resource.failed(error);
    }
    fn sync_async(
        &self,
        completion: Box<dyn SyncCompletion>,
    ) -> Result<(), Box<dyn SyncCompletion>> {
        self.resource.sync_async(completion)
    }
}

/// Accepted original writeback resources. No guest pointers, Memory borrow or
/// View survives capture; unmap/replacement cannot redirect a parked sync.
#[derive(Default)]
pub struct SyncRange {
    objects: Vec<Arc<dyn SyncResource>>,
}
impl SyncRange {
    pub(crate) fn capture<'a>(
        objects: impl Iterator<Item = &'a Arc<dyn PageBacking>>,
    ) -> Result<Self, MemoryError> {
        let mut synced = std::collections::BTreeSet::new();
        Ok(Self {
            objects: objects
                .filter(|b| b.sync_required() && b.sync_key().is_none_or(|key| synced.insert(key)))
                .map(|backing| {
                    backing.sync_resource().unwrap_or_else(|| {
                        Ok(Arc::new(BackingSync(backing.clone())) as Arc<dyn SyncResource>)
                    })
                })
                .collect::<Result<_, _>>()?,
        })
    }
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
    pub(crate) fn source_scoped(&self) -> bool {
        self.objects.iter().all(|object| object.layout().is_some())
    }
    pub fn into_resources(self) -> Vec<Arc<dyn SyncResource>> {
        self.objects
    }
    pub fn run(self) -> Result<(), MemoryError> {
        for object in self.objects {
            object.sync()?;
        }
        Ok(())
    }
}

/// Retained original mapping resources, movable with their address space.
/// Implementations synchronize their own metadata and physical byte owners;
/// Send + Sync does not authorize concurrent structural changes to a Memory.
pub trait PageBacking: Send + Sync {
    /// Physical file or shmem page membership used only at mapping transitions and by smaps.
    fn mapped_residents(&self) -> Option<&MappedResidents> {
        None
    }
    fn proc_dirty(&self) -> bool {
        false
    }
    fn proc_file(&self) -> Option<MappingFileInfo> {
        None
    }
    fn proc_shmem_inode(&self) -> Option<u64> {
        None
    }
    /// Cold fork policy for device mappings (Linux VM_DONTCOPY). Thread clones
    /// sharing the same mm keep the original mapping and never consult this.
    fn inherit_on_fork(&self) -> bool {
        true
    }
    /// Cold VMA growth policy (Linux VM_DONTEXPAND). Byte access is unaffected.
    fn expandable(&self) -> bool {
        true
    }
    fn mapping_remap(&self) -> Option<Arc<dyn MappingRemap>> {
        None
    }
    /// Retained immutable Views of device pages may need the original VMA/OFD
    /// lifetime even without writeback. Kept in cold snapshot metadata only;
    /// ordinary CPU frames and accesses do not gain another backing lookup.
    fn retain_in_view(&self) -> bool {
        false
    }
    /// Publication admission for an original file's physical layout. Only
    /// mapping/snapshot construction consults this; CPU byte access does not.
    fn layout(&self) -> Option<Arc<crate::layout::Layout>> {
        None
    }
    /// Device publications can change executable bytes outside CPU write hooks.
    /// Only address spaces that map such storage executable watch its code epoch.
    fn external_code_updates(&self) -> bool {
        false
    }
    /// Anonymous shared zeros need a charge only on writes; file data is charged
    /// on the first actual read or write, never on VMA/permission metadata.
    fn charge_reads(&self) -> bool {
        true
    }

    /// Check/read/write/version and scoped native-span methods never re-enter
    /// their containing Memory or invoke an arbitrary host callback. Allows one
    /// local VM borrow per interpreter slice or native call; external/custom
    /// backings conservatively opt out. Span methods may invoke only the supplied
    /// memory operation, which cannot yield to guest code while bytes are borrowed.
    fn cpu_borrow_safe(&self) -> bool {
        false
    }
    /// Stable backing-page identity for quiescent parallel snapshots. External
    /// shared backings must opt in; this key describes their original byte owner.
    fn parallel_key(&self) -> Option<(u64, u64)> {
        None
    }
    /// Share resident physical bytes with workers. Provider metadata has its own
    /// synchronization; byte access keeps the existing SharedPage protocol.
    fn shared_page(&self) -> Option<std::sync::Arc<SharedPage>> {
        None
    }
    /// No byte read/allocation: a stable resource handle for deferred page-in.
    fn page_source(&self) -> Option<std::sync::Arc<dyn PageSource>> {
        None
    }
    /// Joined snapshot metadata is unchanged when version() and check() match.
    /// Opt-in providers must version every physical-storage/key replacement as
    /// well as byte changes; their native-span capabilities must remain stable.
    /// Unknown/custom providers retain full per-epoch preparation.
    fn parallel_versioned(&self) -> bool {
        false
    }
    /// Optional change domain for versioned providers at joined checkpoints.
    /// The identity is stable for the mapping lifetime and shared by all pages
    /// covered by the generation. An unchanged generation guarantees unchanged
    /// version/check results, storage identities and native-span capabilities
    /// for every page in that domain. Notify backing_changed() on changes too.
    /// Unknown providers retain individual page checks at mapping preparation.
    fn parallel_change_domain(&self) -> Option<(u64, u64)> {
        None
    }
    /// Data-frame metadata may have a cheaper stable domain than byte versions.
    /// An unchanged generation guarantees infallible unchanged check results,
    /// the same retained canonical shared_page, keys and native capabilities.
    /// Byte writes must remain visible through that shared page and its live
    /// version. This override is never used for executable mappings. Unknown
    /// providers retain the original version/check domain above.
    fn parallel_metadata_domain(&self) -> Option<(u64, u64)> {
        self.parallel_change_domain()
    }
    /// Local mapping commits may run while other address spaces retain this
    /// provider's exported pages. Opt-in requires retained physical owners and
    /// guarded coordinator byte access: check/version/publish/drop and local
    /// mapping preparation cannot invalidate another View's storage or bypass
    /// its byte/monitor ownership. Layout-changing file operations still join.
    /// Unknown providers retain transitive backing-domain quiescence.
    fn parallel_commit_isolated(&self) -> bool {
        false
    }
    /// Stable, page-aligned byte offset within parallel_change_domain(). Used
    /// only to index mapping metadata, never to translate a guest byte access.
    fn parallel_domain_offset(&self) -> Option<u64> {
        None
    }
    /// Conservative changed byte ranges since a previously observed domain
    /// generation. Some must cover EVERY version/check/storage/capability change
    /// in that interval. None requests the existing complete domain scan (also
    /// on layout/EOF changes or expired history). No byte-publication fence.
    fn parallel_changes_since(&self, _generation: u64) -> Option<Vec<std::ops::Range<u64>>> {
        None
    }
    /// Range hints use the selected metadata domain's token. Providers with a
    /// separate metadata generation must not interpret it as a byte generation.
    fn parallel_metadata_changes_since(
        &self,
        generation: u64,
    ) -> Option<Vec<std::ops::Range<u64>>> {
        self.parallel_changes_since(generation)
    }
    /// Publish dirty metadata after this address space's workers have joined,
    /// without copying bytes. Isolated providers may have live other-VM users.
    /// Called only for a provider that returned shared_page().
    fn publish_write(&self, _offset: usize, _len: usize) -> Result<(), MemoryError> {
        Err(MemoryError::BackingIo(95))
    }
    /// Canonical external data with no dirty-range/persistence work may publish
    /// hardware writes once per original allocation through its existing epoch.
    /// Every exported page's version and software reservation must include that
    /// epoch. No byte/storage/check change may require a per-page commit hook.
    /// Executable mappings never use this optimization. Other providers retain
    /// their original dirty-page publication, including file writeback.
    fn hardware_write_epoch(&self) -> Option<std::sync::Arc<std::sync::atomic::AtomicU64>> {
        None
    }
    fn check(&self, address: u64) -> Result<(), MemoryError>;
    /// Immutable shared-mapping write-fault policy, distinct from VMA access
    /// permissions. Device control mappings can admit PROT_WRITE while some
    /// pages fault with SIGBUS on stores. Translation preparation caches this;
    /// changing it requires replacing the original backing/mapping.
    fn write_fault(&self, _address: u64) -> Option<MemoryError> {
        None
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError>;
    fn write(&self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError>;
    /// Resident operations cannot perform fallible backing I/O after complete
    /// permission/EOF preflight. External backings must explicitly opt in.
    fn native_resident(&self) -> bool {
        false
    }
    /// Invoke once on a coherent resident fragment, or return false without
    /// invoking. Implementations retain the backing borrow for the callback.
    /// The caller holds original-mm custody; retained Views keep their existing
    /// physical-byte protocol. This call does not transfer structural custody.
    fn with_read(
        &self,
        _offset: usize,
        _len: usize,
        _f: &mut dyn FnMut(&[u8]),
    ) -> Result<bool, MemoryError> {
        Ok(false)
    }
    /// As above, publishing version/dirty metadata when the write completes.
    fn with_write(
        &self,
        _offset: usize,
        _len: usize,
        _f: &mut dyn FnMut(&mut [u8]),
    ) -> Result<bool, MemoryError> {
        Ok(false)
    }
    fn sync(&self) -> Result<(), MemoryError>;
    /// Capture daemon identity/credentials at the accepted syscall, rather than
    /// looking them up on a later native file worker. Ordinary providers keep
    /// the default retained-backing resource without an actor-dependent path.
    fn sync_resource(&self) -> Option<Result<Arc<dyn SyncResource>, MemoryError>> {
        None
    }
    /// Cold writeback selection only. Providers whose sync body is a no-op
    /// need no retained job or backing publication. Never queried by byte I/O.
    fn sync_required(&self) -> bool {
        true
    }
    fn sync_key(&self) -> Option<u64> {
        None
    }
    fn version(&self) -> u64;
    fn writable(&self) -> bool;
    /// Maximum private/COW permission for special device mappings. Ordinary
    /// read-only files may still create writable private copies.
    fn private_writable(&self) -> bool {
        true
    }
    /// Original VMA removal, before retained byte snapshots are reclaimed.
    fn unmapped(&self) {}
    /// VMA-close writeback, separate from msync/FSYNC. Capture before removing
    /// the original page; the caller waits after releasing mapping custody.
    fn close_resource(&self) -> Option<Arc<dyn SyncResource>> {
        None
    }
    /// Maximum mapping permission, sampled by mmap/mprotect, never CPU loads.
    fn executable(&self) -> bool {
        true
    }
    fn next_page(&self, pages: u64) -> Result<Arc<dyn PageBacking>, MemoryError>;
}
/// A physical backing page may appear in several guest page tables. Execution
/// pins and file-cache references do not constitute additional mappings.
#[derive(Default)]
pub struct MappedResidents(
    parking_lot::Mutex<Members>,
    Arc<crate::cgroup_memory::SharedCharge>,
);
#[derive(Default)]
enum Members {
    #[default]
    Empty,
    One(std::sync::Weak<Charge>),
    Several(Vec<std::sync::Weak<Charge>>),
}
impl MappedResidents {
    /// A non-mmap cache fill reserves its physical owner on the requesting
    /// worker, before IO. Later aliases acquire only their own RSS tickets;
    /// a daemon delivering the bytes cannot become the physical owner.
    pub fn reserve_cache(&self) -> Result<(), MemoryError> {
        self.1.get().map(|_| ())
    }
    fn attach(&self, charge: &Arc<Charge>, private: bool) {
        charge.attach_cache(self.1.clone(), private);
        let mut owners = self.0.lock();
        let next = Arc::downgrade(charge);
        match &mut *owners {
            Members::Empty => *owners = Members::One(next),
            Members::One(first) if first.strong_count() == 0 => *first = next,
            Members::One(first) => *owners = Members::Several(vec![first.clone(), next]),
            Members::Several(items) => {
                items.retain(|w| w.strong_count() != 0);
                items.push(next);
            }
        }
    }
    fn detach(&self, charge: &Arc<Charge>) {
        let mut owners = self.0.lock();
        match &mut *owners {
            Members::One(w) if w.as_ptr() == Arc::as_ptr(charge) => *owners = Members::Empty,
            Members::Several(items) => {
                items.retain(|w| w.as_ptr() != Arc::as_ptr(charge) && w.strong_count() != 0);
                if items.len() <= 1 {
                    *owners = items.pop().map_or(Members::Empty, Members::One);
                }
            }
            _ => {}
        }
    }
    pub(super) fn resident_count(&self) -> usize {
        let resident = |w: &std::sync::Weak<Charge>| w.upgrade().is_some_and(|c| c.resident());
        match &*self.0.lock() {
            Members::Empty => 0,
            Members::One(w) => usize::from(resident(w)),
            Members::Several(items) => items.iter().filter(|w| resident(w)).count(),
        }
    }
}
#[derive(Clone)]
pub(super) struct Backed {
    pub object: Arc<dyn PageBacking>,
    pub shared: bool,
    pub private_copy: bool,
}
impl Backed {
    fn attach(&self, charge: &Arc<Charge>) {
        if !self.private_copy {
            if let Some(owners) = self.object.mapped_residents() {
                owners.attach(charge, !self.shared);
            }
        }
    }
    pub(super) fn detach(&self, charge: &Arc<Charge>) {
        if self.private_copy {
            return;
        }
        if let Some(owners) = self.object.mapped_residents() {
            owners.detach(charge);
        }
    }
    pub(super) fn detached_copy(&mut self, charge: &Arc<Charge>) {
        self.detach(charge);
        self.private_copy = true;
    }
}
impl Page {
    pub(super) fn write_fault(&self, address: u64) -> Option<MemoryError> {
        self.backing
            .as_ref()
            .filter(|backing| backing.shared)
            .and_then(|backing| backing.object.write_fault(address))
    }
    pub(super) fn register_backing(&self) {
        if let Some(b) = &self.backing {
            b.attach(&self.charge);
        }
    }
    pub(super) fn parallel_changes_since(
        &self,
        generation: u64,
    ) -> Option<Vec<std::ops::Range<u64>>> {
        let backing = self.backing.as_ref()?.object.as_ref();
        if self.permissions.execute {
            backing.parallel_changes_since(generation)
        } else {
            backing.parallel_metadata_changes_since(generation)
        }
    }
    pub(super) fn parallel_domain(&self) -> Option<(u64, u64)> {
        let backing = self.backing.as_ref()?.object.as_ref();
        if !backing.parallel_versioned() {
            return None;
        }
        if self.permissions.execute {
            backing.parallel_change_domain()
        } else {
            backing.parallel_metadata_domain()
        }
    }
    #[inline]
    pub(super) fn check_backing(&self, address: u64) -> Result<(), MemoryError> {
        if let Some(b) = &self.backing {
            b.object.check(address)?;
        }
        Ok(())
    }
    /// An asynchronous provider must finish page-in before this mm records a
    /// resident page or starts COW. Resident/native providers keep their existing
    /// byte path; ordinary anonymous RAM never enters this backing-only branch.
    #[inline]
    pub(super) fn prepare_source(&self, address: u64) -> Result<(), MemoryError> {
        if let Some(b) = self
            .backing
            .as_ref()
            .filter(|b| b.shared || !b.private_copy)
        {
            if !b.object.native_resident() {
                if let Some(source) = b.object.page_source() {
                    self.charge.check_available()?;
                    source.load().map_err(|error| error.at_access(address))?;
                }
            }
        }
        Ok(())
    }
    pub(crate) fn shared_storage(&self) -> Option<std::sync::Arc<SharedPage>> {
        if let Some(b) = &self.backing {
            if b.shared || !b.private_copy {
                return b.object.shared_page();
            }
        }
        self.bytes.shared().cloned()
    }
    pub(super) fn shared_write_storage(&self) -> Option<std::sync::Arc<SharedPage>> {
        if self
            .backing
            .as_ref()
            .is_some_and(|b| !b.shared && !b.private_copy)
        {
            return None;
        }
        self.shared_storage()
    }
    pub(super) fn detach_private(&mut self) -> Result<(), MemoryError> {
        if let Some(b) = self
            .backing
            .as_mut()
            .filter(|b| !b.shared && !b.private_copy)
        {
            let mut page = [0; PAGE_SIZE as usize];
            b.object.read(0, &mut page)?;
            self.bytes = Arc::new(PageBytes::new(page));
            b.detached_copy(&self.charge);
        }
        Ok(())
    }
    // Fixed-size interpreter callers should compile resident copies to host
    // loads/stores. Live backing and COW checks still run on every access.
    #[inline]
    pub(super) fn read_bytes(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError> {
        if let Some(b) = &self.backing {
            if b.shared || !b.private_copy {
                self.prepare_source(0)?;
                if b.object.charge_reads() {
                    self.charge.ensure()?;
                }
                return b.object.read(offset, out);
            }
        }
        self.bytes.copy_read(offset, out);
        Ok(())
    }
    #[inline]
    pub(super) fn write_bytes(&mut self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
        if let Some(b) = self.backing.as_ref().filter(|b| b.shared) {
            return b.object.write(offset, bytes);
        }
        self.detach_private()?;
        Arc::make_mut(&mut self.bytes).copy_write(offset, bytes);
        Ok(())
    }
}
impl Memory {
    pub fn mapping_expandable(&self, address: u64) -> bool {
        if let Some(shared) = &self.shared {
            return shared.borrow().mapping_expandable(address);
        }
        self.page_for_access_unchecked(address).is_none_or(|page| {
            page.backing
                .as_ref()
                .is_none_or(|backing| backing.object.expandable())
        })
    }
    pub fn map_backed(
        &mut self,
        address: u64,
        objects: Vec<Arc<dyn PageBacking>>,
        shared_mapping: bool,
        permissions: Permissions,
        fixed: bool,
    ) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().map_backed(
                address,
                objects,
                shared_mapping,
                permissions,
                fixed,
            );
        }
        let len = (objects.len() as u64)
            .checked_mul(PAGE_SIZE)
            .ok_or(MemoryError::Limit)?;
        Self::mapping_end(address, len)?;
        if permissions.execute && objects.iter().any(|backing| !backing.executable()) {
            return Err(MemoryError::Permission {
                address,
                access: Access::Execute,
            });
        }
        if permissions.write
            && objects.iter().any(|b| {
                if shared_mapping {
                    !b.writable()
                } else {
                    !b.private_writable()
                }
            })
        {
            return Err(MemoryError::Permission {
                address,
                access: Access::Write,
            });
        }
        let cpu_safe = objects.iter().all(|object| object.cpu_borrow_safe());
        let external_code =
            permissions.execute && objects.iter().any(|object| object.external_code_updates());
        let async_sources = objects.iter().any(|object| object.page_source().is_some());
        self.check_backed_mapping(address, len, fixed)?;
        let charges: Vec<_> = (0..objects.len())
            .map(|_| Charge::new(&self.account))
            .collect();
        if fixed {
            self.map_fixed(address, len, permissions)?;
        } else {
            self.map(address, len, permissions)?;
        }
        self.materialize_descriptors(address, len as usize);
        let source = &objects[0];
        let origin = if let Some(info) = source.proc_file() {
            proc_maps::Origin::File(info)
        } else if let Some(id) = source.proc_shmem_inode() {
            proc_maps::Origin::SharedAnon(id)
        } else {
            proc_maps::Origin::Other
        };
        Arc::make_mut(&mut self.region_layout).origins.insert(
            address,
            proc_maps::Mapping {
                end: address + len,
                offset: source.parallel_domain_offset().unwrap_or(0),
                origin,
                shared: shared_mapping,
                write_only: false,
                may_write: if shared_mapping {
                    source.writable()
                } else {
                    source.private_writable()
                },
                may_execute: source.executable(),
                name: None,
            },
        );
        let zero = Arc::new(PageBytes::Zero);
        for (i, (object, charge)) in objects.into_iter().zip(charges).enumerate() {
            let frame = self.pages[&(address + i as u64 * PAGE_SIZE)];
            let page = self.frames[frame].as_mut().expect("mapped page");
            page.bytes = zero.clone();
            page.charge = charge;
            page.backing = Some(Backed {
                object,
                shared: shared_mapping,
                private_copy: false,
            });
            page.register_backing();
        }
        self.refresh_mapping_mmu(address, len);
        self.invalidate_translations();
        self.has_backings = true;
        self.cpu_borrow_safe &= cpu_safe;
        self.has_external_code |= external_code;
        self.has_async_sources |= async_sources;
        Ok(())
    }
    pub fn prepare_sync(&self, address: u64, len: u64) -> Result<SyncRange, MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow().prepare_sync(address, len);
        }
        let end = Self::mapping_end(address, len)?;
        self.check_mapped_range(address, end)?;
        SyncRange::capture(self.pages.range(address..end).filter_map(|(_, &frame)| {
            self.frames[frame]
                .as_ref()
                .expect("page")
                .backing
                .as_ref()
                .filter(|b| b.shared)
                .map(|b| &b.object)
        }))
    }
    pub fn sync_range(&self, address: u64, len: u64) -> Result<(), MemoryError> {
        self.prepare_sync(address, len)?.run()
    }
    /// Take only resources detached by completed structural edits. Failed
    /// edits and holes cannot redirect this work to a replacement mapping.
    pub fn take_closed_resources(&mut self) -> Vec<Arc<dyn SyncResource>> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().take_closed_resources();
        }
        std::mem::take(&mut self.closed_resources)
            .into_values()
            .collect()
    }
    /// Attach an original mm resource to final retirement. Ordinary unmap and
    /// fork neither execute nor inherit it; shared-mm owners use the same root.
    pub fn retain_mm_close_resource(&mut self, key: u64, resource: Arc<dyn SyncResource>) {
        if let Some(shared) = &self.shared {
            shared.borrow_mut().retain_mm_close_resource(key, resource);
            return;
        }
        self.mm_close_resources.entry(key).or_insert(resource);
    }
    /// Final-mm close retains mm and inode resources before address-space
    /// destruction. Private COW mappings never write back to their files.
    pub fn close_resources(&self) -> Vec<Arc<dyn SyncResource>> {
        if let Some(shared) = &self.shared {
            return shared.borrow().close_resources();
        }
        let mut seen = BTreeSet::new();
        self.mm_close_resources
            .values()
            .cloned()
            .chain(self.pages.values().filter_map(|&frame| {
                let backing = self.frames[frame].as_ref()?.backing.as_ref()?;
                if !backing.shared
                    || backing
                        .object
                        .sync_key()
                        .is_some_and(|key| !seen.insert(key))
                {
                    return None;
                }
                backing.object.close_resource()
            }))
            .collect()
    }
    pub fn resident(&self, address: u64, len: u64) -> Result<Vec<u8>, MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow().resident(address, len);
        }
        let end = Self::mapping_end(address, len)?;
        self.check_mapped_range(address, end)?;
        let mut pages = vec![0; ((end - address) / PAGE_SIZE) as usize];
        for (base, range) in self.anonymous.overlapping(address, end) {
            let lo = base.max(address);
            let hi = range.end.min(end);
            let first = ((lo - address) / PAGE_SIZE) as usize;
            range.store.residency(
                lo,
                &mut pages[first..first + ((hi - lo) / PAGE_SIZE) as usize],
            )?;
        }
        for (&base, &frame) in self.pages.range(address..end) {
            let page = self.frames[frame].as_ref().expect("page");
            pages[((base - address) / PAGE_SIZE) as usize] = if page.check_backing(base).is_ok() {
                page.charge
                    .page_resident(page.bytes.shared().map(Arc::as_ref))?
            } else {
                0
            };
        }
        Ok(pages)
    }
    pub fn discard(&mut self, address: u64, len: u64) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().discard(address, len);
        }
        let end = Self::mapping_end(address, len)?;
        self.check_mapped_range(address, end)?;
        if self.locks.overlaps(address, end) {
            return Err(MemoryError::InvalidRange);
        }
        self.invalidate_proc_reads(address, end);
        self.retire_sparse(address, end);
        self.retire_anonymous_range(address, end);
        self.advance_code_revision();
        let ranges: Vec<_> = self
            .anonymous
            .ranges
            .iter()
            .filter(|(a, r)| **a < end && r.end > address)
            .map(|(&a, r)| (a.max(address), r.end.min(end), (*r.page).clone()))
            .collect();
        self.anonymous.remove(address, end);
        for (a, b, mut page) in ranges {
            page.instruction_revision = self.code_revision;
            self.anonymous.insert(a, b, Arc::new(page), &self.account);
        }
        self.note_anonymous_change(address, end);
        for (&base, &frame) in self.pages.range(address..end) {
            let page = self.frames[frame].as_mut().expect("page");
            if page.backing.as_ref().is_some_and(|b| b.shared) {
                continue;
            }
            if self.parallel_cache.is_some() {
                self.parallel_mappings.insert(base);
            }
            page.bytes = Arc::new(PageBytes::Zero);
            if page.backing.is_none() {
                page.charge = Charge::new(&self.account);
            }
            if let Some(b) = page.backing.as_mut().filter(|b| b.private_copy) {
                b.private_copy = false;
                b.attach(&page.charge);
            }
            page.instruction_revision = self.code_revision;
        }
        self.refresh_mapping_mmu(address, len);
        self.invalidate_translations();
        self.revision = self.revision.wrapping_add(1);
        self.reclaim_unused();
        Ok(())
    }
    /// Linux old_size == 0 duplicates the source VMA's backing and file offset.
    /// The caller has already removed a fixed destination, even if that removed the source.
    pub fn alias_shared_mapping(
        &mut self,
        old: u64,
        new: u64,
        len: u64,
    ) -> Result<(), MemoryError> {
        if let Some(mm) = &self.shared {
            return mm.borrow_mut().alias_shared_mapping(old, new, len);
        }
        Self::mapping_end(old, PAGE_SIZE)?;
        self.check_backed_mapping(new, len, false)?;
        let page = self
            .page_for_access_unchecked(old)
            .ok_or(MemoryError::Unmapped(old))?;
        let source = page
            .backing
            .as_ref()
            .filter(|b| b.shared)
            .ok_or(MemoryError::BackingIo(14))?;
        if !source.object.expandable() {
            return Err(MemoryError::BackingIo(14));
        }
        if old == new {
            return Err(MemoryError::Overlap(new));
        }
        let permissions = page.permissions;
        let mut objects = Vec::with_capacity((len / PAGE_SIZE) as usize);
        objects.push(source.object.clone());
        for offset in 1..len / PAGE_SIZE {
            objects.push(match self.attachments.extension(old + PAGE_SIZE, offset) {
                Some(page) => page?,
                None => source.object.next_page(offset)?,
            });
        }
        let origins = self.region_layout.origins.moved(old, PAGE_SIZE, new, len);
        let policy = self.vma_policy.moved(old, PAGE_SIZE, new, len);
        let locks = self.locks.moved(old, PAGE_SIZE, new, len);
        let attachments = self.attachments.moved(old, PAGE_SIZE, new, len);
        self.map_backed(new, objects, true, permissions, false)?;
        Arc::make_mut(&mut self.region_layout)
            .origins
            .extend(origins);
        self.attachments.0.extend(attachments);
        self.vma_policy.extend(policy);
        self.locks.finish_move(new, len, new, len, locks);
        Ok(())
    }
    /// Transactional page-table movement; page bytes/backing identity are retained.
    pub fn remap(
        &mut self,
        old: u64,
        old_len: u64,
        new: u64,
        new_len: u64,
        fixed: bool,
    ) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().remap(old, old_len, new, new_len, fixed);
        }
        Self::mapping_end(old, old_len)?;
        Self::mapping_end(new, new_len)?;
        let origins = self.region_layout.origins.moved(old, old_len, new, new_len);
        let policy = self.vma_policy.moved(old, old_len, new, new_len);
        let moved_locks = self.locks.moved(old, old_len, new, new_len);
        let moved = self.attachments.moved(old, old_len, new, new_len);
        let callback = (old != new)
            .then(|| {
                self.page_for_access_unchecked(old)
                    .and_then(|page| page.backing.as_ref())
                    .and_then(|backing| backing.object.mapping_remap())
            })
            .flatten();
        let restore = callback.as_ref().map(|_| {
            (
                self.region_layout.origins.moved(old, old_len, old, new_len),
                self.vma_policy.moved(old, old_len, old, new_len),
                self.attachments.moved(old, old_len, old, new_len),
                self.locks.moved(old, old_len, old, new_len),
            )
        });
        self.remap_inner(old, old_len, new, new_len, fixed)?;
        if let Some(callback) = callback {
            if let Err(error) = callback.remapped(self.original_identity, new) {
                // Linux has already discarded a fixed destination and any
                // truncated tail when a file mremap hook fails. Move back the
                // surviving source pages, preserving that same failure boundary.
                self.remap_inner(new, new_len, old, new_len, false)?;
                let (origins, policy, attachments, locks) = restore.unwrap();
                Arc::make_mut(&mut self.region_layout)
                    .origins
                    .extend(origins);
                self.vma_policy.extend(policy);
                self.attachments.0.extend(attachments);
                self.locks.finish_move(old, old_len, old, new_len, locks);
                return Err(error);
            }
        }
        Arc::make_mut(&mut self.region_layout)
            .origins
            .extend(origins);
        self.attachments.0.extend(moved);
        self.locks
            .finish_move(old, old_len, new, new_len, moved_locks);
        self.vma_policy.remove(old, old + old_len);
        self.vma_policy.remove(new, new + new_len);
        self.vma_policy.extend(policy);
        Ok(())
    }
    fn remap_inner(
        &mut self,
        old: u64,
        old_len: u64,
        new: u64,
        new_len: u64,
        fixed: bool,
    ) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().remap(old, old_len, new, new_len, fixed);
        }
        let old_end = Self::mapping_end(old, old_len)?;
        let new_end = Self::mapping_end(new, new_len)?;
        if fixed && old == new {
            return Err(MemoryError::InvalidRange);
        }
        if old != new && new < old_end && old < new_end {
            return Err(MemoryError::InvalidRange);
        }
        if self.is_reserved(old, old_len) {
            // Both splits and the final insertion must fit before either
            // source or destination changes. Conservative near the metadata cap.
            self.check_reservation_split(0, 0, 4)?;
            if old == new && new_len > old_len && !self.is_free(old_end, new_len - old_len) {
                return Err(MemoryError::Overlap(old_end));
            }
            if old != new && !fixed && !self.is_free(new, new_len) {
                return Err(MemoryError::Overlap(new));
            }
            self.unmap(old, old_len)?;
            return self.reserve(new, new_len, fixed);
        }
        self.check_mapped_range(old, old_end)?;
        if new_len > old_len && !self.mapping_expandable(old) {
            return Err(MemoryError::BackingIo(14));
        }
        self.adopt_anonymous();
        let first = self
            .page_for_access_unchecked(old)
            .ok_or(MemoryError::Unmapped(old))?
            .clone();
        if first.backing.is_none() {
            if self
                .reservations
                .range(..old_end)
                .any(|(&a, &b)| a < old_end && b > old)
                || self.pages.range(old..old_end).any(|(_, &i)| {
                    let p = self.frames[i].as_ref().unwrap();
                    p.backing.is_some()
                        || p.permissions != first.permissions
                        || p.mapping != first.mapping
                })
                || self.anonymous.ranges.range(..old_end).any(|(&a, r)| {
                    a < old_end
                        && r.end > old
                        && (r.page.permissions != first.permissions
                            || r.page.mapping != first.mapping)
                })
            {
                return Err(MemoryError::BackingIo(14));
            }
            if old == new && new_len > old_len && !self.is_free(old_end, new_len - old_len) {
                return Err(MemoryError::Overlap(old_end));
            }
            if old != new && !fixed && !self.is_free(new, new_len) {
                return Err(MemoryError::Overlap(new));
            }
            self.check_reservation_split(new, new_end, 0)?;
            let pages: Vec<_> = self
                .pages
                .range(old..old_end.min(old + new_len))
                .map(|(&base, &i)| (new + base - old, self.frames[i].as_ref().unwrap().clone()))
                .collect();
            self.unmap(old, old_len)?;
            if fixed {
                self.unmap(new, new_len)?;
            }
            // One range replaces the VMA; only reached pages move individually.
            self.map(new, new_len, first.permissions)?;
            for r in self
                .anonymous
                .ranges
                .range_mut(new..new_end)
                .map(|(_, r)| r)
            {
                Arc::make_mut(&mut r.page).mapping = first.mapping;
            }
            for (base, mut page) in pages {
                page.instruction_revision = self.code_revision;
                self.anonymous.remove(base, base + PAGE_SIZE);
                self.insert_owned_page(base, page);
            }
            // Small mappings may already have materialized zero descriptors.
            for (_, &i) in self.pages.range(new..new_end) {
                self.frames[i].as_mut().unwrap().mapping = first.mapping;
            }
            self.parallel_anonymous_dirty = true;
            self.refresh_mapping_mmu(new, new_len);
            self.invalidate_translations();
            return Ok(());
        }
        self.invalidate_translations();
        self.mmu.retire();
        let mut pages = Vec::new();
        for base in (old..old_end).step_by(PAGE_SIZE as usize) {
            pages.push(
                self.frames[*self.pages.get(&base).ok_or(MemoryError::Unmapped(base))?]
                    .as_ref()
                    .expect("page")
                    .clone(),
            );
        }
        // Linux requires a single mapping; reject mixed protection/backing ranges.
        let permissions = pages[0].permissions;
        let first_backed = pages[0].backing.is_some();
        let mapping = pages[0].mapping;
        if pages.iter().any(|p| {
            p.mapping != mapping
                || p.permissions != permissions
                || p.backing.is_some() != first_backed
        }) {
            return Err(MemoryError::BackingIo(14));
        }
        let replaced = if old == new {
            old_len
        } else if fixed {
            (self.pages.range(new..new_end).count() as u64) * PAGE_SIZE
        } else {
            0
        };
        if old != new && !fixed && !self.is_free(new, new_len) {
            return Err(MemoryError::Overlap(new));
        }
        if fixed && old != new {
            self.check_reservation_split(new, new_end, 0)?;
        }
        if (self.pages.len() as u64 * PAGE_SIZE)
            .saturating_sub(old_len + if old == new { 0 } else { replaced })
            .checked_add(new_len)
            .is_none_or(|n| n > MAX_DESCRIBED_BYTES as u64)
        {
            return Err(MemoryError::Limit);
        }
        if old == new && new_len > old_len && !self.is_free(old_end, new_len - old_len) {
            return Err(MemoryError::Overlap(old_end));
        }
        let count = (new_len / PAGE_SIZE) as usize;
        if count > pages.len() {
            let last = pages.last().expect("page").clone();
            let original_count = pages.len();
            for i in original_count..count {
                let mut page = last.clone();
                page.bytes = Arc::new(PageBytes::Zero);
                page.charge = Charge::new(&self.account);
                if let Some(b) = &mut page.backing {
                    b.object = if let Some(expected) = self
                        .attachments
                        .extension(old_end, (i + 1 - original_count) as u64)
                    {
                        expected?
                    } else {
                        last.backing
                            .as_ref()
                            .expect("backed")
                            .object
                            .next_page((i + 1 - original_count) as u64)?
                    };
                    b.private_copy = false;
                }
                pages.push(page);
            }
        }
        self.unmap(old, old_len)?;
        if fixed && old != new {
            self.unmap(new, new_len)?;
        }
        self.map_fixed(new, new_len, permissions)?;
        self.materialize_descriptors(new, new_len as usize);
        self.cpu_borrow_safe &= pages.iter().all(|p| {
            p.backing
                .as_ref()
                .is_none_or(|b| b.object.cpu_borrow_safe())
        });
        for (i, mut page) in pages.into_iter().take(count).enumerate() {
            page.register_backing();
            page.instruction_revision = self.code_revision;
            let frame = self.pages[&(new + i as u64 * PAGE_SIZE)];
            self.frames[frame] = Some(page);
        }
        self.refresh_mapping_mmu(new, new_len);
        self.invalidate_translations();
        Ok(())
    }
}

struct AnonymousData {
    owners: MappedResidents,
    bytes: Arc<SharedPage>,
    revision: AtomicU64,
    identity: u64,
}
impl AnonymousData {
    fn zero() -> Self {
        Self {
            owners: Default::default(),
            bytes: Arc::new(SharedPage::zero()),
            revision: AtomicU64::new(0),
            identity: new_backing_identity(),
        }
    }
}

struct AnonymousPage {
    extent: Arc<[AnonymousData]>,
    index: usize,
    fixed_extent: bool,
}
impl std::ops::Deref for AnonymousPage {
    type Target = AnonymousData;
    fn deref(&self) -> &AnonymousData {
        &self.extent[self.index]
    }
}
impl AnonymousPage {
    fn new() -> Arc<Self> {
        Self::with_extent(false)
    }
    fn with_extent(fixed_extent: bool) -> Arc<Self> {
        Arc::new(Self {
            extent: Arc::new([AnonymousData::zero()]),
            index: 0,
            fixed_extent,
        })
    }
}
// A shared anonymous VMA has a fixed shmem object size. mremap may extend
// its virtual range past EOF, and only an actual access there raises SIGBUS.
struct BeyondAnonymousEnd {
    object: u64,
    index: u64,
}
impl PageBacking for BeyondAnonymousEnd {
    fn parallel_key(&self) -> Option<(u64, u64)> {
        Some((self.object, self.index))
    }
    fn parallel_versioned(&self) -> bool {
        true
    }
    fn cpu_borrow_safe(&self) -> bool {
        true
    }
    fn check(&self, address: u64) -> Result<(), MemoryError> {
        Err(MemoryError::Bus(address))
    }
    fn read(&self, offset: usize, _: &mut [u8]) -> Result<(), MemoryError> {
        Err(MemoryError::Bus(offset as u64))
    }
    fn write(&self, offset: usize, _: &[u8]) -> Result<(), MemoryError> {
        Err(MemoryError::Bus(offset as u64))
    }
    fn sync(&self) -> Result<(), MemoryError> {
        Ok(())
    }
    fn sync_required(&self) -> bool {
        false
    }
    fn version(&self) -> u64 {
        0
    }
    fn writable(&self) -> bool {
        true
    }
    fn next_page(&self, pages: u64) -> Result<Arc<dyn PageBacking>, MemoryError> {
        Ok(Arc::new(Self {
            object: self.object,
            index: self
                .index
                .checked_add(pages)
                .ok_or(MemoryError::InvalidRange)?,
        }))
    }
}
/// A named segment shares the ordinary anonymous page provider across independent
/// attachments, and retains modified pages between detach and reattach.
#[derive(Default)]
pub struct SharedAnonymousPages(std::sync::Mutex<Vec<Arc<AnonymousPage>>>);
impl SharedAnonymousPages {
    /// Shared kernel queue storage has a fixed extent even after mremap.
    pub fn fixed_mapping(count: usize) -> Vec<Arc<dyn PageBacking>> {
        (0..count)
            .map(|_| AnonymousPage::with_extent(true) as Arc<dyn PageBacking>)
            .collect()
    }
    pub fn mapping(&self, count: usize) -> Vec<Arc<dyn PageBacking>> {
        let mut pages = self.0.lock().unwrap();
        if pages.len() < count {
            pages.resize_with(count, AnonymousPage::new);
        }
        pages[..count]
            .iter()
            .map(|p| p.clone() as Arc<dyn PageBacking>)
            .collect()
    }
    pub fn page(&self, index: usize) -> Option<Arc<dyn PageBacking>> {
        self.0
            .lock()
            .unwrap()
            .get(index)
            .map(|p| p.clone() as Arc<dyn PageBacking>)
    }
    pub fn resident_pages(&self) -> u64 {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|p| !p.bytes.unmaterialized_zero())
            .count() as u64
    }
}
struct RetainedPageSource(std::sync::Arc<SharedPage>);
impl PageSource for RetainedPageSource {
    fn load(&self) -> Result<std::sync::Arc<SharedPage>, MemoryError> {
        Ok(self.0.clone())
    }
}
impl PageBacking for AnonymousPage {
    fn mapped_residents(&self) -> Option<&MappedResidents> {
        Some(&self.owners)
    }
    fn proc_dirty(&self) -> bool {
        !self.bytes.unmaterialized_zero()
    }
    fn proc_shmem_inode(&self) -> Option<u64> {
        Some(self.extent[0].identity)
    }
    fn sync_required(&self) -> bool {
        false
    }
    fn parallel_versioned(&self) -> bool {
        // This provider never replaces its retained SharedPage allocation;
        // check() is infallible and version() already covers coordinator and
        // worker writes. Unrelated backing changes need no frame replacement.
        true
    }
    fn charge_reads(&self) -> bool {
        false
    }
    fn page_source(&self) -> Option<std::sync::Arc<dyn PageSource>> {
        Some(std::sync::Arc::new(RetainedPageSource(self.bytes.clone())))
    }

    fn cpu_borrow_safe(&self) -> bool {
        true
    }
    fn native_resident(&self) -> bool {
        true
    }
    fn parallel_key(&self) -> Option<(u64, u64)> {
        Some((self.identity, 0))
    }
    fn shared_page(&self) -> Option<std::sync::Arc<SharedPage>> {
        Some(self.bytes.clone())
    }
    fn publish_write(&self, _: usize, _: usize) -> Result<(), MemoryError> {
        self.revision.fetch_add(1, Ordering::Relaxed);
        backing_changed();
        Ok(())
    }
    fn check(&self, _: u64) -> Result<(), MemoryError> {
        Ok(())
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError> {
        self.bytes
            .with_read(offset, out.len(), |bytes| out.copy_from_slice(bytes));
        Ok(())
    }
    fn write(&self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
        self.bytes
            .with_write(offset, bytes.len(), |out| out.copy_from_slice(bytes));
        self.revision.fetch_add(1, Ordering::Relaxed);
        backing_changed();
        Ok(())
    }
    fn with_read(
        &self,
        offset: usize,
        len: usize,
        f: &mut dyn FnMut(&[u8]),
    ) -> Result<bool, MemoryError> {
        self.bytes.with_read(offset, len, f);
        Ok(true)
    }
    fn with_write(
        &self,
        offset: usize,
        len: usize,
        f: &mut dyn FnMut(&mut [u8]),
    ) -> Result<bool, MemoryError> {
        self.revision.fetch_add(1, Ordering::Relaxed);
        backing_changed();
        self.bytes.with_write(offset, len, f);
        Ok(true)
    }
    fn sync(&self) -> Result<(), MemoryError> {
        Ok(())
    }
    fn version(&self) -> u64 {
        self.revision
            .load(Ordering::Relaxed)
            .wrapping_add(self.bytes.version.load(Ordering::Acquire))
    }
    fn writable(&self) -> bool {
        true
    }
    fn next_page(&self, pages: u64) -> Result<Arc<dyn PageBacking>, MemoryError> {
        if self.fixed_extent {
            return Err(MemoryError::BackingIo(14));
        }
        let Some(index) = self
            .index
            .checked_add(pages as usize)
            .filter(|&i| i < self.extent.len())
        else {
            return Ok(Arc::new(BeyondAnonymousEnd {
                object: self.extent[0].identity,
                index: (self.index as u64)
                    .checked_add(pages)
                    .ok_or(MemoryError::InvalidRange)?,
            }));
        };
        Ok(Arc::new(Self {
            extent: self.extent.clone(),
            index,
            fixed_extent: false,
        }))
    }
}
impl Memory {
    /// Unmap only the surviving parts of this original resource. An application
    /// may have replaced or protected an interior page since queue creation.
    pub fn unmap_backings(
        &mut self,
        address: u64,
        objects: &[Arc<dyn PageBacking>],
    ) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().unmap_backings(address, objects);
        }
        let mut run = None;
        for i in 0..=objects.len() {
            let addr = address + i as u64 * PAGE_SIZE;
            let original = objects.get(i).is_some_and(|object| {
                self.page_for_access_unchecked(addr)
                    .and_then(|p| p.backing.as_ref())
                    .is_some_and(|b| Arc::ptr_eq(&b.object, object))
            });
            if original {
                run.get_or_insert(addr);
            } else if let Some(start) = run.take() {
                self.unmap(start, addr - start)?;
            }
        }
        Ok(())
    }
    pub fn map_shared_anonymous(
        &mut self,
        address: u64,
        len: u64,
        permissions: Permissions,
        fixed: bool,
    ) -> Result<(), MemoryError> {
        Self::mapping_end(address, len)?;
        self.check_backed_mapping(address, len, fixed)?;
        let extent: Arc<[AnonymousData]> = (0..len / PAGE_SIZE)
            .map(|_| AnonymousData::zero())
            .collect();
        let objects = (0..extent.len())
            .map(|index| {
                Arc::new(AnonymousPage {
                    extent: extent.clone(),
                    index,
                    fixed_extent: false,
                }) as Arc<dyn PageBacking>
            })
            .collect();
        self.map_backed(address, objects, true, permissions, fixed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fork_shares_anonymous_bytes_but_not_protections_or_mapping_table() {
        let mut m = Memory::default();
        m.map_shared_anonymous(0x1000, PAGE_SIZE, Permissions::RW, false)
            .unwrap();
        let mut child = m.clone();
        child.write_array(0x1000, [7; 8]).unwrap();
        assert_eq!(m.read_array::<8>(0x1000).unwrap(), [7; 8]);
        child.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        m.write_array(0x1000, [8; 8]).unwrap();
        assert_eq!(child.read_array::<8>(0x1000).unwrap(), [8; 8]);
        child.unmap(0x1000, PAGE_SIZE).unwrap();
        assert!(m.read_array::<8>(0x1000).is_ok());
    }
    #[test]
    fn shared_alias_retains_original_offset_bytes_and_mapping_locks() {
        let mut m = Memory::default();
        let base = 0x10000;
        let alias = 0x20000;
        let p = PAGE_SIZE;
        m.map_shared_anonymous(base, 3 * p, Permissions::RW, false)
            .unwrap();
        m.write_array(base + 2 * p, [37u8]).unwrap();
        m.set_range_lock(base + p, p, Some(true)).unwrap();
        m.alias_shared_mapping(base + p, alias, 3 * p).unwrap();
        assert_eq!(m.lock_mode_at(base + p), Some(true));
        assert_eq!(m.lock_mode_at(alias + 2 * p), Some(true));
        m.write_array(alias, [11u8]).unwrap();
        assert_eq!(m.read_array::<1>(base + p).unwrap(), [11]);
        m.unmap(base, 3 * p).unwrap();
        assert_eq!(m.read_array::<1>(alias + p).unwrap(), [37]);
        assert_eq!(
            m.read_array::<1>(alias + 2 * p),
            Err(MemoryError::Bus(alias + 2 * p))
        );
        m.map(base, p, Permissions::RW).unwrap();
        assert_eq!(
            m.alias_shared_mapping(base, base + p, p),
            Err(MemoryError::BackingIo(14))
        );
    }
    #[test]
    fn failed_remap_is_atomic_and_success_preserves_bytes_and_zero_grows() {
        let mut m = Memory::new(PAGE_SIZE as usize * 4);
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.map(0x2000, PAGE_SIZE, Permissions::R).unwrap();
        m.write_array(0x1000, [3; 8]).unwrap();
        assert!(m
            .remap(0x1000, PAGE_SIZE, 0x1000, PAGE_SIZE * 2, false)
            .is_err());
        assert_eq!(m.read_array::<8>(0x1000).unwrap(), [3; 8]);
        assert!(m
            .remap(0x1000, PAGE_SIZE, 0x8000, ADDRESS_LIMIT, false)
            .is_err());
        assert!(m.is_free(0x8000, PAGE_SIZE * 3));
        m.remap(0x1000, PAGE_SIZE, 0x8000, PAGE_SIZE * 3, false)
            .unwrap();
        assert!(m.is_free(0x1000, PAGE_SIZE));
        assert_eq!(m.read_array::<8>(0x8000).unwrap(), [3; 8]);
        assert_eq!(m.read_array::<8>(0xa000).unwrap(), [0; 8]);
    }
}
