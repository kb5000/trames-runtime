// SPDX-License-Identifier: GPL-3.0-or-later
//! Canonical FUSE attributes, request epochs and persistent bad-inode state.
use super::*;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Update {
    Lookup,
    Read,
    Set,
}
pub(super) struct Attr {
    bad: std::sync::atomic::AtomicBool,
    kind: u32,
    data: std::sync::Mutex<Snapshot>,
    pub(super) validity: permissions::Validity,
    pub(super) cache: cache::Cache,
    pub(super) layout: Arc<trames_memory::layout::Layout>,
    pub(super) dirty_times: AtomicU64,
    // Writer/waiter bits and four units per shared directory lookup. This is the
    // original inode transaction, separate from its short metadata mutex.
    access: std::sync::atomic::AtomicUsize,
    writers: std::sync::Mutex<usize>,
    changed: Arc<Readiness>,
}
/// Linux's original per-inode write/setattr transaction across daemon waits.
/// Failure to enter parks the guest on readiness, never the host execution slot.
pub(super) struct Write(Arc<Attr>);
pub(super) struct Read(Arc<Attr>);
const WRITER: usize = 1;
const WAITING: usize = 2;
const READER: usize = 4;
pub(super) struct WriteWait(Arc<Attr>);
impl Drop for WriteWait {
    fn drop(&mut self) {
        let notify = {
            let mut writers = self.0.writers.lock().unwrap();
            *writers -= 1;
            *writers == 0 && self.0.access.fetch_and(!WAITING, Ordering::Relaxed) & WRITER == 0
        };
        if notify {
            self.0.changed.notify_atomic();
        }
    }
}
impl WriteWait {
    pub(super) fn is_for(&self, attr: &Arc<Attr>) -> bool {
        Arc::ptr_eq(&self.0, attr)
    }
}
pub(super) enum Access {
    Read { _lease: Read },
    Write { _lease: Write },
}
impl Write {
    pub(super) fn is_for(&self, attr: &Arc<Attr>) -> bool {
        Arc::ptr_eq(&self.0, attr)
    }
}
impl Drop for Write {
    fn drop(&mut self) {
        self.0.access.fetch_and(!WRITER, Ordering::Release);
        self.0.changed.notify_atomic();
    }
}
impl Drop for Read {
    fn drop(&mut self) {
        if self.0.access.fetch_sub(READER, Ordering::Release) & !WAITING == READER {
            self.0.changed.notify_atomic();
        }
    }
}
pub(super) struct Snapshot {
    bytes: [u8; 88],
    pub(super) version: u64,
}
impl std::ops::Deref for Snapshot {
    type Target = [u8; 88];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}
impl std::ops::DerefMut for Snapshot {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}
impl Attr {
    pub(super) fn kind_is_regular(&self) -> bool {
        self.kind == 0o100000
    }
    pub(super) fn new(bytes: [u8; 88], version: u64, valid: (u64, u32)) -> Self {
        let validity = permissions::Validity::default();
        validity.set(valid.0, valid.1);
        Self {
            bad: Default::default(),
            kind: word(&bytes, 60) & 0o170000,
            data: std::sync::Mutex::new(Snapshot { bytes, version }),
            validity,
            cache: Default::default(),
            layout: Default::default(),
            dirty_times: Default::default(),
            access: Default::default(),
            writers: Default::default(),
            changed: Default::default(),
        }
    }
    pub(super) fn try_write(self: &Arc<Self>) -> Option<Write> {
        self.access
            .try_update(Ordering::Acquire, Ordering::Relaxed, |state| {
                (state & !WAITING == 0).then_some(state | WRITER)
            })
            .ok()
            .map(|_| Write(self.clone()))
    }
    pub(super) fn writing(&self) -> bool {
        self.access.load(Ordering::Acquire) & WRITER != 0
    }
    pub(super) fn write_ready(&self) -> bool {
        self.access.load(Ordering::Acquire) & !WAITING == 0
    }
    pub(super) fn read_ready(&self) -> bool {
        self.access.load(Ordering::Acquire) & (WRITER | WAITING) == 0
    }
    pub(super) fn enter_write(self: &Arc<Self>, waiting: &mut Option<WriteWait>) -> Option<Write> {
        if let Some(lease) = self.try_write() {
            drop(waiting.take());
            return Some(lease);
        }
        if waiting.as_ref().is_none_or(|wait| !wait.is_for(self)) {
            {
                let mut writers = self.writers.lock().unwrap();
                *writers += 1;
                self.access.fetch_or(WAITING, Ordering::Relaxed);
            }
            *waiting = Some(WriteWait(self.clone()));
        }
        // Registration precedes the retry; an unlock between the first try
        // and subscription cannot leave this original waiter asleep.
        let lease = self.try_write()?;
        drop(waiting.take());
        Some(lease)
    }
    pub(super) fn try_read(self: &Arc<Self>) -> Option<Read> {
        self.access
            .try_update(Ordering::Acquire, Ordering::Relaxed, |state| {
                if state & (WRITER | WAITING) == 0 {
                    state.checked_add(READER)
                } else {
                    None
                }
            })
            .ok()
            .map(|_| Read(self.clone()))
    }
    pub(super) fn subscribe_write(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.changed.subscribe(signal)
    }
    pub(super) fn lock(&self) -> std::sync::LockResult<std::sync::MutexGuard<'_, Snapshot>> {
        self.data.lock()
    }
    pub(super) fn check(&self) -> Result<()> {
        if self.bad.load(Ordering::Relaxed) {
            Err(Errno(5))
        } else {
            Ok(())
        }
    }
    pub(super) fn make_bad(&self) {
        self.bad.store(true, Ordering::Relaxed);
    }
    pub(super) fn read_size(&self, fs: &Mounted, size: u64, version: u64) {
        let mut cached = self.lock().unwrap();
        let current = u64::from_le_bytes(cached[8..16].try_into().unwrap());
        if version >= cached.version
            && size < current
            && !self.writing()
            && !fs.connection.option(1 << 16)
        {
            cached[8..16].copy_from_slice(&size.to_le_bytes());
            cached.version = fs.connection.next_attr_version();
            drop(cached);
            self.cache.resize(current, size);
        }
    }
    pub(super) fn refresh(
        &self,
        fs: &Mounted,
        raw: &mut [u8],
        version: u64,
        valid: (u64, u32),
        update: Update,
    ) -> Result<bool> {
        // LOOKUP must still bind an existing bad identity: O_PATH and EEXIST
        // are decided by namei before an inode operation checks badness.
        if update != Update::Lookup {
            self.check()?;
        }
        let mut cached = self.lock().unwrap();
        if validate(raw).is_err() || word(raw, 60) & 0o170000 != self.kind {
            self.make_bad();
            return Err(Errno(5));
        }
        let old_size = u64::from_le_bytes(cached[8..16].try_into().unwrap());
        // Negotiated writeback gives the original regular inode authority over
        // size and modification times, including replies newer than a write.
        let writeback = self.kind_is_regular() && fs.connection.option(1 << 16);
        if writeback && update != Update::Set {
            raw[8..16].copy_from_slice(&cached[8..16]);
            raw[32..48].copy_from_slice(&cached[32..48]);
            raw[52..60].copy_from_slice(&cached[52..60]);
        }
        let newer = version != 0 && cached.version > version;
        if newer && update != Update::Set {
            return Ok(false);
        }
        let size = u64::from_le_bytes(raw[8..16].try_into().unwrap());
        let data_changed =
            old_size != size || cached[32..40] != raw[32..40] || cached[52..56] != raw[52..56];
        normalize(raw);
        cached.copy_from_slice(raw);
        cached.version = fs.connection.next_attr_version();
        self.validity.set(
            if newer { 0 } else { valid.0 },
            if newer { 0 } else { valid.1 },
        );
        drop(cached);
        // Explicit setattr still resizes the cache in writeback mode.
        if self.kind == 0o100000 && data_changed {
            if old_size != size {
                self.cache.resize(old_size, size);
            }
            if !writeback {
                self.cache.invalidate_all();
            }
        }
        Ok(true)
    }
    pub(super) fn modified(&self, fs: &Mounted) {
        let now = storage::Timestamp::now();
        let mut data = self.lock().unwrap();
        data.version = fs.connection.next_attr_version();
        data[32..40].copy_from_slice(&now.seconds.to_le_bytes());
        data[40..48].copy_from_slice(&now.seconds.to_le_bytes());
        data[52..56].copy_from_slice(&now.nanos.to_le_bytes());
        data[56..60].copy_from_slice(&now.nanos.to_le_bytes());
        self.validity.set(0, 0);
        if self.kind_is_regular() && fs.connection.option(1 << 16) {
            self.dirty_times.fetch_add(1, Ordering::Relaxed);
        }
    }
}
fn word(raw: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(raw[at..at + 4].try_into().unwrap())
}
pub(super) fn validate(raw: &[u8]) -> Result<()> {
    if !transport::valid_attr(raw) {
        return Err(Errno(5));
    }
    Ok(())
}
fn normalize(raw: &mut [u8]) {
    for at in [48, 52, 56] {
        let nano = word(raw, at).min(999_999_999);
        raw[at..at + 4].copy_from_slice(&nano.to_le_bytes());
    }
}
pub(super) fn attr(node: &NodeRef) -> &Arc<Attr> {
    node.fuse_leaf
        .get()
        .map(|n| &n.attr)
        .or_else(|| node.fuse_directory.get().map(|n| &n.attr))
        .expect("FUSE inode")
}
impl Mounted {
    pub(super) fn inode_changed(&self, node: &NodeRef) {
        let attr = attr(node);
        attr.lock().unwrap().version = self.connection.next_attr_version();
        attr.validity.set(0, 0);
        self.invalidate_acl(node);
    }
    pub(super) fn entry_unlinked(&self, node: &NodeRef) {
        let links = {
            let mut data = node.borrow_mut();
            data.links = if node.directory {
                0
            } else {
                data.links.saturating_sub(1)
            };
            data.links
        };
        let attr = attr(node);
        let mut snapshot = attr.lock().unwrap();
        snapshot[64..68].copy_from_slice(&links.to_le_bytes());
        snapshot.version = self.connection.next_attr_version();
        drop(snapshot);
        attr.validity.set(0, 0);
    }
}
impl Mounted {
    pub(in crate::fuse) fn notify_inode(&self, id: u64, offset: i64, length: i64) -> Result<()> {
        let node = self.attribute_target(id).ok_or(Errno(2))?;
        self.notify_original_inode(&node, offset, length)
    }
    pub(super) fn notify_original_inode(
        &self,
        node: &NodeRef,
        offset: i64,
        length: i64,
    ) -> Result<()> {
        let attr = attr(node);
        attr.lock().unwrap().version = self.connection.next_attr_version();
        attr.validity.set(0, 0);
        self.invalidate_acl(node);
        if offset >= 0 {
            if length <= 0 {
                attr.cache.invalidate(offset as u64, u64::MAX);
            } else {
                attr.cache.invalidate(offset as u64, length as u64);
            }
        }
        Ok(())
    }
    pub(in crate::fuse) fn attribute_target(&self, id: u64) -> Option<NodeRef> {
        if id == 1 {
            return Some(self.root_directory());
        }
        self.directories
            .lock()
            .unwrap()
            .range((id, 0)..=(id, u64::MAX))
            .find_map(|(_, node)| node.upgrade())
    }
    pub(in crate::fuse) fn abandoned_attributes(
        &self,
        node: &NodeRef,
        bytes: &[u8],
        version: u64,
        set: bool,
    ) {
        let attr = attr(node);
        if attr.cache.mapped() {
            if let Some(executor) = attr.cache.executor() {
                attr.validity.set(0, 0);
                let resource = Abandoned {
                    fs: self.connection.mounted(),
                    node: node.clone(),
                    bytes: bytes.to_vec(),
                    version,
                    kind: AbandonedKind::Attributes(set),
                };
                executor.submit(Arc::new(resource), Box::new(AbandonedDone));
                return;
            }
        }
        self.apply_abandoned_attributes(node, bytes, version, set);
    }
    fn apply_abandoned_attributes(&self, node: &NodeRef, bytes: &[u8], version: u64, set: bool) {
        if bytes.len() != 104 {
            return;
        }
        let mut raw = bytes[16..].to_vec();
        let valid = (
            u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        );
        let _ = self.refresh_inode_at(
            node,
            &mut raw,
            version,
            valid,
            if set { Update::Set } else { Update::Read },
        );
    }
    pub(in crate::fuse) fn abandoned_entry(&self, bytes: &[u8], version: u64, kind: Option<u32>) {
        if bytes.len() != 128 {
            return;
        }
        let id = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let generation = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let node = self
            .directories
            .lock()
            .unwrap()
            .get(&(id, generation))
            .and_then(std::sync::Weak::upgrade);
        if let Some(node) = node {
            let attr = attr(&node);
            if attr.cache.mapped() {
                if let Some(executor) = attr.cache.executor() {
                    attr.validity.set(0, 0);
                    let resource = Abandoned {
                        fs: self.connection.mounted(),
                        node,
                        bytes: bytes.to_vec(),
                        version,
                        kind: AbandonedKind::Entry(kind),
                    };
                    executor.submit(Arc::new(resource), Box::new(AbandonedDone));
                    return;
                }
            }
        }
        self.apply_abandoned_entry(bytes, version, kind);
    }
    fn apply_abandoned_entry(&self, bytes: &[u8], version: u64, kind: Option<u32>) {
        if bytes.len() != 128 {
            return;
        }
        let id = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let mut raw = bytes[40..].to_vec();
        let valid = (
            u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
            u32::from_le_bytes(bytes[36..40].try_into().unwrap()),
        );
        if id == 1 && kind.is_none() {
            let _ = self.apply_root_lookup(&mut raw, version, valid);
        } else if transport::entry_id(bytes, kind).is_some() {
            let generation = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
            let mut inodes = self.directories.lock().unwrap();
            let retired =
                self.retire_inodes(&mut inodes, id, generation, word(&raw, 60) & 0o170000);
            let node = inodes
                .get(&(id, generation))
                .and_then(std::sync::Weak::upgrade);
            drop(inodes);
            drop(retired);
            if let Some(node) = node {
                let _ = self.refresh_inode_at(&node, &mut raw, version, valid, Update::Lookup);
            }
        }
    }
    pub(super) fn apply_root_lookup(
        &self,
        raw: &mut [u8],
        version: u64,
        valid: (u64, u32),
    ) -> Result<()> {
        // Invalid attributes grant nothing. A valid but wrong root type instead
        // poisons the existing root, as fuse_iget does before alias rejection.
        validate(raw)?;
        self.refresh_inode_at(&self.root_directory(), raw, version, valid, Update::Lookup)
    }
    pub(super) fn check_inode(&self, node: &NodeRef) -> Result<()> {
        attr(node).check()
    }
    pub(super) fn fresh_attr(&self, raw: &mut [u8], valid: (u64, u32)) -> Result<Arc<Attr>> {
        validate(raw)?;
        normalize(raw);
        Ok(Arc::new(Attr::new(
            raw.try_into().unwrap(),
            self.connection.next_attr_version(),
            valid,
        )))
    }
    pub(super) fn refresh_inode_at(
        &self,
        node: &NodeRef,
        raw: &mut [u8],
        version: u64,
        valid: (u64, u32),
        update: Update,
    ) -> Result<()> {
        let mut value = node.borrow_mut();
        if !attr(node).refresh(self, raw, version, valid, update)? {
            return Ok(());
        }
        value.mode = word(raw, 60) & 0o177777;
        value.uid = self
            .namespace
            .to_global(false, word(raw, 68))
            .unwrap_or(u32::MAX);
        value.gid = self
            .namespace
            .to_global(true, word(raw, 72))
            .unwrap_or(u32::MAX);
        value.links = word(raw, 64);
        value.inode = u64::from_le_bytes(raw[..8].try_into().unwrap());
        for (time, (sec, nano)) in value.times.iter_mut().zip([(24, 48), (32, 52), (40, 56)]) {
            *time = storage::Timestamp {
                seconds: i64::from_le_bytes(raw[sec..sec + 8].try_into().unwrap()),
                nanos: word(raw, nano),
            };
        }
        Ok(())
    }
    /// Retire stale identities while keeping upgraded references alive until the
    /// identity-table guard has gone; their destructors may revisit that table.
    pub(super) fn retire_inodes(
        &self,
        map: &mut BTreeMap<(u64, u64), std::sync::Weak<Inode>>,
        id: u64,
        generation: u64,
        kind: u32,
    ) -> Vec<NodeRef> {
        let old: Vec<_> = map
            .range((id, 0)..=(id, u64::MAX))
            .filter_map(|(key, weak)| weak.upgrade().map(|node| (*key, node)))
            .collect();
        for (key, node) in &old {
            if key.1 != generation || attr(node).kind != kind {
                attr(node).make_bad();
                map.remove(key);
            }
        }
        old.into_iter().map(|(_, node)| node).collect()
    }
}
#[derive(Clone, Copy)]
enum AbandonedKind {
    Attributes(bool),
    Entry(Option<u32>),
}
struct Abandoned {
    fs: Option<Arc<Mounted>>,
    node: NodeRef,
    bytes: Vec<u8>,
    version: u64,
    kind: AbandonedKind,
}
impl trames_memory::SyncResource for Abandoned {
    fn layout(&self) -> Option<Arc<trames_memory::layout::Layout>> {
        Some(attr(&self.node).layout.clone())
    }
    fn sync(&self) -> std::result::Result<(), trames_memory::MemoryError> {
        if let Some(fs) = &self.fs {
            match self.kind {
                AbandonedKind::Attributes(set) => {
                    fs.apply_abandoned_attributes(&self.node, &self.bytes, self.version, set)
                }
                AbandonedKind::Entry(kind) => {
                    fs.apply_abandoned_entry(&self.bytes, self.version, kind)
                }
            }
        }
        Ok(())
    }
}
struct AbandonedDone;
impl trames_memory::SyncCompletion for AbandonedDone {
    fn complete(self: Box<Self>, _: std::result::Result<(), trames_memory::MemoryError>) {}
}

pub(super) fn times(raw: &[u8]) -> [storage::Timestamp; 3] {
    std::array::from_fn(|i| storage::Timestamp {
        seconds: i64::from_le_bytes(raw[24 + i * 8..32 + i * 8].try_into().unwrap()),
        nanos: word(raw, 48 + i * 4),
    })
}
