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
    writing: std::sync::atomic::AtomicBool,
    changed: Arc<Readiness>,
}
/// Linux's original per-inode write/setattr transaction across daemon waits.
/// Failure to enter parks the guest on readiness, never the host execution slot.
pub(super) struct Write(Arc<Attr>);
impl Drop for Write {
    fn drop(&mut self) {
        self.0.writing.store(false, Ordering::Release);
        self.0.changed.notify_atomic();
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
            writing: Default::default(),
            changed: Default::default(),
        }
    }
    pub(super) fn try_write(self: &Arc<Self>) -> Option<Write> {
        self.writing
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Write(self.clone()))
    }
    pub(super) fn writing(&self) -> bool {
        self.writing.load(Ordering::Acquire)
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
        if version >= cached.version && size < current && !self.writing() {
            cached[8..16].copy_from_slice(&size.to_le_bytes());
            cached.version = fs.connection.next_attr_version();
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
        let newer = version != 0 && cached.version > version;
        if newer && update != Update::Set {
            return Ok(false);
        }
        let size_changed = cached[8..16] != raw[8..16];
        normalize(raw);
        cached.copy_from_slice(raw);
        cached.version = fs.connection.next_attr_version();
        self.validity.set(
            if newer { 0 } else { valid.0 },
            if newer { 0 } else { valid.1 },
        );
        drop(cached);
        // Neither WRITEBACK_CACHE nor EXPLICIT_INVAL_DATA is negotiated yet.
        // In the ordinary mode a changed server size invalidates clean data.
        if self.kind == 0o100000 && size_changed {
            self.cache.invalidate_all();
        }
        Ok(true)
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
    pub(in crate::fuse) fn notify_inode(&self, id: u64, offset: i64, length: i64) -> Result<()> {
        let node = self.attribute_target(id).ok_or(Errno(2))?;
        let attr = attr(&node);
        attr.lock().unwrap().version = self.connection.next_attr_version();
        attr.validity.set(0, 0);
        self.invalidate_acl(&node);
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

pub(super) fn times(raw: &[u8]) -> [storage::Timestamp; 3] {
    std::array::from_fn(|i| storage::Timestamp {
        seconds: i64::from_le_bytes(raw[24 + i * 8..32 + i * 8].try_into().unwrap()),
        nanos: word(raw, 48 + i * 4),
    })
}
