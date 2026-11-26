// SPDX-License-Identifier: GPL-3.0-or-later
//! Reusable projection payloads have no capability effect until publication.
use super::*;
use std::sync::Weak;

type Caps = Option<file_caps::FileCaps>;
pub(super) type Cache = Mutex<BTreeMap<Caps, Weak<PreparedCaps>>>;
pub(crate) struct PreparedCaps {
    pub file: Arc<PlainFile>,
    caps: Caps,
    staged: Option<storage::projection_caps::Staged>,
}
pub(crate) struct PublishedCaps {
    old: Caps,
    disk: Option<storage::projection_caps::Published>,
}
pub(crate) struct CapabilityGuard<'a> {
    prepared: &'a PreparedCaps,
    bytes: std::sync::RwLockWriteGuard<'a, Bytes>,
}
impl PlainFile {
    pub(crate) fn prepare_projected_caps(
        self: &Arc<Self>,
        caps: Caps,
    ) -> Result<Arc<PreparedCaps>> {
        let mut cache = self
            .projection_caps
            .get_or_init(Default::default)
            .lock()
            .unwrap();
        if let Some(prepared) = cache.get(&caps).and_then(Weak::upgrade) {
            return Ok(prepared);
        }
        cache.retain(|_, prepared| prepared.strong_count() != 0);
        let data = self.bytes.read().unwrap();
        let staged = match &*data {
            Bytes::Disk(d) if d.backing._store.is_some() => caps
                .map(|caps| storage::projection_caps::Staged::new(d.backing.clone(), caps))
                .transpose()?,
            Bytes::Tmpfs(_) => None,
            _ => return Err(Errno(95)),
        };
        let prepared = Arc::new(PreparedCaps {
            file: self.clone(),
            caps,
            staged,
        });
        cache.insert(caps, Arc::downgrade(&prepared));
        Ok(prepared)
    }
}
impl PreparedCaps {
    /// Admit every affected provider before publishing any of them. These
    /// original byte guards only span the already-admitted native commit;
    /// background writeback cannot revoke a grant between rename and rollback.
    pub fn lock(&self, expected: Caps) -> Result<CapabilityGuard<'_>> {
        let bytes = self.file.bytes.write().unwrap();
        self.file.check_transaction()?;
        let current = match &*bytes {
            Bytes::Tmpfs(file) => file.capabilities,
            Bytes::Disk(d) => d.capabilities,
            _ => return Err(Errno(95)),
        };
        if current != expected {
            return Err(overlay::projection::retry());
        }
        Ok(CapabilityGuard {
            prepared: self,
            bytes,
        })
    }
}
impl CapabilityGuard<'_> {
    pub fn publish(&mut self) -> Result<PublishedCaps> {
        let (old, disk) = match &mut *self.bytes {
            Bytes::Tmpfs(file) => {
                let old = file.capabilities;
                file.capabilities = self.prepared.caps;
                (old, None)
            }
            Bytes::Disk(d) => {
                let old = d.capabilities;
                let published =
                    d.publish_projected_caps(self.prepared.caps, self.prepared.staged.as_ref())?;
                (old, Some(published))
            }
            _ => return Err(Errno(95)),
        };
        Ok(PublishedCaps { old, disk })
    }
    pub fn rollback(&mut self, publication: PublishedCaps) -> Result<()> {
        match (&mut *self.bytes, publication.disk) {
            (Bytes::Tmpfs(file), None) => {
                file.capabilities = publication.old;
                Ok(())
            }
            (Bytes::Disk(d), Some(published)) => d.rollback_projected_caps(published),
            _ => Err(Errno(5)),
        }
    }
}
