// SPDX-License-Identifier: GPL-3.0-or-later
//! Original filesystem capacity, shared by inode writers rather than admitted
//! independently from stale whole-filesystem size scans. Only growth reserves;
//! ordinary bytes and metadata do not acquire a filesystem-wide algorithm lock.
use super::*;
use std::sync::OnceLock;

pub(super) struct FileQuota {
    pub used: Arc<AtomicU64>,
    ceiling: AtomicU64,
}
impl FileQuota {
    pub fn new(used: Arc<AtomicU64>, limit: u64, volume: Option<(VolumeSpace, u64)>) -> Arc<Self> {
        let quota = Arc::new(Self {
            used,
            ceiling: AtomicU64::new(0),
        });
        quota.configure(limit, volume);
        quota
    }
    pub fn configure(&self, limit: u64, volume: Option<(VolumeSpace, u64)>) {
        // Preserve the existing host-volume snapshot: allocation since the
        // snapshot consumes its available bytes, and release restores them.
        let ceiling = volume.map_or(limit, |(v, at)| {
            limit
                .min(v.total_bytes)
                .min(at.saturating_add(v.available_bytes))
        });
        self.ceiling.store(ceiling, Ordering::Relaxed);
    }
}

pub(super) struct FileCharge {
    used: Arc<AtomicU64>,
    size: AtomicU64,
    quota: OnceLock<Arc<FileQuota>>,
}
impl FileCharge {
    pub fn register(used: Arc<AtomicU64>, length: u64) -> Arc<Self> {
        used.fetch_add(length, Ordering::Relaxed);
        Arc::new(Self {
            used,
            size: AtomicU64::new(length),
            quota: OnceLock::new(),
        })
    }
    pub fn bind(&self, quota: &Arc<FileQuota>) {
        // An overlay can retain a provider already charged to its actual upper
        // filesystem. Mount aliases never change that original byte account.
        if Arc::ptr_eq(&self.used, &quota.used) {
            let _ = self.quota.set(quota.clone());
        }
    }
    pub fn size(&self) -> u64 {
        self.size.load(Ordering::Relaxed)
    }
    pub fn publish(&self, length: u64) {
        if self.size() == length {
            return;
        }
        let old = self.size.swap(length, Ordering::Relaxed);
        if length > old {
            self.used.fetch_add(length - old, Ordering::Relaxed);
        } else if old > length {
            self.used.fetch_sub(old - length, Ordering::Relaxed);
        }
    }
    /// The file's original byte/resize lock protects its charge. Charging the
    /// proposed EOF before host allocation excludes concurrent oversubscription.
    /// A failed/short transfer reconciles to actual EOF before releasing it.
    pub fn reserve(&self, length: u64) -> Result<()> {
        let old = self.size();
        if length <= old {
            return Ok(());
        }
        let growth = length - old;
        if let Some(quota) = self.quota.get() {
            let limit = quota.ceiling.load(Ordering::Relaxed);
            self.used
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                    used.checked_add(growth).filter(|end| *end <= limit)
                })
                .map_err(|_| Errno(28))?;
        } else {
            self.used.fetch_add(growth, Ordering::Relaxed);
        }
        self.size.store(length, Ordering::Relaxed);
        Ok(())
    }
}
impl Drop for FileCharge {
    fn drop(&mut self) {
        self.used.fetch_sub(*self.size.get_mut(), Ordering::Relaxed);
    }
}

pub(super) struct Growth {
    charge: Arc<FileCharge>,
    before: Option<u64>,
}
impl Growth {
    pub fn commit(mut self, length: u64) {
        self.charge.publish(length);
        self.before = None;
    }
}
impl Drop for Growth {
    fn drop(&mut self) {
        if let Some(before) = self.before {
            self.charge.publish(before);
        }
    }
}
impl FileCharge {
    pub fn admit(quota: &Arc<FileQuota>, length: u64) -> Result<Arc<Self>> {
        let charge = Self::register(quota.used.clone(), 0);
        charge.bind(quota);
        charge.reserve(length)?;
        Ok(charge)
    }
    pub fn grow(self: &Arc<Self>, length: u64) -> Result<Option<Growth>> {
        let before = self.size();
        if length <= before {
            return Ok(None);
        }
        self.reserve(length)?;
        Ok(Some(Growth {
            charge: self.clone(),
            before: Some(before),
        }))
    }
}
