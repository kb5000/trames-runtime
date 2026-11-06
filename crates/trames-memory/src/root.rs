// SPDX-License-Identifier: GPL-3.0-or-later
//! Original CLONE_VM structural custody, separate from execution View bytes.
pub(super) use trames_shared::Custody as Root;
pub use trames_shared::CustodyWrite as Write;

/// Owned structural permission; no additional guest Memory root is created.
/// Its lock is deliberately !Send and is released before parking an executor.
pub struct MemoryAdmission {
    _permit: Option<trames_shared::Admission<crate::Memory>>,
}
impl crate::Memory {
    pub fn try_admit(&self) -> Option<MemoryAdmission> {
        Some(MemoryAdmission {
            _permit: match &self.shared {
                Some(root) => Some(root.try_admit()?),
                None => None,
            },
        })
    }
    /// Register before retrying try_admit; a private mm has no separate
    /// structural owner, so its already-owned task body supplies custody.
    pub fn subscribe_custody(
        &self,
        signal: &std::sync::Arc<trames_shared::IoSignal>,
    ) -> Option<trames_shared::IoSubscription> {
        self.shared.as_ref().map(|root| root.subscribe(signal))
    }
}
