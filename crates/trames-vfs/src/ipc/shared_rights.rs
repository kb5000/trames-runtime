// SPDX-License-Identifier: GPL-3.0-or-later
//! Actual shared OFDs travel with their Unix message, without an owner ledger.
use super::*;

#[derive(Clone, Default)]
pub struct SharedRights(Option<Arc<[Arc<SharedOpenDescription>]>>);
#[derive(Clone)]
pub(super) enum QueuedRights {
    Owner(u64),
    Shared(SharedRights),
}
impl QueuedRights {
    pub fn owner(&self) -> Option<u64> {
        match self {
            Self::Owner(id) => Some(*id),
            Self::Shared(_) => None,
        }
    }
}
impl LocalRights {
    pub(super) fn shared(&self) -> Option<SharedRights> {
        self.0
            .iter()
            .map(|open| match open {
                OpenHandle::Shared(open) => Some(open.clone()),
                OpenHandle::Owner(_) => None,
            })
            .collect::<Option<Vec<_>>>()
            .map(SharedRights::new)
    }
}
impl SharedRights {
    fn new(opens: Vec<Arc<SharedOpenDescription>>) -> Self {
        Self((!opens.is_empty()).then(|| opens.into()))
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_none()
    }
    fn len(&self) -> usize {
        self.0.as_ref().map_or(0, |opens| opens.len())
    }
    fn iter(&self) -> impl Iterator<Item = &Arc<SharedOpenDescription>> {
        self.0.iter().flat_map(|opens| opens.iter())
    }
    pub fn local(&self) -> LocalRights {
        LocalRights(self.iter().cloned().map(OpenHandle::Shared).collect())
    }
}

impl channel::Resource {
    pub fn send_local(
        &self,
        side: usize,
        bytes: &[u8],
        flags: u32,
        rights: &SharedRights,
        identity: [u32; 3],
    ) -> Option<Result<usize>> {
        if rights.is_empty() {
            return Some(self.send_credentials(side, bytes, flags, None, Some(identity)));
        }
        Some(self.send_shared(side, bytes, flags, rights.clone(), Some(identity)))
    }
    pub fn recv_local(
        &self,
        side: usize,
        count: usize,
        flags: u32,
    ) -> Option<Result<LocalReceived<SharedRights>>> {
        self.recv_portable(side, count, flags).map(|result| {
            result.map(|received| {
                let rights = match received.rights {
                    Some(QueuedRights::Shared(rights)) => rights,
                    None => SharedRights::default(),
                    Some(QueuedRights::Owner(_)) => unreachable!("portable receive preflight"),
                };
                let kind = received.options[1];
                LocalReceived {
                    data: received.data,
                    length: received.length,
                    truncated: received.truncated,
                    rights,
                    credentials: if received.options[0] != 0 {
                        received.credentials
                    } else {
                        None
                    },
                    source: vec![1, 0],
                    timestamp: (kind != 0).then_some(received.timestamp).flatten().map(
                        |mut stamp| {
                            if matches!(kind, 29 | 63) {
                                stamp[1] /= 1000;
                            }
                            (kind, stamp)
                        },
                    ),
                }
            })
        })
    }
}

impl DescriptorFactory {
    /// Missing/invalid descriptors retain normal error order. An owner-only
    /// object defers the complete message before any bytes or rights are sent.
    pub fn send_local_rights(&self, fds: &[u32]) -> Option<Result<SharedRights>> {
        if fds.is_empty() {
            return Some(Ok(SharedRights::default()));
        }
        if fds.len() > 253 {
            return Some(Err(Errno(22)));
        }
        let entries = self.files.0.entries.lock().unwrap();
        let mut rights = Vec::with_capacity(fds.len());
        for fd in fds {
            let Some(slot) = entries.get(fd) else {
                return Some(Err(Errno(9)));
            };
            let open = slot.shared_open()?;
            let open = match open {
                Ok(open) => open,
                Err(e) => return Some(Err(e)),
            };
            rights.push(open.clone());
        }
        Some(Ok(SharedRights::new(rights)))
    }
    /// Import into the original real Files domain as one publication. Excess
    /// rights are dropped after releasing Files; no resource destructor or
    /// readiness callback executes under that membership lock.
    pub fn receive_local_rights(
        &self,
        rights: SharedRights,
        capacity: usize,
        cloexec: bool,
    ) -> (Vec<u32>, bool) {
        if rights.is_empty() {
            return (Vec::new(), false);
        }
        let mut fds = Vec::new();
        {
            let mut entries = self.files.0.entries.lock().unwrap();
            for open in rights.iter().take(capacity) {
                let Some(fd) = entries
                    .available(0)
                    .filter(|fd| *fd < self.files.descriptor_limit())
                else {
                    break;
                };
                let previous = entries.insert(
                    fd,
                    fd_table::Slot {
                        open: fd_table::SlotOpen::Shared(open.clone()),
                        cloexec: cloexec.into(),
                    },
                );
                debug_assert!(previous.is_none());
                fds.push(fd);
            }
            if !fds.is_empty() {
                self.files.changed(&mut entries);
            }
        }
        let truncated = fds.len() < rights.len();
        (fds, truncated)
    }
}
