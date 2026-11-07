// SPDX-License-Identifier: GPL-3.0-or-later
//! Actual shared OFDs travel with their Unix message, without an owner ledger.
use super::*;

#[derive(Clone, Default)]
pub struct SharedRights(Option<RightsSet>, bool);
#[derive(Clone)]
enum RightsSet {
    Shared(Arc<[Arc<SharedOpenDescription>]>),
    Original(Arc<[CarriedOpen]>),
}
impl RightsSet {
    fn metadata(&self) -> impl Iterator<Item = &Arc<SharedOpenDescription>> {
        let (shared, original) = match self {
            Self::Shared(v) => (Some(v), None),
            Self::Original(v) => (None, Some(v)),
        };
        shared.into_iter().flat_map(|v| v.iter()).chain(
            original
                .into_iter()
                .flat_map(|v| v.iter())
                .map(CarriedOpen::metadata),
        )
    }
    fn originals(&self) -> impl Iterator<Item = OpenHandle> + '_ {
        let (shared, original) = match self {
            Self::Shared(v) => (Some(v), None),
            Self::Original(v) => (None, Some(v)),
        };
        shared
            .into_iter()
            .flat_map(|v| v.iter())
            .cloned()
            .map(OpenHandle::Shared)
            .chain(
                original
                    .into_iter()
                    .flat_map(|v| v.iter())
                    .map(CarriedOpen::original),
            )
    }
    fn len(&self) -> usize {
        match self {
            Self::Shared(v) => v.len(),
            Self::Original(v) => v.len(),
        }
    }
}
#[derive(Clone)]
enum CarriedOpen {
    Shared(Arc<SharedOpenDescription>),
    Original {
        open: OpenHandle,
        metadata: Arc<SharedOpenDescription>,
    },
}
impl CarriedOpen {
    fn new(open: OpenHandle) -> Self {
        match open {
            OpenHandle::Shared(open) => Self::Shared(open),
            open => {
                let metadata = open.borrow().shared.clone();
                Self::Original { open, metadata }
            }
        }
    }
    fn metadata(&self) -> &Arc<SharedOpenDescription> {
        match self {
            Self::Shared(open) => open,
            Self::Original { metadata, .. } => metadata,
        }
    }
    fn original(&self) -> OpenHandle {
        match self {
            Self::Shared(open) => OpenHandle::Shared(open.clone()),
            Self::Original { open, .. } => open.clone(),
        }
    }
}
#[derive(Clone)]
pub(super) enum QueuedRights {
    Shared(SharedRights),
    Owned(Arc<ownership::Link>),
}
impl QueuedRights {
    pub fn into_shared(self) -> Option<SharedRights> {
        match self {
            Self::Shared(rights) => Some(rights),
            Self::Owned(link) => Some(link.rights()),
        }
    }
    pub fn for_receiver(
        receiver: &Arc<LocalResource>,
        rights: SharedRights,
    ) -> Result<Option<Self>> {
        if rights.is_empty() {
            Ok(None)
        } else if rights.1 {
            ownership::Ownership::shared(receiver, rights).map(|link| Some(Self::Owned(link)))
        } else {
            Ok(Some(Self::Shared(rights)))
        }
    }
}
impl LocalRights {
    pub(super) fn shared(&self) -> SharedRights {
        let mut opens = Vec::with_capacity(self.0.len());
        let mut unix = false;
        for open in &self.0 {
            let OpenHandle::Shared(open) = open else {
                return SharedRights::from_handles(self.0.iter().cloned());
            };
            unix |= open.local.is_some()
                || matches!(open.control, Some(events::SharedControl::Uring(_)));
            opens.push(open.clone());
        }
        SharedRights::new(opens, unix)
    }
}
impl SharedRights {
    pub(super) fn new(opens: Vec<Arc<SharedOpenDescription>>, unix: bool) -> Self {
        Self(
            (!opens.is_empty()).then(|| RightsSet::Shared(opens.into())),
            unix,
        )
    }
    fn from_handles(opens: impl IntoIterator<Item = OpenHandle>) -> Self {
        let opens: Vec<_> = opens.into_iter().map(CarriedOpen::new).collect();
        let unix = opens.iter().any(|o| {
            o.metadata().local.is_some()
                || matches!(o.metadata().control, Some(events::SharedControl::Uring(_)))
        });
        Self(
            (!opens.is_empty()).then(|| RightsSet::Original(opens.into())),
            unix,
        )
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_none()
    }
    pub(super) fn owns_unix(&self) -> bool {
        self.1
    }
    pub(super) fn len(&self) -> usize {
        self.0.as_ref().map_or(0, |opens| opens.len())
    }
    pub(super) fn iter(&self) -> impl Iterator<Item = &Arc<SharedOpenDescription>> {
        self.0.iter().flat_map(RightsSet::metadata)
    }
    pub fn local(&self) -> LocalRights {
        LocalRights(self.0.iter().flat_map(RightsSet::originals).collect())
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
            return Some(self.send_credentials(side, bytes, flags, Some(identity)));
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
                    Some(rights) => rights.into_shared().expect("portable receive preflight"),
                    None => SharedRights::default(),
                };
                let kind = received.options[1];
                LocalReceived {
                    data: received.data,
                    length: received.length,
                    truncated: received.truncated,
                    rights,
                    credentials: if received.options[0] != 0 {
                        received.credentials.or(Some([0, 65534, 65534]))
                    } else {
                        None
                    },
                    source: if received.source.is_empty() {
                        vec![1, 0]
                    } else {
                        received.source
                    },
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
    /// One original Files transaction captures complete descriptions. Opaque
    /// control lifetime does not grant additional byte/control execution authority.
    pub fn send_local_rights(&self, fds: &[u32]) -> Option<Result<SharedRights>> {
        if fds.is_empty() {
            return Some(Ok(SharedRights::default()));
        }
        if fds.len() > 253 {
            return Some(Err(Errno(22)));
        }
        let (shared, originals) = {
            let entries = self.files.0.entries.lock().unwrap();
            let mut shared = Vec::with_capacity(fds.len());
            let mut originals: Option<Vec<OpenHandle>> = None;
            for fd in fds {
                let Some(slot) = entries.get(fd) else {
                    return Some(Err(Errno(9)));
                };
                match &slot.open {
                    fd_table::SlotOpen::Shared(open) => {
                        if open.pipe.as_ref().is_some_and(|p| p.has_waiter()) {
                            return Some(Err(Errno(9)));
                        }
                        if let Some(originals) = &mut originals {
                            originals.push(OpenHandle::Shared(open.clone()));
                        } else {
                            shared.push(open.clone());
                        }
                    }
                    fd_table::SlotOpen::Owner(open, ..) => {
                        originals
                            .get_or_insert_with(|| {
                                std::mem::take(&mut shared)
                                    .into_iter()
                                    .map(OpenHandle::Shared)
                                    .collect()
                            })
                            .push(open.clone());
                    }
                }
            }
            (shared, originals)
        };
        Some(Ok(if let Some(originals) = originals {
            SharedRights::from_handles(originals)
        } else {
            let unix = shared.iter().any(|o| {
                o.local.is_some() || matches!(o.control, Some(events::SharedControl::Uring(_)))
            });
            SharedRights::new(shared, unix)
        }))
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
        let originals = rights
            .0
            .iter()
            .flat_map(RightsSet::originals)
            .take(capacity)
            .map(|open| {
                fd_table::Slot::from_descriptor(&Descriptor {
                    open,
                    cloexec: cloexec.into(),
                })
            })
            .collect::<Vec<_>>();
        let mut slots = originals.into_iter();
        let mut fds = Vec::new();
        {
            let mut entries = self.files.0.entries.lock().unwrap();
            while slots.len() != 0 {
                let Some(fd) = entries
                    .available(0)
                    .filter(|fd| *fd < self.files.descriptor_limit())
                else {
                    break;
                };
                assert!(entries.insert(fd, slots.next().unwrap()).is_none());
                fds.push(fd);
            }
            if !fds.is_empty() {
                self.files.changed(&mut entries);
            }
        }
        drop(slots);

        let truncated = fds.len() < rights.len();
        (fds, truncated)
    }
}
