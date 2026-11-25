// SPDX-License-Identifier: GPL-3.0-or-later
//! Session keyring metadata belongs to the guest. Worker views share a task's
//! selection. Fork copies that selection, while the ring itself stays shared.
use crate::{capabilities, Credentials, Errno, Result, Vfs};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

mod links;
const VIEW: u32 = 1;
const READ: u32 = 2;
const WRITE: u32 = 4;
const LINK: u32 = 16;
const SEARCH: u32 = 8;
const SETATTR: u32 = 32;
const PERMISSIONS: u32 = 0x3f3f3f3f;

pub(super) struct Ring {
    id: i32,
    name: Vec<u8>,
    named: bool,
    uid: u32,
    gid: u32,
    namespace: u64,
    user_session: bool,
    permissions: Mutex<u32>,
    links: Mutex<BTreeMap<Vec<u8>, Arc<Ring>>>,
}

impl Ring {
    fn allows(&self, c: &Credentials, mask: u32, possessed: bool, need: u32) -> bool {
        let class = if c.fsuid == self.uid {
            mask >> 16
        } else if mask & 0x3f00 != 0 && self.gid != u32::MAX && c.in_group(self.gid) {
            mask >> 8
        } else {
            mask
        };
        (class | if possessed { mask >> 24 } else { 0 }) & need != 0
    }
}

#[derive(Default)]
struct Index {
    last_id: i32,
    by_id: BTreeMap<i32, Weak<Ring>>,
}
pub(super) type UserSessions = Mutex<BTreeMap<(u32, bool), Arc<Ring>>>;
pub struct KeyRegistry {
    initial_sessions: UserSessions,
    index: Mutex<Index>,
    limits: [AtomicU32; 2],
}
impl Default for KeyRegistry {
    fn default() -> Self {
        Self {
            initial_sessions: Default::default(),
            index: Mutex::default(),
            limits: [200, 1_000_000].map(AtomicU32::new),
        }
    }
}
impl KeyRegistry {
    pub(super) fn limit(&self, root: bool) -> u32 {
        self.limits[root as usize].load(Ordering::Relaxed)
    }
    pub(super) fn set_limit(&self, root: bool, limit: u32) {
        self.limits[root as usize].store(limit, Ordering::Relaxed);
    }
    fn user_ring(&self, c: &Credentials, session: bool) -> Result<Arc<Ring>> {
        let mut rings = c
            .user_namespace
            .key_sessions(&self.initial_sessions)
            .lock()
            .unwrap();
        if let Some(ring) = rings.get(&(c.uid, session)) {
            return Ok(ring.clone());
        }
        let user = match rings.get(&(c.uid, false)) {
            Some(ring) => ring.clone(),
            None => {
                let ring = self.obtain(c, Kind::User, false)?;
                rings.insert((c.uid, false), ring.clone());
                ring
            }
        };
        if !session {
            return Ok(user);
        }
        let ring = self.obtain(c, Kind::UserSession, false)?;
        ring.links.lock().unwrap().insert(user.name.clone(), user);
        rings.insert((c.uid, true), ring.clone());
        Ok(ring)
    }
    fn obtain(&self, c: &Credentials, kind: Kind, overrun: bool) -> Result<Arc<Ring>> {
        let mut index = self.index.lock().unwrap();
        let uid = c.uid;
        let mut charged = 0;
        index.by_id.retain(|_, ring| ring.strong_count() != 0);
        for ring in index.by_id.values().filter_map(Weak::upgrade) {
            charged += u32::from(ring.uid == uid);
            if let Kind::Named(name) = &kind {
                if ring.named
                    && ring.name == *name
                    && ring.namespace == c.user_namespace.id()
                    && ring.allows(c, *ring.permissions.lock().unwrap(), false, SEARCH)
                {
                    return Ok(ring);
                }
            }
        }
        if !overrun && charged >= self.limit(uid == 0) {
            return Err(Errno(122));
        }
        let id = index.last_id.checked_add(1).ok_or(Errno(28))?;
        let named = matches!(kind, Kind::Named(_));
        let user_session = matches!(kind, Kind::UserSession);
        let (name, gid, permissions) = match kind {
            Kind::Named(name) => (name, c.gid, 0x3f130000),
            Kind::Anonymous => (b"_ses".to_vec(), c.gid, 0x3f030000),
            Kind::User => (
                format!("_uid.{}", c.user_namespace.visible(false, uid)).into_bytes(),
                u32::MAX,
                0x1f3f0000,
            ),
            Kind::UserSession => (
                format!("_uid_ses.{}", c.user_namespace.visible(false, uid)).into_bytes(),
                u32::MAX,
                0x1f3f0000,
            ),
        };
        let ring = Arc::new(Ring {
            id,
            uid,
            gid,
            name,
            named,
            namespace: c.user_namespace.id(),
            user_session,
            permissions: Mutex::new(permissions),
            links: Mutex::default(),
        });
        index.last_id = id;
        index.by_id.insert(id, Arc::downgrade(&ring));
        Ok(ring)
    }
}
enum Kind {
    User,
    UserSession,
    Anonymous,
    Named(Vec<u8>),
}

#[derive(Clone, Default)]
pub struct SessionKeys(Arc<OnceLock<Mutex<Option<Arc<Ring>>>>>);
impl SessionKeys {
    pub fn fork(&self) -> Self {
        let child = Self::default();
        if let Some(ring) = self.0.get().and_then(|slot| slot.lock().unwrap().clone()) {
            child.slot().lock().unwrap().replace(ring);
        }
        child
    }
    fn slot(&self) -> &Mutex<Option<Arc<Ring>>> {
        self.0.get_or_init(Mutex::default)
    }
    pub fn retire(&self) {
        if let Some(slot) = self.0.get() {
            slot.lock().unwrap().take();
        }
    }
    pub fn join(
        &self,
        registry: &KeyRegistry,
        c: &Credentials,
        name: Option<Vec<u8>>,
    ) -> Result<u64> {
        if name.as_ref().is_some_and(|n| n.first() == Some(&b'.')) {
            return Err(Errno(1));
        }
        let kind = match name {
            Some(name) if name.is_empty() => return Err(Errno(22)),
            Some(name) => Kind::Named(name),
            None => Kind::Anonymous,
        };
        let mut selection = self.slot().lock().unwrap();
        let overrun = selection.is_none() && matches!(kind, Kind::Anonymous);
        let ring = registry.obtain(c, kind, overrun)?;
        let id = ring.id;
        *selection = Some(ring);
        Ok(id as u64)
    }
    fn resolve(
        &self,
        registry: &KeyRegistry,
        c: &Credentials,
        id: i32,
        create: bool,
    ) -> Result<(Arc<Ring>, bool)> {
        Ok({
            let mut selection = self.slot().lock().unwrap();
            match id {
                -3 => {
                    if selection.is_none() {
                        *selection = Some(registry.user_ring(c, true)?);
                    }
                    if create && selection.as_ref().is_some_and(|r| r.user_session) {
                        *selection = Some(registry.obtain(c, Kind::Anonymous, false)?);
                    }
                    (selection.as_ref().unwrap().clone(), true)
                }
                -4 => (registry.user_ring(c, false)?, true),
                -5 => (registry.user_ring(c, true)?, true),
                id if id > 0 => {
                    if let Some(ring) = selection.as_ref().filter(|r| r.id == id) {
                        (ring.clone(), true)
                    } else {
                        let ring = registry
                            .index
                            .lock()
                            .unwrap()
                            .by_id
                            .get(&id)
                            .and_then(Weak::upgrade)
                            .ok_or(Errno(126))?;
                        let possessed = selection
                            .as_ref()
                            .is_some_and(|root| links::possessed(root, c, id));
                        (ring, possessed)
                    }
                }
                _ => return Err(Errno(126)),
            }
        })
    }
    pub fn access(
        &self,
        registry: &KeyRegistry,
        c: &Credentials,
        id: i32,
        op: KeyOperation,
    ) -> Result<KeyResult> {
        let (ring, possessed) =
            self.resolve(registry, c, id, matches!(op, KeyOperation::Lookup(true)))?;
        let mut mask = ring.permissions.lock().unwrap();
        let need = match op {
            KeyOperation::Lookup(_) => SEARCH,
            KeyOperation::Describe => VIEW,
            KeyOperation::Read => READ,
            KeyOperation::SetPermissions(value) => {
                if value & !PERMISSIONS != 0 {
                    return Err(Errno(22));
                }
                SETATTR
            }
        };
        if !ring.allows(c, *mask, possessed, need) {
            return Err(Errno(13));
        }
        Ok(match op {
            KeyOperation::Lookup(_) => KeyResult::Number(ring.id as u64),
            KeyOperation::Read => KeyResult::Bytes(
                ring.links
                    .lock()
                    .unwrap()
                    .values()
                    .flat_map(|r| r.id.to_le_bytes())
                    .collect(),
            ),
            KeyOperation::Describe => {
                let uid = c.user_namespace.visible(false, ring.uid);
                let gid = c.user_namespace.visible(true, ring.gid);
                let mut desc = format!("keyring;{uid};{gid};{:08x};", *mask).into_bytes();
                desc.extend_from_slice(&ring.name);
                desc.push(0);
                KeyResult::Description(desc)
            }
            KeyOperation::SetPermissions(value) => {
                if c.fsuid != ring.uid && !c.has_cap(capabilities::SYS_ADMIN) {
                    return Err(Errno(1));
                }
                *mask = value;
                KeyResult::Number(0)
            }
        })
    }
}
pub enum KeyOperation {
    Lookup(bool),
    Describe,
    Read,
    SetPermissions(u32),
}
pub enum KeyResult {
    Number(u64),
    Description(Vec<u8>),
    Bytes(Vec<u8>),
}
impl Vfs {
    pub fn key_registry(&self) -> Arc<KeyRegistry> {
        self.pseudo.borrow().keys.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_charges_real_uid_and_releases_after_last_holder_exits() {
        let keys = KeyRegistry::default();
        keys.set_limit(false, 1);
        let mut c = Credentials::user(1000, 2000);
        c.fsuid = 7;
        c.fsgid = 8;
        let task = SessionKeys::default();
        let name = || Some(b"worker".to_vec());
        let id = task.join(&keys, &c, name()).unwrap();
        let child = task.fork();
        let bytes = match child.access(&keys, &c, -3, KeyOperation::Describe).unwrap() {
            KeyResult::Description(bytes) => bytes,
            _ => unreachable!(),
        };
        assert_eq!(bytes, b"keyring;1000;2000;3f130000;worker\0");
        task.retire();
        assert_eq!(task.join(&keys, &c, name()), Err(Errno(122)));
        child.retire();
        assert_ne!(task.join(&keys, &c, name()).unwrap(), id);
    }

    #[test]
    fn create_replaces_default_and_leaves_inherited_selection_intact() {
        let registry = KeyRegistry::default();
        let user = Credentials::user(1000, 1000);
        let parent = SessionKeys::default();
        let lookup = |task: &SessionKeys, id, create| match task
            .access(&registry, &user, id, KeyOperation::Lookup(create))
            .unwrap()
        {
            KeyResult::Number(value) => value,
            _ => unreachable!(),
        };
        let default = lookup(&parent, -3, false);
        let child = parent.fork();
        let private = lookup(&parent, -3, true);
        assert_ne!(private, default);
        assert_eq!(lookup(&parent, -3, true), private);
        assert_eq!(lookup(&parent, -5, false), default);
        assert_eq!(lookup(&child, -3, false), default);
    }
}
