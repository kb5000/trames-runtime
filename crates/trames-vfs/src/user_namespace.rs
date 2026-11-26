// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest user namespaces. Kernel-facing identities stay global; only ABI edges
//! translate them. The initial namespace requires no map lookup.
use super::*;
use std::sync::{Mutex, OnceLock};
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
const INITIAL: u64 = 0xefff_fffd;
static NEXT: AtomicU64 = AtomicU64::new(0xb000_0000);
#[derive(Clone)]
pub struct UserNamespace(Namespace);
#[derive(Clone)]
enum Namespace {
    Initial(Arc<OverflowIds>),
    Child(Arc<UserSpace>),
}
pub(super) struct OverflowIds(
    [std::sync::atomic::AtomicU32; 2],
    pub(super) Arc<perf::Accounts>,
);
impl Default for OverflowIds {
    fn default() -> Self {
        Self(
            [65534, 65534].map(std::sync::atomic::AtomicU32::new),
            Arc::default(),
        )
    }
}
impl OverflowIds {
    pub(super) fn get(&self, group: bool) -> u32 {
        self.0[group as usize].load(Ordering::Relaxed)
    }
    pub(super) fn set(&self, group: bool, value: u32) {
        self.0[group as usize].store(value, Ordering::Relaxed);
    }
}
#[derive(Clone, Default)]
pub(super) enum WeakUserNamespace {
    #[default]
    Unspecified,
    Initial(std::sync::Weak<OverflowIds>),
    Child(std::sync::Weak<UserSpace>),
}
impl Default for UserNamespace {
    fn default() -> Self {
        Self(Namespace::Initial(Arc::default()))
    }
}
pub(super) struct UserSpace {
    key_sessions: OnceLock<crate::keyrings::UserSessions>,
    overflow: Arc<OverflowIds>,
    id: u64,
    parent: UserNamespace,
    owner: u32,
    depth: u32,
    creator_setfcap: bool,
    maps: [OnceLock<Vec<Extent>>; 2],
    policy: Mutex<bool>,
    limits: Arc<UserNamespaceLimits>,
    // From the immediate parent to the initial namespace, under each creator's UID.
    charges: Vec<NamespaceCharge>,
}
pub(super) struct UserNamespaceLimits {
    usage: Mutex<NamespaceUsage>,
}
struct NamespaceUsage {
    max: u32,
    by_uid: BTreeMap<u32, u32>,
}
impl UserNamespaceLimits {
    fn new(max: u32) -> Self {
        Self {
            usage: Mutex::new(NamespaceUsage {
                max,
                by_uid: BTreeMap::new(),
            }),
        }
    }
    pub(super) fn max(&self) -> u32 {
        self.usage.lock().unwrap().max
    }
    pub(super) fn set(&self, max: u32) {
        self.usage.lock().unwrap().max = max;
    }
    fn charge(self: &Arc<Self>, uid: u32) -> Result<NamespaceCharge> {
        let mut usage = self.usage.lock().unwrap();
        let used = usage.by_uid.get(&uid).copied().unwrap_or(0);
        if used >= usage.max {
            return Err(Errno(28));
        }
        usage.by_uid.insert(uid, used + 1);
        Ok(NamespaceCharge {
            limits: self.clone(),
            uid,
        })
    }
}
struct NamespaceCharge {
    limits: Arc<UserNamespaceLimits>,
    uid: u32,
}
impl Drop for NamespaceCharge {
    fn drop(&mut self) {
        let mut usage = self.limits.usage.lock().unwrap();
        let users = &mut usage.by_uid;
        let count = users.get_mut(&self.uid).expect("live namespace charge");
        *count -= 1;
        if *count == 0 {
            users.remove(&self.uid);
        }
    }
}
#[derive(Clone, Copy)]
struct Extent {
    first: u32,
    lower: u32,
    count: u32,
}
/// A mount takes a copy, including an empty map. Later uid_map/gid_map writes
/// to the namespace cannot change the already accepted mount translation.
pub(super) struct IdMapping([Vec<Extent>; 2]);
impl IdMapping {
    pub(super) fn down(&self, group: bool, id: u32) -> Option<u32> {
        if id == u32::MAX {
            return None;
        }
        let e = self.0[usize::from(group)]
            .iter()
            .find(|e| id >= e.first && id - e.first < e.count)?;
        Some(e.lower + (id - e.first))
    }
    pub(super) fn up(&self, group: bool, id: u32) -> Option<u32> {
        if id == u32::MAX {
            return None;
        }
        let e = self.0[usize::from(group)]
            .iter()
            .find(|e| id >= e.lower && id - e.lower < e.count)?;
        Some(e.first + (id - e.lower))
    }
}
impl std::fmt::Debug for UserNamespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("UserNamespace").field(&self.id()).finish()
    }
}
impl PartialEq for UserNamespace {
    fn eq(&self, other: &Self) -> bool {
        match (self.child(), other.child()) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}
impl Eq for UserNamespace {}
impl UserNamespace {
    pub(super) fn idmapping(&self) -> IdMapping {
        let groups = [false, true].map(|group| {
            self.child()
                .and_then(|ns| ns.maps[usize::from(group)].get())
                .into_iter()
                .flatten()
                .map(|e| Extent {
                    first: e.first,
                    lower: self
                        .global_range(group, e.first, e.count)
                        .expect("published namespace range remains mapped"),
                    count: e.count,
                })
                .collect()
        });
        IdMapping(groups)
    }
    fn child(&self) -> Option<&Arc<UserSpace>> {
        match &self.0 {
            Namespace::Child(n) => Some(n),
            Namespace::Initial(_) => None,
        }
    }
    pub(super) fn overflow(&self) -> &Arc<OverflowIds> {
        match &self.0 {
            Namespace::Initial(ids) => ids,
            Namespace::Child(n) => &n.overflow,
        }
    }
    pub(super) fn key_sessions<'a>(
        &'a self,
        initial: &'a crate::keyrings::UserSessions,
    ) -> &'a crate::keyrings::UserSessions {
        self.child()
            .map_or(initial, |ns| ns.key_sessions.get_or_init(Default::default))
    }
    pub fn is_initial(&self) -> bool {
        matches!(self.0, Namespace::Initial(_))
    }
    pub fn id(&self) -> u64 {
        self.child().map_or(INITIAL, |n| n.id)
    }
    pub fn parent(&self) -> Option<Self> {
        self.child().map(|n| n.parent.clone())
    }
    pub fn owner(&self) -> Option<u32> {
        self.child().map(|n| n.owner)
    }
    pub fn contains(&self, target: &Self) -> bool {
        let mut at = target.clone();
        loop {
            if at == *self {
                return true;
            }
            let Some(parent) = at.parent() else {
                return false;
            };
            at = parent;
        }
    }
    fn create(credentials: &Credentials, limits: &Arc<UserNamespaceLimits>) -> Result<Self> {
        let parent = credentials.user_namespace.clone();
        let depth = parent.child().map_or(1, |n| n.depth + 1);
        if depth > 32 {
            return Err(Errno(28));
        }
        if parent.from_global(false, credentials.euid).is_none()
            || parent.from_global(true, credentials.egid).is_none()
        {
            return Err(Errno(1));
        }
        let mut charges = Vec::with_capacity(depth as usize);
        charges.push(limits.charge(credentials.euid)?);
        if let Some(parent) = parent.child() {
            for ancestor in &parent.charges {
                charges.push(ancestor.limits.charge(ancestor.uid)?);
            }
        }
        let allowed = parent.groups_policy();
        let id = NEXT
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Errno(28))?;
        Ok(Self(Namespace::Child(Arc::new(UserSpace {
            key_sessions: OnceLock::new(),
            overflow: parent.overflow().clone(),
            id,
            parent,
            owner: credentials.euid,
            depth,
            creator_setfcap: credentials.has_local_cap(31),
            maps: Default::default(),
            policy: Mutex::new(allowed),
            limits: Arc::new(UserNamespaceLimits::new(i32::MAX as u32)),
            charges,
        }))))
    }
    pub fn to_global(&self, group: bool, id: u32) -> Option<u32> {
        if id == u32::MAX {
            return None;
        }
        let Some(ns) = self.child() else {
            return Some(id);
        };
        let map = ns.maps[usize::from(group)].get()?;
        let e = map
            .iter()
            .find(|e| id >= e.first && id - e.first < e.count)?;
        ns.parent.to_global(group, e.lower + (id - e.first))
    }
    fn global_range(&self, group: bool, first: u32, count: u32) -> Option<u32> {
        let end = first.checked_add(count.checked_sub(1)?)?;
        if end == u32::MAX {
            return None;
        }
        let Some(ns) = self.child() else {
            return Some(first);
        };
        let e = ns.maps[usize::from(group)]
            .get()?
            .iter()
            .find(|e| first >= e.first && end - e.first < e.count)?;
        ns.parent
            .global_range(group, e.lower + (first - e.first), count)
    }
    pub fn from_global(&self, group: bool, id: u32) -> Option<u32> {
        if id == u32::MAX {
            return None;
        }
        let Some(ns) = self.child() else {
            return Some(id);
        };
        let lower = ns.parent.from_global(group, id)?;
        let e = ns.maps[usize::from(group)]
            .get()?
            .iter()
            .find(|e| lower >= e.lower && lower - e.lower < e.count)?;
        Some(e.first + (lower - e.lower))
    }
    pub fn visible(&self, group: bool, id: u32) -> u32 {
        self.from_global(group, id)
            .unwrap_or_else(|| self.overflow().get(group))
    }
    pub fn stat(&self, mut bytes: [u8; 128]) -> [u8; 128] {
        for (group, at) in [(false, 24), (true, 28)] {
            let id = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
            if !self.is_initial() || id == u32::MAX {
                bytes[at..at + 4].copy_from_slice(&self.visible(group, id).to_le_bytes());
            }
        }
        bytes
    }
    pub fn groups_policy(&self) -> bool {
        self.child().is_none_or(|n| *n.policy.lock().unwrap())
    }
    pub fn may_setgroups(&self) -> bool {
        self.child()
            .is_none_or(|n| n.maps[1].get().is_some() && *n.policy.lock().unwrap())
    }
    pub fn capable(&self, caller: &Credentials, cap: u32) -> bool {
        if self == &caller.user_namespace {
            return caller.has_local_cap(cap);
        }
        let mut at = self.clone();
        while let Some(ns) = at.child() {
            if ns.parent == caller.user_namespace && ns.owner == caller.euid {
                return true;
            }
            at = ns.parent.clone();
            if at == caller.user_namespace {
                return caller.has_local_cap(cap);
            }
        }
        false
    }
    pub(super) fn weak(&self) -> WeakUserNamespace {
        match &self.0 {
            Namespace::Initial(ids) => WeakUserNamespace::Initial(Arc::downgrade(ids)),
            Namespace::Child(ns) => WeakUserNamespace::Child(Arc::downgrade(ns)),
        }
    }
    pub(super) fn upgrade(weak: &WeakUserNamespace) -> Result<Self> {
        match weak {
            WeakUserNamespace::Initial(ids) => ids
                .upgrade()
                .map(|ids| Self(Namespace::Initial(ids)))
                .ok_or(Errno(2)),
            WeakUserNamespace::Child(ns) => ns
                .upgrade()
                .map(|ns| Self(Namespace::Child(ns)))
                .ok_or(Errno(2)),
            WeakUserNamespace::Unspecified => Ok(Self::default()),
        }
    }
    fn map_text(&self, group: bool, observer: &Self) -> Vec<u8> {
        let Some(ns) = self.child() else {
            return format!(
                "{:10} {:10} 4294967295\n",
                0,
                observer.from_global(group, 0).unwrap_or(u32::MAX)
            )
            .into_bytes();
        };
        let mut bytes = String::new();
        if let Some(map) = ns.maps[usize::from(group)].get() {
            for e in map {
                let lower = if observer == self {
                    e.lower
                } else {
                    ns.parent
                        .to_global(group, e.lower)
                        .and_then(|id| observer.from_global(group, id))
                        .unwrap_or(u32::MAX)
                };
                bytes.push_str(&format!("{:10} {:10} {:10}\n", e.first, lower, e.count));
            }
        }
        bytes.into_bytes()
    }
}
#[derive(Clone, Copy)]
pub(super) enum MapKind {
    Uid,
    Gid,
    Groups,
}
pub(super) struct MapFile {
    namespace: UserNamespace,
    opener: Credentials,
    kind: MapKind,
}
impl MapFile {
    pub fn new(namespace: UserNamespace, opener: Credentials, kind: MapKind) -> Self {
        Self {
            namespace,
            opener,
            kind,
        }
    }
    pub fn authorized(&self, c: &Credentials) -> bool {
        c.euid == self.namespace.owner().unwrap_or(0)
            || self.namespace.capable(c, capabilities::SYS_ADMIN)
    }
    pub fn reopen(&self, opener: &Credentials) -> Self {
        Self::new(self.namespace.clone(), opener.clone(), self.kind)
    }
    pub fn read(&self, offset: u64, count: usize) -> Result<Vec<u8>> {
        let bytes = match self.kind {
            MapKind::Groups => {
                if self.namespace.groups_policy() {
                    b"allow\n".to_vec()
                } else {
                    b"deny\n".to_vec()
                }
            }
            MapKind::Uid | MapKind::Gid => self.namespace.map_text(
                matches!(self.kind, MapKind::Gid),
                &self.opener.user_namespace,
            ),
        };
        let offset = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        Ok(bytes[offset..offset + count.min(bytes.len() - offset)].to_vec())
    }
    pub fn write(&self, bytes: &[u8], offset: u64, writer: &Credentials) -> Result<usize> {
        let ns = self.namespace.child().ok_or(Errno(1))?;
        if offset != 0 || bytes.len() >= 4096 {
            return Err(Errno(22));
        }
        if self.opener.user_namespace != self.namespace && self.opener.user_namespace != ns.parent {
            return Err(Errno(1));
        }
        if !self.namespace.capable(writer, capabilities::SYS_ADMIN)
            && matches!(self.kind, MapKind::Groups)
        {
            return Err(Errno(1));
        }
        let text = std::str::from_utf8(bytes.split(|b| *b == 0).next().unwrap_or_default())
            .map_err(|_| Errno(22))?;
        let mut allowed = ns.policy.lock().unwrap();
        if matches!(self.kind, MapKind::Groups) {
            if bytes.len() >= 8 {
                return Err(Errno(22));
            }
            match text.trim_end() {
                "allow" if *allowed => {}
                "deny" if ns.maps[1].get().is_none() => *allowed = false,
                "allow" | "deny" => return Err(Errno(1)),
                _ => return Err(Errno(22)),
            }
            return Ok(bytes.len());
        }
        let group = matches!(self.kind, MapKind::Gid);
        let cap = if group {
            capabilities::SETGID
        } else {
            capabilities::SETUID
        };
        if ns.maps[usize::from(group)].get().is_some()
            || !self.namespace.capable(writer, cap)
            || !self.namespace.capable(&self.opener, cap)
        {
            return Err(Errno(1));
        }
        let mut map = Vec::new();
        for line in text.lines() {
            let values = line
                .split_ascii_whitespace()
                .map(str::parse::<u32>)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| Errno(22))?;
            if values.len() != 3
                || values[2] == 0
                || values[0]
                    .checked_add(values[2] - 1)
                    .is_none_or(|end| end == u32::MAX)
                || values[1]
                    .checked_add(values[2] - 1)
                    .is_none_or(|end| end == u32::MAX)
                || map.len() == 340
            {
                return Err(Errno(22));
            }
            let e = Extent {
                first: values[0],
                lower: values[1],
                count: values[2],
            };
            if map.iter().any(|old: &Extent| {
                (u64::from(e.first) < u64::from(old.first) + u64::from(old.count)
                    && u64::from(old.first) < u64::from(e.first) + u64::from(e.count))
                    || (u64::from(e.lower) < u64::from(old.lower) + u64::from(old.count)
                        && u64::from(old.lower) < u64::from(e.lower) + u64::from(e.count))
            }) {
                return Err(Errno(22));
            }
            ns.parent
                .global_range(group, e.lower, e.count)
                .ok_or(Errno(1))?;
            map.push(e);
        }
        if map.is_empty() {
            return Err(Errno(22));
        }
        let privileged = ns.parent.capable(writer, cap) && ns.parent.capable(&self.opener, cap);
        let own = if group {
            self.opener.egid
        } else {
            self.opener.euid
        };
        if !privileged
            && !(map.len() == 1
                && map[0].count == 1
                && self.opener.euid == ns.owner
                && ns.parent.to_global(group, map[0].lower) == Some(own)
                && (!group || !*allowed))
        {
            return Err(Errno(1));
        }
        if !group && map.iter().any(|e| e.lower == 0) {
            let root_allowed = if self.opener.user_namespace == self.namespace {
                ns.creator_setfcap
            } else {
                ns.parent.capable(writer, 31) && ns.parent.capable(&self.opener, 31)
            };
            if !root_allowed {
                return Err(Errno(1));
            }
        }
        ns.maps[usize::from(group)].set(map).map_err(|_| Errno(1))?;
        Ok(bytes.len())
    }
}

impl Vfs {
    pub(super) fn user_namespace_limits(&self) -> Arc<UserNamespaceLimits> {
        if let Some(ns) = self.credentials.user_namespace.child() {
            return ns.limits.clone();
        }
        let pseudo = self.pseudo.borrow();
        let root;
        let owner = match &pseudo.publication {
            Some(publication) => {
                root = publication.borrow();
                &*root
            }
            None => &*pseudo,
        };
        owner
            .user_namespace_limits
            .get_or_init(|| Arc::new(UserNamespaceLimits::new((MAX_TASKS / 2) as u32)))
            .clone()
    }

    pub fn unshare_user(&mut self) -> Result<()> {
        let paths = self.context.paths.borrow();
        if paths
            .root_mount
            .as_ref()
            .zip(paths.root_node.as_ref())
            .is_some_and(|(mount, root)| !Arc::ptr_eq(root, &mount.root))
        {
            return Err(Errno(1));
        }
        drop(paths);
        let namespace = UserNamespace::create(&self.credentials, &self.user_namespace_limits())?;
        self.credentials.enter_user_namespace(namespace);
        Ok(())
    }
}

impl Vfs {
    pub(super) fn user_map_control(&self, path: &ResolvedPath) -> Option<MapFile> {
        if !self.uses_pseudo(path) {
            return None;
        }
        let parts = path
            .strip_prefix(b"/proc/")?
            .split(|b| *b == b'/')
            .collect::<Vec<_>>();
        let (group, pid, key) = match parts.as_slice() {
            [pid, key] => (None, *pid, *key),
            [group, b"task", pid, key] => (Some(*group), *pid, *key),
            _ => return None,
        };
        let kind = match key {
            b"uid_map" => MapKind::Uid,
            b"gid_map" => MapKind::Gid,
            b"setgroups" => MapKind::Groups,
            _ => return None,
        };
        let number = |b: &[u8]| std::str::from_utf8(b).ok()?.parse::<u32>().ok();
        let pseudo = self.pseudo.borrow();
        let runtime = self.proc_runtime(path, &pseudo.runtime);
        let task = runtime.processes.iter().find(|p| {
            Some(p.pid) == number(pid) && group.is_none_or(|g| Some(p.tgid) == number(g))
        })?;
        Some(MapFile::new(
            task.credentials.user_namespace.clone(),
            self.credentials.clone(),
            kind,
        ))
    }
}

impl Vfs {
    pub fn namespace_ioctl(&self, fd: u32, command: u32) -> Result<u32> {
        let namespace = self
            .descriptor(fd)?
            .open
            .borrow()
            .namespace
            .clone()
            .ok_or(Errno(25))?;
        let target = match command {
            0xb701 => match &namespace {
                linux_namespace::NamespaceHandle::User(ns) => ns.parent().ok_or(Errno(1))?,
                _ => namespace.owner(),
            },
            0xb702 => match namespace {
                linux_namespace::NamespaceHandle::User(ref ns) => ns.parent().ok_or(Errno(1))?,
                _ => return Err(Errno(22)),
            },
            _ => return Err(Errno(25)),
        };
        if !self.credentials.user_namespace.contains(&target) {
            return Err(Errno(1));
        }
        let descriptor = Descriptor {
            open: self.namespace_description(linux_namespace::NamespaceHandle::User(target), None),
            cloexec: true.into(),
        };
        self.shared_files().reserve()?.publish(descriptor, None)
    }
    pub fn namespace_owner_uid(&self, fd: u32) -> Result<u32> {
        let namespace = self
            .descriptor(fd)?
            .open
            .borrow()
            .namespace
            .clone()
            .ok_or(Errno(25))?;
        let linux_namespace::NamespaceHandle::User(ns) = namespace else {
            return Err(Errno(22));
        };
        Ok(self.credentials.local_id(false, ns.owner().unwrap_or(0)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn child(parent: &Credentials) -> Credentials {
        let mut c = parent.clone();
        c.enter_user_namespace(
            UserNamespace::create(
                parent,
                &parent.user_namespace.child().map_or_else(
                    || Arc::new(UserNamespaceLimits::new(1024)),
                    |ns| ns.limits.clone(),
                ),
            )
            .unwrap(),
        );
        c
    }
    fn write(c: &Credentials, kind: MapKind, bytes: &[u8]) -> Result<usize> {
        MapFile::new(c.user_namespace.clone(), c.clone(), kind).write(bytes, 0, c)
    }
    fn own_maps(c: &Credentials, uid: u32, gid: u32) {
        write(c, MapKind::Uid, format!("0 {uid} 1").as_bytes()).unwrap();
        write(c, MapKind::Groups, b"deny").unwrap();
        write(c, MapKind::Gid, format!("0 {gid} 1").as_bytes()).unwrap();
    }
    #[test]
    fn namespace_quota_is_per_user_and_environment_and_follows_live_handles() {
        let root = Vfs::default();
        root.user_namespace_limits().set(1);
        let mut first = root.clone();
        first.unshare_user().unwrap();
        let handle = first.credentials.user_namespace.clone();
        drop(first);
        let mut retry = root.clone();
        assert_eq!(retry.unshare_user(), Err(Errno(28)));

        let mut different_user = root.clone();
        different_user.credentials = Credentials::user(1000, 1000);
        different_user.unshare_user().unwrap();
        let mut independent = Vfs::default();
        independent.user_namespace_limits().set(0);
        assert_eq!(independent.unshare_user(), Err(Errno(28)));

        root.user_namespace_limits().set(0);
        drop(handle);
        assert_eq!(retry.unshare_user(), Err(Errno(28)));
        root.user_namespace_limits().set(1);
        retry.unshare_user().unwrap();
    }

    #[test]
    fn concurrent_namespace_creators_share_one_budget() {
        let limits = Arc::new(UserNamespaceLimits::new(3));
        let gate = std::sync::Barrier::new(9);
        let admitted = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        gate.wait();
                        UserNamespace::create(&Credentials::user(42, 42), &limits)
                    })
                })
                .collect();
            gate.wait();
            threads
                .into_iter()
                .map(|t| t.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(admitted.iter().filter(|r| r.is_ok()).count(), 3);
        assert!(admitted
            .iter()
            .filter_map(|r| r.as_ref().err())
            .all(|e| *e == Errno(28)));
        drop(admitted);
        assert!(limits.usage.lock().unwrap().by_uid.is_empty());
    }

    #[test]
    fn user_namespace_authority_is_scoped_to_owned_descendants() {
        let parent = Credentials::user(1000, 1001);
        let c = child(&parent);
        assert!(c.has_local_cap(capabilities::SYS_ADMIN));
        assert!(!c.has_cap(capabilities::SYS_ADMIN));
        assert!(parent.has_ns_cap(&c.user_namespace, capabilities::SYS_ADMIN));
        assert!(!c.has_ns_cap(&parent.user_namespace, capabilities::SYS_ADMIN));
        let sibling = child(&parent);
        assert!(!c.has_ns_cap(&sibling.user_namespace, capabilities::SYS_ADMIN));
        own_maps(&c, 1000, 1001);
        let grandchild = child(&c);
        assert!(parent.has_ns_cap(&grandchild.user_namespace, capabilities::SYS_ADMIN));
        assert!(c.has_ns_cap(&grandchild.user_namespace, capabilities::SYS_ADMIN));
        assert!(!grandchild.has_ns_cap(&c.user_namespace, capabilities::SYS_ADMIN));
    }
    #[test]
    fn maps_are_live_write_once_and_keep_internal_identities_global() {
        let c = child(&Credentials::user(1000, 1001));
        let observer = c.clone();
        assert_eq!(c.local_id(false, c.uid), 65534);
        assert_eq!(write(&c, MapKind::Uid, b"0 2000 1"), Err(Errno(1)));
        assert_eq!(write(&c, MapKind::Uid, b"0 1000 1\n\0ignored"), Ok(17));
        assert_eq!(observer.local_id(false, 1000), 0);
        assert_eq!(c.uid, 1000);
        assert_eq!(c.mapped_id(false, 0), Ok(1000));
        assert_eq!(c.mapped_id(false, 1), Err(Errno(22)));
        assert_eq!(write(&c, MapKind::Uid, b"1 1000 1"), Err(Errno(1)));
    }
    #[test]
    fn group_mapping_and_setgroups_policy_commit_atomically() {
        let c = child(&Credentials::user(1000, 1001));
        assert!(c.user_namespace.groups_policy());
        assert!(!c.user_namespace.may_setgroups());
        assert_eq!(write(&c, MapKind::Gid, b"0 1001 1"), Err(Errno(1)));
        assert_eq!(write(&c, MapKind::Groups, b"deny\0"), Ok(5));
        assert_eq!(write(&c, MapKind::Gid, b"0 1001 1"), Ok(8));
        assert!(!c.user_namespace.may_setgroups());
        assert_eq!(write(&c, MapKind::Groups, b"allow"), Err(Errno(1)));
        assert_eq!(write(&c, MapKind::Groups, b"deny"), Err(Errno(1)));
        write(&c, MapKind::Uid, b"0 1000 1").unwrap();
        assert!(!child(&c).user_namespace.groups_policy());
    }
    #[test]
    fn malformed_or_unmapped_ranges_do_not_publish_a_partial_map() {
        let root = Credentials::default();
        let c = child(&root);
        for text in [
            b"0 0 0".as_slice(),
            b"0 0 2\n1 5 1",
            b"0 0 2\n5 1 1",
            b"4294967295 0 1",
            b"0 4294967295 1",
            b"0 0 4294967296",
        ] {
            assert_eq!(write(&c, MapKind::Uid, text), Err(Errno(22)));
        }
        MapFile::new(c.user_namespace.clone(), root.clone(), MapKind::Uid)
            .write(b"4000000000 1000 1", 0, &root)
            .unwrap();
        assert_eq!(c.mapped_id(false, 4_000_000_000), Ok(1000));
        assert_eq!(c.local_id(false, 1000), 4_000_000_000);
    }
    #[test]
    fn inode_capabilities_require_mapped_ids_and_cannot_reach_parent_objects() {
        let c = child(&Credentials::user(1000, 1001));
        own_maps(&c, 1000, 1001);
        assert!(c.inode_cap(capabilities::DAC_OVERRIDE, 1000, 1001));
        assert!(!c.inode_cap(capabilities::DAC_OVERRIDE, 0, 1001));
        assert!(!c.inode_cap(capabilities::DAC_OVERRIDE, 1000, 0));
        assert!(c.inode_cap(capabilities::FOWNER, 1000, 0));
        assert!(!c.inode_cap(capabilities::FOWNER, 0, 1001));
        assert!(!c.has_cap(capabilities::NET_ADMIN));
    }
    #[test]
    fn inherited_uts_and_network_keep_their_original_user_namespace_owner() {
        let mut parent = Vfs::default();
        parent.configure_network(NetworkMode::Loopback).unwrap();
        let old_socket = parent.socket(2, 2, 0).unwrap();
        let original = parent.socket_operation(old_socket).unwrap();
        let mut c = parent.clone();
        c.unshare_user().unwrap();
        assert_eq!(c.set_uts_name(false, b"no"), Err(Errno(1)));
        assert!(!c.descriptor_factory().can_admin_network());
        assert!(!c
            .credentials
            .has_ns_cap(original.user_namespace(), capabilities::NET_ADMIN));
        c.unshare_uts().unwrap();
        c.set_uts_name(false, b"child").unwrap();
        assert_ne!(parent.uts_name(false), b"child");
        c.unshare_net().unwrap();
        assert!(c.descriptor_factory().can_admin_network());
        assert!(!c
            .credentials
            .has_ns_cap(original.user_namespace(), capabilities::NET_ADMIN));
    }
    #[test]
    fn overflow_sysctls_belong_to_each_environment_and_follow_live_mappings() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        let fd = v
            .open_at(AT_FDCWD, b"/proc/sys/kernel/overflowuid", 2, 0)
            .unwrap();
        let gid = v
            .open_at(AT_FDCWD, b"/proc/sys/kernel/overflowgid", 2, 0)
            .unwrap();
        let file = v.open_at(AT_FDCWD, b"/owner", 0x42, 0o600).unwrap();
        let mut child = v.clone();
        child.unshare_user().unwrap();
        assert_eq!(v.pread(fd, 32, 0).unwrap(), b"65534\n");
        assert_eq!(v.pwrite(fd, b"65536", 0), Err(Errno(22)));
        assert_eq!(v.pwrite(fd, b"0", 0), Ok(1));
        assert_eq!(v.pwrite(gid, b"65535", 0), Ok(5));
        assert_eq!(child.pread(gid, 32, 0).unwrap(), b"65535\n");
        assert_eq!(child.pwrite(fd, b"123", 0), Err(Errno(13)));
        let c = &child.credentials;
        assert_eq!(c.local_id(false, c.uid), 0);
        assert_eq!(c.user_namespace.to_global(false, 0), None);
        assert_eq!(c.user_namespace.from_global(false, c.uid), None);
        assert_eq!(
            &child.stat_fd(file).unwrap()[24..32],
            &[0, 0, 0, 0, 255, 255, 0, 0]
        );
        let map = MapFile::new(
            v.credentials.user_namespace.clone(),
            c.clone(),
            MapKind::Uid,
        );
        assert_eq!(
            map.read(0, 100).unwrap(),
            b"         0 4294967295 4294967295\n"
        );
        for (kind, text) in [(MapKind::Uid, b"71 0 1"), (MapKind::Gid, b"72 0 1")] {
            MapFile::new(c.user_namespace.clone(), v.credentials.clone(), kind)
                .write(text, 0, &v.credentials)
                .unwrap();
        }
        assert_eq!(
            &child.stat_fd(file).unwrap()[24..32],
            &[71, 0, 0, 0, 72, 0, 0, 0]
        );
        assert_eq!(c.local_id(false, u32::MAX), 0);
        assert_eq!(Vfs::default().credentials.local_id(false, u32::MAX), 65534);
    }

    #[test]
    fn metadata_translation_observes_late_maps_without_changing_inode_ids() {
        let mut v = Vfs::default();
        let fd = v.open_at(AT_FDCWD, b"/mapped-stat", 0x242, 0o600).unwrap();
        v.unshare_user().unwrap();
        assert_eq!(
            u32::from_le_bytes(v.stat_fd(fd).unwrap()[24..28].try_into().unwrap()),
            65534
        );
        write(&v.credentials, MapKind::Uid, b"123 0 1").unwrap();
        write(&v.credentials, MapKind::Groups, b"deny").unwrap();
        write(&v.credentials, MapKind::Gid, b"456 0 1").unwrap();
        let bytes = v.stat_fd(fd).unwrap();
        assert_eq!(u32::from_le_bytes(bytes[24..28].try_into().unwrap()), 123);
        assert_eq!(u32::from_le_bytes(bytes[28..32].try_into().unwrap()), 456);
        assert_eq!(v.credentials.uid, 0);
    }
    fn snapshot(v: &mut Vfs) {
        v.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    credentials: v.credentials.clone(),
                    fds: v.fd_snapshot(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
    }
    #[test]
    fn proc_map_ofd_retains_its_namespace_and_reopen_uses_new_opener() {
        let mut v = Vfs::default();
        snapshot(&mut v);
        let initial = v.open_at(AT_FDCWD, b"/proc/self/uid_map", 2, 0).unwrap();
        v.unshare_user().unwrap();
        snapshot(&mut v);
        let uid = v.open_at(AT_FDCWD, b"/proc/self/uid_map", 2, 0).unwrap();
        assert_eq!(v.read(uid, 128).unwrap(), b"");
        assert_eq!(v.write(initial, b"0 0 1"), Err(Errno(1)));
        assert_eq!(v.write(uid, b"123 0 1"), Ok(7));
        v.seek(uid, 0, 0).unwrap();
        assert_eq!(
            v.read(uid, 128).unwrap(),
            b"       123          0          1\n"
        );
        // A new open file captures the new opener, while dup/SCM_RIGHTS keep
        // the old opener. Retain the original target even after its task exits.
        let map = MapFile::new(
            v.credentials.user_namespace.clone(),
            Credentials::default(),
            MapKind::Uid,
        );
        assert!(map.opener.user_namespace.is_initial());
        assert_eq!(
            map.reopen(&v.credentials).opener.user_namespace,
            v.credentials.user_namespace
        );
        let mut outsider = Credentials::user(2000, 2000);
        outsider.enter_user_namespace(
            UserNamespace::create(&outsider, &Arc::new(UserNamespaceLimits::new(1024))).unwrap(),
        );
        assert_eq!(map.write(b"0 0 1", 0, &outsider), Err(Errno(1)));
    }
    #[test]
    fn nsfs_owner_queries_and_setns_cannot_escape_user_namespace() {
        let mut v = Vfs::default();
        snapshot(&mut v);
        let initial = v.open_at(AT_FDCWD, b"/proc/self/ns/user", 0, 0).unwrap();
        v.unshare_user().unwrap();
        snapshot(&mut v);
        let current = v.open_at(AT_FDCWD, b"/proc/self/ns/user", 0, 0).unwrap();
        assert_eq!(v.namespace_ioctl(current, 0xb702), Err(Errno(1)));
        assert_eq!(v.namespace_owner_uid(current), Ok(65534));
        assert!(matches!(
            v.setns_task(initial, CLONE_NEWUSER, true),
            TaskNamespaceOwnerAttempt::Complete(Err(Errno(1)))
        ));
        assert!(matches!(
            v.setns_task(current, CLONE_NEWUSER, true),
            TaskNamespaceOwnerAttempt::Complete(Err(Errno(22)))
        ));
        assert!(matches!(
            v.setns_task(current, CLONE_NEWUSER, false),
            TaskNamespaceOwnerAttempt::Complete(Err(Errno(22)))
        ));
        own_maps(&v.credentials, 0, 0);
        assert_eq!(v.namespace_owner_uid(current), Ok(0));
        v.unshare_uts().unwrap();
        snapshot(&mut v);
        let uts = v.open_at(AT_FDCWD, b"/proc/self/ns/uts", 0, 0).unwrap();
        let owner = v.namespace_ioctl(uts, 0xb701).unwrap();
        assert_eq!(v.namespace_owner_uid(owner), Ok(0));
    }
    #[test]
    fn inherited_tun_control_keeps_its_network_owner_after_unshare() {
        let mut v = Vfs::default();
        snapshot(&mut v);
        v.configure_network(NetworkMode::Loopback).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/dev/net/tun", 2, 0).unwrap();
        let original = v.tun_file(fd).unwrap().unwrap();
        v.unshare_user().unwrap();
        v.unshare_net().unwrap();
        assert!(!v
            .credentials
            .has_ns_cap(original.user_namespace(), capabilities::NET_ADMIN));
        let next = v.open_at(AT_FDCWD, b"/dev/net/tun", 2, 0).unwrap();
        assert!(v.credentials.has_ns_cap(
            v.tun_file(next).unwrap().unwrap().user_namespace(),
            capabilities::NET_ADMIN
        ));
        assert!(v
            .tun_file(fd)
            .unwrap()
            .unwrap()
            .user_namespace()
            .is_initial());
    }
}
