// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest user namespaces. Kernel-facing identities stay global; only ABI edges
//! translate them. The initial namespace is None and requires no map lookup.
use super::*;
use std::sync::{Mutex, OnceLock};
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
const INITIAL: u64 = 0xefff_fffd;
static NEXT: AtomicU64 = AtomicU64::new(0xb000_0000);
#[derive(Clone, Default)]
pub struct UserNamespace(pub(super) Option<Arc<UserSpace>>);
pub(super) struct UserSpace {
    id: u64,
    parent: UserNamespace,
    owner: u32,
    depth: u32,
    creator_setfcap: bool,
    maps: [OnceLock<Vec<Extent>>; 2],
    policy: Mutex<bool>,
}
#[derive(Clone, Copy)]
struct Extent {
    first: u32,
    lower: u32,
    count: u32,
}
impl std::fmt::Debug for UserNamespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("UserNamespace").field(&self.id()).finish()
    }
}
impl PartialEq for UserNamespace {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}
impl Eq for UserNamespace {}
impl UserNamespace {
    pub fn is_initial(&self) -> bool {
        self.0.is_none()
    }
    pub fn id(&self) -> u64 {
        self.0.as_ref().map_or(INITIAL, |n| n.id)
    }
    pub fn parent(&self) -> Option<Self> {
        self.0.as_ref().map(|n| n.parent.clone())
    }
    pub fn owner(&self) -> Option<u32> {
        self.0.as_ref().map(|n| n.owner)
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
    pub fn create(credentials: &Credentials) -> Result<Self> {
        let parent = credentials.user_namespace.clone();
        let depth = parent.0.as_ref().map_or(1, |n| n.depth + 1);
        if depth > 32 {
            return Err(Errno(28));
        }
        if parent.from_global(false, credentials.euid).is_none()
            || parent.from_global(true, credentials.egid).is_none()
        {
            return Err(Errno(1));
        }
        let allowed = parent.groups_policy();
        let id = NEXT
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Errno(28))?;
        Ok(Self(Some(Arc::new(UserSpace {
            id,
            parent,
            owner: credentials.euid,
            depth,
            creator_setfcap: credentials.has_local_cap(31),
            maps: Default::default(),
            policy: Mutex::new(allowed),
        }))))
    }
    pub fn to_global(&self, group: bool, id: u32) -> Option<u32> {
        if id == u32::MAX {
            return None;
        }
        let Some(ns) = &self.0 else {
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
        let Some(ns) = &self.0 else {
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
        let Some(ns) = &self.0 else {
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
        self.from_global(group, id).unwrap_or(65534)
    }
    pub fn stat(&self, mut bytes: [u8; 128]) -> [u8; 128] {
        if !self.is_initial() {
            for (group, at) in [(false, 24), (true, 28)] {
                let id = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
                bytes[at..at + 4].copy_from_slice(&self.visible(group, id).to_le_bytes());
            }
        }
        bytes
    }
    pub fn groups_policy(&self) -> bool {
        self.0.as_ref().is_none_or(|n| *n.policy.lock().unwrap())
    }
    pub fn may_setgroups(&self) -> bool {
        self.0
            .as_ref()
            .is_none_or(|n| n.maps[1].get().is_some() && *n.policy.lock().unwrap())
    }
    pub fn capable(&self, caller: &Credentials, cap: u32) -> bool {
        if self == &caller.user_namespace {
            return caller.has_local_cap(cap);
        }
        let mut at = self.clone();
        while let Some(ns) = &at.0 {
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
    pub(super) fn weak(&self) -> Option<std::sync::Weak<UserSpace>> {
        self.0.as_ref().map(Arc::downgrade)
    }
    pub(super) fn upgrade(weak: &Option<std::sync::Weak<UserSpace>>) -> Result<Self> {
        Ok(Self(
            weak.as_ref()
                .map(|n| n.upgrade().ok_or(Errno(2)))
                .transpose()?,
        ))
    }
    fn map_text(&self, group: bool, observer: &Self) -> Vec<u8> {
        let Some(ns) = &self.0 else {
            return format!("{:10} {:10} 4294967295\n", 0, observer.visible(group, 0)).into_bytes();
        };
        let mut bytes = String::new();
        if let Some(map) = ns.maps[usize::from(group)].get() {
            for e in map {
                let lower = if observer == self {
                    e.lower
                } else {
                    ns.parent
                        .to_global(group, e.lower)
                        .map_or(65534, |id| observer.visible(group, id))
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
        let ns = self.namespace.0.as_ref().ok_or(Errno(1))?;
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
        let namespace = UserNamespace::create(&self.credentials)?;
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
        c.enter_user_namespace(UserNamespace::create(parent).unwrap());
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
        outsider.enter_user_namespace(UserNamespace::create(&outsider).unwrap());
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
