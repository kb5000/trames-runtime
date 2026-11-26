// SPDX-License-Identifier: GPL-3.0-or-later
//! Mount-local ownership. Shared inodes and ACL caches always keep filesystem
//! IDs; only the original path/OFD supplies a translation at an operation edge.
use super::*;

pub struct MountIdmap {
    pub(super) namespace: UserNamespace,
    pub(super) mapping: Arc<user_namespace::IdMapping>,
}
impl MountIdmap {
    fn from_file(file: &SharedOpenDescription) -> Result<Arc<Self>> {
        if file.flags.get() & O_PATH != 0 {
            return Err(Errno(22));
        }
        let Some(linux_namespace::SharedNamespace::User(namespace)) = &file.namespace_resource
        else {
            return Err(Errno(22));
        };
        if namespace.is_initial() {
            return Err(Errno(1));
        }
        Ok(Arc::new(Self {
            namespace: namespace.clone(),
            mapping: Arc::new(namespace.idmapping()),
        }))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Ids<'a> {
    owner: &'a UserNamespace,
    map: Option<&'a user_namespace::IdMapping>,
}
impl<'a> Ids<'a> {
    #[inline]
    pub(crate) fn plain(owner: &'a UserNamespace) -> Self {
        Self { owner, map: None }
    }
    #[inline]
    pub(crate) fn from_mount(mount: &'a MountIdentity) -> Self {
        Self {
            owner: &mount.fs.owner,
            map: mount.idmap.get().map(Arc::as_ref),
        }
    }
    #[inline]
    pub(crate) fn is_mapped(self) -> bool {
        self.map.is_some()
    }
    #[inline]
    pub(crate) fn visible(self, group: bool, id: u32) -> u32 {
        let Some(map) = self.map else {
            return id;
        };
        Self::mapped_visible(self.owner, map, group, id)
    }
    fn mapped_visible(
        owner: &UserNamespace,
        map: &user_namespace::IdMapping,
        group: bool,
        id: u32,
    ) -> u32 {
        owner
            .from_global(group, id)
            .and_then(|id| map.down(group, id))
            .unwrap_or(u32::MAX)
    }
    #[inline]
    pub(crate) fn owner(self, uid: u32, gid: u32) -> (u32, u32) {
        if self.map.is_none() {
            (uid, gid)
        } else {
            (self.visible(false, uid), self.visible(true, gid))
        }
    }
    pub(crate) fn valid_owner(self, uid: u32, gid: u32) -> Result<(u32, u32)> {
        let owner = self.owner(uid, gid);
        if owner.0 == u32::MAX || owner.1 == u32::MAX {
            return Err(Errno(75));
        }
        Ok(owner)
    }
    pub(crate) fn fs_capable(self, c: &Credentials, cap: u32) -> bool {
        c.has_ns_cap(self.owner, cap)
    }
    pub(crate) fn stored(self, group: bool, id: u32) -> Result<u32> {
        if id == u32::MAX {
            return Ok(id);
        }
        match self.map {
            None => self
                .owner
                .from_global(group, id)
                .map(|_| id)
                .ok_or(Errno(75)),
            Some(map) => map
                .up(group, id)
                .and_then(|id| self.owner.to_global(group, id))
                .ok_or(Errno(75)),
        }
    }
    pub(crate) fn creator(self, c: &Credentials) -> Result<(u32, u32)> {
        let uid = self.stored(false, c.fsuid)?;
        let gid = self.stored(true, c.fsgid)?;
        if self.owner.from_global(false, uid).is_none()
            || self.owner.from_global(true, gid).is_none()
        {
            return Err(Errno(75));
        }
        Ok((uid, gid))
    }
    pub(crate) fn capability_root(self, raw: u32, v2: bool, c: &Credentials) -> Result<u32> {
        if v2 && self.map.is_none() && c.has_ns_cap(self.owner, capabilities::SETFCAP) {
            return Ok(self.owner.to_global(false, 0).unwrap_or(u32::MAX));
        }
        let caller = c.user_namespace.to_global(false, raw).ok_or(Errno(22))?;
        let stored = self.stored(false, caller).map_err(|_| Errno(22))?;
        self.owner.from_global(false, stored).ok_or(Errno(22))?;
        Ok(stored)
    }
}
impl ResolvedPath {
    #[inline]
    pub(crate) fn ids<'a>(&'a self, v: &'a Vfs) -> Ids<'a> {
        self.mount
            .as_ref()
            .map_or_else(|| Ids::plain(&v.fs.owner), |m| Ids::from_mount(&m.identity))
    }
}
impl Vfs {
    pub fn capture_mount_idmap(&self, fd: u64) -> Result<Arc<MountIdmap>> {
        let fd = u32::try_from(fd)
            .ok()
            .filter(|fd| *fd <= i32::MAX as u32)
            .ok_or(Errno(22))?;
        MountIdmap::from_file(&self.descriptor(fd)?.open.borrow())
    }
    #[inline]
    pub(crate) fn open_ids<'a>(&'a self, mount: Option<&'a OpenMount>) -> Ids<'a> {
        mount.map_or_else(
            || Ids::plain(&self.fs.owner),
            |m| Ids::from_mount(&m.identity),
        )
    }
    #[inline]
    pub(crate) fn allowed_on(&self, node: &Node, bits: u32, path: &ResolvedPath) -> bool {
        self.credentials.allows_mapped(node, bits, path.ids(self))
            || bits & 2 == 0 && self.proc_fd_search_allowed(path)
    }
}
impl MountIdentity {
    pub(super) fn idmap_supported(&self) -> bool {
        matches!(self.kind, Kind::Root | Kind::Tmpfs | Kind::Overlay)
    }
}
impl PathQueries {
    pub fn capture_mount_idmap(&self, fd: u64) -> Result<Arc<MountIdmap>> {
        let fd = u32::try_from(fd)
            .ok()
            .filter(|fd| *fd <= i32::MAX as u32)
            .ok_or(Errno(22))?;
        let view = self.view.borrow();
        let query = view.query.as_ref().unwrap();
        let descriptor = query.files.observation_descriptor(fd)?;
        let open = descriptor.open.borrow();
        MountIdmap::from_file(&open)
    }
}
