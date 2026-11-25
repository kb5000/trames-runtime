// SPDX-License-Identifier: GPL-3.0-or-later
//! Read the original mount topology under its existing administration lease.
use super::*;
use std::collections::BTreeSet;

pub const UNIQUE_MOUNT_ID_BASE: u64 = 1 << 31;
const ROOT: u64 = u64::MAX;
const HEADER: usize = 512;
const SB_BASIC: u64 = 1;
const MNT_BASIC: u64 = 2;
const PROPAGATE_FROM: u64 = 4;
const MNT_ROOT: u64 = 8;
const MNT_POINT: u64 = 16;
const FS_TYPE: u64 = 32;
const NS_ID: u64 = 64;
const MNT_OPTS: u64 = 128;
const SB_SOURCE: u64 = 512;
const STRINGS: u64 = MNT_ROOT | MNT_POINT | FS_TYPE | MNT_OPTS | SB_SOURCE;

pub struct MountQuery {
    pub namespace: u64,
    pub mount: u64,
    pub kind: MountQueryKind,
}

pub enum MountQueryKind {
    Stat {
        mask: u64,
        capacity: u64,
    },
    List {
        cursor: u64,
        count: usize,
        reverse: bool,
    },
}

struct ViewRoot {
    mount: Arc<Mount>,
    path: Vec<u8>,
    steps: usize,
}

impl ViewRoot {
    fn new(mount: Arc<Mount>, key: &[u8], steps: usize) -> Result<Self> {
        let path = mount_absolute(&mount, key, &mount, steps).ok_or(Errno(2))?;
        Ok(Self { mount, path, steps })
    }

    fn mountpoint(&self, mount: &Arc<Mount>) -> Option<Vec<u8>> {
        let mut path = mount_absolute(mount, &mount.root_path_view(), &self.mount, self.steps)?;
        if !below(&path, &self.path) {
            return None;
        }
        if self.path != b"/" {
            path.drain(..self.path.len());
            if path.is_empty() {
                path.push(b'/');
            }
        }
        Some(path)
    }
}

impl Vfs {
    fn mount_query_namespace(&self, id: u64) -> Result<(MountNamespace, bool)> {
        let own = self
            .mounts
            .as_ref()
            .and_then(MountNamespace::original)
            .ok_or(Errno(2))?;
        if id == 0 || id == own.id() {
            return Ok((own, true));
        }
        let policy = self.pseudo.borrow().mount_policy.clone();
        let target = policy
            .namespaces
            .borrow()
            .get(&id)
            .and_then(std::sync::Weak::upgrade)
            .ok_or(Errno(2))?;
        if !self
            .credentials
            .has_ns_cap(&target.borrow().user_namespace, capabilities::SYS_ADMIN)
        {
            return Err(Errno(2));
        }
        Ok((MountNamespace(target), false))
    }

    pub(crate) fn mount_query_admin(&self, id: u64) -> Result<Arc<admin::Admin>> {
        let (namespace, _) = self.mount_query_namespace(id)?;
        let admin = namespace.0.borrow().admin.clone();
        Ok(admin)
    }

    pub(crate) fn mount_query(&self, query: &MountQuery) -> Result<Vec<u8>> {
        let (ns, own) = self.mount_query_namespace(query.namespace)?;
        let (default_root, mounts, root_parent, ns_id, owner, admin) = {
            let table = ns.0.borrow();
            (
                table.root.clone(),
                table.mounts.clone(),
                table.root_parent_id,
                table.id,
                table.user_namespace.clone(),
                table.admin.clone(),
            )
        };
        let root = if own {
            let paths = self.context.paths.borrow();
            if let Some(mount) = &paths.root_mount {
                let mount = mounts.iter().find(|m| m.id == mount.id).unwrap_or(mount);
                let node = paths.root_node.as_ref().unwrap_or(&mount.root);
                ViewRoot::new(
                    mount.clone(),
                    &mount.key_of(node).ok_or(Errno(2))?,
                    mounts.len(),
                )?
            } else {
                ViewRoot::new(
                    default_root.clone(),
                    &default_root.root_path_view(),
                    mounts.len(),
                )?
            }
        } else {
            ViewRoot::new(
                default_root.clone(),
                &default_root.root_path_view(),
                mounts.len(),
            )?
        };
        let lookup = |id| {
            mounts
                .iter()
                .find(|m| m.id + UNIQUE_MOUNT_ID_BASE == id)
                .ok_or(Errno(2))
        };
        let permitted = |point: Option<&[u8]>| {
            if point.is_none() && !self.credentials.has_ns_cap(&owner, capabilities::SYS_ADMIN) {
                return Err(Errno(1));
            }
            Ok(())
        };
        match query.kind {
            MountQueryKind::List {
                cursor,
                count,
                reverse,
            } => {
                let subtree;
                let origin = if query.mount == ROOT {
                    &root
                } else {
                    let m = lookup(query.mount)?;
                    permitted(root.mountpoint(m).as_deref())?;
                    subtree = ViewRoot::new(m.clone(), &m.root_path_view(), mounts.len())?;
                    &subtree
                };
                if count == 0 {
                    return Ok(Vec::new());
                }
                let mut ids: Vec<_> = mounts
                    .iter()
                    .filter_map(|m| {
                        let id = m.id + UNIQUE_MOUNT_ID_BASE;
                        let after_cursor =
                            cursor == 0 || if reverse { id < cursor } else { id > cursor };
                        (id != query.mount && after_cursor && origin.mountpoint(m).is_some())
                            .then_some(id)
                    })
                    .collect();
                ids.sort_unstable();
                if reverse {
                    ids.reverse();
                }
                Ok(ids
                    .into_iter()
                    .take(count)
                    .flat_map(u64::to_le_bytes)
                    .collect())
            }
            MountQueryKind::Stat { mask, capacity } => {
                if mask & STRINGS != 0 && capacity == HEADER as u64 {
                    return Err(Errno(75));
                }
                let m = lookup(query.mount)?;
                let point = root.mountpoint(m);
                permitted(point.as_deref())?;
                let mut reply = StatReply::new(mask);
                if mask & SB_BASIC != 0 {
                    let dev = m.device();
                    reply.u32(
                        16,
                        (((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000)) as u32,
                    );
                    reply.u32(20, ((dev & 0xff) | ((dev >> 12) & 0xffffff00)) as u32);
                    reply.u64(24, m.kind.statfs_magic());
                    reply.u32(32, u32::from(m.super_readonly()));
                }
                if mask & (MNT_BASIC | PROPAGATE_FROM) != 0 {
                    let state = m.propagation();
                    let state = if state.master.is_some() {
                        state.resolved(&propagation::live_groups(&admin.namespaces()))
                    } else {
                        state
                    };
                    if mask & MNT_BASIC != 0 {
                        let parent = m
                            .parent
                            .borrow()
                            .as_ref()
                            .map_or(root_parent, |p| p.parent.id);
                        reply.u64(40, query.mount);
                        reply.u64(48, UNIQUE_MOUNT_ID_BASE + parent);
                        reply.u32(56, m.id as u32);
                        reply.u32(60, parent as u32);
                        let flags = m.flags.local();
                        let atime = if flags & MS_NOATIME != 0 {
                            0x10
                        } else if flags & MS_RELATIME != 0 {
                            0
                        } else {
                            0x20
                        };
                        reply.u64(
                            64,
                            (flags & 15)
                                | atime
                                | (u64::from(flags & MS_NODIRATIME != 0) << 7)
                                | (u64::from(flags & MS_NOSYMFOLLOW != 0) << 21),
                        );
                        let shared = state.shared.as_ref().map_or(0, |g| g.id);
                        let master = state.master.as_ref().map_or(0, |g| g.id);
                        let propagation = (u64::from(shared != 0) << 20)
                            | (u64::from(master != 0) << 19)
                            | (u64::from(state.unbindable) << 17);
                        reply.u64(
                            72,
                            if propagation == 0 {
                                1 << 18
                            } else {
                                propagation
                            },
                        );
                        reply.u64(80, shared);
                        reply.u64(88, master);
                    }
                    if mask & PROPAGATE_FROM != 0 && state.master.is_some() {
                        let visible: BTreeSet<_> = mounts
                            .iter()
                            .filter_map(|m| {
                                let group = m.propagation().shared?;
                                root.mountpoint(m).is_some().then_some(group.id)
                            })
                            .collect();
                        reply.u64(96, state.dominating_group(&visible));
                    }
                }
                if mask & FS_TYPE != 0 {
                    reply.string(36, m.fs_name().as_bytes());
                }
                if mask & MNT_ROOT != 0 {
                    reply.string(
                        104,
                        &m.reported_root(m.root_path(), &self.cgroup_namespace.path),
                    );
                }
                if mask & MNT_POINT != 0 {
                    reply.string(108, point.as_deref().unwrap_or_default());
                }
                if mask & MNT_OPTS != 0 {
                    reply.string(4, m.super_options().as_bytes());
                }
                if mask & NS_ID != 0 {
                    reply.u64(112, ns_id);
                }
                if mask & SB_SOURCE != 0 {
                    reply.string(124, m.source());
                }
                reply.finish(capacity)
            }
        }
    }
}

struct StatReply(Vec<u8>);
impl StatReply {
    fn new(mask: u64) -> Self {
        let mut reply = Self(vec![0; HEADER]);
        reply.u64(8, mask & (0xff | SB_SOURCE));
        reply
    }
    fn u32(&mut self, at: usize, value: u32) {
        self.0[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn u64(&mut self, at: usize, value: u64) {
        self.0[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn string(&mut self, at: usize, value: &[u8]) {
        self.u32(at, (self.0.len() - HEADER) as u32);
        self.0.extend_from_slice(value);
        self.0.push(0);
    }
    fn finish(mut self, capacity: u64) -> Result<Vec<u8>> {
        let size = self.0.len();
        if size > HEADER && size as u64 > capacity {
            return Err(Errno(75));
        }
        let copied = size.min(capacity as usize);
        self.u32(0, copied as u32);
        self.0.truncate(copied);
        Ok(self.0)
    }
}
