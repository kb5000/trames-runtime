// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest-wide cgroup v2 domain hierarchy, without resource controllers.
//! Scheduler-owned metadata, independent of disk storage and mount namespaces.
use super::*;
use std::collections::BTreeSet;

const ROOT: u64 = 5 << 32;
const MAX_GROUPS: usize = 128;
const MAX_DEPTH: usize = 32;
const FILES: &[(&str, u32)] = &[
    ("cgroup.procs", 0o644),
    ("cgroup.threads", 0o444),
    ("cgroup.controllers", 0o444),
    ("cgroup.subtree_control", 0o644),
    ("cgroup.type", 0o444),
    ("cgroup.events", 0o444),
    ("cgroup.stat", 0o444),
];
struct Group {
    path: Vec<u8>,
    parent: Option<u64>,
}
struct Dying {
    nodes: Vec<Weak<RefCell<Node>>>,
    ancestors: Vec<u64>,
}
pub(super) struct Cgroups {
    pub fs: Rc<RefCell<Filesystem>>,
    groups: BTreeMap<u64, Group>,
    tasks: BTreeMap<u32, (u32, u64)>, // global TID -> (global TGID, group inode)
    dying: Vec<Dying>,
}
fn below(path: &[u8], root: &[u8]) -> bool {
    path == root || root == b"/" || path.starts_with(root) && path.get(root.len()) == Some(&b'/')
}
fn child_path(path: &[u8], name: &[u8]) -> Vec<u8> {
    let mut out = path.to_vec();
    if out != b"/" {
        out.push(b'/');
    }
    out.extend_from_slice(name);
    out
}
impl Default for Cgroups {
    fn default() -> Self {
        let mut out = Self {
            fs: Rc::new(RefCell::new(Filesystem {
                paths: BTreeMap::new(),
                inodes: Vec::new(),
                next_inode: ROOT,
                flock: BTreeMap::new(),
                record_locks: BTreeMap::new(),
                limits: StorageLimits::memory(),
                disk: None,
                volume: None,
            })),
            groups: BTreeMap::new(),
            tasks: BTreeMap::from([(1, (1, ROOT))]),
            dying: Vec::new(),
        };
        out.add_group(b"/".to_vec(), None, 0o755);
        out
    }
}
impl Cgroups {
    fn add_node(&self, path: Vec<u8>, directory: bool, mode: u32) -> u64 {
        let mut fs = self.fs.borrow_mut();
        let inode = fs.next_inode;
        fs.next_inode += 1;
        let node = Rc::new(RefCell::new(Node {
            device: 5,
            content: if directory {
                Content::Directory
            } else {
                Content::File(storage::FileData::Memory(Vec::new()))
            },
            mode: mode | if directory { 0o40000 } else { 0o100000 },
            uid: 0,
            gid: 0,
            volatile: true,
            inode,
            links: 1,
            times: [storage::Timestamp::now(); 3],
            seals: None,
        }));
        fs.inodes.push(Rc::downgrade(&node));
        fs.paths.insert(path, node);
        inode
    }
    fn add_group(&mut self, path: Vec<u8>, parent: Option<u64>, mode: u32) {
        let id = self.add_node(path.clone(), true, mode);
        for (name, mode) in FILES {
            // Linux omits type/events on the root cgroup.
            if parent.is_none() && matches!(*name, "cgroup.type" | "cgroup.events") {
                continue;
            }
            self.add_node(child_path(&path, name.as_bytes()), false, *mode);
        }
        self.groups.insert(id, Group { path, parent });
    }
    fn ancestors(&self, mut id: u64) -> Vec<u64> {
        let mut out = vec![id];
        while let Some(parent) = self.groups[&id].parent {
            out.push(parent);
            id = parent;
        }
        out
    }
    fn prune(&mut self) {
        self.dying
            .retain(|g| g.nodes.iter().any(|n| n.strong_count() != 0));
        self.fs
            .borrow_mut()
            .inodes
            .retain(|n| n.strong_count() != 0);
    }
}
impl Vfs {
    pub(super) fn cgroup_mount(path: &ResolvedPath) -> bool {
        path.mount
            .as_ref()
            .is_some_and(|m| m.kind == mounts::Kind::Cgroup)
    }
    pub(super) fn cgroup_mkdir(&self, path: &ResolvedPath, mode: u32) -> Result<()> {
        path.writable()?;
        if !self.credentials.has_cap(capabilities::SYS_ADMIN) {
            return Err(Errno(1));
        }
        let parent = self.node(&path.parent())?;
        if !self.allowed(&parent.borrow(), 3) {
            return Err(Errno(13));
        }
        let id = parent.borrow().inode;
        let mut cg = self.cgroups.borrow_mut();
        cg.prune();
        if !cg.groups.contains_key(&id) {
            return Err(Errno(19));
        }
        if cg.groups.len() + cg.dying.len() >= MAX_GROUPS || cg.ancestors(id).len() > MAX_DEPTH {
            return Err(Errno(28));
        }
        cg.add_group(path.key.clone(), Some(id), mode & 0o777 & !self.umask);
        Ok(())
    }
    pub(super) fn cgroup_rmdir(&self, path: &ResolvedPath) -> Result<()> {
        path.writable()?;
        if !self.credentials.has_cap(capabilities::SYS_ADMIN) {
            return Err(Errno(1));
        }
        let node = self.node(path)?;
        let id = node.borrow().inode;
        let mut cg = self.cgroups.borrow_mut();
        if !cg.groups.contains_key(&id) {
            return Err(Errno(1));
        }
        if id == ROOT {
            return Err(Errno(16));
        }
        if cg.groups.values().any(|g| g.parent == Some(id)) {
            return Err(Errno(39));
        }
        if cg.tasks.values().any(|(_, group)| *group == id) {
            return Err(Errno(16));
        }
        let ancestors = cg.ancestors(id)[1..].to_vec();
        let removed: Vec<_> = cg
            .fs
            .borrow()
            .paths
            .keys()
            .filter(|key| below(key, &path.key))
            .cloned()
            .collect();
        let mut nodes = Vec::new();
        for key in removed {
            let node = cg.fs.borrow_mut().paths.remove(&key).expect("cgroup inode");
            node.borrow_mut().links = 0;
            nodes.push(Rc::downgrade(&node));
        }
        cg.groups.remove(&id);
        cg.dying.push(Dying { nodes, ancestors });
        cg.prune();
        Ok(())
    }
    /// Called only after clone's fallible setup has succeeded.
    pub fn cgroup_fork(&self, parent: u32, child: u32, tgid: u32) {
        let mut cg = self.cgroups.borrow_mut();
        let group = cg.tasks.get(&parent).map_or(ROOT, |(_, g)| *g);
        cg.tasks.insert(child, (tgid, group));
    }
    pub fn cgroup_exit(&self, pid: u32) {
        self.cgroups.borrow_mut().tasks.remove(&pid);
    }
    pub fn cgroup_exec_rekey(&self, old: u32, new: u32) {
        let mut cg = self.cgroups.borrow_mut();
        if let Some((_, group)) = cg.tasks.remove(&old) {
            cg.tasks.insert(new, (new, group));
        }
    }
    pub fn cgroup_path(&self, pid: u32) -> Vec<u8> {
        let cg = self.cgroups.borrow();
        let id = cg.tasks.get(&pid).map_or(ROOT, |(_, g)| *g);
        cg.groups
            .get(&id)
            .map_or_else(|| b"/".to_vec(), |g| g.path.clone())
    }
    // Open descriptions retain inode identity: deletion/recreation at the same
    // path must never redirect an old control FD to a new group.
    fn cgroup_control(&self, o: &OpenDescription) -> Result<Option<(u64, Vec<u8>)>> {
        if !o
            .mount
            .as_ref()
            .is_some_and(|m| m.kind == mounts::Kind::Cgroup)
        {
            return Ok(None);
        }
        let FdKind::Node(key) = &o.kind else {
            return Err(Errno(9));
        };
        let node = o.node.as_ref().ok_or(Errno(9))?;
        let cg = self.cgroups.borrow();
        let fs = cg.fs.borrow();
        if !fs.paths.get(key).is_some_and(|n| Rc::ptr_eq(n, node)) {
            return Err(Errno(19));
        }
        if matches!(node.borrow().content, Content::Directory) {
            return Err(Errno(21));
        }
        let split = key.iter().rposition(|b| *b == b'/').ok_or(Errno(19))?;
        let parent = fs.paths.get(&key[..split.max(1)]).ok_or(Errno(19))?;
        let id = parent.borrow().inode;
        Ok(Some((id, key[split + 1..].to_vec())))
    }
    pub(super) fn cgroup_read(
        &self,
        o: &OpenDescription,
        offset: u64,
        count: usize,
    ) -> Result<Option<Vec<u8>>> {
        let Some((id, name)) = self.cgroup_control(o)? else {
            return Ok(None);
        };
        let cg = self.cgroups.borrow();
        let path = &cg.groups.get(&id).ok_or(Errno(19))?.path;
        let text = match name.as_slice() {
            b"cgroup.procs" | b"cgroup.threads" => {
                let ids: BTreeSet<_> = cg
                    .tasks
                    .iter()
                    .filter(|(_, (_, group))| *group == id)
                    .map(|(tid, (tgid, _))| {
                        self.visible_pid(if name == b"cgroup.procs" { *tgid } else { *tid })
                    })
                    .filter(|id| *id != 0)
                    .collect();
                ids.iter().map(|id| format!("{id}\n")).collect::<String>()
            }
            b"cgroup.controllers" | b"cgroup.subtree_control" => "\n".to_owned(),
            b"cgroup.type" => "domain\n".to_owned(),
            b"cgroup.events" => {
                let populated = cg
                    .tasks
                    .values()
                    .any(|(_, g)| below(&cg.groups[g].path, path));
                format!("populated {}\nfrozen 0\n", u8::from(populated))
            }
            b"cgroup.stat" => {
                let descendants = cg
                    .groups
                    .iter()
                    .filter(|(g, entry)| **g != id && below(&entry.path, path))
                    .count();
                let dying = cg
                    .dying
                    .iter()
                    .filter(|g| {
                        g.ancestors.contains(&id) && g.nodes.iter().any(|n| n.strong_count() != 0)
                    })
                    .count();
                format!("nr_descendants {descendants}\nnr_dying_descendants {dying}\n")
            }
            _ => return Err(Errno(22)),
        };
        let from = (offset.min(text.len() as u64)) as usize;
        let to = from + count.min(text.len() - from);
        Ok(Some(text.as_bytes()[from..to].to_vec()))
    }
    pub(super) fn cgroup_write(&self, o: &OpenDescription, bytes: &[u8]) -> Result<Option<usize>> {
        let Some((id, name)) = self.cgroup_control(o)? else {
            return Ok(None);
        };
        if !self.credentials.has_cap(capabilities::SYS_ADMIN) {
            return Err(Errno(1));
        }
        if bytes.len() > 4096 {
            return Err(Errno(7));
        }
        if bytes.is_empty() {
            return Ok(Some(0));
        }
        let text = std::str::from_utf8(bytes).map_err(|_| Errno(22))?.trim();
        match name.as_slice() {
            b"cgroup.subtree_control" => {
                if !text.is_empty() {
                    return Err(Errno(95));
                }
            }
            b"cgroup.procs" => {
                if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(Errno(22));
                }
                let local = text.parse::<u32>().map_err(|_| Errno(22))?;
                let target = if local == 0 {
                    self.pid
                } else {
                    self.global_pid(local)?
                };
                let mut cg = self.cgroups.borrow_mut();
                let (tgid, _) = *cg.tasks.get(&target).ok_or(Errno(3))?;
                for (process, group) in cg.tasks.values_mut() {
                    if *process == tgid {
                        *group = id;
                    }
                }
            }
            b"cgroup.threads" | b"cgroup.type" => return Err(Errno(95)),
            _ => return Err(Errno(13)),
        }
        Ok(Some(bytes.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setup() -> Vfs {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        v
    }
    #[test]
    fn quotas_count_live_deleted_objects_and_release_them() {
        let mut v = setup();
        for i in 1..MAX_GROUPS {
            v.mkdir_at(AT_FDCWD, format!("/sys/fs/cgroup/g{i}").as_bytes(), 0o755)
                .unwrap();
        }
        let fd = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/g1/cgroup.procs", 2, 0)
            .unwrap();
        v.unlink_at(AT_FDCWD, b"/sys/fs/cgroup/g1", true).unwrap();
        assert_eq!(
            v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/new", 0o755),
            Err(Errno(28))
        );
        assert_eq!(v.write(fd, b"0"), Err(Errno(19)));
        v.close(fd).unwrap();
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/new", 0o755).unwrap();
        assert_eq!(v.cgroups.borrow().groups.len(), MAX_GROUPS);
        assert!(v.cgroups.borrow().dying.is_empty());
    }
    #[test]
    fn depth_limit_is_transactional_and_storage_budget_is_separate() {
        let mut v = setup();
        let before = v.capacity();
        let mut path = b"/sys/fs/cgroup".to_vec();
        for _ in 0..MAX_DEPTH {
            path.extend_from_slice(b"/x");
            v.mkdir_at(AT_FDCWD, &path, 0o755).unwrap();
        }
        path.extend_from_slice(b"/x");
        assert_eq!(v.mkdir_at(AT_FDCWD, &path, 0o755), Err(Errno(28)));
        assert_eq!(v.stat_at(AT_FDCWD, &path), Err(Errno(2)));
        assert_eq!(v.capacity().used_bytes, before.used_bytes);
        assert_eq!(v.capacity().nodes_used, before.nodes_used);
    }
}
