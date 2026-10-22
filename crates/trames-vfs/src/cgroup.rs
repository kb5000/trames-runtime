// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest-wide cgroup v2 domains, freezer and hierarchical pids controller.
//! Scheduler-owned metadata, independent of disk storage and mount namespaces.
use super::*;
use std::collections::BTreeSet;

const ROOT: u64 = 5 << 32;
const MAX_GROUPS: usize = 128;
const MAX_DEPTH: usize = 32;
const PIDS_FILES: &[(&str, u32)] = &[
    ("pids.current", 0o444),
    ("pids.max", 0o644),
    ("pids.peak", 0o444),
    ("pids.events", 0o444),
    ("pids.events.local", 0o444),
];
const FILES: &[(&str, u32)] = &[
    ("cgroup.procs", 0o644),
    ("cgroup.threads", 0o444),
    ("cgroup.controllers", 0o444),
    ("cgroup.subtree_control", 0o644),
    ("cgroup.type", 0o444),
    ("cgroup.events", 0o444),
    ("cgroup.stat", 0o444),
    ("cgroup.freeze", 0o644),
    ("cgroup.kill", 0o200),
    // crun opens io.max even for an empty OCI blockIO object. Expose the
    // empty/unlimited view, but reject all writes: no IO controller is
    // advertised and no throttling request can silently succeed.
    ("io.max", 0o644),
];
struct Group {
    device_programs: Vec<Rc<bpf::Program>>,
    device_attach_flags: u32,
    path: Vec<u8>,
    parent: Option<u64>,
    freeze: bool,
    subtree_pids: bool,
    pids_max: Option<u64>,
    pids_peak: u64,
    pids_events: u64,
    pids_events_local: u64,
}
struct Dying {
    nodes: Vec<Weak<RefCell<Node>>>,
    ancestors: Vec<u64>,
}
pub(super) struct Cgroups {
    pub bpf: bpf::Registry,
    pub fs: Rc<RefCell<Filesystem>>,
    groups: BTreeMap<u64, Group>,
    tasks: BTreeMap<u32, (u32, u64)>, // global TID -> (global TGID, group inode)
    dying: Vec<Dying>,
    kill: BTreeSet<u32>,
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
            bpf: bpf::Registry::default(),
            fs: Rc::new(RefCell::new(Filesystem {
                overlay: None,
                shared_budget: trames_shared::SharedBudget::new(memfd::MEMFD_BYTES as usize),
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
            kill: BTreeSet::new(),
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
            notifications: inotify::Marks::default(),
            path_hint: RefCell::default(),
            device: 5,
            content: if directory {
                Content::Directory
            } else {
                Content::File(storage::FileData::memory(Vec::new()))
            },
            mode: mode | if directory { 0o40000 } else { 0o100000 },
            uid: 0,
            gid: 0,
            volatile: true,
            inode,
            links: 1,
            times: [storage::Timestamp::now(); 3],
            xattrs: BTreeMap::new(),
            seals: None,
        }));
        fs.inodes.push(Rc::downgrade(&node));
        fs.paths.insert(path, node);
        inode
    }
    fn add_group(&mut self, path: Vec<u8>, parent: Option<u64>, mode: u32) {
        let id = self.add_node(path.clone(), true, mode);
        for (name, mode) in FILES {
            // These controls apply only below the root cgroup.
            if parent.is_none()
                && matches!(
                    *name,
                    "cgroup.type" | "cgroup.events" | "cgroup.freeze" | "cgroup.kill" | "io.max"
                )
            {
                continue;
            }
            self.add_node(child_path(&path, name.as_bytes()), false, *mode);
        }
        self.groups.insert(
            id,
            Group {
                device_programs: Vec::new(),
                device_attach_flags: 0,
                path,
                parent,
                freeze: false,
                subtree_pids: false,
                pids_max: None,
                pids_peak: 0,
                pids_events: 0,
                pids_events_local: 0,
            },
        );
        if self.pids_enabled(id) {
            self.install_pids(id, true);
        }
    }
    fn pids_enabled(&self, id: u64) -> bool {
        self.groups[&id]
            .parent
            .is_some_and(|parent| self.groups[&parent].subtree_pids)
    }
    fn current(&self, id: u64) -> u64 {
        self.tasks
            .values()
            .filter(|(_, group)| below(&self.groups[group].path, &self.groups[&id].path))
            .count() as u64
    }
    fn update_peak(&mut self, id: u64) {
        for group in self.ancestors(id) {
            let count = self.current(group);
            if self.pids_enabled(group) {
                let entry = self.groups.get_mut(&group).expect("ancestor");
                entry.pids_peak = entry.pids_peak.max(count);
            }
        }
    }
    fn install_pids(&mut self, id: u64, enable: bool) {
        for (name, mode) in PIDS_FILES {
            let path = child_path(&self.groups[&id].path, name.as_bytes());
            if enable {
                self.add_node(path, false, *mode);
            } else if let Some(node) = self.fs.borrow_mut().paths.remove(&path) {
                node.borrow_mut().links = 0;
            }
        }
        let current = self.current(id);
        let group = self.groups.get_mut(&id).expect("group");
        group.pids_max = None;
        group.pids_peak = current;
        group.pids_events = 0;
        group.pids_events_local = 0;
    }
    fn frozen(&self, mut id: u64) -> bool {
        loop {
            let group = &self.groups[&id];
            if group.freeze {
                return true;
            }
            let Some(parent) = group.parent else {
                return false;
            };
            id = parent;
        }
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
    fn bpf_group(&self, fd: u32) -> Result<u64> {
        let open = self.descriptor(fd)?.open.borrow();
        if !open
            .mount
            .as_ref()
            .is_some_and(|m| m.kind == mounts::Kind::Cgroup)
        {
            return Err(Errno(9));
        }
        let node = open.node.as_ref().ok_or(Errno(9))?.borrow();
        if !matches!(node.content, Content::Directory) {
            return Err(Errno(22));
        }
        if node.links == 0 || !self.cgroups.borrow().groups.contains_key(&node.inode) {
            return Err(Errno(19));
        }
        Ok(node.inode)
    }
    pub fn bpf_attach_device(
        &self,
        target: u32,
        program: u32,
        flags: u32,
        replace: u32,
    ) -> Result<()> {
        self.bpf_authorized()?;
        if flags & !6 != 0 || flags == 4 {
            return Err(Errno(22));
        }
        let id = self.bpf_group(target)?;
        let program = self.bpf_program(program)?;
        let replace = if flags & 4 != 0 {
            Some(self.bpf_program(replace)?)
        } else {
            None
        };
        let mut cg = self.cgroups.borrow_mut();
        // ALLOW_OVERRIDE is not supported. A single ancestor attachment keeps
        // the hierarchy closed to descendant attachment, as on Linux.
        if cg.ancestors(id).iter().skip(1).any(|a| {
            !cg.groups[a].device_programs.is_empty() && cg.groups[a].device_attach_flags == 0
        }) {
            return Err(Errno(1));
        }
        if flags == 0
            && cg.groups.iter().any(|(other, g)| {
                *other != id
                    && below(&g.path, &cg.groups[&id].path)
                    && !g.device_programs.is_empty()
            })
        {
            return Err(Errno(1));
        }
        let group = cg.groups.get_mut(&id).unwrap();
        if !group.device_programs.is_empty() && group.device_attach_flags != flags & 2 {
            return Err(Errno(22));
        }
        if group.device_programs.iter().any(|p| p.id == program.id) {
            return Err(Errno(17));
        }
        if let Some(old) = replace {
            let slot = group
                .device_programs
                .iter_mut()
                .find(|p| p.id == old.id)
                .ok_or(Errno(2))?;
            *slot = program;
        } else if flags == 0 {
            group.device_programs = vec![program];
        } else {
            if group.device_programs.len() >= 16 {
                return Err(Errno(7));
            }
            group.device_programs.push(program);
        }
        group.device_attach_flags = flags & 2;
        Ok(())
    }
    pub fn bpf_detach_device(&self, target: u32, program: u32) -> Result<()> {
        self.bpf_authorized()?;
        let id = self.bpf_group(target)?;
        let program = self.bpf_program(program)?;
        let mut cg = self.cgroups.borrow_mut();
        let group = cg.groups.get_mut(&id).unwrap();
        let index = group
            .device_programs
            .iter()
            .position(|p| p.id == program.id)
            .ok_or(Errno(2))?;
        group.device_programs.remove(index);
        if group.device_programs.is_empty() {
            group.device_attach_flags = 0;
        }
        Ok(())
    }
    pub fn bpf_query_device(&self, target: u32, effective: bool) -> Result<(u32, Vec<u32>)> {
        self.bpf_authorized()?;
        let id = self.bpf_group(target)?;
        let cg = self.cgroups.borrow();
        let groups = if effective {
            cg.ancestors(id)
        } else {
            vec![id]
        };
        Ok((
            if effective {
                0
            } else {
                cg.groups[&id].device_attach_flags
            },
            groups
                .iter()
                .flat_map(|g| cg.groups[g].device_programs.iter().map(|p| p.id))
                .collect(),
        ))
    }
    pub(super) fn cgroup_device(&self, mode: u32, rdev: u64, access: u32) -> Result<()> {
        let kind = match mode & 0o170000 {
            0o20000 => 2,
            0o60000 => 1,
            _ => return Ok(()),
        };
        let major = ((rdev >> 8) & 0xfff) | ((rdev >> 32) & 0xfffff000);
        let minor = (rdev & 0xff) | ((rdev >> 12) & 0xffffff00);
        let cg = self.cgroups.borrow();
        let mut id = Some(cg.tasks.get(&self.pid).map_or(ROOT, |(_, g)| *g));
        while let Some(current) = id {
            let group = &cg.groups[&current];
            if group
                .device_programs
                .iter()
                .any(|p| !p.allows([kind | (access << 16), major as u32, minor as u32]))
            {
                return Err(Errno(1));
            }
            id = group.parent;
        }
        Ok(())
    }
    pub(super) fn check_device_open(&self, node: &Node, flags: u32) -> Result<()> {
        if flags & O_PATH != 0 {
            return Ok(());
        }
        let rdev = match node.content {
            Content::Null => 0x103,
            Content::Terminal => 0x500,
            Content::Device(d) => d.rdev(),
            _ => return Ok(()),
        };
        self.cgroup_device(
            node.mode,
            rdev,
            match flags & 3 {
                0 => 2,
                1 => 4,
                _ => 6,
            },
        )
    }
    /// Called before clone commits IDs/TID stores. All workers have joined;
    /// the following membership insertion cannot race another charge.
    pub fn cgroup_can_fork(&self, pid: u32) -> Result<()> {
        let mut cg = self.cgroups.borrow_mut();
        let id = cg.tasks.get(&pid).map_or(ROOT, |(_, group)| *group);
        for group in cg.ancestors(id) {
            if !cg.pids_enabled(group) {
                continue;
            }
            let count = cg.current(group) + 1;
            if cg.groups[&group]
                .pids_max
                .is_some_and(|limit| count > limit)
            {
                cg.groups.get_mut(&group).expect("group").pids_events_local += 1;
                for ancestor in cg.ancestors(group) {
                    if cg.pids_enabled(ancestor) {
                        cg.groups.get_mut(&ancestor).expect("ancestor").pids_events += 1;
                    }
                }
                return Err(Errno(11));
            }
            let entry = cg.groups.get_mut(&group).expect("group");
            entry.pids_peak = entry.pids_peak.max(count);
        }
        Ok(())
    }
    pub(super) fn cgroup_subsystems(&self) -> Vec<u8> {
        format!(
            "#subsys_name\thierarchy\tnum_cgroups\tenabled\npids\t0\t{}\t1\n",
            self.cgroups.borrow().groups.len()
        )
        .into_bytes()
    }
    /// Evaluated only at joined scheduler boundaries, never on CPU workers.
    /// Freeze does not overwrite signal stops or the task's blocked syscall.
    pub fn cgroup_frozen(&self, pid: u32) -> bool {
        let cg = self.cgroups.borrow();
        cg.tasks.get(&pid).is_some_and(|(_, id)| cg.frozen(*id))
    }
    /// The write snapshots the entire subtree before any task can move/fork.
    pub fn take_cgroup_kills(&self) -> BTreeSet<u32> {
        std::mem::take(&mut self.cgroups.borrow_mut().kill)
    }
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
        cg.update_peak(group);
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
            b"io.max" => String::new(),
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
            b"cgroup.controllers" => if id == ROOT || cg.pids_enabled(id) {
                "pids\n"
            } else {
                "\n"
            }
            .to_owned(),
            b"cgroup.subtree_control" => if cg.groups[&id].subtree_pids {
                "pids\n"
            } else {
                "\n"
            }
            .to_owned(),
            b"pids.current" => format!("{}\n", cg.current(id)),
            b"pids.peak" => format!("{}\n", cg.groups[&id].pids_peak),
            b"pids.max" => cg.groups[&id]
                .pids_max
                .map_or_else(|| "max\n".to_owned(), |n| format!("{n}\n")),
            b"pids.events" => format!("max {}\n", cg.groups[&id].pids_events),
            b"pids.events.local" => format!("max {}\n", cg.groups[&id].pids_events_local),
            b"cgroup.type" => "domain\n".to_owned(),
            b"cgroup.events" => {
                let populated = cg
                    .tasks
                    .values()
                    .any(|(_, g)| below(&cg.groups[g].path, path));
                format!(
                    "populated {}\nfrozen {}\n",
                    u8::from(populated),
                    u8::from(cg.frozen(id))
                )
            }
            b"cgroup.freeze" => format!("{}\n", u8::from(cg.groups[&id].freeze)),
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
            b"io.max" => return Err(Errno(95)),
            b"cgroup.freeze" => {
                let freeze = match text {
                    "0" => false,
                    "1" => true,
                    _ => return Err(Errno(22)),
                };
                self.cgroups
                    .borrow_mut()
                    .groups
                    .get_mut(&id)
                    .ok_or(Errno(19))?
                    .freeze = freeze;
            }
            b"cgroup.kill" => {
                if text != "1" {
                    return Err(Errno(22));
                }
                let mut cg = self.cgroups.borrow_mut();
                let path = &cg.groups[&id].path;
                let targets: Vec<_> = cg
                    .tasks
                    .iter()
                    .filter(|(_, (_, group))| below(&cg.groups[group].path, path))
                    .map(|(pid, _)| *pid)
                    .collect();
                cg.kill.extend(targets);
            }
            b"cgroup.subtree_control" => {
                let mut cg = self.cgroups.borrow_mut();
                let mut enable = cg.groups[&id].subtree_pids;
                for token in text.split_whitespace() {
                    enable = match token {
                        "+pids" => true,
                        "-pids" => false,
                        _ => return Err(Errno(95)),
                    };
                }
                if enable == cg.groups[&id].subtree_pids {
                    return Ok(Some(bytes.len()));
                }
                if enable && id != ROOT && !cg.pids_enabled(id) {
                    return Err(Errno(2));
                }
                let children: Vec<_> = cg
                    .groups
                    .iter()
                    .filter(|(_, g)| g.parent == Some(id))
                    .map(|(id, _)| *id)
                    .collect();
                if !enable && children.iter().any(|id| cg.groups[id].subtree_pids)
                    || enable && id != ROOT && cg.tasks.values().any(|(_, group)| *group == id)
                {
                    return Err(Errno(16));
                }
                cg.groups.get_mut(&id).expect("group").subtree_pids = enable;
                for child in children {
                    cg.install_pids(child, enable);
                }
            }
            b"pids.max" => {
                let limit = if text == "max" {
                    None
                } else {
                    let value = text.strip_prefix('+').unwrap_or(text);
                    let (value, radix) = if let Some(value) = value
                        .strip_prefix("0x")
                        .or_else(|| value.strip_prefix("0X"))
                    {
                        (value, 16)
                    } else if value.len() > 1 && value.starts_with('0') {
                        (&value[1..], 8)
                    } else {
                        (value, 10)
                    };
                    Some(
                        u64::from_str_radix(value, radix)
                            .ok()
                            .filter(|n| *n <= 4194304)
                            .ok_or(Errno(22))?,
                    )
                };
                self.cgroups
                    .borrow_mut()
                    .groups
                    .get_mut(&id)
                    .ok_or(Errno(19))?
                    .pids_max = limit;
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
                if id != ROOT && cg.groups[&id].subtree_pids {
                    return Err(Errno(16));
                }
                let (tgid, _) = *cg.tasks.get(&target).ok_or(Errno(3))?;
                for (process, group) in cg.tasks.values_mut() {
                    if *process == tgid {
                        *group = id;
                    }
                }
                cg.update_peak(id);
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
