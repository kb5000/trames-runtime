// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest overlay filesystem. The merged namespace contains metadata references,
//! not copies of lower file contents. A single backing manifest replacement is
//! the namespace commit point, including whiteouts and copied parent directories.
use super::*;
use std::collections::BTreeSet;

type Tree = BTreeMap<Vec<u8>, Rc<RefCell<Node>>>;
static NEXT_DEVICE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0x6f00_0000);
#[derive(Clone)]
struct Layer {
    at: ResolvedPath,
    fs: Rc<RefCell<Filesystem>>,
}
impl Layer {
    fn key(&self, relative: &[u8]) -> Vec<u8> {
        if relative == b"/" {
            return self.at.key.clone();
        }
        let mut key = self.at.key.clone();
        if key == b"/" {
            key.clear();
        }
        key.extend_from_slice(relative);
        key
    }
    fn tree(&self) -> Tree {
        self.fs
            .borrow()
            .paths
            .iter()
            .filter_map(|(p, n)| {
                if !below(p, &self.at.key) {
                    return None;
                }
                let relative = if p == &self.at.key {
                    b"/".to_vec()
                } else if self.at.key == b"/" {
                    p.clone()
                } else {
                    p[self.at.len()..].to_vec()
                };
                Some((relative, n.clone()))
            })
            .collect()
    }
}
#[derive(Clone, PartialEq, Eq)]
struct Metadata {
    mode: u32,
    uid: u32,
    gid: u32,
    // Reading a lower file does not trigger copy-up merely to record atime.
    times: [storage::Timestamp; 2],
    attrs: BTreeMap<Vec<u8>, Vec<u8>>,
}
impl Metadata {
    fn of(node: &Node) -> Self {
        Self {
            mode: node.mode,
            uid: node.uid,
            gid: node.gid,
            times: [node.times[1], node.times[2]],
            attrs: node.xattrs.clone(),
        }
    }
}
struct Entry {
    node: Weak<RefCell<Node>>,
    metadata: Metadata,
}
fn snapshot(paths: &Tree) -> BTreeMap<Vec<u8>, Entry> {
    paths
        .iter()
        .map(|(p, n)| {
            (
                p.clone(),
                Entry {
                    node: Rc::downgrade(n),
                    metadata: Metadata::of(&n.borrow()),
                },
            )
        })
        .collect()
}
pub(super) struct Overlay {
    pub(super) device: u64,
    // Retain backing mount capabilities across detach / mount namespace copies.
    lowers: Vec<Layer>,
    upper: Option<Layer>,
    work: Option<Layer>,
    lower: Tree,
    baseline: RefCell<BTreeMap<Vec<u8>, Entry>>,
    uncopied: RefCell<BTreeSet<usize>>,
    dirty: RefCell<BTreeSet<usize>>,
    userxattr: bool,
    options: Vec<u8>,
}
fn below(path: &[u8], root: &[u8]) -> bool {
    path == root || path.starts_with(root) && (root == b"/" || path.get(root.len()) == Some(&b'/'))
}
fn pointer(n: &Rc<RefCell<Node>>) -> usize {
    Rc::as_ptr(n) as usize
}
fn attribute(node: &Node, tail: &[u8], userxattr: bool) -> bool {
    [if userxattr {
        b"user.overlay.".as_slice()
    } else {
        b"trusted.overlay.".as_slice()
    }]
    .iter()
    .any(|prefix| {
        let mut name = prefix.to_vec();
        name.extend_from_slice(tail);
        node.xattrs
            .get(&name)
            .is_some_and(|v| v == b"y" || tail == b"whiteout")
    })
}
fn whiteout(n: &Node, userxattr: bool) -> bool {
    matches!(n.content,Content::Device(d) if n.mode & 0o170000 == 0o20000 && d.rdev() == 0)
        || matches!(&n.content, Content::File(data) if data.len() == 0)
            && attribute(n, b"whiteout", userxattr)
}
fn merge(layers: impl Iterator<Item = Tree>, userxattr: bool) -> Tree {
    let mut merged = Tree::new();
    for tree in layers {
        for (p, n) in tree {
            let nref = n.borrow();
            let hidden = whiteout(&nref, userxattr);
            if hidden
                || !matches!(nref.content, Content::Directory)
                || attribute(&nref, b"opaque", userxattr)
            {
                merged.retain(|key, _| !below(key, &p));
            }
            drop(nref);
            if !hidden {
                merged.insert(p, n);
            }
        }
    }
    merged
}
impl Overlay {
    pub(super) fn has_upper(&self) -> bool {
        self.upper.is_some()
    }
    pub(super) fn capacity(&self) -> StorageCapacity {
        let layer = self.upper.as_ref().unwrap_or(&self.lowers[0]);
        Vfs::filesystem_capacity(&layer.fs.borrow())
    }
    pub(super) fn allocate_inode(&self) -> Result<u64> {
        let upper = self.upper.as_ref().ok_or(Errno(30))?;
        let mut fs = upper.fs.borrow_mut();
        let inode = fs.next_inode;
        fs.next_inode = inode.checked_add(1).ok_or(Errno(28))?;
        Ok(inode)
    }
    pub(super) fn empty_data(&self) -> Result<storage::FileData> {
        let upper = self.upper.as_ref().ok_or(Errno(30))?;
        Vfs::filesystem_empty_data(&mut upper.fs.borrow_mut())
    }
    fn copy_up(&self, node: &Rc<RefCell<Node>>, truncate: bool) -> Result<()> {
        let id = pointer(node);
        if !self.uncopied.borrow().contains(&id) {
            return Ok(());
        }
        let upper = self.upper.as_ref().ok_or(Errno(30))?;
        let mut n = node.borrow_mut();
        if let Content::File(storage::FileData::Lower(source)) = &n.content {
            let source = source.borrow();
            let Content::File(data) = &source.content else {
                return Err(Errno(5));
            };
            let length = if truncate { 0 } else { data.len() };
            let fs = upper.fs.borrow();
            if length > Vfs::filesystem_capacity(&fs).available_bytes {
                return Err(Errno(28));
            }
            let mut copy = if let Some(disk) = &fs.disk {
                disk.create(n.inode)?
            } else {
                storage::FileData::Memory(Vec::new())
            };
            drop(fs);
            let mut offset = 0;
            while offset < length {
                let bytes = data.read_at(offset, (length - offset).min(65536) as usize)?;
                if bytes.is_empty() {
                    return Err(Errno(5));
                }
                let mut written = 0;
                while written < bytes.len() {
                    let count = copy.write_at(offset + written as u64, &bytes[written..])?;
                    if count == 0 {
                        return Err(Errno(5));
                    }
                    written += count;
                }
                offset += bytes.len() as u64;
            }
            copy.sync(false)?;
            drop(source);
            n.content = Content::File(copy);
        }
        self.uncopied.borrow_mut().remove(&id);
        self.dirty.borrow_mut().insert(id);
        Ok(())
    }
    pub(super) fn prepare(
        &self,
        fs: &Filesystem,
        node: &Rc<RefCell<Node>>,
        truncate: bool,
    ) -> Result<()> {
        self.copy_up(node, truncate)?;
        self.checkpoint(fs)
    }
    pub(super) fn lower_directory(&self, path: &[u8]) -> bool {
        let lower = self
            .lower
            .get(path)
            .is_some_and(|n| matches!(n.borrow().content, Content::Directory));
        lower
            && !self.upper.as_ref().is_some_and(|upper| {
                upper
                    .fs
                    .borrow()
                    .paths
                    .get(&upper.key(path))
                    .is_some_and(|n| attribute(&n.borrow(), b"opaque", self.userxattr))
            })
    }
    fn attr_name(&self, tail: &[u8]) -> Vec<u8> {
        let mut name = if self.userxattr {
            b"user.overlay.".to_vec()
        } else {
            b"trusted.overlay.".to_vec()
        };
        name.extend_from_slice(tail);
        name
    }
    pub(super) fn checkpoint(&self, fs: &Filesystem) -> Result<()> {
        let Some(upper) = &self.upper else {
            return Ok(());
        };
        let baseline = self.baseline.borrow();
        let mut changed = BTreeSet::new();
        for (p, n) in &fs.paths {
            let modified = baseline.get(p).is_none_or(|e| {
                e.node.upgrade().is_none_or(|old| !Rc::ptr_eq(&old, n))
                    || e.metadata != Metadata::of(&n.borrow())
            });
            if modified || self.dirty.borrow().contains(&pointer(n)) {
                changed.insert(p.clone());
            }
        }
        let removed: Vec<_> = baseline
            .keys()
            .filter(|p| !fs.paths.contains_key(*p))
            .cloned()
            .collect();
        // A whiteout is a real upper dentry too. Removing a lower-only nested
        // child therefore copies its parents, without copying sibling data.
        for path in &removed {
            let mut parent = path.clone();
            while parent != b"/" {
                parent.truncate(parent.iter().rposition(|b| *b == b'/').unwrap().max(1));
                if fs.paths.contains_key(&parent)
                    && !upper.fs.borrow().paths.contains_key(&upper.key(&parent))
                {
                    changed.insert(parent.clone());
                }
            }
        }
        if changed.is_empty() && removed.is_empty() {
            return Ok(());
        }
        // Parent directories must exist in upper before any copied child. Copy
        // every visible alias of a lower hard link together (index-free inode map).
        loop {
            let before = changed.len();
            for p in changed.clone() {
                let mut parent = p.clone();
                while parent != b"/" {
                    parent.truncate(parent.iter().rposition(|b| *b == b'/').unwrap().max(1));
                    let key = upper.key(&parent);
                    if !upper.fs.borrow().paths.contains_key(&key) {
                        changed.insert(parent.clone());
                    }
                }
                self.copy_up(fs.paths.get(&p).ok_or(Errno(5))?, false)?;
            }
            for (p, n) in &fs.paths {
                if self.dirty.borrow().contains(&pointer(n)) {
                    changed.insert(p.clone());
                }
            }
            if before == changed.len() {
                break;
            }
        }
        let mut backing = upper.fs.borrow_mut();
        let old_paths = backing.paths.clone();
        let old_inodes = backing.inodes.clone();
        let mut paths = old_paths.clone();
        let mut attrs_restore = Vec::new();
        // Deleting a directory discards its hidden whiteouts as well. A parent
        // whiteout is sufficient to hide the whole lower subtree.
        for p in &removed {
            if removed.iter().any(|parent| parent != p && below(p, parent)) {
                continue;
            }
            let key = upper.key(p);
            paths.retain(|path, _| !below(path, &key));
            if self.lower.contains_key(p) {
                let inode = backing.next_inode;
                backing.next_inode = inode.checked_add(1).ok_or(Errno(28))?;
                let n = Rc::new(RefCell::new(Node {
                    notifications: inotify::Marks::default(),
                    device: upper.fs_device(),
                    content: pseudo::Device::node(0, false),
                    mode: 0o20000,
                    uid: 0,
                    gid: 0,
                    volatile: false,
                    inode,
                    links: 1,
                    times: [storage::Timestamp::now(); 3],
                    xattrs: BTreeMap::new(),
                    seals: None,
                }));
                paths.insert(key, n);
            }
        }
        for p in &changed {
            let n = fs.paths.get(p).ok_or(Errno(5))?;
            if baseline.get(p).is_some_and(|e| {
                e.node.upgrade().is_some_and(|old| {
                    !Rc::ptr_eq(&old, n) && matches!(old.borrow().content, Content::Directory)
                })
            }) {
                let key = upper.key(p);
                paths.retain(|path, _| !below(path, &key));
            }
            // A newly created/replaced directory must not reveal old lower
            // children after remount; ordinary copy-up keeps directory merging.
            if matches!(n.borrow().content, Content::Directory)
                && self.lower.contains_key(p)
                && baseline
                    .get(p)
                    .is_none_or(|e| e.node.upgrade().is_none_or(|old| !Rc::ptr_eq(&old, n)))
            {
                let name = self.attr_name(b"opaque");
                let old = n.borrow_mut().xattrs.insert(name.clone(), b"y".to_vec());
                attrs_restore.push((n.clone(), name, old));
            }
            paths.insert(upper.key(p), n.clone());
        }
        let mut all = BTreeMap::new();
        for n in old_paths.values().chain(paths.values()) {
            all.insert(pointer(n), (n.clone(), n.borrow().links));
        }
        let mut counts = BTreeMap::<usize, u32>::new();
        for n in paths.values() {
            *counts.entry(pointer(n)).or_default() += 1;
        }
        for (id, (n, _)) in &all {
            n.borrow_mut().links = counts.get(id).copied().unwrap_or(0);
        }
        backing.paths = paths;
        let mut known: BTreeSet<_> = backing
            .inodes
            .iter()
            .filter_map(Weak::upgrade)
            .map(|n| pointer(&n))
            .collect();
        for (id, (n, _)) in &all {
            if n.borrow().links != 0 && known.insert(*id) {
                backing.inodes.push(Rc::downgrade(n));
            }
        }
        backing.inodes.retain(|n| n.strong_count() != 0);
        let capacity = Vfs::filesystem_capacity(&backing);
        let mut attr_bytes = 0usize;
        let invalid_attrs = backing.inodes.iter().filter_map(Weak::upgrade).any(|n| {
            let n = n.borrow();
            let bytes = xattr::xattr_size(&n.xattrs);
            attr_bytes = attr_bytes.saturating_add(bytes);
            n.xattrs.len() > 128 || bytes > 65536 || attr_bytes > xattr::XATTR_BUDGET
        });
        let result = if capacity.used_bytes > capacity.budget_bytes
            || capacity.nodes_used > capacity.node_limit
            || invalid_attrs
        {
            Err(Errno(28))
        } else {
            backing.checkpoint()
        };
        if let Err(error) = result {
            backing.paths = old_paths;
            backing.inodes = old_inodes;
            for (_, (n, links)) in all {
                n.borrow_mut().links = links;
            }
            for (n, key, old) in attrs_restore {
                if let Some(value) = old {
                    n.borrow_mut().xattrs.insert(key, value);
                } else {
                    n.borrow_mut().xattrs.remove(&key);
                }
            }
            return Err(error);
        }
        for (_, (n, _)) in all {
            let mut n = n.borrow_mut();
            let orphan = n.links == 0;
            if let Content::File(data) = &mut n.content {
                data.orphan(orphan);
            }
        }
        drop(backing);
        drop(baseline);
        *self.baseline.borrow_mut() = snapshot(&fs.paths);
        self.dirty.borrow_mut().clear();
        let live: BTreeSet<_> = fs.paths.values().map(pointer).collect();
        self.uncopied.borrow_mut().retain(|id| live.contains(id));
        Ok(())
    }
    pub(super) fn options(&self) -> &[u8] {
        &self.options
    }
}
impl Layer {
    fn fs_device(&self) -> u64 {
        // Caller may hold a mutable filesystem borrow; the retained mount root
        // has a separate RefCell and provides the storage device identity.
        self.at
            .mount
            .as_ref()
            .map_or(0xfd01, |m| m.root.borrow().device)
    }
}
// Keep escaping until the final path split: lowerdir itself contains ':' while
// mount options use ','. No guest bytes are interpreted as host paths.
fn split(input: &[u8], delimiter: u8) -> Vec<Vec<u8>> {
    let mut result = vec![Vec::new()];
    let mut escaped = false;
    for &b in input {
        if b == delimiter && !escaped {
            result.push(Vec::new());
        } else {
            result.last_mut().unwrap().push(b);
        }
        escaped = b == b'\\' && !escaped;
    }
    result
}
fn unescape(input: &[u8]) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut iter = input.iter();
    while let Some(&b) = iter.next() {
        result.push(if b == b'\\' {
            *iter.next().ok_or(Errno(22))?
        } else {
            b
        });
    }
    if result.is_empty() {
        return Err(Errno(22));
    }
    Ok(result)
}
impl Vfs {
    pub(super) fn overlay_mount(
        &mut self,
        data: &[u8],
        readonly: bool,
    ) -> Result<(Rc<RefCell<Filesystem>>, bool)> {
        self.reap_detached_mounts();
        let mut lower = None;
        let mut upper = None;
        let mut work = None;
        let mut userxattr = false;
        let mut seen = BTreeSet::new();
        for option in split(data, b',') {
            let mut fields = option.splitn(2, |b| *b == b'=');
            let key = fields.next().unwrap();
            let value = fields.next();
            if !seen.insert(key.to_vec()) {
                return Err(Errno(22));
            }
            match (key, value) {
                (b"lowerdir", Some(value)) => {
                    lower = Some(
                        split(value, b':')
                            .iter()
                            .map(|p| unescape(p))
                            .collect::<Result<Vec<_>>>()?,
                    )
                }
                (b"upperdir", Some(value)) => upper = Some(unescape(value)?),
                (b"workdir", Some(value)) => work = Some(unescape(value)?),
                (b"userxattr", None) => userxattr = true,
                (b"index" | b"metacopy", Some(b"off"))
                | (b"redirect_dir", Some(b"off" | b"nofollow"))
                | (b"xino", Some(b"off" | b"auto")) => {}
                _ => return Err(Errno(95)),
            }
        }
        let lower = lower.ok_or(Errno(22))?;
        if lower.is_empty() || lower.len() > 500 || upper.is_some() != work.is_some() {
            return Err(Errno(22));
        }
        let layer = |path: &[u8]| -> Result<Layer> {
            let at = self.mount_location(path, true)?;
            let fs = at.filesystem(self);
            if fs.borrow().overlay.is_some()
                || !matches!(
                    at.mount.as_ref().map(|m| m.kind),
                    Some(mounts::Kind::Root | mounts::Kind::Tmpfs)
                )
            {
                return Err(Errno(95));
            }
            let n = self.node(&at)?;
            if !matches!(n.borrow().content, Content::Directory) {
                return Err(Errno(20));
            }
            if !self.allowed(&n.borrow(), 5) {
                return Err(Errno(13));
            }
            Ok(Layer { at, fs })
        };
        let lowers = lower.iter().map(|p| layer(p)).collect::<Result<Vec<_>>>()?;
        let upper = upper.as_deref().map(layer).transpose()?;
        let work = work.as_deref().map(layer).transpose()?;
        let overlaps = |a: &Layer, b: &Layer| {
            Rc::ptr_eq(&a.fs, &b.fs) && (below(&a.at, &b.at) || below(&b.at, &a.at))
        };
        if let (Some(u), Some(w)) = (&upper, &work) {
            if !Rc::ptr_eq(&u.fs, &w.fs) {
                return Err(Errno(18));
            }
            u.at.writable()?;
            w.at.writable()?;
            if overlaps(u, w) || lowers.iter().any(|l| overlaps(l, u) || overlaps(l, w)) {
                return Err(Errno(22));
            }
            if w.tree().iter().any(|(p, n)| {
                p != b"/" && (p != b"/work" || !matches!(n.borrow().content, Content::Directory))
            }) {
                return Err(Errno(39));
            }
            for m in self
                .mount_registry
                .borrow()
                .iter()
                .filter_map(Weak::upgrade)
            {
                if let Some(o) = &m.fs.borrow().overlay {
                    if [&o.upper, &o.work]
                        .into_iter()
                        .flatten()
                        .any(|l| overlaps(l, u) || overlaps(l, w))
                    {
                        return Err(Errno(16));
                    }
                }
            }
            if !self.allowed(&self.node(&u.at)?.borrow(), 3)
                || !self.allowed(&self.node(&w.at)?.borrow(), 3)
            {
                return Err(Errno(13));
            }
            let at = ResolvedPath {
                key: w.key(b"/work"),
                mount: w.at.mount.clone(),
            };
            if !w.fs.borrow().paths.contains_key(&at.key) {
                // Moby adjusts ownership of the kernel-created work/work
                // directory after mounting, including idmapped/rootful setups.
                self.insert(at, Content::Directory, 0o40700)?;
            }
        }
        let lower = merge(lowers.iter().rev().map(Layer::tree), userxattr);
        let mut merged = lower.clone();
        if let Some(u) = &upper {
            merged = merge([merged, u.tree()].into_iter(), userxattr);
        }
        let budget = upper.as_ref().unwrap_or(&lowers[0]).fs.borrow().limits;
        if merged.len() > budget.nodes {
            return Err(Errno(28));
        }
        let o = Rc::new(Overlay {
            device: NEXT_DEVICE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            lowers,
            upper,
            work,
            lower,
            baseline: RefCell::default(),
            uncopied: RefCell::default(),
            dirty: RefCell::default(),
            userxattr,
            options: data.to_vec(),
        });
        let upper_nodes: BTreeSet<_> = o
            .upper
            .as_ref()
            .map(|u| u.tree().values().map(pointer).collect())
            .unwrap_or_default();
        let mut clones = BTreeMap::new();
        let mut paths = Tree::new();
        let mut next = 1;
        for (path, source) in merged {
            let id = pointer(&source);
            let n = if upper_nodes.contains(&id) {
                source
            } else if let Some(n) = clones.get(&id) {
                Rc::clone(n)
            } else {
                let inode = if o.upper.is_some() {
                    o.allocate_inode()?
                } else {
                    let i = next;
                    next += 1;
                    i
                };
                let n = source.borrow();
                let content = match &n.content {
                    Content::Directory => Content::Directory,
                    Content::File(_) => Content::File(storage::FileData::Lower(source.clone())),
                    Content::Symlink(target) => Content::Symlink(target.clone()),
                    Content::Null => Content::Null,
                    Content::Terminal => Content::Terminal,
                    Content::Device(d) => Content::Device(*d),
                    Content::Fifo(p) => Content::Fifo(p.clone()),
                    Content::Socket(s) => Content::Socket(s.clone()),
                };
                let copy = Rc::new(RefCell::new(Node {
                    notifications: inotify::Marks::default(),
                    device: n.device,
                    content,
                    mode: n.mode,
                    uid: n.uid,
                    gid: n.gid,
                    volatile: false,
                    inode,
                    links: 0,
                    times: n.times,
                    xattrs: n
                        .xattrs
                        .iter()
                        .filter(|(name, _)| {
                            !name.starts_with(b"trusted.overlay.")
                                && !name.starts_with(b"user.overlay.")
                        })
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                    seals: None,
                }));
                o.uncopied.borrow_mut().insert(pointer(&copy));
                clones.insert(id, copy.clone());
                copy
            };
            if o.uncopied.borrow().contains(&pointer(&n)) {
                n.borrow_mut().links += 1;
            }
            paths.insert(path, n);
        }
        if !paths.contains_key(b"/".as_slice()) {
            return Err(Errno(22));
        }
        for (path, node) in &paths {
            if path == b"/" {
                continue;
            }
            let slash = path.iter().rposition(|b| *b == b'/').ok_or(Errno(22))?;
            let parent = paths.get(&path[..slash.max(1)]).ok_or(Errno(22))?;
            inotify::link(node, parent, &path[slash + 1..]);
        }
        *o.baseline.borrow_mut() = snapshot(&paths);
        let mut unique = BTreeMap::new();
        for n in paths.values() {
            unique.insert(pointer(n), Rc::downgrade(n));
        }
        let ro = readonly || o.upper.is_none();
        let fs = Filesystem {
            overlay: Some(o),
            shared_budget: trames_shared::SharedBudget::new(memfd::MEMFD_BYTES as usize),
            paths,
            inodes: unique.into_values().collect(),
            next_inode: next,
            flock: BTreeMap::new(),
            record_locks: BTreeMap::new(),
            limits: budget,
            disk: None,
            volume: None,
        };
        Ok((Rc::new(RefCell::new(fs)), ro))
    }
    pub(super) fn overlay_prepare(
        &self,
        at: &ResolvedPath,
        node: &Rc<RefCell<Node>>,
        truncate: bool,
    ) -> Result<()> {
        let fs = at.filesystem(self);
        let fs = fs.borrow();
        if let Some(o) = &fs.overlay {
            o.prepare(&fs, node, truncate)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dirs(v: &mut Vfs) {
        for path in [
            b"/lower".as_slice(),
            b"/lower2",
            b"/upper",
            b"/work",
            b"/merged",
            b"/other",
        ] {
            v.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
        }
    }
    fn mount(v: &mut Vfs) {
        v.mount(
            Some(b"overlay"),
            b"/merged",
            Some(b"overlay"),
            0,
            Some(b"lowerdir=/lower:/lower2,upperdir=/upper,workdir=/work,index=off"),
        )
        .unwrap();
    }
    fn write(v: &mut Vfs, path: &[u8], data: &[u8]) {
        let fd = v.open_at(AT_FDCWD, path, 0x242, 0o644).unwrap();
        v.write(fd, data).unwrap();
        v.close(fd).unwrap();
    }
    fn read(v: &mut Vfs, path: &[u8]) -> Vec<u8> {
        let fd = v.open_at(AT_FDCWD, path, 0, 0).unwrap();
        let bytes = v.read(fd, 65536).unwrap();
        v.close(fd).unwrap();
        bytes
    }
    fn names(v: &mut Vfs, path: &[u8]) -> Vec<Vec<u8>> {
        let fd = v.open_at(AT_FDCWD, path, O_DIRECTORY, 0).unwrap();
        let bytes = v.getdents(fd, 65536).unwrap();
        v.close(fd).unwrap();
        let mut result = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let len = u16::from_le_bytes(bytes[at + 16..at + 18].try_into().unwrap()) as usize;
            let name = &bytes[at + 19..at + len];
            let end = name.iter().position(|b| *b == 0).unwrap();
            result.push(name[..end].to_vec());
            at += len;
        }
        result
    }
    #[test]
    fn merged_layers_copy_up_and_old_descriptions_keep_lower() {
        let mut v = Vfs::default();
        dirs(&mut v);
        write(&mut v, b"/lower/a", b"first");
        write(&mut v, b"/lower2/a", b"second");
        write(&mut v, b"/lower2/b", b"bottom");
        let capacity = v.capacity();
        mount(&mut v);
        assert_eq!(v.capacity().used_bytes, capacity.used_bytes);
        assert_eq!(read(&mut v, b"/merged/a"), b"first");
        assert_eq!(read(&mut v, b"/merged/b"), b"bottom");
        assert_eq!(
            names(&mut v, b"/merged"),
            [b".".to_vec(), b"..".to_vec(), b"a".to_vec(), b"b".to_vec()]
        );
        let old = v.open_at(AT_FDCWD, b"/merged/a", 0, 0).unwrap();
        write(&mut v, b"/merged/a", b"new");
        assert_eq!(read(&mut v, b"/lower/a"), b"first");
        assert_eq!(read(&mut v, b"/upper/a"), b"new");
        assert_eq!(v.pread(old, 32, 0).unwrap(), b"first");
        assert_eq!(read(&mut v, b"/merged/a"), b"new");
        v.close(old).unwrap();
        assert_eq!(
            &v.statfs_at(b"/merged").unwrap()[..8],
            &0x794c7630u64.to_le_bytes()
        );
        v.umount(b"/merged", 0).unwrap();
        mount(&mut v);
        assert_eq!(read(&mut v, b"/merged/a"), b"new");
    }
    #[test]
    fn whiteouts_opaque_recreation_symlinks_and_remount() {
        let mut v = Vfs::default();
        dirs(&mut v);
        v.mkdir_at(AT_FDCWD, b"/lower/d", 0o755).unwrap();
        write(&mut v, b"/lower/d/a", b"lower");
        v.symlink_at(b"d/a", AT_FDCWD, b"/lower/link").unwrap();
        mount(&mut v);
        assert_eq!(read(&mut v, b"/merged/link"), b"lower");
        v.unlink_at(AT_FDCWD, b"/merged/d", true).unwrap_err();
        v.unlink_at(AT_FDCWD, b"/merged/d/a", false).unwrap();
        assert_eq!(names(&mut v, b"/merged/d"), [b".".to_vec(), b"..".to_vec()]);
        v.unlink_at(AT_FDCWD, b"/merged/d", true).unwrap();
        v.mkdir_at(AT_FDCWD, b"/merged/d", 0o700).unwrap();
        write(&mut v, b"/merged/d/b", b"upper");
        assert_eq!(v.stat_at(AT_FDCWD, b"/merged/d/a"), Err(Errno(2)));
        v.umount(b"/merged", 0).unwrap();
        mount(&mut v);
        assert_eq!(v.stat_at(AT_FDCWD, b"/merged/d/a"), Err(Errno(2)));
        assert_eq!(read(&mut v, b"/merged/d/b"), b"upper");
        assert_eq!(read(&mut v, b"/lower/d/a"), b"lower");
        v.rename_at(AT_FDCWD, b"/merged/d", AT_FDCWD, b"/merged/moved", 0)
            .unwrap();
        v.umount(b"/merged", 0).unwrap();
        mount(&mut v);
        assert_eq!(v.stat_at(AT_FDCWD, b"/merged/d"), Err(Errno(2)));
        assert_eq!(read(&mut v, b"/merged/moved/b"), b"upper");
    }
    #[test]
    fn metadata_hardlinks_rename_and_open_unlink() {
        let mut v = Vfs::default();
        dirs(&mut v);
        write(&mut v, b"/lower/a", b"original");
        v.link_at(AT_FDCWD, b"/lower/a", AT_FDCWD, b"/lower/b")
            .unwrap();
        v.mkdir_at(AT_FDCWD, b"/lower/d", 0o755).unwrap();
        mount(&mut v);
        v.chmod_at(AT_FDCWD, b"/merged/a", 0o600).unwrap();
        assert_eq!(
            v.node(&v.resolve(AT_FDCWD, b"/lower/a").unwrap())
                .unwrap()
                .borrow()
                .mode
                & 0o777,
            0o644
        );
        assert_eq!(
            &v.stat_at(AT_FDCWD, b"/merged/a").unwrap()[8..16],
            &v.stat_at(AT_FDCWD, b"/merged/b").unwrap()[8..16]
        );
        v.link_at(AT_FDCWD, b"/merged/a", AT_FDCWD, b"/merged/c")
            .unwrap();
        write(&mut v, b"/merged/c", b"changed");
        assert_eq!(read(&mut v, b"/merged/b"), b"changed");
        v.rename_at(AT_FDCWD, b"/merged/a", AT_FDCWD, b"/merged/new", 0)
            .unwrap();
        assert_eq!(
            v.rename_at(AT_FDCWD, b"/merged/d", AT_FDCWD, b"/merged/moved", 0),
            Err(Errno(18))
        );
        assert_eq!(
            v.rename_at(AT_FDCWD, b"/merged/new", AT_FDCWD, b"/other/file", 0),
            Err(Errno(18))
        );
        let fd = v.open_at(AT_FDCWD, b"/merged/new", 2, 0).unwrap();
        v.unlink_at(AT_FDCWD, b"/merged/new", false).unwrap();
        v.pwrite(fd, b"open", 0).unwrap();
        assert_eq!(v.pread(fd, 4, 0).unwrap(), b"open");
        v.close(fd).unwrap();
        v.umount(b"/merged", 0).unwrap();
        mount(&mut v);
        assert_eq!(v.stat_at(AT_FDCWD, b"/merged/a"), Err(Errno(2)));
        assert_eq!(v.stat_at(AT_FDCWD, b"/merged/new"), Err(Errno(2)));
        assert_eq!(read(&mut v, b"/merged/b"), b"openged");
    }
    #[test]
    fn readonly_leases_options_and_layer_type_conflicts() {
        let mut v = Vfs::default();
        dirs(&mut v);
        v.mkdir_at(AT_FDCWD, b"/lower2/d", 0o755).unwrap();
        write(&mut v, b"/lower2/d/file", b"hidden");
        write(&mut v, b"/lower/d", b"top-file");
        mount(&mut v);
        assert_eq!(v.stat_at(AT_FDCWD, b"/merged/d/file"), Err(Errno(20)));
        assert_eq!(
            v.mount(
                None,
                b"/other",
                Some(b"overlay"),
                0,
                Some(b"lowerdir=/lower,upperdir=/upper,workdir=/work")
            ),
            Err(Errno(16))
        );
        v.umount(b"/merged", 0).unwrap();
        v.mount(
            None,
            b"/merged",
            Some(b"overlay"),
            0,
            Some(b"lowerdir=/lower:/lower2"),
        )
        .unwrap();
        assert_eq!(v.open_at(AT_FDCWD, b"/merged/d", 2, 0), Err(Errno(30)));
        assert_eq!(v.mkdir_at(AT_FDCWD, b"/merged/new", 0o755), Err(Errno(30)));
        v.umount(b"/merged", 0).unwrap();
        for options in [
            b"lowerdir=/lower,upperdir=/upper".as_slice(),
            b"lowerdir=/lower,upperdir=/upper,workdir=/upper",
            b"lowerdir=/lower,index=on",
        ] {
            assert!(v
                .mount(None, b"/merged", Some(b"overlay"), 0, Some(options))
                .is_err());
        }
    }
    #[test]
    fn writable_mapping_changes_only_upper_and_read_mapping_retains_lower() {
        use trames_memory::{Memory, Permissions};
        let mut v = Vfs::default();
        dirs(&mut v);
        write(&mut v, b"/lower/a", &[42; 4096]);
        mount(&mut v);
        let reader = v.open_at(AT_FDCWD, b"/merged/a", 0, 0).unwrap();
        let mut memory = Memory::default();
        memory
            .map_backed(
                0x1000,
                v.mapping_pages(reader, 0, 4096, true, false).unwrap(),
                true,
                Permissions::R,
                false,
            )
            .unwrap();
        let writer = v.open_at(AT_FDCWD, b"/merged/a", 2, 0).unwrap();
        memory
            .map_backed(
                0x2000,
                v.mapping_pages(writer, 0, 4096, true, true).unwrap(),
                true,
                Permissions::RW,
                false,
            )
            .unwrap();
        memory.write_array(0x2000, [99]).unwrap();
        memory.sync_range(0x2000, 4096).unwrap();
        assert_eq!(memory.read_array::<1>(0x1000).unwrap(), [42]);
        assert_eq!(v.pread(writer, 1, 0).unwrap(), [99]);
        assert_eq!(read(&mut v, b"/lower/a")[0], 42);
        assert_eq!(read(&mut v, b"/upper/a")[0], 99);
    }
    #[test]
    fn disk_reopen_persists_copy_up_whiteout_metadata_and_opaque() {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "trames-overlay-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        {
            let mut v = Vfs::open_disk(&path, DiskOptions::default()).unwrap();
            dirs(&mut v);
            write(&mut v, b"/lower/a", b"lower");
            write(&mut v, b"/lower/b", b"remove");
            v.mkdir_at(AT_FDCWD, b"/lower/nested", 0o755).unwrap();
            write(&mut v, b"/lower/nested/deleted", b"hidden");
            write(&mut v, b"/lower/nested/retained", b"still-lower");
            v.mkdir_at(AT_FDCWD, b"/lower/opaque", 0o755).unwrap();
            write(&mut v, b"/lower/opaque/deleted", b"hidden");
            mount(&mut v);
            write(&mut v, b"/merged/a", b"persisted");
            v.set_xattr(
                AT_FDCWD,
                Some(b"/merged/a"),
                true,
                b"user.test",
                Some(b"value"),
                0,
            )
            .unwrap();
            v.unlink_at(AT_FDCWD, b"/merged/b", false).unwrap();
            v.unlink_at(AT_FDCWD, b"/merged/nested/deleted", false)
                .unwrap();
            v.unlink_at(AT_FDCWD, b"/merged/opaque/deleted", false)
                .unwrap();
            v.unlink_at(AT_FDCWD, b"/merged/opaque", true).unwrap();
            v.mkdir_at(AT_FDCWD, b"/merged/opaque", 0o700).unwrap();
            v.sync().unwrap();
        }
        {
            let mut v = Vfs::open_disk(&path, DiskOptions::default()).unwrap();
            mount(&mut v);
            assert_eq!(read(&mut v, b"/merged/a"), b"persisted");
            assert_eq!(read(&mut v, b"/lower/a"), b"lower");
            assert_eq!(v.stat_at(AT_FDCWD, b"/merged/b"), Err(Errno(2)));
            assert_eq!(
                v.stat_at(AT_FDCWD, b"/merged/nested/deleted"),
                Err(Errno(2))
            );
            assert_eq!(
                v.stat_at(AT_FDCWD, b"/merged/opaque/deleted"),
                Err(Errno(2))
            );
            assert_eq!(read(&mut v, b"/merged/nested/retained"), b"still-lower");
            assert_eq!(
                v.stat_at(AT_FDCWD, b"/upper/nested/retained"),
                Err(Errno(2))
            );
            assert_eq!(
                v.get_xattr(AT_FDCWD, Some(b"/merged/a"), true, b"user.test")
                    .unwrap(),
                b"value"
            );
        }
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn copy_up_quota_failure_and_readonly_permissions_do_not_change_lower() {
        let mut v = Vfs::default();
        dirs(&mut v);
        write(&mut v, b"/lower/a", b"original");
        v.set_storage_limits(StorageLimits {
            file_bytes: 10,
            nodes: MAX_NODES,
        })
        .unwrap();
        mount(&mut v);
        assert_eq!(v.open_at(AT_FDCWD, b"/merged/a", 2, 0), Err(Errno(28)));
        assert_eq!(v.chmod_at(AT_FDCWD, b"/merged/a", 0o600), Err(Errno(28)));
        assert_eq!(v.stat_at(AT_FDCWD, b"/upper/a"), Err(Errno(2)));
        assert_eq!(read(&mut v, b"/merged/a"), b"original");
        assert_eq!(
            v.node(&v.resolve(AT_FDCWD, b"/merged/a").unwrap())
                .unwrap()
                .borrow()
                .mode
                & 0o777,
            0o644
        );
        assert_eq!(v.capacity().used_bytes, 8);
        v.credentials = Credentials::user(1000, 1000);
        assert_eq!(v.open_at(AT_FDCWD, b"/merged/a", 2, 0), Err(Errno(13)));
    }
    #[test]
    fn upper_directory_rename_namespace_copy_and_readonly_remount() {
        let mut v = Vfs::default();
        dirs(&mut v);
        mount(&mut v);
        v.mkdir_at(AT_FDCWD, b"/merged/d", 0o755).unwrap();
        write(&mut v, b"/merged/d/a", b"upper");
        v.mount(Some(b"/merged"), b"/other", None, 4096, None)
            .unwrap();
        assert_eq!(
            &v.stat_at(AT_FDCWD, b"/merged/d/a").unwrap()[..16],
            &v.stat_at(AT_FDCWD, b"/other/d/a").unwrap()[..16]
        );
        v.umount(b"/other", 0).unwrap();
        let directory = v.open_at(AT_FDCWD, b"/merged/d", O_DIRECTORY, 0).unwrap();
        v.rename_at(AT_FDCWD, b"/merged/d", AT_FDCWD, b"/merged/e", 0)
            .unwrap();
        let fd = v.open_at(directory as i32, b"a", 0, 0).unwrap();
        assert_eq!(v.read(fd, 32).unwrap(), b"upper");
        v.close(fd).unwrap();
        v.close(directory).unwrap();
        let mut child = v.clone();
        child.unshare_mounts().unwrap();
        write(&mut child, b"/merged/e/b", b"shared-superblock");
        assert_eq!(read(&mut v, b"/merged/e/b"), b"shared-superblock");
        drop(child);
        v.umount(b"/merged", 0).unwrap();
        v.mount(
            None,
            b"/merged",
            Some(b"overlay"),
            0,
            Some(b"lowerdir=/upper"),
        )
        .unwrap();
        assert_eq!(v.mount(None, b"/merged", None, 32, None), Err(Errno(30)));
    }
    #[test]
    fn failed_manifest_commit_rolls_back_whiteout_and_visible_namespace() {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "trames-overlay-rollback-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        {
            let mut v = Vfs::open_disk(&path, DiskOptions::default()).unwrap();
            dirs(&mut v);
            write(&mut v, b"/lower/a", b"lower");
            mount(&mut v);
            std::fs::create_dir(path.join("manifest.new")).unwrap();
            assert!(v.unlink_at(AT_FDCWD, b"/merged/a", false).is_err());
            assert_eq!(read(&mut v, b"/merged/a"), b"lower");
            assert_eq!(v.stat_at(AT_FDCWD, b"/upper/a"), Err(Errno(2)));
            assert!(v.mkdir_at(AT_FDCWD, b"/merged/new", 0o755).is_err());
            assert_eq!(v.stat_at(AT_FDCWD, b"/merged/new"), Err(Errno(2)));
            std::fs::remove_dir(path.join("manifest.new")).unwrap();
            v.unlink_at(AT_FDCWD, b"/merged/a", false).unwrap();
            v.sync().unwrap();
        }
        {
            let mut v = Vfs::open_disk(&path, DiskOptions::default()).unwrap();
            mount(&mut v);
            assert_eq!(v.stat_at(AT_FDCWD, b"/merged/a"), Err(Errno(2)));
            assert_eq!(read(&mut v, b"/lower/a"), b"lower");
        }
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn lazy_detach_releases_upper_lease_after_last_file_reference() {
        let mut v = Vfs::default();
        dirs(&mut v);
        write(&mut v, b"/lower/a", b"lower");
        mount(&mut v);
        let fd = v.open_at(AT_FDCWD, b"/merged/a", 0, 0).unwrap();
        v.umount(b"/merged", 2).unwrap();
        assert_eq!(
            v.mount(
                None,
                b"/merged",
                Some(b"overlay"),
                0,
                Some(b"lowerdir=/lower,upperdir=/upper,workdir=/work")
            ),
            Err(Errno(16))
        );
        assert_eq!(v.pread(fd, 16, 0).unwrap(), b"lower");
        v.close(fd).unwrap();
        mount(&mut v);
        assert_eq!(read(&mut v, b"/merged/a"), b"lower");
    }
    #[test]
    fn userxattr_whiteouts_and_opaque_are_selected_by_mount_option() {
        let mut v = Vfs::default();
        dirs(&mut v);
        v.mkdir_at(AT_FDCWD, b"/lower/d", 0o755).unwrap();
        write(&mut v, b"/lower/d/a", b"lower");
        v.mkdir_at(AT_FDCWD, b"/upper/d", 0o755).unwrap();
        write(&mut v, b"/upper/marker", b"");
        v.set_xattr(
            AT_FDCWD,
            Some(b"/upper/d"),
            true,
            b"user.overlay.opaque",
            Some(b"y"),
            0,
        )
        .unwrap();
        v.set_xattr(
            AT_FDCWD,
            Some(b"/upper/marker"),
            true,
            b"user.overlay.whiteout",
            Some(b""),
            0,
        )
        .unwrap();
        mount(&mut v);
        assert_eq!(read(&mut v, b"/merged/d/a"), b"lower");
        assert!(v.stat_at(AT_FDCWD, b"/merged/marker").is_ok());
        v.umount(b"/merged", 0).unwrap();
        v.mount(
            None,
            b"/merged",
            Some(b"overlay"),
            0,
            Some(b"lowerdir=/lower,upperdir=/upper,workdir=/work,userxattr"),
        )
        .unwrap();
        assert_eq!(v.stat_at(AT_FDCWD, b"/merged/d/a"), Err(Errno(2)));
        assert_eq!(v.stat_at(AT_FDCWD, b"/merged/marker"), Err(Errno(2)));
        write(&mut v, b"/merged/new", b"user");
    }
    #[test]
    fn read_and_copy_up_notify_the_merged_inode_and_parent() {
        let mut v = Vfs::default();
        dirs(&mut v);
        write(&mut v, b"/lower/a", b"lower");
        mount(&mut v);
        let events = v.inotify_init(O_NONBLOCK).unwrap();
        v.inotify_add(events, b"/merged", inotify::ACCESS | inotify::MODIFY)
            .unwrap();
        assert_eq!(read(&mut v, b"/merged/a"), b"lower");
        let data = v.read(events, 4096).unwrap();
        assert_eq!(
            u32::from_le_bytes(data[4..8].try_into().unwrap()),
            inotify::ACCESS
        );
        let fd = v.open_at(AT_FDCWD, b"/merged/a", 2, 0).unwrap();
        v.write(fd, b"upper").unwrap();
        v.close(fd).unwrap();
        let data = v.read(events, 4096).unwrap();
        assert_eq!(
            u32::from_le_bytes(data[4..8].try_into().unwrap()),
            inotify::MODIFY
        );
    }
    #[test]
    fn proc_reopens_pin_lower_reads_but_writable_reopens_copy_up() {
        let mut v = Vfs::default();
        dirs(&mut v);
        write(&mut v, b"/lower/a", b"lower");
        mount(&mut v);
        let reader = v.open_at(AT_FDCWD, b"/merged/a", 0, 0).unwrap();
        v.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    fds: v.fd_snapshot(),
                    ..ProcessInfo::default()
                }],
                ..RuntimeInfo::default()
            },
        );
        let path = format!("/proc/self/fd/{reader}");
        let writer = v.open_at(AT_FDCWD, path.as_bytes(), 2, 0).unwrap();
        v.write(writer, b"upper").unwrap();
        let reopened = v.open_at(AT_FDCWD, path.as_bytes(), 0, 0).unwrap();
        assert_eq!(v.pread(reopened, 32, 0).unwrap(), b"lower");
        assert_eq!(read(&mut v, b"/merged/a"), b"upper");
        assert_eq!(read(&mut v, b"/lower/a"), b"lower");
    }
    #[test]
    fn committed_lower_whiteouts_and_hardlinks_survive_another_upper() {
        let mut v = Vfs::default();
        dirs(&mut v);
        v.mkdir_at(AT_FDCWD, b"/lower2/etc", 0o755).unwrap();
        write(&mut v, b"/lower2/etc/alpine-release", b"3.22");
        v.mkdir_at(AT_FDCWD, b"/lower/etc", 0o755).unwrap();
        v.mknod_at(AT_FDCWD, b"/lower/etc/alpine-release", 0o20000, 0)
            .unwrap();
        v.mkdir_at(AT_FDCWD, b"/lower/new", 0o755).unwrap();
        write(&mut v, b"/lower/new/child", b"child");
        v.link_at(AT_FDCWD, b"/lower/new/child", AT_FDCWD, b"/lower/hard")
            .unwrap();
        mount(&mut v);
        assert_eq!(
            v.stat_at(AT_FDCWD, b"/merged/etc/alpine-release"),
            Err(Errno(2))
        );
        assert_eq!(
            &v.stat_at(AT_FDCWD, b"/merged/new/child").unwrap()[8..16],
            &v.stat_at(AT_FDCWD, b"/merged/hard").unwrap()[8..16]
        );
        assert_eq!(read(&mut v, b"/merged/new/child"), b"child");
    }
    #[test]
    fn truncating_lower_file_needs_no_space_for_discarded_data() {
        let mut v = Vfs::default();
        dirs(&mut v);
        write(&mut v, b"/lower/a", b"original");
        v.set_storage_limits(StorageLimits {
            file_bytes: 8,
            nodes: MAX_NODES,
        })
        .unwrap();
        mount(&mut v);
        let old = v.open_at(AT_FDCWD, b"/merged/a", 0, 0).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/merged/a", 0x202, 0).unwrap();
        v.close(fd).unwrap();
        assert_eq!(read(&mut v, b"/merged/a"), b"");
        assert_eq!(v.pread(old, 32, 0).unwrap(), b"original");
        assert_eq!(v.capacity().used_bytes, 8);
    }
}
