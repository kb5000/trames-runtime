// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest inode watches. All producers run on the VFS coordinator; no host watches
//! or extra worker/algorithm locks are involved.
use super::*;

pub(super) const ACCESS: u32 = 1;
pub(super) const MODIFY: u32 = 2;
pub(super) const ATTRIB: u32 = 4;
const CLOSE_WRITE: u32 = 8;
const CLOSE_NOWRITE: u32 = 16;
pub(super) const OPEN: u32 = 32;
pub(super) const MOVED_FROM: u32 = 64;
pub(super) const MOVED_TO: u32 = 128;
pub(super) const CREATE: u32 = 256;
pub(super) const DELETE: u32 = 512;
const DELETE_SELF: u32 = 1024;
pub(super) const MOVE_SELF: u32 = 2048;
const IGNORED: u32 = 0x8000;
const ISDIR: u32 = 0x40000000;
const ALL: u32 = 0xfff;
const MAX_EVENTS: usize = 16384;

#[derive(Default)]
pub(super) struct Marks {
    watchers: Vec<(Weak<RefCell<Instance>>, i32)>,
    links: Vec<Rc<Link>>,
}
pub(super) struct Link {
    parent: RefCell<Weak<RefCell<Node>>>,
    name: RefCell<Vec<u8>>,
    linked: Cell<bool>,
}
pub(super) struct Close {
    node: Weak<RefCell<Node>>,
    pub(super) link: Option<Rc<Link>>,
    writable: bool,
}
impl Close {
    pub(super) fn reopen(
        node: &Rc<RefCell<Node>>,
        flags: u32,
        original: Option<&Close>,
    ) -> Option<Self> {
        if flags & O_PATH != 0 {
            return None;
        }
        let link = original.and_then(|c| c.link.clone());
        notify(node, OPEN, link.as_ref());
        Some(Self {
            node: Rc::downgrade(node),
            link,
            writable: flags & 3 != 0,
        })
    }
}
impl Drop for Close {
    fn drop(&mut self) {
        if let Some(node) = self.node.upgrade() {
            notify(
                &node,
                if self.writable {
                    CLOSE_WRITE
                } else {
                    CLOSE_NOWRITE
                },
                self.link.as_ref(),
            );
        }
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        // Open files defer deletion until their last reference goes away. Watch
        // registrations are weak and do not keep deleted guest inodes alive.
        self.notifications.destroy(self.links == 0);
    }
}
impl Marks {
    pub(super) fn send(&mut self, mask: u32, cookie: u32, name: &[u8], unlinked: bool) {
        self.watchers.retain(|(weak, wd)| {
            let Some(instance) = weak.upgrade() else {
                return false;
            };
            let mut i = instance.borrow_mut();
            let Some(watch) = i.watches.get(wd) else {
                return false;
            };
            if mask & watch.mask & ALL == 0 || unlinked && watch.mask & 0x04000000 != 0 {
                return true;
            }
            let oneshot = watch.mask & 0x80000000 != 0;
            i.push(*wd, mask, cookie, name);
            if oneshot {
                i.remove(*wd);
            }
            !oneshot
        });
    }
    pub(super) fn destroy(&mut self, deleted: bool) {
        if deleted {
            self.send(DELETE_SELF, 0, b"", false);
        }
        for (weak, wd) in self.watchers.drain(..) {
            if let Some(i) = weak.upgrade() {
                i.borrow_mut().remove(wd);
            }
        }
    }
}
struct Watch {
    node: Weak<RefCell<Node>>,
    mask: u32,
}
pub(super) struct Instance {
    watches: BTreeMap<i32, Watch>,
    next: i32,
    queue: VecDeque<Vec<u8>>,
    bytes: usize,
    pub(super) epoch: u64,
}
impl Instance {
    fn push(&mut self, wd: i32, mask: u32, cookie: u32, name: &[u8]) {
        let (wd, mask, cookie, name) = if self.queue.len() >= MAX_EVENTS {
            (-1, 0x4000, 0, b"".as_slice())
        } else {
            (wd, mask, cookie, name)
        };
        let len = if name.is_empty() {
            0
        } else {
            (name.len() + 1).next_multiple_of(16)
        };
        let mut bytes = Vec::with_capacity(16 + len);
        bytes.extend(wd.to_le_bytes());
        bytes.extend(mask.to_le_bytes());
        bytes.extend(cookie.to_le_bytes());
        bytes.extend((len as u32).to_le_bytes());
        bytes.extend(name);
        bytes.resize(16 + len, 0);
        // Linux coalesces identical adjacent unread events, including overflow.
        if self.queue.back() == Some(&bytes) {
            return;
        }
        if self.queue.len() > MAX_EVENTS {
            return;
        }
        self.bytes += bytes.len();
        self.queue.push_back(bytes);
        self.epoch = self.epoch.wrapping_add(1);
    }
    fn remove(&mut self, wd: i32) {
        if self.watches.remove(&wd).is_some() {
            self.push(wd, IGNORED, 0, b"");
        }
    }
    pub(super) fn available(&self) -> usize {
        self.bytes
    }
    pub(super) fn read(&mut self, count: usize) -> Result<Vec<u8>> {
        let Some(first) = self.queue.front() else {
            return Err(Errno(11));
        };
        if count < first.len() {
            return Err(Errno(22));
        }
        let mut out = Vec::new();
        while self
            .queue
            .front()
            .is_some_and(|e| e.len() <= count - out.len())
        {
            let event = self.queue.pop_front().expect("front event");
            self.bytes -= event.len();
            out.extend(event);
        }
        Ok(out)
    }
}

pub(super) fn link(node: &Rc<RefCell<Node>>, parent: &Rc<RefCell<Node>>, name: &[u8]) {
    node.borrow_mut()
        .notifications
        .links
        .retain(|l| l.parent.borrow().strong_count() != 0);
    if node.borrow().notifications.links.iter().any(|l| {
        *l.name.borrow() == name
            && l.parent
                .borrow()
                .upgrade()
                .is_some_and(|p| Rc::ptr_eq(&p, parent))
    }) {
        return;
    }
    node.borrow_mut().notifications.links.push(Rc::new(Link {
        parent: RefCell::new(Rc::downgrade(parent)),
        name: RefCell::new(name.to_vec()),
        linked: Cell::new(true),
    }));
}
pub(super) fn unlink(node: &Rc<RefCell<Node>>, parent: &Rc<RefCell<Node>>, name: &[u8]) {
    node.borrow_mut().notifications.links.retain(|l| {
        let remove = *l.name.borrow() == name
            && l.parent
                .borrow()
                .upgrade()
                .is_some_and(|n| Rc::ptr_eq(&n, parent));
        if remove {
            l.linked.set(false);
        }
        !remove
    });
}
pub(super) fn move_link(
    node: &Rc<RefCell<Node>>,
    old: &Rc<RefCell<Node>>,
    old_name: &[u8],
    new: &Rc<RefCell<Node>>,
    name: &[u8],
) {
    for l in &node.borrow().notifications.links {
        if *l.name.borrow() == old_name
            && l.parent
                .borrow()
                .upgrade()
                .is_some_and(|p| Rc::ptr_eq(&p, old))
        {
            *l.parent.borrow_mut() = Rc::downgrade(new);
            *l.name.borrow_mut() = name.to_vec();
            return;
        }
    }
}
pub(super) fn notify(node: &Rc<RefCell<Node>>, mask: u32, at: Option<&Rc<Link>>) {
    let mut n = node.borrow_mut();
    let mask = mask
        | if matches!(n.content, Content::Directory) {
            ISDIR
        } else {
            0
        };
    n.notifications.send(mask, 0, b"", false);
    // No allocation, filesystem scan, or global lock on the read/write path.
    let send = |l: &Rc<Link>| {
        if let Some(parent) = l.parent.borrow().upgrade() {
            parent
                .borrow_mut()
                .notifications
                .send(mask, 0, &l.name.borrow(), !l.linked.get());
        }
    };
    if let Some(at) = at {
        send(at);
    } else {
        n.notifications.links.iter().for_each(send);
    }
}
impl Vfs {
    pub fn inotify_init(&mut self, flags: u32) -> Result<u32> {
        if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
            return Err(Errno(22));
        }
        self.anonymous(
            flags,
            events::Anonymous::Inotify(Rc::new(RefCell::new(Instance {
                watches: BTreeMap::new(),
                next: 1,
                queue: VecDeque::new(),
                bytes: 0,
                epoch: 0,
            }))),
        )
    }
    fn inotify_instance(&self, fd: u32) -> Result<Rc<RefCell<Instance>>> {
        let open = self.descriptor(fd)?.open.borrow();
        match &open.anonymous {
            Some(events::Anonymous::Inotify(i)) if open.flags & O_PATH == 0 => Ok(i.clone()),
            _ => Err(Errno(22)),
        }
    }
    pub fn inotify_add(&self, fd: u32, path: &[u8], mask: u32) -> Result<i32> {
        let instance = self.inotify_instance(fd)?;
        if mask & ALL == 0
            || mask
                & !(ALL
                    | 0x01000000
                    | 0x02000000
                    | 0x04000000
                    | 0x10000000
                    | 0x20000000
                    | 0x80000000)
                != 0
            || mask & 0x30000000 == 0x30000000
        {
            return Err(Errno(22));
        }
        let (_, node) = self.metadata_target(AT_FDCWD, path, mask & 0x02000000 == 0)?;
        let mut n = node.borrow_mut();
        if mask & 0x01000000 != 0 && !matches!(n.content, Content::Directory) {
            return Err(Errno(20));
        }
        if !self.allowed(&n, 4) {
            return Err(Errno(13));
        }
        let mut i = instance.borrow_mut();
        if let Some((&wd, watch)) = i
            .watches
            .iter_mut()
            .find(|(_, w)| w.node.upgrade().is_some_and(|v| Rc::ptr_eq(&v, &node)))
        {
            if mask & 0x10000000 != 0 {
                return Err(Errno(17));
            }
            watch.mask = if mask & 0x20000000 != 0 {
                watch.mask | mask
            } else {
                mask
            };
            return Ok(wd);
        }
        if i.watches.len() >= 8192 {
            return Err(Errno(28));
        }
        let wd = i.next;
        i.next = i.next.checked_add(1).ok_or(Errno(28))?;
        i.watches.insert(
            wd,
            Watch {
                node: Rc::downgrade(&node),
                mask,
            },
        );
        n.notifications
            .watchers
            .retain(|(w, _)| w.strong_count() != 0);
        n.notifications
            .watchers
            .push((Rc::downgrade(&instance), wd));
        Ok(wd)
    }
    pub fn inotify_remove(&self, fd: u32, wd: i32) -> Result<()> {
        let instance = self.inotify_instance(fd)?;
        let mut i = instance.borrow_mut();
        let node = i.watches.get(&wd).ok_or(Errno(22))?.node.upgrade();
        i.remove(wd);
        drop(i);
        if let Some(node) = node {
            node.borrow_mut()
                .notifications
                .watchers
                .retain(|(weak, w)| *w != wd || !Weak::ptr_eq(weak, &Rc::downgrade(&instance)));
        }
        Ok(())
    }
    pub fn inotify_available(&self, fd: u32) -> Result<Option<usize>> {
        let open = self.descriptor(fd)?.open.borrow();
        Ok(match &open.anonymous {
            Some(events::Anonymous::Inotify(i)) => Some(i.borrow().available()),
            _ => None,
        })
    }
    pub(super) fn notification_parent(
        &self,
        path: &ResolvedPath,
    ) -> Option<(Rc<RefCell<Node>>, Vec<u8>)> {
        let i = path.iter().rposition(|b| *b == b'/')?;
        if path.key == b"/" {
            return None;
        }
        Some((
            self.node(&ResolvedPath {
                key: path[..i.max(1)].to_vec(),
                mount: path.mount.clone(),
            })
            .ok()?,
            path[i + 1..].to_vec(),
        ))
    }
    pub(super) fn notification_entry(
        &self,
        path: &ResolvedPath,
        mask: u32,
        cookie: u32,
        directory: bool,
    ) {
        if let Some((parent, name)) = self.notification_parent(path) {
            parent.borrow_mut().notifications.send(
                mask | if directory { ISDIR } else { 0 },
                cookie,
                &name,
                false,
            );
        }
    }
    pub(super) fn notification_link(
        &self,
        path: &ResolvedPath,
        node: &Rc<RefCell<Node>>,
        add: bool,
    ) {
        if let Some((parent, name)) = self.notification_parent(path) {
            if add {
                link(node, &parent, &name);
            } else {
                unlink(node, &parent, &name);
            }
        }
    }
    pub(super) fn notification_open(
        &self,
        path: &ResolvedPath,
        node: &Rc<RefCell<Node>>,
        flags: u32,
    ) -> Option<Close> {
        if flags & O_PATH != 0 {
            return None;
        }
        let at = self.notification_parent(path).and_then(|(parent, name)| {
            node.borrow()
                .notifications
                .links
                .iter()
                .find(|l| {
                    *l.name.borrow() == name
                        && l.parent
                            .borrow()
                            .upgrade()
                            .is_some_and(|p| Rc::ptr_eq(&p, &parent))
                })
                .cloned()
        });
        notify(node, OPEN, at.as_ref());
        Some(Close {
            node: Rc::downgrade(node),
            link: at,
            writable: flags & 3 != 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn masks(bytes: &[u8]) -> Vec<u32> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            out.push(u32::from_le_bytes(
                bytes[at + 4..at + 8].try_into().unwrap(),
            ));
            at += 16 + u32::from_le_bytes(bytes[at + 12..at + 16].try_into().unwrap()) as usize;
        }
        out
    }
    #[test]
    fn unlinked_open_description_and_excl_unlink() {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/tmp", 0o777).unwrap();
        let a = v.inotify_init(O_NONBLOCK).unwrap();
        let b = v.inotify_init(O_NONBLOCK).unwrap();
        v.inotify_add(a, b"/tmp", ALL).unwrap();
        v.inotify_add(b, b"/tmp", ALL | 0x04000000).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/tmp/a", 0x42, 0o600).unwrap();
        v.read(a, 4096).unwrap();
        v.read(b, 4096).unwrap();
        v.unlink_at(AT_FDCWD, b"/tmp/a", false).unwrap();
        v.read(a, 4096).unwrap();
        v.read(b, 4096).unwrap();
        v.write(fd, b"x").unwrap();
        v.close(fd).unwrap();
        assert_eq!(masks(&v.read(a, 4096).unwrap()), vec![MODIFY, CLOSE_WRITE]);
        assert_eq!(v.read(b, 4096), Err(Errno(11)));
    }
    #[test]
    fn overflow_coalescing_and_new_edges_after_drain() {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/tmp", 0o777).unwrap();
        let fd = v.inotify_init(O_NONBLOCK).unwrap();
        v.inotify_add(fd, b"/tmp", CREATE).unwrap();
        let instance = v.inotify_instance(fd).unwrap();
        for i in 0..MAX_EVENTS + 100 {
            instance
                .borrow_mut()
                .push(1, CREATE, 0, i.to_string().as_bytes());
        }
        let ep = v.epoll_create(0).unwrap();
        v.epoll_ctl(ep, 1, fd, 0x80000001, 77).unwrap();
        assert_eq!(v.epoll_wait(ep, 1, |_, _| Ok(None)).unwrap(), vec![(1, 77)]);
        assert_eq!(v.epoll_wait(ep, 1, |_, _| Ok(None)).unwrap(), vec![]);
        let events = v.read(fd, 1024 * 1024).unwrap();
        let masks = masks(&events);
        assert_eq!(masks.len(), MAX_EVENTS + 1);
        assert_eq!(masks[MAX_EVENTS], 0x4000);
        assert_eq!(
            i32::from_le_bytes(
                events[events.len() - 16..events.len() - 12]
                    .try_into()
                    .unwrap()
            ),
            -1
        );
        assert_eq!(v.poll(fd, 1), 0);
        instance.borrow_mut().push(1, CREATE, 0, b"after-overflow");
        assert_eq!(v.epoll_wait(ep, 1, |_, _| Ok(None)).unwrap(), vec![(1, 77)]);
    }
    #[test]
    fn denied_operations_do_not_emit_events_and_path_watch_lifetime() {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/tmp", 0o777).unwrap();
        let fd = v.inotify_init(O_CLOEXEC | O_NONBLOCK).unwrap();
        let wd = v.inotify_add(fd, b"/tmp", CREATE).unwrap();
        assert_eq!(v.mkdir_at(AT_FDCWD, b"/tmp", 0o755), Err(Errno(17)));
        assert_eq!(v.read(fd, 4096), Err(Errno(11)));
        let alias = v.dup(fd, 0, false).unwrap();
        let mut fork = v.clone();
        fork.close_exec();
        assert_eq!(fork.fd_kind(fd), Err(Errno(9)));
        fork.mkdir_at(AT_FDCWD, b"/tmp/d", 0o700).unwrap();
        assert_eq!(masks(&v.read(alias, 4096).unwrap()), vec![CREATE | ISDIR]);
        v.inotify_remove(fd, wd).unwrap();
        assert_eq!(masks(&fork.read(alias, 4096).unwrap()), vec![IGNORED]);
    }
}
