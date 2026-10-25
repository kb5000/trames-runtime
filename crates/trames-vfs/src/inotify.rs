// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest inode watches: owner path registration, shared queues and event admission.
use super::*;
mod queue;
pub(crate) use queue::Queue;

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
    // Allocate shared event identity only when watched, opened or used as a
    // link's parent; untouched inode metadata keeps its allocation-free default.
    source: std::sync::OnceLock<Arc<Source>>,
    links: Vec<Arc<Link>>,
}
#[derive(Default)]
struct Source {
    watchers: std::sync::Mutex<Vec<(std::sync::Weak<Queue>, i32)>>,
    deleted: std::sync::atomic::AtomicBool,
}
impl Source {
    fn snapshot(&self) -> Vec<(std::sync::Weak<Queue>, i32)> {
        self.watchers.lock().unwrap().clone()
    }
    fn send(&self, mask: u32, cookie: u32, name: &[u8], unlinked: bool) {
        // Queue callbacks may re-enter this inode's notification state. Never
        // notify while holding its registration lock (or a link-state lock).
        for (weak, wd) in self.snapshot() {
            if let Some(queue) = weak.upgrade() {
                queue.send(wd, mask, cookie, name, unlinked);
            }
        }
    }
    fn destroy(&self, deleted: bool) {
        let watchers = std::mem::take(&mut *self.watchers.lock().unwrap());
        Self::destroy_watches(watchers, deleted);
    }
    fn destroy_watches(watchers: Vec<(std::sync::Weak<Queue>, i32)>, deleted: bool) {
        for (weak, wd) in watchers {
            if let Some(queue) = weak.upgrade() {
                if deleted {
                    queue.send(wd, DELETE_SELF, 0, b"", false);
                }
                queue.remove(wd);
            }
        }
    }
    fn add(&self, queue: &Arc<Queue>, wd: i32) {
        let mut watchers = self.watchers.lock().unwrap();
        watchers.retain(|(weak, wd)| weak.upgrade().is_some_and(|q| q.contains(*wd)));
        watchers.push((Arc::downgrade(queue), wd));
    }
    fn remove(&self, queue: &Arc<Queue>, wd: i32) {
        self.watchers
            .lock()
            .unwrap()
            .retain(|(weak, w)| *w != wd || !std::sync::Weak::ptr_eq(weak, &Arc::downgrade(queue)));
    }
}
impl Drop for Source {
    fn drop(&mut self) {
        Self::destroy_watches(
            std::mem::take(self.watchers.get_mut().unwrap()),
            self.deleted.load(Ordering::Relaxed),
        );
    }
}
pub(super) struct Link(std::sync::Mutex<LinkState>);
#[derive(Clone)]
struct LinkState {
    parent: std::sync::Weak<Source>,
    name: Arc<[u8]>,
    linked: bool,
}
impl Link {
    fn matches(&self, parent: &Arc<Source>, name: &[u8]) -> bool {
        let state = self.0.lock().unwrap();
        state.name.as_ref() == name
            && std::sync::Weak::ptr_eq(&state.parent, &Arc::downgrade(parent))
    }
    fn snapshot(&self) -> LinkState {
        self.0.lock().unwrap().clone()
    }
    fn send(&self, mask: u32) {
        let state = self.snapshot();
        if let Some(parent) = state.parent.upgrade() {
            parent.send(mask, 0, &state.name, !state.linked);
        }
    }
}
/// Frozen path/link selection for a file epoch. Registration generations and
/// one-shot admission remain live in each shared queue. This hot byte path
/// retains only weak queue capabilities, not inode or OFD lifetime references.
#[derive(Clone, Default)]
pub(crate) struct Notifications(Vec<Notification>);
#[derive(Clone)]
struct Notification {
    queue: std::sync::Weak<Queue>,
    wd: i32,
    name: Vec<u8>,
    unlinked: bool,
}
impl Notifications {
    pub(crate) fn send(&self, mask: u32) {
        for n in &self.0 {
            if let Some(queue) = n.queue.upgrade() {
                queue.send(n.wd, mask, 0, &n.name, n.unlinked);
            }
        }
    }
}
pub(super) fn capture_node(n: &Node, at: Option<&Arc<Link>>) -> Notifications {
    let mut out = Notifications::default();
    let mut add = |source: &Source, name: &[u8], unlinked| {
        for (weak, wd) in source.snapshot() {
            if weak.upgrade().is_some_and(|queue| queue.contains(wd)) {
                out.0.push(Notification {
                    queue: weak,
                    wd,
                    name: name.to_vec(),
                    unlinked,
                });
            }
        }
    };
    if let Some(source) = n.notifications.source.get() {
        add(source, b"", false);
    }
    let mut parent = |link: &Arc<Link>| {
        let state = link.snapshot();
        if let Some(p) = state.parent.upgrade() {
            add(&p, &state.name, !state.linked);
        }
    };
    if let Some(at) = at {
        parent(at);
    } else {
        n.notifications.links.iter().for_each(parent);
    }
    out
}
/// Real OFD close-notification lease. Weak byte/poll capabilities never retain
/// it. The final Arc may be released on a worker without any inode/path Rc.
pub struct FileClose {
    source: Arc<Source>,
    pub(super) link: Option<Arc<Link>>,
    mask: u32,
}
impl FileClose {
    fn new(node: &Node, flags: u32, link: Option<Arc<Link>>) -> Arc<Self> {
        Arc::new(Self {
            source: node.notifications.source().clone(),
            link,
            mask: (if flags & 3 != 0 {
                CLOSE_WRITE
            } else {
                CLOSE_NOWRITE
            }) | if matches!(node.content, Content::Directory) {
                ISDIR
            } else {
                0
            },
        })
    }
    pub(super) fn reopen(
        node: &NodeRef,
        flags: u32,
        original: Option<&Arc<FileClose>>,
    ) -> Option<Arc<Self>> {
        if flags & O_PATH != 0 {
            return None;
        }
        let link = original.and_then(|c| c.link.clone());
        notify(node, OPEN, link.as_ref());
        Some(Self::new(&node.borrow(), flags, link))
    }
}
impl Drop for FileClose {
    fn drop(&mut self) {
        self.source.send(self.mask, 0, b"", false);
        if let Some(link) = &self.link {
            link.send(self.mask);
        }
        // Dropping source after IN_CLOSE can produce deferred DELETE_SELF and
        // IGNORED. An inode metadata anchor need not live on this worker.
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        if let Some(source) = self.notifications.source.get() {
            // Only the terminal deletion bit: no guest memory publication.
            source.deleted.store(self.links == 0, Ordering::Relaxed);
        }
    }
}
impl Marks {
    fn source(&self) -> &Arc<Source> {
        self.source.get_or_init(Arc::default)
    }
    pub(super) fn send(&self, mask: u32, cookie: u32, name: &[u8], unlinked: bool) {
        if let Some(source) = self.source.get() {
            source.send(mask, cookie, name, unlinked);
        }
    }
    pub(super) fn destroy(&self, deleted: bool) {
        // Removed directories notify immediately even if an open descriptor
        // still names them; ordinary files defer to their last actual lease.
        if let Some(source) = self.source.get() {
            source.destroy(deleted);
        }
    }
}
#[derive(Default)]
struct Registrations {
    watches: BTreeMap<i32, std::sync::Weak<Source>>,
    next: i32,
}
/// Actual notification instance lifetime. Its index contains only weak shared
/// inode identities, so accepted operations may retain/release it on workers.
/// Byte/poll snapshots deliberately retain only the queue, never this lease.
pub struct InotifyInstance {
    registrations: std::sync::Mutex<Registrations>,
    pub(crate) queue: Arc<Queue>,
}
impl Default for InotifyInstance {
    fn default() -> Self {
        Self {
            registrations: std::sync::Mutex::new(Registrations {
                watches: BTreeMap::new(),
                next: 1,
            }),
            queue: Arc::default(),
        }
    }
}
impl InotifyInstance {
    fn add(&self, source: &Arc<Source>, mask: u32) -> Result<i32> {
        let mut i = self.registrations.lock().unwrap();
        for (&wd, weak) in &i.watches {
            if std::sync::Weak::ptr_eq(weak, &Arc::downgrade(source))
                && self.queue.update_watch(wd, mask)?
            {
                return Ok(wd);
            }
        }
        if i.watches.len() >= 8192 {
            i.watches.retain(|wd, _| self.queue.contains(*wd));
            if i.watches.len() >= 8192 {
                return Err(Errno(28));
            }
        }
        let wd = i.next;
        i.next = i.next.checked_add(1).ok_or(Errno(28))?;
        i.watches.insert(wd, Arc::downgrade(source));
        self.queue.set_watch(wd, mask)?;
        source.add(&self.queue, wd);
        Ok(wd)
    }
    fn remove(&self, wd: i32) -> Result<()> {
        // remove publishes IGNORED and wakes outside both queue and index
        // locks. A callback can therefore register a replacement immediately.
        if !self.queue.remove(wd) {
            return Err(Errno(22));
        }
        let source = self
            .registrations
            .lock()
            .unwrap()
            .watches
            .remove(&wd)
            .and_then(|w| w.upgrade());
        if let Some(source) = source {
            source.remove(&self.queue, wd);
        }
        Ok(())
    }
}
/// Frozen byte authority plus a weak route to the actual registration owner.
/// Keeping this capability alive never keeps watches registered after close.
#[derive(Clone)]
pub(crate) struct Capability {
    pub(crate) queue: Arc<Queue>,
    instance: std::sync::Weak<InotifyInstance>,
}
impl std::ops::Deref for Capability {
    type Target = Queue;
    fn deref(&self) -> &Queue {
        &self.queue
    }
}
impl Capability {
    pub(crate) fn remove_watch(&self, wd: i32) -> Result<()> {
        self.instance.upgrade().ok_or(Errno(9))?.remove(wd)
    }
}
impl InotifyInstance {
    pub(crate) fn capability(self: &Arc<Self>) -> Capability {
        Capability {
            queue: self.queue.clone(),
            instance: Arc::downgrade(self),
        }
    }
}
impl Drop for InotifyInstance {
    fn drop(&mut self) {
        self.queue.close();
    }
}

pub(super) fn link(node: &NodeRef, parent: &NodeRef, name: &[u8]) {
    let parent = parent.borrow().notifications.source().clone();
    let mut n = node.borrow_mut();
    n.notifications
        .links
        .retain(|l| l.0.lock().unwrap().parent.strong_count() != 0);
    if n.notifications
        .links
        .iter()
        .any(|l| l.matches(&parent, name))
    {
        return;
    }
    n.notifications
        .links
        .push(Arc::new(Link(std::sync::Mutex::new(LinkState {
            parent: Arc::downgrade(&parent),
            name: name.into(),
            linked: true,
        }))));
}
pub(super) fn unlink(node: &NodeRef, parent: &NodeRef, name: &[u8]) {
    let parent = parent.borrow().notifications.source().clone();
    node.borrow_mut().notifications.links.retain(|l| {
        let mut state = l.0.lock().unwrap();
        let remove = state.name.as_ref() == name
            && std::sync::Weak::ptr_eq(&state.parent, &Arc::downgrade(&parent));
        if remove {
            state.linked = false;
        }
        !remove
    });
}
pub(super) fn move_link(
    node: &NodeRef,
    old: &NodeRef,
    old_name: &[u8],
    new: &NodeRef,
    name: &[u8],
) {
    let old = old.borrow().notifications.source().clone();
    let new = new.borrow().notifications.source().clone();
    for l in &node.borrow().notifications.links {
        let mut state = l.0.lock().unwrap();
        if state.name.as_ref() == old_name
            && std::sync::Weak::ptr_eq(&state.parent, &Arc::downgrade(&old))
        {
            state.parent = Arc::downgrade(&new);
            state.name = name.into();
            return;
        }
    }
}
pub(super) fn notify(node: &NodeRef, mask: u32, at: Option<&Arc<Link>>) {
    let n = node.borrow();
    let mask = mask
        | if matches!(n.content, Content::Directory) {
            ISDIR
        } else {
            0
        };
    n.notifications.send(mask, 0, b"", false);
    if let Some(at) = at {
        at.send(mask);
    } else {
        n.notifications
            .links
            .iter()
            .for_each(|link| link.send(mask));
    }
}

impl Vfs {
    pub fn inotify_init(&mut self, flags: u32) -> Result<u32> {
        if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
            return Err(Errno(22));
        }
        self.anonymous(flags, events::Anonymous::Inotify(Arc::default()))
    }
    fn inotify_instance(&self, fd: u32) -> Result<Arc<InotifyInstance>> {
        let open_descriptor = self.descriptor(fd)?;
        let open = open_descriptor.open.borrow();
        match &open.anonymous {
            Some(events::Anonymous::Inotify(i)) if open.flags.get() & O_PATH == 0 => Ok(i.clone()),
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
        let n = node.borrow();
        if mask & 0x01000000 != 0 && !matches!(n.content, Content::Directory) {
            return Err(Errno(20));
        }
        if !self.allowed(&n, 4) {
            return Err(Errno(13));
        }
        let source = n.notifications.source().clone();
        drop(n);
        instance.add(&source, mask)
    }
    pub fn inotify_remove(&self, fd: u32, wd: i32) -> Result<()> {
        self.inotify_instance(fd)?.remove(wd)
    }
    pub fn inotify_available(&self, fd: u32) -> Result<Option<usize>> {
        let open_descriptor = self.descriptor(fd)?;
        let open = open_descriptor.open.borrow();
        Ok(match &open.anonymous {
            Some(events::Anonymous::Inotify(i)) => Some(i.queue.available()),
            _ => None,
        })
    }
    pub(super) fn notification_parent(&self, path: &ResolvedPath) -> Option<(NodeRef, Vec<u8>)> {
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
    pub(super) fn notification_link(&self, path: &ResolvedPath, node: &NodeRef, add: bool) {
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
        node: &NodeRef,
        flags: u32,
    ) -> Option<Arc<FileClose>> {
        if flags & O_PATH != 0 {
            return None;
        }
        let at = self.notification_parent(path).and_then(|(parent, name)| {
            let parent = parent.borrow().notifications.source().clone();
            node.borrow()
                .notifications
                .links
                .iter()
                .find(|l| l.matches(&parent, &name))
                .cloned()
        });
        notify(node, OPEN, at.as_ref());
        Some(FileClose::new(&node.borrow(), flags, at))
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
    fn shared_instance_last_worker_lease_clears_watches_without_retaining_inodes() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<InotifyInstance>();
        let mut v = Vfs::default();
        let fd = v.inotify_init(O_NONBLOCK).unwrap();
        v.inotify_add(fd, b"/", CREATE).unwrap();
        let lease = v.retain_uring_fd(fd).unwrap().inotify_instance().unwrap();
        let caps = v.direct_descriptors();
        let cap = caps.get(fd).unwrap();
        let alias = v.dup(fd, 0, false).unwrap();
        let mut child = v.clone();
        v.close(fd).unwrap();
        v.close(alias).unwrap();
        child.close_all();
        v.mkdir_at(AT_FDCWD, b"/before-last", 0o755).unwrap();
        assert_eq!(masks(&cap.read(4096).unwrap()), vec![CREATE | ISDIR]);
        std::thread::spawn(move || drop(lease)).join().unwrap();
        v.mkdir_at(AT_FDCWD, b"/after-last", 0o755).unwrap();
        assert_eq!(cap.read(4096), Err(Errno(11)));
        assert_eq!(cap.inotify_remove(1), Err(Errno(9)));
    }

    #[test]
    fn shared_registration_serializes_same_inode_adds_and_never_revives_ignored_wd() {
        let source = Arc::new(Source::default());
        let instance = Arc::new(InotifyInstance::default());
        let gate = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for i in 0..8 {
                let source = &source;
                let instance = &instance;
                let gate = &gate;
                scope.spawn(move || {
                    gate.wait();
                    assert_eq!(
                        instance.add(
                            source,
                            if i % 2 == 0 {
                                ACCESS | 0x20000000
                            } else {
                                MODIFY | 0x20000000
                            }
                        ),
                        Ok(1)
                    );
                });
            }
        });
        assert_eq!(instance.registrations.lock().unwrap().watches.len(), 1);
        source.send(ACCESS, 0, b"", false);
        source.send(MODIFY, 0, b"", false);
        assert_eq!(
            masks(&instance.queue.read(4096).unwrap()),
            vec![ACCESS, MODIFY]
        );
        assert_eq!(instance.add(&source, MODIFY | 0x80000000), Ok(1));
        source.send(MODIFY, 0, b"", false);
        assert_eq!(
            masks(&instance.queue.read(4096).unwrap()),
            vec![MODIFY, IGNORED]
        );
        assert_eq!(instance.queue.update_watch(1, MODIFY), Ok(false));
        assert!(!instance.queue.contains(1));
        assert_eq!(instance.add(&source, MODIFY), Ok(2));
        assert_eq!(instance.add(&source, MODIFY | 0x10000000), Err(Errno(17)));
    }

    #[test]
    fn worker_remove_releases_index_before_return_and_notify_can_register_replacement() {
        use std::sync::atomic::AtomicI32;
        struct Wake {
            instance: Arc<InotifyInstance>,
            source: Arc<Source>,
            replacement: AtomicI32,
        }
        impl IoWake for Wake {
            fn wake_io(&self, _: &Arc<IoSignal>) {
                assert_eq!(
                    masks(&self.instance.queue.read(4096).unwrap()),
                    vec![IGNORED]
                );
                let wd = self.instance.add(&self.source, MODIFY).unwrap();
                self.replacement.store(wd, Ordering::Relaxed);
            }
        }
        let instance = Arc::new(InotifyInstance::default());
        let source = Arc::new(Source::default());
        assert_eq!(instance.add(&source, MODIFY), Ok(1));
        let wake = Arc::new(Wake {
            instance: instance.clone(),
            source: source.clone(),
            replacement: AtomicI32::new(0),
        });
        let target: Arc<dyn IoWake> = wake.clone();
        let signal = IoSignal::new(1, Arc::downgrade(&target));
        let _subscription = instance.queue.readiness.subscribe(&signal);
        let cap = instance.capability();
        std::thread::spawn(move || assert_eq!(cap.remove_watch(1), Ok(())))
            .join()
            .unwrap();
        assert_eq!(wake.replacement.load(Ordering::Relaxed), 2);
        let index = instance.registrations.lock().unwrap();
        assert_eq!(index.watches.len(), 1);
        assert!(index.watches.contains_key(&2));
        drop(index);
        source.send(MODIFY, 0, b"", false);
        assert_eq!(masks(&instance.queue.read(4096).unwrap()), vec![MODIFY]);
    }

    #[test]
    fn shared_close_uses_live_watch_registration_and_renamed_link() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<FileClose>();
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/a", 0o755).unwrap();
        v.mkdir_at(AT_FDCWD, b"/b", 0o755).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/a/old", 0x42, 0o600).unwrap();
        let lease = v.retain_uring_fd(fd).unwrap().close_notification().unwrap();
        // Registered after the file opened: a frozen open-time watcher list
        // would lose these events. Rename changes the actual shared link.
        let notify = v.inotify_init(O_NONBLOCK).unwrap();
        let inode = v.inotify_add(notify, b"/a/old", CLOSE_WRITE).unwrap();
        v.rename_at(AT_FDCWD, b"/a/old", AT_FDCWD, b"/b/new", 0)
            .unwrap();
        let parent = v.inotify_add(notify, b"/b", CLOSE_WRITE).unwrap();
        v.close(fd).unwrap();
        assert_eq!(v.read(notify, 4096), Err(Errno(11)));
        let alias = lease.clone();
        drop(lease);
        std::thread::spawn(move || drop(alias)).join().unwrap();
        let events = v.read(notify, 4096).unwrap();
        assert_eq!(masks(&events), vec![CLOSE_WRITE, CLOSE_WRITE]);
        assert_eq!(i32::from_le_bytes(events[..4].try_into().unwrap()), inode);
        assert_eq!(
            i32::from_le_bytes(events[16..20].try_into().unwrap()),
            parent
        );
        assert_eq!(&events[32..36], b"new\0");
    }

    #[test]
    fn retained_close_defers_inode_deletion_but_not_directory_removal() {
        let mut v = Vfs::default();
        let fd = v.open_at(AT_FDCWD, b"/gone", 0x42, 0o600).unwrap();
        let notify = v.inotify_init(O_NONBLOCK).unwrap();
        v.inotify_add(notify, b"/gone", CLOSE_WRITE | DELETE_SELF)
            .unwrap();
        let close = v.retain_uring_fd(fd).unwrap().close_notification().unwrap();
        let mut epoch = FileEpoch::default();
        let _caps = epoch.capture(&v, true);
        v.unlink_at(AT_FDCWD, b"/gone", false).unwrap();
        v.close(fd).unwrap();
        assert_eq!(v.read(notify, 4096), Err(Errno(11)));
        std::thread::spawn(move || drop(close)).join().unwrap();
        assert_eq!(
            masks(&v.read(notify, 4096).unwrap()),
            vec![CLOSE_WRITE, DELETE_SELF, IGNORED]
        );
        epoch.finish();
        v.mkdir_at(AT_FDCWD, b"/dir", 0o755).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/dir", O_DIRECTORY, 0).unwrap();
        v.inotify_add(notify, b"/dir", CLOSE_NOWRITE | DELETE_SELF)
            .unwrap();
        let close = v.retain_uring_fd(fd).unwrap().close_notification().unwrap();
        v.unlink_at(AT_FDCWD, b"/dir", true).unwrap();
        assert_eq!(
            masks(&v.read(notify, 4096).unwrap()),
            vec![DELETE_SELF, IGNORED]
        );
        v.close(fd).unwrap();
        std::thread::spawn(move || drop(close)).join().unwrap();
        assert_eq!(v.read(notify, 4096), Err(Errno(11)));
    }

    #[test]
    fn shared_close_respects_unlink_and_does_not_retain_closed_watch_instances() {
        let mut v = Vfs::default();
        let fd = v.open_at(AT_FDCWD, b"/gone", 0x42, 0o600).unwrap();
        let notify = v.inotify_init(O_NONBLOCK).unwrap();
        let excluded = v.inotify_init(O_NONBLOCK).unwrap();
        v.inotify_add(notify, b"/", CLOSE_WRITE).unwrap();
        v.inotify_add(excluded, b"/", CLOSE_WRITE | 0x04000000)
            .unwrap();
        let caps = v.direct_descriptors();
        let close = v.retain_uring_fd(fd).unwrap().close_notification().unwrap();
        v.unlink_at(AT_FDCWD, b"/gone", false).unwrap();
        v.close(fd).unwrap();
        std::thread::spawn(move || drop(close)).join().unwrap();
        assert_eq!(masks(&v.read(notify, 4096).unwrap()), vec![CLOSE_WRITE]);
        assert_eq!(v.read(excluded, 4096), Err(Errno(11)));
        let fd = v.open_at(AT_FDCWD, b"/other", 0x42, 0o600).unwrap();
        let close = v.retain_uring_fd(fd).unwrap().close_notification().unwrap();
        v.close(notify).unwrap();
        v.close(excluded).unwrap();
        v.close(fd).unwrap();
        std::thread::spawn(move || drop(close)).join().unwrap();
        assert_eq!(caps.get(notify).unwrap().read(4096), Err(Errno(11)));
    }

    #[test]
    fn shared_close_callbacks_reenter_registration_and_link_state_without_locks() {
        use std::sync::atomic::AtomicUsize;
        struct Wake {
            source: std::sync::Weak<Source>,
            link: std::sync::Weak<Link>,
            queue: Arc<Queue>,
            calls: AtomicUsize,
        }
        impl IoWake for Wake {
            fn wake_io(&self, _: &Arc<IoSignal>) {
                assert_eq!(masks(&self.queue.read(4096).unwrap()), vec![CLOSE_WRITE]);
                let source = self.source.upgrade().unwrap();
                assert_eq!(source.snapshot().len(), 1);
                self.link.upgrade().unwrap().snapshot();
                self.calls.fetch_add(1, Ordering::Relaxed);
            }
        }
        let mut v = Vfs::default();
        let fd = v.open_at(AT_FDCWD, b"/close", 0x42, 0o600).unwrap();
        let notify = v.inotify_init(O_NONBLOCK).unwrap();
        v.inotify_add(notify, b"/close", CLOSE_WRITE).unwrap();
        let close = v.retain_uring_fd(fd).unwrap().close_notification().unwrap();
        let queue = v.inotify_instance(notify).unwrap().queue.clone();
        let wake = Arc::new(Wake {
            source: Arc::downgrade(&close.source),
            link: Arc::downgrade(close.link.as_ref().unwrap()),
            queue: queue.clone(),
            calls: AtomicUsize::new(0),
        });
        let target: Arc<dyn IoWake> = wake.clone();
        let signal = IoSignal::new(1, Arc::downgrade(&target));
        let _subscription = queue.readiness.subscribe(&signal);
        v.close(fd).unwrap();
        std::thread::spawn(move || drop(close)).join().unwrap();
        assert_eq!(wake.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn concurrent_rename_and_shared_close_never_mix_parent_and_filename() {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/a", 0o755).unwrap();
        v.mkdir_at(AT_FDCWD, b"/b", 0o755).unwrap();
        let notify = v.inotify_init(O_NONBLOCK).unwrap();
        let a = v.inotify_add(notify, b"/a", CLOSE_WRITE).unwrap();
        let b = v.inotify_add(notify, b"/b", CLOSE_WRITE).unwrap();
        for _ in 0..32 {
            let fd = v.open_at(AT_FDCWD, b"/a/old", 0x42, 0o600).unwrap();
            let close = v.retain_uring_fd(fd).unwrap().close_notification().unwrap();
            v.close(fd).unwrap();
            let start = Arc::new(std::sync::Barrier::new(2));
            let worker = start.clone();
            let thread = std::thread::spawn(move || {
                worker.wait();
                drop(close);
            });
            start.wait();
            v.rename_at(AT_FDCWD, b"/a/old", AT_FDCWD, b"/b/new", 0)
                .unwrap();
            thread.join().unwrap();
            let event = v.read(notify, 4096).unwrap();
            assert_eq!(event.len(), 32);
            let wd = i32::from_le_bytes(event[..4].try_into().unwrap());
            assert!(
                (wd == a && &event[16..20] == b"old\0") || (wd == b && &event[16..20] == b"new\0")
            );
            v.unlink_at(AT_FDCWD, b"/b/new", false).unwrap();
        }
    }

    #[test]
    fn worker_oneshot_is_atomic_and_notifies_after_unlock() {
        use std::sync::atomic::AtomicUsize;
        struct Wake {
            queue: Arc<Queue>,
            calls: AtomicUsize,
        }
        impl IoWake for Wake {
            fn wake_io(&self, _: &Arc<IoSignal>) {
                // Reentrant reads must see the complete event + IGNORED pair
                // and must not deadlock on a producer's queue mutex.
                assert_eq!(
                    masks(&self.queue.read(4096).unwrap()),
                    vec![MODIFY, IGNORED]
                );
                self.calls.fetch_add(1, Ordering::Relaxed);
            }
        }
        let queue = Arc::new(Queue::default());
        queue.set_watch(1, MODIFY | 0x80000000).unwrap();
        let target = Arc::new(Wake {
            queue: queue.clone(),
            calls: AtomicUsize::new(0),
        });
        let erased: Arc<dyn IoWake> = target.clone();
        let signal = IoSignal::new(7, Arc::downgrade(&erased));
        let _subscription = queue.readiness.subscribe(&signal);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let queue = &queue;
                scope.spawn(move || {
                    queue.send(1, MODIFY, 0, b"", false);
                });
            }
        });
        assert_eq!(target.calls.load(Ordering::Relaxed), 1);
        assert!(!queue.contains(1));
        assert!(!queue.remove(1));
        assert_eq!(queue.read(4096), Err(Errno(11)));
    }
    #[test]
    fn concurrent_queue_producers_preserve_complete_events_and_byte_count() {
        let queue = Arc::new(Queue::default());
        queue.set_watch(1, MODIFY).unwrap();
        std::thread::scope(|scope| {
            for id in 0..8 {
                let queue = &queue;
                scope.spawn(move || {
                    for n in 0..64 {
                        queue.send(1, MODIFY, id * 64 + n + 1, b"a", false);
                    }
                });
            }
        });
        assert_eq!(queue.available(), 8 * 64 * 32);
        assert_eq!(queue.read(31), Err(Errno(22)));
        let bytes = queue.read(1 << 20).unwrap();
        let mut cookies: Vec<_> = bytes
            .chunks_exact(32)
            .map(|event| {
                assert_eq!(&event[..4], &1i32.to_le_bytes());
                assert_eq!(&event[4..8], &MODIFY.to_le_bytes());
                assert_eq!(&event[12..16], &16u32.to_le_bytes());
                assert_eq!(&event[16..18], b"a\0");
                u32::from_le_bytes(event[8..12].try_into().unwrap())
            })
            .collect();
        cookies.sort_unstable();
        assert_eq!(cookies, (1..=512).collect::<Vec<_>>());
        assert_eq!(queue.available(), 0);
        assert_eq!(queue.poll(1).0, 0);
    }
    #[test]
    fn worker_queue_read_and_owner_epoll_share_edges_and_oneshot_state() {
        let mut v = Vfs::default();
        let fd = v.inotify_init(O_NONBLOCK).unwrap();
        v.inotify_add(fd, b"/", CREATE).unwrap();
        let epoll = v.epoll_create(0).unwrap();
        v.epoll_ctl(epoll, 1, fd, 0xc0000001, 42).unwrap();
        let direct = v.direct_descriptors();
        v.mkdir_at(AT_FDCWD, b"/a", 0o700).unwrap();
        assert_eq!(direct.get(fd).unwrap().readable_bytes(), 32);
        assert_eq!(
            direct.get(epoll).unwrap().epoll_wait(1).unwrap(),
            vec![(1, 42)]
        );
        assert!(v.epoll_wait(epoll, 1, |_, _| Ok(None)).unwrap().is_empty());
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let fd = direct.get(fd).unwrap();
                    assert_eq!(fd.read(31), Err(Errno(22)));
                    assert_eq!(masks(&fd.read(32).unwrap()), vec![CREATE | ISDIR]);
                    assert_eq!(fd.read(32), Err(Errno(11)));
                })
                .join()
                .unwrap();
        });
        v.epoll_ctl(epoll, 3, fd, 0x80000001, 43).unwrap();
        let direct = v.direct_descriptors();
        v.mkdir_at(AT_FDCWD, b"/b", 0o700).unwrap();
        assert_eq!(
            direct.get(epoll).unwrap().epoll_wait(1).unwrap(),
            vec![(1, 43)]
        );
        assert!(v.epoll_wait(epoll, 1, |_, _| Ok(None)).unwrap().is_empty());
    }
    #[test]
    fn consumed_watch_generation_and_closed_instance_are_not_retained_by_capabilities() {
        let mut v = Vfs::default();
        v.import_file(b"/data", vec![0; 8]).unwrap();
        let data = v.open_at(AT_FDCWD, b"/data", 2, 0).unwrap();
        let fd = v.inotify_init(O_NONBLOCK).unwrap();
        let old = v.inotify_add(fd, b"/data", MODIFY | 0x80000000).unwrap();
        let mut epoch = FileEpoch::default();
        let files = epoch.capture(&v, true);
        let mut cache = DiskReadCache::default();
        assert_eq!(
            files.get(data).unwrap().write(b"a", Some(0), &mut cache),
            Some(Ok(1))
        );
        assert_eq!(masks(&v.read(fd, 1024).unwrap()), vec![MODIFY, IGNORED]);
        assert_eq!(v.inotify_remove(fd, old), Err(Errno(22)));
        let new = v.inotify_add(fd, b"/data", MODIFY).unwrap();
        assert_ne!(old, new);
        // A stale capability cannot accidentally notify a replacement watch.
        assert_eq!(
            files.get(data).unwrap().write(b"b", Some(0), &mut cache),
            Some(Ok(1))
        );
        assert_eq!(v.read(fd, 1024), Err(Errno(11)));
        epoch.finish();
        let mut epoch = FileEpoch::default();
        let files = epoch.capture(&v, true);
        let bytes = v.direct_descriptors();
        v.close(fd).unwrap();
        assert_eq!(
            files.get(data).unwrap().write(b"c", Some(0), &mut cache),
            Some(Ok(1))
        );
        assert_eq!(bytes.get(fd).unwrap().read(1024), Err(Errno(11)));
        epoch.finish();
    }
    #[test]
    fn worker_removed_watches_release_registration_quota_and_node_marks() {
        let mut v = Vfs::default();
        let fd = v.inotify_init(O_NONBLOCK).unwrap();
        let direct = v.direct_descriptors();
        let cap = direct.get(fd).unwrap();
        for generation in 1..=8193 {
            let wd = v.inotify_add(fd, b"/", CREATE).unwrap();
            assert_eq!(wd, generation);
            assert_eq!(cap.inotify_remove(wd), Ok(0));
            assert_eq!(masks(&cap.read(16).unwrap()), vec![IGNORED]);
        }
        let instance = v.inotify_instance(fd).unwrap();
        assert_eq!(instance.registrations.lock().unwrap().watches.len(), 0);
        let source = v.fs.borrow().paths[b"/".as_slice()]
            .borrow()
            .notifications
            .source()
            .clone();
        assert_eq!(source.watchers.lock().unwrap().len(), 0);
        let wd = v.inotify_add(fd, b"/", CREATE).unwrap();
        assert_eq!(wd, 8194);
        v.mkdir_at(AT_FDCWD, b"/active", 0o700).unwrap();
        assert_eq!(masks(&cap.read(32).unwrap()), vec![CREATE | ISDIR]);
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
                .queue
                .send(1, CREATE, 0, i.to_string().as_bytes(), false);
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
        instance.queue.send(1, CREATE, 0, b"after-overflow", false);
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
