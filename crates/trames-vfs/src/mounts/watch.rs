// SPDX-License-Identifier: GPL-3.0-or-later
//! Mount-table events share the existing executor's resource subscriptions.
use super::*;
use crate::readiness::Readiness;

#[derive(Default)]
pub(crate) struct MountEvents {
    generation: AtomicU64,
    pub readiness: Arc<Readiness>,
}
impl MountEvents {
    pub fn changed(&self) {
        self.generation.fetch_add(1, Ordering::Relaxed);
        self.readiness.notify_locked();
    }
}
pub(crate) struct MountWatch {
    events: Arc<MountEvents>,
    observed: AtomicU64,
}
impl MountWatch {
    pub fn poll(&self, events: u16) -> (u16, [u64; 2]) {
        let ready = self.peek(events);
        if events != 0 {
            self.acknowledge(ready.1[0]);
        }
        ready
    }
    pub fn peek(&self, events: u16) -> (u16, [u64; 2]) {
        let generation = self.events.generation.load(Ordering::Relaxed);
        let changed = self.observed.load(Ordering::Relaxed) != generation;
        (
            (events & 0x41) | if changed { 8 | (events & 2) } else { 0 },
            [generation, 0],
        )
    }
    pub fn acknowledge(&self, generation: u64) {
        self.observed.store(generation, Ordering::Relaxed);
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.events.readiness.subscribe(signal)
    }
}
pub(crate) struct MountFile {
    pub watch: Arc<MountWatch>,
    snapshot: NamespaceSnapshot,
    info: bool,
    // Open proc mount files pin their original namespace and process root.
    _namespace: MountNamespace,
    _root: Option<(Rc<Mount>, NodeRef)>,
}
impl MountFile {
    pub fn text(&self) -> Vec<u8> {
        table_text(&self.snapshot, self.info)
    }
    pub fn read(&self, offset: u64, count: usize) -> Vec<u8> {
        let text = self.text();
        let start = offset.min(text.len() as u64) as usize;
        text[start..text.len().min(start.saturating_add(count))].to_vec()
    }
}

impl Vfs {
    pub(crate) fn proc_mount_file(&self, path: &ResolvedPath) -> Option<Rc<MountFile>> {
        if !self.uses_pseudo(path) {
            return None;
        }
        let parts: Vec<_> = path
            .strip_prefix(b"/proc/")?
            .split(|b| *b == b'/')
            .collect();
        let key = *parts.last()?;
        if !matches!(key, b"mounts" | b"mountinfo") {
            return None;
        }
        let pid: u32 = std::str::from_utf8(parts.first()?).ok()?.parse().ok()?;
        let pseudo = self.pseudo.borrow();
        let runtime = self.proc_runtime(path, &pseudo.runtime);
        let snapshot = runtime
            .processes
            .iter()
            .find(|p| p.pid == pid)?
            .namespaces
            .clone();
        let namespace = MountNamespace(snapshot.mount.upgrade()?);
        let root = snapshot
            .root
            .as_ref()
            .and_then(|(m, n)| Some((m.upgrade()?, n.upgrade()?)));
        let events = namespace.0.borrow().events.clone();
        let generation = events.generation.load(Ordering::Relaxed);
        Some(Rc::new(MountFile {
            watch: Arc::new(MountWatch {
                events,
                observed: AtomicU64::new(generation),
            }),
            snapshot,
            info: key == b"mountinfo",
            _namespace: namespace,
            _root: root,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn vfs() -> Vfs {
        let mut vfs = Vfs::default();
        let namespaces = vfs.namespace_snapshot();
        vfs.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    namespaces,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        vfs.mkdir_at(AT_FDCWD, b"/a", 0o755).unwrap();
        vfs.mkdir_at(AT_FDCWD, b"/b", 0o755).unwrap();
        vfs
    }
    #[test]
    fn moved_subtree_keeps_mount_ids_open_files_and_rejects_cycles() {
        let mut v = vfs();
        v.mount(None, b"/a", Some(b"tmpfs"), 0, None).unwrap();
        let file = v.open_at(AT_FDCWD, b"/a/file", 0x42, 0o600).unwrap();
        v.write(file, b"kept").unwrap();
        let stat = v.stat_fd(file).unwrap();
        let id = v.mount_id_at(AT_FDCWD, b"/a", false).unwrap();
        v.mkdir_at(AT_FDCWD, b"/a/sub", 0o755).unwrap();
        v.mount(None, b"/a/sub", Some(b"tmpfs"), 0, None).unwrap();
        let sub = v.mount_id_at(AT_FDCWD, b"/a/sub", false).unwrap();
        v.mount(Some(b"/a"), b"/b", None, 8192, None).unwrap();
        assert_eq!(v.mount_id_at(AT_FDCWD, b"/b", false), Ok(id));
        assert_eq!(v.mount_id_at(AT_FDCWD, b"/b/sub", false), Ok(sub));
        assert_eq!(v.pread(file, 4, 0).unwrap(), b"kept");
        assert_eq!(v.stat_at(AT_FDCWD, b"/b/file").unwrap()[..16], stat[..16]);
        assert_eq!(v.stat_at(AT_FDCWD, b"/a/file"), Err(Errno(2)));
        assert_eq!(
            v.mount(Some(b"/b"), b"/b/sub", None, 8192, None),
            Err(Errno(40))
        );
        assert_eq!(v.mount_id_at(AT_FDCWD, b"/b", false), Ok(id));
    }
    #[test]
    fn mountinfo_notifies_nested_epoll_and_pins_the_open_namespace() {
        let mut v = vfs();
        let fd = v.open_at(AT_FDCWD, b"/proc/self/mountinfo", 0, 0).unwrap();
        assert!(v.descriptor(fd).unwrap().open.borrow().mount_file.is_some());
        let inner = v.epoll_create(0).unwrap();
        let outer = v.epoll_create(0).unwrap();
        v.epoll_ctl(inner, 1, fd, 0x80000001, 11).unwrap();
        v.epoll_ctl(outer, 1, inner, 1, 22).unwrap();
        assert_eq!(v.epoll_ctl(inner, 1, outer, 1, 33), Err(Errno(40)));
        let direct = v.direct_descriptors();
        let nested = direct.get(outer).unwrap();
        assert_eq!(nested.epoll_wait(1).unwrap(), vec![(1, 22)]);
        assert_eq!(
            direct.get(inner).unwrap().epoll_wait(1).unwrap(),
            vec![(1, 11)]
        );
        assert!(nested.epoll_wait(1).unwrap().is_empty());
        v.mount(None, b"/a", Some(b"tmpfs"), 0, None).unwrap();
        assert_eq!(nested.epoll_wait(1).unwrap(), vec![(1, 22)]);
        assert_eq!(
            direct.get(inner).unwrap().epoll_wait(1).unwrap(),
            vec![(9, 11)]
        );
        assert!(nested.epoll_wait(1).unwrap().is_empty());
        let mut child = v.clone();
        child.unshare_mounts().unwrap();
        child.mount(None, b"/b", Some(b"tmpfs"), 0, None).unwrap();
        assert!(nested.epoll_wait(1).unwrap().is_empty());
        let before = v.pread(fd, 65536, 0).unwrap();
        assert_eq!(child.pread(fd, 65536, 0).unwrap(), before);
        assert!(String::from_utf8(before).unwrap().contains(" /a "));
        v.mount(Some(b"/a"), b"/b", None, 8192, None).unwrap();
        assert_eq!(v.poll(fd, 2), 10);
        assert_eq!(v.poll(fd, 2), 0);
        let text = String::from_utf8(child.pread(fd, 65536, 0).unwrap()).unwrap();
        assert!(text.contains(" /b ") && !text.contains(" /a "));
        v.close(fd).unwrap();
        child.close(fd).unwrap();
        v.mount(None, b"/a", Some(b"tmpfs"), 0, None).unwrap();
        assert!(nested.epoll_wait(1).unwrap().is_empty());
    }
    #[test]
    fn noatime_authority_and_worker_reads_use_the_live_status_flag() {
        let mut v = vfs();
        let fd = v
            .open_at(AT_FDCWD, b"/file", 0x42 | O_NOATIME, 0o644)
            .unwrap();
        v.write(fd, b"x").unwrap();
        v.set_times(fd as i32, None, Some([[1, 0], [1, 0]]))
            .unwrap();
        assert_eq!(v.pread(fd, 1, 0).unwrap(), b"x");
        assert_eq!(
            i64::from_le_bytes(v.stat_fd(fd).unwrap()[72..80].try_into().unwrap()),
            1
        );
        let mut epoch = FileEpoch::default();
        let direct = epoch.capture(&v, true).get(fd).unwrap();
        assert_eq!(
            direct
                .read(1, Some(0), &mut DiskReadCache::default())
                .unwrap()
                .unwrap(),
            b"x"
        );
        v.set_status_flags(fd, 2).unwrap();
        direct
            .read(1, Some(0), &mut DiskReadCache::default())
            .unwrap()
            .unwrap();
        assert!(i64::from_le_bytes(v.stat_fd(fd).unwrap()[72..80].try_into().unwrap()) > 1);
        epoch.finish();
        v.credentials = Credentials::user(1000, 1000);
        assert_eq!(v.open_at(AT_FDCWD, b"/file", O_NOATIME, 0), Err(Errno(1)));
        assert_eq!(v.set_status_flags(fd, 2 | O_NOATIME), Err(Errno(1)));
    }
}
