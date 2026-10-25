// SPDX-License-Identifier: GPL-3.0-or-later
//! Separate owner inode projection from the actual shared pipe endpoint.
use super::*;
use std::sync::atomic::AtomicBool;

/// Stable pipe identity shared by inode aliases, including overlay copies.
/// It owns no endpoint and contains no inode/namespace control references.
#[derive(Clone)]
pub(super) struct Pipe {
    pub(super) inode: u64,
    pub(super) data: Arc<PipeResource>,
}
impl Pipe {
    pub(super) fn new(inode: u64) -> Self {
        Self {
            inode,
            data: Arc::new(PipeResource::new()),
        }
    }
}

/// A real endpoint reference, unlike a poll/byte capability. Cloning this Arc
/// does not open another reader/writer. Its final drop closes the original end
/// on the dropping thread and notifies peers after releasing the pipe lock.
/// Inode/namespace and full OFD lifetime are separate; no owner Rc lives here.
pub struct PipeEndpoint {
    pub(super) data: Arc<PipeResource>,
    pub(super) read: bool,
    pub(super) write: bool,
    pub(super) initial_write_epoch: u64,
    wait_epoch: u64,
    waiting: AtomicBool,
}
impl PipeEndpoint {
    fn open(data: Arc<PipeResource>, flags: u32, fifo: bool) -> Result<Arc<Self>> {
        let read = flags & 3 != 1;
        let write = flags & 3 != 0;
        let mut p = data.lock().unwrap();
        // Admission and reader/writer publication form one pipe transaction.
        // Another worker's last close cannot fit between the ENXIO check and
        // installing the newly opened FIFO endpoint.
        if fifo && write && !read && flags & O_NONBLOCK != 0 && p.readers == 0 {
            return Err(Errno(6));
        }
        let initial_write_epoch = p.write_epoch.wrapping_sub(u64::from(p.writers != 0));
        let waiting = if fifo && flags & O_NONBLOCK == 0 {
            if read && !write && p.writers == 0 {
                Some(p.write_epoch)
            } else if write && !read && p.readers == 0 {
                Some(p.read_epoch)
            } else {
                None
            }
        } else {
            None
        };
        if read {
            p.readers += 1;
            p.read_epoch = p.read_epoch.wrapping_add(1);
            p.io_epoch[1] = p.io_epoch[1].wrapping_add(1);
        }
        if write {
            p.writers += 1;
            p.write_epoch = p.write_epoch.wrapping_add(1);
            p.io_epoch[0] = p.io_epoch[0].wrapping_add(1);
        }
        drop(p);
        Ok(Arc::new(Self {
            data,
            read,
            write,
            initial_write_epoch,
            wait_epoch: waiting.unwrap_or(0),
            waiting: AtomicBool::new(waiting.is_some()),
        }))
    }
    pub(super) fn anonymous(data: Arc<PipeResource>, read: bool, write: bool) -> Arc<Self> {
        let access = if read && write {
            2
        } else if write {
            1
        } else {
            0
        };
        Self::open(data, access, false).expect("anonymous pipe end has no FIFO admission")
    }
    pub(super) fn has_waiter(&self) -> bool {
        self.waiting.load(Ordering::Relaxed)
    }
    pub(super) fn open_ready(&self) -> bool {
        if !self.has_waiter() {
            return true;
        }
        let p = self.data.lock().unwrap();
        let ready = if self.read {
            p.writers != 0 || p.write_epoch != self.wait_epoch
        } else {
            p.readers != 0 || p.read_epoch != self.wait_epoch
        };
        if ready {
            // Only a monotonic "FIFO handshake already completed" bit.
            // Epoch is immutable; actual resource publication uses pipe lock.
            self.waiting.store(false, Ordering::Relaxed);
        }
        ready
    }
}
impl Drop for PipeEndpoint {
    fn drop(&mut self) {
        let mut p = self.data.lock().unwrap();
        p.readers -= u32::from(self.read);
        p.writers -= u32::from(self.write);
        if self.read {
            p.io_epoch[1] = p.io_epoch[1].wrapping_add(1);
        }
        if self.write {
            p.io_epoch[0] = p.io_epoch[0].wrapping_add(1);
        }
        if p.readers == 0 && p.writers == 0 {
            p.bytes.clear();
        }
    }
}

/// Shared endpoint and inode ownership. Metadata and endpoint last release can
/// both occur on a worker; snapshots still do not open another pipe end.
pub(super) struct PipeEnd {
    pub(super) endpoint: Arc<PipeEndpoint>,
    pub(super) pipe: Pipe,
    // Anonymous pipe inode; named FIFO descriptions already hold their Node.
    // Metadata does not define the shared resource or its last-close point.
    pub(super) metadata: Option<NodeRef>,
}
impl PipeEnd {
    pub(super) fn open(pipe: &Pipe, flags: u32) -> Result<Option<Arc<Self>>> {
        if flags & O_PATH != 0 {
            return Ok(None);
        }
        let data = pipe.data.clone();
        let endpoint = PipeEndpoint::open(data, flags, true)?;
        Ok(Some(Arc::new(Self {
            pipe: pipe.clone(),
            endpoint,
            metadata: None,
        })))
    }
    pub(super) fn new(pipe: Pipe, read: bool, write: bool, metadata: Option<NodeRef>) -> Arc<Self> {
        let data = pipe.data.clone();
        let endpoint = PipeEndpoint::anonymous(data, read, write);
        Arc::new(Self {
            pipe,
            endpoint,
            metadata,
        })
    }
}
impl std::ops::Deref for PipeEnd {
    type Target = PipeEndpoint;
    fn deref(&self) -> &PipeEndpoint {
        &self.endpoint
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn shared_named_fifo_poll_uses_pipe_data_and_hangup_instead_of_regular_file_readiness() {
        let mut v = Vfs::default();
        v.mknod_at(AT_FDCWD, b"/fifo", 0o10666, 0).unwrap();
        let reader = v.open_at(AT_FDCWD, b"/fifo", O_NONBLOCK, 0).unwrap();
        let poll = v
            .shared_files()
            .lookup(reader)
            .unwrap()
            .unwrap()
            .direct_poll()
            .unwrap();
        assert_eq!(v.poll(reader, 1), 0);
        assert_eq!(poll.poll_ready(1), Some(0));
        let writer = v.open_at(AT_FDCWD, b"/fifo", 1 | O_NONBLOCK, 0).unwrap();
        v.write(writer, b"x").unwrap();
        assert_eq!(poll.poll_ready(1), Some(1));
        v.close(writer).unwrap();
        assert_eq!(poll.poll_ready(1), Some(17));
        assert_eq!(v.read(reader, 1).unwrap(), b"x");
        assert_eq!(poll.poll_ready(1), Some(16));
    }
    #[test]
    fn complete_pipe_end_releases_inode_and_eof_on_the_last_worker() {
        fn shared<T: Send + Sync>() {}
        shared::<PipeEnd>();
        let mut v = Vfs::default();
        let [reader, writer] = v.pipe(0).unwrap();
        let end = v
            .descriptor(writer)
            .unwrap()
            .open
            .borrow()
            .pipe
            .clone()
            .unwrap();
        let inode = Arc::downgrade(end.metadata.as_ref().unwrap());
        let data = end.data.clone();
        v.close(reader).unwrap();
        v.close(writer).unwrap();
        drop(v);
        assert!(inode.upgrade().is_some());
        assert_eq!(data.lock().unwrap().writers, 1);
        let copy = end.clone();
        std::thread::spawn(move || drop(end)).join().unwrap();
        assert_eq!(data.lock().unwrap().writers, 1);
        std::thread::spawn(move || drop(copy)).join().unwrap();
        assert_eq!(data.lock().unwrap().writers, 0);
        assert_eq!(data.lock().unwrap().read(1).unwrap(), b"");
        assert!(inode.upgrade().is_none());
    }

    fn identity(v: &Vfs, path: &[u8]) -> Pipe {
        let path = v.resolve_final(AT_FDCWD, path, true).unwrap();
        let node = v.node(&path).unwrap();
        let Content::Fifo(pipe) = &node.borrow().content else {
            panic!("FIFO inode")
        };
        pipe.clone()
    }

    #[test]
    fn fifo_inode_identity_is_shared_without_owning_an_open_endpoint() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<Pipe>();
        let mut v = Vfs::default();
        v.mknod_at(AT_FDCWD, b"/fifo", 0o10666, 0).unwrap();
        let pipe = identity(&v, b"/fifo");
        let path_fd = v.open_at(AT_FDCWD, b"/fifo", O_PATH, 0).unwrap();
        let copy = pipe.clone();
        std::thread::spawn(move || {
            assert_eq!(
                (copy.data.lock().unwrap().readers, copy.inode),
                (0, pipe.inode)
            );
            assert!(Arc::ptr_eq(&copy.data, &pipe.data));
            let reader = PipeEndpoint::open(copy.data.clone(), O_NONBLOCK, true).unwrap();
            let writer = PipeEndpoint::open(copy.data.clone(), 1 | O_NONBLOCK, true).unwrap();
            assert_eq!(copy.data.lock().unwrap().write(b"shared"), Ok(6));
            assert_eq!(copy.data.lock().unwrap().read(6).unwrap(), b"shared");
            drop((reader, writer));
            let data = copy.data.lock().unwrap();
            assert_eq!((data.readers, data.writers), (0, 0));
        })
        .join()
        .unwrap();
        assert!(v.descriptor(path_fd).unwrap().open.borrow().pipe.is_none());
    }

    #[test]
    fn fifo_hardlinks_and_replacement_preserve_resources_without_pinning_deleted_inode() {
        let mut v = Vfs::default();
        v.mknod_at(AT_FDCWD, b"/fifo", 0o10666, 0).unwrap();
        v.link_at(AT_FDCWD, b"/fifo", AT_FDCWD, b"/alias").unwrap();
        let old = identity(&v, b"/fifo");
        let old_node = Arc::downgrade(&v.node(b"/fifo").unwrap());
        assert!(Arc::ptr_eq(&old.data, &identity(&v, b"/alias").data));
        let reader = v.open_at(AT_FDCWD, b"/alias", O_NONBLOCK, 0).unwrap();
        let writer = v.open_at(AT_FDCWD, b"/fifo", 1 | O_NONBLOCK, 0).unwrap();
        v.unlink_at(AT_FDCWD, b"/fifo", false).unwrap();
        v.mknod_at(AT_FDCWD, b"/fifo", 0o10666, 0).unwrap();
        assert!(!Arc::ptr_eq(&old.data, &identity(&v, b"/fifo").data));
        assert_eq!(
            v.open_at(AT_FDCWD, b"/fifo", 1 | O_NONBLOCK, 0),
            Err(Errno(6))
        );
        v.write(writer, b"old pipe").unwrap();
        assert_eq!(v.read(reader, 32).unwrap(), b"old pipe");
        v.unlink_at(AT_FDCWD, b"/alias", false).unwrap();
        v.close(reader).unwrap();
        v.close(writer).unwrap();
        assert!(old_node.upgrade().is_none());
        let data = old.data.lock().unwrap();
        assert_eq!((data.readers, data.writers), (0, 0));
        assert!(data.bytes.is_empty());
    }

    #[test]
    fn overlay_fifo_aliases_share_bytes_and_self_splice_detection() {
        let mut v = Vfs::default();
        for dir in [b"/lower".as_slice(), b"/upper", b"/work", b"/merged"] {
            v.mkdir_at(AT_FDCWD, dir, 0o755).unwrap();
        }
        v.mknod_at(AT_FDCWD, b"/lower/fifo", 0o10666, 0).unwrap();
        v.mount(
            None,
            b"/merged",
            Some(b"overlay"),
            0,
            Some(b"lowerdir=/lower,upperdir=/upper,workdir=/work"),
        )
        .unwrap();
        let reader = v.open_at(AT_FDCWD, b"/lower/fifo", O_NONBLOCK, 0).unwrap();
        let writer = v
            .open_at(AT_FDCWD, b"/merged/fifo", 1 | O_NONBLOCK, 0)
            .unwrap();
        assert!(Arc::ptr_eq(
            &identity(&v, b"/lower/fifo").data,
            &identity(&v, b"/merged/fifo").data
        ));
        v.write(writer, b"overlay pipe").unwrap();
        assert_eq!(v.splice(reader, writer, 12, None, None), Err(Errno(22)));
        assert_eq!(v.read(reader, 32).unwrap(), b"overlay pipe");
        v.close(writer).unwrap();
        assert!(v.read(reader, 1).unwrap().is_empty());
    }

    struct Wake {
        reader: DirectFd,
        calls: AtomicUsize,
    }
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {
            // A final-close notification may reenter the same pipe on this
            // thread. This must not run while PipeData is still locked.
            assert!(self.reader.read(1).unwrap().is_empty());
            self.calls.fetch_add(1, Ordering::Relaxed);
        }
    }
    #[test]
    fn final_shared_endpoint_drop_on_worker_wakes_peer_without_owner_projection() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<PipeEndpoint>();
        let mut v = Vfs::default();
        let [reader, writer] = v.pipe(O_NONBLOCK).unwrap();
        let bytes = v.direct_descriptors();
        let lease = v.retain_uring_fd(writer).unwrap().pipe_endpoint().unwrap();
        let end = v
            .descriptor(writer)
            .unwrap()
            .open
            .borrow()
            .pipe
            .as_ref()
            .unwrap()
            .clone();
        let data = end.data.clone();
        let metadata = end.metadata.clone().unwrap();
        drop(end);
        v.close(writer).unwrap();
        assert_eq!(v.read(reader, 1), Err(Errno(11)));
        assert_eq!(data.lock().unwrap().writers, 1);
        let wake = Arc::new(Wake {
            reader: bytes.get(reader).unwrap().clone(),
            calls: AtomicUsize::new(0),
        });
        let erased: Arc<dyn IoWake> = wake.clone();
        let signal = IoSignal::new(7, Arc::downgrade(&erased));
        let subscription = bytes.get(reader).unwrap().subscribe(&signal);
        std::thread::spawn(move || drop(lease)).join().unwrap();
        assert!(signal.ready());
        assert_eq!(wake.calls.load(Ordering::Relaxed), 1);
        assert_eq!(data.lock().unwrap().writers, 0);
        assert_eq!(bytes.get(reader).unwrap().poll_ready(1), Some(16));
        assert!(v.read(reader, 1).unwrap().is_empty());
        drop(subscription);
        // Metadata and byte/poll capabilities are still alive here; none of
        // them counts as a writer or requires an owner acknowledgement.
        assert_eq!(metadata.borrow().mode, 0o10600);
    }
    #[test]
    fn aliases_and_shared_leases_count_one_end_but_independent_opens_count_twice() {
        let mut v = Vfs::default();
        let [reader, writer] = v.pipe(0).unwrap();
        let alias = v.dup(writer, 0, false).unwrap();
        let lease = v.retain_uring_fd(writer).unwrap().pipe_endpoint().unwrap();
        let data = lease.data.clone();
        let clones: Vec<_> = (0..8).map(|_| lease.clone()).collect();
        assert_eq!(data.lock().unwrap().writers, 1);
        v.close(writer).unwrap();
        v.close(alias).unwrap();
        let other = PipeEndpoint::anonymous(data.clone(), false, true);
        assert_eq!(data.lock().unwrap().writers, 2);
        drop(other);
        drop(lease);
        assert_eq!(data.lock().unwrap().writers, 1);
        let gate = Arc::new(std::sync::Barrier::new(clones.len()));
        let mut threads = Vec::new();
        for lease in clones {
            let gate = gate.clone();
            threads.push(std::thread::spawn(move || {
                gate.wait();
                drop(lease);
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(data.lock().unwrap().writers, 0);
        assert!(v.read(reader, 1).unwrap().is_empty());
    }
    #[test]
    fn byte_poll_flags_and_subscriptions_do_not_hold_pipe_endpoints_open() {
        struct Target;
        impl IoWake for Target {
            fn wake_io(&self, _: &Arc<IoSignal>) {}
        }
        let mut v = Vfs::default();
        let [reader, writer] = v.pipe(O_NONBLOCK).unwrap();
        let fd = v.direct_descriptors();
        let flags = v.fd_flags_snapshot();
        let epoll = v.epoll_create(0).unwrap();
        v.epoll_ctl(epoll, 1, reader, 1, 42).unwrap();
        let polls = v.direct_descriptors();
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let signal = IoSignal::new(7, Arc::downgrade(&target));
        let subscription = fd.get(reader).unwrap().subscribe(&signal);
        v.close(writer).unwrap();
        assert!(signal.ready());
        assert_eq!(flags.fcntl(writer, 3, 0), Err(Errno(9)));
        assert!(fd.get(reader).unwrap().read(1).unwrap().is_empty());
        assert_eq!(
            polls.get(epoll).unwrap().epoll_wait(1).unwrap(),
            vec![(16, 42)]
        );
        drop(subscription);
    }
    #[test]
    fn fifo_open_handshake_survives_peer_open_and_close_before_retry() {
        let data = Arc::new(PipeResource::new());
        assert!(matches!(
            PipeEndpoint::open(data.clone(), 1 | O_NONBLOCK, true),
            Err(Errno(6))
        ));
        assert_eq!(data.lock().unwrap().writers, 0);
        let reader = PipeEndpoint::open(data.clone(), 0, true).unwrap();
        assert!(reader.has_waiter() && !reader.open_ready());
        let writer_data = data.clone();
        std::thread::spawn(move || {
            drop(PipeEndpoint::open(writer_data, 1 | O_NONBLOCK, true).unwrap());
        })
        .join()
        .unwrap();
        assert!(reader.open_ready());
        assert!(!reader.has_waiter());
        assert_eq!(data.lock().unwrap().writers, 0);
        assert!(data.lock().unwrap().read(1).unwrap().is_empty());
        drop(reader);
        let writer = PipeEndpoint::open(data.clone(), 1, true).unwrap();
        assert!(writer.has_waiter() && !writer.open_ready());
        drop(PipeEndpoint::open(data.clone(), O_NONBLOCK, true).unwrap());
        assert!(writer.open_ready());
        assert_eq!(data.lock().unwrap().write(b"x"), Err(Errno(32)));
    }
    #[test]
    fn racing_fifo_nonblocking_open_and_last_reader_close_preserves_counts() {
        for _ in 0..128 {
            let data = Arc::new(PipeResource::new());
            let reader = PipeEndpoint::open(data.clone(), O_NONBLOCK, true).unwrap();
            let gate = std::sync::Barrier::new(2);
            std::thread::scope(|scope| {
                let data = &data;
                let gate = &gate;
                scope.spawn(move || {
                    gate.wait();
                    drop(reader);
                });
                gate.wait();
                let writer = PipeEndpoint::open(data.clone(), 1 | O_NONBLOCK, true);
                assert!(writer.is_ok() || matches!(writer, Err(Errno(6))));
                drop(writer);
            });
            let p = data.lock().unwrap();
            assert_eq!((p.readers, p.writers), (0, 0));
        }
    }
    #[test]
    fn final_reader_drop_on_worker_produces_epipe_and_releases_last_buffer() {
        let mut v = Vfs::default();
        let [reader, writer] = v.pipe(O_NONBLOCK).unwrap();
        let bytes = v.direct_descriptors();
        let lease = v.retain_uring_fd(reader).unwrap().pipe_endpoint().unwrap();
        let data = lease.data.clone();
        v.write(writer, b"buffered").unwrap();
        v.close(reader).unwrap();
        assert_eq!(v.write(writer, b"still open"), Ok(10));
        std::thread::spawn(move || drop(lease)).join().unwrap();
        assert_eq!(v.write(writer, b"closed"), Err(Errno(32)));
        assert_eq!(bytes.get(writer).unwrap().poll_ready(4), Some(8));
        v.close(writer).unwrap();
        let p = data.lock().unwrap();
        assert_eq!((p.readers, p.writers), (0, 0));
        assert!(p.bytes.is_empty());
    }
}
