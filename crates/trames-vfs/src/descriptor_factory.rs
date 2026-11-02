// SPDX-License-Identifier: GPL-3.0-or-later
//! Real Files publication for fully shared anonymous resources. No owner RPC.
use super::*;

#[derive(Clone)]
pub struct DescriptorFactory {
    files: SharedFiles,
    ids: Arc<AtomicU64>,
    owner: (u32, u32),
}
pub(super) fn next_id(ids: &AtomicU64) -> u64 {
    (1u64 << 62) | ids.fetch_add(1, Ordering::Relaxed)
}
impl Vfs {
    pub fn descriptor_factory(&self) -> DescriptorFactory {
        DescriptorFactory {
            files: self.shared_files(),
            ids: self.next_open.clone(),
            owner: (self.credentials.fsuid, self.credentials.fsgid),
        }
    }
}
impl DescriptorFactory {
    fn open_id(&self) -> u64 {
        next_id(&self.ids)
    }
    fn anonymous(&self, flags: u32, resource: events::Anonymous) -> Result<u32> {
        let reservation = self.files.reserve()?;
        let descriptor = events::anonymous_descriptor(self.open_id(), flags, resource);
        Ok(reservation.publish(descriptor, None))
    }
    pub fn eventfd(&self, initial: u32, flags: u32) -> Result<u32> {
        if flags & !(O_CLOEXEC | O_NONBLOCK | 1) != 0 {
            return Err(Errno(22));
        }
        self.anonymous(
            flags,
            events::Anonymous::Event(Arc::new(direct_io::EventCounter::new(
                initial as u64,
                flags & 1 != 0,
            ))),
        )
    }
    pub fn timerfd(&self, clock: u32, flags: u32) -> Result<u32> {
        if !matches!(clock, 0 | 1 | 7) || flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
            return Err(Errno(22));
        }
        self.anonymous(flags, events::Anonymous::Timer(TimerFd::new(clock)))
    }
    pub fn inotify_init(&self, flags: u32) -> Result<u32> {
        if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
            return Err(Errno(22));
        }
        self.anonymous(flags, events::Anonymous::Inotify(Arc::default()))
    }
    pub fn pipe(&self, flags: u32) -> Result<[u32; 2]> {
        self.pipe_with_output(flags, |_| Ok(()))
    }
    /// Output runs before either descriptor becomes visible, with no Files lock.
    /// Failure/panic releases both reservations and the original pipe ends.
    pub fn pipe_with_output(
        &self,
        flags: u32,
        output: impl FnOnce([u32; 2]) -> Result<()>,
    ) -> Result<[u32; 2]> {
        if flags & !(O_NONBLOCK | O_CLOEXEC) != 0 {
            return Err(Errno(22));
        }
        let reservation = self.files.reserve_pair()?;
        let p = Pipe::new(self.open_id());
        let inode = p.inode;
        let metadata = Arc::new(Inode::new(Node {
            identity: 0,
            record_locks: std::sync::OnceLock::new(),
            whole_locks: std::sync::OnceLock::new(),
            notifications: inotify::Marks::default(),
            path_hint: SharedCell::default(),
            device: 6,
            content: Content::Null,
            mode: 0o10600,
            uid: self.owner.0,
            gid: self.owner.1,
            volatile: false,
            inode,
            links: 1,
            times: [storage::Timestamp::now(); 3],
            xattrs: BTreeMap::new(),
            seals: None,
        }));
        let read = PipeEnd::new(p.clone(), true, false, Some(metadata.clone()));
        let write = PipeEnd::new(p, false, true, Some(metadata));

        let descriptions = [(read, FdKind::PipeRead, 0), (write, FdKind::PipeWrite, 1)].map(
            |(end, kind, access)| Descriptor {
                open: OpenHandle::new(OpenDescription {
                    shared: Arc::new(SharedOpenDescription {
                        _disk_file: None,
                        #[cfg(all(feature = "hostfs", unix))]
                        host_file: None,
                        native_image: None,
                        mount_resource: std::sync::OnceLock::new(),
                        file_authority: Default::default(),
                        tcp_publication: Default::default(),
                        control: None,
                        read_node: None,
                        id: self.open_id(),
                        owner: self.owner,
                        kind,
                        flags: ((flags & O_NONBLOCK) | access).into(),
                        file_position: Arc::default(),
                        flock: std::sync::OnceLock::new(),
                        ofd_records: Default::default(),
                        node: None,
                        pipe: Some(end),
                        bridge: None,
                        kernel_log: None,
                        notification: None,
                    }),
                    position: 0,
                    socket: None,
                    anonymous: None,
                    local: None,
                    pty: None,
                    namespace: None,
                    network_control: None,
                    mount_file: None,
                    oom: None,
                    mount: None,
                }),
                cloexec: (flags & O_CLOEXEC != 0).into(),
            },
        );
        output(reservation.numbers())?;
        Ok(reservation.publish(descriptions))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn factories_are_send_sync_and_publish_real_resources_into_existing_views() {
        fn shared<T: Send + Sync>() {}
        shared::<DescriptorFactory>();
        let mut owner = Vfs {
            credentials: Credentials::user(123, 456),
            ..Vfs::default()
        };
        let direct = owner.direct_descriptors();
        let factory = owner.descriptor_factory();
        let resources = std::thread::spawn(move || {
            let pipe = factory.pipe(O_NONBLOCK | O_CLOEXEC).unwrap();
            [
                pipe[0],
                pipe[1],
                factory.eventfd(7, O_NONBLOCK | O_CLOEXEC).unwrap(),
                factory.timerfd(1, O_NONBLOCK | O_CLOEXEC).unwrap(),
                factory.inotify_init(O_NONBLOCK | O_CLOEXEC).unwrap(),
            ]
        })
        .join()
        .unwrap();
        for &fd in &resources {
            assert!(owner.fds.lookup(fd).unwrap().cloexec.get());
            assert!(direct.get(fd).is_some());
        }
        let stat = owner.stat_fd(resources[0]).unwrap();
        assert_eq!(stat[24..28], 123u32.to_le_bytes());
        assert_eq!(stat[28..32], 456u32.to_le_bytes());
        assert!(direct.get(resources[2]).unwrap().is_eventfd());
        assert_eq!(direct.get(resources[3]).unwrap().timer().unwrap().clock, 1);
        assert!(direct.get(resources[4]).unwrap().is_inotify());
        for fd in resources {
            owner.close(fd).unwrap();
        }
    }
    #[test]
    fn pipe_copyout_failure_and_panic_release_both_unpublished_numbers() {
        let mut owner = Vfs::default();
        let factory = owner.descriptor_factory();
        let files = owner.shared_files();
        assert_eq!(
            factory.pipe_with_output(0, |fds| {
                for fd in fds {
                    assert!(matches!(files.lookup(fd), Some(Err(Errno(9)))));
                }
                // The Files lock must not be held over a guest-memory callback.
                let other = factory.eventfd(1, 0).unwrap();
                assert_eq!(other, 5);
                files.close(other, 1).unwrap().unwrap();
                Err(Errno(14))
            }),
            Err(Errno(14))
        );
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || factory.pipe_with_output(0, |_| panic!("copyout interrupted"))
        ))
        .is_err());
        assert_eq!(owner.fd_snapshot().len(), 3);
        let pair = factory.pipe(0).unwrap();
        assert_eq!(pair, [3, 4]);
        for fd in pair {
            owner.close(fd).unwrap();
        }
    }
    #[test]
    fn fd_limit_and_flag_errors_have_no_partial_pipe_or_output_effects() {
        let mut owner = Vfs::default();
        owner.set_descriptor_limit(4);
        let factory = owner.descriptor_factory();
        assert_eq!(
            factory.pipe_with_output(0, |_| panic!("EMFILE cannot copy output")),
            Err(Errno(24))
        );
        let event = factory.eventfd(0, 0).unwrap();
        assert_eq!(event, 3);
        owner.close(event).unwrap();
        assert_eq!(
            factory.pipe_with_output(1, |_| panic!("EINVAL cannot copy output")),
            Err(Errno(22))
        );
        assert_eq!(factory.eventfd(0, 2), Err(Errno(22)));
        assert_eq!(factory.timerfd(2, 0), Err(Errno(22)));
        assert_eq!(factory.inotify_init(1), Err(Errno(22)));
        owner.set_descriptor_limit(5);
        let pair = factory.pipe(0).unwrap();
        assert_eq!(pair, [3, 4]);
        for fd in pair {
            owner.close(fd).unwrap();
        }
    }
    #[test]
    fn concurrent_creators_publish_disjoint_live_slots_and_unique_ofd_ids() {
        let mut owner = Vfs::default();
        let factory = owner.descriptor_factory();
        let gate = Arc::new(std::sync::Barrier::new(8));
        let jobs: Vec<_> = (0..8)
            .map(|_| {
                let factory = factory.clone();
                let gate = gate.clone();
                std::thread::spawn(move || {
                    gate.wait();
                    let p = factory.pipe(0).unwrap();
                    [
                        p[0],
                        p[1],
                        factory.eventfd(0, 0).unwrap(),
                        factory.timerfd(1, 0).unwrap(),
                        factory.inotify_init(0).unwrap(),
                    ]
                })
            })
            .collect();
        let fds: Vec<_> = jobs.into_iter().flat_map(|j| j.join().unwrap()).collect();
        assert_eq!(
            fds.iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            40
        );
        let ids: std::collections::BTreeSet<_> = fds
            .iter()
            .map(|&fd| owner.descriptor(fd).unwrap().open.borrow().id)
            .collect();
        assert_eq!(ids.len(), 40);
        for fd in fds {
            owner.close(fd).unwrap();
        }
    }
}
