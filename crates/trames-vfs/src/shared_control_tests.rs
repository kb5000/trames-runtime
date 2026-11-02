// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn snapshot(v: &mut Vfs) {
    v.set_runtime_info(
        1,
        RuntimeInfo {
            processes: vec![ProcessInfo {
                pid: 1,
                tgid: 1,
                ..Default::default()
            }],
            ..Default::default()
        },
    );
}
fn bpf_allow() -> [u8; 16] {
    [0xb7, 0, 0, 0, 1, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0]
}

#[test]
fn signal_mask_lifecycle_is_shared_but_readiness_stays_with_the_reading_task() {
    let mut v = Vfs::default();
    let a = 1 << 9;
    let b = 1 << 11;
    let fd = v.signalfd(-1, a, O_NONBLOCK | O_CLOEXEC).unwrap();
    let files = v.shared_files();
    let alias = files.duplicate(fd, 0, false).unwrap().unwrap();
    let ep = v.epoll_create(0).unwrap();
    v.epoll_ctl(ep, 1, alias, 1, 73).unwrap();
    assert_eq!(v.poll_signals(alias, 1, a), 1);
    assert_eq!(v.poll_signals(alias, 1, b), 0);
    assert!(
        v.direct_descriptors().get(alias).is_none(),
        "a shared mask is not a creator-task byte/poll capability"
    );
    let factory = v.descriptor_factory();
    std::thread::spawn(move || {
        assert_eq!(
            factory.signalfd(alias as i32, b | (1 << 8) | (1 << 18), O_CLOEXEC),
            Some(Ok(alias))
        );
    })
    .join()
    .unwrap();
    assert_eq!(v.signalfd_mask(fd), Ok(Some(b)));
    assert_eq!(v.poll_signals(alias, 1, a), 0);
    assert_eq!(
        v.epoll_wait_signals(ep, 1, b, |_, _| Ok(None)).unwrap(),
        vec![(1, 73)]
    );
    assert!(v.fds.get(&fd).unwrap().cloexec.get());
    assert!(
        !v.fds.get(&alias).unwrap().cloexec.get(),
        "update flags do not change existing per-FD CLOEXEC"
    );
    assert_eq!(v.flags(alias).unwrap() & O_NONBLOCK, O_NONBLOCK);
    assert_eq!(
        v.fd_snapshot()
            .iter()
            .find(|f| f.fd == fd)
            .unwrap()
            .signal_mask,
        Some(b)
    );
    let (owner, _ring) = v.uring_create(2, 4).unwrap();
    let factory = v.descriptor_factory();
    assert_eq!(factory.signalfd(owner as i32, a, 0), None);
    assert_eq!(v.signalfd(owner as i32, a, 0), Err(Errno(22)));
    assert_eq!(factory.signalfd(alias as i32, a, 1), Some(Err(Errno(22))));
    assert_eq!(v.signalfd_mask(alias), Ok(Some(b)));
    assert_eq!(factory.signalfd(9999, a, 0), Some(Err(Errno(9))));
    let actual = files.lookup(fd).unwrap().unwrap();
    v.close(fd).unwrap();
    v.close(alias).unwrap();
    let weak = Arc::downgrade(&actual.open);
    std::thread::spawn(move || drop(actual)).join().unwrap();
    assert!(
        weak.upgrade().is_none(),
        "epoll and prepared snapshots do not retain last-close lifetime"
    );
}
#[test]
fn concurrent_signal_mask_updates_publish_whole_masks_without_task_locks() {
    let mut v = Vfs::default();
    let fd = v.signalfd(-1, 0, 0).unwrap();
    let masks = [0x5555_5555_5555_5555, 0xaaaa_aaaa_aaaa_aaaa];
    let allowed = |mask| mask & !((1 << 8) | (1 << 18));
    let jobs: Vec<_> = masks
        .into_iter()
        .map(|mask| {
            let factory = v.descriptor_factory();
            std::thread::spawn(move || {
                for _ in 0..4096 {
                    assert_eq!(factory.signalfd(fd as i32, mask, 0), Some(Ok(fd)));
                }
            })
        })
        .collect();
    for _ in 0..4096 {
        let mask = v.signalfd_mask(fd).unwrap().unwrap();
        assert!(mask == 0 || mask == allowed(masks[0]) || mask == allowed(masks[1]));
    }
    for job in jobs {
        job.join().unwrap();
    }
}
#[test]
fn complete_namespace_ofds_cross_workers_and_keep_original_setns_authority() {
    let mut v = Vfs::default();
    snapshot(&mut v);
    let kinds = [
        (b"uts".as_slice(), linux_namespace::CLONE_NEWUTS),
        (b"pid", CLONE_NEWPID),
        (b"ipc", linux_namespace::CLONE_NEWIPC),
        (b"cgroup", linux_namespace::CLONE_NEWCGROUP),
        (b"net", linux_namespace::CLONE_NEWNET),
    ];
    let mut fds = Vec::new();
    for (kind, _) in kinds {
        fds.push(
            v.open_at(
                AT_FDCWD,
                &[b"/proc/self/ns/".as_slice(), kind].concat(),
                0,
                0,
            )
            .unwrap(),
        );
    }
    let ids: Vec<_> = fds
        .iter()
        .map(|fd| v.stat_fd(*fd).unwrap()[8..16].to_vec())
        .collect();
    let files = v.shared_files();
    let factory = v.descriptor_factory();
    let rights = factory
        .send_local_rights(&fds)
        .expect("complete shared namespace resources")
        .unwrap();
    for &fd in &fds {
        v.close(fd).unwrap();
    }
    v.unshare_uts().unwrap();
    v.unshare_ipc().unwrap();
    v.unshare_cgroup().unwrap();
    v.unshare_net().unwrap();
    let imported = std::thread::spawn(move || factory.receive_local_rights(rights, 5, true))
        .join()
        .unwrap();
    assert!(!imported.1);
    assert_eq!(imported.0.len(), 5);
    for ((fd, (_, kind)), inode) in imported.0.iter().zip(kinds).zip(ids) {
        assert_eq!(v.namespace_type(*fd), Ok(Some(kind)));
        assert_eq!(v.stat_fd(*fd).unwrap()[8..16], inode);
        assert!(v.fds.get(fd).unwrap().cloexec.get());
        assert!(files.lookup(*fd).unwrap().unwrap().direct_byte().is_none());
    }
    v.setns(imported.0[0], linux_namespace::CLONE_NEWUTS)
        .unwrap();
    v.set_uts_name(false, b"restored").unwrap();
    assert_eq!(v.uts_name(false), b"restored");
    v.setns(imported.0[2], linux_namespace::CLONE_NEWIPC)
        .unwrap();
    v.setns(imported.0[3], linux_namespace::CLONE_NEWCGROUP)
        .unwrap();
    v.setns(imported.0[4], linux_namespace::CLONE_NEWNET)
        .unwrap();
    v.import_file(b"/pinned", vec![]).unwrap();
    v.mount(Some(b"/proc/self/ns/uts"), b"/pinned", None, 4096, None)
        .unwrap();
    let bound = v.open_at(AT_FDCWD, b"/pinned", 0, 0).unwrap();
    assert!(
        files.lookup(bound).is_none(),
        "nsfs mount topology remains owner control"
    );
    assert_eq!(
        v.namespace_type(bound),
        Ok(Some(linux_namespace::CLONE_NEWUTS))
    );
    assert_eq!(v.umount(b"/pinned", 0), Err(Errno(16)));
    v.close(bound).unwrap();
    v.umount(b"/pinned", 0).unwrap();
    v.credentials = Credentials::user(1000, 1000);
    assert_eq!(
        v.setns(imported.0[0], linux_namespace::CLONE_NEWUTS),
        Err(Errno(1))
    );
    assert_eq!(
        v.setns(imported.0[0], linux_namespace::CLONE_NEWIPC),
        Err(Errno(22))
    );
}
#[test]
fn ipc_and_cgroup_quota_reclaims_the_last_actual_worker_lease() {
    for ipc in [true, false] {
        let mut v = Vfs::default();
        let mut leases = Vec::new();
        let kind = if ipc { b"ipc".as_slice() } else { b"cgroup" };
        loop {
            let result = if ipc {
                v.unshare_ipc()
            } else {
                v.unshare_cgroup()
            };
            if result == Err(Errno(28)) {
                break;
            }
            result.unwrap();
            assert!(leases.len() < 128);
            snapshot(&mut v);
            let fd = v
                .open_at(
                    AT_FDCWD,
                    &[b"/proc/self/ns/".as_slice(), kind].concat(),
                    0,
                    0,
                )
                .unwrap();
            leases.push(v.shared_files().lookup(fd).unwrap().unwrap());
            v.close(fd).unwrap();
        }
        assert_eq!(leases.len(), 128);
        let first = leases.remove(0);
        std::thread::spawn(move || drop(first)).join().unwrap();
        if ipc {
            v.unshare_ipc().unwrap();
        } else {
            v.unshare_cgroup().unwrap();
        }
    }
}
#[test]
fn bpf_ofd_worker_lifetime_preserves_original_program_registry_and_quota() {
    let mut v = Vfs::default();
    let fd = v.bpf_load_device(&bpf_allow()).unwrap();
    let id = v.bpf_program(fd).unwrap().id;
    let actual = v.shared_files().lookup(fd).unwrap().unwrap();
    assert!(actual.clone().direct_byte().is_none());
    assert_eq!(v.read(fd, 8), Err(Errno(22)));
    let ep = v.epoll_create(0).unwrap();
    assert_eq!(v.epoll_ctl(ep, 1, fd, 1, 0), Err(Errno(1)));
    v.close(fd).unwrap();
    for _ in 1..128 {
        v.bpf_load_device(&bpf_allow()).unwrap();
    }
    assert_eq!(v.bpf_load_device(&bpf_allow()), Err(Errno(28)));
    std::thread::spawn(move || {
        let Some(events::SharedControl::Bpf(program)) = &actual.open.control else {
            panic!("original shared program");
        };
        assert_eq!(program.id, id);
        assert!(program.allows([1, 1, 3]));
        drop(actual);
    })
    .join()
    .unwrap();
    assert_eq!(v.bpf_get_fd(id), Err(Errno(2)));
    v.bpf_load_device(&bpf_allow()).unwrap();
}
