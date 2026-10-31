// SPDX-License-Identifier: GPL-3.0-or-later
use super::{tests::Fixture, *};
use std::os::fd::AsFd;
use std::time::{Duration, Instant};

fn events(v: &mut Vfs, fd: u32) -> Vec<(i32, u32, u32, Vec<u8>)> {
    let bytes = v.read(fd, 65536).unwrap();
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let word =
            |offset| u32::from_le_bytes(bytes[at + offset..at + offset + 4].try_into().unwrap());
        let len = word(12) as usize;
        out.push((
            word(0) as i32,
            word(4),
            word(8),
            bytes[at + 16..at + 16 + len]
                .split(|b| *b == 0)
                .next()
                .unwrap()
                .to_vec(),
        ));
        at += 16 + len;
    }
    out
}

#[test]
fn native_directory_changes_and_existing_file_writes_reach_inotify() {
    let f = Fixture::new();
    std::fs::write(f.0.join("old"), b"old").unwrap();
    let mut v = f.vfs(false);
    let fd = v.inotify_init(O_NONBLOCK).unwrap();
    let wd = v.inotify_add(fd, b"/host", 0xfff).unwrap();
    std::fs::write(f.0.join("old"), b"modified").unwrap();
    assert!(events(&mut v, fd)
        .iter()
        .any(|e| e.0 == wd && e.1 & 2 != 0 && e.3 == b"old"));
    std::fs::write(f.0.join("new"), b"new").unwrap();
    assert!(events(&mut v, fd)
        .iter()
        .any(|e| e.1 & 256 != 0 && e.3 == b"new"));
    std::fs::rename(f.0.join("new"), f.0.join("renamed")).unwrap();
    let moved = events(&mut v, fd);
    let from = moved
        .iter()
        .find(|e| e.1 & 64 != 0 && e.3 == b"new")
        .unwrap();
    let to = moved
        .iter()
        .find(|e| e.1 & 128 != 0 && e.3 == b"renamed")
        .unwrap();
    assert_ne!(from.2, 0);
    assert_eq!(from.2, to.2);
    std::fs::remove_file(f.0.join("renamed")).unwrap();
    assert!(events(&mut v, fd)
        .iter()
        .any(|e| e.1 & 512 != 0 && e.3 == b"renamed"));
    v.inotify_remove(fd, wd).unwrap();
    assert!(events(&mut v, fd).iter().any(|e| e.1 == 0x8000));
    assert!(!v.has_native_event_sources());
}

#[test]
fn native_inode_watches_through_separate_grants_are_independent() {
    let f = Fixture::new();
    std::fs::write(f.0.join("file"), b"initial").unwrap();
    let mut v = f.vfs(false);
    v.mkdir_at(AT_FDCWD, b"/alias", 0o755).unwrap();
    v.mount_host(b"/alias", &f.0, true).unwrap();
    let fd = v.inotify_init(O_NONBLOCK).unwrap();
    let a = v.inotify_add(fd, b"/host/file", 2).unwrap();
    let b = v.inotify_add(fd, b"/alias/file", 2).unwrap();
    assert_ne!(a, b);
    std::fs::write(f.0.join("file"), b"changed").unwrap();
    let got = events(&mut v, fd);
    assert!(got.iter().any(|e| e.0 == a && e.1 & 2 != 0));
    assert!(got.iter().any(|e| e.0 == b && e.1 & 2 != 0));
    v.inotify_remove(fd, a).unwrap();
    events(&mut v, fd);
    std::fs::write(f.0.join("file"), b"still watched").unwrap();
    assert!(events(&mut v, fd).iter().any(|e| e.0 == b && e.1 & 2 != 0));
}

#[test]
fn native_watch_wakes_the_existing_poll_and_epoll_path() {
    let f = Fixture::new();
    let mut v = f.vfs(true);
    let fd = v.inotify_init(O_NONBLOCK).unwrap();
    v.inotify_add(fd, b"/host", 256 | 0x80000000).unwrap();
    let ep = v.epoll_create(0).unwrap();
    v.epoll_ctl(ep, 1, fd, 1, 42).unwrap();
    let handles = v.native_wait_fds();
    assert_eq!(handles.len(), 1);
    let handles: Vec<_> = handles.iter().map(|fd| fd.as_fd()).collect();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(30));
            std::fs::write(f.0.join("wake"), b"wake").unwrap();
        });
        let began = Instant::now();
        trames_net::wait_with_fds(&[], &handles, Duration::from_secs(2)).unwrap();
        assert!(began.elapsed() < Duration::from_secs(1));
    });
    assert_eq!(v.epoll_wait(ep, 4, |_, _| Ok(None)).unwrap(), vec![(1, 42)]);
    let got = events(&mut v, fd);
    assert!(got.iter().any(|e| e.1 & 256 != 0));
    assert!(got.iter().any(|e| e.1 == 0x8000));
    assert!(!v.has_native_event_sources());
}

#[test]
fn native_watch_rearms_on_worker_poller_and_mask_updates_release_interests() {
    struct Wake(Arc<HostEvents>);
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
        fn host_events(&self) -> Option<Arc<HostEvents>> {
            Some(self.0.clone())
        }
    }
    let f = Fixture::new();
    std::fs::write(f.0.join("file"), b"initial").unwrap();
    let mut v = f.vfs(false);
    let fd = v.inotify_init(O_NONBLOCK).unwrap();
    let wd = v.inotify_add(fd, b"/host", 256).unwrap();
    assert_eq!(v.inotify_add(fd, b"/host", 2), Ok(wd));
    let hub = HostEvents::new().unwrap();
    let wake: Arc<dyn IoWake> = Arc::new(Wake(hub.clone()));
    let signal = IoSignal::new(1, Arc::downgrade(&wake));
    let files = v.direct_descriptors();
    let subscriptions = files.get(fd).unwrap().subscribe(&signal);
    assert!(subscriptions.iter().any(|s| s.external()));
    for i in 0..3 {
        signal.reset();
        for subscription in &subscriptions {
            subscription.rearm_host().unwrap();
        }
        std::fs::write(f.0.join("file"), format!("{i}")).unwrap();
        hub.wait(Some(Instant::now() + Duration::from_secs(1)))
            .unwrap();
        assert!(signal.ready());
        assert!(events(&mut v, fd).iter().any(|e| e.1 & 2 != 0));
    }
    drop(subscriptions);
    // Replacing a native mask with guest-only OPEN retires native resources.
    assert_eq!(v.inotify_add(fd, b"/host", 32), Ok(wd));
    assert!(!v.has_native_event_sources());
    v.inotify_remove(fd, wd).unwrap();
    for _ in 0..64 {
        let wd = v.inotify_add(fd, b"/host", 256).unwrap();
        v.inotify_remove(fd, wd).unwrap();
    }
    assert!(v.native_wait_fds().is_empty());
}

#[test]
fn short_lived_guest_names_are_preserved_and_native_echoes_are_coalesced() {
    let f = Fixture::new();
    let mut v = f.vfs(false);
    let fd = v.inotify_init(O_NONBLOCK).unwrap();
    v.inotify_add(fd, b"/host", 256 | 512).unwrap();
    let file = v.open_at(AT_FDCWD, b"/host/short", 0x42, 0o600).unwrap();
    v.close(file).unwrap();
    v.unlink_at(AT_FDCWD, b"/host/short", false).unwrap();
    let got = events(&mut v, fd);
    assert_eq!(got.iter().filter(|e| e.1 & 256 != 0).count(), 1);
    assert_eq!(got.iter().filter(|e| e.1 & 512 != 0).count(), 1);
    let file = v.open_at(AT_FDCWD, b"/host/present", 0x42, 0o600).unwrap();
    v.close(file).unwrap();
    assert_eq!(
        events(&mut v, fd).iter().filter(|e| e.1 & 256 != 0).count(),
        1
    );
    v.close(fd).unwrap();
    assert!(!v.has_native_event_sources());
}

#[test]
fn native_flock_conflicts_in_both_directions_and_follows_dup_lifetime() {
    let f = Fixture::new();
    std::fs::write(f.0.join("file"), b"file").unwrap();
    let mut v = f.vfs(false);
    let native = File::open(f.0.join("file")).unwrap();
    let guest = v.open_at(AT_FDCWD, b"/host/file", 2, 0).unwrap();
    assert_eq!(
        unsafe { libc::flock(native.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    assert_eq!(v.flock(guest, 6), Err(Errno(11)));
    assert_eq!(unsafe { libc::flock(native.as_raw_fd(), libc::LOCK_UN) }, 0);
    v.flock(guest, 6).unwrap();
    assert_ne!(
        unsafe { libc::flock(native.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let duplicate = v.dup(guest, 0, false).unwrap();
    v.close(guest).unwrap();
    assert_ne!(
        unsafe { libc::flock(native.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    v.close(duplicate).unwrap();
    assert_eq!(
        unsafe { libc::flock(native.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
}

#[cfg(target_vendor = "apple")]
#[test]
fn native_flock_unlock_is_waitable_and_private_mapping_keeps_ofd_lock() {
    let f = Fixture::new();
    std::fs::write(f.0.join("file"), vec![0; 4096]).unwrap();
    let mut v = f.vfs(false);
    let native = File::open(f.0.join("file")).unwrap();
    let guest = v.open_at(AT_FDCWD, b"/host/file", 2, 0).unwrap();
    assert_eq!(unsafe { libc::flock(native.as_raw_fd(), libc::LOCK_EX) }, 0);
    assert_eq!(v.flock(guest, 2), Err(Errno(11)));
    let (request, lease) = v.retain_flock(guest, 2).unwrap();
    let fd = request.native_wait_fd().unwrap();
    assert_eq!(unsafe { libc::flock(native.as_raw_fd(), libc::LOCK_UN) }, 0);
    let began = Instant::now();
    trames_net::wait_with_fds(&[], &[fd.as_fd()], Duration::from_secs(1)).unwrap();
    assert!(began.elapsed() < Duration::from_millis(500));
    request.try_lock().unwrap();
    drop(request);
    drop(lease);
    let pages = v.mapping_pages(guest, 0, 4096, false, true).unwrap();
    v.close(guest).unwrap();
    assert_ne!(
        unsafe { libc::flock(native.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    drop(pages);
    assert_eq!(
        unsafe { libc::flock(native.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
}
