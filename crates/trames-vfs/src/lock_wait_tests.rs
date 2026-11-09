// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::sync::{atomic::AtomicUsize, Barrier};
#[derive(Default)]
struct Wake(AtomicUsize);
impl IoWake for Wake {
    fn wake_io(&self, _: &Arc<IoSignal>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
fn file(v: &mut Vfs, name: &[u8]) -> u32 {
    v.open_at(AT_FDCWD, name, 0x42, 0o600).unwrap()
}
fn locked(v: &Vfs, fd: u32, kind: u16) -> RecordLock {
    let lock = v.normalize_lock(fd, kind, 0, 0, 8).unwrap();
    v.record_lock_set(fd, lock).unwrap();
    lock
}
fn wait(v: &Vfs, fd: u32) -> RecordLockRequest {
    let lock = v.normalize_lock(fd, 1, 0, 0, 8).unwrap();
    v.retain_record_lock(fd, lock).unwrap()
}
#[test]
fn posix_wait_graph_detects_cycles_and_cancellation_removes_only_its_original_edge() {
    let mut a = Vfs::default();
    a.set_lock_owner(1);
    let x = file(&mut a, b"/x");
    let y = file(&mut a, b"/y");
    let z = file(&mut a, b"/z");
    let mut b = a.clone_with_files(false);
    b.set_lock_owner(2);
    let mut c = a.clone_with_files(false);
    c.set_lock_owner(3);
    locked(&a, x, 1);
    locked(&b, y, 1);
    locked(&c, z, 1);
    let xy = wait(&a, y).wait().unwrap();
    let xz = wait(&a, z).wait().unwrap();
    assert!(matches!(wait(&b, x).wait(), Err(Errno(35))));
    drop(xy);
    let yx = wait(&b, x).wait().unwrap();
    assert!(matches!(wait(&c, y).wait(), Err(Errno(35))));
    drop(xz);
    let zy = wait(&c, y).wait().unwrap();
    drop((yx, zy));
    assert!(a.record_locks.1.lock().unwrap().is_empty());
}
#[test]
fn concurrent_posix_wait_registration_cannot_publish_both_sides_of_a_cycle() {
    let mut v = Vfs::default();
    v.set_lock_owner(1);
    let x = file(&mut v, b"/x");
    let y = file(&mut v, b"/y");
    let mut other = v.clone_with_files(false);
    other.set_lock_owner(2);
    locked(&v, x, 1);
    locked(&other, y, 1);
    let gate = Arc::new(Barrier::new(2));
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        for request in [wait(&v, y), wait(&other, x)] {
            let (gate, send) = (gate.clone(), send.clone());
            scope.spawn(move || {
                gate.wait();
                send.send(request.wait()).unwrap();
            });
        }
    });
    let results = [receive.recv().unwrap(), receive.recv().unwrap()];
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(Errno(35))))
            .count(),
        1
    );
    drop(results);
    assert!(v.record_locks.1.lock().unwrap().is_empty());
}
#[test]
fn original_record_wait_wakes_on_downgrade_close_and_release_without_fd_relookup() {
    for release in 0..3 {
        let mut v = Vfs::default();
        v.set_lock_owner(1);
        let fd = file(&mut v, b"/original");
        let mut peer = v.clone_with_files(false);
        peer.set_lock_owner(2);
        locked(&v, fd, 1);
        let requested = peer.normalize_lock(fd, 0, 0, 0, 8).unwrap();
        let original = peer
            .retain_record_lock(fd, requested)
            .unwrap()
            .wait()
            .unwrap();
        peer.close(fd).unwrap();
        assert_eq!(file(&mut peer, b"/replacement"), fd);
        let wake = Arc::new(Wake::default());
        let target: Arc<dyn IoWake> = wake.clone();
        let signal = IoSignal::new(2, Arc::downgrade(&target));
        let subscription = original.subscribe(&signal);
        assert_eq!(original.try_lock(), Err(Errno(11)));
        match release {
            0 => {
                locked(&v, fd, 0);
            }
            1 => v.close(fd).unwrap(),
            _ => v.release_process_locks(),
        }
        assert!(signal.ready());
        assert_eq!(wake.0.load(Ordering::Relaxed), 1);
        assert_eq!(original.try_lock(), Ok(()));
        let replacement = peer.normalize_lock(fd, 1, 0, 0, 8).unwrap();
        assert_eq!(peer.record_lock_conflict(fd, replacement), Ok(None));
        drop((original, subscription));
        assert!(v.record_locks.1.lock().unwrap().is_empty());
    }
}
#[test]
fn ofd_waits_keep_the_original_description_and_do_not_enter_posix_deadlock_detection() {
    let mut v = Vfs::default();
    let a = file(&mut v, b"/same");
    let b = file(&mut v, b"/same");
    let lock = v.normalize_ofd_lock(a, 1, 0, 0, 8).unwrap();
    v.record_lock_set(a, lock).unwrap();
    let requested = v.normalize_ofd_lock(b, 1, 0, 0, 8).unwrap();
    let wait = v.retain_record_lock(b, requested).unwrap().wait().unwrap();
    assert!(v.record_locks.1.lock().unwrap().is_empty());
    let wake: Arc<dyn IoWake> = Arc::new(Wake::default());
    let signal = IoSignal::new(2, Arc::downgrade(&wake));
    let subscription = wait.subscribe(&signal);
    v.close(b).unwrap();
    assert_eq!(file(&mut v, b"/replacement"), b);
    assert_eq!(wait.try_lock(), Err(Errno(11)));
    v.close(a).unwrap();
    assert!(signal.ready());
    assert_eq!(wait.try_lock(), Ok(()));
    drop((wait, subscription));
}
