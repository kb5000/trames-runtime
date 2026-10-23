// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::uring::tests::{add, cq, setup, sqe};
use trames_memory::{Memory, MemoryError, Permissions};
struct Target;
impl IoWake for Target {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
fn target() -> Arc<dyn IoWake> {
    Arc::new(Target)
}
fn start(s: &UringSnapshot, fd: u32, n: u32, min: u32, m: &mut impl CpuMemory) -> IoAttempt {
    s.start(
        [fd as u64, n as u64, min as u64, u64::from(min != 0), 0, 0],
        m,
        s.task,
        &Arc::downgrade(&target()),
    )
    .unwrap()
}
fn complete(a: IoAttempt, n: u64) {
    assert!(matches!(a,IoAttempt::Complete(Ok(v)) if v==n));
}
fn data(op: u8, fd: u32, address: u64, len: u32, id: u64, flags: u8) -> [u8; 64] {
    let mut s = sqe(op, fd, id);
    s[1] = flags;
    s[16..24].copy_from_slice(&address.to_le_bytes());
    s[24..28].copy_from_slice(&len.to_le_bytes());
    s
}
fn register_buffers(l: &mut Linux, m: &mut Memory, fd: u32, address: u64, len: u64) {
    m.write_array(0x1100, address.to_le_bytes()).unwrap();
    m.write_array(0x1108, len.to_le_bytes()).unwrap();
    l.uring_register([fd as u64, 0, 0x1100, 1, 0, 0], m)
        .unwrap();
}
fn register_files(l: &mut Linux, m: &mut Memory, fd: u32, files: &[i32]) {
    for (i, file) in files.iter().enumerate() {
        m.write_array(0x1200 + i as u64 * 4, file.to_le_bytes())
            .unwrap();
    }
    l.uring_register([fd as u64, 2, 0x1200, files.len() as u64, 0, 0], m)
        .unwrap();
}
#[test]
fn fixed_request_keeps_pin_and_ofd_across_unmap_unregister_and_epoch_handoff() {
    let (mut l, mut m, fd, r) = setup(8);
    let owner = m.instruction_identity().0;
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    register_buffers(&mut l, &mut m, fd, 0x3ffe, 4);
    let pin = r.state.borrow().buffers.as_ref().unwrap()[0].clone();
    register_files(&mut l, &mut m, fd, &[reader as i32]);
    l.vfs.close(reader).unwrap();
    let [replacement, _] = l.vfs.pipe(0).unwrap();
    assert_eq!(reader, replacement);
    m.protect(0x3000, PAGE_SIZE * 2, Permissions::R).unwrap();
    m.unmap(0x3000, PAGE_SIZE * 2).unwrap();
    m.map(0x3000, PAGE_SIZE * 2, Permissions::RW).unwrap();
    m.write(0x3ffe, b"xxxx").unwrap();
    add(&mut m, &r, data(4, 0, 0x3ffe, 4, 1, 1));
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, owner, 7);
    let IoAttempt::Blocked(wait) = start(&s, fd, 1, 1, &mut m) else {
        panic!("expected fixed read wait")
    };
    drop(wait);
    drop(s);
    let handoff = epoch.finish();
    assert_eq!(handoff[0].submitted, Some(1));
    l.uring_register([fd as u64, 1, 0, 0, 0, 0], &mut m)
        .unwrap();
    l.uring_register([fd as u64, 3, 0, 0, 0, 0], &mut m)
        .unwrap();
    l.vfs.write(writer, b"new!").unwrap();
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, owner, 7);
    assert!(epoch.adopt_wait(7, &r, 1, None));
    complete(start(&s, fd, 1, 1, &mut m), 1);
    assert_eq!(cq(&mut m, &r), (1, 4));
    assert_eq!(pin.read(0, 4).unwrap(), b"new!");
    assert_eq!(m.read_array::<4>(0x3ffe).unwrap(), *b"xxxx");
    drop(s);
    assert!(epoch.finish().is_empty());
    let resident = m.resident_bytes();
    drop(pin);
    assert_eq!(resident - m.resident_bytes(), PAGE_SIZE as usize * 2);
}
#[test]
fn fixed_buffer_cross_vm_uses_registered_bytes_and_shared_page_guards() {
    let (mut l, mut m, fd, r) = setup(8);
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    register_buffers(&mut l, &mut m, fd, 0x3000, 8);
    m.write_array(0x3000, 3u64.to_le_bytes()).unwrap();
    let mut child = m.clone();
    child.write_array(0x3000, 9u64.to_le_bytes()).unwrap();
    add(&mut child, &r, data(5, writer, 0x3000, 8, 2, 0));
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, child.instruction_identity().0, 8);
    let mut view = child.parallel_view(&mut Default::default()).unwrap();
    complete(start(&s, fd, 1, 1, &mut view), 1);
    drop(view);
    assert_eq!(cq(&mut child, &r), (2, 8));
    assert_eq!(l.vfs.read(reader, 8).unwrap(), 3u64.to_le_bytes());
    l.vfs.write(writer, &11u64.to_le_bytes()).unwrap();
    add(&mut child, &r, data(4, reader, 0x3000, 8, 3, 0));
    let mut view = child.parallel_view(&mut Default::default()).unwrap();
    complete(start(&s, fd, 1, 1, &mut view), 1);
    drop(view);
    assert_eq!(cq(&mut child, &r), (3, 8));
    assert_eq!(m.read_u64(0x3000).unwrap(), 11);
    assert_eq!(child.read_u64(0x3000).unwrap(), 9);
    assert!(epoch.finish().is_empty());
}
#[test]
fn fixed_sparse_and_bad_indexes_complete_errors_without_disabling_ring() {
    let (mut l, mut m, fd, r) = setup(8);
    register_files(&mut l, &mut m, fd, &[-1]);
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
    add(&mut m, &r, data(22, 0, 0x2000, 1, 4, 1 | 4));
    add(&mut m, &r, sqe(0, 0, 5));
    complete(start(&s, fd, 2, 2, &mut m), 2);
    assert_eq!(cq(&mut m, &r), (4, -9));
    assert_eq!(cq(&mut m, &r), (5, -125));
    add(&mut m, &r, data(22, 50000, 0x2000, 1, 6, 1 | 8));
    add(&mut m, &r, sqe(0, 0, 7));
    complete(start(&s, fd, 2, 2, &mut m), 2);
    assert_eq!(cq(&mut m, &r), (6, -9));
    assert_eq!(cq(&mut m, &r), (7, 0));
    let [reader, _] = l.vfs.pipe(0).unwrap();
    drop(s);
    assert!(epoch.finish().is_empty());
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
    add(&mut m, &r, data(4, reader, 0x2000, 1, 8, 0));
    complete(start(&s, fd, 1, 1, &mut m), 1);
    assert_eq!(cq(&mut m, &r), (8, -14));
    assert!(epoch.finish().is_empty());
}
#[test]
fn linked_short_vector_uses_uncapped_requested_length_and_hardlink_continues() {
    let (mut l, mut m, fd, r) = setup(8);
    let length = crate::MAX_WRITE;
    l.vfs
        .import_file(b"/large", vec![b'a'; length + 1])
        .unwrap();
    let file = l
        .vfs
        .open_at(trames_vfs::AT_FDCWD, b"/large", 2, 0)
        .unwrap();
    m.map(0x100000, (length as u64) + PAGE_SIZE, Permissions::RW)
        .unwrap();
    m.write_array(0x1100, 0x100000u64.to_le_bytes()).unwrap();
    m.write_array(0x1108, (length as u64 + 1).to_le_bytes())
        .unwrap();
    let mut files = trames_vfs::FileEpoch::default();
    let caps = files.capture(&l.vfs, true);
    let mut epoch = UringEpoch::default();
    let s = epoch.capture_with_files(&l.vfs, m.instruction_identity().0, 7, &caps);
    add(&mut m, &r, data(1, file, 0x1100, 1, 9, 4));
    add(&mut m, &r, sqe(0, 0, 10));
    complete(start(&s, fd, 2, 2, &mut m), 2);
    assert_eq!(cq(&mut m, &r), (9, length as i32));
    assert_eq!(cq(&mut m, &r), (10, -125));
    assert_eq!(
        m.read_array::<1>(0x100000 + length as u64 - 1).unwrap(),
        [b'a']
    );
    assert_eq!(m.read_array::<1>(0x100000 + length as u64).unwrap(), [0]);
    add(&mut m, &r, data(22, file, u64::MAX, 1, 11, 8));
    add(&mut m, &r, sqe(0, 0, 12));
    complete(start(&s, fd, 2, 2, &mut m), 2);
    assert_eq!(cq(&mut m, &r), (11, -14));
    assert_eq!(cq(&mut m, &r), (12, 0));
    assert!(epoch.finish().is_empty());
    files.finish();
}
#[test]
fn linked_eagain_and_drain_survive_owner_handoff_without_early_effects() {
    let (mut l, mut m, fd, r) = setup(8);
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    let owner = m.instruction_identity().0;
    add(&mut m, &r, data(22, reader, 0x2000, 1, 13, 4));
    add(&mut m, &r, sqe(0, 0, 14));
    let mut drain = sqe(0, 0, 15);
    drain[1] = 2;
    add(&mut m, &r, drain);
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, owner, 7);
    complete(start(&s, fd, 3, 0, &mut m), 3);
    drop(s);
    let handoff = epoch.finish();
    assert_eq!(handoff.len(), 1);
    assert_eq!(handoff[0].submitted, None);
    assert_eq!(r.state.borrow().pending.len(), 3);
    assert_eq!(r.state.borrow().pending[1].dependency, Some((1, false)));
    assert!(!r.state.borrow().pending[1].started);
    l.vfs.write(writer, b"l").unwrap();
    assert_eq!(
        l.uring_enter([fd as u64, 0, 3, 1, 0, 0], &mut m, None, 7),
        Ok((0, true))
    );
    assert_eq!(cq(&mut m, &r), (13, 1));
    assert_eq!(cq(&mut m, &r), (14, 0));
    assert_eq!(cq(&mut m, &r), (15, 0));
}
#[test]
fn retained_regular_fixed_file_keeps_original_data_permissions_and_position() {
    let (mut l, mut m, fd, r) = setup(8);
    l.vfs.import_file(b"/original", b"abc".to_vec()).unwrap();
    let file = l
        .vfs
        .open_at(trames_vfs::AT_FDCWD, b"/original", 2, 0)
        .unwrap();
    register_files(&mut l, &mut m, fd, &[file as i32]);
    l.vfs.close(file).unwrap();
    let replacement = l
        .vfs
        .open_at(trames_vfs::AT_FDCWD, b"/replacement", 0x42, 0o600)
        .unwrap();
    assert_eq!(replacement, file);
    l.vfs.write(replacement, b"xyz").unwrap();
    let mut files = trames_vfs::FileEpoch::default();
    let caps = files.capture(&l.vfs, true);
    let retained = files.capture_uring(&l.vfs, true);
    let mut epoch = UringEpoch::default();
    let s = epoch.capture_all(&l.vfs, m.instruction_identity().0, 7, &caps, &retained);
    let mut request = data(22, 0, 0x2000, 1, 16, 1 | 4);
    request[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    add(&mut m, &r, request);
    add(&mut m, &r, data(23, 0, 0x2000, 1, 17, 1));
    complete(start(&s, fd, 2, 2, &mut m), 2);
    assert_eq!(cq(&mut m, &r), (16, 1));
    assert_eq!(cq(&mut m, &r), (17, 1));
    assert_eq!(m.read_array::<1>(0x2000).unwrap(), *b"a");
    assert!(epoch.finish().is_empty());
    files.finish();
    assert_eq!(l.vfs.pread(replacement, 3, 0).unwrap(), b"xyz");
    let source = l
        .vfs
        .open_at(trames_vfs::AT_FDCWD, b"/original", 0, 0)
        .unwrap();
    assert_eq!(l.vfs.read(source, 3).unwrap(), b"abc");
}

#[test]
fn ring_fd_aliases_share_one_fixed_table_per_task_and_execute_same_queue() {
    let (mut l, mut m, fd, r) = setup(8);
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    register_files(&mut l, &mut m, fd, &[reader as i32]);
    l.vfs.close(reader).unwrap();
    let alias = l.vfs.dup(fd, 0, false).unwrap();
    let second = l.vfs.dup(alias, 0, false).unwrap();
    let owner = m.instruction_identity().0;
    let mut epoch = UringEpoch::default();
    let a = epoch.capture(&l.vfs, owner, 7);
    let b = epoch.capture(&l.vfs, owner, 8);
    assert!(
        Arc::ptr_eq(&a.fixed[&fd], &a.fixed[&alias])
            && Arc::ptr_eq(&a.fixed[&alias], &a.fixed[&second])
    );
    assert!(Arc::ptr_eq(&a.rings[&fd], &a.rings[&alias]));
    assert!(!Arc::ptr_eq(&a.fixed[&fd], &b.fixed[&fd]));
    let entry = &epoch.owners[&(Rc::as_ptr(&r) as usize)];
    assert_eq!(entry.tasks.len(), 2);
    assert_eq!(entry.fixed.len(), 2);
    l.vfs.write(writer, b"q").unwrap();
    add(&mut m, &r, data(22, 0, 0x2000, 1, 22, 1));
    complete(start(&a, alias, 1, 1, &mut m), 1);
    assert_eq!(cq(&mut m, &r), (22, 1));
    assert_eq!(m.read_array::<1>(0x2000).unwrap(), *b"q");
    assert!(epoch.finish().is_empty());
}

/// A real transfer pauses during gather, after claiming its request. Only the
/// test transport waits; production still uses the unmodified memory model.
struct Gate<M> {
    inner: M,
    entered: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
    once: Cell<bool>,
}
impl<M: CpuMemory> CpuMemory for Gate<M> {
    fn read(&self, a: u64, b: &mut [u8]) -> std::result::Result<(), MemoryError> {
        if a == 0x2100 && !self.once.replace(true) {
            self.entered.send(()).unwrap();
            self.release.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        self.inner.read(a, b)
    }
    fn write(&mut self, a: u64, b: &[u8]) -> std::result::Result<(), MemoryError> {
        if a == 0x2200 && !self.once.replace(true) {
            self.entered.send(()).unwrap();
            self.release.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        self.inner.write(a, b)
    }
    fn check(&self, a: u64, n: usize, x: Access) -> std::result::Result<(), MemoryError> {
        self.inner.check(a, n, x)
    }
    fn check_translation(&self, a: u64) -> std::result::Result<(), MemoryError> {
        self.inner.check_translation(a)
    }
    fn fetch_u32(&self, a: u64) -> std::result::Result<u32, MemoryError> {
        self.inner.fetch_u32(a)
    }
    fn instruction_identity(&self) -> (u64, u64, u64) {
        self.inner.instruction_identity()
    }
    fn instruction_page_identity(
        &self,
        a: u64,
    ) -> std::result::Result<(u64, u64, u64), MemoryError> {
        self.inner.instruction_page_identity(a)
    }
    fn atomic_update<T>(
        &mut self,
        a: u64,
        n: usize,
        f: impl FnOnce(&mut [u8]) -> (T, bool),
    ) -> std::result::Result<T, MemoryError> {
        self.inner.atomic_update(a, n, f)
    }
    fn exclusive_read(&mut self, a: u64, b: &mut [u8]) -> std::result::Result<u128, MemoryError> {
        self.inner.exclusive_read(a, b)
    }
    fn exclusive_write(
        &mut self,
        a: u64,
        b: &[u8],
        t: Option<u128>,
    ) -> std::result::Result<bool, MemoryError> {
        self.inner.exclusive_write(a, b, t)
    }
}
fn add_view(m: &mut impl CpuMemory, r: &Uring, s: [u8; 64]) {
    let tail = u32::from_le_bytes(m.read_array(0x10004).unwrap());
    let slot = tail & (r.entries - 1);
    m.write_array(0x20000 + slot as u64 * 64, s).unwrap();
    m.write_array(
        0x10000 + URING_SQ_ARRAY as u64 + slot as u64 * 4,
        slot.to_le_bytes(),
    )
    .unwrap();
    m.write_array(0x10004, tail.wrapping_add(1).to_le_bytes())
        .unwrap();
}
fn cq_view(m: &mut impl CpuMemory, r: &Uring) -> (u64, i32) {
    let head = u32::from_le_bytes(m.read_array(0x10040).unwrap());
    let b = m
        .read_array::<16>(0x10000 + URING_CQES as u64 + (head & (r.cq_entries - 1)) as u64 * 16)
        .unwrap();
    m.write_array(0x10040, head.wrapping_add(1).to_le_bytes())
        .unwrap();
    (
        u64::from_le_bytes(b[..8].try_into().unwrap()),
        i32::from_le_bytes(b[8..12].try_into().unwrap()),
    )
}
#[test]
fn concurrent_drain_waits_for_claimed_io_but_unrelated_work_uses_same_ring() {
    let (mut l, mut m, fd, r) = setup(8);
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    m.write(0x2100, b"z").unwrap();
    let owner = m.instruction_identity().0;
    add(&mut m, &r, data(23, writer, 0x2100, 1, 18, 0));
    let mut epoch = UringEpoch::default();
    let a = epoch.capture(&l.vfs, owner, 7);
    let b = epoch.capture(&l.vfs, owner, 8);
    let va = m.parallel_view(&mut Default::default()).unwrap();
    let mut vb = m.parallel_view(&mut Default::default()).unwrap();
    let (entered, receive) = std::sync::mpsc::sync_channel(1);
    let (release, blocked) = std::sync::mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let job = scope.spawn(move || {
            let mut memory = Gate {
                inner: va,
                entered,
                release: blocked,
                once: Cell::new(false),
            };
            complete(start(&a, fd, 1, 0, &mut memory), 1);
        });
        receive.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(b.rings[&fd].state.lock().unwrap().inflight, 1);
        add_view(&mut vb, &r, sqe(0, 0, 19));
        let mut drain = sqe(0, 0, 20);
        drain[1] = 2;
        add_view(&mut vb, &r, drain);
        add_view(&mut vb, &r, sqe(0, 0, 21));
        complete(start(&b, fd, 3, 0, &mut vb), 3);
        assert_eq!(cq_view(&mut vb, &r), (19, 0));
        assert_eq!(
            vb.read_array::<4>(0x10040).unwrap(),
            vb.read_array::<4>(0x10044).unwrap()
        );
        release.send(()).unwrap();
        job.join().unwrap();
        assert_eq!(cq_view(&mut vb, &r), (18, 1));
        complete(start(&b, fd, 0, 2, &mut vb), 0);
        assert_eq!(cq_view(&mut vb, &r), (20, 0));
        assert_eq!(cq_view(&mut vb, &r), (21, 0));
    });
    drop(vb);
    assert!(epoch.finish().is_empty());
    assert_eq!(l.vfs.read(reader, 2).unwrap(), b"z");
}

#[path = "async_tests.rs"]
mod asynchronous;
