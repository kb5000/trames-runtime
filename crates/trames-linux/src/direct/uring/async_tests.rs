// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

#[test]
fn invalid_selected_data_waits_for_readiness_without_consuming_pool_or_bytes() {
    let (mut l, mut m, fd, r) = setup(8);
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
    pool(&mut m, &r, 0x60000000, 1, 1, (99, 7), 1);
    complete(start(&s, fd, 1, 1, &mut m), 1);
    assert_eq!(flags(&mut m, &r), (1, 0, 0));
    add(&mut m, &r, selected(22, reader, 7, false, 2));
    complete(start(&s, fd, 1, 0, &mut m), 1);
    {
        let state = s.rings[&fd].state.lock().unwrap();
        assert_eq!(state.provided[&7].slots(), 1);
        assert_eq!(state.pending.len(), 1);
        assert_eq!(state.tail, s.rings[&fd].queue.load(64));
    }
    l.vfs.write(writer, b"x").unwrap();
    complete(start(&s, fd, 0, 1, &mut m), 0);
    assert_eq!(flags(&mut m, &r), (2, -14, 1 | 99 << 16));
    assert_eq!(l.vfs.read(reader, 1).unwrap(), b"x");
    assert_eq!(s.rings[&fd].state.lock().unwrap().provided[&7].slots(), 0);
}

fn flags(m: &mut impl CpuMemory, r: &Uring) -> (u64, i32, u32) {
    let head = u32::from_le_bytes(m.read_array(0x10040).unwrap());
    let b = m
        .read_array::<16>(0x10000 + URING_CQES as u64 + (head & (r.cq_entries - 1)) as u64 * 16)
        .unwrap();
    m.write_array(0x10040, head.wrapping_add(1).to_le_bytes())
        .unwrap();
    (
        u64::from_le_bytes(b[..8].try_into().unwrap()),
        i32::from_le_bytes(b[8..12].try_into().unwrap()),
        u32::from_le_bytes(b[12..].try_into().unwrap()),
    )
}
fn pool(m: &mut Memory, r: &Uring, base: u64, len: u32, count: u32, ids: (u64, u16), tag: u64) {
    let (id, group) = ids;
    let mut s = data(31, count, base, len, tag, 0);
    s[8..16].copy_from_slice(&id.to_le_bytes());
    s[40..42].copy_from_slice(&group.to_le_bytes());
    add(m, r, s);
}
fn selected(op: u8, fd: u32, group: u16, multi: bool, tag: u64) -> [u8; 64] {
    let mut s = data(op, fd, 0, if multi { 0 } else { 1 }, tag, 32);
    s[40..42].copy_from_slice(&group.to_le_bytes());
    s[2..4].copy_from_slice(&(if multi { 2u16 } else { 0 }).to_le_bytes());
    s
}
fn timeout(m: &mut Memory, r: &Uring, tag: u64, offset: u64, ns: u64, mode: (u8, u32, u8)) {
    let (op, flags, link) = mode;
    m.write_array(0x2800, [0u8; 16]).unwrap();
    m.write_array(0x2808, ns.to_le_bytes()).unwrap();
    let mut s = data(op, u32::MAX, 0x2800, 1, tag, link);
    s[8..16].copy_from_slice(&offset.to_le_bytes());
    s[28..32].copy_from_slice(&flags.to_le_bytes());
    add(m, r, s);
}

#[test]
fn selected_buffers_preserve_vm_authority_errors_and_empty_retry() {
    let (mut l, mut m, fd, r) = setup(8);
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
    pool(&mut m, &r, 0x2200, 1, 2, (40, 9), 1);
    complete(start(&s, fd, 1, 1, &mut m), 1);
    assert_eq!(flags(&mut m, &r), (1, 0, 0));
    add(&mut m, &r, selected(22, reader, 9, false, 2));
    complete(start(&s, fd, 1, 0, &mut m), 1);
    assert_eq!(s.rings[&fd].state.lock().unwrap().provided[&9].slots(), 2);
    l.vfs.write(writer, b"ab").unwrap();
    complete(start(&s, fd, 0, 1, &mut m), 0);
    assert_eq!(flags(&mut m, &r), (2, 1, 1 | 40 << 16));
    assert_eq!(m.read_array::<1>(0x2200).unwrap(), *b"a");
    // Another VM cannot use the original VM's provided virtual address.
    drop(s);
    let mut child = m.clone();
    let child_s = epoch.capture(&l.vfs, child.instruction_identity().0, 8);
    add(&mut child, &r, selected(22, reader, 9, false, 3));
    complete(start(&child_s, fd, 1, 1, &mut child), 1);
    assert_eq!(flags(&mut child, &r), (3, -14, 0));
    assert_eq!(l.vfs.read(reader, 1).unwrap(), b"b");
    assert_eq!(
        child_s.rings[&fd].state.lock().unwrap().provided[&9].slots(),
        1
    );
    drop(child_s);
    epoch.finish();
    assert_eq!(r.state.borrow().provided[&9].slots(), 1);
}

#[test]
fn multishot_recv_keeps_link_until_terminal_and_cancels_without_stale_flags() {
    let (mut l, mut m, fd, r) = setup(8);
    let [a, b] = l.vfs.socketpair(1, 1, 0).unwrap();
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
    pool(&mut m, &r, 0x2200, 1, 3, (50, 10), 1);
    complete(start(&s, fd, 1, 1, &mut m), 1);
    flags(&mut m, &r);
    let mut recv = selected(27, a, 10, true, 2);
    recv[1] |= 4;
    add(&mut m, &r, recv);
    add(&mut m, &r, sqe(0, 0, 3));
    complete(start(&s, fd, 2, 0, &mut m), 2);
    l.vfs.write(b, b"ab").unwrap();
    complete(start(&s, fd, 0, 2, &mut m), 0);
    assert_eq!(flags(&mut m, &r), (2, 1, 3 | 50 << 16));
    assert_eq!(flags(&mut m, &r), (2, 1, 3 | 51 << 16));
    assert_eq!(s.rings[&fd].state.lock().unwrap().active.len(), 2);
    add(&mut m, &r, data(14, u32::MAX, 2, 0, 4, 0));
    complete(start(&s, fd, 1, 3, &mut m), 1);
    assert_eq!(flags(&mut m, &r), (2, -125, 0));
    assert_eq!(flags(&mut m, &r), (4, 0, 0));
    assert_eq!(flags(&mut m, &r), (3, -125, 0));
    let state = s.rings[&fd].state.lock().unwrap();
    assert!(state.active.is_empty() && state.completed.is_empty() && state.dependencies.is_empty());
    drop(state);
    drop(s);
    assert!(epoch.finish().is_empty());
}

#[test]
fn multishot_poll_preserves_epochs_and_update_remove_rules() {
    let (mut l, mut m, fd, r) = setup(8);
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
    let mut poll = data(6, reader, 0, 1, 1, 0);
    poll[28..32].copy_from_slice(&1u32.to_le_bytes());
    add(&mut m, &r, poll);
    complete(start(&s, fd, 1, 0, &mut m), 1);
    for byte in *b"xy" {
        l.vfs.write(writer, &[byte]).unwrap();
        complete(start(&s, fd, 0, 1, &mut m), 0);
        assert_eq!(flags(&mut m, &r), (1, 1, 2));
        complete(start(&s, fd, 0, 0, &mut m), 0);
        assert_eq!(s.rings[&fd].queue.load(64), s.rings[&fd].queue.load(68));
    }
    let mut update = data(7, u32::MAX, 1, 6, 3, 0);
    update[8..16].copy_from_slice(&2u64.to_le_bytes());
    update[28..32].copy_from_slice(&1u32.to_le_bytes());
    add(&mut m, &r, update);
    complete(start(&s, fd, 1, 2, &mut m), 1);
    assert_eq!(flags(&mut m, &r), (3, 0, 0));
    assert_eq!(flags(&mut m, &r), (2, 1, 2));
    add(&mut m, &r, data(7, u32::MAX, 2, 0, 4, 0));
    complete(start(&s, fd, 1, 2, &mut m), 1);
    assert_eq!(flags(&mut m, &r), (2, -125, 0));
    assert_eq!(flags(&mut m, &r), (4, 0, 0));
    drop(s);
    assert!(epoch.finish().is_empty());
}

#[test]
fn timeout_relative_issue_count_multishot_and_updates_use_imported_values() {
    let (l, mut m, fd, r) = setup(8);
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
    timeout(&mut m, &r, 1, 2, 0, (11, 64, 0));
    complete(start(&s, fd, 1, 2, &mut m), 1);
    assert_eq!(flags(&mut m, &r), (1, -62, 2));
    assert_eq!(flags(&mut m, &r), (1, -62, 0));
    assert_eq!(s.rings[&fd].state.lock().unwrap().completion_count, 0);
    timeout(&mut m, &r, 2, 1, 999999999, (11, 0, 0));
    add(&mut m, &r, sqe(0, 0, 3));
    complete(start(&s, fd, 2, 2, &mut m), 2);
    assert_eq!(flags(&mut m, &r), (3, 0, 0));
    assert_eq!(flags(&mut m, &r), (2, 0, 0));
    timeout(&mut m, &r, 4, 0, 999999999, (11, 0, 0));
    complete(start(&s, fd, 1, 0, &mut m), 1);
    m.write_array(0x2800, [0u8; 16]).unwrap();
    let mut update = data(12, u32::MAX, 4, 0, 5, 0);
    update[8..16].copy_from_slice(&0x2800u64.to_le_bytes());
    update[28..32].copy_from_slice(&2u32.to_le_bytes());
    add(&mut m, &r, update);
    complete(start(&s, fd, 1, 2, &mut m), 1);
    assert_eq!(flags(&mut m, &r), (5, 0, 0));
    assert_eq!(flags(&mut m, &r), (4, -62, 0));
    drop(s);
    assert!(epoch.finish().is_empty());
}

#[test]
fn linked_timeout_can_cancel_issued_predecessor_and_preserves_drain_and_chain() {
    let (mut l, mut m, fd, r) = setup(8);
    let [reader, _writer] = l.vfs.pipe(0).unwrap();
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
    add(&mut m, &r, data(22, reader, 0x2200, 1, 1, 2 | 4));
    timeout(&mut m, &r, 2, 0, 0, (15, 0, 4));
    add(&mut m, &r, sqe(0, 0, 3));
    complete(start(&s, fd, 3, 3, &mut m), 3);
    assert_eq!(flags(&mut m, &r), (1, -125, 0));
    assert_eq!(flags(&mut m, &r), (2, -62, 0));
    assert_eq!(flags(&mut m, &r), (3, -125, 0));
    drop(s);
    assert!(epoch.finish().is_empty());
}

#[test]
fn ext_arg_wait_handoff_keeps_original_deadline_without_reimport_or_resubmit() {
    let (l, mut m, fd, r) = setup(8);
    m.write_array(0x2600, [0u8; 24]).unwrap();
    m.write_array(0x2610, 0x2800u64.to_le_bytes()).unwrap();
    m.write_array(0x2800, [0u8; 16]).unwrap();
    m.write_array(0x2800, 3600u64.to_le_bytes()).unwrap();
    let args = [fd as u64, 0, 1, 9, 0x2600, 24];
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
    let IoAttempt::Blocked(wait) = s
        .start(args, &mut m, 7, &Arc::downgrade(&target()))
        .unwrap()
    else {
        panic!("deadline wait")
    };
    let original = wait.deadline.unwrap();
    assert_eq!(wait.wake_deadline(), Some(original));
    drop(wait);
    drop(s);
    let handoff = epoch.finish();
    assert_eq!(handoff[0].deadline, Some(original));
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
    assert!(epoch.adopt_wait(7, &r, 0, Some(original)));
    m.unmap(0x2000, PAGE_SIZE).unwrap();
    let IoAttempt::Blocked(wait) = s
        .start(args, &mut m, 7, &Arc::downgrade(&target()))
        .unwrap()
    else {
        panic!("saved deadline")
    };
    assert_eq!(wait.deadline, Some(original));
    s.rings[&fd]
        .state
        .lock()
        .unwrap()
        .waits
        .get_mut(&7)
        .unwrap()
        .1 = Some(Instant::now());
    assert!(matches!(
        s.resume(wait, &mut m),
        IoAttempt::Complete(Err(Errno(62)))
    ));
    drop(s);
    assert!(epoch.finish().is_empty());
}

#[test]
fn in_flight_cancel_reports_already_executing_and_other_worker_keeps_running() {
    let (mut l, mut m, fd, r) = setup(8);
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    m.write(0x2100, b"z").unwrap();
    let owner = m.instruction_identity().0;
    add(&mut m, &r, data(23, writer, 0x2100, 1, 1, 0));
    let mut epoch = UringEpoch::default();
    let a = epoch.capture(&l.vfs, owner, 7);
    let b = epoch.capture(&l.vfs, owner, 8);
    let va = m.parallel_view(&mut Default::default()).unwrap();
    let mut vb = va.clone();
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
        add_view(&mut vb, &r, data(14, u32::MAX, 1, 0, 2, 0));
        add_view(&mut vb, &r, sqe(0, 0, 3));
        complete(start(&b, fd, 2, 2, &mut vb), 2);
        assert_eq!(flags(&mut vb, &r), (2, -114, 0));
        assert_eq!(flags(&mut vb, &r), (3, 0, 0));
        release.send(()).unwrap();
        job.join().unwrap();
        assert_eq!(flags(&mut vb, &r), (1, 1, 0));
    });
    assert_eq!(l.vfs.read(reader, 1).unwrap(), b"z");
    drop(vb);
    drop(b);
    assert!(epoch.finish().is_empty());
}

#[test]
fn registered_descriptor_ring_keeps_original_pin_and_controls_stay_local() {
    use trames_vfs::{UringBufferGroup, UringBufferSource};
    let (mut l, mut m, fd, r) = setup(8);
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    let pin = Arc::new(m.pin_rw(0x3000, 32).unwrap());
    let owner = m.instruction_identity().0;
    let mut descriptor = [0; 16];
    descriptor[..8].copy_from_slice(&0x4000u64.to_le_bytes());
    descriptor[8..12].copy_from_slice(&1u32.to_le_bytes());
    descriptor[12..14].copy_from_slice(&65535u16.to_le_bytes());
    pin.write(16, &descriptor).unwrap();
    pin.write(14, &0u16.to_le_bytes()).unwrap();
    r.state.borrow_mut().provided.insert(
        7,
        UringBufferGroup {
            owner,
            source: UringBufferSource::Ring {
                memory: pin.clone(),
                head: u16::MAX,
                entries: 2,
            },
        },
    );
    m.unmap(0x3000, PAGE_SIZE).unwrap();
    m.map(0x3000, PAGE_SIZE, Permissions::RW).unwrap();
    m.write_array(0x300e, 99u16.to_le_bytes()).unwrap();
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, owner, 7);
    m.write_array(0x2000, [0u8; 40]).unwrap();
    m.write_array(0x2000, 7u32.to_le_bytes()).unwrap();
    complete(
        s.register([fd as u64, 26, 0x2000, 1, 0, 0], &mut m, 7)
            .unwrap(),
        0,
    );
    assert_eq!(
        u32::from_le_bytes(m.read_array::<4>(0x2004).unwrap()),
        65535
    );
    l.vfs.write(writer, b"x").unwrap();
    add(&mut m, &r, selected(22, reader, 7, false, 1));
    complete(start(&s, fd, 1, 1, &mut m), 1);
    assert_eq!(flags(&mut m, &r), (1, 1, 1 | 65535 << 16));
    assert_eq!(m.read_array::<1>(0x4000).unwrap(), *b"x");
    m.write_array(0x2000, [0u8; 40]).unwrap();
    m.write_array(0x2000, 7u32.to_le_bytes()).unwrap();
    complete(
        s.register([fd as u64, 26, 0x2000, 1, 0, 0], &mut m, 7)
            .unwrap(),
        0,
    );
    assert_eq!(u32::from_le_bytes(m.read_array::<4>(0x2004).unwrap()), 0);
    m.write_array(0x2000, [0u8; 40]).unwrap();
    m.write_array(0x200c, 7u16.to_le_bytes()).unwrap();
    complete(
        s.register([fd as u64, 23, 0x2000, 1, 0, 0], &mut m, 7)
            .unwrap(),
        0,
    );
    complete(
        s.register([fd as u64, 8, 0x2000, 64, 0, 0], &mut m, 7)
            .unwrap(),
        0,
    );
    assert_eq!(m.read_array::<2>(0x2000).unwrap(), [57, 58]);
    assert!(s.rings[&fd].state.lock().unwrap().provided.is_empty());
    drop(s);
    assert!(epoch.finish().is_empty());
    assert!(r.state.borrow().provided.is_empty());
}

#[test]
fn worker_unregister_buffers_keeps_accepted_pin_and_rejects_new_fixed_io() {
    let (mut l, mut m, fd, r) = setup(8);
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    register_buffers(&mut l, &mut m, fd, 0x3000, 8);
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
    add(&mut m, &r, data(4, reader, 0x3000, 1, 1, 0));
    complete(start(&s, fd, 1, 0, &mut m), 1);
    complete(
        s.register([fd as u64, 1, 0, 0, 0, 0], &mut m, 7).unwrap(),
        0,
    );
    add(&mut m, &r, data(4, reader, 0x3000, 1, 2, 0));
    complete(start(&s, fd, 1, 1, &mut m), 1);
    assert_eq!(flags(&mut m, &r), (2, -14, 0));
    l.vfs.write(writer, b"x").unwrap();
    complete(start(&s, fd, 0, 1, &mut m), 0);
    assert_eq!(flags(&mut m, &r), (1, 1, 0));
    assert_eq!(m.read_array::<1>(0x3000).unwrap(), *b"x");
    drop(s);
    assert!(epoch.finish().is_empty());
    assert!(r.state.borrow().buffers.is_none());
}

#[test]
fn multishot_backpressure_reserves_terminal_space_and_rotates_past_budget() {
    let (l, mut m, fd, r) = setup(2);
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
    timeout(&mut m, &r, 1, 0, 0, (11, 64, 0));
    complete(start(&s, fd, 1, 0, &mut m), 1);
    {
        let state = s.rings[&fd].state.lock().unwrap();
        assert_eq!(s.rings[&fd].outstanding(&state), 16);
        assert!(s.rings[&fd].backpressured(&state, &state.pending[0]));
        assert_eq!(state.active.len(), 1);
    }
    for _ in 0..4 {
        assert_eq!(flags(&mut m, &r), (1, -62, 2));
    }
    add(&mut m, &r, data(14, u32::MAX, 1, 0, 2, 0));
    complete(start(&s, fd, 1, 0, &mut m), 1);
    {
        let state = s.rings[&fd].state.lock().unwrap();
        assert!(state.active.is_empty());
        assert!(s.rings[&fd].outstanding(&state) <= 16);
    }
    drop(s);
    epoch.finish();
    let (mut l, mut m, fd, r) = setup(128);
    let event = l.vfs.eventfd(1, 0).unwrap();
    let idle = l.vfs.eventfd(0, 0).unwrap();
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
    for id in 1..=128 {
        let mut p = data(6, event, 0, 1, id, 0);
        p[28..32].copy_from_slice(&1u32.to_le_bytes());
        add(&mut m, &r, p);
    }
    complete(start(&s, fd, 128, 0, &mut m), 128);
    for id in 1..=64 {
        assert_eq!(flags(&mut m, &r), (id, 1, 2));
    }
    complete(start(&s, fd, 0, 0, &mut m), 0);
    for id in 65..=128 {
        assert_eq!(flags(&mut m, &r), (id, 1, 2));
    }
    let mut p = data(6, idle, 0, 1, 129, 0);
    p[28..32].copy_from_slice(&1u32.to_le_bytes());
    add(&mut m, &r, p);
    complete(start(&s, fd, 1, 0, &mut m), 1);
    l.vfs.write(event, &1u64.to_le_bytes()).unwrap();
    complete(start(&s, fd, 0, 1, &mut m), 0);
    assert!(
        s.rings[&fd]
            .queue
            .load(68)
            .wrapping_sub(s.rings[&fd].queue.load(64))
            > 0
    );
}

#[test]
fn same_group_leases_are_distinct_and_other_same_ring_work_is_parallel() {
    let (mut l, mut m, fd, r) = setup(8);
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    let owner = m.instruction_identity().0;
    let mut epoch = UringEpoch::default();
    let a = epoch.capture(&l.vfs, owner, 7);
    let b = epoch.capture(&l.vfs, owner, 8);
    pool(&mut m, &r, 0x2200, 1, 2, (60, 20), 1);
    complete(start(&a, fd, 1, 1, &mut m), 1);
    flags(&mut m, &r);
    l.vfs.write(writer, b"ab").unwrap();
    add(&mut m, &r, selected(22, reader, 20, false, 2));
    let va = m.parallel_view(&mut Default::default()).unwrap();
    let mut vb = va.clone();
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
        add_view(&mut vb, &r, selected(22, reader, 20, false, 3));
        add_view(&mut vb, &r, sqe(0, 0, 4));
        let IoAttempt::Blocked(wait) = start(&b, fd, 2, 2, &mut vb) else {
            panic!("second buffer lease must wait")
        };
        assert_eq!(flags(&mut vb, &r), (4, 0, 0));
        release.send(()).unwrap();
        job.join().unwrap();
        assert!(wait.signal.ready());
        complete(b.resume(wait, &mut vb), 2);
        assert_eq!(flags(&mut vb, &r), (2, 1, 1 | 60 << 16));
        assert_eq!(flags(&mut vb, &r), (3, 1, 1 | 61 << 16));
        assert_eq!(vb.read_array::<2>(0x2200).unwrap(), *b"ab");
    });
    drop(vb);
    drop(b);
    assert!(epoch.finish().is_empty());
}

#[test]
fn cq_ppoll_and_epoll_drive_pending_bytes_and_wait_on_original_resource() {
    let (mut l, mut m, fd, r) = setup(8);
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    let epoll = l.vfs.epoll_create(0).unwrap();
    l.vfs.epoll_ctl(epoll, 1, fd, 1 | 0x80000000, 123).unwrap();
    let mut epoch = UringEpoch::default();
    let uring = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
    let direct = DirectSyscalls::new(l.vfs.direct_descriptors()).with_urings(uring);
    let target = target();
    let wake = Arc::downgrade(&target);
    add(&mut m, &r, data(22, reader, 0x2200, 1, 1, 0));
    complete(
        direct
            .start(426, [fd as u64, 1, 0, 0, 0, 0], &mut m, 7, &wake, None)
            .unwrap(),
        1,
    );
    let mut poll = [0u8; 8];
    poll[..4].copy_from_slice(&fd.to_le_bytes());
    poll[4..6].copy_from_slice(&1u16.to_le_bytes());
    m.write_array(0x2600, poll).unwrap();
    let IoAttempt::Blocked(wait) = direct
        .start(73, [0x2600, 1, 0, 0, 0, 0], &mut m, 7, &wake, None)
        .unwrap()
    else {
        panic!("CQ ppoll must park")
    };
    l.vfs.write(writer, b"p").unwrap();
    assert!(wait.signal.ready());
    complete(direct.resume(wait, &mut m), 1);
    assert_eq!(m.read_array::<2>(0x2606).unwrap(), 1u16.to_le_bytes());
    assert_eq!(flags(&mut m, &r), (1, 1, 0));
    add(&mut m, &r, data(22, reader, 0x2201, 1, 2, 0));
    complete(
        direct
            .start(426, [fd as u64, 1, 0, 0, 0, 0], &mut m, 7, &wake, None)
            .unwrap(),
        1,
    );
    let IoAttempt::Blocked(wait) = direct
        .start(
            22,
            [epoll as u64, 0x2600, 1, u32::MAX as u64, 0, 0],
            &mut m,
            7,
            &wake,
            None,
        )
        .unwrap()
    else {
        panic!("CQ epoll must park")
    };
    l.vfs.write(writer, b"e").unwrap();
    assert!(wait.signal.ready());
    complete(direct.resume(wait, &mut m), 1);
    assert_eq!(m.read_array::<4>(0x2600).unwrap(), 1u32.to_le_bytes());
    assert_eq!(m.read_u64(0x2608).unwrap(), 123);
    assert_eq!(flags(&mut m, &r), (2, 1, 0));
    assert_eq!(m.read_array::<2>(0x2200).unwrap(), *b"pe");
    drop(direct);
    assert!(epoch.finish().is_empty());
}

#[test]
fn cq_observer_does_not_borrow_another_tasks_guest_memory() {
    let (mut l, mut m, fd, r) = setup(8);
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    let owner = m.instruction_identity().0;
    let mut epoch = UringEpoch::default();
    let a = epoch.capture(&l.vfs, owner, 7);
    let b = epoch.capture(&l.vfs, owner, 8);
    add(&mut m, &r, data(22, reader, 0x2200, 1, 1, 0));
    complete(start(&a, fd, 1, 0, &mut m), 1);
    l.vfs.write(writer, b"x").unwrap();
    let direct = DirectSyscalls::new(l.vfs.direct_descriptors()).with_urings(b);
    let mut poll = [0u8; 8];
    poll[..4].copy_from_slice(&fd.to_le_bytes());
    poll[4..6].copy_from_slice(&1u16.to_le_bytes());
    m.write_array(0x2600, poll).unwrap();
    assert!(matches!(
        direct
            .start(
                73,
                [0x2600, 1, 0, 0, 0, 0],
                &mut m,
                8,
                &Arc::downgrade(&target()),
                None
            )
            .unwrap(),
        IoAttempt::Checkpoint
    ));
    assert_eq!(m.read_array::<1>(0x2200).unwrap(), [0]);
    assert_eq!(l.vfs.read(reader, 1).unwrap(), b"x");
    l.vfs.write(writer, b"y").unwrap();
    complete(start(&a, fd, 0, 1, &mut m), 0);
    complete(
        direct
            .start(
                73,
                [0x2600, 1, 0, 0, 0, 0],
                &mut m,
                8,
                &Arc::downgrade(&target()),
                None,
            )
            .unwrap(),
        1,
    );
    assert_eq!(flags(&mut m, &r), (1, 1, 0));
    drop(a);
    drop(direct);
    assert!(epoch.finish().is_empty());
}
