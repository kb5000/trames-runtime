// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::uring::tests::{add, cq, setup, sqe};
use std::{
    cell::Cell,
    io::{Read, Write},
    net::{Ipv4Addr, TcpListener},
    os::{fd::AsFd, unix::net::UnixStream},
};

struct Target(Arc<trames_vfs::HostEvents>);
impl IoWake for Target {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
    fn host_events(&self) -> Option<Arc<trames_vfs::HostEvents>> {
        Some(self.0.clone())
    }
}
fn target() -> (Arc<dyn IoWake>, Arc<trames_vfs::HostEvents>) {
    let hub = trames_vfs::HostEvents::new().unwrap();
    (Arc::new(Target(hub.clone())), hub)
}
fn mark_unused(sources: &mut WaitSources) {
    for subscription in sources.hosts.values_mut() {
        subscription.used = false;
    }
}
fn wait(hub: &trames_vfs::HostEvents) {
    hub.wait(Some(Instant::now() + Duration::from_secs(2)))
        .unwrap();
}

#[test]
fn retained_host_interest_rearms_without_reopening_and_actors_remain_independent() {
    let (t, hub) = target();
    let weak = Arc::downgrade(&t);
    let first = IoSignal::new(7, weak.clone());
    let second = IoSignal::new(8, weak.clone());
    let (mut socket, mut peer) = UnixStream::pair().unwrap();
    socket.set_nonblocking(true).unwrap();
    let mut a = WaitSources::default();
    let mut b = WaitSources::default();
    let opens = Cell::new(0);
    a.host((1, false), &first, &weak, || {
        opens.set(opens.get() + 1);
        socket.as_fd().try_clone_to_owned().map(Into::into)
    })
    .unwrap();
    // An unrelated wake must neither duplicate the host FD nor register again.
    for _ in 0..128 {
        mark_unused(&mut a);
        a.host((1, false), &first, &weak, || panic!("reopened host FD"))
            .unwrap();
    }
    assert_eq!(opens.get(), 1);
    b.host((1, false), &second, &weak, || {
        socket.as_fd().try_clone_to_owned().map(Into::into)
    })
    .unwrap();
    peer.write_all(b"a").unwrap();
    wait(&hub);
    assert!(first.ready() && second.ready());
    assert_eq!(socket.read(&mut [0]).unwrap(), 1);
    first.reset();
    second.reset();
    mark_unused(&mut a);
    a.host((1, false), &first, &weak, || panic!("rearm must reuse FD"))
        .unwrap();
    hub.wait(Some(Instant::now())).unwrap();
    assert!(!first.ready() && !second.ready());
    // Cancel the first actor. Only the independently rearmed second may wake.
    drop(a);
    mark_unused(&mut b);
    b.host((1, false), &second, &weak, || {
        panic!("second actor reopened FD")
    })
    .unwrap();
    peer.shutdown(std::net::Shutdown::Write).unwrap();
    wait(&hub);
    assert!(!first.ready() && second.ready());
    assert_eq!(socket.read(&mut [0]).unwrap(), 0);
    // No pending interest means no wait-scoped FD lease remains.
    assert!(b.refresh(&[], 0, 8, &second, &weak));
    assert!(!b.external());
    drop(socket);
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
}

#[test]
fn host_interest_distinguishes_direction_and_replacement_ofd() {
    let (t, hub) = target();
    let weak = Arc::downgrade(&t);
    let signal = IoSignal::new(7, weak.clone());
    let (a, _peer_a) = UnixStream::pair().unwrap();
    let (b, mut peer_b) = UnixStream::pair().unwrap();
    let mut sources = WaitSources::default();
    for write in [false, true] {
        sources
            .host((1, write), &signal, &weak, || {
                a.as_fd().try_clone_to_owned().map(Into::into)
            })
            .unwrap();
    }
    assert_eq!(sources.hosts.len(), 2);
    // A reused guest FD has a different retained OFD identity. It must acquire
    // a new lease; a stale event may never target the replacement description.
    assert!(sources.refresh(&[], 0, 7, &signal, &weak));
    signal.reset();
    sources
        .host((2, false), &signal, &weak, || {
            b.as_fd().try_clone_to_owned().map(Into::into)
        })
        .unwrap();
    hub.wait(Some(Instant::now())).unwrap();
    assert!(!signal.ready());
    peer_b.write_all(b"x").unwrap();
    wait(&hub);
    assert!(signal.ready());
}

#[test]
fn native_wait_retains_transport_and_releases_it_on_worker_cancellation() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let mut vfs = trames_vfs::Vfs::default();
    vfs.configure_network(trames_vfs::NetworkMode::Loopback)
        .unwrap();
    let fd = vfs.socket(2, 1, 0).unwrap();
    let socket = vfs.socket_fd(fd).unwrap();
    assert!(matches!(
        socket.connect(listener.local_addr().unwrap()),
        Ok(()) | Err(trames_net::NetError(115))
    ));
    let (mut peer, _) = listener.accept().unwrap();
    assert_eq!(socket.connect_complete(), Ok(true));
    let tcp = vfs.direct_network().get(fd).unwrap().tcp.clone();
    let (t, hub) = target();
    let weak = Arc::downgrade(&t);
    let signal = IoSignal::new(7, weak.clone());
    let mut sources = WaitSources::default();
    sources
        .host((1, false), &signal, &weak, || tcp_wait_fd(&tcp))
        .unwrap();
    drop(socket);
    vfs.close(fd).unwrap();
    drop(vfs);
    assert_eq!(tcp.send(b"a", 0), Ok(1));
    let mut byte = [0];
    peer.read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"a");
    peer.write_all(b"b").unwrap();
    wait(&hub);
    assert!(signal.ready());
    assert_eq!(tcp.recv(1, 0).unwrap(), b"b");
    std::thread::spawn(move || drop(sources)).join().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    assert_eq!(tcp.send(b"stale", 0), Err(trames_net::NetError(9)));
}

fn read(fd: u32, address: u64, tag: u64) -> [u8; 64] {
    let mut s = sqe(22, fd, tag);
    s[16..24].copy_from_slice(&address.to_le_bytes());
    s[24..28].copy_from_slice(&1u32.to_le_bytes());
    s
}

#[test]
fn native_ring_aliases_share_one_interest_and_survive_retry_partial_read_and_eof() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let (mut l, mut m, fd, ring) = setup(8);
    l.vfs
        .configure_network(trames_vfs::NetworkMode::Loopback)
        .unwrap();
    let socket = l.vfs.socket(2, 1, 0).unwrap();
    let original = l.vfs.socket_fd(socket).unwrap();
    assert!(matches!(
        original.connect(listener.local_addr().unwrap()),
        Ok(()) | Err(trames_net::NetError(115))
    ));
    let mut peer = listener.accept().unwrap().0;
    assert_eq!(original.connect_complete(), Ok(true));
    let alias = l.vfs.dup(socket, 0, false).unwrap();
    add(&mut m, &ring, read(socket, 0x2200, 1));
    add(&mut m, &ring, read(alias, 0x2201, 2));
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
    let (t, hub) = target();
    let blocked = s
        .start([fd as u64, 2, 2, 1, 0, 0], &mut m, 7, &Arc::downgrade(&t))
        .unwrap();
    let IoAttempt::Blocked(mut pending) = blocked else {
        panic!("expected TCP wait")
    };
    for _ in 0..32 {
        assert_eq!(pending.uring.as_ref().unwrap().sources.hosts.len(), 1);
        let IoAttempt::Blocked(next) = s.resume(pending, &mut m) else {
            panic!("idle retry completed")
        };
        pending = next;
    }
    peer.write_all(b"x").unwrap();
    wait(&hub);
    assert!(pending.signal.ready());
    let IoAttempt::Blocked(pending) = s.resume(pending, &mut m) else {
        panic!("second read must wait")
    };
    assert_eq!(m.read_array::<1>(0x2200).unwrap(), *b"x");
    assert_eq!(pending.uring.as_ref().unwrap().sources.hosts.len(), 1);
    peer.shutdown(std::net::Shutdown::Write).unwrap();
    wait(&hub);
    assert!(matches!(
        s.resume(pending, &mut m),
        IoAttempt::Complete(Ok(2))
    ));
    assert_eq!(cq(&mut m, &ring), (1, 1));
    assert_eq!(cq(&mut m, &ring), (2, 0));
    drop(s);
    assert!(epoch.finish().is_empty());
    drop(original);
    l.vfs.close(socket).unwrap();
    l.vfs.close(alias).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
}

#[test]
fn local_ring_retries_deduplicate_resources_and_drop_finished_interests() {
    let (mut l, mut m, fd, ring) = setup(8);
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    add(&mut m, &ring, read(reader, 0x2200, 1));
    add(&mut m, &ring, read(reader, 0x2201, 2));
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
    let (t, _hub) = target();
    let signal = IoSignal::new(7, Arc::downgrade(&t));
    assert!(matches!(
        s.start([fd as u64, 2, 0, 0, 0, 0], &mut m, 7, &Arc::downgrade(&t)),
        Some(IoAttempt::Complete(Ok(2)))
    ));
    let rings = [s.rings[&fd].clone()];
    let mut sources = WaitSources::default();
    for _ in 0..32 {
        signal.reset();
        assert!(sources.refresh(&rings, s.owner, 7, &signal, &Arc::downgrade(&t)));
        assert_eq!(sources.local.len(), 2); // CQ plus one original pipe.
        assert!(!signal.ready());
    }
    l.vfs.write(writer, b"xy").unwrap();
    assert!(signal.ready());
    assert!(matches!(
        s.start([fd as u64, 0, 2, 1, 0, 0], &mut m, 7, &Arc::downgrade(&t)),
        Some(IoAttempt::Complete(Ok(0)))
    ));
    assert!(sources.refresh(&rings, s.owner, 7, &signal, &Arc::downgrade(&t)));
    assert_eq!(sources.local.len(), 1); // Only CQ after both reads complete.
    signal.reset();
    l.vfs.write(writer, b"z").unwrap();
    assert!(
        !signal.ready(),
        "completed requests retained a pipe listener"
    );
}

#[test]
fn cq_aliases_do_not_multiply_a_rings_progress_budget() {
    let (l, mut m, fd, ring) = setup(128);
    m.write_array(0x2800, [0u8; 16]).unwrap();
    let mut timeout = sqe(11, u32::MAX, 1);
    timeout[16..24].copy_from_slice(&0x2800u64.to_le_bytes());
    timeout[24..28].copy_from_slice(&1u32.to_le_bytes());
    timeout[28..32].copy_from_slice(&64u32.to_le_bytes());
    add(&mut m, &ring, timeout);
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
    let (t, _hub) = target();
    assert!(matches!(
        s.start([fd as u64, 1, 0, 0, 0, 0], &mut m, 7, &Arc::downgrade(&t)),
        Some(IoAttempt::Complete(Ok(1)))
    ));
    let direct = &s.rings[&fd];
    let before_tail = direct.state.lock().unwrap().tail;
    assert!(s.poll_pump(&[direct.identity; 4], &mut m));
    assert_eq!(
        direct.state.lock().unwrap().tail.wrapping_sub(before_tail),
        64
    );
}

/// A local mechanism comparison, not an application throughput benchmark.
#[test]
#[ignore = "manual host subscription lifetime cost comparison"]
fn subscription_lifetime_cost() {
    let (t, hub) = target();
    let weak = Arc::downgrade(&t);
    let signal = IoSignal::new(7, weak.clone());
    let (socket, _peer) = UnixStream::pair().unwrap();
    const N: u32 = 100_000;
    let rebuild = || {
        let began = Instant::now();
        for _ in 0..N {
            drop(
                hub.subscribe(socket.as_fd().try_clone_to_owned().unwrap(), false, &signal)
                    .unwrap(),
            );
        }
        began.elapsed()
    };
    let retain = || {
        let began = Instant::now();
        let mut sources = WaitSources::default();
        for _ in 0..N {
            mark_unused(&mut sources);
            sources
                .host((1, false), &signal, &weak, || {
                    socket.as_fd().try_clone_to_owned().map(Into::into)
                })
                .unwrap();
        }
        began.elapsed()
    };
    for sample in 0..7 {
        let (rebuilt, retained) = if sample % 2 == 0 {
            (rebuild(), retain())
        } else {
            let retained = retain();
            (rebuild(), retained)
        };
        println!("subscription lifetime: sample={sample} retries={N} rebuilt_ns={} retained_ns={} ratio={:.2}", rebuilt.as_nanos()/N as u128, retained.as_nanos()/N as u128, rebuilt.as_secs_f64()/retained.as_secs_f64());
    }
}
