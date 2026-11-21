// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn reply(id: u64, error: i32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(((16 + payload.len()) as u32).to_le_bytes());
    bytes.extend(error.to_le_bytes());
    bytes.extend(id.to_le_bytes());
    bytes.extend(payload);
    bytes
}
fn id(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[8..16].try_into().unwrap())
}
fn op(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[4..8].try_into().unwrap())
}
fn start() -> (Arc<Device>, Arc<Connection>) {
    let dev = Device::new(UserNamespace::default());
    let c = dev.connect(Caller::default()).unwrap();
    let init = c.read(8192).unwrap();
    assert_eq!(op(&init), 26);
    let mut payload = [0; 64];
    payload[..4].copy_from_slice(&7u32.to_le_bytes());
    payload[4..8].copy_from_slice(&31u32.to_le_bytes());
    let out = reply(id(&init), 0, &payload);
    assert_eq!(c.write(&out), Ok(out.len()));
    (dev, c)
}
#[test]
fn handshake_gates_queued_requests_and_preserves_header_identity() {
    let c = Connection::new(Caller::default());
    let caller = Caller {
        uid: 11,
        gid: 12,
        pid: 42,
    };
    let req = c.request(3, 1, caller, &[0; 16]).unwrap();
    assert_eq!(c.read(100), Err(Errno(22)));
    let init = c.read(8192).unwrap();
    assert_eq!(c.read(8192), Err(Errno(11)));
    assert_eq!(c.poll(1).0, 0);
    assert_eq!(c.write(&[0; 15]), Err(Errno(22)));
    assert_eq!(c.write(&reply(id(&init), 0, &[])), Err(Errno(22)));
    let mut info = [0; 64];
    info[..4].copy_from_slice(&7u32.to_le_bytes());
    info[4..8].copy_from_slice(&31u32.to_le_bytes());
    c.write(&reply(id(&init), 0, &info)).unwrap();
    assert_eq!(c.poll(1).0, 1);
    let msg = c.read(8192).unwrap();
    assert_eq!(op(&msg), 3);
    assert_eq!(msg.len(), 56);
    assert_eq!(&msg[24..28], &11u32.to_le_bytes());
    assert_eq!(&msg[28..32], &12u32.to_le_bytes());
    assert_eq!(&msg[32..36], &42u32.to_le_bytes());
    c.write(&reply(id(&msg), 0, b"stat")).unwrap();
    assert_eq!(req.take(), Some(Ok(b"stat".to_vec())));
    assert_eq!(c.write(&reply(id(&msg), 0, b"twice")), Err(Errno(2)));
}
#[test]
fn interrupt_priority_retry_disable_and_reply_races() {
    let (_dev, c) = start();
    let a = c.request(3, 1, Caller::default(), &[]).unwrap();
    let b = c.request(17, 1, Caller::default(), &[]).unwrap();
    a.interrupt();
    a.interrupt();
    let first = c.read(8192).unwrap();
    assert_eq!(op(&first), 3);
    let n = id(&first);
    let interrupt = c.read(8192).unwrap();
    assert_eq!(op(&interrupt), 36);
    assert_eq!(id(&interrupt), n | 1);
    assert_eq!(&interrupt[40..], &n.to_le_bytes());
    assert_eq!(c.write(&reply(n | 1, 0, &[0; 8])), Err(Errno(22)));
    c.write(&reply(n | 1, -11, &[])).unwrap();
    assert_eq!(id(&c.read(8192).unwrap()), n | 1);
    c.write(&reply(n | 1, -38, &[])).unwrap();
    assert!(a.take().is_none());
    c.write(&reply(n, -4, &[])).unwrap();
    assert_eq!(a.take(), Some(Err(Errno(4))));
    let next = c.read(8192).unwrap();
    assert_eq!(op(&next), 17);
    b.interrupt();
    assert_eq!(c.read(8192), Err(Errno(11)));
    c.write(&reply(id(&next), 0, &[])).unwrap();
    assert_eq!(b.take(), Some(Ok(vec![])));
}
#[test]
fn unread_cancel_sent_cancel_and_last_daemon_close() {
    let (dev, c) = start();
    let peer = Device::new(UserNamespace::default());
    peer.attach_clone(&dev).unwrap();
    assert_eq!(dev.attach_clone(&peer), Err(Errno(22)));
    let mk = || c.request(3, 1, Caller::default(), &[]).unwrap();
    drop(mk());
    assert_eq!(c.read(8192), Err(Errno(11)));
    let sent = mk();
    let n = id(&c.read(8192).unwrap());
    drop(sent);
    c.write(&reply(n, 0, &[])).unwrap();
    let in_flight = mk();
    c.read(8192).unwrap();
    let queued = mk();
    drop(dev);
    assert!(in_flight.take().is_none());
    drop(peer);
    assert_eq!(in_flight.take(), Some(Err(Errno(103))));
    assert_eq!(queued.take(), Some(Err(Errno(103))));
    assert_eq!(c.poll(1).0, 8);
    assert_eq!(c.read(8192), Err(Errno(19)));
}

#[test]
fn waiter_registered_before_mount_observes_successive_requests() {
    struct Wake;
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let signal = IoSignal::new(0, Arc::downgrade(&wake));
    let device = Device::new(UserNamespace::default());
    let _registered = device.subscribe(&signal);
    let connection = device.connect(Caller::default()).unwrap();
    let init = connection.read(8192).unwrap();
    let mut info = [0; 64];
    info[..4].copy_from_slice(&7u32.to_le_bytes());
    info[4..8].copy_from_slice(&31u32.to_le_bytes());
    connection.write(&reply(id(&init), 0, &info)).unwrap();
    for _ in 0..3 {
        signal.reset();
        let request = connection.request(3, 1, Caller::default(), &[]).unwrap();
        assert!(signal.ready());
        let msg = connection.read(8192).unwrap();
        connection.write(&reply(id(&msg), 0, &[])).unwrap();
        assert_eq!(request.take(), Some(Ok(vec![])));
    }
}
