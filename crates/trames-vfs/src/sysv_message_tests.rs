// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
fn received(request: &Request) -> (i64, Vec<u8>) {
    match request.attempt().unwrap() {
        Reply::Received { kind, data } => (kind, data),
        _ => panic!("receive"),
    }
}
#[test]
fn selection_copy_truncation_and_capacity_use_one_queue_state() {
    let vfs = Vfs::default();
    let factory = vfs.descriptor_factory();
    let id = factory.message_get(42, 0x200 | 0o600).unwrap();
    assert_eq!(factory.message_get(42, 0).unwrap(), id);
    assert_eq!(factory.message_get(42, 0x600), Err(Errno(17)));
    for kind in [3, 1, 2, 1] {
        factory
            .message_send(id, kind, vec![kind as u8; 8], 1)
            .unwrap()
            .attempt()
            .unwrap();
    }
    assert_eq!(
        received(&factory.message_receive(id, -2, 8, 0, 2).unwrap()).0,
        1
    );
    assert_eq!(
        received(&factory.message_receive(id, 3, 8, 0x2000, 2).unwrap()).0,
        2
    );
    let copy = factory.message_receive(id, 0, 8, 0x4800, 2).unwrap();
    assert_eq!(received(&copy), received(&copy));
    assert!(matches!(
        factory
            .message_receive(id, 0, 7, 0x4800, 2)
            .unwrap()
            .attempt(),
        Err(Errno(7))
    ));
    assert!(matches!(
        factory
            .message_receive(id, 0, 7, 0x5800, 2)
            .unwrap()
            .attempt(),
        Err(Errno(22))
    ));
    assert!(matches!(
        factory.message_receive(id, 0, 7, 0, 2).unwrap().attempt(),
        Err(Errno(7))
    ));
    assert_eq!(
        received(&factory.message_receive(id, 0, 7, 0x1000, 2).unwrap()),
        (3, vec![3; 7])
    );
    let (_, stat) = factory.message_control(id, 2, None).unwrap();
    assert_eq!(u64::from_le_bytes(stat[80..88].try_into().unwrap()), 1);
    assert_eq!(u64::from_le_bytes(stat[72..80].try_into().unwrap()), 8);
    factory.message_control(id, 0, None).unwrap();
    assert!(matches!(copy.attempt(), Err(Errno(43))));
    assert!(matches!(
        factory.message_receive(id, 0, 8, 0, 2),
        Err(Errno(22))
    ));
}
#[test]
fn namespace_and_permissions_are_original_resources_after_unshare_or_remove() {
    let mut vfs = Vfs::default();
    let old = vfs.descriptor_factory();
    let id = old.message_get(42, 0x200 | 0o600).unwrap();
    let accepted = old.message_receive(id, 0, 8, 0, 2).unwrap();
    vfs.unshare_ipc().unwrap();
    let next = vfs.descriptor_factory();
    assert_eq!(next.message_get(42, 0), Err(Errno(2)));
    next.message_get(42, 0x200 | 0o600).unwrap();
    old.message_send(id, 1, b"original".to_vec(), 1)
        .unwrap()
        .attempt()
        .unwrap();
    assert_eq!(received(&accepted).1, b"original");
    let mut other = old.clone();
    other.credentials = Credentials::user(1000, 1000);
    assert_eq!(other.message_control(id, 0, None), Err(Errno(1)));
    assert!(matches!(
        other.message_receive(id, 0, 8, 0, 2).unwrap().attempt(),
        Err(Errno(13))
    ));
    old.message_control(id, 0, None).unwrap();
    assert!(matches!(accepted.attempt(), Err(Errno(43))));
}
#[test]
fn existing_executors_can_fill_drain_and_remove_without_a_service_thread() {
    let factory = Vfs::default().descriptor_factory();
    let id = factory.message_get(0, 0o600).unwrap();
    let (_, mut stat) = factory.message_control(id, 2, None).unwrap();
    stat[88..96].copy_from_slice(&0u64.to_le_bytes());
    factory
        .message_control(id, 1, Some(stat.as_slice().try_into().unwrap()))
        .unwrap();
    let send = factory.message_send(id, 1, Vec::new(), 1).unwrap();
    assert!(matches!(send.attempt(), Err(Errno(11))));
    stat[88..96].copy_from_slice(&(MSGMNB as u64).to_le_bytes());
    factory
        .message_control(id, 1, Some(stat.as_slice().try_into().unwrap()))
        .unwrap();
    let gate = Arc::new(std::sync::Barrier::new(4));
    std::thread::scope(|scope| {
        for kind in 1..=4 {
            let factory = factory.clone();
            let gate = gate.clone();
            scope.spawn(move || {
                gate.wait();
                for _ in 0..100 {
                    factory
                        .message_send(id, kind, vec![kind as u8; 16], kind as u32)
                        .unwrap()
                        .attempt()
                        .unwrap();
                    assert_eq!(
                        received(
                            &factory
                                .message_receive(id, kind, 16, 0, kind as u32)
                                .unwrap()
                        ),
                        (kind, vec![kind as u8; 16])
                    );
                }
            });
        }
    });
    assert!(matches!(
        factory.message_receive(id, 0, 8, 0, 1).unwrap().attempt(),
        Err(Errno(42))
    ));
}
