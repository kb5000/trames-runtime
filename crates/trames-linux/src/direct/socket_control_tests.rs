// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_memory::{Memory, Permissions};
use trames_vfs::{Vfs, O_CLOEXEC, O_NONBLOCK};
fn memory() -> Memory {
    let mut m = Memory::new(0x10000);
    m.map(0x1000, 0x1000, Permissions::RW).unwrap();
    m
}
fn address(m: &mut Memory, value: std::net::SocketAddr) -> u64 {
    let bytes = trames_net::encode_address(value);
    m.write(0x1000, &bytes).unwrap();
    bytes.len() as u64
}
fn create(d: &DirectSyscalls, m: &mut Memory) -> u32 {
    d.invoke_creation(198, [2, (1 | O_NONBLOCK) as u64, 0, 0, 0, 0], m)
        .unwrap()
        .unwrap() as u32
}
#[test]
fn native_and_virtual_full_socket_controls_publish_accept_to_existing_captures() {
    for virtual_socket in [false, true] {
        let mut v = Vfs::default();
        if virtual_socket {
            v.configure_local_fabric(trames_net::NetworkMode::Loopback)
                .unwrap();
        } else {
            v.configure_network(trames_net::NetworkMode::Loopback)
                .unwrap();
        }
        let network = v.direct_network();
        let factory = v.descriptor_factory();
        let direct = DirectSyscalls::default()
            .with_network(network.clone())
            .with_resources(factory);
        let mut m = memory();
        let listener = create(&direct, &mut m);
        let client = create(&direct, &mut m);
        let len = address(&mut m, "127.0.0.1:0".parse().unwrap());
        assert_eq!(
            direct.invoke_socket_control(200, [listener as u64, 0x1000, len, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        assert_eq!(
            direct.invoke_socket_control(201, [listener as u64, 4, 0, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        m.write(0x1200, &16u32.to_le_bytes()).unwrap();
        assert_eq!(
            direct.invoke_socket_control(204, [listener as u64, 0x1100, 0x1200, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        let peer = v.socket_fd(listener).unwrap().local_addr().unwrap();
        let len = address(&mut m, peer);
        assert!(matches!(
            direct.invoke_socket_control(203, [client as u64, 0x1000, len, 0, 0, 0], &mut m),
            Some(Ok(0) | Err(Errno(115)))
        ));
        // Invalid output is rejected before consuming any queued connection.
        assert_eq!(
            direct.invoke_socket_control(242, [listener as u64, 0x9000, 0x1200, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        let until = Instant::now() + Duration::from_secs(3);
        let accepted = loop {
            match direct
                .invoke_socket_control(
                    242,
                    [
                        listener as u64,
                        0x1100,
                        0x1200,
                        (O_NONBLOCK | O_CLOEXEC) as u64,
                        0,
                        0,
                    ],
                    &mut m,
                )
                .unwrap()
            {
                Ok(fd) => break fd as u32,
                Err(Errno(11)) if Instant::now() < until => trames_net::wait(
                    &[(v.socket_fd(listener).unwrap(), 1)],
                    Duration::from_millis(1),
                )
                .unwrap(),
                other => panic!("accept {other:?}"),
            }
        };
        assert_eq!(v.socket_fd(accepted).unwrap().local_addr().unwrap(), peer);
        assert_eq!(
            v.flags(accepted).unwrap() & (O_CLOEXEC | O_NONBLOCK),
            O_CLOEXEC | O_NONBLOCK
        );
        assert!(v.shared_files().lookup(accepted).unwrap().is_ok());
        if !virtual_socket {
            assert!(
                network.get(accepted).is_some(),
                "native capability published before FD visibility"
            );
        }
        assert_eq!(
            direct.invoke_socket_control(208, [accepted as u64, 6, 1, 0x1300, 4, 0], &mut m),
            Some(Ok(0))
        );
        assert_eq!(
            direct.invoke_socket_control(210, [accepted as u64, 2, 0, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        for fd in [listener, client, accepted] {
            v.close(fd).unwrap();
        }
        assert_eq!(v.live_sockets(), 0);
    }
}
#[test]
fn full_socket_controls_preserve_captured_low_port_authority_and_error_order() {
    let mut v = Vfs::default();
    v.configure_network(trames_net::NetworkMode::Loopback)
        .unwrap();
    v.credentials = trames_vfs::Credentials::user(1000, 1000);
    let factory = v.descriptor_factory();
    v.credentials = trames_vfs::Credentials::user(0, 0);
    std::thread::spawn(move || {
        let direct = DirectSyscalls::default().with_resources(factory);
        let mut m = memory();
        let fd = create(&direct, &mut m);
        let len = address(&mut m, "127.0.0.1:80".parse().unwrap());
        assert_eq!(
            direct.invoke_socket_control(200, [fd as u64, 0x1000, len, 0, 0, 0], &mut m),
            Some(Err(Errno(13)))
        );
        assert_eq!(
            direct.invoke_socket_control(200, [fd as u64, 0x9000, len, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert_eq!(
            direct.invoke_socket_control(209, [fd as u64, 6, 1, 0x9000, 0x9000, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert_eq!(
            direct.invoke_socket_control(201, [u32::MAX as u64, 4, 0, 0, 0, 0], &mut m),
            Some(Err(Errno(9)))
        );
    })
    .join()
    .unwrap();
}

#[test]
fn immediate_blocking_udp_and_netlink_connect_complete_but_tcp_waits_defer_before_effects() {
    let mut v = Vfs::default();
    v.configure_network(trames_net::NetworkMode::Loopback)
        .unwrap();
    let direct = DirectSyscalls::default().with_resources(v.descriptor_factory());
    let mut m = memory();
    let udp = v.socket(2, 2, 0).unwrap();
    let peer = "127.0.0.1:12345".parse().unwrap();
    let len = address(&mut m, peer);
    assert_eq!(
        direct.invoke_socket_control(203, [udp as u64, 0x1000, len, 0, 0, 0], &mut m),
        Some(Ok(0))
    );
    assert_eq!(v.socket_fd(udp).unwrap().peer_addr().unwrap(), peer);
    let tcp = v.socket(2, 1, 0).unwrap();
    assert_eq!(
        direct.invoke_socket_control(203, [tcp as u64, 0x1000, len, 0, 0, 0], &mut m),
        None
    );
    assert!(v.socket_fd(tcp).unwrap().info().unwrap().peer.is_none());
    assert_eq!(
        direct.invoke_socket_control(202, [tcp as u64, 0, 0, 0, 0, 0], &mut m),
        None
    );
    let netlink = v.socket(16, 3, 0).unwrap();
    let mut address = [0; 12];
    address[..2].copy_from_slice(&16u16.to_le_bytes());
    m.write(0x1000, &address).unwrap();
    assert_eq!(
        direct.invoke_socket_control(203, [netlink as u64, 0x1000, 12, 0, 0, 0], &mut m),
        Some(Ok(0))
    );
    for fd in [udp, tcp, netlink] {
        v.close(fd).unwrap();
    }
}
