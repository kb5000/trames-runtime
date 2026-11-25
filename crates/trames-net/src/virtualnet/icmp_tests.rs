// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn echo(family: u32, id: u16) -> Vec<u8> {
    let mut data = vec![if family == 2 { 8 } else { 128 }, 0, 0, 0, 0, 0, 0, 1];
    data[4..6].copy_from_slice(&id.to_be_bytes());
    if family == 2 {
        smoltcp::wire::Icmpv4Packet::new_unchecked(&mut data).fill_checksum();
    } else {
        smoltcp::wire::Icmpv6Packet::new_unchecked(&mut data)
            .fill_checksum(&Ipv6Addr::LOCALHOST, &Ipv6Addr::LOCALHOST);
    }
    data
}

#[test]
fn raw_icmp_filter_updates_partial_bytes_and_filters_only_new_arrivals() {
    let fabric = Fabric::new().unwrap();
    let net = crate::Network::virtual_network(&fabric, 2, NetworkMode::Full).unwrap();
    let socket = net.socket(2, 3, 1).unwrap();
    socket.set_option(255, 1, 0xffff0000u32 as i32).unwrap();
    socket.set_option_bytes(255, 1, &[0xff]).unwrap();
    socket.set_option_bytes(255, 1, &[]).unwrap();
    assert_eq!(socket.get_option(255, 1).unwrap() as u32, 0xffff00ff);
    assert_eq!(
        net.socket(2, 3, 17).unwrap().set_option(255, 1, 0),
        Err(NetError(95))
    );
    socket.set_option(255, 1, 1 << 8).unwrap();
    socket
        .send(&echo(2, 0x1234), 0, Some("127.0.0.1:0".parse().unwrap()))
        .unwrap();
    socket.set_option(255, 1, -1).unwrap();
    // The echo request was filtered; the already queued reply survives a later filter change.
    assert_eq!(socket.recv(128, 0).unwrap().data[20], 0);
    assert_eq!(socket.recv(128, 0).map(|r| r.data), Err(NetError(11)));
    socket
        .send(&echo(2, 0x1234), 0, Some("127.0.0.1:0".parse().unwrap()))
        .unwrap();
    assert_eq!(socket.recv(128, 0).map(|r| r.data), Err(NetError(11)));
}

#[test]
fn raw_and_ping_arrival_timestamps_survive_peeks_and_option_changes() {
    for family in [2, 10] {
        for kind in [2, 3] {
            let fabric = Fabric::new().unwrap();
            let net = crate::Network::virtual_network(&fabric, 2, NetworkMode::Full).unwrap();
            let socket = net
                .socket(family, kind, if family == 2 { 1 } else { 58 })
                .unwrap();
            let peer: SocketAddr = if family == 2 {
                "127.0.0.1:0"
            } else {
                "[::1]:0"
            }
            .parse()
            .unwrap();
            socket.bind(peer).unwrap();
            if kind == 3 {
                if family == 2 {
                    socket.set_option(255, 1, 1 << 8).unwrap();
                } else {
                    let mut filter = [0; 32];
                    filter[16] = 1;
                    socket.set_option_bytes(58, 1, &filter).unwrap();
                }
            }
            assert_eq!(socket.last_packet_ns(), Err(NetError(2)));
            socket.send(&echo(family, 0x1234), 0, Some(peer)).unwrap();
            assert!(socket.recv(128, 0).unwrap().ip.timestamp.is_none());
            let first = socket.last_packet_ns().unwrap();
            assert_ne!(first, 0);
            socket.send(&echo(family, 0x1234), 0, Some(peer)).unwrap();
            let mut previous = None;
            for (option, flags) in [(29, MSG_PEEK), (35, MSG_PEEK), (63, MSG_PEEK), (64, 0)] {
                socket.set_option(1, option, 1).unwrap();
                let (returned, ns) = socket.recv(128, flags).unwrap().ip.timestamp.unwrap();
                assert_eq!(returned, option);
                assert!(ns >= first);
                assert_eq!(previous.replace(ns).unwrap_or(ns), ns);
                assert_eq!(socket.last_packet_ns(), Ok(first));
            }
        }
    }
}

#[test]
fn raw_error_queue_matches_the_original_echo_independently_of_its_data_filter() {
    for kind in [2, 3] {
        let fabric = Fabric::new().unwrap();
        let net = crate::Network::virtual_network(&fabric, 2, NetworkMode::Full).unwrap();
        let client = net.socket(2, kind, 1).unwrap();
        let other = net.socket(2, kind, 1).unwrap();
        let wrong_device = net.socket(2, kind, 1).unwrap();
        let peer = "127.0.0.1:0".parse().unwrap();
        for (socket, id) in [(&client, 0x1234), (&other, 0x5678)] {
            if kind == 3 {
                socket.set_option(255, 1, -1).unwrap();
            }
            socket
                .bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), id))
                .unwrap();
            socket.set_option(0, 11, 1).unwrap();
            socket.send(&echo(2, id), 0, Some(peer)).unwrap();
        }
        wrong_device.set_option(0, 11, 1).unwrap();
        wrong_device.set_option_bytes(1, 25, b"eth0\0").unwrap();
        let crate::SocketBackend::Virtual(socket) = &wrong_device.backend else {
            unreachable!()
        };
        socket.state.borrow_mut().raw_identifiers.insert(0x1234);
        let data = echo(2, 0x1234);
        let mut quoted = packet::raw_ipv4(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 1, 64, &data);
        smoltcp::wire::Ipv4Packet::new_unchecked(&mut quoted).fill_checksum();
        let mut error = vec![3, 1, 0, 0, 0, 0, 0, 0];
        error.extend_from_slice(&quoted);
        smoltcp::wire::Icmpv4Packet::new_unchecked(&mut error).fill_checksum();
        let reporter = net.socket(2, 3, 1).unwrap();
        reporter.send(&error, 0, Some(peer)).unwrap();
        assert_eq!(client.poll(1).unwrap() & 8, 8);
        assert_eq!(client.get_option(1, 4), Ok(113));
        let received = client.recv(128, crate::MSG_ERRQUEUE).unwrap();
        assert_eq!(received.data, data);
        let error = received.ip.error.unwrap();
        assert_eq!(
            (error.errno, error.origin, error.kind, error.code),
            (113, 2, 3, 1)
        );
        assert_eq!(
            other.recv(128, crate::MSG_ERRQUEUE).err(),
            Some(NetError(11))
        );
        assert_eq!(
            wrong_device.recv(128, crate::MSG_ERRQUEUE).err(),
            Some(NetError(11))
        );
        if kind == 3 {
            assert_eq!(client.recv(128, 0).err(), Some(NetError(11)));
        }
    }
}

#[test]
fn raw_error_options_reject_the_other_ip_family() {
    let fabric = Fabric::new().unwrap();
    let net = crate::Network::virtual_network(&fabric, 2, NetworkMode::Full).unwrap();
    for (family, protocol, level, option) in [(2, 1, 41, 25), (10, 58, 0, 11)] {
        for kind in [2, 3] {
            let socket = net.socket(family, kind, protocol).unwrap();
            assert!(socket.set_option(level, option, 1).is_err());
            assert!(socket.get_option(level, option).is_err());
        }
    }
}
