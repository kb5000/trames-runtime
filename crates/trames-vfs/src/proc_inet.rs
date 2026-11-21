// SPDX-License-Identifier: GPL-3.0-or-later
//! Namespace-owned Internet socket tables for procfs.
use super::Credentials;

pub(super) fn table(
    network: Option<&trames_net::Network>,
    key: &[u8],
    credentials: &Credentials,
) -> Vec<u8> {
    let family = if key.ends_with(b"6") { 10 } else { 2 };
    let (kind, protocol) = if key.starts_with(b"tcp") {
        (1, 6)
    } else if key.starts_with(b"udp") {
        (2, 17)
    } else if key.starts_with(b"raw") {
        (3, if family == 2 { 1 } else { 58 })
    } else {
        (2, if family == 2 { 1 } else { 58 })
    };
    let hex = |a: Option<std::net::SocketAddr>, port: Option<u16>| {
        let (address, p) = a.map_or(
            (if family == 2 { vec![0; 4] } else { vec![0; 16] }, 0),
            |a| {
                (
                    match a.ip() {
                        std::net::IpAddr::V4(v) => v.octets().to_vec(),
                        std::net::IpAddr::V6(v) => v.octets().to_vec(),
                    },
                    a.port(),
                )
            },
        );
        format!(
            "{}:{:04X}",
            address
                .chunks_exact(4)
                .map(|p| format!("{:08X}", u32::from_le_bytes(p.try_into().unwrap())))
                .collect::<String>(),
            port.unwrap_or(p)
        )
    };
    let addresses = if family == 2 {
        "local_address rem_address  "
    } else {
        "local_address                         remote_address                       "
    };
    let header =
        format!("  sl  {addresses} st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode");
    let mut data = match (kind, family) {
        (1, 2) => format!("{header:<149}\n"),
        (2, _) => format!("{header} ref pointer drops\n"),
        _ => format!("{header}\n"),
    };
    let mut slot = 0;
    for (inode, socket) in network.into_iter().flat_map(|n| n.inet_inodes()) {
        let Some(s) = socket.info() else { continue };
        if s.family != family || s.kind != kind || s.protocol != protocol {
            continue;
        }
        if protocol == 6 && s.state == 7 || protocol == 17 && s.local.is_none_or(|a| a.port() == 0)
        {
            continue;
        }
        let local = hex(s.local, (kind == 3).then_some(protocol as u16));
        let remote = hex(s.peer, None);
        let uid = credentials.local_id(false, socket.inode_owner()[0]);
        let drops = if kind == 2 { " 0" } else { "" };
        data.push_str(&format!("{slot:4}: {local} {remote} {:02X} {:08X}:{:08X} 00:00000000 00000000 {uid:5} 0 {inode} 1 0000000000000000{drops}\n", s.state, s.tx_queue.unwrap_or(0), s.rx_queue.unwrap_or(0)));
        slot += 1;
    }
    data.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ipc, Vfs};
    #[test]
    fn tables_follow_the_namespace_and_last_file_reference() {
        let mut creator = Vfs::default();
        creator
            .configure_local_fabric(trames_net::NetworkMode::Loopback)
            .unwrap();
        let mut observer = creator.clone();
        let fd = creator.socket(2, 2, 0).unwrap();
        let udp = creator.socket_fd(fd).unwrap();
        udp.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        udp.chown(1234, 1234, |_| Ok(())).unwrap();
        drop(udp);
        let local = creator.socket(1, 2, 0).unwrap();
        let endpoint = creator.local_socket(local).unwrap().unwrap();
        creator
            .local_bind(&endpoint, b"\x01\0\0scope\0test")
            .unwrap();
        drop(endpoint);
        let unix = |v: &Vfs| String::from_utf8(ipc::proc_unix(Some(&v.root_network))).unwrap();
        let udp =
            |v: &Vfs| String::from_utf8(table(Some(&v.network), b"udp", &v.credentials)).unwrap();
        assert!(unix(&observer).contains("@scope@test"));
        assert_eq!(
            udp(&observer)
                .lines()
                .nth(1)
                .unwrap()
                .split_whitespace()
                .nth(7),
            Some("1234")
        );
        observer.unshare_net().unwrap();
        assert_eq!(udp(&observer).lines().count(), 1);
        assert_eq!(unix(&observer).lines().count(), 1);
        let alias = creator.dup(fd, 0, false).unwrap();
        creator.close(fd).unwrap();
        assert_eq!(udp(&creator).lines().count(), 2);
        creator.close(alias).unwrap();
        creator.close(local).unwrap();
        assert_eq!(udp(&creator).lines().count(), 1);
        assert_eq!(unix(&creator).lines().count(), 1);
    }
}
