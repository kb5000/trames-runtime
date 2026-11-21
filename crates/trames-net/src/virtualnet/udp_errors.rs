// SPDX-License-Identifier: GPL-3.0-or-later
//! All per-address transport handles for a UDP descriptor share one error queue.
use super::*;
use crate::ExtendedError;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::Relaxed};

#[derive(Debug)]
struct Record {
    peer: SocketAddr,
    error: ExtendedError,
    data: Vec<u8>,
}
impl Record {
    fn charge(len: usize) -> usize {
        std::mem::size_of::<Self>() + len
    }
}

#[derive(Debug)]
struct Queue {
    enabled: [bool; 2],
    records: VecDeque<Record>,
    used: usize,
    budget: usize,
}
#[derive(Debug)]
pub(super) struct Errors {
    pending: AtomicU32,
    queued: AtomicBool,
    queue: parking_lot::Mutex<Queue>,
}
impl Default for Errors {
    fn default() -> Self {
        Self {
            pending: AtomicU32::new(0),
            queued: AtomicBool::new(false),
            queue: parking_lot::Mutex::new(Queue {
                enabled: [false; 2],
                records: VecDeque::new(),
                used: 0,
                budget: BUFFER,
            }),
        }
    }
}
impl Errors {
    pub fn ready(&self) -> bool {
        self.pending.load(Relaxed) != 0 || self.queued.load(Relaxed)
    }
    pub fn take_pending(&self) -> u32 {
        if self.pending.load(Relaxed) == 0 {
            0
        } else {
            self.pending.swap(0, Relaxed)
        }
    }
    pub fn check_pending(&self) -> Result<()> {
        let errno = self.take_pending();
        if errno == 0 {
            Ok(())
        } else {
            Err(NetError(errno))
        }
    }
    pub fn set_budget(&self, bytes: usize) {
        self.queue.lock().budget = bytes;
    }
    pub fn enabled(&self, v6: bool) -> bool {
        self.queue.lock().enabled[usize::from(v6)]
    }
    pub fn enable(&self, v6: bool, enable: bool) {
        let mut q = self.queue.lock();
        q.enabled[usize::from(v6)] = enable;
        if !enable {
            q.records.retain(|r| r.peer.is_ipv6() != v6);
            q.used = q.records.iter().map(|r| Record::charge(r.data.len())).sum();
            self.queued.store(!q.records.is_empty(), Relaxed);
        }
    }
    fn report(
        &self,
        peer: SocketAddr,
        error: ExtendedError,
        data: &[u8],
        hard_connected: bool,
    ) -> bool {
        let mut q = self.queue.lock();
        let errno = error.errno;
        if q.enabled[usize::from(peer.is_ipv6())] {
            let charge = Record::charge(data.len());
            if charge > q.budget.saturating_sub(q.used) {
                return false;
            }
            q.records.push_back(Record {
                peer,
                error,
                data: data.to_vec(),
            });
            q.used += charge;
            self.queued.store(true, Relaxed);
        } else if !hard_connected {
            return false;
        }
        self.pending.store(errno, Relaxed);
        true
    }
    pub fn too_big(&self, peer: SocketAddr, mtu: u32) -> bool {
        self.report(
            peer,
            ExtendedError {
                errno: 90,
                origin: 1,
                kind: 0,
                code: 0,
                info: mtu,
                reporter: None,
            },
            &[],
            false,
        )
    }
    pub fn receive(&self, count: usize, v6_socket: bool) -> Result<Received> {
        let mut q = self.queue.lock();
        let mut record = q.records.pop_front().ok_or(NetError(11))?;
        q.used -= Record::charge(record.data.len());
        self.queued.store(!q.records.is_empty(), Relaxed);
        self.pending
            .store(q.records.front().map_or(0, |r| r.error.errno), Relaxed);
        let length = record.data.len();
        record.data.truncate(count);
        if v6_socket {
            if let Some(IpAddr::V4(a)) = record.error.reporter {
                record.error.reporter = Some(a.to_ipv6_mapped().into());
            }
        }
        Ok(Received {
            stream_minimum: 0,
            netlink_address: None,
            packet_address: None,
            credentials: None,
            packet_info: None,
            ip: crate::ReceivedIp {
                ipv6: v6_socket,
                error: Some(Box::new(record.error)),
                ..Default::default()
            },
            data: record.data,
            address: Some(record.peer),
            length,
            truncated: count < length,
        })
    }
}
impl udp::ErrorReceiver for Errors {
    fn unreachable(
        &self,
        connected: bool,
        reporter: IpAddress,
        peer: IpEndpoint,
        code: u8,
        quote: &[u8],
    ) -> bool {
        let peer = address(peer);
        let v6 = peer.is_ipv6();
        let (errno, hard) = match (v6, code) {
            (false, 3) | (true, 4) => (111, true),
            (false, 2) => (92, true),
            (false, 0 | 11) | (true, 0) => (101, false),
            (false, 1 | 12) | (true, 2 | 3) => (113, false),
            (true, 1 | 5 | 6) => (13, true),
            (false, 5) => (95, false),
            (false, 6 | 9) => (101, true),
            (false, 7) => (112, true),
            (false, 8) => (64, true),
            (false, 10 | 13..=15) => (113, true),
            _ => return false,
        };
        self.report(
            peer,
            ExtendedError {
                errno,
                origin: if v6 { 3 } else { 2 },
                kind: if v6 { 1 } else { 3 },
                code,
                info: 0,
                reporter: Some(addr(reporter)),
            },
            quote,
            hard && connected,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_wire_quotes_keep_data_and_error_queues_independent() {
        let fabric = Fabric::new().unwrap();
        let clients = fabric.environment(2, NetworkMode::Full).unwrap();
        let servers = fabric.environment(3, NetworkMode::Full).unwrap();
        let payload = vec![0xa5; 1400];
        for (family, server_ip, level, option) in [
            (2, IpAddr::from(v4(3)), 0, 11),
            (10, IpAddr::from(v6(3)), 41, 25),
        ] {
            let client = clients.socket(family, 2, 0).unwrap();
            let other = clients.socket(family, 2, 0).unwrap();
            let peer = SocketAddr::new(server_ip, 34561);
            client.set_option(level, option, 1).unwrap();
            client.connect(peer).unwrap();
            client.send(&payload, 0, None).unwrap();
            assert_eq!(client.get_option(1, 4), Ok(111));
            assert_eq!(client.poll(1), Ok(8));
            assert_eq!(other.poll(1), Ok(0));
            let sender = servers.socket(family, 2, 0).unwrap();
            sender.bind(peer).unwrap();
            sender.send(b"reply", 0, client.info().local).unwrap();
            assert_eq!(client.recv(10, 0).unwrap().data, b"reply");
            let record = client.recv(7, crate::MSG_ERRQUEUE).unwrap();
            assert!(record.truncated && record.length < payload.len() && record.length >= 7);
            assert_eq!(record.data, payload[..7]);
            assert_eq!(record.address, Some(peer));
            assert_eq!(record.ip.error.unwrap().reporter, Some(server_ip));
            assert_eq!(client.poll(1), Ok(0));
        }
    }

    #[test]
    fn reused_port_returns_the_error_to_the_same_flow_as_a_reply() {
        let fabric = Fabric::new().unwrap();
        let clients = fabric.environment(2, NetworkMode::Full).unwrap();
        let servers = fabric.environment(3, NetworkMode::Full).unwrap();
        let local: SocketAddr = "10.0.0.2:34501".parse().unwrap();
        let receivers = [
            clients.socket(2, 2, 0).unwrap(),
            clients.socket(2, 2, 0).unwrap(),
        ];
        for socket in &receivers {
            socket.set_option(1, 15, 1).unwrap();
            socket.set_option(0, 11, 1).unwrap();
            socket.bind(local).unwrap();
        }
        let mut chosen = [0; 2];
        for port in 34502..34534 {
            let remote = SocketAddr::new(v4(3).into(), port);
            receivers[0].send(b"probe", 0, Some(remote)).unwrap();
            let responder = servers.socket(2, 2, 0).unwrap();
            responder.bind(remote).unwrap();
            responder.send(b"reply", 0, Some(local)).unwrap();
            let mut owners = 0;
            for (index, socket) in receivers.iter().enumerate() {
                let error = socket.recv(5, crate::MSG_ERRQUEUE);
                let reply = socket.recv(5, MSG_DONTWAIT);
                match (error, reply) {
                    (Ok(error), Ok(reply)) => {
                        assert_eq!(error.data, b"probe");
                        assert_eq!(reply.data, b"reply");
                        owners += 1;
                        chosen[index] += 1;
                    }
                    (Err(NetError(11)), Err(NetError(11))) => {}
                    _ => panic!("flow ownership diverged"),
                }
            }
            assert_eq!(owners, 1);
        }
        assert!(chosen.iter().all(|&n| n > 0));
    }

    #[test]
    fn queue_budget_includes_empty_records_and_disabling_one_family_preserves_the_other() {
        let errors = Errors::default();
        let v4 = "192.0.2.4:17".parse().unwrap();
        let v6 = "[::1]:17".parse().unwrap();
        errors.set_budget(2 * Record::charge(0));
        errors.enable(false, true);
        errors.enable(true, true);
        let report = |peer| {
            errors.report(
                peer,
                ExtendedError {
                    errno: 111,
                    origin: 1,
                    kind: 0,
                    code: 0,
                    info: 0,
                    reporter: None,
                },
                &[],
                false,
            )
        };
        assert!(report(v4) && report(v6));
        assert!(!report(v6));
        errors.enable(false, false);
        assert!(report(v6));
        assert_eq!(errors.receive(0, true).unwrap().address, Some(v6));
        assert_eq!(errors.take_pending(), 111);
        assert!(errors.ready());
        assert_eq!(errors.receive(0, true).unwrap().address, Some(v6));
        assert!(!errors.ready());
    }
}
