// SPDX-License-Identifier: GPL-3.0-or-later
//! DNS-only endpoint for native networking. Ordinary traffic never enters an IP fabric.
use crate::{dns, NetError, NetworkMode, Received, MSG_PEEK};
use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    net::{Ipv4Addr, SocketAddr},
    rc::{Rc, Weak},
    time::{Duration, Instant},
};

pub(crate) const ADDRESS: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53)), 53);
pub(crate) const ROUTABLE_ADDRESS: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(169, 254, 0, 53)), 53);
pub(crate) fn system_address(address: SocketAddr) -> bool {
    address == ADDRESS || address == ROUTABLE_ADDRESS
}
const LIMIT: usize = 8;
const BUFFER: usize = 8192;
type Result<T> = std::result::Result<T, NetError>;
struct Pending {
    endpoint: Weak<Endpoint>,
    question: Vec<u8>,
    deadline: Instant,
}
struct Resolver {
    worker: dns::Resolver,
    pending: BTreeMap<u64, Pending>,
}
pub(crate) struct Service {
    mode: NetworkMode,
    resolver: RefCell<Option<Resolver>>,
}
impl Service {
    pub fn new(mode: NetworkMode) -> Rc<Self> {
        Rc::new(Self {
            mode,
            resolver: RefCell::new(None),
        })
    }
    fn tick(&self) {
        let mut resolver = self.resolver.borrow_mut();
        let Some(r) = resolver.as_mut() else {
            return;
        };
        while let Some((token, response)) = r.worker.result() {
            if let Some(p) = r.pending.remove(&token) {
                if let Some(e) = p.endpoint.upgrade() {
                    e.complete(response.answer(&p.question, if e.stream { 4096 } else { 512 }));
                }
            }
        }
        r.pending.retain(|_, p| {
            let Some(e) = p.endpoint.upgrade() else {
                return false;
            };
            if p.deadline <= Instant::now() {
                e.complete(dns::answer(&p.question, &[], 2, 512));
                false
            } else {
                true
            }
        });
    }
    fn submit(&self, endpoint: &Rc<Endpoint>, packet: &[u8]) -> Result<()> {
        self.tick();
        {
            let state = endpoint.state.borrow();
            if state.pending + state.replies.len() >= LIMIT {
                return Err(NetError(11));
            }
        }
        let question = match dns::parse(packet) {
            Ok(q) => q,
            Err(code) => {
                endpoint.reply(dns::answer(packet, &[], code, 512));
                return Ok(());
            }
        };
        // localhost is synthesized locally, including absence of other RR
        // types; it must not leak to an upstream public resolver.
        if question.name == "localhost" && !matches!(question.kind, 1 | 28) {
            endpoint.reply(dns::answer(packet, &[], 0, 512));
            return Ok(());
        }
        if self.mode == NetworkMode::Loopback && question.name != "localhost" {
            endpoint.reply(dns::answer(packet, &[], 5, 512));
            return Ok(());
        }
        let mut resolver = self.resolver.borrow_mut();
        let r = resolver.get_or_insert_with(|| Resolver {
            worker: dns::Resolver::new(),
            pending: BTreeMap::new(),
        });
        if r.pending.len() >= LIMIT {
            return Err(NetError(11));
        }
        if let Some(token) = r.worker.query(&question) {
            endpoint.state.borrow_mut().pending += 1;
            r.pending.insert(
                token,
                Pending {
                    endpoint: Rc::downgrade(endpoint),
                    question: question.packet,
                    deadline: Instant::now() + Duration::from_secs(5),
                },
            );
        } else {
            endpoint.reply(dns::answer(packet, &[], 2, 512));
        }
        Ok(())
    }
}
#[derive(Default)]
struct State {
    input: Vec<u8>,
    replies: VecDeque<Vec<u8>>,
    pending: usize,
    read_closed: bool,
    write_closed: bool,
    failed: bool,
}
pub(crate) struct Endpoint {
    service: Rc<Service>,
    stream: bool,
    state: RefCell<State>,
    epoch: std::cell::Cell<u64>,
}
impl Endpoint {
    pub fn new(service: Rc<Service>, stream: bool) -> Rc<Self> {
        Rc::new(Self {
            service,
            stream,
            state: RefCell::default(),
            epoch: std::cell::Cell::new(0),
        })
    }
    pub fn epoch(&self) -> u64 {
        self.epoch.get()
    }
    fn reply(&self, mut packet: Vec<u8>) {
        let mut s = self.state.borrow_mut();
        if s.read_closed {
            return;
        }
        if self.stream {
            let mut framed = Vec::with_capacity(packet.len() + 2);
            framed.extend_from_slice(&(packet.len() as u16).to_be_bytes());
            framed.append(&mut packet);
            packet = framed;
        }
        s.replies.push_back(packet);
        self.epoch.set(self.epoch.get().wrapping_add(1));
    }
    fn complete(&self, packet: Vec<u8>) {
        self.state.borrow_mut().pending -= 1;
        self.reply(packet);
    }
    fn pump(self: &Rc<Self>) {
        self.service.tick();
        if !self.stream {
            return;
        }
        loop {
            let packet = {
                let mut s = self.state.borrow_mut();
                if s.input.len() < 2 || s.failed {
                    return;
                }
                let size = u16::from_be_bytes([s.input[0], s.input[1]]) as usize;
                if size > 4096 {
                    s.failed = true;
                    s.input.clear();
                    return;
                }
                if s.input.len() < size + 2 {
                    return;
                }
                s.input[2..size + 2].to_vec()
            };
            if self.service.submit(self, &packet).is_err() {
                return;
            }
            self.state.borrow_mut().input.drain(..packet.len() + 2);
        }
    }
    pub fn send(self: &Rc<Self>, bytes: &[u8]) -> Result<usize> {
        self.pump();
        {
            let s = self.state.borrow();
            if s.write_closed {
                return Err(NetError(32));
            }
            if s.failed {
                return Err(NetError(71));
            }
        }
        if !self.stream {
            if bytes.len() > 4096 {
                return Err(NetError(90));
            }
            self.service.submit(self, bytes)?;
            return Ok(bytes.len());
        }
        let mut s = self.state.borrow_mut();
        let size = bytes.len().min(BUFFER - s.input.len());
        if size == 0 && !bytes.is_empty() {
            return Err(NetError(11));
        }
        s.input.extend_from_slice(&bytes[..size]);
        drop(s);
        self.pump();
        Ok(size)
    }
    pub fn recv(self: &Rc<Self>, count: usize, flags: u32) -> Result<Received> {
        self.pump();
        let mut s = self.state.borrow_mut();
        if s.failed {
            return Err(NetError(71));
        }
        let empty = || Received {
            netlink_address: None,
            packet_info: None,
            data: Vec::new(),
            address: None,
            length: 0,
            truncated: false,
        };
        if s.read_closed || self.stream && count == 0 {
            return Ok(empty());
        }
        let Some(front) = s.replies.front_mut() else {
            return if self.stream && s.write_closed && s.pending == 0 && s.input.is_empty() {
                Ok(empty())
            } else {
                Err(NetError(11))
            };
        };
        let size = count.min(front.len());
        let length = if self.stream { size } else { front.len() };
        let data = front[..size].to_vec();
        if flags & MSG_PEEK == 0 {
            if self.stream && size != front.len() {
                front.drain(..size);
            } else {
                s.replies.pop_front();
            }
        }
        Ok(Received {
            netlink_address: None,
            packet_info: None,
            data,
            address: (!self.stream).then_some(ADDRESS),
            length,
            truncated: !self.stream && length > size,
        })
    }
    pub fn poll(self: &Rc<Self>, events: u16) -> u16 {
        self.pump();
        let s = self.state.borrow();
        if s.failed {
            return 8 | 16;
        }
        let eof =
            s.read_closed || self.stream && s.write_closed && s.pending == 0 && s.input.is_empty();
        let readable = !s.replies.is_empty() || eof;
        let writable = !s.write_closed
            && if self.stream {
                s.input.len() < BUFFER
            } else {
                s.pending + s.replies.len() < LIMIT
            };
        (if readable { events & 1 } else { 0 }) | (if writable { events & 4 } else { 0 })
    }
    pub fn shutdown(&self, how: u32) -> Result<()> {
        if how > 2 {
            return Err(NetError(22));
        }
        let mut s = self.state.borrow_mut();
        if how != 1 {
            s.read_closed = true;
            s.replies.clear();
        }
        if how != 0 {
            s.write_closed = true;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn query(id: u16, name: &[u8], kind: u16) -> Vec<u8> {
        let mut q = vec![0; 12];
        q[..2].copy_from_slice(&id.to_be_bytes());
        q[2] = 1;
        q[5] = 1;
        for label in name.split(|b| *b == b'.') {
            q.push(label.len() as u8);
            q.extend(label);
        }
        q.push(0);
        q.extend(kind.to_be_bytes());
        q.extend([0, 1]);
        q
    }
    fn ready(e: &Rc<Endpoint>) {
        let end = Instant::now() + Duration::from_secs(3);
        while e.poll(1) & 1 == 0 {
            assert!(Instant::now() < end, "host localhost resolver timed out");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    #[test]
    fn dns_only_udp_preserves_ids_datagrams_peek_and_truncation() {
        let e = Endpoint::new(Service::new(NetworkMode::Full), false);
        for (id, kind) in [(0x1234, 1), (0x5678, 28)] {
            let q = query(id, b"localhost", kind);
            assert_eq!(e.send(&q).unwrap(), q.len());
        }
        for _ in 0..2 {
            ready(&e);
            let peek = e.recv(2, MSG_PEEK).unwrap();
            assert!(peek.truncated && peek.length > 12);
            let answer = e.recv(4096, 0).unwrap();
            assert_eq!(peek.data, answer.data[..2]);
            assert_eq!(answer.address, Some(ADDRESS));
            assert_eq!(answer.data[3] & 15, 0);
        }
        assert!(matches!(e.recv(1, 0), Err(NetError(11))));
    }
    #[test]
    fn dns_tcp_reassembles_split_frames_and_half_close_preserves_reply() {
        let e = Endpoint::new(Service::new(NetworkMode::Full), true);
        let q = query(17, b"localhost", 1);
        let size = (q.len() as u16).to_be_bytes();
        assert_eq!(e.send(&size[..1]).unwrap(), 1);
        assert_eq!(e.poll(1), 0);
        assert_eq!(e.send(&[&size[1..], &q[..3]].concat()).unwrap(), 4);
        assert_eq!(e.send(&q[3..]).unwrap(), q.len() - 3);
        e.shutdown(1).unwrap();
        ready(&e);
        let prefix = e.recv(2, 0).unwrap().data;
        let size = u16::from_be_bytes(prefix.try_into().unwrap()) as usize;
        let packet = e.recv(size, 0).unwrap().data;
        assert_eq!(packet.len(), size);
        assert_eq!(&packet[..2], &17u16.to_be_bytes());
        assert!(e.recv(16, 0).unwrap().data.is_empty());
        assert!(matches!(e.send(&q), Err(NetError(32))));
    }
    #[test]
    fn malformed_queries_and_backpressure_are_bounded_and_loopback_cannot_resolve_external() {
        let e = Endpoint::new(Service::new(NetworkMode::Loopback), false);
        let q = query(1, b"external.invalid", 1);
        e.send(&q).unwrap();
        assert_eq!(e.recv(512, 0).unwrap().data[3] & 15, 5);
        for _ in 0..LIMIT {
            assert_eq!(e.send(b"xx").unwrap(), 2);
        }
        assert!(matches!(e.send(b"xx"), Err(NetError(11))));
        for _ in 0..LIMIT {
            assert_eq!(e.recv(512, 0).unwrap().data[3] & 15, 1);
        }
        let tcp = Endpoint::new(e.service.clone(), true);
        assert_eq!(tcp.send(&[0xff, 0xff]).unwrap(), 2);
        assert_eq!(tcp.poll(1), 24);
        assert!(matches!(tcp.recv(32, 0), Err(NetError(71))));
    }
}
