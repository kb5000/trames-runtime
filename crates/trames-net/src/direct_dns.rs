// SPDX-License-Identifier: GPL-3.0-or-later
//! DNS-only endpoint for native networking. Ordinary traffic never enters an IP fabric.
use crate::{dns, NetError, NetworkMode, Received, MSG_PEEK};
use std::{
    collections::{BTreeMap, VecDeque},
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc, Mutex, Weak,
    },
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
    resolver: Mutex<Option<Resolver>>,
}
impl Service {
    pub fn new(mode: NetworkMode) -> Arc<Self> {
        Arc::new(Self {
            mode,
            resolver: Mutex::new(None),
        })
    }
    fn tick(&self) {
        let mut resolver = self.resolver.lock().unwrap();
        let Some(r) = resolver.as_mut() else { return };
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
    fn submit(&self, endpoint: &Arc<Endpoint>, packet: &[u8]) -> Result<()> {
        self.tick();
        // Reserve the original per-endpoint bound in the same transaction as
        // all other pending/reply changes. Parallel malformed/local requests
        // must not each pass an independent check and overflow the queue.
        let admission = endpoint.reserve()?;
        let question = match dns::parse(packet) {
            Ok(q) => q,
            Err(code) => {
                admission.reply(dns::answer(packet, &[], code, 512));
                return Ok(());
            }
        };
        // localhost must not leak to an upstream public resolver.
        if question.name == "localhost" && !matches!(question.kind, 1 | 28) {
            admission.reply(dns::answer(packet, &[], 0, 512));
            return Ok(());
        }
        if self.mode == NetworkMode::Loopback && question.name != "localhost" {
            admission.reply(dns::answer(packet, &[], 5, 512));
            return Ok(());
        }
        let mut resolver = self.resolver.lock().unwrap();
        let r = resolver.get_or_insert_with(|| Resolver {
            worker: dns::Resolver::new(),
            pending: BTreeMap::new(),
        });
        if r.pending.len() >= LIMIT {
            return Err(NetError(11));
        }
        if let Some(token) = r.worker.query(&question) {
            r.pending.insert(
                token,
                Pending {
                    endpoint: Arc::downgrade(endpoint),
                    question: question.packet,
                    deadline: Instant::now() + Duration::from_secs(5),
                },
            );
            admission.queued();
        } else {
            admission.reply(dns::answer(packet, &[], 2, 512));
        }
        Ok(())
    }
}
#[derive(Default)]
struct Input {
    bytes: Vec<u8>,
    failed: bool,
}
#[derive(Default)]
struct State {
    replies: VecDeque<Vec<u8>>,
    pending: usize,
    read_closed: bool,
    write_closed: bool,
}
pub(crate) struct Endpoint {
    service: Arc<Service>,
    stream: bool,
    // Only this stream's input/framing transaction spans submit. Completion
    // needs only state, never input. Lock order: input -> resolver -> state;
    // no method calls the resolver or takes input while holding state.
    input: Mutex<Input>,
    state: Mutex<State>,
    epoch: AtomicU64,
}
struct Admission<'a> {
    endpoint: &'a Endpoint,
    pending: bool,
}
impl Admission<'_> {
    fn queued(mut self) {
        self.pending = false;
    }
    fn reply(mut self, packet: Vec<u8>) {
        self.pending = false;
        self.endpoint.complete(packet);
    }
}
impl Drop for Admission<'_> {
    fn drop(&mut self) {
        if self.pending {
            self.endpoint.state.lock().unwrap().pending -= 1;
        }
    }
}
impl Endpoint {
    pub fn new(service: Arc<Service>, stream: bool) -> Arc<Self> {
        Arc::new(Self {
            service,
            stream,
            input: Mutex::default(),
            state: Mutex::default(),
            epoch: AtomicU64::new(0),
        })
    }
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Relaxed)
    }
    fn reserve(&self) -> Result<Admission<'_>> {
        let mut s = self.state.lock().unwrap();
        if !self.stream && s.write_closed {
            return Err(NetError(32));
        }
        if s.pending + s.replies.len() >= LIMIT {
            return Err(NetError(11));
        }
        s.pending += 1;
        Ok(Admission {
            endpoint: self,
            pending: true,
        })
    }
    fn complete(&self, mut packet: Vec<u8>) {
        let mut s = self.state.lock().unwrap();
        s.pending -= 1;
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
        self.epoch.fetch_add(1, Relaxed);
    }
    fn pump(self: &Arc<Self>) {
        self.service.tick();
        if !self.stream {
            return;
        }
        let mut input = self.input.lock().unwrap();
        loop {
            if input.bytes.len() < 2 || input.failed {
                return;
            }
            let size = u16::from_be_bytes([input.bytes[0], input.bytes[1]]) as usize;
            if size > 4096 {
                input.failed = true;
                input.bytes.clear();
                return;
            }
            if input.bytes.len() < size + 2 {
                return;
            }
            if self
                .service
                .submit(self, &input.bytes[2..size + 2])
                .is_err()
            {
                return;
            }
            input.bytes.drain(..size + 2);
        }
    }
    pub fn send(self: &Arc<Self>, bytes: &[u8]) -> Result<usize> {
        self.pump();
        if !self.stream {
            if self.state.lock().unwrap().write_closed {
                return Err(NetError(32));
            }
            if bytes.len() > 4096 {
                return Err(NetError(90));
            }
            self.service.submit(self, bytes)?;
            return Ok(bytes.len());
        }
        let mut input = self.input.lock().unwrap();
        let s = self.state.lock().unwrap();
        if s.write_closed {
            return Err(NetError(32));
        }
        if input.failed {
            return Err(NetError(71));
        }
        let size = bytes.len().min(BUFFER - input.bytes.len());
        if size == 0 && !bytes.is_empty() {
            return Err(NetError(11));
        }
        input.bytes.extend_from_slice(&bytes[..size]);
        drop(s);
        drop(input);
        self.pump();
        Ok(size)
    }
    pub fn recv(self: &Arc<Self>, count: usize, flags: u32) -> Result<Received> {
        self.pump();
        let input = self.stream.then(|| self.input.lock().unwrap());
        let mut s = self.state.lock().unwrap();
        if input.as_ref().is_some_and(|i| i.failed) {
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
            return if self.stream
                && s.write_closed
                && s.pending == 0
                && input.as_ref().is_none_or(|i| i.bytes.is_empty())
            {
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
    pub fn poll(self: &Arc<Self>, events: u16) -> u16 {
        self.pump();
        let input = self.stream.then(|| self.input.lock().unwrap());
        let s = self.state.lock().unwrap();
        if input.as_ref().is_some_and(|i| i.failed) {
            return 8 | 16;
        }
        let eof = s.read_closed
            || self.stream
                && s.write_closed
                && s.pending == 0
                && input.as_ref().is_none_or(|i| i.bytes.is_empty());
        let readable = !s.replies.is_empty() || eof;
        let writable = !s.write_closed
            && if self.stream {
                input.as_ref().unwrap().bytes.len() < BUFFER
            } else {
                s.pending + s.replies.len() < LIMIT
            };
        (if readable { events & 1 } else { 0 }) | (if writable { events & 4 } else { 0 })
    }
    pub fn shutdown(&self, how: u32) -> Result<()> {
        if how > 2 {
            return Err(NetError(22));
        }
        let mut s = self.state.lock().unwrap();
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
    #[test]
    fn concurrent_datagram_admission_keeps_the_original_bound_and_returns_slots() {
        fn shared<T: Send + Sync>() {}
        shared::<Service>();
        shared::<Endpoint>();
        let e = Endpoint::new(Service::new(NetworkMode::Loopback), false);
        let start = std::sync::Barrier::new(33);
        std::thread::scope(|scope| {
            let jobs: Vec<_> = (0..32)
                .map(|_| {
                    let (e, start) = (&e, &start);
                    scope.spawn(move || {
                        start.wait();
                        e.send(b"xx")
                    })
                })
                .collect();
            start.wait();
            let mut accepted = 0;
            for job in jobs {
                match job.join().unwrap() {
                    Ok(2) => accepted += 1,
                    Err(NetError(11)) => {}
                    result => panic!("{result:?}"),
                }
            }
            assert_eq!(accepted, LIMIT);
        });
        assert_eq!(e.state.lock().unwrap().pending, 0);
        assert_eq!(e.epoch(), LIMIT as u64);
        for _ in 0..LIMIT {
            assert_eq!(e.recv(512, 0).unwrap().data[3] & 15, 1);
        }
        e.send(b"again").unwrap();
        assert_eq!(e.recv(512, 0).unwrap().data[3] & 15, 1);
        e.shutdown(1).unwrap();
        assert!(matches!(e.send(&vec![0; 4097]), Err(NetError(32))));
    }
    #[test]
    fn concurrent_stream_writers_and_reader_preserve_every_dns_frame_once() {
        let e = Endpoint::new(Service::new(NetworkMode::Loopback), true);
        let start = std::sync::Barrier::new(5);
        std::thread::scope(|scope| {
            for worker in 0..4 {
                let (e, start) = (&e, &start);
                scope.spawn(move || {
                    start.wait();
                    for index in 0..16 {
                        let q = query(worker * 16 + index, b"localhost", 65);
                        let frame = [&(q.len() as u16).to_be_bytes()[..], &q].concat();
                        assert_eq!(e.send(&frame), Ok(frame.len()));
                    }
                });
            }
            start.wait();
            let mut bytes = Vec::new();
            let mut ids = std::collections::BTreeSet::new();
            let deadline = Instant::now() + Duration::from_secs(5);
            while ids.len() < 64 {
                match e.recv(7, 0) {
                    Ok(r) => bytes.extend(r.data),
                    Err(NetError(11)) => std::thread::yield_now(),
                    Err(error) => panic!("{error:?}"),
                }
                while bytes.len() >= 2 {
                    let size = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
                    if bytes.len() < size + 2 {
                        break;
                    }
                    assert!(size >= 12);
                    let id = u16::from_be_bytes([bytes[2], bytes[3]]);
                    assert!(ids.insert(id), "duplicate DNS frame {id}");
                    assert_eq!(bytes[5] & 15, 0);
                    bytes.drain(..size + 2);
                }
                assert!(Instant::now() < deadline, "lost frame or lock cycle");
            }
            assert!(bytes.is_empty());
            assert_eq!(ids, (0..64).collect());
        });
        e.shutdown(1).unwrap();
        assert!(e.recv(512, 0).unwrap().data.is_empty());
        assert_eq!(e.epoch(), 64);
    }
    #[test]
    fn resolver_backpressure_rolls_back_admission_and_preserves_buffered_frames() {
        for stream in [false, true] {
            let service = Service::new(NetworkMode::Full);
            let blocker = Endpoint::new(service.clone(), false);
            let q = query(17, b"localhost", 1);
            // Keep the actual namespace resolver table full without relying
            // on host DNS latency. These weak outstanding targets model jobs
            // whose callers disappear while another socket is backpressured.
            *service.resolver.lock().unwrap() = Some(Resolver {
                worker: dns::Resolver::new(),
                pending: (0..LIMIT as u64)
                    .map(|token| {
                        (
                            token,
                            Pending {
                                endpoint: Arc::downgrade(&blocker),
                                question: q.clone(),
                                deadline: Instant::now() + Duration::from_secs(30),
                            },
                        )
                    })
                    .collect(),
            });
            let e = Endpoint::new(service.clone(), stream);
            if stream {
                let frame = [&(q.len() as u16).to_be_bytes()[..], &q].concat();
                assert_eq!(e.send(&frame), Ok(frame.len()));
                e.shutdown(1).unwrap();
                assert!(
                    matches!(e.recv(512, 0), Err(NetError(11))),
                    "buffered frame must not become EOF"
                );
            } else {
                assert_eq!(e.send(&q), Err(NetError(11)));
            }
            assert_eq!(e.state.lock().unwrap().pending, 0);
            assert!(e.state.lock().unwrap().replies.is_empty());
            drop(blocker);
            if !stream {
                assert_eq!(e.send(&q), Ok(q.len()));
            }
            ready(&e);
            let answer = e.recv(512, 0).unwrap().data;
            let packet = if stream { &answer[2..] } else { &answer[..] };
            assert_eq!(&packet[..2], &q[..2]);
            assert_eq!(packet[3] & 15, 0);
            if stream {
                assert!(e.recv(512, 0).unwrap().data.is_empty());
            }
            assert_eq!(e.state.lock().unwrap().pending, 0);
        }
    }
    #[test]
    fn shared_resolver_dispatches_concurrent_endpoints_and_reclaims_dead_requests() {
        let service = Service::new(NetworkMode::Full);
        std::thread::scope(|scope| {
            for worker in 0..8u16 {
                let e = Endpoint::new(service.clone(), false);
                scope.spawn(move || {
                    for index in 0..8 {
                        let q = query(
                            worker * 8 + index,
                            b"localhost",
                            if worker % 2 == 0 { 1 } else { 28 },
                        );
                        assert_eq!(e.send(&q).unwrap(), q.len());
                        ready(&e);
                        let answer = e.recv(512, 0).unwrap().data;
                        assert_eq!(&answer[..2], &q[..2]);
                        assert_eq!(answer[3] & 15, 0);
                    }
                });
            }
        });
        assert!(service
            .resolver
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .pending
            .is_empty());
        let e = Endpoint::new(service.clone(), false);
        e.send(&query(99, b"localhost", 1)).unwrap();
        let weak = Arc::downgrade(&e);
        drop(e);
        assert!(weak.upgrade().is_none());
        service.tick();
        assert!(service
            .resolver
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .pending
            .is_empty());
        std::thread::spawn(move || drop(service)).join().unwrap();
    }
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
    fn ready(e: &Arc<Endpoint>) {
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
