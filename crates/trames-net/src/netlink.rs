// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest NETLINK_ROUTE sockets, bounded subscriptions and namespace-owned control.
//! The logical host eth0 is a read-only view; dynamic links never configure the host.
use super::*;
use std::rc::Weak;
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeSet, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT_NAMESPACE: AtomicU64 = AtomicU64::new(1);
pub(super) struct Namespace {
    id: u64,
    pub(crate) graph: Rc<RefCell<crate::netdev::Topology>>,
    pub(crate) fabric: Rc<RefCell<Option<Fabric>>>,
    listeners: Rc<RefCell<Vec<Weak<Socket>>>>,
    loopback: Option<Rc<Cell<bool>>>,
    pub(super) ping_range: Cell<[u32; 2]>,
    pub(super) unprivileged_port: Cell<u16>,
    quota: Rc<Cell<usize>>,
    live: Cell<usize>,
    next: Cell<u32>,
    ports: RefCell<BTreeSet<u32>>,
}
impl Default for Namespace {
    fn default() -> Self {
        let id = NEXT_NAMESPACE.fetch_add(1, Ordering::Relaxed);
        let graph = Rc::new(RefCell::new(crate::netdev::Topology::default()));
        graph.borrow_mut().add_space(id, None, None);
        Self {
            id,
            graph,
            fabric: Rc::default(),
            listeners: Rc::default(),
            loopback: None,
            ping_range: Cell::new([0, i32::MAX as u32]),
            unprivileged_port: Cell::new(1024),
            quota: Rc::new(Cell::new(1)),
            live: Cell::new(0),
            next: Cell::new(0),
            ports: RefCell::default(),
        }
    }
}
impl Namespace {
    pub fn isolated(&self, loopback: Rc<Cell<bool>>) -> Result<Self> {
        if !self.graph.borrow().can_add_space() {
            return Err(NetError(28));
        }
        if self.quota.get() >= 128 {
            return Err(NetError(28));
        }
        self.quota.set(self.quota.get() + 1);
        let mut namespace = Self::default();
        namespace.quota = self.quota.clone();
        namespace.graph = self.graph.clone();
        namespace.fabric = self.fabric.clone();
        namespace.listeners = self.listeners.clone();
        namespace
            .graph
            .borrow_mut()
            .add_space(namespace.id(), Some(loopback.clone()), None);
        namespace.loopback = Some(loopback);
        namespace.ping_range.set([1, 0]);
        Ok(namespace)
    }
    pub fn id(&self) -> u64 {
        self.id
    }
    pub fn loopback_up(&self) -> bool {
        self.loopback.as_ref().is_none_or(|lo| lo.get())
    }
    pub fn set_loopback_up(&self, up: bool) -> Result<()> {
        match &self.loopback {
            Some(lo) => {
                lo.set(up);
                Ok(())
            }
            None if up => Ok(()),
            None => Err(NetError(95)),
        }
    }
    pub fn live(&self) -> usize {
        self.live.get()
    }
}
impl Drop for Namespace {
    fn drop(&mut self) {
        let changes = {
            let mut graph = self.graph.borrow_mut();
            let removed = graph.removed_with_space(self.id());
            graph.remove_space(self.id());
            removed
                .into_iter()
                .map(|d| (d.namespace, 17, 1, crate::rtnetlink::link_data(&graph, &d)))
                .collect()
        };
        notify(&self.listeners, changes);
        self.quota.set(self.quota.get() - 1);
    }
}
pub(super) struct Socket {
    namespace: Rc<Namespace>,
    info: Option<NetworkInfo>,
    kind: u32,
    port: Cell<u32>,
    connected: Cell<bool>,
    groups: Cell<u32>,
    overrun: Cell<bool>,
    replies: RefCell<VecDeque<Vec<u8>>>,
    read_epoch: Cell<u64>,
    buffers: Cell<i32>,
    ext_ack: Cell<bool>,
    strict: Cell<bool>,
}
pub(super) fn address(port: u32) -> Vec<u8> {
    let mut bytes = vec![0; 12];
    bytes[..2].copy_from_slice(&16u16.to_le_bytes());
    bytes[4..8].copy_from_slice(&port.to_le_bytes());
    bytes
}
fn decode(bytes: &[u8]) -> Result<(u32, u32)> {
    if bytes.len() < 12 {
        return Err(NetError(22));
    }
    if bytes[..2] != 16u16.to_le_bytes() {
        return Err(NetError(97));
    }
    Ok((
        u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
    ))
}
pub(crate) fn attr(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    out.extend_from_slice(&((data.len() + 4) as u16).to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(data);
    out.resize((out.len() + 3) & !3, 0);
}
pub(crate) fn message(kind: u16, flags: u16, sequence: u32, port: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + data.len());
    out.extend_from_slice(&((16 + data.len()) as u32).to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&sequence.to_le_bytes());
    out.extend_from_slice(&port.to_le_bytes());
    out.extend_from_slice(data);
    out.resize((out.len() + 3) & !3, 0);
    out
}
fn notify(listeners: &Rc<RefCell<Vec<Weak<Socket>>>>, changes: Vec<(u64, u16, u32, Vec<u8>)>) {
    let mut listeners = listeners.borrow_mut();
    listeners.retain(|s| s.strong_count() != 0);
    for (ns, kind, group, data) in changes {
        for listener in listeners.iter().filter_map(Weak::upgrade) {
            if listener.namespace.id() != ns || listener.groups.get() & group == 0 {
                continue;
            }
            let p = message(kind, 0, 0, 0, &data);
            let mut q = listener.replies.borrow_mut();
            if q.len() >= 128 || q.iter().map(Vec::len).sum::<usize>() + p.len() > MAX_BUFFER {
                listener.overrun.set(true);
            } else {
                q.push_back(p);
                listener
                    .read_epoch
                    .set(listener.read_epoch.get().wrapping_add(1));
            }
        }
    }
}
impl Socket {
    pub fn new(
        namespace: Rc<Namespace>,
        info: Option<NetworkInfo>,
        kind: u32,
        protocol: u32,
    ) -> Result<Rc<Self>> {
        if protocol != 0 {
            return Err(NetError(93));
        }
        if !matches!(kind, 2 | 3) {
            return Err(NetError(94));
        }
        namespace.live.set(namespace.live.get() + 1);
        let s = Rc::new(Self {
            namespace: namespace.clone(),
            info,
            kind,
            port: Cell::new(0),
            connected: Cell::new(false),
            groups: Cell::new(0),
            overrun: Cell::new(false),
            replies: RefCell::new(VecDeque::new()),
            read_epoch: Cell::new(0),
            buffers: Cell::new(65536),
            ext_ack: Cell::new(false),
            strict: Cell::new(false),
        });
        namespace
            .listeners
            .borrow_mut()
            .retain(|s| s.strong_count() != 0);
        namespace.listeners.borrow_mut().push(Rc::downgrade(&s));
        Ok(s)
    }
    fn autobind(&self) -> Result<()> {
        if self.port.get() != 0 {
            return Ok(());
        }
        let mut next = self.namespace.next.get().max(1);
        while self.namespace.ports.borrow().contains(&next) {
            next = next.checked_add(1).ok_or(NetError(98))?;
        }
        self.namespace
            .next
            .set(next.checked_add(1).ok_or(NetError(98))?);
        self.namespace.ports.borrow_mut().insert(next);
        self.port.set(next);
        Ok(())
    }
    pub fn bind_bytes(&self, bytes: &[u8]) -> Result<()> {
        let (port, groups) = decode(bytes)?;
        if self.port.get() != 0 {
            return Err(NetError(22));
        }
        if groups & !(1 | 0x10 | 0x40 | 0x100 | 0x400) != 0 {
            return Err(NetError(95));
        }
        self.groups.set(groups);
        if port == 0 {
            return self.autobind();
        }
        if !self.namespace.ports.borrow_mut().insert(port) {
            return Err(NetError(98));
        }
        self.port.set(port);
        Ok(())
    }
    pub fn connect_bytes(&self, bytes: &[u8]) -> Result<()> {
        if decode(bytes)? != (0, 0) {
            return Err(NetError(95));
        }
        self.autobind()?;
        self.connected.set(true);
        Ok(())
    }
    pub fn local_bytes(&self) -> Result<Vec<u8>> {
        Ok(address(self.port.get()))
    }
    pub fn peer_bytes(&self) -> Result<Vec<u8>> {
        if self.connected.get() {
            Ok(address(0))
        } else {
            Err(NetError(107))
        }
    }
    pub fn send_bytes(
        &self,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
    ) -> Result<usize> {
        self.send_bytes_authorized(bytes, flags, destination, false)
    }
    pub fn send_bytes_authorized(
        &self,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
        net_admin: bool,
    ) -> Result<usize> {
        self.send_with_namespace(bytes, flags, destination, net_admin, &|_| Err(NetError(9)))
    }
    pub fn send_with_namespace(
        &self,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
        net_admin: bool,
        resolve: &dyn Fn(u32) -> Result<Network>,
    ) -> Result<usize> {
        if flags & !(MSG_DONTWAIT | MSG_NOSIGNAL) != 0 {
            return Err(NetError(95));
        }
        if bytes.len() > MAX_TRANSFER {
            return Err(NetError(90));
        }
        if let Some(destination) = destination {
            if decode(destination)? != (0, 0) {
                return Err(NetError(95));
            }
        }
        let mut requests = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            if bytes.len() - offset < 16 {
                return Err(NetError(22));
            }
            let length = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            if length < 16 || length > bytes.len() - offset {
                return Err(NetError(22));
            }
            requests.push(&bytes[offset..offset + length]);
            if requests.len() > 128 {
                return Err(NetError(105));
            }
            if offset + length == bytes.len() {
                break;
            }
            offset += (length + 3) & !3;
            if offset > bytes.len() {
                return Err(NetError(22));
            }
        }
        if requests.is_empty() {
            return Err(NetError(22));
        }
        self.autobind()?;
        let mut replies = Vec::new();
        for request in requests {
            // Bound response storage before a mutating request. Dumps remain
            // side-effect free and are checked against the exact response size.
            if matches!(
                u16::from_le_bytes(request[4..6].try_into().unwrap()),
                16 | 17 | 19 | 20 | 21 | 24 | 25
            ) && (self.replies.borrow().len() + replies.len() >= 128
                || self.replies.borrow().iter().map(Vec::len).sum::<usize>()
                    + replies.iter().map(Vec::len).sum::<usize>()
                    > MAX_BUFFER - 512)
            {
                return Err(NetError(105));
            }
            let generated = if self.namespace.loopback.is_some()
                || self
                    .namespace
                    .graph
                    .borrow()
                    .devices(self.namespace.id())
                    .iter()
                    .any(|d| {
                        matches!(
                            d.kind,
                            crate::DeviceKind::Veth { .. } | crate::DeviceKind::Bridge
                        )
                    })
                || matches!(
                    u16::from_le_bytes(request[4..6].try_into().unwrap()),
                    16 | 17 | 19 | 20 | 21 | 24 | 25
                ) {
                let r = crate::rtnetlink::request(
                    &self.namespace,
                    request,
                    self.port.get(),
                    net_admin,
                    resolve,
                )?;
                notify(&self.namespace.listeners, r.changes);
                r.messages
            } else {
                self.request(request, net_admin)?
            };
            if replies.len() + generated.len() > 128 {
                return Err(NetError(105));
            }
            replies.extend(generated);
        }
        let mut queued = self.replies.borrow_mut();
        if queued.len() + replies.len() > 128
            || queued.iter().map(Vec::len).sum::<usize>()
                + replies.iter().map(Vec::len).sum::<usize>()
                > MAX_BUFFER
        {
            return Err(NetError(105));
        }
        if !replies.is_empty() {
            self.read_epoch.set(self.read_epoch.get().wrapping_add(1));
        }
        queued.extend(replies);
        Ok(bytes.len())
    }
    fn request(&self, request: &[u8], net_admin: bool) -> Result<Vec<Vec<u8>>> {
        let kind = u16::from_le_bytes(request[4..6].try_into().unwrap());
        let flags = u16::from_le_bytes(request[6..8].try_into().unwrap());
        let sequence = u32::from_le_bytes(request[8..12].try_into().unwrap());
        let dump = flags & 0x300 == 0x300;
        let multipart = if dump { 2 } else { 0 };
        let family = request.get(16).copied().unwrap_or(0);
        let mut out = Vec::new();
        let interfaces = [1u32, 2]
            .into_iter()
            .filter(|i| *i == 1 || self.info.is_some());
        match kind {
            16 | 17 | 20 | 21 | 24 | 25 => {
                // The direct root network has an always-up loopback. Accept
                // only the exact idempotent LinkSetUp request; never pretend
                // that down, rename, MTU, address or route changes took effect.
                let loopback_change = kind == 16
                    && request.len() == 32
                    && flags & !5 == 0
                    && request[16..20] == [0; 4]
                    && request[20..24] == 1u32.to_le_bytes()
                    && matches!(
                        u32::from_le_bytes(request[24..28].try_into().unwrap()),
                        0 | 1
                    )
                    && request[28..32] == 1u32.to_le_bytes();
                let up = request.get(24..28) == Some(1u32.to_le_bytes().as_slice());
                let errno: i32 = if !net_admin {
                    -1
                } else if loopback_change && (self.namespace.loopback.is_some() || up) {
                    if let Some(lo) = &self.namespace.loopback {
                        lo.set(up);
                    }
                    0
                } else {
                    -95
                };
                if errno != 0 || flags & 4 != 0 {
                    let mut data = errno.to_le_bytes().to_vec();
                    data.extend_from_slice(&request[..16]);
                    out.push(message(2, 0, sequence, self.port.get(), &data));
                }
                return Ok(out);
            }
            18 if request.len() >= 17 => {
                let mut name = None;
                let mut at = 32;
                while at < request.len() {
                    if request.len() - at < 4 {
                        return Err(NetError(22));
                    }
                    let len = u16::from_le_bytes(request[at..at + 2].try_into().unwrap()) as usize;
                    let kind =
                        u16::from_le_bytes(request[at + 2..at + 4].try_into().unwrap()) & 0x3fff;
                    if len < 4 || len > request.len() - at {
                        return Err(NetError(22));
                    }
                    if kind == 3 {
                        let value = &request[at + 4..at + len];
                        let end = value.iter().position(|b| *b == 0).unwrap_or(value.len());
                        name = Some(&value[..end]);
                    }
                    at += (len + 3) & !3;
                }
                let index = if request.len() >= 24 {
                    u32::from_le_bytes(request[20..24].try_into().unwrap())
                } else {
                    0
                };
                for i in interfaces.filter(|i| {
                    dump || (index == 0 || *i == index)
                        && name.is_none_or(|name| {
                            name == if *i == 1 { b"lo".as_slice() } else { b"eth0" }
                        })
                }) {
                    let lo = i == 1;
                    let mut data = vec![0; 16];
                    data[2..4].copy_from_slice(&(if lo { 772u16 } else { 65534 }).to_le_bytes());
                    data[4..8].copy_from_slice(&i.to_le_bytes());
                    data[8..12].copy_from_slice(
                        &(if lo {
                            if self.namespace.loopback_up() {
                                0x49u32
                            } else {
                                8
                            }
                        } else {
                            0xc1
                        })
                        .to_le_bytes(),
                    );
                    data[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
                    attr(&mut data, 3, if lo { b"lo\0" } else { b"eth0\0" });
                    attr(
                        &mut data,
                        4,
                        &self.info.map_or(65536, |n| n.mtu).to_le_bytes(),
                    );
                    attr(&mut data, 1, &[0; 6]);
                    attr(&mut data, 2, &[0; 6]);
                    attr(
                        &mut data,
                        16,
                        &[if lo {
                            if self.namespace.loopback_up() {
                                0
                            } else {
                                2
                            }
                        } else {
                            6
                        }],
                    );
                    attr(
                        &mut data,
                        33,
                        &[u8::from(!lo || self.namespace.loopback_up())],
                    );
                    attr(&mut data, 13, &0u32.to_le_bytes());
                    out.push(message(16, multipart, sequence, self.port.get(), &data));
                }
            }
            22 if request.len() >= 17 => {
                for i in interfaces {
                    if i == 1 && !self.namespace.loopback_up() {
                        continue;
                    }
                    for af in [2u8, 10] {
                        if family != 0 && family != af {
                            continue;
                        }
                        let lo = i == 1;
                        let address = match (af, lo) {
                            (2, true) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                            (10, true) => IpAddr::V6(Ipv6Addr::LOCALHOST),
                            (2, false) => IpAddr::V4(self.info.unwrap().ipv4),
                            _ => IpAddr::V6(self.info.unwrap().ipv6),
                        };
                        if address.is_unspecified() {
                            continue;
                        }
                        let mut data = vec![
                            af,
                            if lo {
                                if af == 2 {
                                    8
                                } else {
                                    128
                                }
                            } else if af == 2 {
                                self.info.unwrap().prefix4
                            } else {
                                self.info.unwrap().prefix6
                            },
                            0x80,
                            if lo { 254 } else { 0 },
                        ];
                        data.extend_from_slice(&i.to_le_bytes());
                        let bytes = match address {
                            IpAddr::V4(a) => a.octets().to_vec(),
                            IpAddr::V6(a) => a.octets().to_vec(),
                        };
                        attr(&mut data, 1, &bytes);
                        attr(&mut data, 2, &bytes);
                        attr(&mut data, 3, if lo { b"lo\0" } else { b"eth0\0" });
                        attr(&mut data, 8, &0x80u32.to_le_bytes());
                        out.push(message(20, multipart, sequence, self.port.get(), &data));
                    }
                }
            }
            26 if request.len() >= 17 && dump => {
                for af in [2u8, 10] {
                    if family != 0 && family != af {
                        continue;
                    }
                    if let Some(n) = self.info {
                        if (af == 2 && n.ipv4.is_unspecified())
                            || (af == 10 && n.ipv6.is_unspecified())
                        {
                            continue;
                        }
                        let mut data = vec![af, 0, 0, 0, 254, 3, 0, 1, 0, 0, 0, 0];
                        attr(&mut data, 4, &2u32.to_le_bytes());
                        if n.id != 0 {
                            attr(
                                &mut data,
                                5,
                                &if af == 2 {
                                    n.gateway4.octets().to_vec()
                                } else {
                                    n.gateway6.octets().to_vec()
                                },
                            );
                        }
                        out.push(message(24, 2, sequence, self.port.get(), &data));
                        let mut data = vec![
                            af,
                            if af == 2 { n.prefix4 } else { n.prefix6 },
                            0,
                            0,
                            254,
                            2,
                            253,
                            1,
                            0,
                            0,
                            0,
                            0,
                        ];
                        attr(&mut data, 4, &2u32.to_le_bytes());
                        attr(
                            &mut data,
                            1,
                            &if af == 2 {
                                (u32::from(n.ipv4)
                                    & (u32::MAX.checked_shl(32 - n.prefix4 as u32).unwrap_or(0)))
                                .to_be_bytes()
                                .to_vec()
                            } else {
                                (u128::from(n.ipv6)
                                    & (u128::MAX.checked_shl(128 - n.prefix6 as u32).unwrap_or(0)))
                                .to_be_bytes()
                                .to_vec()
                            },
                        );
                        attr(
                            &mut data,
                            7,
                            &if af == 2 {
                                n.ipv4.octets().to_vec()
                            } else {
                                n.ipv6.octets().to_vec()
                            },
                        );
                        out.push(message(24, 2, sequence, self.port.get(), &data));
                    }
                }
            }
            _ => {
                let errno = if matches!(kind, 16 | 17 | 19 | 20 | 21 | 24 | 25 | 27) {
                    -95i32
                } else {
                    -22
                };
                let mut data = errno.to_le_bytes().to_vec();
                data.extend_from_slice(&request[..request.len().min(256)]);
                out.push(message(2, 0, sequence, self.port.get(), &data));
                return Ok(out);
            }
        }
        if dump {
            out.push(message(
                3,
                2,
                sequence,
                self.port.get(),
                &0i32.to_le_bytes(),
            ));
        } else if out.is_empty() || flags & 4 != 0 {
            let mut data = (if out.is_empty() { -19i32 } else { 0 })
                .to_le_bytes()
                .to_vec();
            data.extend_from_slice(&request[..16]);
            out.push(message(2, 0, sequence, self.port.get(), &data));
        }
        Ok(out)
    }
    pub fn address_size(&self) -> usize {
        12
    }
    pub fn bind(&self, _: SocketAddr) -> Result<()> {
        Err(NetError(97))
    }
    pub fn connect(&self, _: SocketAddr) -> Result<()> {
        Err(NetError(97))
    }
    pub fn listen(&self, _: u32) -> Result<()> {
        Err(NetError(95))
    }
    pub fn connect_complete(&self) -> Result<bool> {
        Ok(self.connected.get())
    }
    pub fn resume_connect(&self) -> Result<bool> {
        Ok(self.connected.get())
    }
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Err(NetError(97))
    }
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        Err(NetError(97))
    }
    pub fn shutdown(&self, _: u32) -> Result<()> {
        Err(NetError(95))
    }
    pub fn send(&self, bytes: &[u8], flags: u32, destination: Option<SocketAddr>) -> Result<usize> {
        if destination.is_some() {
            return Err(NetError(97));
        }
        self.send_bytes(bytes, flags, None)
    }
    pub fn recv(&self, count: usize, flags: u32) -> Result<Received> {
        if flags & !(MSG_DONTWAIT | MSG_PEEK | MSG_TRUNC) != 0 {
            return Err(NetError(95));
        }
        if self.overrun.replace(false) {
            return Err(NetError(105));
        }
        let mut queue = self.replies.borrow_mut();
        let bytes = queue.front().ok_or(NetError(11))?;
        let result = Received {
            data: bytes[..bytes.len().min(count)].to_vec(),
            length: bytes.len(),
            truncated: count < bytes.len(),
            address: None,
        };
        if flags & MSG_PEEK == 0 {
            queue.pop_front();
        }
        Ok(result)
    }
    pub fn poll_epoch(&self) -> [u64; 2] {
        [self.read_epoch.get(), 0]
    }
    pub fn poll(&self, events: u16) -> Result<u16> {
        Ok((if self.overrun.get() { 8 } else { 0 })
            | (if self.replies.borrow().is_empty() {
                0
            } else {
                events & 1
            })
            | events & 4)
    }
    pub fn set_option(&self, level: u32, name: u32, value: i32) -> Result<()> {
        match (level, name) {
            (1, 7 | 8) if value > 0 => self.buffers.set(value.clamp(4096, MAX_BUFFER as i32)),
            (270, 1 | 2) if (1..=32).contains(&value) => {
                let group = 1u32 << (value - 1);
                if group & !(1 | 0x10 | 0x40 | 0x100 | 0x400) != 0 {
                    return Err(NetError(95));
                }
                self.groups.set(if name == 1 {
                    self.groups.get() | group
                } else {
                    self.groups.get() & !group
                });
            }
            (270, 11) => self.ext_ack.set(value != 0),
            (270, 12) => self.strict.set(value != 0),
            _ => return Err(NetError(92)),
        }
        Ok(())
    }
    pub fn get_option(&self, level: u32, name: u32) -> Result<i32> {
        match (level, name) {
            (1, 3) => Ok(self.kind as i32),
            (1, 4) => Ok(if self.overrun.replace(false) { 105 } else { 0 }),
            (1, 7 | 8) => Ok(self.buffers.get()),
            (1, 39) => Ok(0),
            (1, 38) => Ok(0),
            (270, 11) => Ok(i32::from(self.ext_ack.get())),
            (270, 12) => Ok(i32::from(self.strict.get())),
            _ => Err(NetError(92)),
        }
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        self.namespace.live.set(self.namespace.live.get() - 1);
        self.namespace.ports.borrow_mut().remove(&self.port.get());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn loopback_up_requires_authority_and_never_accepts_real_interface_changes() {
        let s = Socket::new(Rc::new(Namespace::default()), None, 3, 0).unwrap();
        let mut data = vec![0; 16];
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        data[8..12].copy_from_slice(&1u32.to_le_bytes());
        data[12..16].copy_from_slice(&1u32.to_le_bytes());
        for (admin, index, up, expected) in [
            (false, 1, 1, -1i32),
            (true, 1, 1, 0),
            (true, 1, 0, -95),
            (true, 2, 1, -19),
        ] {
            data[4..8].copy_from_slice(&u32::to_le_bytes(index));
            data[8..12].copy_from_slice(&u32::to_le_bytes(up));
            let request = message(16, 5, 42, 0, &data);
            s.send_bytes_authorized(&request, 0, None, admin).unwrap();
            let reply = s.recv(4096, 0).unwrap();
            assert_eq!(
                i32::from_le_bytes(reply.data[16..20].try_into().unwrap()),
                expected
            );
        }
        data.fill(0);
        attr(&mut data, 3, b"absent\0");
        s.send_bytes(&message(18, 1, 43, 0, &data), 0, None)
            .unwrap();
        let reply = s.recv(4096, 0).unwrap();
        assert_eq!(
            i32::from_le_bytes(reply.data[16..20].try_into().unwrap()),
            -19
        );
    }
    #[test]
    fn malformed_multi_request_has_no_reply_and_dump_preserves_sequence_and_peek() {
        let s = Socket::new(Rc::new(Namespace::default()), None, 3, 0).unwrap();
        let request = message(18, 0x301, 45, 0, &[0; 16]);
        let mut malformed = request.clone();
        malformed.push(1);
        assert_eq!(s.send_bytes(&malformed, 0, None), Err(NetError(22)));
        assert_eq!(s.poll(1), Ok(0));
        assert_eq!(s.port.get(), 0);
        assert_eq!(s.send_bytes(&request, 0, None), Ok(request.len()));
        let peek = s.recv(4, MSG_PEEK).unwrap();
        assert!(peek.truncated);
        let link = s.recv(65536, 0).unwrap();
        assert_eq!(&link.data[4..6], &16u16.to_le_bytes());
        assert_eq!(&link.data[8..12], &45u32.to_le_bytes());
        assert!(link.data.windows(3).any(|w| w == b"lo\0"));
        assert_eq!(peek.length, link.length);
        assert_eq!(&s.recv(65536, 0).unwrap().data[4..6], &3u16.to_le_bytes());
        assert_eq!(s.poll(1), Ok(0));
    }
    #[test]
    fn reply_and_request_limits_fail_without_appending_partial_results() {
        let s = Socket::new(Rc::new(Namespace::default()), None, 3, 0).unwrap();
        let request = message(18, 0x301, 1, 0, &[0; 16]);
        assert_eq!(
            s.send_bytes(&request.repeat(129), 0, None),
            Err(NetError(105))
        );
        assert_eq!(s.poll(1), Ok(0));
        for _ in 0..64 {
            s.send_bytes(&request, 0, None).unwrap();
        }
        assert_eq!(s.replies.borrow().len(), 128);
        assert_eq!(s.send_bytes(&request, 0, None), Err(NetError(105)));
        assert_eq!(s.replies.borrow().len(), 128);
    }
}
