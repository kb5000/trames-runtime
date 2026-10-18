// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest route/netfilter sockets, bounded subscriptions and namespace-owned control.
//! The logical host eth0 is a read-only view; dynamic links never configure the host.
use super::*;
use std::rc::Weak;
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeSet, VecDeque},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT_NAMESPACE: AtomicU64 = AtomicU64::new(1);
pub(super) struct Namespace {
    id: u64,
    pub(crate) native: std::cell::OnceCell<native::Network>,
    pub(crate) socket_count: Cell<usize>,
    pub(crate) nft_packet_hooks: Cell<bool>,
    // Netlink sockets also pin the complete stack, not just link metadata.
    pub(crate) stack: std::cell::OnceCell<virtualnet::Network>,
    pub(crate) graph: Rc<RefCell<crate::netdev::Topology>>,
    pub(crate) fabric: Rc<RefCell<Option<Fabric>>>,
    listeners: Rc<RefCell<Vec<Weak<Socket>>>>,
    loopback: Option<Rc<Cell<bool>>>,
    pub(super) ping_range: Cell<[u32; 2]>,
    pub(super) unprivileged_port: Cell<u16>,
    quota: Rc<Cell<usize>>,
    live: Cell<usize>,
    next: Cell<u32>,
    ports: RefCell<BTreeSet<(u32, u32)>>,
}
impl Default for Namespace {
    fn default() -> Self {
        let id = NEXT_NAMESPACE.fetch_add(1, Ordering::Relaxed);
        let graph = Rc::new(RefCell::new(crate::netdev::Topology::default()));
        graph.borrow_mut().add_space(id, None, None);
        Self {
            id,
            native: std::cell::OnceCell::new(),
            socket_count: Cell::new(0),
            nft_packet_hooks: Cell::new(true),
            stack: std::cell::OnceCell::new(),
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
    pub fn refresh_native(&self) {
        if let Some(n) = self.native.get() {
            self.graph.borrow_mut().refresh_direct(
                self.id(),
                matches!(n.mode(), NetworkMode::Full | NetworkMode::Outbound),
                n.info(),
            );
        }
    }
    pub fn root_stack(&self) -> Result<virtualnet::Network> {
        if let Some(stack) = self.stack.get() {
            return Ok(stack.clone());
        }
        let n = self.native.get().ok_or(NetError(95))?;
        let fabric = {
            let mut shared = self.fabric.borrow_mut();
            if shared.is_none() {
                *shared = Some(Fabric::new()?);
            }
            shared.as_ref().unwrap().clone()
        };
        let view = crate::netdev::View {
            graph: self.graph.clone(),
            namespace: self.id(),
            native_root: true,
        };
        let stack = fabric.dynamic_environment(n.mode(), view, Rc::new(Cell::new(true)))?;
        self.stack
            .set(stack.clone())
            .ok()
            .expect("root stack initialized by coordinator");
        Ok(stack)
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
}
impl Drop for Namespace {
    fn drop(&mut self) {
        // Tear down sockets before removing connectivity, preserving FIN/RST
        // handling and the existing fabric teardown order. No ownership cycle:
        // virtual namespaces hold only the topology, never this identity.
        if let Some(stack) = self.stack.take() {
            stack.finish();
        }
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
    kind: u32,
    protocol: u32,
    port: Cell<u32>,
    connected: Cell<bool>,
    groups: Cell<u32>,
    overrun: Cell<bool>,
    replies: RefCell<VecDeque<Datagram>>,
    read_epoch: Cell<u64>,
    buffers: Cell<i32>,
    ext_ack: Cell<bool>,
    strict: Cell<bool>,
}
struct Datagram {
    data: Vec<u8>,
    source: [u8; 12],
}
fn source(port: u32, groups: u32) -> [u8; 12] {
    let mut bytes = [0; 12];
    bytes[..2].copy_from_slice(&16u16.to_le_bytes());
    bytes[4..8].copy_from_slice(&port.to_le_bytes());
    bytes[8..12].copy_from_slice(&groups.to_le_bytes());
    bytes
}
fn enqueue(listener: &Socket, data: &[u8], source: [u8; 12]) {
    let mut q = listener.replies.borrow_mut();
    if q.len() >= 128 || q.iter().map(|p| p.data.len()).sum::<usize>() + data.len() > MAX_BUFFER {
        listener.overrun.set(true);
    } else {
        q.push_back(Datagram {
            data: data.to_vec(),
            source,
        });
        listener
            .read_epoch
            .set(listener.read_epoch.get().wrapping_add(1));
    }
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
            if listener.protocol != 0
                || listener.namespace.id() != ns
                || listener.groups.get() & group == 0
            {
                continue;
            }
            let p = message(kind, 0, 0, 0, &data);
            enqueue(&listener, &p, source(0, group));
        }
    }
}
impl Socket {
    pub fn new(
        namespace: Rc<Namespace>,
        _info: Option<NetworkInfo>,
        kind: u32,
        protocol: u32,
    ) -> Result<Rc<Self>> {
        if !matches!(protocol, 0 | 12) {
            return Err(NetError(93));
        }
        if !matches!(kind, 2 | 3) {
            return Err(NetError(94));
        }
        namespace.live.set(namespace.live.get() + 1);
        let s = Rc::new(Self {
            namespace: namespace.clone(),
            kind,
            protocol,
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
    fn supported_groups(&self) -> u32 {
        if self.protocol == 0 {
            1 | 0x10 | 0x40 | 0x100 | 0x400
        } else {
            0
        }
    }
    fn autobind(&self) -> Result<()> {
        if self.port.get() != 0 {
            return Ok(());
        }
        let mut next = self.namespace.next.get().max(1);
        while self
            .namespace
            .ports
            .borrow()
            .contains(&(self.protocol, next))
        {
            next = next.checked_add(1).ok_or(NetError(98))?;
        }
        self.namespace
            .next
            .set(next.checked_add(1).ok_or(NetError(98))?);
        self.namespace
            .ports
            .borrow_mut()
            .insert((self.protocol, next));
        self.port.set(next);
        Ok(())
    }
    pub fn bind_bytes(&self, bytes: &[u8]) -> Result<()> {
        let (port, groups) = decode(bytes)?;
        if self.port.get() != 0 {
            return Err(NetError(22));
        }
        if groups & !self.supported_groups() != 0 {
            return Err(NetError(95));
        }
        self.groups.set(groups);
        if port == 0 {
            return self.autobind();
        }
        if !self
            .namespace
            .ports
            .borrow_mut()
            .insert((self.protocol, port))
        {
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
        let mut group = 0;
        if let Some(destination) = destination {
            let (port, groups) = decode(destination)?;
            if port != 0 || groups & !self.supported_groups() != 0 {
                return Err(NetError(95));
            }
            if groups != 0 {
                if !net_admin {
                    return Err(NetError(1));
                }
                // Linux selects the first set destination group. Go reuses
                // the subscriber's bound sockaddr when requesting a dump.
                group = 1 << groups.trailing_zeros();
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
        if self.protocol == 12 {
            self.autobind()?;
            // Admission and commit are one coordinator operation. Never commit
            // a batch whose replies cannot fit, even when the reader stalls.
            let mut queue = self.replies.borrow_mut();
            let available = MAX_BUFFER - queue.iter().map(|p| p.data.len()).sum::<usize>();
            let generated = crate::nftables::request(
                &self.namespace,
                &requests,
                self.port.get(),
                net_admin,
                128 - queue.len(),
                available,
            )?;
            if !generated.is_empty() {
                self.read_epoch.set(self.read_epoch.get().wrapping_add(1));
            }
            queue.extend(generated.into_iter().map(|data| Datagram {
                data,
                source: source(0, 0),
            }));
            return Ok(bytes.len());
        }
        self.namespace.refresh_native();
        if net_admin
            && self.namespace.native.get().is_some()
            && requests.iter().any(|r| {
                matches!(
                    u16::from_le_bytes(r[4..6].try_into().unwrap()),
                    16 | 17 | 19 | 20 | 21 | 24 | 25
                )
            })
        {
            self.namespace.root_stack()?;
        }
        self.autobind()?;
        if group != 0 {
            let mut listeners = self.namespace.listeners.borrow_mut();
            listeners.retain(|s| s.strong_count() != 0);
            for listener in listeners.iter().filter_map(Weak::upgrade) {
                if listener.namespace.id() == self.namespace.id()
                    && listener.port.get() != self.port.get()
                    && listener.groups.get() & group != 0
                {
                    enqueue(&listener, bytes, source(self.port.get(), group));
                }
            }
        }
        let mut replies = Vec::new();
        for request in requests {
            // Bound response storage before a mutating request. Dumps remain
            // side-effect free and are checked against the exact response size.
            if matches!(
                u16::from_le_bytes(request[4..6].try_into().unwrap()),
                16 | 17 | 19 | 20 | 21 | 24 | 25
            ) && (self.replies.borrow().len() + replies.len() >= 128
                || self
                    .replies
                    .borrow()
                    .iter()
                    .map(|p| p.data.len())
                    .sum::<usize>()
                    + replies.iter().map(Vec::len).sum::<usize>()
                    > MAX_BUFFER - 512)
            {
                return Err(NetError(105));
            }
            let r = crate::rtnetlink::request(
                &self.namespace,
                request,
                self.port.get(),
                net_admin,
                resolve,
            )?;
            notify(&self.namespace.listeners, r.changes);
            let generated = r.messages;
            if replies.len() + generated.len() > 128 {
                return Err(NetError(105));
            }
            replies.extend(generated);
        }
        let mut queued = self.replies.borrow_mut();
        if queued.len() + replies.len() > 128
            || queued.iter().map(|p| p.data.len()).sum::<usize>()
                + replies.iter().map(Vec::len).sum::<usize>()
                > MAX_BUFFER
        {
            return Err(NetError(105));
        }
        if !replies.is_empty() {
            self.read_epoch.set(self.read_epoch.get().wrapping_add(1));
        }
        queued.extend(replies.into_iter().map(|data| Datagram {
            data,
            source: source(0, 0),
        }));
        Ok(bytes.len())
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
        let packet = queue.front().ok_or(NetError(11))?;
        let bytes = &packet.data;
        let result = Received {
            netlink_address: Some(packet.source),
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
                if group & !self.supported_groups() != 0 {
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
            (1, 39) => Ok(16),
            (1, 38) => Ok(self.protocol as i32),
            (270, 11) => Ok(i32::from(self.ext_ack.get())),
            (270, 12) => Ok(i32::from(self.strict.get())),
            _ => Err(NetError(92)),
        }
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        self.namespace.live.set(self.namespace.live.get() - 1);
        self.namespace
            .ports
            .borrow_mut()
            .remove(&(self.protocol, self.port.get()));
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
