// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest route/netfilter sockets, bounded subscriptions and namespace-owned control.
//! The logical host eth0 is a read-only view; dynamic links never configure the host.
use super::*;
use crate::shared_state::{Cell, State as SharedState};
use std::sync::Weak;
use std::{
    collections::{BTreeSet, VecDeque},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT_NAMESPACE: AtomicU64 = AtomicU64::new(1);
type InetInodes = std::collections::BTreeMap<(u64, usize), Weak<super::Socket>>;
pub(super) struct Namespace {
    id: u64,
    pub(super) inet_inodes: parking_lot::Mutex<InetInodes>,
    pub(crate) native: std::sync::OnceLock<native::Network>,
    pub(crate) socket_count: std::sync::Arc<crate::socket_quota::Quota>,
    pub(crate) nft_packet_hooks: Cell<bool>,
    // Netlink sockets also pin the complete stack, not just link metadata.
    pub(crate) stack: std::sync::OnceLock<virtualnet::Network>,
    pub(crate) graph: std::sync::Arc<std::sync::RwLock<crate::netdev::Topology>>,
    pub(crate) fabric: Arc<crate::protocol::Group>,
    pub(crate) driver: Arc<crate::protocol::Driver>,
    listeners: Arc<SharedState<Vec<Weak<Socket>>>>,
    pub(super) loopback: Option<std::sync::Arc<crate::netdev::Loopback>>,
    pub(super) ping_range: Cell<[u32; 2]>,
    pub(super) unprivileged_port: Cell<u16>,
    pub(super) port_config: parking_lot::Mutex<()>,
    quota: Arc<crate::socket_quota::Quota<128>>,
    _reservation: crate::socket_quota::Reservation<128>,
    stack_init: parking_lot::Mutex<()>,
    live: Cell<usize>,
    next: Cell<u32>,
    ports: SharedState<BTreeSet<(u32, u32)>>,
}
impl Default for Namespace {
    fn default() -> Self {
        Self::with_socket_limit(crate::MAX_SOCKETS)
    }
}
impl Namespace {
    pub(crate) fn packet_stack() -> Self {
        Self::with_socket_limit(crate::socket_quota::GUEST_SOCKET_LIMIT)
    }
    fn with_socket_limit(socket_limit: usize) -> Self {
        let id = NEXT_NAMESPACE.fetch_add(1, Ordering::Relaxed);
        let graph = std::sync::Arc::new(std::sync::RwLock::new(crate::netdev::Topology::default()));
        graph.write().unwrap().add_space(id, None, None);
        let quota = Arc::new(crate::socket_quota::Quota::default());
        let reservation = quota.reserve().expect("initial namespace reservation");
        let fabric = Arc::new(crate::protocol::Group::default());
        let driver = Arc::new(crate::protocol::Driver::new(&fabric));
        Self {
            id,
            inet_inodes: Default::default(),
            native: std::sync::OnceLock::new(),
            socket_count: Arc::new(crate::socket_quota::Quota::with_limit(socket_limit)),
            nft_packet_hooks: Cell::new(true),
            stack: std::sync::OnceLock::new(),
            graph,
            fabric,
            driver,
            listeners: Arc::default(),
            loopback: None,
            ping_range: Cell::new([0, i32::MAX as u32]),
            unprivileged_port: Cell::new(1024),
            port_config: Default::default(),
            quota,
            _reservation: reservation,
            stack_init: parking_lot::Mutex::new(()),
            live: Cell::new(0),
            next: Cell::new(0),
            ports: SharedState::default(),
        }
    }
}
impl Namespace {
    pub fn notify(&self, changes: Vec<(u64, u16, u32, Vec<u8>)>) {
        let mut wakes = Notifications::default();
        self.link_wakes(&changes, &mut wakes);
        notify_deferred(&self.listeners, changes, &mut wakes);
        wakes.flush();
    }
    fn link_wakes(&self, changes: &[(u64, u16, u32, Vec<u8>)], wakes: &mut Notifications) {
        let graph = self.graph.read().unwrap();
        for (ns, kind, _, data) in changes {
            if matches!(kind, 16 | 17) && data.len() >= 8 {
                graph.link_wakes(
                    *ns,
                    u32::from_le_bytes(data[4..8].try_into().unwrap()),
                    &mut wakes.0,
                );
            }
        }
    }
    pub fn isolated(&self, loopback: std::sync::Arc<crate::netdev::Loopback>) -> Result<Self> {
        let reservation = self.quota.reserve().map_err(|_| NetError(28))?;
        let mut namespace = Self::packet_stack();
        namespace.quota = self.quota.clone();
        namespace._reservation = reservation;
        namespace.fabric = self.fabric.clone();
        namespace.driver = self.driver.clone();
        namespace.listeners = self.listeners.clone();
        {
            let mut graph = self.graph.write().unwrap();
            if !graph.can_add_space() {
                return Err(NetError(28));
            }
            graph.add_space(namespace.id(), Some(loopback.clone()), None);
        }
        namespace.graph = self.graph.clone();
        namespace.loopback = Some(loopback);
        namespace.ping_range.set([1, 0]);
        Ok(namespace)
    }
    pub fn refresh_native(&self) {
        if let Some(n) = self.native.get() {
            let info = n.info();
            crate::netdev::refresh_native(
                &self.graph,
                self.id(),
                matches!(n.mode(), NetworkMode::Full | NetworkMode::Outbound),
                info,
            );
        }
    }
    pub fn root_stack(&self) -> Result<virtualnet::Network> {
        if let Some(stack) = self.stack.get() {
            return Ok(stack.clone());
        }
        let _initialization = self.stack_init.lock();
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
        };
        let stack = fabric.dynamic_environment(
            n.mode(),
            view,
            self.loopback
                .clone()
                .unwrap_or_else(|| Arc::new(crate::netdev::Loopback::new(true))),
        )?;
        fabric.bind_driver(&self.fabric.changed);
        self.stack
            .set(stack.clone())
            .ok()
            .expect("root stack initialized under namespace gate");
        drop(_initialization);
        self.fabric.changed.notify_atomic();
        Ok(stack)
    }
    pub fn id(&self) -> u64 {
        self.id
    }
    pub fn loopback_up(&self) -> bool {
        self.loopback.as_ref().is_none_or(|lo| lo.get())
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
        let mut wakes = Notifications::default();
        let changes: Vec<_> = {
            let mut graph = self.graph.write().unwrap();
            let removed = graph.removed_with_space(self.id());
            for d in &removed {
                if let Some(port) = graph.tunnel(d.namespace, d.index) {
                    wakes.0.push(port.readiness());
                }
            }
            graph.remove_space(self.id());
            removed
                .into_iter()
                .map(|d| (d.namespace, 17, 1, crate::rtnetlink::link_data(&graph, &d)))
                .collect()
        };
        self.link_wakes(&changes, &mut wakes);
        notify_deferred(&self.listeners, changes, &mut wakes);
        wakes.flush();
    }
}
pub(super) struct Socket {
    namespace: Arc<Namespace>,
    kind: u32,
    protocol: u32,
    port: Cell<u32>,
    connected: Cell<bool>,
    groups: Cell<u32>,
    membership_allocated: Cell<bool>,
    overrun: Cell<bool>,
    replies: SharedState<VecDeque<Datagram>>,
    read_epoch: Cell<u64>,
    readiness: Arc<trames_shared::Readiness>,
    send_buffer: Cell<i32>,
    receive_buffer: Cell<i32>,
    filter: std::sync::OnceLock<SharedState<Option<crate::socket_filter::Program>>>,
    ext_ack: Cell<bool>,
    cap_ack: Cell<bool>,
    strict: Cell<bool>,
    pass_credentials: Cell<bool>,
    timestamp: Cell<u32>,
}
struct Datagram {
    data: Vec<u8>,
    source: [u8; 12],
    sender: [u32; 3],
}
fn source(port: u32, groups: u32) -> [u8; 12] {
    let mut bytes = [0; 12];
    bytes[..2].copy_from_slice(&16u16.to_le_bytes());
    bytes[4..8].copy_from_slice(&port.to_le_bytes());
    bytes[8..12].copy_from_slice(&groups.to_le_bytes());
    bytes
}
fn enqueue(
    listener: &Socket,
    data: &[u8],
    source: [u8; 12],
    sender: [u32; 3],
    wakes: &mut Notifications,
) {
    let Some(len) = listener.filtered_length(data) else {
        return;
    };
    let data = &data[..len];
    wakes.0.push(listener.readiness.clone());
    let mut q = listener.replies.borrow_mut();
    if q.len() >= 128
        || q.iter().map(|p| p.data.len()).sum::<usize>() + data.len()
            > listener.receive_buffer.get() as usize
    {
        listener.overrun.set(true);
    } else {
        q.push_back(Datagram {
            data: data.to_vec(),
            source,
            sender,
        });
        listener.read_epoch.update(|n| n.wrapping_add(1));
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
// Drop upgraded owners outside the registry: final close may notify again.
fn live_listeners(registry: &SharedState<Vec<Weak<Socket>>>) -> Vec<Arc<Socket>> {
    let mut registry = registry.borrow_mut();
    registry.retain(|s| s.strong_count() != 0);
    registry.iter().filter_map(Weak::upgrade).collect()
}
// Flush only after queue, topology, registry and outer Socket gates release.
#[derive(Default)]
pub(super) struct Notifications(Vec<Arc<trames_shared::Readiness>>, Vec<Network>);
impl Notifications {
    pub fn flush(mut self) {
        // A final namespace release may itself generate link notifications.
        // Its topology and source Socket gates must already be released.
        drop(self.1);
        self.0.sort_unstable_by_key(Arc::as_ptr);
        self.0.dedup_by(|a, b| Arc::ptr_eq(a, b));
        for source in self.0 {
            source.notify_locked();
        }
    }
}
#[cfg(test)]
fn notify(listeners: &Arc<SharedState<Vec<Weak<Socket>>>>, changes: Vec<(u64, u16, u32, Vec<u8>)>) {
    let mut wakes = Notifications::default();
    notify_deferred(listeners, changes, &mut wakes);
    wakes.flush();
}
fn notify_deferred(
    listeners: &Arc<SharedState<Vec<Weak<Socket>>>>,
    changes: Vec<(u64, u16, u32, Vec<u8>)>,
    wakes: &mut Notifications,
) {
    notify_request(listeners, changes, wakes, None);
}
fn notify_request(
    listeners: &Arc<SharedState<Vec<Weak<Socket>>>>,
    changes: Vec<(u64, u16, u32, Vec<u8>)>,
    wakes: &mut Notifications,
    request: Option<(u16, u32, u32, u16)>,
) {
    if changes.is_empty() {
        return;
    }
    let listeners = live_listeners(listeners);
    for (ns, kind, group, data) in changes {
        let (flags, seq, port) = match request {
            Some((op, seq, port, route_flags)) if op == kind && matches!(kind, 24 | 25) => {
                (route_flags, seq, port)
            }
            Some((op, seq, port, _)) if op == kind && matches!(kind, 20 | 21) && group == 0x10 => {
                (0, seq, port)
            }
            _ if kind == 24 => (0x600, 0, 0),
            _ => (0, 0, 0),
        };
        let mut packet = None;
        for listener in &listeners {
            if listener.protocol != 0
                || listener.namespace.id() != ns
                || listener.groups.get() & group == 0
            {
                continue;
            }
            let p = packet.get_or_insert_with(|| message(kind, flags, seq, port, &data));
            enqueue(listener, p, source(0, group), [0; 3], wakes);
        }
    }
}
impl Socket {
    pub fn new(
        namespace: Arc<Namespace>,
        _info: Option<NetworkInfo>,
        kind: u32,
        protocol: u32,
    ) -> Result<Arc<Self>> {
        if !matches!(protocol, 0 | 12 | 15) {
            return Err(NetError(93));
        }
        if !matches!(kind, 2 | 3) {
            return Err(NetError(94));
        }
        namespace.live.update(|n| n + 1);
        let s = Arc::new(Self {
            namespace: namespace.clone(),
            kind,
            protocol,
            port: Cell::new(0),
            connected: Cell::new(false),
            groups: Cell::new(0),
            membership_allocated: Cell::new(false),
            overrun: Cell::new(false),
            replies: SharedState::new(VecDeque::new()),
            read_epoch: Cell::new(0),
            readiness: Arc::default(),
            send_buffer: Cell::new(65536),
            receive_buffer: Cell::new(65536),
            filter: Default::default(),
            ext_ack: Cell::new(false),
            cap_ack: Cell::new(false),
            strict: Cell::new(false),
            pass_credentials: Cell::new(false),
            timestamp: Cell::new(0),
        });
        namespace
            .listeners
            .borrow_mut()
            .retain(|s| s.strong_count() != 0);
        namespace.listeners.borrow_mut().push(Arc::downgrade(&s));
        Ok(s)
    }
    pub(super) fn set_filter(&self, instructions: Option<&[u8]>) -> Result<()> {
        if let Some(bytes) = instructions {
            let program = crate::socket_filter::Program::new(bytes)?;
            *self.filter.get_or_init(Default::default).borrow_mut() = Some(program);
        } else if self
            .filter
            .get()
            .and_then(|slot| slot.borrow_mut().take())
            .is_none()
        {
            return Err(NetError(2));
        }
        Ok(())
    }
    fn filtered_length(&self, data: &[u8]) -> Option<usize> {
        let Some(slot) = self.filter.get() else {
            return Some(data.len());
        };
        let len = slot
            .borrow()
            .as_ref()
            .map_or(data.len(), |program| program.run(data));
        (len != 0).then_some(len.min(data.len()))
    }
    fn kernel_reply(&self, data: Vec<u8>) -> Option<Datagram> {
        let mut data = self.capped_ack(data);
        data.truncate(self.filtered_length(&data)?);
        Some(Datagram {
            data,
            source: source(0, 0),
            sender: [0; 3],
        })
    }
    fn supported_groups(&self) -> u32 {
        match self.protocol {
            // ND_USEROPT is a valid subscription too. This guest network has
            // no router-advertisement producer, so it remains quiet until one
            // exists, like a Linux interface receiving no advertisements.
            0 => 1 | 4 | 0x10 | 0x40 | 0x80 | 0x100 | 0x400 | (1 << 19),
            // Container devices are provisioned before listeners start. This
            // is the guest's actual quiet uevent channel, not the host's device
            // stream. Device injection and synthetic broadcasts are unsupported.
            15 => u32::MAX,
            _ => 0,
        }
    }
    fn autobind(&self, process: u32) -> Result<()> {
        if self.port.get() != 0 {
            return Ok(());
        }
        let mut ports = self.namespace.ports.borrow_mut();
        // Allocation and publication share the actual port registry transaction.
        if self.port.get() != 0 {
            return Ok(());
        }
        if process != 0 && ports.insert((self.protocol, process)) {
            self.port.set(process);
            return Ok(());
        }
        // Additional sockets use the high port-ID range, leaving ordinary
        // process IDs available to the first socket of each process.
        let mut next = self.namespace.next.get().max(0x8000_0000);
        while ports.contains(&(self.protocol, next)) {
            next = next.wrapping_add(1).max(0x8000_0000);
        }
        self.namespace
            .next
            .set(next.wrapping_add(1).max(0x8000_0000));
        ports.insert((self.protocol, next));
        self.port.set(next);
        Ok(())
    }
    pub fn bind_bytes(&self, bytes: &[u8], process: u32) -> Result<()> {
        let (port, groups) = decode(bytes)?;
        if groups & !self.supported_groups() != 0 {
            return Err(NetError(95));
        }
        let bound = self.port.get();
        if bound != 0 {
            if bound != port {
                return Err(NetError(22));
            }
        } else if port == 0 {
            self.autobind(process)?;
        } else {
            if !self
                .namespace
                .ports
                .borrow_mut()
                .insert((self.protocol, port))
            {
                return Err(NetError(98));
            }
            self.port.set(port);
        }
        if groups != 0 {
            self.membership_allocated.set(true);
        }
        self.groups.set(groups);
        Ok(())
    }
    pub fn connect_bytes(&self, bytes: &[u8], process: u32) -> Result<()> {
        if decode(bytes)? != (0, 0) {
            return Err(NetError(95));
        }
        self.autobind(process)?;
        self.connected.set(true);
        Ok(())
    }
    pub fn local_bytes(&self) -> Result<Vec<u8>> {
        Ok(source(self.port.get(), self.groups.get()).to_vec())
    }
    pub fn peer_bytes(&self) -> Result<Vec<u8>> {
        Ok(address(0))
    }
    pub fn memberships(&self) -> Option<u32> {
        self.membership_allocated.get().then(|| self.groups.get())
    }
    #[cfg(test)]
    pub fn send_bytes(
        &self,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
    ) -> Result<usize> {
        self.send_bytes_authorized(bytes, flags, destination, false)
    }
    #[cfg(test)]
    pub fn send_bytes_authorized(
        &self,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
        net_admin: bool,
    ) -> Result<usize> {
        self.send_with_namespace(bytes, flags, destination, net_admin, &|_| Err(NetError(9)))
    }
    #[cfg(test)]
    pub fn send_with_namespace(
        &self,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
        net_admin: bool,
        resolve: &dyn Fn(u32) -> Result<Network>,
    ) -> Result<usize> {
        let mut wakes = Notifications::default();
        let result = self.send_deferred(
            bytes,
            flags,
            destination,
            net_admin,
            resolve,
            (0, [0; 3]),
            &mut wakes,
        );
        wakes.flush();
        result
    }
    fn capped_ack(&self, mut reply: Vec<u8>) -> Vec<u8> {
        // A single datagram may pack several aligned nlmsghdr records. Compact
        // each ACK in place; never drop later batch ACKs or dump records.
        let (mut read, mut write) = (0, 0);
        while read + 16 <= reply.len() {
            let length = u32::from_le_bytes(reply[read..read + 4].try_into().unwrap()) as usize;
            if length < 16 || length > reply.len() - read {
                return reply;
            }
            let capped = length >= 36
                && u16::from_le_bytes(reply[read + 4..read + 6].try_into().unwrap()) == 2
                && (self.cap_ack.get() || reply[read + 16..read + 20] == [0; 4]);
            let kept = if capped { 36 } else { length };
            let stored = ((length + 3) & !3).min(reply.len() - read);
            let kept_stored = if capped { 36 } else { stored };
            reply.copy_within(read..read + kept_stored, write);
            if capped {
                reply[write..write + 4].copy_from_slice(&(kept as u32).to_le_bytes());
                let flags =
                    u16::from_le_bytes(reply[write + 6..write + 8].try_into().unwrap()) | 0x100;
                reply[write + 6..write + 8].copy_from_slice(&flags.to_le_bytes());
            }
            read += stored;
            write += kept_stored;
        }
        reply.truncate(write);
        reply
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn send_deferred(
        &self,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
        net_admin: bool,
        resolve: &dyn Fn(u32) -> Result<Network>,
        (process, sender): (u32, [u32; 3]),
        wakes: &mut Notifications,
    ) -> Result<usize> {
        if flags & !(MSG_DONTWAIT | MSG_NOSIGNAL) != 0 {
            return Err(NetError(95));
        }
        if bytes.len() > MAX_TRANSFER {
            return Err(NetError(90));
        }
        if self.protocol == 15 {
            return Err(NetError(95));
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
                if self.protocol == 0 {
                    break;
                }
                return Err(NetError(22));
            }
            let length = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            if length < 16 || length > bytes.len() - offset {
                if self.protocol == 0 {
                    break;
                }
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
            if offset > bytes.len() && self.protocol != 0 {
                return Err(NetError(22));
            }
        }
        if bytes.is_empty() {
            return Err(NetError(61));
        }
        if requests.is_empty() && self.protocol != 0 {
            return Err(NetError(22));
        }
        if self.protocol == 12 {
            self.autobind(process)?;
            // Admission and commit share this reply-queue transaction. Never commit
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
            let previous = queue.len();
            queue.extend(
                generated
                    .into_iter()
                    .filter_map(|data| self.kernel_reply(data)),
            );
            if previous != queue.len() {
                self.read_epoch.update(|n| n.wrapping_add(1));
                wakes.0.push(self.readiness.clone());
            }
            return Ok(bytes.len());
        }
        self.namespace.refresh_native();
        if net_admin
            && self.namespace.native.get().is_some()
            && requests.iter().any(|r| {
                matches!(
                    u16::from_le_bytes(r[4..6].try_into().unwrap()),
                    16 | 17 | 19 | 20 | 21 | 24 | 25 | 28 | 29 | 32 | 33
                )
            })
        {
            self.namespace.root_stack()?;
        }
        self.autobind(process)?;
        if group != 0 {
            let listeners = live_listeners(&self.namespace.listeners);
            for listener in &listeners {
                if listener.protocol == self.protocol
                    && listener.namespace.id() == self.namespace.id()
                    && listener.port.get() != self.port.get()
                    && listener.groups.get() & group != 0
                {
                    enqueue(
                        listener,
                        bytes,
                        source(self.port.get(), group),
                        sender,
                        wakes,
                    );
                }
            }
        }
        let mut replies = Vec::new();
        for request in requests {
            // Bound response storage before a mutating request. Dumps remain
            // side-effect free and are checked against the exact response size.
            if matches!(
                u16::from_le_bytes(request[4..6].try_into().unwrap()),
                16 | 17 | 19 | 20 | 21 | 24 | 25 | 28 | 29 | 32 | 33
            ) && (self.replies.borrow().len() + replies.len() >= 128
                || self
                    .replies
                    .borrow()
                    .iter()
                    .map(|p| p.data.len())
                    .sum::<usize>()
                    + replies
                        .iter()
                        .map(|r: &Datagram| r.data.len())
                        .sum::<usize>()
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
            wakes.1.extend(r.retained_namespaces);
            self.namespace.link_wakes(&r.changes, wakes);
            notify_request(
                &self.namespace.listeners,
                r.changes,
                wakes,
                Some((
                    u16::from_le_bytes(request[4..6].try_into().unwrap()),
                    u32::from_le_bytes(request[8..12].try_into().unwrap()),
                    self.port.get(),
                    r.route_flags,
                )),
            );
            let generated = r.messages;
            if replies.len() + generated.len() > 128 {
                return Err(NetError(105));
            }
            replies.extend(
                generated
                    .into_iter()
                    .filter_map(|reply| self.kernel_reply(reply)),
            );
        }
        let mut queued = self.replies.borrow_mut();
        if queued.len() + replies.len() > 128
            || queued.iter().map(|p| p.data.len()).sum::<usize>()
                + replies
                    .iter()
                    .map(|r: &Datagram| r.data.len())
                    .sum::<usize>()
                > MAX_BUFFER
        {
            return Err(NetError(105));
        }
        if !replies.is_empty() {
            self.read_epoch.update(|n| n.wrapping_add(1));
            wakes.0.push(self.readiness.clone());
        }
        queued.extend(replies);
        Ok(bytes.len())
    }
    pub fn subscribe(
        &self,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> trames_shared::IoSubscription {
        self.readiness.subscribe(signal)
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
            ip: Default::default(),
            packet_info: None,
            stream_minimum: 0,
            packet_address: None,
            netlink_address: Some(packet.source),
            credentials: self.pass_credentials.get().then_some(packet.sender),
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
            (1, 16) => self.pass_credentials.set(value != 0),
            (1, 29 | 35 | 63 | 64) => self.timestamp.set(if value != 0 { name } else { 0 }),
            (1, 7) if value > 0 => self.send_buffer.set(value.clamp(4096, MAX_BUFFER as i32)),
            (1, 8) if value > 0 => self
                .receive_buffer
                .set(value.clamp(4096, MAX_BUFFER as i32)),
            (270, 1 | 2) if (1..=32).contains(&value) => {
                let group = 1u32 << (value - 1);
                if group & !self.supported_groups() != 0 {
                    return Err(NetError(95));
                }
                self.membership_allocated.set(true);
                self.groups.set(if name == 1 {
                    self.groups.get() | group
                } else {
                    self.groups.get() & !group
                });
            }
            (270, 10) => self.cap_ack.set(value != 0),
            (270, 11) => self.ext_ack.set(value != 0),
            (270, 12) => self.strict.set(value != 0),
            _ => return Err(NetError(92)),
        }
        Ok(())
    }
    pub fn get_option(&self, level: u32, name: u32) -> Result<i32> {
        match (level, name) {
            (1, 16) => Ok(i32::from(self.pass_credentials.get())),
            (1, 29 | 35 | 63 | 64) => Ok(i32::from(self.timestamp.get() == name)),
            (1, 3) => Ok(self.kind as i32),
            (1, 4) => Ok(if self.overrun.replace(false) { 105 } else { 0 }),
            (1, 7) => Ok(self.send_buffer.get()),
            (1, 8) => Ok(self.receive_buffer.get()),
            (1, 39) => Ok(16),
            (1, 38) => Ok(self.protocol as i32),
            (270, 10) => Ok(i32::from(self.cap_ack.get())),
            (270, 11) => Ok(i32::from(self.ext_ack.get())),
            (270, 12) => Ok(i32::from(self.strict.get())),
            _ => Err(NetError(92)),
        }
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        self.namespace.live.update(|n| n - 1);
        if self.protocol == 12 && self.port.get() != 0 {
            // Release owned nftables before this port ID can be reused.
            let firewall = self
                .namespace
                .graph
                .read()
                .unwrap()
                .firewall(self.namespace.id());
            firewall.release_port(self.port.get());
        }
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
    fn socket_port_ids_and_filtered_delivery_follow_the_calling_process() {
        let ns = Arc::new(Namespace::default());
        let first = Socket::new(ns.clone(), None, 3, 0).unwrap();
        let second = Socket::new(ns.clone(), None, 3, 0).unwrap();
        let events = Socket::new(ns.clone(), None, 3, 15).unwrap();
        for s in [&first, &second, &events] {
            s.bind_bytes(&source(0, 1), 17).unwrap();
        }
        assert_eq!(first.port.get(), 17);
        assert_eq!(events.port.get(), 17);
        assert!(second.port.get() >= 0x8000_0000);
        let mut wakes = Notifications::default();
        let mut ret = [6, 0, 0, 0, 0, 0, 0, 0];
        second.set_option(1, 16, 1).unwrap();
        second.set_filter(Some(&ret)).unwrap();
        let msg = message(1, 1, 3, 0, &[]);
        let send = |wakes: &mut Notifications| {
            first
                .send_deferred(
                    &msg,
                    0,
                    Some(&source(0, 1)),
                    true,
                    &|_| Err(NetError(9)),
                    (45, [45, 78, 99]),
                    wakes,
                )
                .unwrap();
        };
        send(&mut wakes);
        assert_eq!(second.recv(24, 0).err(), Some(NetError(11)));
        ret[4] = 8;
        second.set_filter(Some(&ret)).unwrap();
        assert_eq!(second.set_filter(Some(&[0; 8])), Err(NetError(22)));
        send(&mut wakes);
        let datagram = second.recv(24, 0).unwrap();
        assert_eq!(datagram.data, msg[..8]);
        assert_eq!(datagram.credentials, Some([45, 78, 99]));
        assert_eq!(datagram.netlink_address, Some(source(17, 1)));
        assert_eq!(events.recv(24, 0).err(), Some(NetError(11)));
        second.set_filter(None).unwrap();
        assert_eq!(second.set_filter(None), Err(NetError(2)));
        send(&mut wakes);
        assert_eq!(second.recv(24, 0).unwrap().data, msg);
        drop(first);
        let reused = Socket::new(ns, None, 3, 0).unwrap();
        reused.connect_bytes(&source(0, 0), 17).unwrap();
        assert_eq!(reused.port.get(), 17);
    }
    #[test]
    fn capped_ack_preserves_every_packed_batch_record() {
        let socket = Socket::new(Arc::new(Namespace::default()), None, 3, 12).unwrap();
        socket.set_option(270, 10, 1).unwrap();
        let mut payload = (-22i32).to_le_bytes().to_vec();
        payload.extend_from_slice(&message(0x0a00, 5, 1, 0, &[0; 20]));
        let first = message(2, 0, 1, 0, &payload);
        let second = message(2, 0, 2, 0, &payload);
        let out = socket.capped_ack([first, second].concat());
        assert_eq!(out.len(), 72);
        assert_eq!(&out[8..12], &1u32.to_le_bytes());
        assert_eq!(&out[44..48], &2u32.to_le_bytes());
        assert_eq!(&out[52..56], &(-22i32).to_le_bytes());
    }
    #[test]
    fn capped_error_ack_preserves_original_header_and_marks_truncated_payload() {
        for protocol in [0, 12] {
            let socket = Socket::new(Arc::new(Namespace::default()), None, 3, protocol).unwrap();
            let request = message(0xffff, 5, 99, 0, &[0; 20]);
            socket
                .send_bytes_authorized(&request, 0, None, true)
                .unwrap();
            let full = socket.recv(65536, 0).unwrap().data;
            assert!(full.len() > 36);
            socket.set_option(270, 10, 1).unwrap();
            assert_eq!(socket.get_option(270, 10), Ok(1));
            socket
                .send_bytes_authorized(&request, 0, None, true)
                .unwrap();
            let capped = socket.recv(65536, 0).unwrap().data;
            assert_eq!(capped.len(), 36);
            assert_eq!(&capped[20..36], &request[..16]);
            assert_eq!(
                u16::from_le_bytes(capped[6..8].try_into().unwrap()) & 0x100,
                0x100
            );
            assert_eq!(&capped[16..20], &full[16..20]);
        }
    }
    #[test]
    fn container_uevent_listener_is_quiet_and_separate_from_rtnetlink() {
        let namespace = Arc::new(Namespace::default());
        let events = Socket::new(namespace.clone(), None, 2, 15).unwrap();
        events.bind_bytes(&source(123, u32::MAX), 0).unwrap();
        assert_eq!(events.local_bytes().unwrap(), source(123, u32::MAX));
        events.set_option(1, 16, 1).unwrap();
        assert_eq!(events.get_option(1, 16), Ok(1));
        assert_eq!(events.poll(1), Ok(0));
        assert!(matches!(events.recv(1024, MSG_DONTWAIT), Err(NetError(11))));
        notify(
            &namespace.listeners,
            vec![(namespace.id(), 16, 1, vec![0; 16])],
        );
        assert_eq!(events.poll(1), Ok(0));
        assert_eq!(events.send_bytes(b"injected", 0, None), Err(NetError(95)));
        // Port IDs are scoped by protocol even within the same namespace.
        let routes = Socket::new(namespace, None, 3, 0).unwrap();
        routes.bind_bytes(&source(123, 1 | (1 << 19)), 0).unwrap();
        routes.set_option(1, 16, 1).unwrap();
        routes.set_option(1, 29, 1).unwrap();
        assert_eq!(routes.get_option(1, 29), Ok(1));
        let request = message(18, 1 | 0x300, 42, 0, &[0; 16]);
        routes.send_bytes(&request, 0, None).unwrap();
        // Linux netlink accepts SO_TIMESTAMP but does not attach timestamps.
        assert_eq!(
            routes.recv(65536, MSG_PEEK).unwrap().credentials,
            Some([0, 0, 0])
        );
        let packet = routes.recv(65536, 0).unwrap();
        assert_eq!(packet.credentials, Some([0, 0, 0]));
        assert_eq!(packet.netlink_address, Some(source(0, 0)));
        routes.set_option(1, 16, 0).unwrap();
        routes.set_option(1, 29, 0).unwrap();
        routes.send_bytes(&request, 0, None).unwrap();
        assert_eq!(routes.recv(65536, 0).unwrap().credentials, None);
    }
    #[test]
    fn namespace_resolution_precedes_topology_writer_and_preserves_error_ack() {
        let network = Network::new(NetworkMode::Loopback);
        let mut data = vec![0; 16];
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        attr(&mut data, 28, &55u32.to_le_bytes());
        let request = message(19, 1, 7, 0, &data);
        let mut count = 0;
        let calls = std::cell::Cell::new(0);
        let reply = crate::rtnetlink::request(&network.1, &request, 0, true, &|fd| {
            assert_eq!(fd, 55);
            assert!(
                network.1.graph.try_write().is_ok(),
                "namespace FD lookup held topology writer"
            );
            calls.set(calls.get() + 1);
            Err(NetError(9))
        })
        .unwrap();
        for packet in reply.messages {
            if packet[4..6] == 2u16.to_le_bytes() {
                assert_eq!(i32::from_le_bytes(packet[16..20].try_into().unwrap()), -9);
                count += 1;
            }
        }
        assert_eq!(count, 1);
        assert_eq!(calls.get(), 1);
    }
    #[test]
    fn namespace_target_remains_pinned_in_deferred_notifications() {
        let network = Network::new(NetworkMode::Loopback);
        let target = network.isolated().unwrap();
        let weak = Arc::downgrade(&target.1);
        let target = std::cell::RefCell::new(Some(target));
        let mut data = vec![0; 16];
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        attr(&mut data, 28, &55u32.to_le_bytes());
        let reply =
            crate::rtnetlink::request(&network.1, &message(19, 1, 8, 0, &data), 0, true, &|_| {
                Ok(target.borrow_mut().take().unwrap())
            })
            .unwrap();
        assert!(weak.upgrade().is_some());
        assert_eq!(reply.retained_namespaces.len(), 1);
        let mut wakes = Notifications::default();
        wakes.1.extend(reply.retained_namespaces);
        assert!(weak.upgrade().is_some());
        wakes.flush();
        assert!(weak.upgrade().is_none());
    }
    #[test]
    fn loopback_up_requires_authority_and_never_accepts_real_interface_changes() {
        let s = Socket::new(Arc::new(Namespace::default()), None, 3, 0).unwrap();
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
    fn route_dump_ignores_trailing_bytes_and_preserves_sequence_and_peek() {
        let s = Socket::new(Arc::new(Namespace::default()), None, 3, 0).unwrap();
        let request = message(18, 0x301, 45, 0, &[0; 16]);
        let mut malformed = request.clone();
        malformed.push(1);
        assert_eq!(s.send_bytes(&malformed, 0, None), Ok(malformed.len()));
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
        let s = Socket::new(Arc::new(Namespace::default()), None, 3, 0).unwrap();
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
