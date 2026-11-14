// SPDX-License-Identifier: GPL-3.0-or-later
//! Checked sockets with native and isolated userspace packet-stack backends.
mod conntrack;
mod direct_dns;
mod dns;
mod hybrid;
mod interfaces;
mod native;
mod netdev;
mod netlink;
mod nftables;
mod rtnetlink;
mod shared_state;
mod socket_quota;
pub use netdev::{Address as DeviceAddress, Device, DeviceKind, Route as DeviceRoute};
mod virtualnet;
use crate::shared_state::Cell;
pub use native::{
    decode_address, encode_address, DirectControl, DirectTcp, NetError, NetworkMode, Received,
    TcpLease, TcpPoll, MAX_BUFFER, MAX_SOCKETS, MAX_TRANSFER, MSG_DONTWAIT, MSG_NOSIGNAL, MSG_PEEK,
    MSG_TRUNC,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
pub use virtualnet::{Fabric, LinkStats, NetworkInfo, NetworkStats};
type Result<T> = std::result::Result<T, NetError>;
#[derive(Clone)]
pub struct SocketInfo {
    /// Identity of the socket's creating network namespace, retained across setns.
    pub namespace_id: u64,
    pub family: u32,
    pub kind: u32,
    pub protocol: u32,
    pub state: u8,
    pub local: Option<SocketAddr>,
    pub peer: Option<SocketAddr>,
    pub tx_queue: Option<usize>,
    pub rx_queue: Option<usize>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketInfo {
    pub address: std::net::IpAddr,
    pub interface: u32,
}
#[derive(Clone)]
pub struct Network(Backend, Arc<netlink::Namespace>);
#[derive(Clone)]
enum Backend {
    Native(native::Network),
    Virtual(virtualnet::Network),
}
impl Default for Network {
    fn default() -> Self {
        Self::new(NetworkMode::Off)
    }
}
impl Network {
    pub fn is_managed_uplink(&self) -> bool {
        self.1.graph.read().unwrap().managed(self.namespace_id())
    }
    pub fn stable_secret(&self, scope: u32) -> Result<std::net::Ipv6Addr> {
        self.1
            .graph
            .read()
            .unwrap()
            .stable_secret(self.namespace_id(), scope)
    }
    pub fn set_stable_secret(&self, scope: u32, secret: std::net::Ipv6Addr) -> Result<()> {
        self.1
            .graph
            .write()
            .unwrap()
            .set_stable_secret(self.namespace_id(), scope, secret)
    }
    pub fn ipv6_knob(&self, scope: u32, knob: usize) -> Result<i32> {
        self.1
            .graph
            .read()
            .unwrap()
            .ipv6_knob(self.namespace_id(), scope, knob)
    }
    pub fn set_ipv6_knob(&self, scope: u32, knob: usize, value: i32) -> Result<()> {
        let changes =
            self.1
                .graph
                .write()
                .unwrap()
                .set_ipv6_knob(self.namespace_id(), scope, knob, value)?;
        self.1.notify(changes);
        Ok(())
    }
    /// Trusted embedder test/service mapping; never reachable from a guest syscall.
    pub fn map_host_ip(
        &self,
        virtual_ip: std::net::IpAddr,
        host_ip: std::net::IpAddr,
    ) -> Result<()> {
        let fabric = {
            let mut shared = self.1.fabric.borrow_mut();
            if shared.is_none() {
                *shared = Some(Fabric::new()?);
            }
            shared.as_ref().unwrap().clone()
        };
        fabric.map_host_ip(virtual_ip, host_ip)
    }
    /// Host-authorized mapping on an existing private network, never a syscall.
    pub fn publish_port(&self, host: SocketAddr, port: u16, kind: u32) -> Result<()> {
        let Backend::Virtual(stack) = &self.0 else {
            return Err(NetError(95));
        };
        let info = stack.info();
        let guest = SocketAddr::new(
            if host.is_ipv4() {
                info.ipv4.into()
            } else {
                info.ipv6.into()
            },
            port,
        );
        stack.fabric().publish(host, guest, kind)
    }
    pub fn unpublish_port(&self, host: SocketAddr, kind: u32) -> Result<()> {
        let Backend::Virtual(stack) = &self.0 else {
            return Err(NetError(95));
        };
        stack.fabric().unpublish(host, kind)
    }
    pub fn namespace_id(&self) -> u64 {
        self.1.id()
    }
    pub fn ping_range(&self) -> [u32; 2] {
        self.1.ping_range.get()
    }
    pub fn set_ping_range(&self, range: [u32; 2]) {
        self.1.ping_range.set(range);
    }
    pub fn unprivileged_port(&self) -> u16 {
        self.1.unprivileged_port.get()
    }
    pub fn set_unprivileged_port(&self, port: u16) {
        self.1.unprivileged_port.set(port);
    }
    /// A new Linux network namespace starts with an unconfigured, down lo and
    /// no external devices. Its stack never binds a host listener.
    pub fn isolated(&self) -> Result<Self> {
        let mode = match &self.0 {
            Backend::Native(n) => n.mode(),
            Backend::Virtual(n) => n.mode(),
        };
        let fabric = {
            let mut shared = self.1.fabric.borrow_mut();
            if shared.is_none() {
                *shared = Some(Fabric::new()?);
            }
            shared.as_ref().unwrap().clone()
        };
        let loopback = std::sync::Arc::new(netdev::Loopback::new(false));
        let namespace = Arc::new(self.1.isolated(loopback.clone())?);
        let view = netdev::View {
            graph: namespace.graph.clone(),
            namespace: namespace.id(),
        };
        let stack = fabric.dynamic_environment(mode, view, loopback)?;
        namespace
            .stack
            .set(stack.clone())
            .ok()
            .expect("new namespace stack");
        Ok(Self(Backend::Virtual(stack), namespace))
    }
    pub fn devices(&self) -> Vec<Device> {
        self.1.refresh_native();
        self.1.graph.read().unwrap().devices(self.namespace_id())
    }
    pub fn set_device_up(&self, index: u32, up: bool) -> Result<()> {
        if self.1.native.get().is_some() {
            self.1.root_stack()?;
        }
        self.1.graph.write().unwrap().change_link(
            self.namespace_id(),
            index,
            None,
            None,
            Some(up),
            None,
            None,
            None,
        )
    }
    pub fn loopback_up(&self) -> bool {
        self.1.loopback_up()
    }
    pub fn set_loopback_up(&self, up: bool) -> Result<()> {
        self.1.set_loopback_up(up)
    }
    pub fn new(mode: NetworkMode) -> Self {
        let native = native::Network::new(mode);
        let namespace = Arc::new(netlink::Namespace::default());
        namespace
            .graph
            .write()
            .unwrap()
            .add_space(namespace.id(), None, native.info());
        namespace
            .native
            .set(native.clone())
            .ok()
            .expect("new native namespace");
        namespace.refresh_native();
        Self(Backend::Native(native), namespace)
    }
    /// Configurable guest IP link with the existing userspace/native gateway;
    /// host interface addresses and routes remain outside guest control.
    pub fn managed_uplink(mode: NetworkMode) -> Result<Self> {
        let network = Self::new(mode);
        network.1.graph.write().unwrap().manage_uplink(
            network.namespace_id(),
            matches!(mode, NetworkMode::Full | NetworkMode::Outbound),
        );
        let stack = network.1.root_stack()?;
        Ok(Self(Backend::Virtual(stack), network.1))
    }
    pub fn set_device_ipv4(
        &self,
        index: u32,
        address: Option<std::net::Ipv4Addr>,
        prefix: Option<u8>,
    ) -> Result<()> {
        let changes = {
            let mut graph = self.1.graph.write().unwrap();
            let before = graph.device(self.namespace_id(), index)?;
            graph.ioctl_ipv4(self.namespace_id(), index, address, prefix)?;
            let after = graph.device(self.namespace_id(), index)?;
            let mut changes = Vec::new();
            for (a, kind) in before
                .addresses
                .iter()
                .filter(|a| !after.addresses.contains(a))
                .map(|a| (a, 21))
                .chain(
                    after
                        .addresses
                        .iter()
                        .filter(|a| !before.addresses.contains(a))
                        .map(|a| (a, 20)),
                )
            {
                changes.push((
                    self.namespace_id(),
                    kind,
                    0x10,
                    rtnetlink::address_data(&after, *a),
                ));
            }
            changes
        };
        self.1.notify(changes);
        Ok(())
    }
    pub fn virtual_network(fabric: &Fabric, id: u8, mode: NetworkMode) -> Result<Self> {
        let stack = fabric.environment(id, mode)?;
        let namespace = Arc::new(netlink::Namespace::default());
        namespace.nft_packet_hooks.set(false);
        namespace
            .graph
            .write()
            .unwrap()
            .add_space(namespace.id(), None, Some(stack.info()));
        namespace
            .stack
            .set(stack.clone())
            .ok()
            .expect("new explicit fabric namespace stack");
        Ok(Self(Backend::Virtual(stack), namespace))
    }
    pub fn forwarding(&self, ipv6: bool) -> bool {
        self.1
            .graph
            .read()
            .unwrap()
            .forwarding(self.namespace_id(), ipv6)
    }
    pub fn set_forwarding(&self, ipv6: bool, enabled: bool) {
        self.1
            .graph
            .write()
            .unwrap()
            .set_forwarding(self.namespace_id(), ipv6, enabled);
    }
    pub fn bridge_filter(&self, ipv6: bool) -> bool {
        self.1
            .graph
            .read()
            .unwrap()
            .bridge_filter(self.namespace_id(), ipv6)
    }
    pub fn set_bridge_filter(&self, ipv6: bool, enabled: bool) {
        self.1
            .graph
            .write()
            .unwrap()
            .set_bridge_filter(self.namespace_id(), ipv6, enabled);
    }
    pub fn routes(&self) -> Vec<DeviceRoute> {
        self.1.refresh_native();
        self.1.graph.read().unwrap().routes(self.namespace_id())
    }
    pub fn device_carrier(&self, d: &Device) -> bool {
        self.1.graph.read().unwrap().carrier(d)
    }
    pub fn live_sockets(&self) -> usize {
        self.1.socket_count.live()
    }
    pub fn info(&self) -> Option<NetworkInfo> {
        self.1.refresh_native();
        match &self.0 {
            Backend::Native(n) => n.info(),
            Backend::Virtual(n) => (!n.is_isolated()).then(|| n.info()),
        }
    }
    pub fn links(&self) -> Option<[LinkStats; 2]> {
        match &self.0 {
            Backend::Native(n) => Some(n.links()),
            Backend::Virtual(n) => Some(n.links()),
        }
    }
    pub fn finish(&self) {
        if let Some(stack) = self.1.stack.get() {
            stack.finish();
        } else if let Backend::Virtual(n) = &self.0 {
            n.finish();
        }
    }
    pub fn socket(&self, family: u32, kind: u32, protocol: u32) -> Result<Arc<Socket>> {
        let reservation = self.1.socket_count.reserve()?;
        if family == 16 {
            return Ok(Socket::wrap(
                SocketBackend::Netlink(netlink::Socket::new(
                    self.1.clone(),
                    self.info(),
                    kind,
                    protocol,
                )?),
                self.1.clone(),
                reservation,
                kind,
            ));
        }
        let backend = match &self.0 {
            Backend::Native(n) => SocketBackend::Hybrid(hybrid::Socket::new(
                n.clone(),
                self.1.clone(),
                family,
                kind,
                protocol,
            )?),
            Backend::Virtual(n) => SocketBackend::Virtual(n.socket(family, kind, protocol)?),
        };
        Ok(Socket::wrap(backend, self.1.clone(), reservation, kind))
    }
}
pub struct Socket {
    inode_owner: Cell<u64>,
    // Immutable ABI type, retained across native/virtual endpoint transitions.
    kind: u32,
    // Serializes endpoint/control transitions, while ordinary data operations
    // can run concurrently. Cached native byte capabilities bypass this gate.
    operation: parking_lot::RwLock<()>,
    backend: SocketBackend,
    namespace: Arc<netlink::Namespace>,
    timeouts: [Cell<Option<Duration>>; 2],
    // Drop after the backend and namespace; the lease itself contains no Arc.
    _reservation: socket_quota::Reservation,
    changed: Arc<trames_shared::Readiness>,
}
enum SocketBackend {
    Hybrid(Arc<hybrid::Socket>),
    Netlink(Arc<netlink::Socket>),
    Native(Arc<native::Socket>),
    Virtual(Arc<virtualnet::Socket>),
}
macro_rules! delegate {
    ($gate:ident, $name:ident($($arg:ident:$ty:ty),*) -> $ret:ty) => {
        pub fn $name(&self,$($arg:$ty),*) -> $ret {
            let _operation = self.operation.$gate();
            match &self.backend {SocketBackend::Hybrid(s)=>s.$name($($arg),*), SocketBackend::Native(s)=>s.$name($($arg),*),SocketBackend::Virtual(s)=>s.$name($($arg),*), SocketBackend::Netlink(s)=>s.$name($($arg),*) }
        }
    }
}
/// One original native observer, with stable identity across repeated waits.
/// The handle keeps that identity allocated until its registration is retired.
#[derive(Clone)]
pub enum WaitSource {
    Native(Arc<native::Socket>),
    Link(Arc<std::os::unix::net::UnixDatagram>),
}
impl WaitSource {
    pub fn identity(&self) -> usize {
        match self {
            Self::Native(s) => Arc::as_ptr(s) as usize,
            Self::Link(s) => Arc::as_ptr(s) as usize,
        }
    }
    pub fn drain(&self) {
        if let Self::Native(s) = self {
            let _ = s.poll_epoch();
        }
    }
    fn fd(&self) -> std::io::Result<std::os::fd::OwnedFd> {
        match self {
            Self::Native(s) => s.wait_event_fd(),
            Self::Link(s) => Ok(s.try_clone()?.into()),
        }
    }
    pub fn open(&self) -> std::io::Result<trames_shared::HostFd> {
        let keep: Arc<dyn std::any::Any + Send + Sync> = match self {
            Self::Native(s) => Arc::new(Arc::downgrade(s)),
            Self::Link(s) => s.clone(),
        };
        Ok(trames_shared::HostFd::retained(self.fd()?, keep))
    }
}
impl Socket {
    pub fn inode_owner(&self) -> [u32; 2] {
        let v = self.inode_owner.get();
        [v as u32, (v >> 32) as u32]
    }
    /// Set the fresh sockfs inode's creator, before publishing the descriptor.
    /// Accepted transport routing UID is inherited separately from its listener.
    pub fn initialize_inode_owner(&self, uid: u32, gid: u32) {
        self.inode_owner.set(uid as u64 | ((gid as u64) << 32));
    }
    /// Serialize the actual inode metadata change and its Linux sk_uid update
    /// on this socket's existing control gate, without a service thread.
    pub fn chown(
        &self,
        uid: u32,
        gid: u32,
        authorize: impl FnOnce([u32; 2]) -> Result<()>,
    ) -> Result<()> {
        let _operation = self.operation.write();
        let mut owner = self.inode_owner();
        authorize(owner)?;
        if uid != u32::MAX {
            self.set_owner_uid(uid);
            owner[0] = uid;
        }
        if gid != u32::MAX {
            owner[1] = gid;
        }
        self.initialize_inode_owner(owner[0], owner[1]);
        Ok(())
    }
    pub fn set_owner_uid(&self, uid: u32) {
        if let SocketBackend::Virtual(socket) = &self.backend {
            socket.set_owner_uid(uid);
        }
    }
    fn wrap(
        backend: SocketBackend,
        namespace: Arc<netlink::Namespace>,
        reservation: socket_quota::Reservation,
        kind: u32,
    ) -> Arc<Self> {
        Arc::new(Self {
            inode_owner: Cell::new(0),
            kind: kind & 0xf,
            operation: parking_lot::RwLock::new(()),
            backend,
            namespace,
            timeouts: [Cell::new(None), Cell::new(None)],
            _reservation: reservation,
            changed: Arc::default(),
        })
    }
    pub fn is_stream(&self) -> bool {
        self.kind == 1
    }
    /// Connected-native transport capability with the original live policy.
    /// Ordinary snapshots stay weak; accepted calls retain the actual socket.
    pub fn quiescent_tcp(&self) -> bool {
        let _operation = self.operation.read_recursive();
        match &self.backend {
            SocketBackend::Native(s) => s.quiescent_tcp(),
            SocketBackend::Hybrid(s) => s.quiescent_tcp(),
            _ => false,
        }
    }
    pub fn idle_tcp(&self) -> bool {
        let _operation = self.operation.read_recursive();
        match &self.backend {
            SocketBackend::Native(socket) => socket.idle_tcp(),
            SocketBackend::Hybrid(socket) => socket.idle_tcp(),
            _ => false,
        }
    }
    pub fn direct_control(&self) -> Option<DirectControl> {
        let _operation = self.operation.read_recursive();
        let mut control = match &self.backend {
            SocketBackend::Native(s) => s.direct_control(),
            SocketBackend::Hybrid(s) => s.direct_control(),
            _ => None,
        }?;
        control.timeouts = [false, true].map(|receive| self.io_timeout(receive));
        Some(control)
    }
    /// Native control stays on the same endpoint while the operation runs.
    /// The full socket, not a publication mirror, owns control transitions.
    pub fn with_direct_control<T>(&self, operation: impl FnOnce(&DirectControl) -> T) -> Option<T> {
        let _operation = self.operation.read_recursive();
        let control = self.direct_control()?;
        let _lease = control.retain().ok()?;
        Some(operation(&control))
    }
    pub fn direct_tcp(&self) -> Option<DirectTcp> {
        let _operation = self.operation.read_recursive();
        match &self.backend {
            SocketBackend::Native(s) => s.direct_tcp(),
            SocketBackend::Hybrid(s) => s.direct_tcp(),
            _ => None,
        }
    }
    /// Guest socket timeouts are enforced by the virtual task scheduler; host
    /// sockets remain nonblocking. The shared socket owns them across dup/fork.
    pub fn set_io_timeout(&self, receive: bool, timeout: Option<Duration>) {
        let _operation = self.operation.write();
        self.timeouts[usize::from(receive)].set(timeout);
    }
    pub fn io_timeout(&self, receive: bool) -> Option<Duration> {
        self.timeouts[usize::from(receive)].get()
    }
    pub fn poll_epoch(&self) -> Option<[u64; 2]> {
        let _operation = self.operation.read_recursive();
        match &self.backend {
            SocketBackend::Netlink(s) => Some(s.poll_epoch()),
            SocketBackend::Native(s) => s.poll_epoch(),
            SocketBackend::Hybrid(s) => s.poll_epoch(),
            SocketBackend::Virtual(s) => Some(s.poll_epoch()),
        }
    }
    /// Existing native edge observers and packet-stack timer for one retained
    /// operation. Drain old edges before the deciding retry; no service thread.
    pub fn wait_interests(&self) -> (Vec<WaitSource>, Option<Duration>) {
        let _operation = self.operation.read_recursive();
        let (mut native, fabric) = match &self.backend {
            SocketBackend::Native(s) => (vec![s.clone()], None),
            SocketBackend::Hybrid(s) => {
                let (native, fabric) = s.waiters(5);
                (native.into_iter().map(|(s, _)| s).collect(), fabric)
            }
            SocketBackend::Virtual(s) => (Vec::new(), Some(s.fabric())),
            SocketBackend::Netlink(_) => (Vec::new(), None),
        };
        let delay = fabric.as_ref().map(|f| f.next_wait());
        let external = fabric.as_ref().and_then(|f| f.external_waiter());
        if let Some(fabric) = fabric {
            native.extend(fabric.native_waiters().into_iter().map(|(s, _)| s));
        }
        let mut sources: Vec<_> = native
            .into_iter()
            .flat_map(|socket| socket.wait_interests())
            .collect();
        if let Some(link) = external {
            sources.push(WaitSource::Link(link));
        }
        (sources, delay)
    }
    pub fn wait_sources(&self) -> std::io::Result<(Vec<std::os::fd::OwnedFd>, Option<Duration>)> {
        let (sources, delay) = self.wait_interests();
        let fds = sources
            .into_iter()
            .map(|source| {
                source.drain();
                source.fd()
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        Ok((fds, delay))
    }
    /// Timer of the original packet stack without duplicating native FDs.
    pub fn wait_delay(&self) -> Option<Duration> {
        let _operation = self.operation.read_recursive();
        match &self.backend {
            SocketBackend::Hybrid(socket) => socket.waiters(5).1.map(|fabric| fabric.next_wait()),
            SocketBackend::Virtual(socket) => Some(socket.fabric().next_wait()),
            _ => None,
        }
    }
    pub fn subscribe_changes(
        &self,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> trames_shared::IoSubscription {
        self.changed.subscribe(signal)
    }
    /// Identity of the original event-source selection, not a data epoch.
    pub fn wait_revision(&self) -> u64 {
        match &self.backend {
            SocketBackend::Hybrid(socket) => socket.wait_revision(),
            SocketBackend::Native(socket) => socket.wait_revision(),
            SocketBackend::Virtual(socket) => socket.fabric().revision(),
            _ => 0,
        }
    }
    /// The VFS publishes control changes after releasing its admission lock.
    pub fn publish_changes(&self) {
        self.changed.notify_atomic();
    }
    pub fn info(&self) -> Option<SocketInfo> {
        let _operation = self.operation.read_recursive();
        let mut info = match &self.backend {
            SocketBackend::Hybrid(s) => Some(s.info()),
            SocketBackend::Virtual(s) => Some(s.info()),
            SocketBackend::Native(s) => Some(s.info()),
            SocketBackend::Netlink(_) => None,
        }?;
        info.namespace_id = self.namespace.id();
        Some(info)
    }
    pub fn set_option_bytes(&self, level: u32, name: u32, value: &[u8]) -> Result<()> {
        if let SocketBackend::Hybrid(s) = &self.backend {
            let _operation = self.operation.write();
            return s.set_option_bytes(level, name, value);
        }
        if let SocketBackend::Native(s) = &self.backend {
            let _operation = self.operation.write();
            return s.set_option_bytes(level, name, value);
        }
        if let SocketBackend::Virtual(s) = &self.backend {
            let _operation = self.operation.write();
            return s.set_option_bytes(level, name, value);
        }
        if value.len() < 4 {
            return Err(NetError(22));
        }
        self.set_option(
            level,
            name,
            i32::from_le_bytes(value[..4].try_into().unwrap()),
        )
    }
    pub fn send_packet(
        &self,
        bytes: &[u8],
        flags: u32,
        destination: Option<SocketAddr>,
        mut info: PacketInfo,
    ) -> Result<usize> {
        let _operation = self.operation.read_recursive();
        self.namespace.refresh_native();
        let graph = self.namespace.graph.read().unwrap();
        let owned_ip = match info.address {
            std::net::IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map_or(info.address, std::net::IpAddr::V4),
            ip => ip,
        };
        if info.interface != 0 {
            let device = graph.device(self.namespace.id(), info.interface)?;
            if info.address.is_unspecified() {
                info.address = device
                    .addresses
                    .iter()
                    .find(|a| a.ip.is_ipv4() == info.address.is_ipv4())
                    .ok_or(NetError(99))?
                    .ip;
            } else if !device.addresses.iter().any(|a| {
                a.ip == owned_ip
                    || device.kind == DeviceKind::Loopback
                        && owned_ip.is_loopback()
                        && a.contains(owned_ip)
            }) {
                return Err(NetError(99));
            }
        }
        if !owned_ip.is_unspecified() && !graph.own(self.namespace.id(), owned_ip) {
            return Err(NetError(99));
        }
        drop(graph);
        match &self.backend {
            SocketBackend::Native(s) => s.send_packet(bytes, flags, destination, info),
            SocketBackend::Virtual(s) => s.send_control(bytes, flags, destination, Some(info)),
            SocketBackend::Hybrid(s) => s.send_control(bytes, flags, destination, Some(info)),
            _ => Err(NetError(95)),
        }
    }
    pub fn ancillary_hop(&self) -> Option<(u32, u32, u8)> {
        let _operation = self.operation.read_recursive();
        if let SocketBackend::Hybrid(s) = &self.backend {
            return s.ancillary_hop();
        }
        if let SocketBackend::Virtual(s) = &self.backend {
            s.ancillary_hop()
        } else if let SocketBackend::Native(s) = &self.backend {
            s.ancillary_hop()
        } else {
            None
        }
    }
    pub fn bind_bytes(&self, bytes: &[u8]) -> Result<()> {
        if let SocketBackend::Netlink(s) = &self.backend {
            {
                let _operation = self.operation.write();
                s.bind_bytes(bytes)
            }
        } else {
            self.bind(decode_address(bytes)?)
        }
    }
    pub fn bind_authorized(&self, bytes: &[u8], can_bind_service: bool) -> Result<()> {
        if self.info().is_some_and(|s| matches!(s.protocol, 6 | 17)) {
            let address = decode_address(bytes)?;
            if address.port() != 0
                && address.port() < self.namespace.unprivileged_port.get()
                && !can_bind_service
            {
                return Err(NetError(13));
            }
        }
        self.bind_bytes(bytes)
    }
    pub fn connect_bytes(&self, bytes: &[u8]) -> Result<()> {
        if let SocketBackend::Netlink(s) = &self.backend {
            {
                let _operation = self.operation.write();
                s.connect_bytes(bytes)
            }
        } else {
            self.connect(decode_address(bytes)?)
        }
    }
    pub fn local_bytes(&self) -> Result<Vec<u8>> {
        if let SocketBackend::Netlink(s) = &self.backend {
            {
                let _operation = self.operation.read_recursive();
                s.local_bytes()
            }
        } else {
            self.local_addr().map(encode_address)
        }
    }
    pub fn peer_bytes(&self) -> Result<Vec<u8>> {
        if let SocketBackend::Netlink(s) = &self.backend {
            {
                let _operation = self.operation.read_recursive();
                s.peer_bytes()
            }
        } else {
            self.peer_addr().map(encode_address)
        }
    }
    pub fn received_address(&self, received: &Received) -> Vec<u8> {
        if matches!(self.backend, SocketBackend::Netlink(_)) {
            received
                .netlink_address
                .map_or_else(|| netlink::address(0), Vec::from)
        } else {
            received.address.map_or_else(Vec::new, encode_address)
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
        self.send_bytes_with_namespace(bytes, flags, destination, net_admin, &|_| Err(NetError(9)))
    }
    pub fn send_bytes_with_namespace(
        &self,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
        net_admin: bool,
        resolve: &dyn Fn(u32) -> Result<Network>,
    ) -> Result<usize> {
        if let SocketBackend::Netlink(s) = &self.backend {
            let mut wakes = netlink::Notifications::default();
            let result = {
                let _operation = self.operation.write();
                s.send_deferred(bytes, flags, destination, net_admin, resolve, &mut wakes)
            };
            wakes.flush();
            result
        } else {
            self.send(bytes, flags, destination.map(decode_address).transpose()?)
        }
    }
    delegate!(read_recursive, address_size() -> usize);
    delegate!(write, bind(address: SocketAddr) -> Result<()>);
    delegate!(write, listen(backlog: u32) -> Result<()>);
    delegate!(write, connect(address: SocketAddr) -> Result<()>);
    delegate!(read_recursive, connect_complete() -> Result<bool>);
    delegate!(write, resume_connect() -> Result<bool>);
    delegate!(read_recursive, local_addr() -> Result<SocketAddr>);
    delegate!(read_recursive, peer_addr() -> Result<SocketAddr>);
    delegate!(write, shutdown(how: u32) -> Result<()>);
    pub fn is_netlink(&self) -> bool {
        matches!(self.backend, SocketBackend::Netlink(_))
    }
    pub fn subscribe(
        &self,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> Option<trames_shared::IoSubscription> {
        match &self.backend {
            SocketBackend::Netlink(socket) => Some(socket.subscribe(signal)),
            _ => None,
        }
    }
    pub fn send(&self, bytes: &[u8], flags: u32, address: Option<SocketAddr>) -> Result<usize> {
        if self.is_netlink() {
            if address.is_some() {
                return Err(NetError(97));
            }
            return self.send_bytes(bytes, flags, None);
        }
        let _operation = self.operation.read_recursive();
        match &self.backend {
            SocketBackend::Native(socket) => socket.send(bytes, flags, address),
            SocketBackend::Hybrid(socket) => socket.send(bytes, flags, address),
            SocketBackend::Virtual(socket) => socket.send(bytes, flags, address),
            SocketBackend::Netlink(_) => unreachable!(),
        }
    }
    delegate!(
        read_recursive,
        recv(count: usize, flags: u32) -> Result<Received>
    );
    delegate!(read_recursive, poll(events: u16) -> Result<u16>);
    delegate!(
        write,
        set_option(level: u32, name: u32, value: i32) -> Result<()>
    );
    delegate!(
        read_recursive,
        get_option(level: u32, name: u32) -> Result<i32>
    );
    pub fn accept(&self) -> Result<(Arc<Self>, SocketAddr)> {
        let _operation = self.operation.read_recursive();
        let reservation = self.namespace.socket_count.reserve()?;
        let (backend, peer) = match &self.backend {
            SocketBackend::Hybrid(s) => s.accept()?,
            SocketBackend::Netlink(_) => return Err(NetError(95)),
            SocketBackend::Native(s) => {
                let (s, peer) = s.accept()?;
                (SocketBackend::Native(s), peer)
            }
            SocketBackend::Virtual(s) => {
                let (s, peer) = s.accept()?;
                (SocketBackend::Virtual(s), peer)
            }
        };
        let accepted = Self::wrap(backend, self.namespace.clone(), reservation, self.kind);
        for receive in [false, true] {
            accepted.set_io_timeout(receive, self.io_timeout(receive));
        }
        Ok((accepted, peer))
    }
}
pub fn wait(sockets: &[(Arc<Socket>, u16)], timeout: Duration) -> Result<()> {
    wait_with_fds(sockets, &[], timeout)
}
/// Wait on native resources and network transports in the same idle executor.
pub fn wait_with_fds(
    sockets: &[(Arc<Socket>, u16)],
    fds: &[std::os::fd::BorrowedFd<'_>],
    timeout: Duration,
) -> Result<()> {
    let mut native = Vec::new();
    let mut fabrics: Vec<Fabric> = Vec::new();
    for (s, events) in sockets {
        match &s.backend {
            SocketBackend::Hybrid(s) => {
                let (n, f) = s.waiters(*events);
                if let Some(n) = n {
                    native.push(n);
                }
                if let Some(f) = f {
                    if !fabrics.iter().any(|other| other.same(&f)) {
                        fabrics.push(f);
                    }
                }
            }
            SocketBackend::Netlink(_) => {}
            SocketBackend::Native(s) => native.push((s.clone(), *events)),
            SocketBackend::Virtual(s) => {
                let f = s.fabric();
                if !fabrics.iter().any(|other| other.same(&f)) {
                    fabrics.push(f);
                }
            }
        }
    }
    let mut duration = timeout;
    for f in &fabrics {
        f.tick();
        duration = duration.min(f.next_wait());
        native.extend(f.native_waiters());
    }
    use std::os::fd::AsFd;
    let links: Vec<_> = fabrics.iter().filter_map(Fabric::external_waiter).collect();
    let mut fds = fds.to_vec();
    fds.extend(links.iter().map(|link| link.as_fd()));
    if native.is_empty() && fds.is_empty() {
        std::thread::sleep(duration);
    } else {
        native::wait_with_fds(&native, &fds, duration)?;
    }
    for f in &fabrics {
        f.tick();
    }
    Ok(())
}

#[cfg(test)]
mod routing_tests;

#[cfg(test)]
mod root_routing_tests;

#[cfg(test)]
mod shared_network_tests;

#[cfg(test)]
mod managed_network_tests;
