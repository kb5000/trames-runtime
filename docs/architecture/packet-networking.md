# Guest Ethernet and packet networking

Mac and iPad use the same userspace Linux network implementation. Guest-owned
links carry real Ethernet frames; ordinary native root-namespace TCP/UDP keeps
its BSD socket path. No host NIC, host bridge, host TAP, or host firewall is
configured. There is no protocol broker or coordinator thread.

## Data path

An IP socket resolves its actual next hop with ARP or IPv6 NDP. The resulting
Ethernet frame crosses veth endpoints, bridges and private Trames links by
MAC/VLAN, independently of destination IP. Arbitrary EtherTypes and RAW source
MACs are preserved. A static FDB entry can redirect normal UDP to a TAP sink;
there is no parallel IP shortcut that bypasses the bridge.

Each bridge owns its forwarding database. Known unicast goes to the learned
port; unknown unicast, broadcast and multicast flood eligible ports. Learning,
port state, hairpin and independent flood flags apply on the actual path. Static
forwarding entries and local MAC entries are distinct. Dynamic entries age
lazily (Linux clock ticks, default 300 seconds; zero disables expiry). Port
removal/detachment clears its learned entries and neighbor state. Local veth
attachments that would create a known bridge cycle are rejected.

802.1Q filtering supports access/trunk ports, PVIDs, tagged/untagged egress,
VLAN membership and range updates. VLAN configuration is validated before
publication. Filtering is off by default, as on Linux. With filtering enabled,
unknown VLANs cannot cross ports. The bridge local endpoint has its own VLAN
membership. Endpoint VLAN netdevices and stacked/service tags are separate,
unimplemented features.

ARP requests/replies and IPv6 NS/NA are actual observable packets. A bounded
neighbor cache holds unresolved datagrams, retries probes, releases pending
traffic on resolution and reports failed/stale neighbors. Explicit entries
remain authoritative. NDP validates hop limit, checksum and options and handles
DAD requests. This is basic reachability probing, not a complete Linux NUD,
router-advertisement, SLAAC or neighbor-proxy implementation.

The existing IPv4/IPv6 routes, nftables filter/NAT and connection tracking remain
at IP endpoints. Optional bridge IP filtering uses the same hooks. Only this
filtering path reassembles fragmented datagrams before L4 matching, then
restores wire fragments. A plain bridge forwards fragments without inspecting
transport headers. Virtual gateway endpoints also reassemble wire fragments
before flow lookup; large native UDP replies are fragmented for Ethernet MTU.

## Linux controls

| Interface | Implemented scope |
| --- | --- |
| `ip link` | veth, bridge, namespace moves for movable links, master attachment, link state and existing interface controls |
| `bridge link` | AF_BRIDGE port state, hairpin, learning, unicast/multicast/broadcast flood controls |
| `bridge fdb` | AF_BRIDGE neighbor dump, add/replace/delete; dynamic, static and local entries; MAC moves and lazy aging |
| `bridge vlan` | AF_BRIDGE SETLINK/DELLINK and dumps, PVID/untagged flags, VLAN ranges |
| `ip neigh` | IPv4/IPv6 dumps and explicit add/change/replace/delete, plus traffic-learned ARP/NDP cache |
| AF_PACKET | RAW/DGRAM, actual frame capture/injection, protocol/interface binding, outgoing suppression, promiscuous/all-multicast/multicast membership, peek/truncation and poll/epoll |
| Classic socket BPF | Verified `SO_ATTACH_FILTER`, detach/lock, actual Ethernet-byte loads and snap lengths |
| `/dev/net/tun` | Single-queue nonpersistent TUN and TAP, optional PI, ioctl configuration, interface reporting, read/write, poll/epoll and final-close cleanup |

Mutating controls require the existing guest capabilities. Manual link/FDB/
neighbor updates notify the existing rtnetlink subscription groups. Dynamic
learning and lazy expiration are currently visible through dumps, without
asynchronous learning/aging multicast notifications. Unsupported bridge options
(e.g. enabling STP or multicast snooping) return an error instead of advertising
an implementation.

With PI enabled, TUN/TAP has the four-byte Linux `tun_pi` header. TUN carries IP;
TAP carries the complete Ethernet frame and preserves its outer EtherType.
Final close removes the interface and routes; dup/fork retain the original open
file and namespace. Persistent interfaces, owner/group delegation, multiqueue,
vnet headers and checksum/GSO offloads are not advertised.

## Ownership, wakeups and isolation

The original fabric transaction moves frames; switches and neighbor tables own
their state. Broadcast actions share immutable frame storage. Work queues,
neighbor pending data and fragment caches are bounded. Stable-MAC FDB hits use
a read lock and relaxed timestamp update; MAC moves update that bridge's table.
Absent packet observers, capture skips its observer/queue lock and packet copy.

Private Trames networks transport Ethernet through their existing private Unix
datagram endpoints. Learned unicast avoids directory discovery; floods discover
peers only within that named network. The transport is internal to Trames and
requires matching runtime versions at both ends. It never exposes the LAN's L2
segment. STP/RSTP, distributed loop detection, LACP and multicast snooping are
not implemented; userspace relays must not form forwarding cycles. The bounded
work slice/queues contain floods, but do not make a cyclic topology useful.

A weak protocol-resource handle registers its actual native/Unix event sources
and earliest protocol deadline with the existing executor. It can complete ARP
and deliver a queued UDP datagram after the sending guest task goes to sleep,
without borrowing that task's CPU or address space. Idle resources have no
periodic timer. No new polling bus, resource-service thread, task authority,
guest-memory authority or global guest stop is introduced. Callbacks run after
fabric/topology locks are released; executor progress runs outside its queue
mutex. Final namespace-group close retires the subscriptions.

Native-only applications do not create a fabric/event poller for this facility.
Their normal TCP byte capability remains independent. Packet sockets cannot
capture the host's native traffic or bind to the direct host-backed interface.
Classic socket BPF is separate from seccomp and `bpf()`; this does not add XDP,
TC or general networking eBPF. Existing IP protocol/extension-header limits
continue to apply.

## Reproducing the Linux ABI check

The standalone fixture exercises interface ioctls, socket BPF, epoll, TUN UDP
round trips, TAP, bridge/VLAN rtnetlink controls and opaque frame forwarding:

```sh
python3 runtime/scripts/build-packet-fixture.py target/packet-tun/packet-tun
cargo build -p trames-cli --locked
target/debug/trames-run --network full --cpus 1 --max-instructions 100000000 target/packet-tun/packet-tun
target/debug/trames-run --network full --cpus 2 --max-instructions 100000000 target/packet-tun/packet-tun
```

References: [Linux bridge](https://docs.kernel.org/networking/bridge.html),
[packet sockets](https://man7.org/linux/man-pages/man7/packet.7.html),
[classic socket BPF](https://docs.kernel.org/networking/filter.html),
[TUN/TAP](https://docs.kernel.org/networking/tuntap.html),
[ARP](https://www.rfc-editor.org/rfc/rfc826.html),
[IPv6 neighbor discovery](https://www.rfc-editor.org/rfc/rfc4861.html).
