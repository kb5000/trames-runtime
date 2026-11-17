# Guest packet networking

Trames uses a shared userspace Linux network implementation on Mac and iPad.
Ordinary root-namespace BSD TCP/UDP sockets keep their existing native path.
Guest-owned interfaces use the existing IP fabric, routes, connection tracking,
and nftables hooks. No host interface, host firewall, or coordinator thread is
created by the interfaces below.

## Supported interfaces

| Interface | Current scope |
| --- | --- |
| Route neighbors | IPv4/IPv6 `RTM_GETNEIGH`, add/change/replace/delete, dumps and `RTMGRP_NEIGH` subscriptions on guest veth/bridge interfaces. Explicit failed/incomplete entries block delivery; an incorrect explicit MAC cannot silently reach the intended peer. |
| AF_PACKET | `SOCK_RAW` and `SOCK_DGRAM`, protocol selection, namespace/interface binding, send/receive, peek/truncation, poll/epoll, receive buffers and `PACKET_IGNORE_OUTGOING`. Creation requires guest `CAP_NET_RAW`. |
| Socket BPF | Classic `SO_ATTACH_FILTER`, `SO_DETACH_FILTER`, and irreversible `SO_LOCK_FILTER` on AF_PACKET sockets. Verified forward control flow, definite scratch initialization, packet loads, arithmetic and snap lengths. |
| IP/port firewall | Existing IPv4/IPv6 nftables filter/NAT/connection-tracking implementation. TUN ingress and packet-socket injection enter its actual packet hooks. Capturing ingress precedes an INPUT drop; packet capture is observation, not an acceptance bypass. |
| TUN | `/dev/net/tun` (character device 10:200), single-queue IPv4/IPv6 `IFF_TUN`, optional `IFF_NO_PI`, automatic `tun%d` naming, `TUNSETIFF`, `TUNGETIFF`, `TUNGETFEATURES`, and zero-offload negotiation. Creating an interface requires guest `CAP_NET_ADMIN`. |

TUN programs configure addresses/routes through the usual Linux interface
ioctls or rtnetlink. A read returns an outgoing IP datagram; a write injects an
incoming one. With packet information enabled, the four-byte `tun_pi` header
uses native-endian flags and a network-endian protocol. Short reads consume one
datagram and set `TUN_PKT_STRIP` when appropriate. Final close removes the
nonpersistent interface and its routes; dup/fork retain the original open file.
The open file pins the namespace in which `/dev/net/tun` was opened.

## Scope boundaries

The fabric is an IP medium. Neighbor discovery is resolved from live guest
connectivity and reported as `NUD_NOARP`; it does not run host ARP/NDP or a
simulated Ethernet reachability timer. Explicit neighbor entries override that
resolution. REACHABLE/STALE/DELAY/PROBE labels can be stored, but no timed NUD
state machine is claimed. Proxy neighbors, bridge FDB management, and Ethernet
broadcast/ARP injection are unsupported. Automatic topology-derived NOARP
entries are reconstructed on query, rather than being a traffic-learned cache.

Packet capture covers packets processed by the Trames IP fabric, including
veth and bridge boundaries. It cannot observe traffic carried entirely by native
BSD sockets. Binding a packet socket to the host-backed direct interface is
rejected. RAW capture uses a logical Ethernet header on Ethernet-like links;
on TUN it carries the IP datagram with `ARPHRD_NONE` and no link address.
Injection supports IPv4/IPv6 unicast on guest links; arbitrary Ethernet frames,
spoofed RAW source MACs, packet mmap rings, fanout and promiscuous membership
management are not implemented. TUN packet input inherits the IP stack's
existing transport/protocol and IPv6 extension-header limitations.

Classic socket BPF is separate from seccomp BPF and the existing `bpf()`
capabilities. This change does not implement general networking eBPF, XDP, or
TC programs. Unsupported ancillary BPF metadata loads are rejected.

TAP, persistent TUN interfaces (`ip tuntap add`), owner/group delegation,
multiqueue, vnet headers, and checksum/GSO offloads are not advertised. Open a
TUN file and keep it open while using the interface. Actual VPN application
compatibility and throughput remain to be measured.

## Ownership and cost

Packet queues and filters belong to their original socket or TUN open file.
The topology retains only weak queue metadata, with no final-close callback
under its lock. Queue notifications accumulate in the existing fabric
transaction and fire after the fabric and topology locks are released. A
reentrant-wake regression checks both conditions. Blocking file I/O and epoll
use the existing worker resource capabilities and fabric timer, releasing the
execution slot instead of adding a service thread.

With no AF_PACKET observers, the observation path checks an atomic active count
and does not acquire an observer/queue lock or allocate/copy a packet. Neighbor
queries derive NOARP entries without inserting a new mutable hot-path cache.
TUN memory is allocated for the actual interface and queued datagrams, not for
unused network address space. The ordinary native TCP byte capability is
unchanged.

## Validation checkpoint — 2026-11-17

- Local runtime workflow: all eight shell steps pass; 1,622 tests pass and 31
  retain their existing skip conditions.
- Tests cover actual UDP over TUN in both directions, PI/no-PI, IPv6, final-close
  cleanup, namespace isolation, AF_PACKET capture/injection, BPF control flow,
  scratch state, filtering/snap lengths, IP/port firewall enforcement, syscall
  pointer preflight, and notification reentry.
- The standalone Linux ARM64 fixture passes under the interpreter with one and
  two CPUs. A second guest thread sends while the first blocks in epoll.
  Interface ioctls, guest-pointer `sock_fprog` import, TUN reads/writes, and the
  UDP reply are exercised through the real syscall ABI.
- `trames-ffi` checks successfully for `aarch64-apple-ios`. This is compile
  coverage, not a claim of a physical-iPad VPN acceptance run.

From the iPad repository, reproduce the standalone fixture with:

```sh
python3 runtime/scripts/build-packet-fixture.py target/packet-tun/packet-tun
cargo build -p trames-cli --locked
target/debug/trames-run --network full --cpus 1 --max-instructions 100000000 target/packet-tun/packet-tun
target/debug/trames-run --network full --cpus 2 --max-instructions 100000000 target/packet-tun/packet-tun
```

ABI references: [Linux packet sockets](https://man7.org/linux/man-pages/man7/packet.7.html),
[classic socket BPF](https://docs.kernel.org/networking/filter.html), and
[Linux TUN/TAP](https://docs.kernel.org/networking/tuntap.html).
