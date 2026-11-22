# UDP multicast on IPv4 and IPv6 guest interfaces

The Mac hardware runner at shared runtime `cc2dc63` passed 36 of the 46 original AArch64 cases in the two UDP unbound external-networking suites. The updated Mac runner and the iPad interpreter hosted on Mac each passed all 46. The suites require an active loopback and a second addressed interface. All traffic stayed in the guest topology. Both blocking and nonblocking sockets were tested.

| Cases (each includes both socket modes) | Baseline | Updated | Native Linux reference |
| --- | ---: | ---: | ---: |
| IPv4 independent interface index and multicast source address; conflict with SO_BINDTODEVICE | 0/4 | 4/4 | 4/4 |
| IPv6 multicast output interface selection, conflict and reset | 0/2 | 2/2 | 2/2 |
| IPv6 loopback join/leave and send/receive with an explicit multicast interface | 0/4 | 4/4 | 0/4 |
| Other IPv4 and dual-stack assertions | 36/36 | 36/36 | 36/36 |

The IPv4 interface index selects the output link. An independently supplied local IPv4 address can be used as the source. A conflicting device selection fails before changing socket state. IPv6 UDP sockets have separate multicast interface, hop limit, local loopback, multicast-all and membership controls. Group datagrams use the existing guest firewall hooks, UDP queues, readiness notifications, Ethernet framing and fragmentation. IPv6 uses its own multicast MAC mapping and requires a UDP checksum. A scoped bind and the address returned for a link-local sender carry the guest interface index.

The cross-guest test verifies delivery of a 4,097-byte datagram after fragmentation, the hop limit, ingress index, sender-loop suppression, duplicate join, leave and delivery after leave. A separate veth test binds a receiver to a link-scoped multicast address and verifies the sender's scope uses the receiving namespace's index. Host-LAN multicast, MLD and multicast forwarding between routed links are outside this coverage. Socket option and membership behavior was checked against the Linux sources. [IPv4 options](https://github.com/torvalds/linux/blob/master/net/ipv4/ip_sockglue.c), [IPv6 options](https://github.com/torvalds/linux/blob/master/net/ipv6/ipv6_sockglue.c), [IPv6 membership](https://github.com/torvalds/linux/blob/master/net/ipv6/mcast.c).

## Validation

The native harness now creates a dummy Ethernet interface, IPv4/IPv6 routes and a multicast-capable loopback inside each case's fresh Linux network namespace. It fingerprints the setup script when reusing native results. Previously all 46 cases skipped in the stored reference because it had only loopback. With the new fixture, 42 passed and four reached a failed receive assertion (EAGAIN after the upstream deadline) for site-scope multicast on loopback. Those four are differences from this Linux setup. Every Mac, interpreter and reference result was checked against original GoogleTest XML.

The 307 existing regression cases retained their individual classifications: 297 passed, five failed and five skipped. Local macOS runtime CI passed all eight stages, including 1,886 tests. The harness passed its 18 tests and the iOS ARM64 FFI compiled. No physical iPad run was performed.

The cumulative inventory now includes 14,372 of 14,530 discovered cases: 13,709 passed, 123 failed, 23 timed out, 516 skipped and one failed during fixture setup. All 46 cases were newly included in that inventory. The ten fixes reduce failures within this batch relative to the immediately preceding runtime. They were outside its 123 previously recorded failures.

## Performance

Both signed release runners used the same two-CPU guest configuration. Each workload used two warmup pairs and 32 measured pairs, alternating execution order. Times are median guest milliseconds.

| Workload | Before | After | Change |
| --- | ---: | ---: | ---: |
| udp_64B | 45.47 | 45.26 | -0.45% |
| udp_1400B | 46.76 | 46.05 | -1.52% |
| udp_8KiB | 36.11 | 35.97 | -0.37% |
| tcp_16KiB | 70.92 | 71.53 | +0.85% |
| memory | 175.09 | 174.59 | -0.28% |
| mmap_fault_unmap | 132.17 | 131.33 | -0.63% |
| file_pread_pwrite | 99.36 | 99.28 | -0.08% |
| fork_wait | 19.46 | 19.45 | -0.04% |

Mac runner SHA-256 `4ecf72b35e1c9bdf0599350fbd934d4a8bafc5fcb61c8bde8a0d5fc0ecf91738`.
