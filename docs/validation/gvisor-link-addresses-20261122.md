# Network interface address lifecycle

Shared runtime baseline `4877eb5`. This batch covers isolated loopback startup, retained addresses, IPv6 route removal and scoped virtual Ethernet addresses.

An isolated namespace starts with an unconfigured loopback interface. Bringing it up installs the loopback addresses. Taking it down retains assigned IPv4 addresses for binding and enumeration. It removes ::1, and the existing keep_addr_on_down setting governs retention of global IPv6 addresses. Taking an interface down also removes its explicit IPv6 routes from the main and policy tables and notifies route listeners.

When both ends of a veth acquire carrier in EUI-64 mode, eligible interfaces derive a link-local address from their own MAC. Listeners in either namespace receive the address change. Netlink and /proc/net/if_inet6 report link scope. A scoped bind verifies that the indicated interface owns the address. The socket keeps its interface for route selection. Source selection prefers global or link-local addresses according to the destination. One link-local address per veth fits alongside the namespace’s existing manual address budget. The packet stack grows its address list when the configuration changes.

## Coverage

The signed Mac guest ran all 181 original AArch64 tests from socket_netlink_route (120), proc_net (26), tuntap (25) and network_namespace (10). Per-case XML or timeout logs were checked against the original binary hashes. Results were 160 passed, 9 failed, 1 timed out and 11 skipped.

| Upstream case | Previous | Current | Recorded native ARM64 Linux run |
| --- | --- | --- | --- |
| NetworkNamespaceTest.LoopbackAddressesAddedOnUp | Failed | Passed | Failed |
| NetworkNamespaceTest.IPv6FlushedOnDown | Failed | Passed | Failed |
| NetlinkRouteTest.VethLinkLocalAddrOnUpDown | Failed | Passed | Passed |

The two namespace tests disagree with the recorded Linux run on bind expectations. The table counts the original assertions independently of that reference. All other 178 classifications held. Outstanding failures in these four suites cover proc network controls, unsupported route types and TUN/TAP semantics. The existing no-packet-info TUN test timed out.

Of 14,530 discovered cases, the cumulative inventory has 14,326 measured, including 13,663 passes, 123 failures, 23 timeouts, 516 skips and one fixture failure. Cases outside this batch retain earlier evidence.

The Mac-hosted iPad interpreter passed all three changed cases and LinkChangeFlagsLikeLinux. The ARM64 iOS FFI compiled. Physical iPad behavior and performance were not measured. A runtime regression verifies both namespaces receive their address notification, invalid or missing scopes fail binding, getsockname preserves the interface and a UDP datagram crosses the live veth. Local macOS runtime CI passed all eight stages and 1,885 tests.

This coverage includes EUI-64 generation on carrier and sends from a socket bound to a link-local address. Stable-private address generation, duplicate-address detection, and per-datagram scope selection on an unbound socket are outside the measured behavior.

## Performance

Two release runners alternated on the same Mac using two guest CPUs, two warmup pairs and 32 measured pairs for each workload. Times are median guest milliseconds.

| Workload | Previous | Current | Change |
| --- | ---: | ---: | ---: |
| udp_64B | 45.23 | 45.33 | +0.24% |
| udp_1400B | 45.96 | 46.65 | +1.50% |
| udp_8KiB | 36.16 | 35.99 | -0.48% |
| tcp_16KiB | 71.60 | 71.91 | +0.43% |
| memory | 178.90 | 174.85 | -2.26% |
| mmap_fault_unmap | 135.94 | 132.47 | -2.55% |
| file_pread_pwrite | 100.57 | 100.04 | -0.53% |
| fork_wait | 19.77 | 19.76 | -0.04% |

Updated runner SHA-256 `bd8872ba77206543e76dd09bf5947b0c074b17785e2ed07e3e0edd34f9a0d556`.
