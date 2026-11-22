# Bridge forwarding, destination rules and socket stress tests

On November 22, 2026, all nine targeted AArch64 gVisor cases passed on the Mac executor and on the Mac-hosted iPad interpreter. The previous Mac runner (runtime `7a2f7e4`) passed three of the nine on the same guest network. The native Linux reference passed all nine.

## Network behavior

- A local forwarding-database hit stops bridge forwarding. Unicast to the bridge or the ingress port can reach the local IP stack. Unicast to a different bridge port’s own address stops at the bridge. An unknown unicast is flooded to eligible ports. An AF_PACKET socket on a receiving veth can observe a frame intended for another MAC with packet type `PACKET_OTHERHOST`. The original bridge tests also cover broadcast and changes to a port’s MAC.
- Guest-owned networks accept IPv4 and IPv6 destination-prefix routing rules. The same selector is used to list, remove and apply the rule. A three-endpoint UDP regression verifies that a prohibition blocks the selected endpoint, a control destination remains reachable, and deleting the rule restores delivery. The ordinary route lookup is used whenever the policy returns to its default state. This decision is recomputed on configuration changes.
- Link creation and updates accept an administrative UP change from a full-mask read/modify/write and from a nonzero flags field with an implicit mask. A request with both fields zero leaves the state alone. The same handling applies to the peer of a new veth.

## Original gVisor suites

The five adjacent suites cover 191 cases. Additionally, 33 previously unmeasured cases from two complete stress suites were run separately on both Mac runners. Cases are counted by suite and full parameterized test name. The native column is the existing AArch64 Linux reference for those binaries.

| Suite | Mac passed | Mac failed | Mac skipped | Native passed |
| --- | ---: | ---: | ---: | ---: |
| bridge | 6 | 0 | 0 | 6 |
| network_namespace | 7 | 2 | 1 | 7 |
| socket_netlink_route | 109 | 2 | 9 | 112 |
| packet_socket | 21 | 0 | 0 | 21 |
| packet_socket_raw | 32 | 0 | 2 | 32 |
| socket_data_transfer_stress | 3 | 0 | 0 | 3 |
| socket_stress | 27 | 3 | 0 | 30 |
| Total | 205 | 7 | 12 | 211 |

The six recovered cases cover three bridge scenarios, link flags, and adding/removing IPv4 and IPv6 routing rules. All other previously measured cases in these suites kept their recorded outcomes. Of 14,530 discovered cases, 14,326 now have a guest result: 13,652 passed, 133 failed, 24 timed out, 516 skipped and one failed during fixture setup. The other 204 remain unmeasured.

### Remaining differences

- On both Trames builds, closing the active TCP endpoint first in the persistent-listener stress test exhausts the restricted ephemeral port range. Connect returns `EADDRINUSE` in its IPv4, IPv6 and dual-stack variants. The reference passes all three. The fixture retries `EADDRNOTAVAIL` after a delay to allow reuse. Port reuse timing and connect-specific error reporting need separate verification.
- Linux passes the tests for less common route types and bringing up a veth IPv6 link-local address. Trames still fails them. A third netlink test, `VethAddRefusedPeerNetnsLeavesNothing`, skips on the guest kernel version and passes on the reference.
- Both systems fail the two network-namespace tests for loopback address setup and IPv6 cleanup on link-down. They fail at different assertions. Matching top-level outcomes do not establish equivalent behavior.

## Performance and build validation

Both signed Mac runners used the same 2-CPU environment and workload executables on an internal Trames network. Each row shows median elapsed milliseconds from 32 paired runs, alternating order and excluding two warmup pairs. The workloads measure ordinary socket operations and guest transfers; they do not measure maximum bridge or packet-capture throughput.

| Workload | Previous (ms) | Updated (ms) | Change |
| --- | ---: | ---: | ---: |
| `udp_bind_close` | 98.05 | 97.35 | -0.71% |
| `udp_connected_delivery` | 152.66 | 151.81 | -0.56% |
| `tcp_connect_accept_send` | 20.36 | 20.29 | -0.34% |
| `unix_socketpair` | 12.46 | 12.41 | -0.45% |
| `unix_stream_send_recv` | 19.95 | 19.93 | -0.09% |
| `unix_datagram_send_recv` | 21.72 | 21.68 | -0.15% |
| `sendmsg_recvmsg` | 56.38 | 56.65 | +0.49% |
| `udp_64B` | 45.18 | 45.49 | +0.68% |
| `udp_1400B` | 46.07 | 46.71 | +1.39% |
| `udp_8KiB` | 35.84 | 35.88 | +0.11% |
| `tcp_16KiB` | 78.15 | 75.50 | -3.40% |

All eight local runtime CI stages passed, including workspace tests, the release build and the memory reclamation check. The ARM64 iOS FFI target compiled. Interpreter results were checked against the individual guest-generated test XML files. Physical iPad performance was not measured.
