# TUN and TAP network namespace migration, 2026-11-22

Moving a TUN or TAP interface through RTM_NEWLINK transfers the live queue binding and its persistence flag under the topology writer. The descriptor keeps the queue that it opened. Interface queries, persistence changes and final close follow the new owner. TUN packets and TAP frames enter the destination stack. The queue holds a weak reference to the destination so that removing the namespace can wake a blocked reader. Device indexes in this topology are unique across namespaces. Both backends use the shared implementation.

Two regressions exercise live UDP ingress and egress, a packet queued before a move, permission failure before a move, a combined rename and move, a detached persistent TAP, a second move, capture of an actual Ethernet frame and descriptor readiness on namespace teardown. The complete network library run passed all 196 tests.

## Original ARM64 gVisor cases

| Runner and selection | Passed | Failed | Timed out | Skipped |
| --- | ---: | ---: | ---: | ---: |
| TUN/TAP baseline | 20 | 3 | 1 | 1 |
| TUN/TAP updated | 21 | 2 | 1 | 1 |
| Native ARM64 Linux, same selection | 21 | 2 | 1 | 1 |
| Adjacent routing and namespace tests | 119 | 1 | 0 | 10 |

SaveRestoreAfterNetnsMove now completes the move, reconfiguration and final-close check. The native reference also omits the exclusive creation bit from TUNGETIFF, returns EBUSY on exclusive reattachment, accepts the 4,206-byte TAP write and times out in TUNNoPacketInfo. TuntapHostInetTest.NoNetTun requires a different network configuration and skipped. The selection ran 24 of the 25 tuntap originals plus this hostinet case. The prior result for the remaining tuntap case was carried forward. All 130 adjacent outcomes match the previous inventory.

All 21 completing TUN cases passed using the iPad interpreter on the Mac, with each original running in its own guest network namespace. The ARM64 iOS FFI check passed. The shared runtime CI completed eight stages, including three reused checks. No app was installed for this validation.

Cumulative coverage across revisions is 14,417 of 14,530 original cases, with 13,771 passes, 61 failures, 23 timeouts, 561 skips and one fixture failure. There are 113 unmeasured cases.

## Paired performance

The same two-CPU Mac guest ran the old and new signed binaries in alternating order. The table gives median milliseconds over 32 measured pairs after two warm-up pairs. The TUN sample performs 4,000 validated UDP round trips through an open TUN descriptor, reading each outbound packet, returning it through TUN and receiving the payload on the UDP socket. General workloads use the established probes.

| Workload | Previous (ms) | Updated (ms) | Elapsed change |
| --- | ---: | ---: | ---: |
| tun udp roundtrip | 341.342 | 341.154 | -0.06% |
| udp bind close | 90.738 | 90.573 | -0.18% |
| udp connected delivery | 142.765 | 142.561 | -0.14% |
| tcp connect accept send | 19.305 | 19.187 | -0.61% |
| unix socketpair | 11.979 | 11.959 | -0.16% |
| unix stream send recv | 19.315 | 19.336 | +0.11% |
| unix datagram send recv | 20.960 | 20.763 | -0.94% |
| memory | 174.992 | 174.075 | -0.52% |
| mmap fault unmap | 124.079 | 123.451 | -0.51% |
| file pread pwrite | 94.895 | 96.022 | +1.19% |
| fork wait | 18.180 | 18.315 | +0.74% |

Previous runner SHA-256 `4725b4ee070dc313ba91f142b2544ab9b420e723c1cd821f14eb36f3b7d19d0f`. Updated runner SHA-256 `6705422b2fad56fa7e52d8322aa4ef694de4a19c629284a44f42897aebb632fa`. TUN probe SHA-256 `ec1f1823ec244b98b4b25539afb249776ebdde407e6fbd42409aede4e165062e`.
