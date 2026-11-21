# UDP port reuse and blocked receiver wakeups

The Mac hardware executor ran 247 original ARM64 gVisor cases from 12 suites. Baseline runtime `d5e99c9` and the final build used identical binaries, a two-CPU Linux guest, the same filters and a 20-second timeout. All 180 final passes have corresponding passing GoogleTest XML.

| Result | Baseline | Final |
| --- | ---: | ---: |
| Passed | 128 | 180 |
| Failed | 114 | 62 |
| Skipped | 5 | 5 |
| Timed out | 0 | 0 |

All 52 transitions were failures to passes. The native Linux reference passes these same cases. The iPad interpreter running on the Mac passed all 52 original cases as well. The iOS ARM64 FFI compiled and the common runtime passed its eight-step local CI.

## What changed

The guest UDP stack implements SO_REUSEPORT admission alongside SO_REUSEADDR. A port-only shared bind requires both sockets to opt in and their guest socket owners to match. A connected receiver and an explicit local address retain their respective lookup priorities. Within a port-sharing group, the four-tuple and the original logical bind order determine which socket receives the packet. Replacing a wildcard socket's per-address handle retains its options and binding identity. The host-backed socket's native port-sharing policy is outside the scope of this implementation.

The initial implementation passed the short distribution checks, but all five 10,000-round request/reply tests exceeded 20 seconds. A blocked receiver had a protocol deadline to retry against. Ingress did not notify the guest socket whose receive queue had just become readable. On the final build a watched queue publishes this edge to its own readers after releasing the fabric lock. Shutdown wakes blocked readers on that socket, too. Native event sources and protocol timers still handle their respective operations.

The five long tests cover IPv4, IPv6 and IPv4-mapped connectors with wildcard and specific bindings. Their final Mac GoogleTest times ranged from 1.82 to 4.26 seconds. A direct two-family regression verifies that only the selected socket wakes, two packets from each client arrive in order on the same receiver, all three receivers serve traffic, and a different guest UID cannot join via SO_REUSEPORT alone.

## Common-path timings

Each guest workload ran on the same Mac against both versions, alternating which version went first. The table uses medians from 16 measured pairs following two warm-ups. These results measure the ordinary socket workloads and do not isolate individual instructions.

| Workload | Baseline (ms) | Final (ms) | Elapsed change |
| --- | ---: | ---: | ---: |
| udp_bind_close | 96.67 | 94.76 | -1.97% |
| udp_connected_delivery | 152.00 | 151.03 | -0.64% |
| tcp_connect_accept_send | 21.69 | 21.25 | -2.00% |
| unix_socketpair | 12.52 | 12.27 | -1.97% |
| unix_stream_send_recv | 20.01 | 19.89 | -0.63% |
| unix_datagram_send_recv | 21.74 | 21.40 | -1.56% |
| sendmsg_recvmsg | 56.59 | 56.20 | -0.69% |

## Outstanding cases

The cumulative inventory now covers 9,663 of 14,530 discovered cases, with 9,219 passes, 100 failures, 20 timeouts, 323 skips and one fixture failure. This batch added 42 previously uncounted cases. Eighteen of the improvements clear failures already in the previous inventory.

Of the 62 remaining failures in this selection, 46 exercise IPv4 UDP multicast and four exercise broadcast. Seven come from binding sequence tests (six TCP variants and an unusual mixed UDP bind). The remaining five are three procfs cases, a network timestamp query and an isolated network fixture with an unsupported socket prerequisite.
