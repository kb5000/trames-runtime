# Guest UDP receive semantics and packet timestamps

The Mac hardware executor ran six complete upstream ARM64 gVisor suites with the same binaries, root filesystem, two guest CPUs and 20-second timeout on baseline `8c346af` and the updated runtime.

| Suite | Cases | Baseline passes | Updated passes | Remaining failures | Skips |
| --- | ---: | ---: | ---: | ---: | ---: |
| socket_ip_udp_loopback | 552 | 482 | 524 | 12 | 16 |
| socket_ip_unbound | 84 | 80 | 80 | 0 | 4 |
| socket_ipv4_datagram_based_socket_unbound_loopback | 96 | 0 | 0 | 64 | 32 |
| socket_netdevice | 7 | 6 | 7 | 0 | 0 |
| socket_non_stream_blocking_udp | 8 | 4 | 8 | 0 | 0 |
| udp_socket | 164 | 112 | 129 | 35 | 0 |
| **Total** | **911** | **684** | **748** | **111** | **52** |

All 64 changes in outcome were failures becoming passes. The same cases pass on the native Linux reference. Original GoogleTest XML verifies all 748 Mac passes. The iPad interpreter running on the Mac independently passed the 64 changed cases. The ARM64 iOS FFI compiled and all eight steps of local shared-runtime CI passed. No physical iPad was used.

## Behavior

Guest-owned IPv4 and IPv6 UDP sockets capture a wall-clock arrival time with each datagram. SO_TIMESTAMP and SO_TIMESTAMPNS expose it in microseconds or nanoseconds, including their time64 variants. Peeking an existing record retains its arrival time. The legacy timestamp ioctl retains the last timestamp from a receive with ancillary timestamps disabled. The guest netdevice timestamp query reports no hardware clock or SO_TIMESTAMPING modes. Host-native sockets use a separate backend.

MSG_WAITALL on a datagram returns a single record and honors nonblocking and timeout settings. MSG_CTRUNC supplied on input is ignored. UDP stores the configured read low-water mark and linger value. IPv4 UDP can disable its optional transmit checksum using SO_NO_CHECK. IPv6 output retains its checksum. Connected dual-stack datagram sockets accept a plain IPv4 sockaddr for the Linux address-family probe used by glibc. Calling accept on UDP returns EOPNOTSUPP.

A direct TUN regression inspects outgoing IPv4 UDP header bytes with checksum omission enabled and disabled. A separate queue regression switches timestamp options while peeking and consuming the same packet and checks the previous ioctl timestamp.

## Coverage and remaining failures

The selection adds 669 cases to the cumulative inventory. Of these, 174 failed against the previous revision and 63 of those now pass. One previously recorded failure also passes. The expanded inventory covers 10,392 of 14,530 discovered cases, with 9,840 passes, 160 failures, 20 timeouts, 371 skips and one fixture failure.

Of this selection's 111 remaining failures, 64 stop in test setup while probing raw socket protocols. Their multicast assertions have not run. The other 47 reach failures in UDP operations, including disconnect and rebinding, delivery of queued errors, socket filters and receive-buffer handling.

## Ordinary socket timings

Each measurement ran the same guest workload on both revisions, alternating run order after two warm-ups. The six ordinary workloads used two series of 16 measured pairs with opposite starting orders. The sendmsg/recvmsg workload used 16 measured pairs. Times below are pooled medians.

| Workload | Baseline (ms) | Updated (ms) | Elapsed change |
| --- | ---: | ---: | ---: |
| UDP bind and close | 96.69 | 97.05 | +0.37% |
| Connected UDP delivery | 152.37 | 153.35 | +0.64% |
| TCP connect, accept and send | 21.58 | 22.03 | +2.08% |
| Unix socketpair | 12.28 | 12.28 | +0.05% |
| Unix stream send and receive | 19.86 | 19.84 | −0.08% |
| Unix datagram send and receive | 21.52 | 21.43 | −0.43% |
| sendmsg and recvmsg | 56.07 | 56.28 | +0.39% |

TCP was slower in both series (+3.20% and +1.45%). Connected UDP measured +1.86% and −0.56%. These local timings cover socket workloads and do not measure end-to-end application latency.
