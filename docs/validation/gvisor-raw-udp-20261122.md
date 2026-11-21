# IPv4 raw UDP and multicast socket compatibility

The baseline is runtime `c0bbdb2`. The Mac hardware-backed runner and the iPad interpreter on Mac used the same pinned Linux ARM64 gVisor binaries. Network tests ran on the internal guest network.

## What changed

- The guest IP stack handles IPv4 raw UDP using its existing raw IP sockets and routing. A reader can receive UDP before binding. Unicast raw sends preserve the caller's UDP header. The host-backed configuration also selects the guest IP stack for this socket type. Opening a raw socket still requires the network namespace's raw-socket capability.
- Raw UDP and ordinary UDP share IPv4 multicast interface selection, membership and error handling. Multicast delivery observes guest packet policy, interface, group and peer. An ordinary receiver reads UDP payload, while a raw receiver reads the IP packet. Selecting a nonexistent multicast interface and joining on an invalid local address now return the respective Linux errors.
- Raw local IPv4 readers can receive the IP payload before UDP length validation. The exceptional delivery applies the guest local output and input hooks before placing a copy in a matching raw receive queue. Ordinary UDP and forwarded traffic continue through transport validation. Both socket-level and per-message TTLs are preserved.
- A packet-level regression covers queued traffic before bind, explicit bind after receive, unicast and multicast delivery of one packet to both socket types, peer port, peek and header bytes. It also checks that a local raw reader receives the per-message TTL while an ordinary UDP socket rejects the same invalid UDP length. Existing ICMP raw sockets retain their own protocol and checksum handling.
- This change covers guest IPv4 UDP with kernel-built IP headers. The raw unicast transport accepts UDP segments up to the internal 1500-byte link MTU less the IPv4 header. Further raw protocols, IPv6 raw UDP and user-supplied IP headers require their own data-path verification.

## Original multicast suite

| Platform | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| Previous hardware-backed Mac | 0 | 64 | 32 |
| Updated hardware-backed Mac | 60 | 0 | 36 |
| iPad interpreter on Mac | 60 | 0 | 36 |
| Native Linux reference | 60 | 0 | 36 |

The previous fixture failed during a raw-UDP capability probe, including when it was preparing ordinary UDP sockets. Of those 64 failures, 60 now reach their assertions and pass. The other four reach the upstream native-platform skip for the no-interface membership test. The remaining 32 skips are ICMP variants. All 96 updated results match native Linux case by case.

## Expanded coverage and regression results

The final Mac binary ran 1,039 original cases. The 680 previously tracked socket regression cases retained all 657 passes, 7 failures and 16 skips. The following 263 cases had native results but no entry in the previous Trames inventory. The previous Trames binary also ran every one of them under the same internal-network configuration.

| Newly tracked suite | Cases | Previous passes | Current passes | Current failures | Timeouts | Skips |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packet_socket_raw | 34 | 0 | 1 | 33 | 0 | 0 |
| ping_socket | 37 | 23 | 23 | 14 | 0 | 0 |
| raw_socket | 155 | 1 | 18 | 137 | 0 | 0 |
| raw_socket_hdrincl | 15 | 0 | 0 | 15 | 0 | 0 |
| raw_socket_icmp | 20 | 7 | 7 | 8 | 2 | 3 |
| udp_raw_socket | 2 | 0 | 1 | 1 | 0 | 0 |

In the six newly tracked suites, 19 failures became passes, including the IPv4 zero-source-port datagram and receipt of the per-message TTL. All other results matched the preceding build. Of the 208 remaining failures here, 116 stop at capability probes for IPv4 raw TCP or IPv6 raw UDP/TCP. Another 30 hit the missing loopback IPv4 accept_local sysctl during setup. These counts describe the first observed blocker; later assertions still need to run.

Across both the prior inventory and the newly measured suites, matched coverage moved from 367 failures to 284. Of that reduction, 79 failures became passes and four reached upstream skips. The updated inventory covers 13,401 of 14,530 cases with 12,668 passes, 284 failures, 426 skips, 22 timeouts and one fixture failure.

The updated iPad interpreter ran all 96 multicast cases and all 19 newly passing cases from the expanded suites on the Mac. The iOS arm64 FFI check passed. The local eight-stage runtime workflow passed, including the network tests, with three unchanged stages reused.

## Performance

Both hardware-backed Mac builds ran the same guest workloads on the internal network. Times are medians over 32 paired measurements after two warm-up pairs. The execution order alternated by pair. A negative change means lower elapsed time.

| Guest workload | Previous (ms) | Current (ms) | Change |
| --- | ---: | ---: | ---: |
| udp bind close | 93.628 | 94.197 | +0.61% |
| udp connected delivery | 145.745 | 145.808 | +0.04% |
| tcp connect accept send | 19.343 | 19.272 | -0.37% |
| unix socketpair | 12.096 | 12.077 | -0.16% |
| unix stream send recv | 19.701 | 19.634 | -0.34% |
| unix datagram send recv | 21.215 | 21.030 | -0.87% |
| get link | 2.304 | 2.315 | +0.46% |
| dump addr | 6.653 | 6.686 | +0.49% |
| dump route | 8.530 | 8.614 | +0.98% |
