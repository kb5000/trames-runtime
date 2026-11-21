# Dual-stack raw TCP and UDP compatibility

This batch adds IPv4 raw TCP and IPv6 raw TCP/UDP to the guest IP stack and extends the existing IPv4 raw UDP implementation. The comparison uses runtime `e23cdee` and the same Linux ARM64 gVisor binaries on both builds.

## Runtime behavior

- Raw sockets subscribe by address family and protocol when created. Their address, shutdown, buffer sizing and datagram semantics follow the Linux raw socket ABI. Receivers see the IPv4 header or the IPv6 payload, including on a peek.
- The guest constructs the IP header and uses the selected route's MTU. A large loopback packet can exceed the Ethernet MTU. A raw receive queue can admit one oversized datagram while empty. The guest tracks the incoming interface, traffic class and hop limit and exposes the requested control messages.
- IPv6 raw TCP and UDP can request checksum generation and validation at an even payload offset. Linux transport validation still applies to ordinary TCP and UDP. Local raw delivery uses the namespace routing and firewall hooks. Host-network environments also use the guest stack for raw TCP and UDP.
- A regression test opens all four family/protocol combinations at once and checks which socket receives each short loopback payload.

## Results

The six raw, packet and ping suites contain 263 cases. All 139 newly passing cases also passed on the native Linux reference and on the iPad interpreter running on the Mac. The iOS arm64 FFI target compiled. The local Mac runtime workflow passed all eight stages, including three reused stages.

| Suite | Cases | Previous passes | Current passes | Failures | Timeouts | Skips |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| raw_socket | 155 | 18 | 154 | 1 | 0 | 0 |
| udp_raw_socket | 2 | 1 | 2 | 0 | 0 | 0 |
| raw_socket_icmp | 20 | 7 | 8 | 7 | 2 | 3 |
| packet_socket_raw | 34 | 1 | 2 | 32 | 0 | 0 |
| raw_socket_hdrincl | 15 | 0 | 0 | 15 | 0 | 0 |
| ping_socket | 37 | 23 | 23 | 14 | 0 | 0 |

The 680 ordinary socket and 96 multicast cases retained their previous outcomes. The final ordinary-socket run reached its disk-space threshold. After clearing the Rust debug incremental cache, all 346 interrupted cases ran with the same binary and guest image. Original GTest XML was checked for each reported pass.

The cumulative inventory covers 13,401 of 14,530 cases. It contains 12,807 passes, 145 failures, 426 skips, 22 timeouts and one fixture failure. The previous inventory had 284 failures. The remaining raw_socket failure exercises IPv6 protocol 255 (`IPPROTO_RAW`). Header-included sockets have a separate 15-case suite. The largest remaining group is the 32 packet_socket_raw failures, including 30 that first encounter the missing loopback `accept_local` sysctl during setup.

## Performance

The two hardware-backed Mac runners alternated order across 32 measured pairs after two warm-up pairs per workload. Each pair used the same internal network and guest benchmark. The table reports median elapsed milliseconds.

| Workload | Previous (ms) | Current (ms) | Change |
| --- | ---: | ---: | ---: |
| udp bind close | 92.597 | 92.650 | +0.06% |
| udp connected delivery | 143.420 | 144.354 | +0.65% |
| tcp connect accept send | 19.038 | 19.097 | +0.31% |
| unix socketpair | 12.049 | 12.023 | -0.22% |
| unix stream send recv | 19.572 | 19.516 | -0.29% |
| unix datagram send recv | 21.062 | 21.156 | +0.45% |
| get link | 2.303 | 2.318 | +0.67% |
| dump addr | 6.668 | 6.697 | +0.43% |
| dump route | 8.690 | 8.671 | -0.22% |
