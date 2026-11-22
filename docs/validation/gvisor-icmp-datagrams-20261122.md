# ICMP datagrams and raw socket delivery, 2026-11-22

The baseline was shared runtime `edf08d0`. Both Mac runners used the same original Linux ARM64 gVisor executables, fresh stores and a two-CPU internal network. All 57 results were compared by original case name.

| Suite | Previous | Updated |
| --- | --- | --- |
| ping_socket | 23 pass, 14 fail | 36 pass, 1 fail |
| raw_socket_icmp | 8 pass, 7 fail, 2 timeout, 3 skip | 17 pass, 3 skip |

All 22 improved cases also passed in the iPad interpreter running on the Mac. The native Linux reference passed the nine raw-socket cases and skipped the 13 ping-socket cases. The remaining ping identifier exhaustion test hit the guest's open-file limit before it could occupy all identifiers. The three skips come from the original raw/ping fixtures. The iOS ARM64 FFI compiled and the eight local runtime CI stages passed. Across the cumulative 13,669 measured cases of 14,530 discovered, the results are 13,020 passes, 117 failures, 508 skips, 23 timeouts and one fixture failure.

## Behavior covered

- Both IP families preserve the selected source address, traffic class, hop limit, local destination and ingress interface with each echo packet. The receiver can enable ancillary data after sending. Peeking retains the message and its metadata. The Ethernet regression changes the sender option after transmission and verifies the original class across two internal endpoints.
- Ping bind follows the address-family rules for multicast and directed broadcast. Oversized scalar writes and sends report EMSGSIZE before reading the payload. Ordinary datagram sends and stream sends retain their distinct size and partial-write behavior.
- Raw listeners receive local packets when opened. ICMPv6 filters admit messages to the receive queue by type and expose the installed bitmap to full or partial reads. IPv4 raw listeners can observe a locally delivered ICMP packet with a bad ICMP checksum. Echo handling still validates its checksum. Other checksum-valid ICMPv6 types travel through the routing and firewall hooks without creating an echo connection-tracking entry. [Linux ping sockets](https://codebrowser.dev/linux/linux/net/ipv4/ping.c.html)

The vendored stack's standalone library suite produced the same 600 passes and five failures before and after the changes. The five existing failures cover the IPv4 packet-length and raw/UDP tests on two media and the 6LoWPAN UDP fragmentation test. The 13 socket-level ICMP tests passed.

## Main-path performance

The previous and updated signed Mac runners alternated on the same two-CPU guest fixtures. Times are medians of guest workload durations after two warm-up pairs. Network timings use 16 measured pairs and the remaining workloads use 32.

| Workload | Previous (ms) | Updated (ms) | Change |
| --- | ---: | ---: | ---: |
| udp bind close | 94.663 | 94.944 | +0.30% |
| udp connected delivery | 144.805 | 145.312 | +0.35% |
| tcp connect accept send | 19.067 | 19.101 | +0.18% |
| unix socketpair | 12.027 | 11.987 | -0.33% |
| unix stream send recv | 19.499 | 19.532 | +0.17% |
| unix datagram send recv | 21.006 | 21.038 | +0.15% |
| sendmsg recvmsg | 55.506 | 55.712 | +0.37% |
| memory | 167.496 | 167.796 | +0.18% |
| mmap fault unmap | 123.190 | 123.239 | +0.04% |
| file pread pwrite | 93.100 | 92.319 | -0.84% |
| fork wait | 18.387 | 18.384 | -0.02% |
| proc cpuinfo | 1.639 | 1.655 | +0.97% |
| ordinary open | 70.801 | 70.760 | -0.06% |
| ordinary stat | 18.196 | 18.100 | -0.53% |
