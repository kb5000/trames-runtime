# TCP port reuse and neighbor resolution

In the virtual network, explicit TCP binds and listeners now retain the admitted reuse-port owner per namespace and port. A mixed reuse-address/reuse-port sequence matches the cached UID and, for an existing bucket, the admitted local address. Listen rechecks sharing, and closing the last bound socket discards the record. Ordinary stream sends and receives do not consult these records. [Linux TCP bind implementation](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/inet_connection_sock.c)

An active open can send a SYN to destination port zero. Local closed ports respond with a reset. When an Ethernet neighbor remains unresolved after its probes, the fabric reports host-unreachable to the original local connecting socket. The queued SYN must match both endpoints and the initial sequence number. Old probes cannot terminate a subsequent connection with the same endpoints. IPv4 ARP and IPv6 Neighbor Discovery use the same completion path. This change covers local active opens; forwarding ICMP errors for other traffic is outside this batch.

## Original AArch64 gVisor suites

The comparison below uses the previous cumulative inventory and the final signed Mac runner. Both suites for socket binding ran in full. The TUN/TAP selection used a fresh guest network namespace for each case.

| Suite | Cases | Previous passes | Current passes | Current failures |
| --- | ---: | ---: | ---: | ---: |
| socket_bind_to_device_sequence | 42 | 41 | 42 | 0 |
| socket_inet_loopback_isolated | 166 | 164 | 166 | 0 |
| tuntap | 23 | 18 | 20 | 3 |

Five previously recorded failures pass. A fresh before/after comparison with runtime `b8bf71b` attributes three gains to this batch: the mixed TCP bind and both TAP connection errors. The two device-bound TCP/UDP reuse cases already pass on that baseline after its raw socket capability fix. The three remaining failures in this selection are TUN exclusive-open reporting, oversized TAP writes and moving a live TUN to another network namespace. The first two also fail on the native reference.

Both the Mac hardware executor and the iPad interpreter on the Mac passed all six focused original cases. A separate dual-stack guest probe observed host-unreachable on a nonzero remote port after about three seconds on each backend, connection-refused for port zero on each loopback family, and uninterrupted data exchange on a neighboring established socket. The iOS ARM64 FFI compiled; the physical iPad was not used.

All eight local macOS runtime CI stages passed (1,901 tests). The cumulative inventory covers 14,372 of 14,530 discovered cases, including 13,754 passes, 78 failures, 23 timeouts, 516 skips and one fixture failure. Cases outside the replay retain their earlier evidence.

## Paired performance

Runs used the same two-CPU guest per workload and previous/candidate signed binaries in alternating order. The medians below use 32 pairs after two warmup pairs. Positive differences mean longer guest execution time.

| Workload | Previous (ms) | Candidate (ms) | Difference |
| --- | ---: | ---: | ---: |
| udp_bind_close | 91.31 | 91.01 | -0.33% |
| udp_connected_delivery | 141.62 | 142.68 | +0.74% |
| tcp_connect_accept_send | 19.13 | 19.20 | +0.40% |
| unix_socketpair | 12.03 | 12.06 | +0.27% |
| unix_stream_send_recv | 19.27 | 19.35 | +0.38% |
| unix_datagram_send_recv | 20.87 | 20.79 | -0.37% |
| udp_64B | 43.88 | 43.83 | -0.10% |
| udp_1400B | 44.57 | 44.78 | +0.48% |
| udp_8KiB | 34.63 | 34.30 | -0.95% |
| tcp_16KiB | 68.30 | 67.99 | -0.45% |
| memory | 172.50 | 168.60 | -2.26% |
| mmap_fault_unmap | 127.61 | 123.93 | -2.88% |
| file_pread_pwrite | 96.88 | 96.32 | -0.57% |
| fork_wait | 18.72 | 18.47 | -1.33% |
