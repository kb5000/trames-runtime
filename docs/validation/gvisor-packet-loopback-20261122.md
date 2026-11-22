# Guest packet sockets and loopback ingress

The baseline is runtime `3205c144`. Both Mac runners used the same Linux ARM64 gVisor binaries, Alpine image and internal network. Results below use the original per-case GTest XML. A skip counts separately from a pass.

## Changes exercised

- IPv4 exposes `accept_local` and `route_localnet` under `/proc/sys/net/ipv4/conf/{all,default,INTERFACE}`. Each network namespace owns these settings. New links inherit its defaults. The receive path checks the interface and namespace-wide settings before delivering an injected packet. Both settings start disabled. [Linux IP sysctl documentation](https://docs.kernel.org/networking/ip-sysctl.html#ip-variables)
- Raw and cooked packet sockets can inject frames into the guest loopback device. An all-protocol observer sees an outgoing frame and then an incoming frame. An IP-protocol observer sees the incoming copy. A sending packet socket is excluded from its own outgoing copy. Real Ethernet validation still rejects a zero source MAC.
- Binding with protocol zero retains the bound protocol. The socket reports the hardware type and address length for its bound interface. Sending to an explicitly unspecified interface returns `ENXIO`. Socket buffer and linger options round-trip through the packet backend.
- A pipe can splice a datagram into an Internet message socket. A failed send preserves the pipe prefix. The oversized raw datagram cases now reach the transport's message size check.

## Original test results

| Suite | Cases | Baseline passes | Current passes | Current failures | Skips | Timeouts |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packet_socket_raw | 34 | 2 | 32 | 0 | 2 | 0 |
| packet_socket | 21 | 13 | 21 | 0 | 0 | 0 |
| packet_socket_dgram | 15 | 0 | 10 | 0 | 4 | 1 |
| packet_mmap | 13 | 0 | 0 | 13 | 0 | 0 |

The first three suites now match the native Linux status of each individual case, including the cooked socket timeout. Native Linux passed 12 packet_mmap cases and timed out on one. The shared packet ring and its associated options remain open.

The last three suites add 49 cases to the cumulative inventory. At equal coverage, 48 former failures passed and six reached their upstream skip conditions. The previous 13,401 tracked cases went from 145 failures to 113. After adding the newly measured cases, coverage is 13,450 of 14,530, with 12,868 passes, 126 failures, 432 skips, 23 timeouts and one fixture failure.

The iPad interpreter ran on the Mac and passed 61 packet-socket cases. The iOS arm64 FFI compiled. Local runtime CI passed all eight stages, including three reused checks.

All 680 ordinary socket, 96 multicast and 29 splice regression cases retained their previous individual outcomes. The ordinary suite still has seven failures and 16 skips. The multicast suite has 36 skips. All splice cases passed.

## Performance

On the same Mac, the two hardware-backed runners alternated order over 32 measured pairs per workload after two warm-up pairs. The table gives median guest elapsed time. These workloads exercise ordinary sockets and routing queries with packet capture inactive.

| Workload | Before (ms) | After (ms) | Change |
| --- | ---: | ---: | ---: |
| udp bind close | 95.311 | 95.575 | +0.28% |
| udp connected delivery | 146.264 | 146.191 | -0.05% |
| tcp connect accept send | 19.395 | 19.225 | -0.87% |
| unix socketpair | 12.070 | 11.964 | -0.88% |
| unix stream send recv | 19.570 | 19.526 | -0.22% |
| unix datagram send recv | 21.108 | 21.103 | -0.02% |
| get link | 2.394 | 2.331 | -2.62% |
| dump addr | 6.824 | 6.814 | -0.15% |
| dump route | 8.724 | 8.787 | +0.73% |
