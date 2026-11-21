# UDP socket options and IPv6 address retention

Eight ARM64 gVisor suites ran on the Mac hardware executor against baseline `4f35c6a` and the final build, with identical binaries, rootfs, filters and two CPUs per environment. The selection covered IPv4 and IPv6 UDP, unbound IPv6 sockets, generic TCP/UDP, nonblocking TCP and UDP, network devices and procfs.

| Result | Baseline | Final |
| --- | ---: | ---: |
| Passed | 110 | 128 |
| Failed | 90 | 72 |
| Skipped | 5 | 5 |

The 18 transitions were failures to passes. Each has passing original GoogleTest XML on both the Mac hardware executor and the shared iPad interpreter running on the Mac. All 18 also pass the native Linux reference. The iOS ARM64 FFI compiled and the shared runtime passed all eight local CI steps.

* Twelve cases exercise UDP send and receive buffer sizing, including below-minimum and above-maximum requests. The guest stack applies the effective capacity to live buffers. The native backend uses the host socket option.
* Four cases request the original IPv4 or IPv6 destination through recvmsg. Ordinary UDP receives acquire host packet metadata only when requested. A direct regression binds wildcard sockets, toggles packet info and original destination independently, and checks the same datagram with peek and consume on both backends.
* Two cases open, read and write the IPv6 keep_addr_on_down sysctl. The guest network namespace resolves the interface name to its device. A link transition test verifies that a nonzero all value overrides the interface setting, global IPv6 addresses follow the policy, link-local addresses are removed and IPv4 addresses survive.

## Remaining coverage

The cumulative inventory now includes 9,621 of 14,530 discovered cases. It contains 9,167 passes, 110 failures, 20 timeouts, 323 skips and one fixture failure. Of the 205 cases in this batch, 163 were new to the inventory. On the baseline these included 85 previously uncounted failures. Of those, 16 now pass, along with two previously counted procfs failures.

The 72 failures still observed in these suites all pass on the native Linux reference. They include 68 IPv4 UDP cases involving multicast, broadcast and port reuse, three procfs cases covering IPv6 file coverage and TCP recovery configuration, and one network-device timestamp capability query.

## Performance

The same Mac alternated old and new executables using the same guest workloads, reversing order each pair. Times are medians from 16 measured pairs following two warm-up pairs.

| Workload | Baseline (ms) | Final (ms) | Change |
| --- | ---: | ---: | ---: |
| udp_bind_close | 95.70 | 96.94 | +1.30% |
| udp_connected_delivery | 150.70 | 150.35 | -0.24% |
| tcp_connect_accept_send | 21.39 | 21.26 | -0.60% |
| unix_socketpair | 12.22 | 12.25 | +0.19% |
| unix_stream_send_recv | 19.77 | 19.78 | +0.07% |
| unix_datagram_send_recv | 21.33 | 21.42 | +0.44% |
| sendmsg_recvmsg | 55.90 | 56.32 | +0.75% |
