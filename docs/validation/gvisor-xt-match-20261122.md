# Netfilter connection and transport matchers, 2026-11-22

Both signed Mac runners executed the same 268 original Linux ARM64 gVisor Netfilter cases, one case per process. The previous shared runtime was `7d3f001`. All 13 new passes were failures on that revision and passed on the native Linux reference. No other case changed status.

| Runner | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| Previous Trames | 224 | 37 | 7 |
| Updated Trames | 237 | 24 | 7 |
| Native Linux | 263 | 0 | 5 |

| Original group | Previous passes | Updated passes | Total |
| --- | ---: | ---: | ---: |
| CompatConntrackTests | 0 | 8 | 9 |
| CompatNoopMatchTests | 0 | 2 | 2 |
| CompatRuleDumpTests | 3 | 6 | 6 |

## Packet behavior

- The conntrack matcher reads the ARM64 structures for revisions 1, 2 and 3 at their correct sizes. Rule insertion accepts the unpadded structure or its xtables alignment. The dump returns zero-filled alignment bytes and the nesting format used by Linux. Invalid revisions and truncated structures have distinct errors.
- The evaluator uses the stored original and reply tuples. It reads the expiration deadline only for a rule that requests it. The packet tests cover state, status overlap, reply direction, expiry, network-order exact ports in revisions 1/2 and host-order port intervals in revision 3.
- TCP and UDP compatibility rules check the declared protocol at insertion, then match ports on packets. TCP also matches flags and options. ICMPv4 and ICMPv6 match types and codes, with the IPv4 wildcard and inversion. Short required transport headers trigger a drop verdict. The tests exercise source/destination ranges, TCP flags and option inversion, short headers, and both ICMP families.
- A two-CPU Mac guest loaded an unpadded UDP match with a destination-port condition and counter. It delivered 256 datagrams divided equally between two live sockets. The counter recorded exactly 128 matching packets.
- The remaining 24 Netfilter failures cover seven payload expressions, five metadata expressions, nine set management and lookup cases, and three chain binding cases. A gVisor-only conntrack assertion is skipped on the native comparison and on Trames.
- Protocol references: [connection tracking](https://github.com/torvalds/linux/blob/master/net/netfilter/xt_conntrack.c) and [transport matches](https://github.com/torvalds/linux/blob/v6.12/net/netfilter/xt_tcpudp.c).

Another 145 Netlink cases retained their previous results (132 passes, four failures, nine skips). The iPad interpreter executed all 13 newly passing original cases on Mac. The iOS ARM64 FFI build check and all eight local runtime CI stages passed. An actual iPad was not used.

Measured inventory: 14,201 of 14,530 original cases, 13,521 passes, 141 failures, 515 skips, 23 timeouts and one fixture failure. Another 329 cases have no current result.

## Main-path performance

Two-CPU hardware runs alternated old and new binaries on the same guest with two warm-up pairs. Each active-filter sample sent and received 5,000 UDP datagrams and read the kernel rule counter before and after, requiring exactly 5,000 hits. Socket timings use 16 measured pairs, and memory, file and process timings use 32. Elapsed-time medians are in milliseconds.

| Workload | Previous | Updated | Change |
| --- | ---: | ---: | ---: |
| udp_active_output_counter | 153.369 | 152.027 | -0.87% |
| udp_bind_close | 96.439 | 97.172 | +0.76% |
| udp_connected_delivery | 150.743 | 151.589 | +0.56% |
| tcp_connect_accept_send | 19.992 | 20.220 | +1.14% |
| unix_socketpair | 12.252 | 12.286 | +0.27% |
| unix_stream_send_recv | 19.843 | 19.787 | -0.28% |
| unix_datagram_send_recv | 21.459 | 21.420 | -0.18% |
| sendmsg_recvmsg | 56.456 | 56.040 | -0.74% |
| memory | 176.547 | 175.439 | -0.63% |
| mmap_fault_unmap | 131.837 | 131.952 | +0.09% |
| file_pread_pwrite | 95.484 | 96.139 | +0.69% |
| fork_wait | 19.287 | 19.258 | -0.15% |
| proc_cpuinfo | 1.738 | 1.716 | -1.23% |
| ordinary_open | 76.111 | 75.730 | -0.50% |
| ordinary_stat | 19.833 | 19.728 | -0.53% |

Original test binary SHA-256: `87f4d8ae2ac1fed82e22b5fe17a75f1bb658a38f29b1f9d6d6a6fabc3491489f`. Updated Mac runner SHA-256: `2ff7f53e7a018fc034e21cef4f7929838121a2747130a4e564a454dec08a40e2`.
