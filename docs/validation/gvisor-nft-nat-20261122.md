# nftables NAT and masquerade, 2026-11-22

Both signed Mac runners executed the same 268 original Linux ARM64 gVisor Netfilter cases, one case per process. The previous shared runtime was `b3d55b4`. All 47 new passes were failures on that revision and passed on the native Linux reference. No other case changed status.

| Runner | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| Previous Trames | 177 | 84 | 7 |
| Updated Trames | 224 | 37 | 7 |
| Native Linux | 263 | 0 | 5 |

| Original group | Previous passes | Updated passes | Total |
| --- | ---: | ---: | ---: |
| NATRuleTest | 0 | 8 | 8 |
| MasqRuleTest | 1 | 9 | 9 |
| CompatNATTests | 0 | 18 | 18 |
| CompatMasqTests | 1 | 13 | 13 |
| CompatRuleDumpTests | 2 | 3 | 6 |

## Packet behavior

- Native nftables and compatible iptables targets accept configurable priorities for NAT base chains after conntrack. Prerouting and output can translate the destination. Input and postrouting can translate the source, with masquerade restricted to postrouting. Within each translation stage the configured priorities determine which chain gets the first opportunity to bind a connection.
- IPv4 legacy and dual-family target layouts use the family and revision reported in the request. Port ranges can include zero. An existing port in range is preserved. If a candidate reply tuple is occupied, the allocator tries the remaining ports in the explicit range. Replacing the reverse binding looks up the old key directly. Fixed addresses bypass range hashing, and subsequent packets reuse the connection's binding.
- An isolated two-CPU Mac guest loaded a native nftables output rule at priority 37. A connected UDP client sent 32 distinct requests to a frontend port. A listener on a different port received them all. Every reply reached the client with the original frontend address and port.
- Runtime packet tests cover a filter placed between the NAT stage and the requested chain priorities, the first matching chain, repeated packets, reverse translation and checksums. IPv4 and IPv6 collision tests exercise both endpoints of a two-port range, failure on exhaustion and preservation of established bindings.
- Advanced allocation policies such as randomized ports and persistent bindings remain unsupported. Remaining Netfilter failures include sets and lookups, payload and metadata expressions, compatibility matchers and chain binding. The 47 new passes cover the original NAT and masquerade failures and one rule dump.

Another 145 Netlink cases retained their previous results (132 passes, four failures, nine skips). The iPad interpreter executed all 47 newly passing original cases on Mac. The iOS ARM64 FFI build check and all eight local runtime CI stages passed. An actual iPad was not used.

Measured inventory: 14,201 of 14,530 original cases, 13,508 passes, 154 failures, 515 skips, 23 timeouts and one fixture failure. Another 329 cases have no current result.

## Main-path performance

Two-CPU hardware runs alternated old and new binaries on the same guest with two warm-up pairs. Each active-filter sample sent and received 5,000 UDP datagrams and read the kernel rule counter before and after, requiring exactly 5,000 hits. Socket timings use 16 measured pairs, and memory, file and process timings use 32. Elapsed-time medians are in milliseconds.

| Workload | Previous | Updated | Change |
| --- | ---: | ---: | ---: |
| udp_active_output_counter | 150.913 | 150.487 | -0.28% |
| udp_bind_close | 98.255 | 97.539 | -0.73% |
| udp_connected_delivery | 151.187 | 153.454 | +1.50% |
| tcp_connect_accept_send | 20.085 | 20.255 | +0.84% |
| unix_socketpair | 12.301 | 12.410 | +0.89% |
| unix_stream_send_recv | 20.015 | 19.879 | -0.68% |
| unix_datagram_send_recv | 21.798 | 21.493 | -1.40% |
| sendmsg_recvmsg | 56.158 | 56.310 | +0.27% |
| memory | 176.652 | 175.969 | -0.39% |
| mmap_fault_unmap | 135.034 | 133.256 | -1.32% |
| file_pread_pwrite | 95.783 | 94.724 | -1.11% |
| fork_wait | 19.658 | 19.189 | -2.38% |
| proc_cpuinfo | 1.712 | 1.747 | +2.01% |
| ordinary_open | 75.135 | 75.235 | +0.13% |
| ordinary_stat | 19.076 | 19.433 | +1.87% |

Original test binary SHA-256: `87f4d8ae2ac1fed82e22b5fe17a75f1bb658a38f29b1f9d6d6a6fabc3491489f`. Updated Mac runner SHA-256: `65cac4d9f5f7d82a6e7d703717bad0e45745490506443cbbb9d9e32df3a08c9a`.
