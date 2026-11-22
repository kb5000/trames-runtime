# nftables packet expressions, 2026-11-22

Both signed Mac runners executed the same 268 original Linux ARM64 gVisor Netfilter cases, one case per process. The previous shared runtime was `ce9530a`. All 39 new passes were failures on that revision and passed on the native Linux reference. No other case changed status.

| Runner | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| Previous Trames | 138 | 123 | 7 |
| Updated Trames | 177 | 84 | 7 |
| Native Linux | 263 | 0 | 5 |

| Original group | Previous passes | Updated passes | Total |
| --- | ---: | ---: | ---: |
| CompatAddrtypeTests | 6 | 21 | 21 |
| FibRuleTest | 2 | 16 | 16 |
| BitwiseRuleTest | 5 | 10 | 10 |
| CTRuleTest | 5 | 9 | 9 |
| CmpRuleTest | 1 | 2 | 2 |

## Packet behavior

- Route expressions resolve a source or destination through the guest namespace routing table. Results can be an interface index, a padded interface name, route presence or address type. Interface-constrained lookups distinguish addresses on different guest links. Mark-based lookups remain unsupported because the packet hooks do not carry a mark end to end.
- The IPv4 revision-zero address-type matcher supports independent source and destination inversion. Revision one can restrict a match to the input or output interface. Transaction validation walks jump targets before publishing a rule with a hook restriction. Route lookup, device name lookup, broadcast classification and masquerade address selection run when their expression needs them.
- Left and right shifts operate in native-endian 32-bit words and propagate carries across adjacent words in Linux traversal order. The connection-tracking parser checks key width, the direction required by tuple fields and which keys can carry a direction. An explicit IPv4/IPv6 address key breaks the rule on a mismatched packet family. Invalid comparison operations return EINVAL.
- Packet tests exercised overlapping registers, route hits and misses, interface names and interface-constrained local addresses. Linux references include the [bitwise evaluator](https://github.com/torvalds/linux/blob/master/net/netfilter/nft_bitwise.c), [IPv4 route expression](https://github.com/torvalds/linux/blob/master/net/ipv4/netfilter/nft_fib_ipv4.c) and [address type matcher](https://github.com/torvalds/linux/blob/master/net/netfilter/xt_addrtype.c).

Another 145 Netlink cases retained their previous results (132 passes, four failures, nine skips). The iPad interpreter executed all 39 newly passing original cases on Mac. The iOS ARM64 FFI build check and all eight local runtime CI stages passed. An actual iPad was not used.

Measured inventory: 14,201 of 14,530 original cases, 13,461 passes, 201 failures, 515 skips, 23 timeouts and one fixture failure. Another 329 cases have no current result.

## Main-path performance

Two-CPU hardware runs alternated old and new binaries on the same guest with two warm-up pairs. Each active-filter sample sent and received 5,000 UDP datagrams and read the kernel rule counter before and after, requiring exactly 5,000 hits. Socket timings use 16 measured pairs, and memory, file and process timings use 32. Elapsed-time medians are in milliseconds.

| Workload | Previous | Updated | Change |
| --- | ---: | ---: | ---: |
| udp_active_output_counter | 145.701 | 144.612 | -0.75% |
| udp_bind_close | 90.342 | 90.369 | +0.03% |
| udp_connected_delivery | 142.749 | 143.092 | +0.24% |
| tcp_connect_accept_send | 18.930 | 19.032 | +0.54% |
| unix_socketpair | 11.928 | 11.954 | +0.21% |
| unix_stream_send_recv | 19.328 | 19.330 | +0.01% |
| unix_datagram_send_recv | 20.881 | 20.945 | +0.30% |
| sendmsg_recvmsg | 54.561 | 54.997 | +0.80% |
| memory | 164.776 | 165.795 | +0.62% |
| mmap_fault_unmap | 122.821 | 124.151 | +1.08% |
| file_pread_pwrite | 92.150 | 92.002 | -0.16% |
| fork_wait | 18.134 | 18.310 | +0.97% |
| proc_cpuinfo | 1.650 | 1.641 | -0.52% |
| ordinary_open | 71.500 | 71.224 | -0.39% |
| ordinary_stat | 18.186 | 18.105 | -0.44% |

Original test binary SHA-256: `87f4d8ae2ac1fed82e22b5fe17a75f1bb658a38f29b1f9d6d6a6fabc3491489f`. Updated Mac runner SHA-256: `53a7d2db929c4a89c58820a6cb0fc863127005a5b3a82871f76ae53a4d4ef04f`.
