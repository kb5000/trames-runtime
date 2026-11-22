# Netfilter named sets and data maps, 2026-11-22

Both signed Mac runners executed the same 268 original Linux ARM64 gVisor Netfilter cases, one case per process. The previous shared runtime was `d645a8f`. All nine new passes were failures on that revision and passed on the native Linux reference. No other case changed status.

| Runner | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| Previous Trames | 237 | 24 | 7 |
| Updated Trames | 246 | 15 | 7 |
| Native Linux | 263 | 0 | 5 |

| Original group | Previous passes | Updated passes | Total |
| --- | ---: | ---: | ---: |
| Set dump | 0 | 1 | 1 |
| Set elements | 0 | 5 | 5 |
| Lookup | 0 | 3 | 3 |

## Packet behavior

- Named fixed-width key sets and binary data maps belong to the guest table. A binding resolves its set and validates the source and destination register widths at rule installation. Data-map lookup can overwrite its key register and clears padding at the end of the last 32-bit word. Exact keys take precedence over the catch-all on ordinary lookups. An inverted membership test supports exclusion rules.
- A change to a set's elements takes a private copy on the first write to that set in the batch. All requests succeed before the new rules and elements become visible to packets. Deletion of a bound set is rejected. Numeric set IDs are scoped to the creating transaction. Dumps use resolved names and return complete elements in bounded messages. There is no background thread or extra namespace lock for set lookups.
- In two guest runs, an output-chain map classified real UDP traffic to two local ports. Each run delivered 192 datagrams. The hit counts at A/B were 32/0 initially, 0/32 after a two-operation replacement and 0/32 after a deliberately failing two-operation deletion. The runs used a four-byte and a one-byte map result respectively. Both compared the entire four-byte destination word.
- Runtime regressions additionally exercise inverted membership, expiry of a transaction ID, deletion of a bound set, rollback of multiple element edits, lookup dump identity, overlapping register use, and a 1,000-element dump checked for every key and its user data.
- Scope covers named exact-key sets and data maps on the existing Netfilter path. Interval and timed sets, anonymous sets and verdict maps remain unsupported. Existing per-namespace ruleset accounting applies to sets and their elements. Lookup semantics follow the [Linux evaluator](https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nft_lookup.c) and [register-copy implementation](https://github.com/torvalds/linux/blob/v6.12/include/net/netfilter/nf_tables.h).

Another 145 Netlink cases retained their previous results (132 passes, four failures, nine skips). The iPad interpreter executed all nine newly passing original cases on Mac. The iOS ARM64 FFI build check and all eight local runtime CI stages passed. An actual iPad was not used.

Measured inventory: 14,201 of 14,530 original cases, 13,530 passes, 132 failures, 515 skips, 23 timeouts and one fixture failure. Another 329 cases have no current result.

## Main-path performance

Two-CPU hardware runs alternated old and new binaries on the same guest with two warm-up pairs. Each active-filter sample sent and received 5,000 UDP datagrams and read the kernel rule counter before and after, requiring exactly 5,000 hits. Socket timings use 16 measured pairs, and memory, file and process timings use 32. Elapsed-time medians are in milliseconds.

| Workload | Previous | Updated | Change |
| --- | ---: | ---: | ---: |
| udp_active_output_counter | 152.479 | 150.955 | -1.00% |
| udp_bind_close | 96.641 | 97.504 | +0.89% |
| udp_connected_delivery | 153.451 | 150.635 | -1.84% |
| tcp_connect_accept_send | 20.348 | 20.096 | -1.24% |
| unix_socketpair | 12.512 | 12.275 | -1.89% |
| unix_stream_send_recv | 20.105 | 20.040 | -0.32% |
| unix_datagram_send_recv | 21.534 | 21.558 | +0.11% |
| sendmsg_recvmsg | 56.389 | 56.553 | +0.29% |
| memory | 178.575 | 176.401 | -1.22% |
| mmap_fault_unmap | 134.430 | 134.157 | -0.20% |
| file_pread_pwrite | 95.577 | 96.224 | +0.68% |
| fork_wait | 19.391 | 19.754 | +1.87% |
| proc_cpuinfo | 1.732 | 1.716 | -0.93% |
| ordinary_open | 74.843 | 75.286 | +0.59% |
| ordinary_stat | 19.286 | 19.364 | +0.41% |

Original test binary SHA-256: `87f4d8ae2ac1fed82e22b5fe17a75f1bb658a38f29b1f9d6d6a6fabc3491489f`. Updated Mac runner SHA-256: `c0c640fe86bba379e9bca1484f4a9796e40658a5547d16cb7d1a7109c37f2dc8`.
