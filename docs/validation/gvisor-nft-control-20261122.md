# nftables control transactions, 2026-11-22

The current inventory gained 268 original gVisor Netfilter cases. Each comparison ran one case per guest process on the same signed Mac hardware executor configuration with two virtual CPUs, using the original Linux ARM64 test binary. The baseline used shared runtime `04afa47`. Test discovery, expected results and the guest kernel version were unchanged.

| Runner | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| Previous Trames | 40 | 221 | 7 |
| Updated Trames | 138 | 123 | 7 |
| Native Linux reference | 263 | 0 | 5 |

98 previous failures now pass. All previously passing cases stayed green. Running one case per process uncovered a cold-start generation query that passed after another test had modified the rules. The extra two Trames skips are chain/table destroy tests gated on Linux 6.5 or later.

## Implemented behavior

- Table creation, family-scoped deletion and lookup by handle. A dormant table retains policy without evaluating it. Final close removes tables owned by that Netfilter socket before the port ID becomes available for reuse. Plain tables and tables owned by other sockets survive.
- Per-table chain and rule handles, chain renames with jump references, optional policy counters and preservation of counters on updates that omit them. Failed batches discard staged renames. Rule listing serializes the current target name.
- Empty rules, creation and replacement flag handling, checked verdict/register inputs, and the metadata-only xtables comment match. A fresh ruleset starts at generation one. An explicit zero permits a batch at any generation, while a stale nonzero value rejects it. See the [Linux implementation](https://github.com/torvalds/linux/blob/master/net/netfilter/nf_tables_api.c).
- Packet dispatch retains the existing empty-policy shortcut. Optional chain counters only charge packets when configured. The new ownership work runs on configuration or socket close.

## Validation and open gaps

The Mac runner replayed another 145 previously measured Netlink cases. All matched their recorded status (132 passed, four failed, nine skipped). The iPad interpreter ran the 98 newly passing cases on Mac. The ARM64 iOS FFI build check and all eight shared-runtime CI stages passed. Physical iPad performance was not measured.

Cumulative coverage reached 14,201 of 14,530 original cases. The inventory includes 240 failed, 1 fixture_failed, 13,422 passed, 515 skipped, 23 timeout. There are 329 unmeasured cases. The new failures represent coverage of previously excluded Netfilter cases.

| Remaining Netfilter group | Failed |
| --- | ---: |
| CompatNATTests/NetlinkNetfilterCompatTest | 18 |
| CompatAddrtypeTests/NetlinkNetfilterCompatTest | 15 |
| FibRuleTest/AddRuleWithExprTest | 14 |
| CompatMasqTests/NetlinkNetfilterCompatTest | 12 |
| CompatConntrackTests/NetlinkNetfilterCompatTest | 8 |
| MasqRuleTest/AddRuleWithExprTest | 8 |
| NATRuleTest/AddRuleWithExprTest | 8 |
| PayloadRuleTest/AddRuleWithExprTest | 7 |
| BitwiseRuleTest/AddRuleWithExprTest | 5 |
| MetaRuleTest/AddRuleWithExprTest | 5 |
| NetlinkNetfilterSetElementsTest | 5 |
| CTRuleTest/AddRuleWithExprTest | 4 |
| CompatRuleDumpTests/NetlinkNetfilterCompatDumpTest | 4 |
| NetlinkNetfilterTest | 4 |
| LookupRuleTest/AddRuleWithExprTest | 3 |
| CompatNoopMatchTests/NetlinkNetfilterCompatTest | 2 |
| CmpRuleTest/AddRuleWithExprTest | 1 |

## Main-path timing

Matched guest probes ran on the same host with alternating runner order and two warm-up pairs. Socket and message results use 16 measured pairs. Memory, file and process probes use 32 pairs. The values are elapsed-time medians. The socket probes use the standard internal bridge without packet rules. These measurements do not characterize a large active firewall.

| Guest workload | Previous (ms) | Updated (ms) | Change |
| --- | ---: | ---: | ---: |
| udp_bind_close | 90.616 | 91.094 | +0.5% |
| udp_connected_delivery | 142.769 | 142.705 | -0.0% |
| tcp_connect_accept_send | 19.096 | 19.000 | -0.5% |
| unix_socketpair | 11.959 | 11.946 | -0.1% |
| unix_stream_send_recv | 19.309 | 19.385 | +0.4% |
| unix_datagram_send_recv | 20.904 | 20.988 | +0.4% |
| sendmsg_recvmsg | 54.798 | 54.575 | -0.4% |
| memory | 165.733 | 166.072 | +0.2% |
| mmap_fault_unmap | 122.759 | 123.733 | +0.8% |
| file_pread_pwrite | 92.337 | 92.315 | -0.0% |
| fork_wait | 18.367 | 18.280 | -0.5% |
| proc_cpuinfo | 1.656 | 1.651 | -0.3% |
| ordinary_open | 70.561 | 71.138 | +0.8% |
| ordinary_stat | 18.224 | 18.474 | +1.4% |

Mac runner SHA-256, previous `0001cb705484be90941a0e39e814af824fbc256033137bfe78ca6fbd06496f21`, updated `7adaca8a456bfa63db1c0cb0c0fea68f19f6f5ea9b0d20ca2dc7a27ddf1fcf71`.
