# Packet marks in the Linux guest, 2026-11-22

The guest network stack now carries a 32-bit mark alongside packet bytes. A socket's `SO_MARK` supplies the initial mark. Firewall rules can then match it, replace masked bits with the xtables MARK target, or read and write it through nftables registers. The connection tracker maintains its own independent mark. Ethernet serialization omits the packet mark, and delivery across a network namespace boundary clears it. [Linux mark match and target](https://codebrowser.dev/linux/linux/net/netfilter/xt_mark.c.html) · [Linux packet scrubbing](https://codebrowser.dev/linux/linux/net/core/skbuff.c.html#skb_scrub_packet)

Subsequent hooks in the same namespace see updated marks. An ordinary output filter can change the mark and preserve the selected route. A route-type output chain can trigger a new route lookup, including rejection by a mark-based policy rule. Marked nftables FIB lookups support output interface index and name. Mark-based address-type classification remains unsupported. [Linux route chains](https://codebrowser.dev/linux/linux/net/netfilter/nft_chain_route.c.html)

## Compatibility and integration

| Original gVisor selection | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| Selected cases, previous Mac runner | 41 | 2 | 0 |
| Same cases, updated Mac runner | 43 | 0 | 0 |
| Same cases, iPad interpreter on Mac | 43 | 0 | 0 |
| Same cases, native ARM64 Linux reference | 43 | 0 | 0 |
| Adjacent cases, updated Mac runner | 75 | 0 | 1 |

The two recovered cases are `IPTablesBasic.GetRevisionMatchMark` and `MetaRuleTest/AddRuleWithExprTest.AddRuleWithExpr/GetMarkValid`. Every adjacent outcome matches the previous inventory and native Linux reference. Cumulative coverage across revisions is 14,437 of 14,530 cases, with 13,792 passes, 60 failures, 23 timeouts, 561 skips and one fixture failure. Another 93 cases have no recorded result.

The packet-level regression exercises both IP families, loopback, 8 KiB UDP datagrams, per-packet mark changes on the same flow, namespace crossing, bidirectional TCP and accepted socket marks. It also checks delivery under an ordinary filter and rejection after a route-chain mark change. A separate test exercises a marked guest socket against a real UDP receiver on the Mac.

Local runtime CI completed eight stages, including three reused stages. All 198 network unit tests passed. The ARM64 iOS FFI check passed. The interpreter result above is from the Mac-hosted runner. This batch did not include a physical iPad run.

## Paired performance

Each binary ran the same workload in a two-vCPU Mac guest. Execution order alternated across 34 pairs. Median times below use the 32 pairs following warm-up. Positive elapsed changes indicate a slowdown.

| Workload | Previous (ms) | Updated (ms) | Elapsed change |
| --- | ---: | ---: | ---: |
| udp bind close | 91.980 | 92.293 | +0.34% |
| udp connected delivery | 144.135 | 144.686 | +0.38% |
| tcp connect accept send | 19.620 | 19.494 | -0.64% |
| unix socketpair | 12.088 | 12.110 | +0.18% |
| unix stream send recv | 19.434 | 19.547 | +0.59% |
| unix datagram send recv | 21.051 | 21.071 | +0.09% |
| udp active output counter | 144.847 | 145.215 | +0.25% |
| memory | 169.326 | 169.892 | +0.33% |
| mmap fault unmap | 124.220 | 124.586 | +0.29% |
| file pread pwrite | 96.073 | 95.474 | -0.62% |
| fork wait | 18.308 | 18.553 | +1.34% |

Previous runner SHA-256 `d4c610433159bf910839aebfb61e3e66e5a3f98c0748fa4a682d7610a6d30d01`. Updated runner SHA-256 `f6bca7d8f67fd7ef190613a87980973424592c4a4d799e7460df7009d6098972`.
