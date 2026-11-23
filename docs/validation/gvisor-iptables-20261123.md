# IPv4 and IPv6 legacy iptables, 2026-11-23

The Linux ARM64 socket ABI supports legacy `GET_INFO`, `GET_ENTRIES`,
`SET_REPLACE` and `ADD_COUNTERS` for the `raw`, `mangle`, `nat` and `filter`
tables. The socket's creating user and network namespaces determine authority
and table selection. IPv4 controls also work on non-raw IPv6 sockets. The
names of registered tables appear in `/proc/net/ip_tables_names` and
`/proc/net/ip6_tables_names`. [IPv4 UAPI](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/linux/netfilter_ipv4/ip_tables.h) · [IPv6 UAPI](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/linux/netfilter_ipv6/ip6_tables.h)

Table replacement validates the rule image and graph before publishing the
new rules. The runtime returns the old table's counters before publication.
The regression test verifies that a counter copy fault preserves the old
rules and counters. Legacy and nftables rules share guest Netfilter hooks,
extension implementations and connection tracking. The `SO_ORIGINAL_DST`
option reads the original TCP destination of a tracked connection. Legacy
table images are capped at 4 MiB. Supported verdicts and extensions are
limited to the implemented guest packet operations. [IPv4 table control](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/ipv4/netfilter/ip_tables.c) · [IPv6 table control](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/ipv6/netfilter/ip6_tables.c)

## Original gVisor cases

The pinned binaries and native reference are from the expanded November 17
run. The Mac runner used a guest-only bridge. The iPad interpreter ran on
the Mac host with guest loopback. Each selected case ran in a fresh store.

| Selection | Previous Mac and interpreter, each | Updated Mac and interpreter, each |
| --- | --- | --- |
| 22 missing IPv4 records | 1 passed, 20 failed, 1 skipped | 22 passed |
| 14 missing IPv6 records | 14 failed | 14 passed |
| 20 revision probes | | 20 passed |
| 76 adjacent nftables cases | | 75 passed, 1 skipped |

The adjacent skip is the existing conditional skip in
`CompatConntrackTests/NetlinkNetfilterCompatTest.AddCompatRule/UnsupportedFlags`.
Both executors also passed `IPTablesTest.InitialState` and
`IPTablesTest.RawTableInitialState` in the upstream userspace-kernel test mode.
Two historical crash regressions, one in each family, remain without Trames
results. The November 23 rolling comparison counts 13,862 Trames passes
among the 13,864 original cases that passed on native ARM64 Linux.

## Guest tools and local checks

Alpine's signed iptables 1.8.11-r1 tools exercised IPv4 and IPv6 loopback
traffic with legacy and nftables tables present. The checks created a user
chain, dropped and allowed UDP packets, saved and restored live counters,
redirected TCP and read the original destination on the accepted socket.
The checks passed on both executors. All eight Runtime local CI stages and
the ARM64 iOS FFI compile check passed.

Final Mac runner SHA-256
`22ea59cf6e4d1f96e79cb5ef15156902765531e8357f5ccc7fea36c40e406167`.
Final interpreter runner SHA-256
`edc94567eb2070289d8d39cb8fa870f2c0719872cc632bcf0dcda1d753191c16`.

Local validation logs, scoped original case plans and guest fixtures are
under `target/gvisor-iptables-20261123` in the iPad checkout.

## Paired socket performance

A two-vCPU Mac guest ran the ordinary socket workload against Runtime
`c3dcaf6` and the updated runner in alternating order. The table reports
median milliseconds from 32 measured pairs after two warm-up pairs.

| Workload | Previous (ms) | Updated (ms) | Elapsed change |
| --- | ---: | ---: | ---: |
| UDP bind and close | 100.812 | 100.194 | -0.61% |
| UDP connected delivery | 156.643 | 157.172 | +0.34% |
| TCP connect, accept and send | 21.103 | 20.896 | -0.98% |
| Unix socketpair | 13.026 | 12.979 | -0.36% |
| Unix stream send and receive | 20.893 | 20.909 | +0.07% |
| Unix datagram send and receive | 22.366 | 22.334 | -0.14% |
