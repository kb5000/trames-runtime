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

## Chain entry validation follow-up

Chain labels and the terminal marker retain their wire entries and counter
slots. They carry no executable rule body. The parser resolves table entry
points, policy offsets and jumps through one executable-entry check, and its
graph walk checks fallthrough destinations. The evaluator drops a packet if
it encounters a record without a rule body.

The IPv4 and IPv6 regression tests cover rule-boundary lookup, metadata-only
records and atomic rejection when an offset is invalid. Rejection leaves the
previous table and counters in place and precedes counter copyout. The two
historical upstream crash cases still have no Trames test records.

The Mac runner and the interpreter each passed 58 original IPv4 and IPv6
iptables tests. The two IPv4 initial-table tests used the upstream
userspace-kernel mode. Both runners also passed the signed Alpine legacy
tool checks for legitimate user chains, counters and REDIRECT. Runtime CI
passed all eight stages, and the ARM64 iOS FFI check passed.

Runner SHA-256 values were
`44973bc238b9d95031a7d1641c8863f18a75662e9ad1f8eabf8b18946bad6390`
for Mac and
`bef22c3be435a7274ce95f235ef2496037bc6d85e78b18cac9f3d2c8dd514275`
for the interpreter. Logs and case selections are under
`target/gvisor-iptables-entry-20261123` in the iPad checkout.

The same six ordinary socket workloads ran for 32 paired samples against
Runtime `c856286`. Median elapsed changes ranged from -1.12% to
+0.35%.

## UserChainTargetCrash closure

Both remaining original cases now have passing results on both executors:

| Original case | Mac HVF | Interpreter on Mac |
| --- | --- | --- |
| `IPTablesBasic.UserChainTargetCrash` | passed | passed |
| `IP6TablesTest.UserChainTargetCrash` | passed | passed |

The unchanged November 17 ARM64 binaries ran separately in fresh Alpine
stores with two guest CPUs and the ordinary upstream test mode. Each result
has completed GoogleTest XML, exit status zero and no skips. The runners are
the source-verified `9a20d6a` executables fingerprinted above. The interpreter
run does not represent a physical iPad test.

The existing entry-validation fix already rejects these images. This
follow-up adds regression tests without changing production code. The tests
recreate the original four-entry images, reject chain labels, terminal
markers and interior offsets as hook, policy and jump destinations, and
reject fallthrough into a chain label. Rejection precedes counter copyout
and preserves the old wire image and live counters. Positive controls accept
hooks entering a chain body and a legitimate jump to a returning user chain.

All 204 `trames-net` unit tests, 13 integration tests and its doc-test check
passed, as did scoped Clippy and workspace formatting. Unchanged production checks, iOS FFI,
guest-tool acceptance and the 32-pair socket performance measurements above
are reused. Local evidence, including both original case plans, XML and the
126-case closure audit, is under `target/gvisor-user-chain-20261123` in the
iPad checkout.

The audit matches all 126 original November 23 gaps to passing Mac and
interpreter evidence from the five documented batches. The cumulative
comparison is **13,864/13,864 native-passing cases**, with zero remaining
gaps in that fixed selection. This is a rolling result across revisions;
it is not a full same-revision rerun or coverage of every Linux interface.
