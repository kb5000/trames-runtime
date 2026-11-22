# IPv4 and IPv6 xtables extension queries and REDIRECT, 2026-11-22

The Linux socket ABI and nftables compatibility queries now consult the same revision registry. A socket query checks the socket namespace's administrative capability and the 30-byte guest ABI, and returns success only for an implemented extension and version. IPv4 options also work on non-raw IPv6 sockets. Unsupported revisions of known extensions return EPROTONOSUPPORT and unknown extensions return ENOENT. The Linux IP socket wrappers write back the option length on success. [IPv4 socket wrapper](https://codebrowser.dev/linux/linux/net/ipv4/ip_sockglue.c.html#ip_getsockopt) · [IPv6 socket wrapper](https://codebrowser.dev/linux/linux/net/ipv6/ipv6_sockglue.c.html#ipv6_getsockopt) · [xtables revision lookup](https://codebrowser.dev/linux/linux/net/netfilter/x_tables.c.html#xt_find_revision)

The xtables REDIRECT target in an nftables NAT chain uses loopback on local output and an address of the receiving interface on prerouting. The existing connection tracker records the first destination and port translation and reverses it on replies. A packet-level regression covers both IP families, first and established packets, checksums, replies, an unknown input interface, an invalid hook and an explicit-address flag. The network library passed all 197 unit tests. [Linux REDIRECT implementation](https://codebrowser.dev/linux/linux/net/netfilter/nf_nat_redirect.c.html)

## Original gVisor tests

| Selection | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| Extension revision probes, previous Mac runner | 0 | 20 | 0 |
| Same probes, updated Mac runner | 19 | 1 | 0 |
| Same probes, iPad interpreter on Mac | 19 | 1 | 0 |
| Same probes, native ARM64 Linux reference | 20 | 0 | 0 |
| Adjacent nftables compatibility cases, updated Mac runner | 75 | 0 | 1 |

Each adjacent outcome matches its previous result and native reference. All 20 revision probes add coverage to the cumulative inventory. The outstanding case is IPTablesBasic.GetRevisionMatchMark. Packet mark matching needs packet-scoped metadata across hooks, separate from the conntrack mark. Legacy table listing and replacement are outside this batch.

Cumulative coverage is 14,437 of 14,530 cases across revisions. Results comprise 13,790 passes, 62 failures, 23 timeouts, 561 skips and one fixture failure. There are 93 unmeasured cases. Local runtime CI completed all eight stages, including three reused stages. The ARM64 iOS FFI check passed. The interpreter run used the Mac host.

## Paired performance

A two-vCPU Mac guest ran each previous and updated signed binary in alternating order on the same workload. Results are median milliseconds from 32 measured pairs after two warm-up pairs.

| Workload | Previous (ms) | Updated (ms) | Elapsed change |
| --- | ---: | ---: | ---: |
| memory | 169.957 | 169.683 | -0.16% |
| mmap fault unmap | 124.733 | 124.831 | +0.08% |
| file pread pwrite | 96.305 | 95.894 | -0.43% |
| fork wait | 18.637 | 18.501 | -0.73% |
| udp bind close | 91.915 | 92.017 | +0.11% |
| udp connected delivery | 144.195 | 143.866 | -0.23% |
| tcp connect accept send | 19.388 | 19.214 | -0.90% |
| unix socketpair | 12.062 | 12.057 | -0.04% |
| unix stream send recv | 19.458 | 19.512 | +0.28% |
| unix datagram send recv | 20.937 | 21.143 | +0.98% |

Previous runner SHA-256 `6705422b2fad56fa7e52d8322aa4ef694de4a19c629284a44f42897aebb632fa`. Updated runner SHA-256 `d4c610433159bf910839aebfb61e3e66e5a3f98c0748fa4a682d7610a6d30d01`.
