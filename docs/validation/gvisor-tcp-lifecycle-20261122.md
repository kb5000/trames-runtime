# Guest TCP connection and listener lifecycle

The baseline is shared runtime `54571df`. This batch covers guest packet-stack connections on IPv4 and IPv6. The native BSD transport has its own admission limit and native connection implementation.

- A failed active open releases its transport slot and an automatically assigned port. A blocking caller can retry on the same descriptor. A nonblocking caller can collect the pending error exactly once through SO_ERROR or I/O. A later connect finishes the outstanding attempt before another one starts. A completed active open can also be collected after the peer's FIN.
- Normal read/write readiness and half-close events reach poll with their requested Linux bits. Shutting down a connecting stream aborts the handshake. Read shutdown on a listener stops accepting and resets queued children. Accepted descriptors have independent lifetimes. A closed or TIME_WAIT stream reports ENOTCONN on shutdown.
- A listener allocates one armed protocol slot per eligible address at startup. A validated SYN that fills a slot can arm another after the network interface poll. The remaining backlog grows with arriving connections. A full listening endpoint drops new SYNs so the client can retransmit. An unaccepted child reset returns its slot to the listener. Socket ownership, the receive queues and protocol timers stay on the existing network path.
- Pure packet-stack namespaces can hold 1,024 guest socket descriptors. Both the outer admission and the internal transport account for actual leases. A native socket namespace retains its 64-descriptor admission policy. File descriptor limits still apply at the normal guest FD allocation boundary.

A runtime regression requests a backlog of 512, verifies one initial slot, establishes twelve queued connections, resets a child and checks that its slot is reused. A dual-stack regression crosses 256 actual protocol handles with live connections, exercises IPv4 and IPv6 delivery and releases both namespaces.

## Coverage

Seven complete upstream suites (1,125 existing cases) ran again on the Mac hardware executor. The baseline had 899 passes, 214 failures and 12 timeouts. The candidate had 937 passes, 176 failures and the same 12 timeouts. All 38 improved cases have a passing native Linux reference and a matching original guest XML result. No existing pass regressed. The timeouts are the oversized blocking-send variants.

Including the additional suite below, the inventory covers 12,479 of 14,530 discovered cases. It records 11,681 passes, 358 failures, 32 timeouts, 407 skips and one fixture failure.

The 318 previously unmeasured cases in `socket_ip_tcp_loopback` ran on both release executables. Both produced 264 passes, 42 failures and 12 skips with identical outcomes for every case. The 42 failures comprise six address variants of each of seven cases: receive low-water and buffer sizes, forced receive buffer limits, boolean socket options, and three WAITALL behaviors.

The iPad interpreter ran the 38 corrected cases on the Mac, including the concurrent listener cases, and produced 38 original passing XML entries without skips. The ARM64 iOS FFI compiled. Shared runtime CI passed eight of eight steps. The independent vendored TCP tests passed 174 of 174. The full vendored suite retained the five baseline failures in IPv4 length handling, raw/UDP coexistence and 6LoWPAN fragmentation.

## Performance

The Mac ran alternating baseline/candidate pairs with two guest CPUs and identical guest executables. Each series kept 16 measured pairs after two warm-up pairs. The reversed series started with the opposite executable. The large transfer checks the delivered bytes and child exit status.

| Workload | Baseline median (ms) | Updated median (ms) | Elapsed change | Reversed series |
| --- | ---: | ---: | ---: | ---: |
| TCP connect, accept and send | 18.73 | 18.76 | +0.15% | −0.86% |
| TCP 16 MiB, two processes | 66.32 | 65.28 | −1.56% | +0.37% |
| UDP bind and close | 91.02 | 90.02 | −1.10% | +0.88% |
| Connected UDP delivery | 144.22 | 143.31 | −0.63% | +0.80% |
| Unix socketpair | 11.84 | 11.83 | −0.07% | +0.51% |
| Unix stream send and receive | 19.37 | 19.41 | +0.24% | +0.16% |
| Unix datagram send and receive | 20.89 | 20.85 | −0.18% | +0.70% |
| sendmsg and recvmsg | 55.07 | 54.92 | −0.27% | |

These timings measure the guest network paths on one Mac. Physical iPad performance and external network throughput were outside this run.
