# Guest TCP controls, recovery and Unix socket coverage

The Mac ARM64 hardware executor ran four complete upstream TCP suites against runtime `5177ad4` and the updated transport. Both runs used the same binaries, root filesystem, two guest CPUs and 20-second timeout. Original passing XML was checked against the exact suite and case names.

| TCP outcome | Previous runtime | Updated runtime |
| --- | ---: | ---: |
| Passed | 549 | 701 |
| Failed | 506 | 354 |
| Timed out | 12 | 12 |
| Total | 1,067 | 1,067 |

All 152 changed outcomes went from failure to pass. The ARM64 Linux reference, the shared CPU interpreter and the final packaged Mac runner each passed the same 152 cases. These include 56 congestion-control cases, 60 FIN-WAIT-2 option cases, 12 reads after half-close and 24 IPv4 multicast default queries on stream sockets.

Guest TCP defaults to CUBIC. Switching to Reno or back changes the active send window, including on connections accepted from a configured listener. The transport caps unacknowledged bytes across the entire flight, arms retransmission on the first outstanding byte, and tracks timeout backoff separately from measured RTT. IPv4 data transfer with both loss and corruption completes under each controller. The guest FIN-WAIT-2 timeout starts after the final descriptor closes. A live half-closed descriptor continues receiving. Orphan expiry sends a reset and releases the port using the existing fabric timer. Established connections clear their handshake deadline at the state transition, removing a per-tick scan of all sockets.

These controls cover the guest packet stack, including a root socket routed to an internal bridge. Native BSD connections continue to use their existing controls. A combined native and guest listener rejects guest-only settings before changing either endpoint.

## Inventory and remaining failures

Four additional Unix-domain suites ran on the previous runtime in this batch. They added 716 passes and 24 upstream skips (740 new cases). The four TCP suites added another 1,029 previously uncounted cases. The combined inventory now covers 12,161 of 14,530 discovered cases, with 11,239 passes, 494 failures, 32 timeouts, 395 skips and one fixture failure. All 152 TCP improvements were in the newly covered portion.

The twelve TCP timeouts all occur in the oversized blocking sendmsg test. Remaining assertion failures include TCP_CORK, TCP_QUICKACK, TCP_USER_TIMEOUT, positive SO_LINGER behavior, receive shutdown and partial blocking I/O. These are distinct from TCP_LINGER2.

## Performance and validation

The same Mac ran old and new runners in alternating order inside a private bridge environment. Each median excludes two warmup pairs and includes 16 measured pairs. A second short-operation series reversed which runner went first. Times are milliseconds per benchmark run.

| Workload | Previous | Updated | Time change | Reversed order |
| --- | ---: | ---: | ---: | ---: |
| TCP loopback, 16 MiB | 673.16 | 509.84 | −24.3% | |
| TCP connect, accept and send | 21.95 | 22.69 | +3.4% | +4.3% |
| UDP bind and close | 95.44 | 97.85 | +2.5% | +0.5% |
| Connected UDP delivery | 151.28 | 153.75 | +1.6% | −0.4% |
| Unix socketpair | 12.43 | 12.33 | −0.8% | +0.4% |
| Unix stream send and receive | 19.95 | 20.02 | +0.4% | +0.5% |
| Unix datagram send and receive | 21.70 | 21.66 | −0.2% | −0.4% |
| sendmsg and recvmsg | 56.30 | 56.52 | +0.4% | |

The 16 MiB test checks the received bytes and child exit status. The short TCP workload slowed down in both run orders. These are guest loopback measurements on one Mac.

The local runtime workflow passed all eight steps. The iPad FFI target compiled. All 172 vendored TCP tests passed. The broader vendored test run reproduced the same five failures on the baseline and candidate, in two IPv4 packet-length cases, two raw/UDP coexistence cases and one 6LoWPAN fragmentation case. The production runtime test suite passed.
