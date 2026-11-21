# TCP delivery deadlines, receive windows and deferred accept

The baseline is shared runtime `0634b0b`. Both executables ran the same ARM64 guest programs on the Mac hardware executor.

## Behavior

| Linux option | Guest TCP behavior |
| --- | --- |
| TCP_USER_TIMEOUT | ACK progress refreshes a delivery deadline. A stalled send, zero-window block or unanswered keepalive can expire it. The socket wakes its subscribers and reports ETIMEDOUT once through SO_ERROR or I/O. An idle stream with keepalive disabled can stay open. |
| TCP_WINDOW_CLAMP | Limits newly advertised receive credit from the handshake onward. A live reduction honors outstanding credit. The implementation tracks the unscaled SYN advertisement when negotiating a scaled window. |
| TCP_SYNCNT | Counts active-open SYN retransmissions after a successful packet emission. An explicit retry budget takes effect once the initial SYN is on the wire. |
| TCP_DEFER_ACCEPT | Poll and accept on the listener use the same readiness condition. Contiguous incoming data, peer FIN or the existing transport deadline releases the accepted stream. |

These options apply to guest-owned TCP. A wildcard socket that also owns a native BSD listener rejects unsupported options before changing either half. Deferred accept was validated at the Linux socket interface. Its packet exchange can differ from a Linux kernel's SYN/ACK retransmission sequence.

## Compatibility

Eight complete suites and four additional parameterized families in a ninth suite were exercised. These families add 88 previously uncounted cases covering option inheritance, data arrival and accept timeout. Each result was matched by suite and case name. All 1,447 passes have original guest GoogleTest XML.

| Matched cases | Baseline | Updated |
| --- | ---: | ---: |
| Passed | 1,297 | 1,447 |
| Failed | 222 | 72 |
| Skipped | 12 | 12 |
| Total | 1,531 | 1,531 |

All 150 improvements also passed the native Linux reference. Of those, 84 were prior inventory failures and 66 came from the new families. The other 22 new cases already passed on the baseline. No previously passing case regressed. The iPad interpreter running on the Mac independently passed all 150 corrected cases, including the real timeout waits. The iOS ARM64 FFI target compiled. Physical iPad performance and external network throughput were outside this run.

The cumulative inventory covers 12,567 of 14,530 cases, with 11,927 passes, 212 failures, 20 timeouts, 407 skips and one fixture failure. The 72 failures in the matched set include 38 linger cases, 12 OOBINLINE cases, six forced receive-buffer cases and 16 filter, path-MTU and ancillary-data cases.

All eight local runtime CI steps passed. The standalone vendored transport suite passed 609 tests, including all 178 TCP tests. The same five pre-existing IPv4 and 6LoWPAN cases failed on both revisions. Added regressions exercise partial and duplicate ACKs, zero-window deadlines, one-shot timeout errors and wakeups after packet loss, real SYN retry exhaustion, and scaled passive-open receive windows.

## Performance

The internal-network benchmarks used two guest CPUs, the same fixture and an isolated store. Each series alternated executable order, discarded two warm-up pairs and measured elapsed time inside the guest. The reverse series started with the opposite executable.

| Workload | Baseline (ms) | Updated (ms) | Change | Reverse change |
| --- | ---: | ---: | ---: | ---: |
| TCP connect, accept and send | 18.71 | 19.15 | +2.37% | +1.87% |
| UDP bind and close | 90.86 | 90.57 | −0.32% | +0.13% |
| Connected UDP delivery | 144.32 | 143.60 | −0.50% | +0.61% |
| Unix socketpair | 11.85 | 11.82 | −0.29% | −0.16% |
| Unix stream send and receive | 19.57 | 19.34 | −1.16% | −0.22% |
| Unix datagram send and receive | 20.95 | 20.81 | −0.68% | −0.22% |
| sendmsg and recvmsg | 54.74 | 54.89 | +0.27% | — |

The table gives per-version medians of 16 samples in each series. TCP connection setup and delivery took about 0.35–0.44 ms longer per benchmark run.

The cross-process TCP bulk probe verifies 16 MiB. The first two series of 16 pairs gave changes of +8.92% and +2.20% in median elapsed time. Two further series of 32 pairs gave +2.58% and −2.78%. Over all 96 pairs the baseline median was 67.47 ms and the updated median was 68.37 ms (+1.34%). The median change within a pair was +0.38%, and the updated executable took longer in 51 pairs. The large change in the first series did not repeat.
