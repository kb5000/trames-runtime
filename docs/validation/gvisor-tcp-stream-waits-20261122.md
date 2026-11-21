# Guest TCP stream waits and live socket buffers

The baseline is shared runtime `cf05c00`. This batch exercises blocking stream I/O, ordinary TCP buffer options and read readiness on the guest-owned IPv4 and IPv6 stack.

## Behavior

* An accepted blocking read tracks its copied prefix across waits, including iovec boundaries. MSG_WAITALL targets the request length. Ordinary reads honor SO_RCVLOWAT up to the request length. Nonblocking calls return the available prefix. A blocking peek reads from the head on each retry and leaves the data queued. MSG_TRUNC consumes bytes without copying their payload.
* A blocking write continues from its accepted offset until it finishes the staged payload, hits backpressure or sees an error. On interruption or peer close, the caller can collect its partial length. Batch calls write the length of the interrupted item before returning the completed count. The existing per-call staging cap still applies.
* SO_SNDBUF and SO_RCVBUF now size the actual TCP queues. A live resize preserves queued data, out-of-order receive bytes, and previously advertised credit. An established receive queue keeps its larger backing allocation after a shrink. Accepted sockets inherit the listener's buffer, low-water and boolean option settings.
* Ordinary readers are notified on the first readable byte. A blocking peek or poll waiting on a larger prefix arms a byte threshold on the same protocol socket. The next threshold crossing wakes subscribers to recheck their requests. This avoids a notification for every segment of an already readable stream. The implementation uses the existing socket wait source.

## Compatibility

Eight complete upstream suites cover 1,443 cases. Results are classified by original guest XML and matched by suite and case against the previous inventory.

| Result | Baseline | Updated |
| --- | ---: | ---: |
| Passed | 1,201 | 1,275 |
| Failed | 218 | 156 |
| Timed out | 12 | 0 |
| Skipped | 12 | 12 |

The same 1,201 existing passes were retained. All 74 newly passing cases also passed the native Linux reference. They comprise 36 loopback cases (ordinary buffer options, low-water and WAITALL), 36 blocking-stream cases (including all 12 former partial-write timeouts), and two sender-wakeup cases after a live buffer increase.

The cumulative inventory covers 12,479 of 14,530 discovered cases, with 11,755 passes, 296 failures, 20 timeouts, 407 skips and one fixture failure. The 156 failures in these eight suites include linger and OOBINLINE, TCP_USER_TIMEOUT, TCP_WINDOW_CLAMP, forced receive buffers, and ancillary options. Native BSD socket behavior and these outstanding options are outside the measured compatibility gain.

The iPad interpreter on the Mac reran all 74 corrected cases and produced original passing XML for each one. The iOS ARM64 FFI check passed. The shared runtime's eight local CI steps passed. Focused regressions exercise split iovecs, interrupted recvmmsg length copyout, repeated peeks, discard reads, and simultaneous poll and peek thresholds. The independent vendored tests passed 606 cases, including all 175 TCP tests. The same five baseline IPv4 and 6LoWPAN tests still fail.

## Performance

Two guest CPUs on the Mac hardware executor, the same guest executables and socket configuration, and 16 measured baseline/candidate pairs per series after two warm-up pairs. The second series starts with the opposite executable. The bulk transfer verifies all 16 MiB and the child exit status. Each timing is elapsed time inside the guest.

| Workload | Baseline (ms) | Updated (ms) | Change | Reverse baseline (ms) | Reverse updated (ms) | Reverse change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| TCP 16 MiB across processes | 66.44 | 68.55 | +3.17% | 64.86 | 62.99 | -2.89% |
| TCP connect, accept and send | 18.47 | 18.72 | +1.34% | 18.59 | 18.66 | +0.42% |
| UDP bind and close | 89.83 | 90.52 | +0.76% | 90.05 | 89.93 | -0.13% |
| Connected UDP delivery | 143.04 | 142.49 | -0.38% | 143.27 | 142.72 | -0.39% |
| Unix socketpair | 11.84 | 11.86 | +0.11% | 11.81 | 11.90 | +0.77% |
| Unix stream send and receive | 19.29 | 19.40 | +0.58% | 19.43 | 19.40 | -0.15% |
| Unix datagram send and receive | 20.79 | 20.88 | +0.46% | 20.87 | 20.90 | +0.16% |
| sendmsg and recvmsg | 54.93 | 55.14 | +0.39% | — | — | — |

An intermediate implementation notified subscribers whenever the receive queue grew. Its two bulk series took 23.61% and 4.35% longer than baseline. The threshold implementation reduced this to +3.17% and −2.89%. External network throughput and physical iPad performance were not measured.
