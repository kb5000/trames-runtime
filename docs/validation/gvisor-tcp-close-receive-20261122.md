# TCP final close, reset delivery and receive metadata

The baseline is shared runtime `fd66c22`. The comparison uses the same ARM64 Linux guest executables, original GoogleTest case names and internal network topology on both revisions.

## Behavior

* An explicit close with positive SO_LINGER releases the descriptor immediately. When it releases the final socket owner, close can park on the original stream until the FIN is acknowledged or the configured time expires. Duplicates remain usable. Zero linger aborts the connection. Disabling linger preserves the previously configured duration for getsockopt.
* A fully closed endpoint resets new data that arrives in its receive window. A write-half shutdown preserves the reader. The transport records an accepted reset on its own socket, replacing a scan of the namespace's socket registry for matching addresses. A refused connect, reset connection, write after peer close and delivery timeout retain distinct errors.
* TCP_INQ reports the bytes left at the end of a receive. A FIN contributes one sequence point to the hint, including after the payload has drained. Zero-length reads and peeks preserve the queue. Receive timestamps use the arrival time of the last byte returned. When the caller requests both, recvmsg delivers the timestamp before TCP_INQ.
* These changes target guest-owned TCP. Receive timestamp tracking allocates storage and samples the clock only on sockets that enable it. The close wait reuses socket wakeups and the existing transport timers.

Upstream describes the receive hint in `tcp_inq_hint` and the linger configuration in `sk_setsockopt`. The Linux kernel's exact readback for negative linger intervals depends on its timer conversion. Trames preserves the guest's 32-bit interval. [Linux TCP](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp.c) · [Linux socket options](https://github.com/torvalds/linux/blob/master/net/core/sock.c)

## Compatibility

| Original cases | Baseline | Updated |
| --- | ---: | ---: |
| Passed | 1,624 | 1,690 |
| Failed | 94 | 28 |
| Skipped | 12 | 12 |
| Total | 1,730 | 1,730 |

The comparison includes 199 newly covered loopback cases. Of those, 177 already passed on the baseline. The other 22 exposed a peer that could keep writing after final close. The remaining 44 improvements came from the previous inventory, including 38 linger cases and six receive-control cases. Every improvement also passed the native Linux reference and was rerun with the iPad interpreter on the Mac.

The 28 outstanding failures cover TCP urgent data (12), forced receive buffers (6), socket filters (6) and path-MTU discovery (4). Cumulative coverage is 12,766 of 14,530 discovered cases, with 12,170 passes, 168 failures, 20 timeouts, 407 skips and one fixture failure.

The runtime's eight local CI steps and the iOS ARM64 FFI check passed. Focused regressions cover closing duplicated descriptors under packet loss, waiting to the configured deadline, zero-length and peek reads across a FIN, and timestamp ranges across reordered and overlapping data. The standalone transport tests passed 610 cases, including all 179 TCP tests. Five pre-existing IPv4 and 6LoWPAN tests failed with the same names on the baseline.

## Performance

The Mac hardware executor used two guest CPUs. Timings are inside the Linux guest. The comparison alternated executables, discarded two warm-up pairs per series, and used the same executable and data checks for each baseline/candidate pair. Physical iPad speed and external traffic were not measured.

| Workload | Baseline (ms) | Updated (ms) | Change | Reverse-order change |
| --- | ---: | ---: | ---: | ---: |
| TCP connect, accept and send | 19.14 | 18.96 | −0.94% | +1.77% |
| UDP bind and close | 89.76 | 90.82 | +1.18% | −0.35% |
| Connected UDP delivery | 142.89 | 141.86 | −0.73% | +1.36% |
| Unix socketpair | 11.87 | 11.81 | −0.52% | −0.08% |
| Unix stream send and receive | 19.34 | 19.35 | +0.04% | +0.35% |
| Unix datagram send and receive | 20.76 | 20.80 | +0.22% | +0.12% |
| sendmsg and recvmsg | 54.97 | 54.63 | −0.61% | — |

Each row uses 16 measured pairs per series. For a separate 16 MiB cross-process TCP transfer, the two series of 32 pairs gave +18.00% and +0.34% when comparing their medians. Across 64 pairs the baseline median was 66.17 ms and the updated median was 68.28 ms (+3.19%). The median within-pair change was +0.47%. The fast baseline samples in the first series make the short-transfer result sensitive to sample order.

To check sustained transfer, the same probe verified 128 MiB per run. Two series of 24 pairs gave −0.31% and +0.22%. Across all 48 pairs, the baseline median was 308.71 ms and the updated median was 309.03 ms (+0.10%). The median within-pair change was +0.15%.
