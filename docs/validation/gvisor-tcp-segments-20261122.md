# Guest TCP segmentation, receive semantics and blocking I/O

The baseline is runtime `f96a68c`. Both Mac hardware-executor builds used the same ARM64 gVisor binaries, guest root filesystem and two guest CPUs. The selection covers all cases in `socket_ip_tcp_generic_loopback` (805), `tcp_socket` (190), `socket_stream_blocking_tcp` (60), and `socket_blocking_ip` (12).

## gVisor results

| Original GoogleTest outcome | Baseline | Updated |
| --- | ---: | ---: |
| Passed | 701 | 841 |
| Failed | 354 | 214 |
| Timed out | 12 | 12 |

All 140 improvements matched a passing native Linux case. No previously passing case changed to another outcome. Corking accounts for 62 passes, quick ACK for 24, truncation and peek for 20, read shutdown for 12, MSS for six, connected sendto and self-connect for four, and file/pipe transfers for 12. Each updated pass was verified against its original GoogleTest XML. The same 12 oversized blocking-send cases timed out in both runs.

The cumulative inventory records 12,161 of 14,530 reference cases, with 11,379 passes, 354 failures, 32 timeouts, 395 skips and one fixture failure. This iteration retested existing entries. Remaining TCP failures include user timeouts, positive linger, receive-window clamping and connection error handling.

## Transport behavior

- TCP_CORK holds a new short segment until the segment fills, the application flushes it, the stream closes, or the 200 ms timer expires. Retransmission of previously sent bytes can proceed while a new short tail remains corked. A pending ACK can still travel.
- TCP_MAXSEG limits the advertised and outgoing segment size. TCP_QUICKACK can flush a delayed ACK and then returns to normal ACK timing. These options operate on the guest transport. A hybrid wildcard listener rejects unsupported options before changing either half.
- MSG_TRUNC advances the stream without copying into the guest buffer. MSG_PEEK with MSG_TRUNC reports the available count and leaves the bytes queued. SHUT_RD allows already queued bytes to drain. A sendto on an established stream uses its connected peer.
- A successful read only requests an extra network poll if it opens an advertisable receive window. A blocked reader or writer subscribes to its existing connected socket. Incoming data, freed transmit capacity and connection-state changes wake subscribers after the fabric lock is released. Native descriptors and protocol timers retain their existing roles. Tests fill both rings, drain the receive window and check that the waiting writer can send again.

## Performance

The previous and updated release executables alternated on the same Mac with two guest CPUs and an internal network. Times are guest elapsed milliseconds. Each short workload used 16 measured pairs after two warm-up pairs. The short-socket suite also ran with the starting order reversed.

| Workload | Baseline | Updated | Elapsed change | Reversed order |
| --- | ---: | ---: | ---: | ---: |
| TCP connect, accept and send | 20.80 | 18.86 | −9.3% | −8.7% |
| UDP bind and close | 90.17 | 90.49 | +0.3% | −0.1% |
| Connected UDP delivery | 142.64 | 144.93 | +1.6% | −0.3% |
| Unix socketpair | 11.90 | 11.82 | −0.7% | −0.4% |
| Unix stream send and receive | 19.34 | 19.35 | +0.1% | +0.0% |
| Unix datagram send and receive | 20.77 | 20.77 | +0.0% | −0.1% |
| sendmsg and recvmsg | 54.82 | 54.80 | −0.05% | |
| TCP 16 MiB, one thread alternating send and receive | 38.92 | 39.06 | +0.4% | |
| TCP 16 MiB, separate sender and receiver processes | 131.99 | 66.25 | −49.8% | |

Both 16 MiB probes verified delivered data. The two-process result pools 80 measured pairs across three series. Median elapsed time improved in all three series (69%, 26% and 45%). The median within-pair change was −50.1%, with a 95% bootstrap interval of −62.2% to −39.6% from resampling pairs within each series. Absolute times varied with scheduling. The one-thread probe shows how much of the gain depends on blocking and wakeup in this workload. These are guest loopback results on one Mac.

## Additional validation

The iPad interpreter ran on the Mac and passed each of the 140 changed cases in a fresh store, with no skips in either original GoogleTest XML report. The ARM64 iOS FFI compiled. The eight-step shared runtime CI passed locally. Of the vendored TCP unit tests, all 174 passed. The broader vendored library suite passed 604 and reproduced five failures previously observed at baseline (two IPv4 packet length checks, two raw/UDP coexistence checks, and 6LoWPAN UDP fragmentation).
