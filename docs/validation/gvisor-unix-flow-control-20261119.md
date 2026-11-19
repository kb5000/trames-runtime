# Unix socket flow control and receive completion — 2026-11-19

This continuation closes the known Unix endpoint failures except the user-namespace dependency: **340 new native-confirmed passes, zero regressions** across the same **6,093 original cases in 17 complete groups**. The strict fraction on native-passing cases rises from **92.93% to 98.76%**.

## Shared implementation

Addressed datagrams now charge the original sender across all destinations, including empty-packet metadata. Receive, truncation and final receiver close release that charge and notify the existing sender readiness source outside the queue lock. Peek retains the charge. A failed capacity probe does not generate a notification to itself. Increasing `SO_SNDBUF` updates the original budget and wakes waiters; datagram `POLLOUT` follows sender capacity even after write shutdown. No endpoint/OFD is kept alive by a queued charge.

The sender address is an immutable cached snapshot. Binding replaces the cache for future sends; already queued unbound packets retain their original source. A charge replaces the old per-packet source Vec, keeping queue records compact. Paired and addressed send/receive bodies are compiled separately, so ordinary streams and socketpairs execute no sender-accounting atomics. The existing object lock still protects their queues. No coordinator, service thread, polling loop, global lock, unsafe code or additional guest-memory policy was added.

`recvfrom` retains the same original byte OFD and timeout as `read`. Expired `MSG_WAITALL` and `SO_RCVLOWAT` waits return their already queued prefix, including a plain read that discards ancillary metadata, rather than hanging or returning an empty error. Close/reuse of the numeric FD does not replace the accepted socket. Credential changes split stream receives only while the receiver requests credentials; descriptor-rights boundaries remain intact.

The batch also implements the Unix boolean socket options, receive low-water storage/behavior, Linux receive-buffer minimum, signed force-buffer normalization, `TIOCOUTQ`, namespace-owned five-hex-digit abstract autobind names, listener peer credentials, protocol 1 acceptance and unconnected-stream `sendto` errors. Ordinary send/receive buffer hints have a 4 MiB input ceiling and Linux doubling; privileged force requests bypass that hint ceiling without preallocating memory. `O_RDONLY | O_TRUNC` resolves socket nodes to `ENXIO`; regular-file truncation requires write permission and overlay preparation.

The behavior is checked against the [Linux Unix socket implementation](https://github.com/torvalds/linux/blob/v6.12/net/unix/af_unix.c) and [generic socket options](https://github.com/torvalds/linux/blob/v6.12/net/core/sock.c), plus the unchanged native ARM64 Linux oracle.

## Original upstream results

| Outcome | Before | After |
|---|---:|---:|
| passed | 5,433 | 5,773 |
| failed | 424 | 72 |
| skipped | 212 | 248 |
| timeout | 24 | 0 |

The additional 36 skips are the upstream native `TIOCOUTQ` cases: they now pass their initial assertion and reach their original Linux skip. They are **not** counted as passes. Among 5,826 native-passing cases, Trames passes 5,754. Native skips and 19 missing native results remain outside the strict denominator.

| Group | New native-confirmed passes |
|---|---:|
| socket_abstract | 80 |
| socket_domain | 56 |
| socket_filesystem | 80 |
| socket_unix_dgram_local | 32 |
| socket_unix_pair | 28 |
| socket_unix_unbound_abstract | 18 |
| socket_unix_unbound_filesystem | 6 |
| socket_unix_unbound_stream | 40 |
| **Total** | **340** |

The remaining 72 failures are `SetSocketRecvBufForceAboveMax` and `SetSocketRecvBufForceWithoutCapability` (36 each), both blocked at `unshare(CLONE_NEWUSER)`. Supporting user namespaces requires a separate identity/mapping and capability-ownership implementation; these tests were not made to pass by pretending namespace creation succeeded. Receiver record limits remain 128, and this batch does not claim exact Linux skb allocation sizes or writable `max_dgram_qlen`. Other network families and disabled upstream cases are unchanged.

All original selected names and static ELF checksums are retained. Passing outcomes are independently audited against exact XML identities and successful exit status. Each process has a fresh disposable store, internal network without NAT, and two guest CPUs. The final optimized runner reruns the entire selection.

## Performance comparison

The same extended `unix-io` source is compiled against 8f6f44a and the candidate with matching locks, compiler and release settings (`overflow-checks=true`, thin LTO, no incremental compilation). Two warmups precede 15 alternating process pairs of 300,000 roundtrips, with eight times as many polls. CI, conformance workers, builds and the Linux test machine are stopped during measurement. Exact source, manifests, binary identities and every sample are included in the JSON.

| Operation | Before ns | After ns | Median change |
|---|---:|---:|---:|
| stream-64 | 50.71 | 52.42 | +3.37% |
| stream-4096 | 115.23 | 115.56 | +0.29% |
| dgram-64 | 46.36 | 47.90 | +3.32% |
| dgram-4096 | 108.67 | 109.41 | +0.68% |
| seqpacket-64 | 46.33 | 47.60 | +2.74% |
| recvmsg-stream-64 | 61.73 | 63.52 | +2.90% |
| addressed-dgram-64 | 121.31 | 116.31 | -4.12% |
| addressed-dgram-4096 | 187.70 | 176.96 | -5.72% |
| poll-empty | 5.49 | 5.45 | -0.80% |

Positive changes mean more time. Large paired transfers are within 0.7% of baseline, addressed datagrams improve by 4–6%, and small paired operations measure about 1–2 ns / 3% higher. Paired p10/p90 changes include zero for the small paired cases, so these samples do not establish a precise slowdown bound. They do not justify a claim of zero overhead either. These are original-resource microbenchmarks, not Firefox latency, whole-guest throughput or startup measurements.

## Validation and evidence

Both complete common-runtime local workflows pass **8/8** steps on macOS and native ARM64 Linux. Linux retains the previously verified **8 MiB test-harness stack**; production stacks and guest settings are unchanged. The iPad target compiles, all **11 interpreter Unix regressions** pass, and the final **24 FFI tests** pass. Interpreter scheduling fixtures now fill the actual sender budget instead of assuming the old 128-record queue capacity; their worker-slot and single-filter-decision assertions remain intact.

[Machine-readable results](gvisor-unix-flow-control-20261119.json) retain exact newly passing identities, source hashes, counts and performance samples. Raw logs are under ignored `target/gvisor-network-20261119`, with Linux CI logs under `target/local-ci/io/gvisor-network-20261119`. The physical iPad was not contacted, and installed environments were not restarted or replaced.
