# Unix endpoint compatibility — 2026-11-19

This batch repairs the shared Unix endpoint class across original embedding and
worker paths. It adds **430 native-confirmed gVisor passes with zero regressions**
on previously passing cases. The final affected selection contains **6,093 cases
in 17 complete Unix socket groups**; no upstream source, assertion or skip rule
was changed.

## Changes

- Unix `SOCK_RAW` is normalized to datagram once at creation, retaining FD flags.
- Shutdown publishes both directions on stream/seqpacket connections; datagrams
  keep independent receive state. Existing readiness epochs notify blocked waiters.
- Close publishes authoritative endpoint state too, removing repeated peer-state
  reconstruction from ordinary reads and poll. All changes use the original
  channel lock; there is no new coordinator, service thread, poller or global lock.
- Zero-length socket receives distinguish an empty live queue (`EAGAIN`) from
  EOF, while plain `read(0)` stays non-consuming. SCM_RIGHTS peek/detachment and
  original OFD lifetime continue through the existing shared queue algorithm.
- Closing with unread stream data and closing a listener with unaccepted children
  publish a one-shot reset error. Read and `SO_ERROR` consume the same state;
  output faults do not consume it, and accepted connections remain independent.
- `SO_LINGER` stores/returns the endpoint option. Addressed datagrams support
  reconnecting to the same or a new peer; datagram accept reports `EOPNOTSUPP`.

These rules follow the original [Linux AF_UNIX implementation](https://github.com/torvalds/linux/blob/v6.12/net/unix/af_unix.c).
Neither host sockets nor additional guest-memory admission checks are involved.

## Original upstream results

| Group | New native-confirmed passes |
|---|---:|
| socket_abstract | 12 |
| socket_domain | 12 |
| socket_filesystem | 12 |
| socket_unix_dgram_local | 332 |
| socket_unix_stream | 48 |
| socket_unix_stream_listener_close | 2 |
| socket_unix_unbound_dgram | 12 |
| **Total** | **430** |

The stream group passes **216/216**, local seqpacket **336/336**, and unbound
datagram **52/52**. The complete ancillary matrix keeps its previous passing
results. Raw passes are independently checked against original XML, exact case
identity and successful process exit. The same immutable ARM64 ELF and saved
native Linux oracle are used. Each process has a fresh disposable store, an
internal network, two guest CPUs and an 8 GiB lazy budget.

| Final selection outcome | Cases |
|---|---:|
| passed | 5433 |
| failed | 424 |
| skipped | 212 |
| timeout | 24 |

Among **5,826 native-passing cases**, Trames passes **5,414 (92.93%)**.
Native skips/failures are excluded from this strict fraction. These are Unix
selection totals, not an updated score for the full 14,530-case inventory.

## Performance guard

`crates/trames-vfs/examples/unix-io.rs` is compiled against unmodified 7f408e3
and the candidate with identical compiler, dependency versions and release
settings. After warmup, 15 process pairs alternate order, each using 300,000
roundtrips (eight times as many polls). No CI, build or conformance worker is
running during measurement; all raw samples and both benchmark binary identities
remain in the evidence directory. These are resource microbenchmarks, excluding
guest startup and teardown, not Firefox or whole-system performance scores.

| Operation | Before ns | After ns | Median change |
|---|---:|---:|---:|
| stream-64 | 51.24 | 50.60 | -1.25% |
| stream-4096 | 114.63 | 114.99 | +0.31% |
| dgram-64 | 48.41 | 46.51 | -3.93% |
| dgram-4096 | 111.03 | 108.21 | -2.54% |
| seqpacket-64 | 48.58 | 46.58 | -4.12% |
| recvmsg-stream-64 | 62.13 | 61.90 | -0.37% |
| poll-empty | 5.49 | 5.51 | +0.40% |

Initial measurements showed a small repeatable stream/poll penalty. Publishing
the endpoint receive state at shutdown/close removed the duplicate hot-path
inference. Final median differences are within noise for stream/poll, with no
obvious regression; small-packet datagram/seqpacket samples are modestly faster.
This does not establish an end-to-end application speedup.

## Concentrated validation and remaining gaps

Common runtime CI passes **8/8 macOS and 8/8 ARM64 Linux**, including clippy,
all-feature tests, release build and physical reclaim. iPad ARM64 compilation
and **11 interpreter Unix conformance tests** pass. CPU/graphics acceptance with
unchanged code is reused; no physical iPad or installed app is accessed.

The native ARM64 debug netlink fixture exceeds its default Rust test-thread
stack with the 16-address network build. This was reproduced on both the clean
baseline and candidate under the same workspace features. Linux CI therefore
uses an explicit **8 MiB test-harness stack**, retaining every original assertion.
Production thread stacks and guest settings are unchanged. The test environment
adaptation and raw baseline/candidate failures are retained in the JSON/evidence.

Remaining Unix gaps include addressed-datagram sender accounting/queue capacity,
generic options, credential coalescing and existing receive timeouts. In
particular, this batch does not remove a queue bound to conceal missing sender
budgeting. Other syscall families and disabled upstream cases are unchanged.

[Machine-readable report](gvisor-unix-endpoints-20261119.json) includes exact
newly passing identities, baseline precedence, source/runner hashes and samples.
Raw evidence: ignored `target/gvisor-unix-20261119`; Linux CI logs are in
`target/local-ci/io/gvisor-unix-20261119`. Incremental compilation is disabled;
the isolated Linux CI machine is stopped after checks.
