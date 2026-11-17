# gVisor compatibility batch — 2026-11-17

This batch repairs Unix packet I/O, advisory locks, file-copy validation and
scoped path resolution together. The affected selection has **5,115 original
cases across 42 groups**. It gains **127 native-confirmed passes with zero
regressions against previously passing cases**.

## Changes

- Unix flow control follows the sender's `SO_SNDBUF`; a peer's `SO_RCVBUF`
  no longer blocks a larger sender. Increasing the send buffer updates the
  existing readiness epochs and unblocks original waiters. Packet size checks
  retain Linux's 32-byte send-buffer allowance. See the
  [Linux AF_UNIX socket options](https://man7.org/linux/man-pages/man7/unix.7.html).
- Unix datagrams and sequenced packets preserve whole messages beyond the
  generic 1 MiB streaming chunk. Scalar, vectored and message calls use the
  same packet decoder on embedding and worker paths, with the original socket
  buffer and Linux I/O range as bounds. Receive capacity alone does not allocate
  that amount of payload. Streams retain their bounded transport chunks.
- Connected sequenced-packet sends ignore a supplied destination, following
  [Linux's sequenced-packet send path](https://github.com/torvalds/linux/blob/v6.12/net/unix/af_unix.c).
- Pipe `flock` and byte-range locks use the existing shared anonymous inode;
  socket aliases use their original shared open description. Directories accept
  read locks. Conflicts, access modes, process/OFD ownership, close release and
  retained blocking requests remain real object state. A close of any alias
  releases that process's POSIX locks; a retained OFD continues to own its flock.
- Both file-copy paths share requested-range validation. Unsigned wraparound is
  rejected before EOF shortening, directories return `EISDIR`, and rejected
  operations leave descriptors, explicit offsets and file contents unchanged.
  See [Linux copy-file checks](https://github.com/torvalds/linux/blob/v6.12/fs/read_write.c).
- Scoped `openat2` lookups reject proc magic-link object jumps with `EXDEV`;
  explicit `NO_MAGICLINKS`/`NO_SYMLINKS` still take precedence with `ELOOP`.

There is no new coordinator, service thread, polling bus or global data-path
lock. Existing object locks, original OFD references and readiness notifications
continue to arbitrate operations. This is common runtime code for both products.

## Original upstream results

| Group | Newly passing cases |
|---|---:|
| Unix sequenced-packet local | 48 |
| Unix unbound sequenced-packet | 16 |
| Unix datagram local | 28 |
| Unix stream | 12 |
| Unix unbound stream | 12 |
| Unix socket pair | 1 |
| fcntl locks | 3 |
| flock | 2 |
| copy_file_range | 3 |
| openat2 | 2 |
| **Total** | **127** |

`socket_unix_seqpacket_local` now passes **336/336** and `copy_file_range`
passes **25/25**. The previous complete ancillary matrix remains **1,914 passes,
30 upstream skips and zero failures**.

The selection uses unchanged static ARM64 ELFs from gVisor
`89cacadae21eca4270a8f7c79281d0426d33ac5f`, the saved native Linux reference,
fresh disposable stores, an internal network, two CPUs and a lazy 8 GiB budget.
No upstream assertion, source or skip rule was changed. All reported passes
were independently audited against the original XML and process exit status.

| Final affected-selection result | Cases |
|---|---:|
| Passed | 4,308 |
| Assertion failures | 604 |
| Timeouts | 30 |
| No usable result | 6 |
| Upstream skips | 167 |
| Native-passing cases | 4,912 |
| Trames passes on those native-passing cases | 4,285 (87.24%) |

The first run covers all 5,115 cases. A follow-up reruns all 82 copy-file,
sendfile and splice cases after the retained-copy-path repair; those results
replace matching first-run records. Two separate signed test bundles preserve
binary provenance. Baseline precedence is the prior ancillary run, the preceding
network repair where covered, then the original broad sweep. The
[machine-readable report](gvisor-multi-area-20261117.json) records those inputs,
runner hashes, group results and all 127 newly passing identities.

These are affected-selection totals, not a new overall pass rate for the
14,530-case inventory. Other Unix datagram semantics, asynchronous fcntl signals,
one flock blocking timeout and concurrent mount/rename resolution remain open.
The unchanged 128-record queue bound and addressed-datagram sender-accounting
model are not claimed as Linux-equivalent by this checkpoint.

## Local checks and evidence

The common-runtime workflows pass **8/8 on macOS and 8/8 on native ARM64 Linux**,
including clippy, all-feature tests, release build and physical memory reclaim.
New regressions also cover large packets on scalar/vector/message embedding and
worker entries, real pipe/socket lock conflicts, retained close/reuse lifetimes,
and copy errors after original-resource asynchronous completion. The dedicated
Linux CI instance is stopped after validation.

Original XML, native plans, audited results and logs are retained under ignored
`target/gvisor-multi-area-20261117`; Linux CI evidence is under
`target/local-ci/io/gvisor-multi-area-20261117`. Incremental compilation stays
disabled for these builds; free disk space remains about 130 GiB. Installed apps
and existing environments are not replaced or restarted by this repair batch.
