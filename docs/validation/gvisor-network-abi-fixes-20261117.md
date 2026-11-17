# gVisor network ABI repairs — 2026-11-17

Follow-up: the [complete Unix ancillary-message matrix](gvisor-unix-ancillary-20261117.md)
now closes all 84 Unix failures listed below. This document retains the earlier
checkpoint's counts.

This follows the [14,530-case inventory](gvisor-expanded-20261117.md). It repairs
the receive/ancillary-message dependency class, TCP diagnostics and connection
readiness, namespace inspection prerequisites, and the identified seccomp
failures. It does not replace the full inventory with a new overall pass rate.

## Results

The final concentrated run contains **19 groups / 2,697 original cases**,
including all **1,944 UnixSocketPairCmsgTest cases** across the three upstream
target binaries, complete netfilter and seccomp groups, and all recvmmsg,
TCP_INFO and related half-close cases in the pinned inventory.

Trames: **2,196 pass, 412 assertion failures, 89 skips**; no timeout, missing XML,
or global fixture failure. Every reported pass was independently checked against
the original GoogleTest XML. Native Linux: 2,591 pass, 87 skips, 19 missing results.

On the **2,591 native-passing cases**, Trames passes **2,177 (84.02%)**, compared
with **1,739 (67.12%)** in the original sweep: **438 new passes, zero regressions**
among previously passing cases. The remaining outcomes are 412 failures and two
additional skips. Cases without a passing native reference are excluded from
this comparison.

| Area | Native-passing cases | Previous pass | Current pass |
|---|---:|---:|---:|
| Unix ancillary messages, complete matrix | 1,895 | 1,619 | 1,811 |
| recvmmsg | 132 | 0 | 132 |
| TCP_INFO / connection state | 70 | 0 | 70 |
| seccomp | 19 | 16 | 19 |
| netfilter | 263 | 0 | 41 |

Counts in this table use the same cases and native reference on both sides.
The 48 upstream recvmmsg skips and four seccomp skips are not successes.
The [machine-readable report](gvisor-network-abi-fixes-20261117.json) retains
the group counts, source hashes and binary provenance.

## Implementation

- `recvmmsg` uses the existing accepted-call message machinery for Unix, IPv4,
  IPv6 and netlink sockets. The call retains its original OFD, current message,
  received-message count and guest destinations across parking and FD reuse.
  It implements MSG_WAITFORONE, nonblocking partial results, timeout copyout and
  partial completion on interruption. The explicit batch timeout is checked
  between messages, matching Linux's empty-queue timeout behavior.
- Unix SCM_CREDENTIALS now preserves the distinction between explicit
  credentials, automatic credentials requested by either endpoint at send time,
  and enabling SO_PASSCRED only after a message was queued. Addressed datagrams,
  connected datagrams, streams, seqpacket and descriptor passing share the same
  decision. The caller's existing authority checks remain in the message decoder.
- TCP_INFO exposes the classic 104-byte Linux prefix. Internal sockets query
  the original smoltcp transport; native sockets use Linux TCP_INFO or public
  Darwin TCP_CONNECTION_INFO. State, RTO/RTT estimates, peer MSS and congestion
  window come from the actual transport. Fields without a corresponding backend
  counter remain zero. No control block layout is cast or copied into guest memory.
- Unspecified connect destinations select local loopback. POLLRDHUP observes
  real TCP half-close even with unread payload, on both internal and native
  transports. Darwin performs its extra state query only for requested, readable
  half-close observations; ordinary byte transfers do not acquire a new lock.
- `/proc/PID/uid_map` and `gid_map`, including task paths, truthfully report the
  initial user namespace. These read-only queries unblock netfilter and cgroup
  setup; creating a user namespace remains unsupported.
- Netlink implements NETLINK_CAP_ACK, preserving every aligned record in a
  packed batch. nftables accepts the operation resource ID used by upstream
  clients and implements family-specific or unspecified unnamed table flushes
  inside the existing rules transaction. Unsupported features still return errors.
- SECCOMP_RET_LOG permits execution while retaining action precedence. Linux
  audit logging is not implemented. A real group STOP/CONT makes relative sleep
  re-enter through restart_syscall filtering; absolute sleep uses its original
  entry. Host checkpoints and normal executor yields retain the accepted decision.

All production work stays on existing executors and original shared resources.
No coordinator fallback, polling bus, resource service thread or batch-wide
socket lock was added. The small vendored transport addition is documented in
[TRAMES-PATCHES.md](../../vendor/smoltcp/TRAMES-PATCHES.md).

## Validation and resources

- Complete common-runtime local workflow: **8/8 on macOS and 8/8 on ARM64 Linux**,
  including format, clippy, all-feature tests, release build and physical reclaim.
- iPad interpreter composition: **490 pass, three existing ignores** in the
  final complete serial conformance run. An earlier concurrent run hit a
  structural-fixture completion-marker assertion under shared instruction
  budgets; the unchanged fixture passes in the final run. Both logs are retained.
- One existing Linux debug packet-stack fixture receives an 8 MiB test thread
  stack instead of libtest's default 2 MiB. Production thread stacks are unchanged.
- The sysinfo accounting fixture awaits actual progress with bounded cohort
  budgets; a shared instruction budget cannot guarantee dispatch of every PID.
  All policy/accounting assertions remain intact.
- A broad first repair run of 2,980 cases exposed an overly broad automatic
  credential condition. It was corrected before the complete matrix run above;
  all 48 introduced regressions were eliminated without changing upstream tests.
- The final TCP_INFO diagnostic-field adjustment was followed by all 70 original
  TCP_INFO cases and affected local CI checks. Their separate runner hash is
  recorded; unaffected class results are reused rather than rerun.
- The same pinned ARM64 ELF binaries and native reference as the original sweep
  are reused. Every invocation uses a disposable store, two CPUs, a lazy 8 GiB
  budget and an internal network with host interoperability disabled. Installed
  Stable/Dev applications and existing environments were not replaced or restarted.
- Reproducible Cargo debug caches recovered **127.2 GiB**, raising free space
  from 13.2 to 140.5 GiB before validation. Release apps, environment stores,
  source archives and original test evidence were retained. This run disables
  incremental compilation and uses reduced debug information; it does not change
  repository-wide build defaults.

Raw logs, original XML, selected reference plans and independent audits are under
ignored `target/gvisor-gap-fixes-20261117`; native CI logs are under
`target/local-ci/io/gvisor-gap-fixes-20261117`. The existing test guide's `batch.py`,
`normalize.py` and `compare.py` commands reproduce the checks with these plans.

## Remaining gaps

The complete Unix ancillary matrix still has 84 native-confirmed failures:
36 null-control-buffer truncation cases, 36 nonexistent credential-PID cases,
and 12 zero-length receives that must receive descriptor metadata. The remaining
netfilter failures include sets, advanced chain/rule features and exact validation
errors; clearing the global fixture blocker is not full nftables conformance.

Other inventory gaps—user namespaces, clone3/pidfd details, System V IPC, memory
locking and additional filesystem/network semantics—remain tracked in the broad
report. This checkpoint does not claim a new full-suite result or physical iPad
CTS execution.
