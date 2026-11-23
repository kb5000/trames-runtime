# Batch stability follow-up, 2026-11-23

This closes the three intermittent differences retained by the
[full gVisor rerun](gvisor-full-20261123.md). It does not extend that report's
14,530-case selection or claim physical iPad acceptance.

## Mapping custody and false terminal idle

The five original Unix datagram cases were repeated with the same ARM64 ELFs,
two guest CPUs, fresh stores, and loopback/full guest network profiles. Before
the fix, 28 of 30 singleton executions passed; two
`DgramUnixSockets/UnixNonStreamSocketPairTest.FragmentedSendMsg/8` executions
ended without XML and reported that all virtual processes were blocked without
an event source. Both used the full profile, but this is insufficient evidence
to attribute the fault to networking. Full syscall tracing hid the failure.

A diagnostic limited to terminal idle captured PID 1 waiting in syscall 133
and PID 3 waiting for custody in syscall 222 (`mmap`), before `sendmsg`.
The mapping lifecycle published runnable jobs while retaining task/mm custody
until after cold accounting. Another CPU could resume the task, park its next
additive mapping on that custody, and declare terminal idle before the original
handler released it. That handler was missing from the queue's producer count.

The lifecycle now releases custody after preparing original bodies and Views,
before restoring or deferring jobs. The layout-only branch uses the same order.
The existing `completing` counter also covers the complete source lifecycle
handler, including release and accounting. No service thread, polling loop,
global guest-operation lock or ordinary-memory fence was added.

`resumed_mapping_releases_custody_before_cold_accounting` holds the accounting
lock after publication and attempts admission from another thread. It passes
with the fix and fails when the previous release order is restored. This
negative control is retained in `regression-negative.log`; diagnostic printing
was removed from production.

The unchanged original cases passed:

| Execution | Repetitions / cases | Result |
| --- | ---: | --- |
| Interpreter, fresh singleton stores, both network profiles | 100 | All pass |
| Interpreter, five-case batches, five rounds per network profile | 50 | All pass |
| Mac HVF, five-case batches, five rounds | 25 | All pass |
| Native Linux, five-case batches, three rounds | 15 | All pass |

## Socket pressure isolation and inotify budget

The original `socket_stress` suite narrows its namespace's ephemeral port range
to 51 ports. Earlier tests leave TCP TIME_WAIT entries; subsequent persistent
listeners can fail to bind. Three fresh native Linux namespace batches of the
same 30 cases produced 79 passes and 11 failures, including `EADDRINUSE`.
The pinned upstream source also notes listener binding interference between
tests. A shared harness policy now runs `socket_stress` cases in separate fresh
guest stores/processes on both executors and fingerprints that isolation in the
plan. The complete 30-case suite passes on each executor with this policy.

`Inotify.EpollNoDeadlock` creates 1,000 directories/watches before its five-second
epoll workload. A prior passing singleton took 22.603 seconds, exceeding the
initial full-run allowance of about 18 seconds. Its explicit harness allowance
is now 60 seconds; an explicit user suite timeout still takes priority. The
original test and assertions are unchanged. It passed on the interpreter and
twice on Mac using the new case allowance with a 15-second base setting.

## Additional conformance fixture corrections

The complete interpreter checks exposed two unreliable fixture assumptions:

- The host pause test treated three equal samples as acknowledgement. A
  descheduled, still-running CPU can satisfy that heuristic. A test-only epoch
  observer now waits under the queue mutex for host pause plus zero running and
  completing jobs, then requires counters to remain unchanged for the pause
  interval. Original CPU/View identity, resume progress and one-cohort checks
  remain. Five pause tests and 24 concurrent repetitions pass. Twenty-four
  baseline repetitions passed too; these do not establish the baseline failure
  rate. No production pause behavior changed.
- The shared-mm memory observation test used a 100,000-instruction budget with
  up to 12 workers, each allowed to reserve 16,384 instructions. Concurrent
  reservations can stop the fixture before all actors run, even when actual
  retired work is small. The test now waits for real idle completion without a
  finite instruction budget. A sentinel result and an explicit infinite-futex
  state assertion require every actor to complete its observation.

Two existing Domain test constructors were also updated with the required
`membarrier_registered: None` fixture field.

## Validation and ordinary workload timing

- Runtime local CI: all eight workflow stages pass.
- Complete interpreter kernel conformance: **504 pass, 0 fail, 3 ignored**.
- Six lifecycle tests, five pause tests and all 19 harness evidence tests pass.
- iOS ARM64 FFI check and signed Mac build pass. Physical iPad was not run.
- A second audit re-parsed original XML, checked exact case identities and
  process exit status for all 238 passing Trames executions in the table and
  the stress/inotify follow-ups. Native evidence is retained separately.

The signed old/new Mac runners alternated order, with two warm-up pairs and
32 measured pairs. These are workload medians, not a general performance claim.

| Workload | Before (ms) | After (ms) | Change |
| --- | ---: | ---: | ---: |
| Memory | 182.037 | 183.429 | +0.76% |
| mmap, fault, unmap | 149.567 | 149.536 | -0.02% |
| pread, pwrite | 110.103 | 110.373 | +0.25% |
| fork, wait | 21.200 | 21.265 | +0.31% |

## Source and retained evidence

The candidate starts from Runtime `dde38f7bb69f4350cd608ceebdfc90238c5708bc`.
The gVisor revision and static ELFs are unchanged from the full rerun:
`89cacadae21eca4270a8f7c79281d0426d33ac5f`. The signed candidate Mac snapshot's
production session sources match the final worktree after excluding bounded
test fixtures; later fixture corrections did not change the product binaries.
The normalized session source aggregate is
`c285407990c8b95b5aa50e21a66c4990d7be855957aa13d05532df77bff55abf`.

Raw plans, stdout/stderr, original XML, source audit, positive/negative regression
logs, CI logs and performance samples are under
`target/batch-stability-20261123`. `audit.json` records each audited XML checksum.
Native batch results are under
`target/local-ci/io/batch-stability-20261123-native`. Failed and diagnostic runs
remain separate from passing candidate results. Broad unchanged CPU, Linux,
network and graphics acceptance results are reused; another full gVisor run was
not triggered for these scoped corrections.
