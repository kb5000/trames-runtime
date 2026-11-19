# Execution completion and wait-publication stability — 2026-11-19

This batch fixes the execution queue's complete publication/completion class:
late protocol/timer returns, new runnable work and deadlines, source-backend
failure, and cold CPU registration after completion. Mac and iPad share the
same implementation. It adds no coordinator, service thread, timer polling,
ordinary guest-memory check or per-instruction synchronization.

## Mechanisms and repair

| Boundary | Old failure | Repair |
|---|---|---|
| Protocol/timer callback outside the queue lock | Completion notifies while the worker is outside the lock; returning worker registers a new indefinite sleep or selects work after completion | Recheck admission after reacquiring the original queue lock, before dispatch or sleep |
| Protocol progress error | Phase closes outside the queue lock without waking idle peers | Publish failure and notify under the queue lock |
| New ready task / first deadline | Work is published without waking already idle executors or an indefinite native wait | Notify existing executors and native event interests with the same publication |
| Cold CPU activation | Late activation extends the completion set after joining begins | Serialize registration with the queue's completion boundary; completed admission cannot start another slot |
| CPU/protocol-binding failure | Other executors may remain asleep despite failed admission | Preserve the error and wake the original queue/native waiters |

The existing callback remains outside the queue mutex. Ordinary ready dispatch
keeps its existing path. The new checks run after actual out-of-lock timer or
protocol work; CPU registration locking occurs at cold slot activation. The
active-slot mask remains relaxed atomic bookkeeping under the existing queue
boundary. No whole-session pause or host execution fallback is introduced.

## Fixed-interleaving regressions

The same seven regression bodies/assertions run against unchanged production code at
09ce17b: **0 pass / 7 fail**. Only test-helper visibility and test-module
registration are added to the baseline production file. A later unused import
removal does not change a test body or assertion. Candidate: **7 pass / 0 fail**.

Tests force completion during protocol progress and actual timer delivery,
preserve accepted jobs after completion, introduce ready work and deadlines
while executors sleep, interrupt a native socket wait without socket traffic,
reject late CPU registration, and fail activation while another executor waits.
The protocol matrix covers handoff, cancel, exit, failure, budget and protocol
error, on one, two and the host's twelve available CPU slots. Failed baseline
tests recover their waiting actors after recording the missing completion, so
these regressions fail CI instead of hanging it.

The fast-backend-failure fixture now waits for **actually registered CPU slots**,
not every slot initially planned: failure can correctly close admission before
later slots start. It also rejects duplicate/unregistered returns. Its original
error, unchanged guest state and no-owner-replay assertions remain intact.
Neither of the two originally hanging tests is instrumented, skipped or relaxed.

## Concentrated acceptance

- Six complete interpreter runs alternate serial and four-way libtest execution:
  **498 pass / 3 existing manual-benchmark ignores / 0 filtered**, every run.
- Each original raw-IP and complete-socket-control test passes **30/30** fresh
  process repetitions. Additional isolated io_uring runs pass **20/20**.
- All **6194 original gVisor cases** from the preceding checkpoint are rerun:
  **5920 pass / 271 skip / 3 fail / 0 timeout**, identical outcomes, zero old-pass
  regressions. The prior network gaps remain explicit rather than counted as
  repaired by this scheduler batch.
- Both complete shared-runtime workflows pass **8/8** on macOS and ARM64 Linux.
  Linux retains the established 8 MiB test-harness stack; production stacks are
  unchanged. Interpreter Clippy passes with warnings denied. FFI passes **24/24**
  and the iOS ARM64 core compiles. The physical iPad is not contacted.

### Nonpassing validation attempts retained

An early repetition exposes the planned-versus-started CPU-count assumption
above. After correcting that fixture, a 40-second **whole-suite** allowance
expires during overlapping validation, with the last prefix naming an io_uring
test. There is no captured stack proving that individual test hung; the timeout
is retained and is not promoted to a pass or claimed as a diagnosed io_uring
bug. Subsequent isolated io_uring runs and all six complete serial/concurrent
runs pass. Finite stress runs are evidence for these repairs, not a guarantee
that every possible scheduler race is absent.

## Performance guard

The frozen 09ce17b Dev bundle and candidate execute the same static ARM64
`tests/fixtures/event-waits.c`, compiled at -O2 with pthread support. No CI,
conformance workers or disposable Linux VM run during measurement. Existing
installed Dev/Stable environments continue running; there is no exclusive CPU
reservation. Each pair rotates before/after order.

The first matrix measures pselect6, ppoll, epoll_pwait and epoll_pwait2, with and
without a signal mask, on 1/2/12 CPUs: **24 scenarios, five paired samples,
1000 iterations**. Median change across the eight scenarios at each width:

| CPUs | Median candidate time change |
|---|---:|
| 1 | -0.02% |
| 2 | +1.23% |
| 12 | +0.71% |

The largest short-run shifts are checked with **15 paired samples and 10,000
iterations** of epoll_pwait, both mask modes, on 1/2/12 CPUs:

| CPUs | Signal mask | Baseline ms | Candidate ms | Change | Paired p10 / p90 |
|---|---|---:|---:|---:|---:|
| 1 | no | 36.342 | 36.218 | -0.34% | -5.56% / +0.70% |
| 2 | no | 44.995 | 43.463 | -3.41% | -6.35% / +4.32% |
| 12 | no | 272.669 | 271.382 | -0.47% | -10.43% / +9.47% |
| 1 | yes | 35.900 | 35.663 | -0.66% | -2.19% / +1.11% |
| 2 | yes | 45.579 | 45.983 | +0.89% | -7.33% / +6.91% |
| 12 | yes | 264.789 | 268.949 | +1.57% | -5.24% / +5.49% |

Positive changes mean more time. Follow-up medians span -3.41% to +1.57%; every
paired p10/p90 interval includes zero. These samples show no clear sustained
slowdown, and do not establish zero overhead or cover every blocking network
workload. Native macOS pselect is measured with the same source; its results
are retained in JSON. Other Linux wait APIs have no corresponding native
Darwin implementation and are not assigned a substituted native score.

Native macOS pselect reference for the first 1000-iteration matrix (longest
worker loop, medians in milliseconds; reference measurements, not a claim of
identical backend costs or a cross-platform speedup):

| CPUs | Signal mask | Native macOS | Trames baseline | Trames candidate |
|---|---|---:|---:|---:|
| 1 | no | 1.365 | 3.864 | 3.818 |
| 2 | no | 2.075 | 4.804 | 4.869 |
| 12 | no | 27.827 | 30.365 | 30.709 |
| 1 | yes | 0.578 | 3.803 | 3.573 |
| 2 | yes | 1.386 | 4.827 | 4.917 |
| 12 | yes | 28.193 | 30.706 | 30.555 |

[Machine-readable evidence](executor-completion-stability-20261119.json) records
all samples, exact source/binary identities, baseline failures, stress outcomes
and full-gVisor comparison. Raw evidence lives in ignored
`target/executor-stability-20261119`; large completed logs are losslessly gzip
compressed with verified original SHA-256 values. Installed applications and
existing environments are not replaced or restarted by this validation.
