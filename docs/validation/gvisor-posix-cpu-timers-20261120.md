# POSIX process and thread CPU timers on ARM64

Both backends implement timer_create, timer_settime, timer_gettime, timer_getoverrun and timer_delete for CLOCK_PROCESS_CPUTIME_ID and CLOCK_THREAD_CPUTIME_ID. The clock follows the original process or thread even when a different thread in the group arms or reads the timer. A signal timer with an absolute deadline in the past expires during settime. Periodic timers preserve their phase across a late CPU accounting update.

Existing executors check the original owner's deadline index when they charge guest CPU time. A task with no signal timer has no CPU timer queue to lock. SIGEV_NONE computes remaining time on demand and installs no queue. Clock registrations use weak identities. Exec and deletion remove scheduled entries. These changes cover the two standard POSIX CPU clock IDs. CPU-clock nanosleep and dynamically encoded clock IDs for timer_create are outside this batch. [Linux POSIX CPU timers](https://github.com/torvalds/linux/blob/master/kernel/time/posix-cpu-timers.c)

## Verification

| Suite | Mac hardware execution | Mac-hosted iPad interpreter |
| --- | ---: | ---: |
| timers | 15/15 | 15/15 |
| itimer | 4/4 | 3/4 after checking child diagnostics |

IntervalTimerTest.NegativeInterval previously failed at timer creation. It now reaches the negative interval check. Updating only the 19 Mac results in the cumulative 3,240-case inventory yields 3,030 passed, 101 failed, 82 skipped, 25 timeouts, one fixture failure and one missing result.

On the interpreter, the ITIMER_REAL signal distribution test reported success in XML even though its child failed the worker share limit twice. The pinned upstream parent accepts a child killed by a signal because its exit-status expression evaluates to zero. The harness now marks this specific child's assertion as a failure in individual, chunked and archived results. A clean interpreter rebuilt from the previous runtime b30806c also reproduced the child failure. The Mac run met the test's threshold. Interpreter figures above incorporate the child's actual result.

A guest probe on both backends installed one-shot timers on both CPU clocks, slept for 100 ms with a 30 ms CPU deadline, then consumed CPU and received SIGALRM. It verified that each timer disarmed. Runtime tests cover cross-thread setting and reading, per-group and per-thread charging, overruns, immediate absolute expiry, silent periodic timers and dead owners. The iOS device-target FFI compiled. The interpreter ran on the Mac.

## Performance

Median guest elapsed milliseconds against b30806c on the same Mac. Runs alternated old and new executors with two warmup pairs per series. The first four rows pool two independent series of 16 measured pairs each. The last three use 16 measured pairs. In the first series mmap/fault/unmap took 3.15% longer and in the second it took 2.65% less time.

| Workload | Before (ms) | After (ms) | Change |
| --- | ---: | ---: | ---: |
| memory | 175.94 | 175.75 | -0.11% |
| mmap_fault_unmap | 130.97 | 131.82 | +0.65% |
| file_pread_pwrite | 94.58 | 94.33 | -0.26% |
| fork_wait | 19.15 | 19.18 | +0.15% |
| getuid | 102.68 | 102.74 | +0.06% |
| ordinary_stat | 19.00 | 18.86 | -0.73% |
| ordinary_open | 73.18 | 73.70 | +0.71% |

Raw XML, child logs, comparison samples and the updated inventory are in the iPad worktree under `target/gvisor-cpu-timers-20261120`.
