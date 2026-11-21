# Task personality, IPC limits and the multiprocess fixture

Trames keeps the Linux personality word per task. Fork and thread creation copy
the calling task’s value. An existing worker accesses the original task’s word,
and a successful exec retains the supported flags of the calling thread.
The ARM64 guest supports legacy low-byte domains except the AArch32 domain,
the inert SHORT_INODE and WHOLE_SECONDS flags, and UNAME26. The latter reports
2.6.60-trames in uname. Other high-bit flags return EINVAL. A regression checks
a nonleader's independent personality across exec and another checks uname
through separate tasks sharing a UTS namespace.

Seven read-only entries under /proc/sys/kernel expose the implemented System V
shared memory, semaphore and message queue limits. They reuse the constants
from the corresponding IPC implementations. The concurrency fixture now
declares multiprocess support to the upstream test binary. This lets the test
actually fork, kill and reap its busy child. The fixture is part of the
saved plan and reuse checks.

## Original upstream tests

On the same 25 cases the previous Mac build recorded 13 passes, 10 failures,
one upstream skip and one missing result. The candidate recorded 24 passes
and the same skip. Seven failures covered personality, three covered IPC limit
queries, and the multiprocess concurrency case previously exited before running
its assertions. On the Mac-hosted iPad interpreter the same 24 passed and one
skipped. The iOS arm64 FFI build passed cargo check.

| Mac hardware suite | Passed | Skipped |
| --- | ---: | ---: |
| concurrency | 3 | 0 |
| personality | 9 | 1 |
| proc_isolated | 3 | 0 |
| proc_pid_coredump | 5 | 0 |
| proc_pid_oomscore | 4 | 0 |
| semaphore | 30 | 0 |
| shm | 26 | 1 |
| msgqueue | 36 | 0 |

The two upstream skips are UnsupportedPersonalityBitsAreRejected (gVisor
only) and ShmStat (skipped for the native platform setting). All 116 passing
Mac results have matching original XML. The macOS shared-runtime workflow
passed all eight steps and the test harness passed its 13 regressions.

The expanded inventory has 3,287 distinct suite/case pairs, including 22 newly
counted cases. On this denominator, passes increased from 3,120 to 3,131,
failures fell from 57 to 47 and missing results fell from one to zero.
Both versions have 88 skips, 20 timeouts and one fixture failure. The inventory
combines stored results with this batch’s reruns.

## Main-path timings

Two series used identical two-core private guest workloads, two warmups per
build per series, and opposite starting orders. The table pools the 32
measured samples per build and reports median milliseconds.

| Workload | Previous | Candidate | Change |
| --- | ---: | ---: | ---: |
| Memory loop | 174.43 | 175.14 | +0.41% |
| Map, fault and unmap | 130.92 | 133.28 | +1.80% |
| File pread/pwrite | 94.81 | 95.15 | +0.36% |
| Fork and wait | 19.20 | 19.14 | -0.30% |

Map/fault/unmap measured +3.63% in the first series and -1.15% with the
starting order reversed. These samples do not establish an enduring slowdown.
The original XML, per-run timings and cumulative inventory are under
`target/gvisor-task-abi-20261121` in the iPad checkout.
