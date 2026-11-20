# Clock sleeps, signals and timer delivery on ARM64

The signed Mac runner reran 254 distinct original cases across 18 suites against gVisor revision `89cacadae21eca4270a8f7c79281d0426d33ac5f`. The runtime comparison was local revision `e41bc3ef84bce85ee89d93ef71fe989e53bec77b`. The final selection had 235 passes with matching GoogleTest XML, 16 skips, two assertion failures and one fixture failure.

| Previously failing or timing out | Result | Evidence |
| --- | --- | --- |
| Process CPU clock sleep | Passed | A sibling accumulated five CPU seconds. The idle caller slept until the process clock reached the deadline. |
| Relative boottime sleep | Passed | The original two-second test completed on both execution backends. The timer uses the host continuous clock. Physical host suspend was not exercised. |
| Stop and resume | Passed | The original test waits five seconds and then twenty more. Both old and new runners passed with a sufficient watchdog. |
| Signal delivery to a starting task via pidfd | Passed on retest | Eight further repetitions passed on each binary. The earlier timeout remains unexplained. |

The two SIGPROF fairness tests exceeded the initial 25-second watchdog. Isolated runs took 40.017 and 86.184 seconds. Each upstream worker accrues 20 CPU seconds, and the idle case sleeps between turns. The harness now accounts for these waits and the deliberate SIGSTOP interval per case.

The four original cases in the table also passed on the iPad interpreter running on the Mac. The interpreter conformance suite passed 502 tests with three ignored. The ARM64 iOS FFI compiled. A separate freestanding ARM64 guest verified nested floating-point signal state, interruption of an idle process-clock sleeper with its remaining CPU time, and boottime completion with an unused remainder pointer on both execution backends.

The original nested floating-point assertion still failed on native ARM64 Linux and on both Mac runner revisions. Its pinned ARM64 test macro declares its assembly memory source as an output. The kill restart test and the wait fixture require ptrace operations. All three remain recorded with their observed outcomes.

## Inventory

The previous 3,240-case cohort now has 3,061 passes, 75 failures, 82 skips, 20 timeouts, one fixture failure and one missing result. The additional seccomp and vDSO suites contributed 21 passes and four skips, yielding 3,265 cases and 3,082 passes in the expanded inventory. Cases outside the selected suites retain their previous evidence.

## Performance

The same Mac alternated the old and new release runners in both orders, with two warm-up pairs and 16 measured pairs. Median elapsed-time changes were getuid +0.03%, stat +1.28%, open +1.30%, memory +0.44%, mmap/fault/unmap −0.40%, pread/pwrite +0.24% and fork/wait +2.20%. These measurements cover the individual workloads. They do not establish end-to-end application performance.
