# Process descriptors and child waits

Mac and iPad share process-level pidfd_open, CLONE_PIDFD with clone and clone3, pidfd_send_signal, waitid(P_PIDFD), poll and epoll. A process descriptor tracks the original child's exit and final reap. Its open description can survive close in another thread. An accepted wait keeps the target across descriptor reuse and preserves the original guest arguments for signal restart. Each clone reserves the parent descriptor after copying Files and publishes it after admitting the child. A failed output copy releases the reservation. Ordinary children allocate the pidfd object only on request. The signal path uses the existing guest sender permissions and signal queues. The expected process-level behavior is described in the [Linux pidfd_open manual](https://man7.org/linux/man-pages/man2/pidfd_open.2.html).

## Upstream results

Baseline runtime 15235e0. The Mac hardware executor ran 177 distinct upstream ARM64 cases with a fresh store per case. After auditing the fixture and rerunning the long vfork case, the results were 161 passes, nine failures, six skips and one fixture failure.

| Cases | Passed | Failed | Skipped | Fixture failed |
| --- | ---: | ---: | ---: | ---: |
| pidfd, 32 selected of 34 | 17 | 9 | 6 | 0 |
| fork, vfork, wait, epoll, poll and rtsignal | 144 | 0 | 0 | 1 |

All 17 pidfd passes had previously failed. The thread descriptor feature probe now reaches its unsupported-feature skip. The nine remaining failures exercise pidfd_getfd or setns via a pidfd. The invalid-setns-flags case passes but does not establish support for switching namespaces through a pidfd. The two race cases retain their earlier timeout and skip and were not rerun. The iPad interpreter on the Mac passed all 17 newly passing cases. The ARM64 iOS FFI check passed. Physical iPad behavior was not measured.

WaitTest.TraceeWALL still reports ENOSYS in the child's ptrace setup even though the parent XML passes. Single-case execution and saved-result auditing now apply the same fixture check as chunked execution. VforkTest.ParentStopsUntilChildExecves has two deliberate waits. It completed in 20.17 seconds with a 40-second per-case deadline. The original 18-second attempt is retained in the evidence.

The cumulative inventory combines the 177 reruns with prior results. Of 3,163 cases, 2,883 passed, 134 failed, 119 skipped, 25 timed out, one has no result and one failed in fixture setup.

## Main-path measurements

Each run alternated the old and new Mac binaries, with 16 measured samples per binary after two warmups. The median columns pool the two runs, giving 32 samples per binary. A positive difference means more elapsed time.

| Workload | Old median (ms) | New median (ms) | Difference | Run 1 | Run 2 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Memory access | 175.32 | 175.30 | −0.01% | +0.04% | +0.61% |
| Map, fault and unmap | 134.33 | 132.62 | −1.28% | −0.06% | −0.82% |
| Private file pread/pwrite | 95.15 | 95.98 | +0.87% | −0.10% | +2.03% |
| Fork and wait | 19.40 | 19.45 | +0.26% | +1.84% | −2.20% |

Local raw XML, stderr, normalized rows, cumulative inventory and paired timing samples are in target/gvisor-pidfd-20261120 in the iPad worktree. The runtime CI passed all eight steps and the gVisor harness passed 12 tests.
