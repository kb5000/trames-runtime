# Clone exit notifications and child selection on ARM64

The comparison used runtime `2897047` as the baseline, two guest CPUs, fresh
stores and the original gVisor binaries from
`89cacadae21eca4270a8f7c79281d0426d33ac5f`. Both builds used the same
isolation rules. The audit matched every passing case to its Google Test XML.

| Suite | Cases | Previous passes | Current passes |
| --- | ---: | ---: | ---: |
| wait | 64 | 53 | 63 |
| fork | 24 | 24 | 24 |
| vfork | 4 | 4 | 4 |
| fpsig_fork | 1 | 1 | 1 |
| getrusage | 5 | 5 | 5 |
| sigtimedwait | 11 | 11 | 11 |
| Total | 109 | 98 | 108 |

Nine failures and one skip became passes. Both builds still return ENOSYS for
the child's PTRACE_TRACEME setup in WaitTest.TraceeWALL. The upstream parent
accepts ECHILD on its Linux path, so its XML can report success after the child
aborts. Running the case in its own process protects later wait(-1) tests
from collecting that zombie. The harness retains the child assertion as
`fixture_failed`, together with the original stderr and XML.

The [previous inventory](gvisor-resource-usage-20261120.md) covered 3,003 cases.
With 109 refreshed there are 2,514 passes, 348 failures, one fixture failure,
119 skips, 18 timeouts and three missing results. A previously timed-out vfork
case passed on both builds in this run. Results for 2,894 cases carry forward.

## Guest behavior

Wait4 and waitid share the same child selection at entry, wakeup and collection.
The clone exit signal determines the wait class. A zero signal wakes waiters
silently. A nonzero signal reaches the parent through the existing process
signal path. The accepted process exit signals range from zero through 64. SIGCHLD retains the parent's disposition and automatic-reaping
semantics. CLONE_PARENT inherits the original parent's relationship.
Successful exec in the child restores SIGCHLD. A change of image in the
parent substitutes SIGCHLD for the delivered notification while preserving
the child's wait class. [Linux wait selection](https://github.com/torvalds/linux/blob/v6.12/kernel/exit.c)
and [parent notification](https://github.com/torvalds/linux/blob/v6.12/kernel/signal.c).

Thread-specific waits compare the caller with the current parent thread.
Retirement and exec rekeying transfer ownership of outstanding children,
including zombies, within the parent's existing resources. Adoption by
another process resets the wait class. Ordinary wait calls take the existing
parent/child locks. Sibling handoff can scan that parent's child list.

The [guest regression](../../tests/fixtures/clone-wait.c) checked clone3,
delivery of a nonstandard exit signal, ignored SIGCHLD, child and parent exec,
CLONE_PARENT inheritance, an exited thread's unreaped child and adoption by a
subreaper. It passed on Mac hardware and on the iPad interpreter running on the
Mac. The interpreter also passed 16 original wait cases. Kernel conformance
passed 500 with three ignored. The macOS runtime CI passed all eight steps.
The iOS FFI and Linux ARM64 session targets passed cross-target compilation checks. Physical iPad
execution and native Linux CI remain unverified for this change.

## Main-path timing

Two independent runs each used two warmup pairs and 16 measured pairs,
alternating baseline and candidate order. Values below are median guest
milliseconds across all 32 measured samples per build. Graphics was disabled.

| Workload | Previous | Current | Time change |
| --- | ---: | ---: | ---: |
| Ordinary memory | 170.42 | 169.33 | -0.64% |
| Map, fault and unmap | 130.22 | 127.99 | -1.71% |
| 20,000 private-file 4 KiB pwrite/pread pairs | 93.55 | 93.88 | +0.35% |
| 150 fork/wait pairs | 19.72 | 19.37 | -1.75% |

The first implementation increased fork/wait time by 2.78% and 2.33%.
The integrated version binds the wait identity and task presence under one
lock at birth, compares the existing parent identity directly and reads child
credentials only for waitid calls returning siginfo. Its two fork/wait
medians were -1.83% and -1.23% relative to baseline.
Raw XML, isolated stderr, rolling results and all samples are under
`target/gvisor-clone-wait-20261120` in the iPad checkout.
