# Process resource usage and child collection on ARM64

The Mac hardware runner used the same two guest CPUs, fresh stores and
unmodified gVisor binaries before and after the changes. The baseline runtime
was `bf33072` and gVisor was `89cacadae21eca4270a8f7c79281d0426d33ac5f`.
The harness matched each pass to its original Google Test XML.

| Suite | Cases | Previous passes | Current passes |
| --- | ---: | ---: | ---: |
| getrusage | 5 | 0 | 5 |
| wait | 64 | 47 | 54 |
| mmap | 118 | 118 | 118 |
| madvise | 18 | 18 | 18 |
| mlock | 20 | 20 | 20 |
| mincore | 5 | 5 | 5 |
| Total | 230 | 208 | 220 |

Eleven failures and one timeout became passes. A waitid caller requesting
only stop events now gets ECHILD when its only child has already exited.
That child can still be collected by a subsequent WEXITED wait. Nine wait
failures and one skip remain in clone exit-signal and per-thread wait selection.
The [rolling inventory](gvisor-scheduling-20261120.md) contains 2,504 passes,
357 failures, 120 skips, 19 timeouts and three missing results across 3,003
cases. Observations for 2,773 other cases carry forward.

## Accounting behavior

getrusage, times, wait4 and waitid use the original guest task's execution
clock. Collection adds child and collected descendant CPU time exactly once
and keeps the maximum resident peak. A zombie, WNOWAIT observation or
automatic SIGCHLD reaping leaves the parent's collected totals unchanged.
An ordinary exec preserves the process peak across the image replacement.
CPU time is attributed to user time. The runtime does not yet separate system
CPU time or account for every Linux rusage counter, including block I/O and
context switches.
[Linux child collection](https://codebrowser.dev/linux/linux/kernel/exit.c.html)

Guest-accounted pages retain a high-water mark at release. Native extents use
host-reported residency at observation and retirement, so short-lived hardware
residency changes between samples can escape measurement. The current image's
peak appears in /proc/self/status as VmHWM. MAP_POPULATE requests a best-effort
prefault, and MAP_NONBLOCK suppresses it. Ordinary mappings remain demand-paged.
Execution threads handle these calls directly.

The [guest regression](../../tests/fixtures/resource-usage.c) checked an
8 MiB write-only mapping after unmap, an untouched nonblocking mapping,
thread usage, errno, elapsed and child CPU ticks, repeated WNOWAIT observation
and final collection. It passed on both backends. The iPad interpreter on the
Mac also passed all five getrusage cases and eight relevant wait cases.
The full interpreter kernel suite passed 500 with three ignored. One
thread-registration assertion failed once and passed in an individual retry
and a full repeat. The runtime workflow ran on macOS and the iOS FFI and Linux
ARM64 session targets were cross-checked. Physical iPad execution and native
Linux CI were outside this run.

## Main-path timing

Both builds used external Vulkan linkage with graphics disabled and the same
two-CPU guest. Two warmup pairs preceded 16 measured pairs in alternating
order. Values are median guest times in milliseconds.

| Workload | Previous | Current | Time change |
| --- | ---: | ---: | ---: |
| Ordinary memory | 172.41 | 170.36 | −1.19% |
| Map, fault and unmap | 132.10 | 128.61 | −2.64% |
| 20,000 private-file 4 KiB pwrite/pread pairs | 93.93 | 95.58 | +1.76% |
| 150 fork/wait pairs | 19.94 | 20.20 | +1.32% |

Original XML, matched results, the rolling inventory and timing samples are
under `target/gvisor-rusage-20261120` in the iPad checkout.
