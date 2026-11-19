# Task scheduling and I/O priority on ARM64

The previous runtime (`954bd5f`) and the candidate ran the same original
gVisor binaries at `89cacadae21eca4270a8f7c79281d0426d33ac5f`, with four
guest CPUs on the Mac hardware runner. Each affinity case used its own process.
Each pass was checked against its Google Test XML.

| Suite | Cases | Previous passes | Current passes |
| --- | ---: | ---: | ---: |
| sched | 14 | 6 | 14 |
| priority | 19 | 14 | 19 |
| affinity | 14 | 13 | 14 |
| getcpu | 2 | 2 | 2 |
| getrusage | 5 | 0 | 0 |
| Total | 54 | 35 | 49 |

The [previous inventory](gvisor-poll-20261120.md) contained 49 of these
cases. Twenty previously recorded failures now pass. Fourteen gained passes
in the matched comparison. The old runner already passed the other six
under the new test conditions. Some upstream affinity cases narrow their
own mask and leave it in effect. With the old two-CPU grouped harness,
subsequent cases could start with just one eligible CPU. The batch runner
now isolates this suite even when the other suites run in chunks.

The five newly tracked getrusage cases pass in the saved native ARM64 Linux
reference and fail on both Trames builds. Failures include an unimplemented
getrusage entry and an empty peak RSS returned by wait4. Across 3,003 cases
the inventory has 2,492 passes, 368 failures, 120 skips, 20 timeouts and
three missing results. The remaining 2,949 observations carry forward.

## Guest behavior

The version-zero sched_attr layout supports ordinary, batch and idle policy,
nice, reset-on-fork and a zero-tailed newer userspace structure. Policy and
nice publish together and fork reads a consistent pair. Affinity rejects a
misaligned output size and an unreaped task retains its identity and access
checks. An exited task's scheduling metadata can be inspected without
allocating a CPU slot. Reaping ends this lookup.

I/O priority supports a task, process group or UID in the guest. Individual
queries report the raw setting. Group queries select the best effective
value. An ordinary fork inherits an explicit I/O class. These are guest
attributes. Host disk request ordering, shared CLONE_IO contexts, realtime
CPU scheduling, SCHED_DEADLINE and utilization clamps are outside this
change. The syscall paths operate on the original task.
[Linux I/O priority implementation](https://github.com/torvalds/linux/blob/v6.12/block/ioprio.c)

The iPad interpreter running on the Mac passed all 14 sched and 19 priority
cases and both selected affinity cases (size and remote-UID authorization).
The kernel regression suite passed 500 with three ignored in a serial run.
One structural dispatch assertion failed once during a parallel run; its
individual retry and the serial suite passed. The full runtime workflow ran
on macOS. The ARM64 Linux session and the iOS FFI target were cross-checked.
This batch did not execute native Linux CI or use a physical iPad.

## Main-path timings

Both hardware runner builds used the same guest fixture, two CPUs, external
Vulkan linkage and graphics disabled. Two warmup pairs preceded 16 measured
pairs in alternating order. Median guest time is in milliseconds.

| Workload | Previous | Current | Change |
| --- | ---: | ---: | ---: |
| Ordinary memory | 168.61 | 171.78 | +1.88% |
| Map, fault and unmap | 128.49 | 129.32 | +0.65% |
| 20,000 private-file 4 KiB pwrite/pread pairs | 93.21 | 94.53 | +1.42% |
| 150 fork/wait pairs | 19.89 | 19.84 | −0.23% |

The manifests, raw XML, timing samples and merged case inventory are under
`target/gvisor-sched-20261120` in the iPad checkout.
