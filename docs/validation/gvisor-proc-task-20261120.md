# Procfs thread directories, names and status on ARM64

On 2026-11-20 the complete 160-case gVisor proc suite passed 119 cases on
the Mac hardware executor, up from 95 on runtime `169e23c`. Twenty-two
previous failures and both timeouts now pass. The other 136 classifications
match. The same executable, rootfs and settings were used for both builds.

| Run | Pass | Fail | Skip | Timeout |
| --- | ---: | ---: | ---: | ---: |
| Previous Mac, full proc | 95 | 61 | 2 | 2 |
| Updated Mac, full proc | 119 | 39 | 2 | 0 |
| Updated Mac, 25 thread-related cases in separate processes | 24 | 1 | 0 | 0 |
| ARM64 interpreter, same 25 cases | 24 | 1 | 0 | 0 |

Both executors still fail `ProcTask.VerifyTaskDir`, which requires the
per-task `io` accounting file. Each Mac pass was verified against the original
GoogleTest XML. Across the rolling 3,163-case inventory there are now 2,724
passes, 305 failures, 121 skips, ten timeouts, two missing results and one
fixture failure. Only the 160 proc cases were rerun in this round.

## Changes exercised by the tests

- Directory reads of `/proc/PID/task` enumerate a snapshot of the original
  thread group, bind each entry to its own PID object, and omit members that
  disappear before their metadata can be read. The same group supplies the
  directory link count. PID, TID and FD entries require canonical decimal names.
- A thread's `children` file reads the existing wait queue, selects children of
  that thread, and translates their IDs into the proc mount's PID namespace.
- Reads and writes of `comm` use the same original task name as prctl. Write
  authority is checked against the writer's thread group even through an
  inherited descriptor. A separate interpreter probe verified the 15-byte
  truncation, unchanged read offset after a write, and rejection of a write
  in the forked child. See the [Linux procfs task-name implementation](https://github.com/torvalds/linux/blob/v6.12/fs/proc/base.c#L1615-L1639).
- Immutable task directories return the appropriate errors for access, open,
  rename and removal. The status file reports the state code and description.
  Several upstream tests wait for a state such as sleeping before checking
  another file. Their passes reflect that the prerequisite and subsequent
  assertions both succeeded.

## Normal-path performance

The same Mac ran two warmups and 16 measured samples per version, alternating
the execution order. Figures are median guest elapsed milliseconds.

| Workload | Previous | Updated | Change |
| --- | ---: | ---: | ---: |
| Ordinary memory | 170.877 | 171.569 | +0.41% |
| Map, fault and unmap | 128.586 | 130.233 | +1.28% |
| Private file pread/pwrite | 93.383 | 93.360 | -0.03% |
| Fork and wait | 18.964 | 19.023 | +0.31% |

Shared runtime CI passed all eight steps. Interpreter kernel conformance
passed 500 cases with three ignored. The iOS FFI and ARM64 Linux musl session
targets compiled. Evidence and individual timings are in
`target/gvisor-proc-task-20261120` in the iPad checkout.
