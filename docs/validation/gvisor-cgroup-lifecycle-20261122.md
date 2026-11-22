# Cgroup delegation and task lifecycle

The baseline is shared runtime `8c346db`. A delegated user can create and remove child cgroups under a writable, searchable parent. Child directories and initial controls use the creating task’s filesystem UID and GID. Enabling the pids controller through a writable subtree-control descriptor creates its files with the writer’s ownership. Existing namespace restrictions still apply.

Exit removes the task from live membership and population counts. Until reap, its proc entry reports the original group and adds ` (deleted)` after removal. A replacement group with the same path has a different inode. Writes to `cgroup.procs` resolve an unreaped target through the existing task directory on a live-member miss, check the original ancestry and acknowledge the write without moving the dead task.

Both executors allow a frozen process to exit on an unblocked default-fatal signal such as SIGTERM. Signals with a handler and signals whose default action dumps core remain deferred while frozen. SIGKILL retains priority. The queue checks dispositions only when a signal is pending.

## Validation

The signed Mac guest ran all 87 original AArch64 cgroup2 cases individually. Four cases now pass and the other 83 retained their classifications.

| Upstream case | Previous | Current |
| --- | --- | --- |
| DelegatedCgroupOwnership | Failed | Passed |
| ZombieCgroupMembership | Failed | Passed |
| FrozenProcessWakesAndDiesOnDefaultFatalSignal | Timed out | Passed |
| FrozenProcessDefersCoreDumpSignalUntilThaw | Failed | Passed |

The suite finished with 69 passes, 3 failures and 15 skips. The outstanding failures cover `memory.current`, hierarchical memory charging and a v1 mount requesting a controller active in v2. Another 99 original cases across exit, kill, signal masks, stop, tgkill and wait retained their previous outcomes, including the existing restart-argument failure and tracee fixture failure.

The cumulative inventory contains 13,660 passes, 126 failures, 23 timeouts, 516 skips and one fixture failure among 14,326 measured cases. Discovery listed 14,530. Counts reuse earlier evidence for cases outside this run.

The iPad CPU interpreter hosted on Mac passed six original cases, including the four fixes, SIGKILL while frozen and nonfatal signal deferral. The ARM64 iOS FFI compiled. Physical iPad performance was not measured. All eight stages of the local runtime CI passed, including 1,884 tests.

## Performance

The release runners alternated in a two-CPU Mac guest. Each workload had two warmup pairs and 32 measured pairs. Values are median guest elapsed times in milliseconds.

| Workload | Previous | Current | Change |
| --- | ---: | ---: | ---: |
| memory | 173.37 | 175.31 | +1.12% |
| mmap_fault_unmap | 134.91 | 132.23 | -1.99% |
| file_pread_pwrite | 99.61 | 99.76 | +0.15% |
| fork_wait | 19.60 | 19.62 | +0.12% |
| proc_cpuinfo | 1.73 | 1.73 | +0.14% |
| ordinary_open | 75.26 | 75.12 | -0.18% |
| ordinary_stat | 19.13 | 19.29 | +0.83% |
