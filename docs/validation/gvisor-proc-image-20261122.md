# Process image accounting and cgroup mount roots

## Linux compatibility

The ELF loader retains the main executable's relocated load-segment bounds. The Linux entry stack supplies the original argument and environment spans. Both executors use these values for fields 26–28 and 45–51 of a live task's `/proc/PID/stat`. The ptrace read-credentials check uses the identity of the task reading the descriptor. Reading after a descriptor transfer or a credential change can therefore produce different address fields. [Linux proc stat implementation](https://github.com/torvalds/linux/blob/master/fs/proc/array.c)

`statm` reports the main executable's page-aligned text span. In `status`, `VmExe` caps that span at the current executable VMA total, and `VmLib` reports the rest of that total. The existing lazy calculation over each immutable layout now counts executable mappings alongside stack and data. Reading these counters requires no guest page faults. Per-VMA residency and shared/dirty accounting for `smaps` remain open. [Linux task memory accounting](https://github.com/torvalds/linux/blob/master/fs/proc/task_mmu.c)

Cgroup mount roots in `mountinfo` are relative to the reader's cgroup namespace. The open descriptor retains the observed mount table and process root. Reading from another cgroup namespace changes the reported cgroup root, including for a descriptor that was already open. [Linux cgroup path rendering](https://github.com/torvalds/linux/blob/master/kernel/cgroup/cgroup.c)

## Validation

| Original AArch64 suite | Selected | Mac passed | Skipped |
| --- | ---: | ---: | ---: |
| proc | 56 | 55 | 1 |
| cgroup2 | 13 | 13 | 0 |

All 69 outcomes match the native Linux reference. The upstream platform guard skipped `ProcSelfMaps.Mprotect`. The previous failure `Cgroup2Test.MountInfoRootIsCgroupNamespaceRelative` now passes. The cumulative inventory has 13,656 passes, 129 failures, 24 timeouts, 516 skips and one fixture failure across 14,326 measured cases out of 14,530 discovered.

The iPad interpreter running on Mac passed six original cases, including the cgroup mount regression. A separate static AArch64 guest program checked its argument and environment lengths against their proc files, compared executable sizes across the three stat files, and checked an inherited parent stat descriptor after the child changed UID and GID. Both executors passed. The ARM64 iOS FFI compiled. Physical iPad behavior was not measured. All eight stages of the local macOS runtime CI job passed.

## Performance

The previous runner used runtime `8e8a8a5`. Each series alternated the previous and candidate release runners in the same two-CPU guest and dropped two warmup pairs. Times below are medians in milliseconds across 32 pairs per series. The four task-file workloads each open and read the named file 250 times per sample.

| Workload | Previous | Candidate | Change |
| --- | ---: | ---: | ---: |
| proc_stat | 11.51 | 11.80 | +2.58% |
| proc_statm | 5.80 | 5.80 | +0.00% |
| proc_status | 12.70 | 12.61 | -0.77% |
| proc_mountinfo | 30.13 | 30.11 | -0.06% |
| proc_cpuinfo | 1.70 | 1.73 | +1.75% |
| ordinary_open | 74.90 | 75.00 | +0.14% |
| ordinary_stat | 19.22 | 19.18 | -0.23% |
| memory | 177.66 | 179.88 | +1.25% |
| mmap_fault_unmap | 133.64 | 138.14 | +3.36% |
| file_pread_pwrite | 100.28 | 102.12 | +1.84% |
| fork_wait | 19.52 | 19.65 | +0.66% |
| memory (reversed order) | 178.32 | 176.24 | -1.17% |
| mmap_fault_unmap (reversed order) | 144.94 | 141.75 | -2.20% |
| file_pread_pwrite (reversed order) | 102.41 | 100.87 | -1.50% |
| fork_wait (reversed order) | 20.92 | 20.86 | -0.27% |
