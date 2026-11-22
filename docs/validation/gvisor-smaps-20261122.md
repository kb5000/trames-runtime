# Guest mapping statistics on Apple Silicon

The Linux proc filesystem exposes `smaps` and `smaps_rollup` for the original address space opened through a process or task directory. Reading at offset zero samples the current mappings. Subsequent chunks use that sample. A retired address space cannot redirect an open descriptor to the replacement image. File access uses the credential checks for `maps`.

The per-mapping view and rollup use the same accounting. RSS counts resident guest pages. PSS divides each physical page among its resident mappings. Private copy-on-write pages use their address-space ownership. File and shmem pages use their backing object's mapping membership, independently of file handles and execution pins. A private file write can change class before the worker commits. Shared dirty accounting includes both the file's dirty state and writes still in the worker's journal. Ordinary loads and stores keep their existing fast paths.

Sparse anonymous mappings visit reached descriptors and admitted native extents. Sampling needs no guest page fault and allocates no vector proportional to the reserved guest address range. Native residency is observed at the host granule and reported in 4 KiB guest units. The report includes page size, residency, PSS, clean and dirty splits, anonymous bytes, locked bytes, swap and VMA permission flags. Device mappings without a provider for physical sharing or dirty state have no cross-mapping attribution. Linux fields for facilities such as transparent huge pages are outside this batch.

## Compatibility

| Selection | Previous Mac | Updated Mac | Native ARM64 Linux |
| --- | --- | --- | --- |
| Original private anonymous, shared anonymous and shared read-only file cases | 3 failed | 3 passed | 3 passed |
| Full selected set from madvise, mincore, mlock, mremap, proc and proc_pid_smaps | See baseline below | 91 passed, 2 skipped | 91 passed, 2 skipped |

The preceding Mac binary ran 61 cases before implementation, with 57 passes, the three failures and one skip. Each final case was checked against its own GoogleTest XML and against the native reference outcome for the same guest test executable. The two upstream skips are `ProcPidSmapsTest.GvisorFields` and `ProcSelfMaps.Mprotect`. Across the historical inventory the change brings total passes to 13,807 and failures to 45. There are 23 timeouts, 561 skips, one fixture failure and 93 cases without a recorded result.

The Mac-hosted iPad interpreter passed all three affected original cases. A second ARM64 Linux program on each backend reserved 64 MiB and initially measured zero resident bytes for the area. Writing 8 MiB raised the same descriptor's reported RSS by 8,192 KiB. The rollup grew from 440 to 8,632 KiB. Two resident mappings of the same written file page each reported 4 KiB shared dirty and 2 KiB PSS. No physical iPad or installed environment was used.

A runtime regression reserves 256 GiB without allocating page wrappers, checks physical sharing after fork, then verifies the private split after a write and unmap. Another regression reads real file aliases while a worker still holds the mappings. Proc reads, positioned and vectored reads, and io_uring reads complete with zero address-space checkpoints in the interpreter concurrency test. The test's idle peer waits on a dedicated zero futex word. Its previous address overlapped an iovec and could send the peer into a busy loop.

All eight local runtime CI stages and the iOS ARM64 FFI check passed.

## Paired performance

Two guest CPUs ran the same binaries on the Mac after compilation finished. Each selection ran twice in opposite orders. Each run used 34 alternating pairs, with two warm-up pairs excluded. The table pools the 64 measured samples per version. Positive percentages indicate longer elapsed times.

| Workload | Previous median (ms) | Updated median (ms) | Elapsed change |
| --- | ---: | ---: | ---: |
| memory | 168.792 | 168.253 | -0.32% |
| mmap fault unmap | 124.682 | 123.597 | -0.87% |
| file pread pwrite | 96.480 | 96.244 | -0.25% |
| fork wait | 18.267 | 18.250 | -0.09% |
| map unmap shared file | 13.978 | 14.023 | +0.32% |
| read map unmap shared file | 75.416 | 75.625 | +0.28% |
| fork with shared file | 14.686 | 14.760 | +0.50% |

The file-specific workload repeatedly maps and unmaps a 1 MiB shared file, repeats with a read per page, then forks with the file resident. The general workload covers memory, map/fault/unmap, positional file I/O and fork/wait.

Previous Mac executable SHA-256 `bd866e282c4e977398a038a5482bc90e7deca9f880059caef9159a2c26683054`. Candidate `eb2a3132c6b8bb57b7647a309a5c4037feafc67677998460db195cd7776cadf6`.
