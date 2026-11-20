# Sparse memfd offsets on ARM64

Owned shared files now accept logical lengths through INT64_MAX on 64-bit hosts. Extending an empty memfd to this length charges zero guest blocks. Linux specifies ordinary file truncation and mapping operations on memfds. [memfd_create(2)](https://man7.org/linux/man-pages/man2/memfd_create.2.html) and [ftruncate(2)](https://man7.org/linux/man-pages/man2/ftruncate.2.html).

## Storage and descriptor behavior

The first 1 TiB uses the existing host descriptor. Reads from absent higher windows return zero. Writes and mappings create sparse unlinked backing files on demand. A mapping across a window boundary maps both files into adjacent addresses in a private reservation. Shrinking clears the truncated extent, including bytes visible through retained mappings. Physical backing and Trames working-set charges may outlive a shrink while the shared inode is retained.

Trames descriptor transfers preserve the full segmented file by recovering its owner from the transferred inode identity. A standalone native descriptor export via `duplicate_fd` returns EOVERFLOW when the owned logical file exceeds one window. A single raw host descriptor represents the primary backing only. Imported external files continue using their own descriptor.

Quota accounting tracks contiguous ranges of touched pages. A guest can request a huge reservation without an enumeration of all its logical pages. A write crossing a backing boundary can return the completed prefix when the next window exceeds quota. The published length follows that prefix.

## Compatibility and scope

The Mac hardware executor reran all 202 selected upstream cases across memfd, fallocate, truncate, pread64, pwrite64, mmap and madvise. Original XML confirms 201 passes and one skip. Pread64Test.Overflow changed from failing at ftruncate to passing the entire test. MemfdTest.TmpfsFilesHaveSealSeal previously skipped because the test directory was on the guest root filesystem. Moving it to tmpfs exposed EINVAL on F_GET_SEALS. Named tmpfs regular files now report F_SEAL_SEAL, reject further sealing with EPERM, and remain writable across unlink. The seal query uses the open file's retained mount.

The harness mounts a private tmpfs as the memfd suite's working directory on native Linux and Trames. Reference and candidate both executed all 21 memfd cases successfully. Results from the old fixture cannot satisfy the new plan's cache key. Original XML stays on the test store for collection. AllocateTest.FallocateKeepSize still skips on the default test filesystem. It passed separately on tmpfs on both Trames executors.

The cumulative 3,240-case inventory contains 3,019 passes, 112 failures, 82 skips, 25 timeouts, one fixture failure and one missing result. Other suites retain their previous evidence.

The Mac-hosted iPad interpreter passed the overflow case, all 21 memfd cases and the tmpfs keep-size allocation test. An independent ARM64 guest program verified a zero initial block count after maximum-size extension, tail reads and writes, shared mmap coherence across the 1 TiB boundary, and zeroes after shrink and regrowth on both executors. The iPad FFI compiled for aarch64-apple-ios. Physical iPad execution was outside this batch.

## Performance

Both Mac runners used the same guest environment for each workload with alternating run order. The table uses median guest elapsed milliseconds from 16 measured pairs after two warmup pairs. Each memfd workload performed 20,000 operations of 4 KiB on a prepopulated 1 MiB file.

| Workload | Before (ms) | After (ms) | Elapsed time change |
| --- | ---: | ---: | ---: |
| memfd_hot_pwrite_4k | 45.04 | 45.96 | +2.05% |
| memfd_hot_pread_4k | 34.64 | 35.21 | +1.65% |
| memory | 174.17 | 175.05 | +0.51% |
| mmap_fault_unmap | 132.57 | 132.96 | +0.29% |
| file_pread_pwrite | 94.39 | 95.10 | +0.76% |
| fork_wait | 19.32 | 19.07 | -1.30% |
| getuid | 102.54 | 103.42 | +0.85% |
| ordinary_stat | 18.97 | 19.13 | +0.85% |
| ordinary_open | 72.71 | 73.69 | +1.35% |

A separate 32-pair repeat of the two memfd workloads measured −0.76% for writes and +0.40% for reads. Local XML, independent guest probes and timing samples are under `target/gvisor-sparse-shm-20261120` in the iPad worktree. The native Linux reference XML is under `target/local-ci/io/gvisor-sparse-memfd-native-20261120`.
