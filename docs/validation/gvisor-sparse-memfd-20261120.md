# Sparse memfd offsets on ARM64

Owned shared files now accept logical lengths through INT64_MAX on 64-bit hosts. Extending an empty memfd to this length charges zero guest blocks. Linux specifies ordinary file truncation and mapping operations on memfds. [memfd_create(2)](https://man7.org/linux/man-pages/man2/memfd_create.2.html) and [ftruncate(2)](https://man7.org/linux/man-pages/man2/ftruncate.2.html).

## Storage and descriptor behavior

The first 1 TiB uses the existing host descriptor. Reads from absent higher windows return zero. Writes and mappings create sparse unlinked backing files on demand. A mapping across a window boundary maps both files into adjacent addresses in a private reservation. Shrinking clears the truncated extent, including bytes visible through retained mappings. Physical backing and Trames working-set charges may outlive a shrink while the shared inode is retained.

Trames descriptor transfers preserve the full segmented file by recovering its owner from the transferred inode identity. A standalone native descriptor export via `duplicate_fd` returns EOVERFLOW when the owned logical file exceeds one window. A single raw host descriptor represents the primary backing only. Imported external files continue using their own descriptor.

Quota accounting tracks contiguous ranges of touched pages. A guest can request a huge reservation without an enumeration of all its logical pages. A write crossing a backing boundary can return the completed prefix when the next window exceeds quota. The published length follows that prefix.

## Compatibility and scope

Mac hardware execution reran all 202 selected upstream cases across memfd, fallocate, truncate, pread64, pwrite64, mmap and madvise. Original XML confirms 200 passes and two skips. Pread64Test.Overflow changed from failing at ftruncate to passing the complete test. Every other selected case retained its previous classification. The cumulative 3,240-case inventory contains 3,018 passes, 112 failures, 83 skips, 25 timeouts, one fixture failure and one missing result.

The Mac-hosted iPad interpreter ran the overflow case and the 21-case memfd suite. Original XML confirms 21 passes and one upstream skip because the test directory is on a different filesystem than tmpfs. An independent ARM64 guest program verified a zero initial block count after maximum-size extension, tail reads and writes, shared mmap coherence across the 1 TiB boundary, and zeroes after shrinking and regrowing the file on both executors. The iPad FFI compiled for aarch64-apple-ios. Physical iPad execution was outside this batch.

## Performance

Both Mac runners used the same guest environment for each workload with alternating run order. The table uses median guest elapsed milliseconds from 16 measured pairs after two warmup pairs. Each memfd workload performed 20,000 operations of 4 KiB on a prepopulated 1 MiB file.

| Workload | Before (ms) | After (ms) | Elapsed time change |
| --- | ---: | ---: | ---: |
| memfd_hot_pwrite_4k | 44.01 | 43.97 | -0.09% |
| memfd_hot_pread_4k | 34.39 | 34.27 | -0.34% |
| memory | 177.01 | 175.44 | -0.89% |
| mmap_fault_unmap | 133.81 | 131.90 | -1.43% |
| file_pread_pwrite | 94.47 | 93.94 | -0.57% |
| fork_wait | 19.37 | 19.53 | +0.83% |
| getuid | 103.51 | 103.60 | +0.09% |
| ordinary_stat | 19.09 | 18.97 | -0.62% |
| ordinary_open | 73.71 | 73.76 | +0.07% |

Local XML, independent guest probes and timing samples are under `target/gvisor-sparse-shm-20261120` in the iPad worktree.
