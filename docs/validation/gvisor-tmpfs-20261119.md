# Sparse tmpfs allocation and mapped faults

The Mac ARM64 runner executed 482 original cases in ten gVisor suites against
disposable guest stores. The reference uses upstream revision
`89cacadae21eca4270a8f7c79281d0426d33ac5f`. The previous runtime was
`29a3ae0133b5dc6a7221dd3c9fee9b51be7ea7ca`.

| Selection | Cases | Previous passes | Passes | Failures | Skips |
| --- | ---: | ---: | ---: | ---: | ---: |
| tmpfs cases in the mount suite | 16 | 7 | 16 | 0 | 0 |
| Remaining mount cases, overlay, truncate, fallocate, memfd, mmap, link, symlink, stat and lseek | 466 | 390 | 390 | 41 | 35 |
| Total | 482 | 397 | 406 | 41 | 35 |

Eight assertion failures and one missing result became verified passes. In
TmpfsSizeMmap, ftruncate now extends a file to two pages on a one-page mount.
Reading the first mapped page succeeds. Touching the second signals SIGBUS in
the test child and the parent completes the case. All 406 passes have matching
original XML. The final sparse overlay copy was also checked against the full
mount and overlay suites (191 cases).

The [previous inventory](gvisor-rename-20261119.md) plus this batch gives
2,415 passes, 436 failures, 120 skips, 24 timeouts and three missing results.
The 2,516 cases outside this selection retain their earlier observations.

## Semantics

A tmpfs inode separates logical length, allocated guest pages and resident byte
buffers. Extents account for allocated 4 KiB pages under the mount's quota.
Ordinary reads of holes return zeros. Writes may complete up to the first
unavailable page. Allocation requests reserve the complete range or fail.
Truncation releases whole pages and zeroes the retained page tail. Open file
descriptors, hard links and mappings share the inode's account. Long symlinks
charge one guest page. The mount accepts a block count through nr_blocks.

Faulting a mapped hole consumes a page. A failed allocation reports SIGBUS for
the virtual address that was accessed, including aliases at different addresses.
Regressions cover local and parallel memory access, release and retry after
truncation, and a sparse file with data at a 1 TiB offset. An overlay with a
two-page tmpfs upper can copy up and modify that file. A separate backing test
copies a 256 GiB allocated but mostly unwritten extent and checks the destination
still uses just one data buffer.

## Timing

The baseline and candidate alternated order with two warmups per build. Median
guest times are in milliseconds. The four common workloads each had 16 measured
pairs. The two tmpfs measurements each had eight. These benchmarks ran before
the final change confined to sparse overlay copy-up. None uses an overlay.

| Workload | Previous | Candidate | Change |
| --- | ---: | ---: | ---: |
| Ordinary memory | 174.76 | 173.10 | −0.95% |
| Map, fault and unmap | 133.57 | 130.76 | −2.11% |
| 20,000 private-store 4 KiB pwrite/pread pairs | 96.16 | 95.44 | −0.75% |
| 150 fork/wait pairs | 19.50 | 19.70 | +1.04% |
| First 8 MiB written to tmpfs, 4 KiB writes | 3.46 | 3.60 | +3.88% |
| 16,384 tmpfs 4 KiB pwrite/pread pairs over those 8 MiB | 43.07 | 44.74 | +3.87% |

Local evidence is under `target/gvisor-tmpfs-20261119` in the iPad checkout.
The timing runner SHA-256 is
`cace32be7bbd1950d71f463fc6c4239e3c95d01a64f04cdd23c264c8d5d10a4e`.
The final copy-up runner SHA-256 is
`5fb27a5ea7283c773e2bf41f8f8d201743ab094abfae47d7e31ee6a4fd64bb42`.
