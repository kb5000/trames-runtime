# Zero-device reads and splice backpressure on ARM64

## Zero-producing devices

The synchronous guest read, readv, pread64, preadv and preadv2 paths for /dev/zero and /dev/full can transfer up to Linux MAX_RW_COUNT. Both current-position and explicit-offset preadv2 calls use the same copy operation. The runtime snapshots vector descriptors before writing output, including when destinations overlap the descriptor table. Each copy uses the existing guest memory write operation on a page fragment. This preserves page permissions, COW and mapped backing effects. The first inaccessible page returns a fault or the byte count already transferred. A long copy checks for a deliverable task signal every 64 KiB. The host uses one constant zero page and space for at most 1,024 vector descriptors. Access time and successful read notification are handled once on the accepted open description. [Linux zero and full device implementations](https://codebrowser.dev/linux/linux/drivers/char/mem.c.html#456)

## File-to-pipe splice

The pipe capacity reservation and its wakeup predicate now use the same amount of available space. File-source transfers reserve from the portion of available byte capacity rounded down to whole guest pages. With a one-page pipe containing 3,968 bytes, a file splice waits for space and leaves the input position intact. The existing readiness subscription and signal interruption path handle this wait. The pipe still uses its existing byte queue and does not track individual Linux pipe buffer descriptors.

## Validation

The Mac hardware executor reran 253 distinct upstream cases covering pipe, splice, read, readv, pread64, preadv and preadv2. Of these, 248 passed with original XML, four were skipped and one failed. After a separate explicit-offset preadv2 probe exposed another dispatch path, all 64 read-family cases were rerun on the final source. Two failures on runtime f64098c now pass.

- ReadvTestNoFixture.TruncatedAtMax now returns 2,147,479,552 bytes instead of 1,048,576.
- SpliceTest.ToPipeWithSmallCapacityDoesNotSpin now blocks and returns EINTR on signal delivery instead of reporting a 128-byte transfer.

The remaining Pread64Test.Overflow failure is at fixture setup. The guest tries to truncate a memfd to INT64_MAX. SharedFile currently caps logical size at 2 GiB and returns EINVAL before the pread assertion.

The Mac-hosted iPad interpreter also passed both formerly failing cases. A separate ARM64 guest probe verified every byte and guard bytes across twelve combinations of device and syscall on both executors, using 1,572,867-byte transfers. A unit regression exercises aliasing and faults after a writable prefix. The iPad device-target FFI compiled. No physical device was used.

The historical inventory now contains 3,017 passes, 113 failures, 83 skips, 25 timeouts, one fixture failure and one missing result across 3,240 cases.

## Paired performance measurements

Each pair used the same isolated guest environment and alternating runner order on the same Mac. Two warmup pairs preceded 16 measured pairs. The device-specific workloads each performed 25,000 reads of 4 KiB. Times are median guest elapsed milliseconds.

| Workload | Previous | Updated | Change |
| --- | ---: | ---: | ---: |
| memory | 175.97 | 177.04 | +0.61% |
| mmap_fault_unmap | 131.87 | 133.03 | +0.88% |
| file_pread_pwrite | 95.18 | 95.12 | -0.06% |
| fork_wait | 19.36 | 19.39 | +0.14% |
| getuid | 103.75 | 103.19 | -0.54% |
| ordinary_stat | 18.95 | 19.07 | +0.67% |
| ordinary_open | 73.88 | 73.64 | -0.34% |
| zero_read_4k | 31.80 | 30.38 | -4.45% |
| zero_readv_4k | 33.66 | 31.36 | -6.82% |

Original XML, probe output and paired timing samples are under `target/gvisor-device-io-20261120` in the iPad worktree.
