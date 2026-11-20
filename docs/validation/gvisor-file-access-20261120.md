# Linux file descriptor access modes

Linux open access mode 3 checks both read and write permission on the target and retains a descriptor for control operations. Data reads and writes through that descriptor fail with EBADF. The VFS uses common access predicates for ordinary I/O, positioned and vector I/O, AIO, io_uring, record locks, file-backed mappings, transfers and native file exports. Shared host directories keep the accepted host file alive after unlink, including for a control-only open. [Linux open(2)](https://man7.org/linux/man-pages/man2/open.2.html)

Opening a Unix socket pathname now checks the caller's file permissions before reporting ENXIO for the unsupported data open. O_PATH remains available to obtain a reference to the socket inode.

## Compatibility

Runtime 569971b reproduced both original failures in fresh Mac guest stores. The candidate passed both on the Mac hardware executor and on the iPad interpreter running on the Mac. The iOS device target compiled. Focused VFS tests also verified permission denial with only one of the required permission bits, positional I/O and mapping denial, record locks, seek, and metadata after unlink in a host directory.

The Mac executor ran 304 upstream cases covering open, open_create, fcntl, flock, read, write, pread64, pwrite64, copy_file_range, sendfile and the affected exec case. The original XML confirmed 302 passed and two were skipped. Updating these rows in the 3,240-case inventory gives 3,036 passed, 96 failed, 82 skipped, 24 timeouts, one fixture failure and one missing result.

One former timeout was a harness issue. FlockTest.BlockingLockNoBlockingForSharedLocks deliberately sleeps for 30 seconds while also checking that another reader acquires a shared lock within one second. The harness now allows 45 seconds for this case. The baseline and candidate both passed with the original lock assertions intact.

## Performance

The signed Mac binaries alternated on the same two-CPU Alpine environment. Each probe had two warm-up pairs and 16 measured pairs. Times are median guest milliseconds per probe. Positive changes mean greater elapsed time.

| Probe | Baseline | Candidate | Change |
| --- | ---: | ---: | ---: |
| Memory | 174.783 | 176.416 | +0.93% |
| mmap, fault and unmap | 131.740 | 132.046 | +0.23% |
| Private pread and pwrite | 95.612 | 95.168 | −0.46% |
| Fork and wait | 19.394 | 19.241 | −0.79% |
| getuid | 103.361 | 103.479 | +0.11% |
| stat | 19.181 | 19.085 | −0.50% |
| open | 74.039 | 73.594 | −0.60% |

Raw XML, the cumulative inventory and timing samples are in the iPad checkout under `target/gvisor-access-mode-20261120`.
