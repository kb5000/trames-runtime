# FUSE file operations on November 21, 2026

The signed ARM64 Mac runner at runtime baseline `cf1d1fe` passed 77 of the 83 original gVisor device, ioctl and FUSE cases. With guest file operations enabled, the same binaries passed 81 and skipped two. All 81 have a matching completed testcase in the original GoogleTest XML. The gVisor revision was `89cacadae21eca4270a8f7c79281d0426d33ac5f`.

| Former failure | Behavior checked by the upstream guest program |
| --- | --- |
| AccessUnsupported | An access denial is returned. After an ACCESS reply of ENOSYS, a child name must still exist, and the guest can check a different access mask without another ACCESS request. |
| AioRead | A delayed FUSE READ reply reaches the Linux AIO event with the expected byte count and contents. |
| Fallocate | Successful allocation past EOF updates the size seen by AT_STATX_DONT_SYNC and preserves the server's inode number and block count. |
| FlushUnsupported | ENOSYS disables future FLUSH requests on the connection. Two independent opens still produce two RELEASE messages. |

The iPad interpreter on the Mac passed all four cases in the initial run of the final source and three further fresh-store runs. Local kernel conformance passed 502 tests, with three ignored, and the iOS ARM64 FFI compiled. The 11 FUSE unit tests also cover handle and lookup-reference cleanup after cancellation, nested lookup, expired attributes, readlink, shared file position across short I/O, and flush failure on a duplicated descriptor.

A separate Mac run revisited all 307 inventoried cases from aio, close_range, dup, fallocate, fcntl, lseek, open, read, stat and write. The results matched the previous inventory case by case, with 305 passes and two skips. Across both runs, 390 distinct cases were exercised. The cumulative inventory now has 3,107 passes, 49 failures, 87 skips, 20 timeouts, one fixture failure and one missing result.

## Ordinary workload timing

Both signed release runners executed the same private-volume guest workloads on the same Mac. The order reversed on alternating pairs. Each median uses 16 samples after two warm-up pairs. Times are for a complete workload in milliseconds.

| Workload | Before | After | Change |
| --- | ---: | ---: | ---: |
| getuid | 103.897 | 104.104 | +0.20% |
| stat | 19.192 | 19.223 | +0.16% |
| open | 74.203 | 74.682 | +0.65% |
| memory | 177.045 | 177.164 | +0.07% |
| mmap, fault and unmap | 135.604 | 132.750 | −2.10% |
| pread and pwrite | 97.553 | 95.952 | −1.64% |
| fork and wait | 20.032 | 19.594 | −2.19% |

These measurements cover the established workloads. Throughput for guest FUSE file transfers remains unmeasured.

## Remaining boundaries

Simple descendant lookups, file attributes, readlink, regular file handles, reads, writes, basic allocation, fsync and close now communicate with the mounted guest daemon. LOOKUP and OPEN replies have separate identifiers. The connection balances references using FORGET and releases an open handle after its outstanding operations. Daemon waits use existing task readiness subscriptions.

Directory enumeration, general symlink traversal, creation and unlink, rename, and file-backed mmap through these handles remain incomplete. The current guest data requests cap a transfer at 4 KiB. The two skipped upstream cases still require separate fixtures. EpollAfterAbort needs a fusectl mount, and LookupUpdatesInode expects an externally configured FUSE mirror at /fuse. Snapshot restoration and physical iPad execution were outside this run.
