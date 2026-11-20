# Guest process and thread I/O accounting

Linux applications can read logical I/O counters from /proc/PID/io and /proc/PID/task/TID/io. The runtime counts read and write calls and the bytes they actually return. This includes vectored and positioned I/O, and successful sendfile and copy_file_range transfers. A retained call updates the original task at completion. A checkpoint or a park does not complete the call. A syscall rejected by seccomp does not enter VFS accounting.

Each task owns its counters. A group read combines members and retired threads under the existing membership lock, and includes the usage of children collected by wait. The original PID binding prevents a retained descriptor from selecting a reused PID. Reads check the current reader's credentials against the target. [Linux proc accounting](https://github.com/torvalds/linux/blob/v6.12/fs/proc/base.c) and [Linux read/write accounting sites](https://github.com/torvalds/linux/blob/v6.12/fs/read_write.c)

The four reported fields are rchar, wchar, syscr and syscw. The guest currently provides no per-task block-layer attribution for read_bytes, write_bytes or cancelled_write_bytes. In particular a cache hit or a pipe write cannot be counted as a physical disk transfer. For some error paths the runtime knows the final errno but cannot distinguish every stage at which Linux would reject a request.

## Compatibility

The final signed Mac executor ran 587 original ARM64 gVisor cases from 16 suites. Comparing exact test identities to the previous inventory produced four new passes across proc and no other classification changes. The proc suite passed 143 of 160 cases with 15 failures and two skips. The other 427 cases produced 419 passes, six skips, one existing sendfile_socket failure and one existing wait fixture failure. The cumulative inventory contains 3,043 passes, 89 failures, 82 skips, 24 timeouts, one fixture failure and one missing result.

PidTidIOAccounting measured exactly 100 writes on the writer and zero on its idle sibling. VerifyTaskDir, SubprocessRunning and SubprocessExited also passed. These four cases and SubprocessZombie passed on the iPad interpreter running locally on the Mac. The iOS device target compiled.

A separate ARM64 probe exercised write, pwrite, writev, a zero-length write, an invalid descriptor, waited-child accounting, and a short pipe read after a delayed writer. It checked that lowering credentials prevents reading an inherited parent I/O file and that seccomp denial leaves syscw unchanged while an allowed write increments it. The probe exited successfully on both executors.

## Timings

The previous and candidate signed Mac runners alternated on a private two-CPU Alpine environment. Each series excluded two warmup pairs and measured 16 pairs. Positive changes indicate longer elapsed time.

| Workload | Before (ms) | After (ms) | Change |
| --- | ---: | ---: | ---: |
| memory | 173.764 | 171.046 | -1.56% |
| mmap_fault_unmap | 135.295 | 134.132 | -0.86% |
| file_pread_pwrite | 95.459 | 94.708 | -0.79% |
| fork_wait | 19.825 | 19.442 | -1.93% |
| getuid | 102.308 | 103.398 | +1.06% |
| ordinary_stat | 19.374 | 19.434 | +0.31% |
| ordinary_open | 72.368 | 72.332 | -0.05% |

The original XML, normalized results, probe source and raw timings are in `target/gvisor-task-io-20261120` in the iPad checkout.
