# Descriptor flags and async I/O notifications

The ARM64 gVisor `fcntl` and `ioctl` suites ran on the macOS HVF executor
on 2026-11-20. Runtime `f7bb8f2` and the candidate used identical binaries,
guest rootfs, harness, isolated per-case stores and two virtual CPUs. Each
passing result has a matching original GoogleTest XML record and successful
process exit.

| Suite | Cases | Baseline passed | Candidate passed | Remaining failures |
| --- | ---: | ---: | ---: | ---: |
| fcntl | 97 | 86 | 97 | 0 |
| ioctl | 42 | 32 | 41 | 1 |
| Total | 139 | 118 | 138 | 1 |

The existing per-open-file notification registration now preserves its
first descriptor number when another descriptor for the same file changes
the owner or signal. Unix socket registration uses readiness, including
before connection. The four socket ownership ioctls use the same task and
process-group lookup as fcntl. Close-on-exec affects only the accepted
descriptor slot. Nonblocking and async status operate on the shared open
file description, including when another thread reuses the numeric FD.

For regular files and signalfds, enabling O_ASYNC through F_SETFL succeeds
without installing a notification. The explicit FIOASYNC ioctl on a regular
file reports ENOTTY when asked to change the async bit. The targeted Rust
test checks the distinction, FD reuse, alias visibility and argument access.
The kernel interfaces are described by the upstream implementations of
[fcntl](https://github.com/torvalds/linux/blob/v6.12/fs/fcntl.c),
[ioctl](https://github.com/torvalds/linux/blob/v6.12/fs/ioctl.c) and
[socket ioctls](https://github.com/torvalds/linux/blob/v6.12/net/socket.c).

`IoctlTest.FIOASYNCHandlesFuseFD` still fails opening `/dev/fuse` with
ENOENT. It never reaches the async ioctl. Native internet socket SIGIO was
outside this batch and remains unsupported by the registration path.

All 20 newly passing cases passed again on the local ARM64 interpreter
(11 fcntl and nine ioctl). The shared runtime workflow passed eight steps.
Kernel conformance passed 500 cases with three ignored. Both the iOS FFI
and Linux ARM64 session targets compiled. No physical iPad run was performed.

## Performance

Old and new HVF builds alternated starting order. The values below are guest
wall-time medians of 16 samples per build after two warmup pairs, with two CPUs
and identical workloads. The first four rows each exercise 40,000 calls
on a pipe. They include the existing observer setup and teardown when
toggling O_ASYNC.

| Workload | Baseline ms | Candidate ms | Change |
| --- | ---: | ---: | ---: |
| Read status flags | 40.291 | 40.273 | -0.05% |
| Toggle nonblocking with fcntl | 40.364 | 40.614 | +0.62% |
| Toggle nonblocking with ioctl | 44.157 | 44.446 | +0.65% |
| Toggle O_ASYNC with fcntl | 42.623 | 42.898 | +0.65% |
| Ordinary memory | 168.227 | 166.788 | -0.86% |
| Map, fault and unmap | 128.110 | 126.673 | -1.12% |
| Private file pread/pwrite | 94.359 | 93.665 | -0.74% |
| Fork and wait | 19.469 | 19.126 | -1.76% |

After replacing the 139 measured rows, the rolling 3,003-case inventory
has 2,578 passes, 292 failures, 10 timeouts, 119 skips, one fixture failure
and three without results. Original logs and XML, sample timings, fixture
source and the rolling inventory are in `target/gvisor-fd-controls-20261120`
in the iPad checkout.
