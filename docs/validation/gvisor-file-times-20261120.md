# Directory enumeration, timestamps and namespace operations on ARM64

The baseline used runtime `a826e4e`. Both builds ran the same 251 original
gVisor cases from `89cacadae21eca4270a8f7c79281d0426d33ac5f` on the Mac
hardware backend, with fresh stores, two guest CPUs and the same rootfs.
Each pass was matched to the named case in its original Google Test XML.

| Suite | Cases | Baseline passes | Candidate passes |
| --- | ---: | ---: | ---: |
| getdents | 23 | 20 | 23 |
| link | 23 | 18 | 19 |
| mkdir | 7 | 7 | 7 |
| rename | 44 | 42 | 42 |
| stat | 59 | 40 | 40 |
| stat_times | 12 | 8 | 12 |
| symlink | 33 | 32 | 32 |
| truncate | 11 | 10 | 10 |
| unlink | 23 | 21 | 22 |
| utimes | 16 | 12 | 16 |
| Total | 251 | 210 | 223 |

Thirteen failures became passes. The same 22 tests skipped on both builds.
The six remaining failures cover protected hard-link errno, two same-name
renames on sysfs, symlink atime on traversal, the `/dev/shm` fixture, and
`chdir` through procfs to an unlinked directory.

Refreshing these cases in the [rolling inventory](gvisor-clone-wait-20261120.md)
gives 2,527 passes, 335 failures, one fixture failure, 119 skips,
18 timeouts and three missing results. The other 2,752 results carry
forward from earlier runs.

## Behavior

Directory listing copies the encoded records in one operation when the
destination is writable. On a fault, it returns the complete records that
fit and advances the shared position through the last copied entry. An
empty result touches no guest memory. Procfs fd and fdinfo directories use
descriptor-number positions so closing a previously listed descriptor
does not skip another. Directory reads update atime using the existing mount policy.

Creation, linking, unlinking and renaming update parent mtime and ctime in
the existing namespace commit. A cross-directory rename updates both
parents. If the manifest commit fails, their previous modification and
change times are restored. The rollback regression also checks the parent.
The link operation honors AT_SYMLINK_FOLLOW. Removal of a final dot or
dot-dot preserves the directory and returns the corresponding Linux errno.

Utimensat handles AT_EMPTY_PATH and O_PATH, preserves omitted times and
checks ownership for explicit timestamps. When both timestamps are omitted
the kernel can return success before resolving the path or descriptor.
[Linux utimes implementation](https://github.com/torvalds/linux/blob/v6.12/fs/utimes.c)

## Validation and timing

The iPad interpreter running on the Mac passed 34 original cases across
five suites. The iOS FFI and Linux ARM64 session passed cross-target checks.
The runtime workflow passed all eight local steps. Physical iPad execution
and native Linux CI were outside this run.

A separate msync regression occasionally read the guest marker before the
bounded 10 ms test round ended its work. The test now waits for the same
cohort to park on its futexes, retaining its single-cohort, zero-service and
guest-result assertions. This change is confined to the interpreter test.

Two independent runs alternated build order, then reversed the starting
order. Each run discarded two warmup pairs and retained 16 measured pairs.
The table gives pooled medians of the 32 guest measurements per build.
Graphics and networking were disabled and the CPU count was two.

| Workload | Baseline ms | Candidate ms | Time change |
| --- | ---: | ---: | ---: |
| Ordinary memory | 168.192 | 169.590 | +0.83% |
| Map, fault and unmap | 128.315 | 129.221 | +0.71% |
| 20,000 private-file 4 KiB pwrite/pread pairs | 93.977 | 93.412 | -0.60% |
| 150 fork/wait pairs | 19.563 | 19.893 | +1.69% |
| Rewind and list 100 tmpfs files, 1,000 times | 7.498 | 7.452 | -0.61% |
| 2,000 tmpfs mkdir, rename and rmdir sequences | 18.393 | 18.673 | +1.53% |

The first candidate added parent lookups to namespace changes. The final
version reuses the parent references already retained during permission
checks and updates directory metadata directly. The measured namespace
sequence costs about 0.14 microseconds more per sequence than the baseline.
Application startup and disk-latency distributions were not benchmarked.
The binaries, original XML, run plans, benchmark source, per-sample timings
and rolling inventory are under `target/gvisor-file-times-20261120` in the
iPad checkout.
