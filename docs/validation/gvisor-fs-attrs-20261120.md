# Linux shared memory mounts and extended attributes

The Mac Linux shell and the interpreter CLI now mount a session-local tmpfs at `/dev/shm` after importing the root filesystem. The iPad uses the same mount setup, including its existing sticky mode (01777) and 64 MiB size limit. Pages are charged on use. Repeated preparation preserves the live mount. Cold reopening creates a fresh filesystem. Explicit startup file imports under this path use the mounted store and its quota. Android and systemd have their own boot mount setup.

Guest inodes retain arbitrary nonempty `trusted.*` attributes, including after a disk reopen. Access requires CAP_SYS_ADMIN in the initial guest user namespace. The attribute check also covers lists and removal. Invalid setxattr flag bits return EINVAL before reading the attribute name or value. These permission and flag rules follow the [Linux 7.0 xattr implementation](https://github.com/torvalds/linux/blob/v7.0/fs/xattr.c). The change uses the existing inode metadata transaction.

## Upstream results

Baseline runtime 70b9583 reproduced seven failures in statfs, truncate and xattr. The Mac hardware executor then ran all 187 original ARM64 cases in the five suites below, with a fresh store per case. The six newly passing cases also passed through the iPad interpreter running on the Mac. The two iPad session mount tests and the ARM64 iOS FFI build check passed. No physical iPad run was performed.

| Suite | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| statfs | 8 | 0 | 1 |
| truncate | 11 | 0 | 0 |
| mknod | 9 | 0 | 0 |
| xattr | 44 | 1 | 2 |
| posix_acl | 97 | 1 | 13 |
| Total | 169 | 2 | 16 |

The new passes cover statfs and fstatfs on `/dev/shm`, ftruncate on shared memory, xattr behavior on a FIFO, invalid setxattr flags and trusted attributes with CAP_SYS_ADMIN. All previously passing cases retained their status. The two outstanding failures are `WriteRemovesSecurityCapability` (setting the initial file capability returns EOPNOTSUPP) and `DeviceFileModeUnaffectedByPostCopyUpParentDefaultACL/OverlayLower` (stat cannot find the device added directly to the lower directory after the overlay was mounted).

The cumulative inventory combines these 187 results with earlier runs. Of 3,163 cases, 2,889 passed, 128 failed, 119 skipped, 25 timed out, one has no result and one failed during fixture setup.

## Main-path timings

Two independent rounds each alternated the old and new Mac binaries with two warmups and 16 measured samples per binary. Times are guest workload medians in milliseconds, excluding process startup for the benchmark runner. Each pooled median uses 32 samples. Positive differences indicate more elapsed time.

| Workload | Baseline (ms) | Candidate (ms) | Pooled change | Round 1 | Round 2 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Memory access | 177.54 | 177.55 | +0.00% | -0.25% | -0.15% |
| Map, fault and unmap | 133.81 | 134.32 | +0.38% | +0.76% | -0.32% |
| Private pread/pwrite | 95.45 | 95.68 | +0.24% | +0.22% | -0.54% |
| Fork and wait | 19.53 | 19.72 | +0.98% | +3.20% | -1.47% |

The local evidence, including original XML, normalized results, inventory and timing samples, is under `target/gvisor-fs-attrs-20261120` in the iPad checkout.
