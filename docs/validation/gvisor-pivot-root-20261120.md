# Pivoting an attached guest root

A process can use pivot_root after chroot into a mount within its namespace. The runtime moves the new mount to the previous root's attachment, then places the previous root at put_old. A separate mount beneath the new root is a valid put_old. Directory checks, membership in the original namespace, both reachability checks, shared-parent exclusions and inherited attachment locks are checked before changing topology. An inherited attachment lock moves with the original attachment point. Existing filesystem contexts that reference exactly the moved root are updated by the existing path-context mechanism. Open directory descriptors and independent roots keep their identities. The [Linux implementation](https://github.com/torvalds/linux/blob/v6.12/fs/namespace.c#L4097-L4178) defines the corresponding checks and exchange.

Trames starts with a mounted guest volume identified by /dev/vda1. The namespace retains a separate bootstrap parent ID for that volume's mountpoint. Mountinfo reports that ID, which remains stable when a new volume takes the top position. The bootstrap parent has no user-visible path. Both nested and top-level pivots use the original mount-administration transaction. No coordinator or additional regular file I/O synchronization was introduced.

## Original gVisor tests

The baseline was runtime 42222f5. The Mac hardware executor reran 189 upstream ARM64 cases, one per fresh store. Each passing result matched the exact test name in the guest XML.

| Suite | Before (pass / fail / skip / missing) | After (pass / fail / skip / missing) |
| --- | ---: | ---: |
| pivot_root | 8 / 10 / 0 / 1 | 18 / 0 / 1 / 0 |
| chroot | 10 / 2 / 0 / 0 | 10 / 2 / 0 / 0 |
| mount | 117 / 0 / 0 / 0 | 117 / 0 / 0 / 0 |
| mount_fd | 36 / 0 / 5 / 0 | 36 / 0 / 5 / 0 |

The previous missing result was PivotRootTest.OnRootFS. The upstream test checks whether the root mount has itself as parent before exercising the initial Linux rootfs. It now records a skip on the mounted Trames volume. An independent VFS regression exercises nested and top-level pivots and verifies the volume's parent ID and the calling and observing processes' root identities.

The ten cases that previously failed all passed on the iPad interpreter running on the Mac. The ARM64 iOS FFI build passed. No physical iPad run was performed. An isolated Mac guest also ran the existing runc 1.1.15 OCI fixture and executed /bin/true inside its container with exit status zero.

With unchanged suites carried forward, the cumulative inventory contains 2,866 passes, 152 failures, 118 skips, 25 timeouts, one missing result and one fixture failure across 3,163 cases.

## Main-path timings

The same ARM64 probe ran on the Mac hardware executor, alternating the order of the old and new binaries. Medians use 16 samples per binary after two warmups. Positive changes indicate longer elapsed time.

| Workload | Before (ms) | After (ms) | Change |
| --- | ---: | ---: | ---: |
| Memory access | 177.608 | 177.809 | +0.11% |
| Map, fault and unmap | 133.638 | 132.882 | -0.57% |
| Private file pread/pwrite | 95.026 | 94.525 | -0.53% |
| Fork and wait | 19.247 | 18.972 | -1.43% |

The local evidence directory is target/gvisor-pivot-root-20261120 under the iPad checkout. It contains the XML audits, interpreter results, OCI guest log, cumulative inventory and raw timing samples with runner hashes.
