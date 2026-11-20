# Shared mount propagation, unmount and the namespace mount limit

Trames exposes the environment's existing default of 128 mounts per namespace through a writable /proc/sys/fs/mount-max. Lowering the ceiling preserves existing trees. Mount, recursive bind and detached-tree publication check the live setting. Publication charges all recipient namespaces before cloning or attaching a tree. Only initial-user-namespace root can write this environment-wide setting. The [Linux sysctl documentation](https://docs.kernel.org/admin-guide/sysctl/fs.html#mount-max) defines the per-namespace scope.

A propagated mount is inserted under an existing mount at the recipient's mountpoint. Detaching a tree propagates each original attachment's unmount event to its peers and downstream slaves. An independent child keeps its peer mounted. When a propagated layer is removed, its surviving covering mount regains the old mountpoint. Ordinary unmount checks busy references before changing any table. Peer group numbers are allocated per guest and recycled after the last reference, including detached trees and slave ancestry. The existing namespace topology transaction owns these changes. Regular file I/O does not acquire it. The [Linux shared subtrees documentation](https://docs.kernel.org/filesystems/sharedsubtree.html) describes the propagation directions.

## ARM64 gVisor results

The Mac hardware executor ran all 158 original cases from mount and mount_fd in isolated stores. Each passing case was matched to its upstream XML result. The baseline was runtime 14cfa30.

| Suite | Baseline (pass / fail / skip) | Updated (pass / fail / skip) |
| --- | ---: | ---: |
| mount | 109 / 7 / 1 | 117 / 0 / 0 |
| mount_fd | 36 / 0 / 5 | 36 / 0 / 5 |

The seven previous failures and the previously skipped MountMax case also passed under the iPad interpreter on the Mac. The iOS ARM64 FFI build passed. No physical iPad run was performed. A VFS regression exercises a lower ceiling than the existing tree, subsequent increases through a sibling namespace and rejection of a zero limit.

The cumulative inventory carries forward cases outside these two suites. Its 3,163 entries contain 2,857 passes, 161 failures, 117 skips, 25 timeouts, two missing results and one fixture failure.

## Main-path performance

Two separate runs alternated the old and new Mac hardware executors on the same guest fixture. Each run discarded two warmups per binary and measured 16 samples per binary. The table pools all 32 measured samples per binary. Percentages describe changes in elapsed time.

| Guest workload | Baseline median (ms) | Updated median (ms) | Change | Run 1 | Run 2 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Memory access | 175.771 | 177.131 | +0.77% | +1.20% | +0.47% |
| Map, fault and unmap | 131.119 | 132.625 | +1.15% | +3.87% | -0.65% |
| Private file pread/pwrite | 95.238 | 95.102 | -0.14% | -0.01% | -0.13% |
| Fork and wait | 19.223 | 19.125 | -0.51% | +0.98% | -0.80% |

The largest single-run difference was for map/fault/unmap. Its direction reversed in the second run. Raw XML, all timing samples and runner hashes are in target/gvisor-mount-propagation-final in the iPad checkout.
