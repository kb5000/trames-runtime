# Mount attributes, file access and topology

The original ARM64 gVisor mount and statfs binaries ran against the previous runtime (c5c9f81) and the updated Mac hardware executor. Each of the 126 cases used a fresh guest store. The fixture, rootfs and CPU count were identical. The original Google Test XML accounts for every pass.

| Result | Previous | Updated |
| --- | ---: | ---: |
| Passed | 90 | 102 |
| Failed | 31 | 19 |
| Skipped | 5 | 5 |

All 12 newly passing cases also passed on the Mac-hosted interpreter used by the iPad product. The cumulative inventory now contains 2,800 passes, 214 failures, 25 timeouts, 121 skips, two missing results and one fixture failure across 3,163 unique cases. Only the 126 entries above were rerun. The remaining mount and statfs failures concern propagation, user namespaces and locked mounts, capacity limits, pseudo-filesystem mountpoints and the absent default /dev/shm mount. The separate mount file descriptor API suite was outside this batch.

## Behavior

- A read-only mount permits data writes through FIFO and character device endpoints. Regular files and directory entries retain write protection. The existing device-node and descriptor access checks still apply. The four original read-only FIFO and character device cases now pass.
- The mount and remount paths implement noatime, nodiratime, relatime and strictatime. Ordinary fresh mounts default to relatime. A remount retains the old access-time policy when the caller omits all access-time flags. A prepared file retains a reference to the mount's flag word so an old descriptor observes changes without a path lookup or inode lock. The two original atime cases, the proc mount-flags case and the statfs flags case now pass. A VFS regression also covers directory enumeration and independent bind-mount policy.
- Mount listings retain and escape the supplied source, render an absent source as `none` on a guest-created filesystem, and report nondefault tmpfs creation mode across binds. The original MountInfo and MountProc cases now pass.
- A bind from a detached source and a move from a shared parent return EINVAL. Both original cases now pass.

Access-time flag behavior follows the Linux [mount manual](https://man7.org/linux/man-pages/man2/mount.2.html). Local artifacts including XML, the merged inventory, binary hashes and timing samples reside under `target/gvisor-mount-attrs-20261120` in the iPad checkout.

## Validation

Shared runtime CI passed all eight steps. The product kernel suite passed 501 tests with three ignored. The ARM64 Linux musl session and iOS FFI compiled. The directory-atime regression passed separately after it was added. Physical iPad execution was not measured.

## Main-path timings

The two Mac binaries ran alternately on the same machine. Each median uses 16 measured samples after two warmups per binary. Lower is faster.

| Workload | Before (ms) | After (ms) | Elapsed change |
| --- | ---: | ---: | ---: |
| Memory | 177.271 | 175.997 | -0.72% |
| Map, fault and unmap | 133.136 | 130.609 | -1.90% |
| Private file pread/pwrite | 94.741 | 95.281 | +0.57% |
| Fork and wait | 19.266 | 19.104 | -0.84% |
