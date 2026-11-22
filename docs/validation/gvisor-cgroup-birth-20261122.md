# gVisor process creation in a cgroup, 2026-11-22

The previous shared runtime was `d0de4ba9f2e55ab886cfbdd038c53217a9c9f0f2`. It rejected `CLONE_INTO_CGROUP` during clone3 argument decoding. The guest can now select a cgroup v2 directory descriptor at birth.

## Implementation

- The clone3 importer requires the complete version-two argument structure for a directed clone and validates the descriptor number. Read-only and O_PATH directory descriptors retain the target inode across close and descriptor reuse. An unlinked, recreated directory cannot receive a child through the old descriptor.
- Admission checks the caller's write access to the destination and common ancestor's `cgroup.procs` with the existing guest inode permission model. Placement, quota charging and PID namespace allocation commit in the existing birth transaction before the child is runnable. Initial freezer state and resource notifications use the destination hierarchy. A newly requested cgroup namespace is rooted at the selected group. [Linux process placement](https://codebrowser.dev/linux/linux/kernel/cgroup/cgroup.c.html#6686)
- Ordinary fork inherits the parent's membership. Only a directed clone looks up a destination descriptor or snapshots its caller credentials. A VFS regression covers directory reuse, O_PATH, denied common-ancestor access, disallowed cross-domain thread placement and the new namespace root.

## Validation

The Mac hardware runner exercised 213 original cases from the cgroup2, fork, vfork, wait and pidfd suites. It used the same ARM64 binaries, Alpine rootfs and two guest CPUs as the prior inventory. Tests ran separately with original XML verification. The iPad interpreter on the Mac repeated the seven directed-clone cases together, including repeated births into a frozen cgroup. The iOS arm64 FFI compiled and all eight stages of local runtime CI passed.

| Same 213 cases | Passed | Failed | Skipped | Timed out | Fixture failed |
| --- | ---: | ---: | ---: | ---: | ---: |
| Previous runtime | 167 | 22 | 22 | 1 | 1 |
| Updated runtime | 174 | 15 | 22 | 1 | 1 |

Seven cgroup2 failures became passes. They cover ordinary placement, caller permission denial, a deleted directory, a full parent group with room at the destination, placement together with a new user namespace, and both frozen-group birth tests. Every other individual outcome matched the previous inventory. The cumulative 13,635 measured cases now contain 12,956 passes and 145 failures, with 508 skips, 25 timeouts and one fixture failure.

The cgroup2 suite still has 15 failures, 15 skips and a timeout. Remaining paths include delegation, memory accounting, zombie membership and freezer signal handling. CPU and memory controller tests that the guest skipped are excluded from passes.

## Main-path performance

The same Mac alternated previous and current release-mode runners for 32 measured pairs after two warm-up pairs. Both used identical guest fixtures, two CPUs and networking disabled. Median elapsed times include only guest workload execution.

| Workload | Before (ms) | After (ms) | Change |
| --- | ---: | ---: | ---: |
| memory | 166.877 | 167.189 | +0.19% |
| mmap fault unmap | 123.099 | 123.497 | +0.32% |
| file pread pwrite | 92.320 | 91.770 | -0.60% |
| fork wait | 18.412 | 18.282 | -0.70% |
| proc cpuinfo | 1.643 | 1.642 | -0.09% |
| ordinary open | 70.869 | 71.051 | +0.26% |
| ordinary stat | 18.136 | 18.186 | +0.27% |
