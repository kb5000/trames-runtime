# gVisor cgroup namespace delegation, 2026-11-22

The previous runtime was `e02c17449906ad46f8c3c86dcc59a0c491a3af76`. It rejected the `nsdelegate` cgroup2 mount option. The shared guest hierarchy now supports the option on mount and remount. A mount requires authority in the user namespace that owns the cgroup namespace as well as the existing mount-namespace permission. Only the initial cgroup namespace can change the hierarchy-wide setting. Bind mounts share it and a bind remount leaves it intact. The mount table reports the current setting. Failed mount validation cannot change the policy. [Linux cgroup root flags](https://codebrowser.dev/linux/linux/kernel/cgroup/cgroup.c.html#2045)

The namespace retained by an open control file determines the delegation boundary even if the task subsequently changes namespaces. At a delegated namespace root, writes to non-delegatable control files fail. Migration through an open `cgroup.procs` file checks the opener’s credentials against the live common ancestor of the source and destination. The PID operand is interpreted in the writing task’s PID namespace. Directed clone shares the migration boundary check and uses the caller’s credentials. The namespace root retains inode identity across deletion or path reuse. [Linux cgroup migration permissions](https://codebrowser.dev/linux/linux/kernel/cgroup/cgroup.c.html#5306)

This change retains the runtime’s existing administration requirement on control writes. Directory creation by an unprivileged delegate and the remaining controller implementations have separate coverage. Ordinary file reads, writes and forks do not test the mount option.

## Validation

Mac hardware execution covered all 250 original cases in the cgroup2, mount, mount_fd and unshare suites. The guest used the same ARM64 binaries, rootfs and two CPUs as the previous inventory. Each case ran in a separate test process. Passes require an original matching GoogleTest XML entry.

| Same 250 cases | Passed | Failed | Skipped | Timed out |
| --- | ---: | ---: | ---: | ---: |
| Previous runtime | 214 | 15 | 20 | 1 |
| Updated runtime | 222 | 7 | 20 | 1 |

Eight cgroup2 failures became passes. They cover mount permission relative to the user namespace, option handling outside the initial cgroup namespace, namespace-root writes, namespace containment for migration and clone, both directions of a namespace change after opening a control file, and common-ancestor checks using the opener’s credentials. All eight also passed in the native Linux reference and on the iPad interpreter running on the Mac. Every other individual result was unchanged. The iOS arm64 FFI compiled and all eight stages of local runtime CI passed.

At unchanged coverage of 13,635 cases, the cumulative inventory contains 12,964 passes, 137 failures, 508 skips, 25 timeouts and one fixture failure. The cgroup2 suite itself has 64 passes, seven failures, 15 skips and one timeout.

## Main-path performance

The same Mac alternated previous and current release-mode runners for 32 measured pairs after two warm-up pairs. Both used identical guest fixtures, two CPUs and networking disabled. Median elapsed times include only guest workload execution.

| Workload | Before (ms) | After (ms) | Change |
| --- | ---: | ---: | ---: |
| memory | 166.853 | 167.118 | +0.16% |
| mmap fault unmap | 123.863 | 123.935 | +0.06% |
| file pread pwrite | 92.412 | 92.802 | +0.42% |
| fork wait | 18.463 | 18.363 | -0.54% |
| proc cpuinfo | 1.643 | 1.640 | -0.13% |
| ordinary open | 71.570 | 71.686 | +0.16% |
| ordinary stat | 18.202 | 18.408 | +1.13% |
