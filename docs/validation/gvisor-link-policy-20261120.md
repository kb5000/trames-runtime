# Link permissions, sticky directories and symlink access times

Two unchanged gVisor cases failed on Mac runtime `6afe93e`. In `LinkTest.PermissionDenied`, all three attempts returned the directory's `EACCES` instead of the source inode's `EPERM`. In `SymlinkTest.FollowUpdatesATime`, following a private symlink left its access time unchanged.

## Behavior

Guest hard-link creation now checks the original source inode before the destination directory's write permission. Ownership, filesystem credentials, capabilities, ACLs and both set-ID bits affect the result. For a symlink in a sticky world-writable directory, following the final link considers the owner of the directory, the owner of the link and the caller's filesystem UID. Reading the link text and opening its target are distinct operations. Following a private link or reading its text updates the link's access time according to the mount used for that access, including a retained descriptor. The common relatime path can skip the inode write lock. Host-shared directories refresh metadata from the host. The time tests here cover the private guest filesystem and its bind mounts.

The four Linux controls are visible under `/proc/sys/fs/`. Trames starts `protected_hardlinks` and `protected_symlinks` at 1 and `protected_fifos` and `protected_regular` at 0. An environment's privileged writer can change those settings while tasks run. For FIFOs and regular files, level 1 applies to sticky world-writable directories and level 2 also covers sticky group-writable directories. The policy checks existing files opened with `O_CREAT` before truncation. Each environment owns the settings and workers access them directly. [Linux filesystem sysctl documentation](https://docs.kernel.org/admin-guide/sysctl/fs.html)

## Validation

| Check | Result |
| --- | --- |
| Mac hardware backend, all three original suites (`link`, `symlink`, `open_create`) | 69 passed with matching XML, three existing `AT_EMPTY_PATH` skips, zero failures in 72 cases |
| Shared iPad interpreter on Mac | Both previously failing cases passed with original XML |
| Direct guest probe on each backend | All four sysctls had the intended defaults. A second user observed live link-policy changes. Denied creates preserved file contents. The FIFO open returned the expected error |
| Shared runtime unit tests | Covered capability and mode rules, inherited controls, sticky group and world-writable directories, descriptor-based readlink, read-only, noatime and relatime bind mounts |
| Runtime and iPad builds | Runtime CI passed all eight steps on macOS ARM64. The iPad FFI compiled for the device target |

The cumulative inventory replaces only the 72 rerun entries. Of 3,163 cases, 2,902 passed, 115 failed, 119 skipped, 25 timed out, one fixture failed and one had no result.

## Paired performance

The old and new Mac runners used the same Alpine store for each benchmark and alternated running order. Times below are guest-side medians of 16 pairs following two warmup pairs. Negative changes indicate lower elapsed time.

| Workload | Before (ms) | After (ms) | Change |
| --- | ---: | ---: | ---: |
| Open and close a regular file, 4,000 | 74.22 | 74.57 | +0.48% |
| Stat a regular file, 4,000 | 19.06 | 18.81 | -1.30% |
| Stat through a symlink, 4,000 | 20.26 | 20.19 | -0.32% |
| Memory access | 176.08 | 175.54 | -0.31% |
| Map, fault and unmap | 133.65 | 131.15 | -1.87% |
| Private pread/pwrite | 95.35 | 95.07 | -0.30% |
| Fork and wait | 19.41 | 19.24 | -0.85% |

Raw results, benchmark samples and guest probes are in `target/gvisor-namei-20261120` in the iPad checkout.
