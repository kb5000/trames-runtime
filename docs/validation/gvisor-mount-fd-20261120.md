# Descriptor-based mount lifecycle on ARM64

Trames now supports creating a filesystem context, supplying its parameters, obtaining a detached mount, populating it through a directory descriptor, and attaching it with move_mount. The same guest syscall path serves the Mac hardware executor and iPad interpreter. The [Linux filesystem mount API](https://www.kernel.org/doc/html/latest/filesystems/mount_api.html) describes the context and the separation between creation and attachment.

- fsopen and fsconfig support tmpfs, proc and sysfs contexts. A tmpfs context supports source, size or block count, inode count, root mode, UID, GID and read-only state. Reconfiguration updates tmpfs capacity and superblock read-only state. A bind alias retains its own per-mount read-only flag when the superblock returns to read-write. Unsupported operations report an error.
- fsmount reserves a guest descriptor and creates an independently usable detached root. Descriptor exhaustion leaves the original context usable for a retry. Parameter state is shared across duplicated context descriptors. Closing a descriptor uses the ordinary guest file table.
- open_tree can return a path descriptor or clone a file or directory tree. move_mount can compose detached subtrees and publish them together. Publication uses the existing namespace administration and propagation code. A namespace transfer preserves locked mount attributes and the direction of propagation into a less privileged namespace. The new calls introduce no coordination thread.
- Filesystem-layer lookup checks the user namespace that owns a detached source. Dedicated VFS regressions cover ownership after the originating descriptor closes, descriptor exhaustion, and reconfiguration across bind aliases.
- fspick, mount_setattr and filesystem-specific configuration for overlay, cgroup2, mqueue and devpts remain outside this implementation. Those four filesystems retain their existing mount(2) entry points.

## Verification

The Mac hardware executor reran the same 241 original ARM64 gVisor cases before and after the change, with a fresh private store for each case. The baseline runtime was e4a94c1. Each passing result matched the named upstream case in the guest XML.

| Suite | Before (pass / fail / skip) | After (pass / fail / skip) |
| --- | ---: | ---: |
| mount_fd | 0 / 36 / 5 | 36 / 0 / 5 |
| mount | 96 / 17 / 4 | 109 / 7 / 1 |
| statfs | 6 / 2 / 1 | 6 / 2 / 1 |
| overlay | 62 / 6 / 6 | 62 / 6 / 6 |
| Total | 164 / 61 / 16 | 213 / 15 / 13 |

Of the 49 new passes, 46 previously failed and three previously skipped. The five remaining mount_fd skips come from three upstream platform checks and two kernel-version checks. Outstanding legacy mount cases cover mount quotas and propagation group/stack behavior. The cumulative inventory of 3,163 cases, carrying forward untouched results, now contains 2,849 passes, 168 failures, 118 skips, 25 timeouts, two missing results and one fixture failure.

The iPad interpreter running on the Mac independently passed the same 49 cases. Physical iPad execution was not measured. The shared runtime CI passed all eight steps. The iOS FFI and Linux ARM64 musl builds passed. In the kernel suite 500 passed, three were ignored and one sysinfo/seccomp epoch-progress assertion failed during concurrent validation. All five isolated reruns of that test passed. The cause of that single failure is unconfirmed.

## Main-path timings

Each version ran the same ARM64 guest probe on the Mac hardware executor. The order alternated by pair. Medians use 16 measured runs per version after two warmups each. Positive changes indicate longer elapsed time.

| Workload | Baseline (ms) | Updated (ms) | Change |
| --- | ---: | ---: | ---: |
| Memory access | 174.401 | 174.878 | +0.27% |
| Map, fault and unmap | 131.460 | 131.453 | −0.005% |
| Private file pread/pwrite | 94.689 | 95.091 | +0.42% |
| Fork and wait | 19.034 | 18.963 | −0.37% |

Local evidence is in target/gvisor-mount-fd-20261120 under the iPad checkout. product-audit contains the case-by-case hardware executor results, the interp XML files contain the interpreter results, and perf-long.json contains all timing samples and both runner hashes.
