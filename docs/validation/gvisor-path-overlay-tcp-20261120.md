# Scoped path walks, overlay mounts and TCP close

The signed Mac Dev runner passed 397 of 424 selected upstream gVisor cases across seven suites. Five failed and 22 skipped. All 397 passes have original test XML. Nine results improved against the previous inventory at runtime `bdba4af`. Two of those nine previously timed out. The local iPad interpreter also passed all nine improved cases. The iOS FFI target compiled, and the shared runtime passed 8/8 local CI steps.

| Area | Verified change |
| --- | --- |
| openat2 | RESOLVE_BENEATH and RESOLVE_IN_ROOT retry a parent walk that overlaps a rename or mount topology change. The four upstream mount and rename races passed. An object-local view of the environment's path-change counter supports concurrent writers. Ordinary opens skip the counter. |
| OverlayFS | Lower, upper and work layers use the same namespace-membership and locked-child admission. All four upstream locked-mount cases passed, including a directory FD from another namespace. Detached trees retain their separate owner checks. |
| TCP | Linux SO_LINGER uses an eight-byte structure on the native socket and on the direct worker path. The virtual stack inherits abortive close on accept and emits a reset on close. The original TCP sendfile shutdown case passed. Positive linger time on a purely virtual endpoint returns EOPNOTSUPP. |

The five outstanding assertions in the selected suites cover two security.capability operations on overlayfs, one lower-layer device appearing after mount, and two sysfs self-renames on the read-only guest mount. The cumulative inventory across 3,240 cases is 3,052 passed, 82 failed, 82 skipped, 22 timed out, one fixture failure and one case without a result. Cases outside the selected suites retain their earlier evidence.

## Same-machine timing

Each pair used the same guest and store with two guest CPUs. Version order alternated across 18 pairs. The medians exclude the first two pairs. Times are milliseconds per workload. The three topology workloads each ran 4,000 iterations on tmpfs.

| Workload | Before (ms) | After (ms) | Elapsed time change |
| --- | ---: | ---: | ---: |
| getuid | 103.44 | 103.02 | -0.40% |
| Ordinary stat | 18.79 | 19.15 | +1.95% |
| Ordinary open | 73.73 | 73.29 | -0.60% |
| Memory accesses | 175.64 | 175.75 | +0.06% |
| Map, fault and unmap | 133.90 | 133.22 | -0.51% |
| File pread and pwrite | 96.50 | 95.16 | -1.39% |
| Fork and wait | 19.42 | 19.18 | -1.26% |
| tmpfs rename | 20.22 | 20.16 | -0.30% |
| Scoped open | 20.04 | 19.91 | -0.68% |
| Scoped open through .. | 20.93 | 20.68 | -1.24% |
