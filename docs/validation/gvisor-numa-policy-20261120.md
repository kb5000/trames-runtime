# Single-node Linux memory policies on ARM64

The Mac HVF baseline was runtime `1e55ec3`. The unmodified gVisor mempolicy
suite passed 4/9 in a single process and 4/9 in fresh processes on that build.
The candidate passed 9/9 in both arrangements. The local ARM64 interpreter
also passed 9/9 in one process. All passing guest cases have original XML.

Each new guest thread inherits a private copy of the caller's policy and exec
preserves it. Address policies belong to the mm. Worker views see their
generation of the sparse placement table. Fork initially shares that immutable
table and an edit copies it on demand. Moving or replacing a mapping adjusts
the applicable ranges. Ordinary guest memory loads, stores and faults have
no placement-table lookup. The guest has one usable node. Selecting it also
satisfies eligible home-node requests without moving host pages.

A separate ARM64 executable passed on both backends. It checked pthread
inheritance, independent thread defaults, shared address binding, fork
isolation, exec inheritance and clearing policy over a hole. It exercised
set_mempolicy_home_node for a supported policy, an unsupported policy and
an unbound range. Rust tests cover old worker views, range growth, partial
replacement, mask bounds and the capability required for MPOL_MF_MOVE_ALL.

This round implements thread and VMA placement for the single-node guest.
Cross-process page migration and policy sharing between independent mappings
of the same shared-memory object were outside the measured scope. ABI details
are documented in the [upstream Linux implementation](https://github.com/torvalds/linux/blob/v6.12/mm/mempolicy.c).

## Performance and regression checks

Both Mac builds used the same rootfs, two CPUs and the same workload.
The following are guest wall-time medians from 16 measured runs per build,
alternating order after two warmup pairs.

| Workload | Before ms | After ms | Change |
| --- | ---: | ---: | ---: |
| Ordinary memory | 173.176 | 171.388 | -1.03% |
| Map, fault and unmap | 130.635 | 131.455 | +0.63% |
| Private file pread/pwrite | 94.410 | 95.297 | +0.94% |
| Fork and wait | 19.672 | 19.774 | +0.52% |

Shared runtime CI passed 8/8. Kernel conformance passed 500 cases with
three ignored. One earlier run failed an epoch assertion in the sysinfo
scheduling test. It passed 16 consecutive focused reruns and the subsequent
complete run. Its cause remains unconfirmed. The iOS FFI and ARM64 Linux
session targets compiled. iPad execution was checked on the local interpreter.

Replacing the nine verified rows in the rolling 3,003-case inventory gives
2,595 passes, 275 failures, 119 skips, ten timeouts, three without results
and one fixture failure. Original evidence and both performance samples
are in `target/gvisor-numa-policy-20261120` in the iPad workspace.
