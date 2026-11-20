# Joining guest namespaces through a pidfd on ARM64

A caller can join user, mount, UTS, IPC, PID, cgroup and network namespaces in a single setns call. The caller resolves its descriptor once. The target publishes weak references to its current namespaces at the same boundary as its credentials and file table. An accepted request retains only the selected namespaces, including while waiting for a mount operation. Joining a PID namespace selects the target’s active PID namespace for the caller’s future children. Time namespaces remain unsupported.

The runtime checks the caller’s real credentials against the target and validates every requested membership before publishing any change. When a user namespace is included, the original caller must have the required capabilities in the proposed user namespace and in each namespace’s owner. IPC semaphore undo adjustments retire only on success. Both execution backends use the existing task namespace transaction. See the [Linux namespace transaction](https://github.com/torvalds/linux/blob/master/kernel/nsproxy.c).

The same batch corrects the initial-user-namespace CAP_SYS_RESOURCE check and unused argument validation for PR_SET_MM. Privileged mutation of process memory layout remains unsupported.

## Compatibility results

| Suite | Mac hardware executor | Mac-hosted iPad interpreter | Recorded ARM64 Linux |
| --- | ---: | ---: | ---: |
| pidfd (selected setns and getfd cases) | 10/10 | 10/10 | 10/10 |
| setns | 17/17 | 17/17 | 17/17 |
| unshare | 5/5 | 5/5 | 5/5 |

The five previously failing cases covered a reaped target, a zombie target, ptrace permission denial, joining a live child’s UTS namespace and PR_SET_MM across user namespace creation. The 32 updated results bring the cumulative 3,240-case inventory to 3,029 passes, 102 failures, 82 skips, 25 timeouts, one fixture failure and one missing result.

A separate guest program on both executors joined UTS, IPC and PID together. It checked the target hostname, namespace identities, active PID versus PID-for-children and ESRCH after reaping. VFS regressions cover rollback on a later permission denial and the lifetime of selected namespaces after descriptor reuse and target exit while a mount is busy. The iOS device-target FFI compiled. Physical iPad execution was outside this run.

## Main path performance

Two warmup pairs preceded 16 measured pairs per workload on the same Mac, alternating runner order. Times are median guest elapsed milliseconds. The baseline runtime was 16470b1.

| Workload | Before (ms) | After (ms) | Change |
| --- | ---: | ---: | ---: |
| memory | 178.17 | 180.02 | +1.04% |
| mmap_fault_unmap | 130.30 | 131.17 | +0.67% |
| file_pread_pwrite | 94.83 | 94.71 | -0.13% |
| fork_wait | 19.08 | 19.42 | +1.81% |
| getuid | 103.20 | 103.31 | +0.11% |
| ordinary_stat | 18.79 | 18.66 | -0.68% |
| ordinary_open | 73.23 | 73.78 | +0.76% |

Individual samples, original XML and the updated inventory are in the iPad worktree under `target/gvisor-pidfd-setns-20261120`.
