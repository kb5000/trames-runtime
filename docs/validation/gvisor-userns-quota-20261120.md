# User namespace limits and process reaping on ARM64, 2026-11-20

All 11 upstream `ProcSysUserMaxUserNamespaces` cases failed on the previous
Mac build. All 11 pass on the updated Mac hardware executor and on the ARM64
interpreter. The complete 160-case Mac `proc` binary moved from 84 to 95
passes, with 61 failures, two skips and the same two timeouts. Every previously
passing case still passes.

## What changed

The guest can read and write `/proc/sys/user/max_user_namespaces`. The initial
namespace starts at 32,768 (half the default guest task limit). A new user
namespace starts at INT_MAX. The setting belongs to that environment and
namespace. Writes require CAP_SYS_RESOURCE in the namespace that owns the
opened control. Zero prevents new admissions. Lowering a limit leaves existing
namespaces alive.

A namespace creation charges the effective UID of its creator and the
corresponding creator in each ancestor. An ancestor refusal releases partial
charges. The last reference releases the charges, including when an open nsfs
handle outlives the creating task. Only occupied UID entries are stored.
Ordinary fork does not enter quota accounting. The accounting model follows
the [Linux user sysctl documentation](https://docs.kernel.org/admin-guide/sysctl/user.html).

A first candidate passed ten cases. In the remaining case, a parent waited
for its child to exit but still received ENOSPC on the next creation. Tracking
live references showed the resource-limit lookup table still owned the
child's published credentials after task and family removal. Reaping now
removes the original identities from all three tables and runs destructors
outside their locks. A non-consuming wait retains the zombie. Session shutdown
also preserves the final CPU registers used by the embedding's execution
budget and cancellation checks.

## Coverage

| Upstream group | Updated Mac result |
| --- | --- |
| proc | 95 passed, 61 failed, 2 skipped, 2 timed out |
| proc_pid_uid_gid_map | 22 passed |
| setns | 17 passed |
| unshare | 4 passed, 1 failed |
| wait | 63 passed, 1 fixture failure |

The remaining unshare failure is the PR_SET_MM capability case. The wait
fixture for TraceeWALL calls PTRACE_TRACEME and receives ENOSYS. Each passing
row was checked against its original GoogleTest XML. The interpreter run
covered the 11 quota cases with zero skips. Rust tests additionally cover
competing creators, separate UIDs and environments, retained handles,
lowered limits, and registration before and after a consuming wait.

The rolling 3,163-case inventory now has 2,700 passes, 327 failures, 121 skips,
12 timeouts, two missing results and one fixture failure. This round reran
268 distinct cases. Eleven failure-to-pass changes are attributable to this
patch. One older failure, the MbindMoveAll unshare case, already passed on
the previous binary when rerun in isolation.

## Main-path timings

Mac hardware executor, same machine, rootfs and workload. The baseline was
runtime `7cfeee9`. Each version had two warmups and 16 measured samples.
Execution order alternated between pairs. Values are median guest elapsed
milliseconds and relative differences.

| Workload | Previous | Updated | Change |
| --- | ---: | ---: | ---: |
| Ordinary memory | 169.273 | 170.436 | +0.69% |
| Map, fault and unmap | 129.611 | 130.040 | +0.33% |
| Private file pread/pwrite | 92.982 | 93.719 | +0.79% |
| Fork and wait | 19.123 | 19.096 | -0.14% |

Shared runtime CI passed all eight steps. Interpreter kernel conformance
passed 500 cases with three ignored. The iOS FFI and ARM64 Linux musl session
targets compiled. Local XML, inventories and timing samples are in
`target/gvisor-userns-quota-20261120` in the iPad product checkout.
