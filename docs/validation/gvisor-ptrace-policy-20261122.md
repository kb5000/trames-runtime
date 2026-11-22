# Guest ptrace policy and process-debugging regression, 2026-11-22

## Result

Six of the previous 25 ptrace gaps now pass on the Mac hardware executor and on the iPad product’s interpreter running locally. The Mac sets of 237 and four upstream cases are disjoint and use the same signed build. Together they cover all 31 outstanding process-debugging cases and their neighbors. Of the 241 cases, 206 passed, 24 failed, ten skipped and one timed out. Each result other than a timeout was verified against the original Google Test XML. The 25 residual process-debugging gaps consist of 19 ptrace tests and six related tests. The rolling native-pass gap count across all categories changed from 157 to 151.

The complete upstream ptrace binary produced 16 passes, 19 failures and one skip. The skipped sysctl test detects a native platform and deliberately avoids changing that platform’s policy. The 11 earlier Yama-conditioned skips in the target group all ran. The exec/attach stress case checks completion under concurrent permission checks and exec. Its pass says nothing about successful live attach.

## Guest behavior

Each guest now defaults to Linux Yama scope 1. Related tasks, a designated debugger and its descendants, and a caller with the required capability are eligible under the additional policy. Ordinary UID, dumpability, namespace and image checks still apply. The guest exposes `/proc/sys/kernel/yama/ptrace_scope` and `prctl(PR_SET_PTRACER)`. The policy participates in ptrace admission, `process_vm_*`, opening `/proc/PID/mem`, and `pidfd_getfd`. Exceptions are stored against original task identities. The shared parent graph handles ancestor checks at inspection time. Normal guest execution has no policy polling or extra coordinator.

Scope 0 adds no Yama restriction, scope 2 requires the relevant capability, and scope 3 disables new tracing for the rest of the guest kernel lifetime. Nested PID namespaces share the setting. Separate guest kernels have independent settings. Changing the setting requires CAP_SYS_PTRACE in the initial guest user namespace. These behaviors follow the [Linux Yama implementation](https://github.com/torvalds/linux/blob/master/security/yama/yama_lsm.c).

The original identity, PID reuse, exception clearing and namespace-sharing regressions passed. Mac and interpreter guests both exercised the sysctl through its filesystem interface, including the irreversible transition to 3 and refusal of stock strace even for guest root. All eight local runtime CI stages passed and the ARM64 iOS FFI compiled.

## The six cases outside the ptrace suite

| Original case | Result and first blocker |
| --- | --- |
| `ExecTest.SUIDExecDoesntGainUIDWithPtracerAttached` | Timed out after the tracer's external attach returned ENOSYS. |
| `ElfTest.PtraceExecuteOnlyBinary` | The readable control requires a successful ptrace word write. |
| `ExecveTest.BrkAfterBinary` | Register replacement to run a remote brk query failed. |
| `ProcPidMem.DifferentUserAttached` | The setup requires PTRACE_SEIZE. |
| `SysretTest.BadRip` | The debugger cannot install the requested program counter. |
| `SysretTest.BadRsp` | The debugger cannot install the requested stack pointer. |

Two independent guest checks narrowed the diagnosis. On both executors, a one-page, fixed-address ELF queried its own heap before initializing a C runtime and verified that the break was beyond the last image page. A different executable confined to printing its real and effective UID ran as guest UID 65534 from a guest-root-owned, set-ID file. Ordinary execution printed effective UID 0. Voluntary tracing by stock strace printed effective UID 65534. These checks exercise the heap and credential behavior directly. The six original tests retain the results above.

## Original 25 ptrace cases

| Upstream case | Previous | Current |
| --- | --- | --- |
| `PtraceTest.ExecvePtraceLockStress` | skipped | passed |
| `PtraceTest.PrctlNotInherited` | skipped | passed |
| `PtraceTest.PrctlSetPtracerDoesNotPersistPastNonLeaderExec` | skipped | passed |
| `PtraceTest.PrctlSetPtracerDoesNotPersistPastTracerThreadExit` | skipped | passed |
| `PtraceTest.TraceNonDescendantNotAllowed` | skipped | passed |
| `PtraceTest.TraceParentNotAllowed` | skipped | passed |
| `PtraceTest.AccessVmUsesAttachCreds_CapDroppedAfterAttach` | failed | failed |
| `PtraceTest.AccessVmUsesAttachCreds_CapGainedAfterAttach` | failed | failed |
| `PtraceTest.AttachParent_PeekData_PokeData_SignalSuppression` | failed | failed |
| `PtraceTest.ExitWhenParentIsNotTracer_Syscall_TraceVfork_TraceVforkDone` | failed | failed |
| `PtraceTest.GetSiginfo_SetSiginfo_SignalInjection` | failed | failed |
| `PtraceTest.PrctlClearPtracerDoesNotAffectCurrentTracer` | skipped | failed |
| `PtraceTest.PrctlSetPtracer` | skipped | failed |
| `PtraceTest.PrctlSetPtracerPersistsPastLeaderExec` | skipped | failed |
| `PtraceTest.PrctlSetPtracerPersistsPastTraceeThreadExit` | skipped | failed |
| `PtraceTest.PrctlSetPtracerRespectsTracerThreadID` | skipped | failed |
| `PtraceTest.SeizeSetOptions` | failed | failed |
| `PtraceTest.Seize_Interrupt_Listen` | failed | failed |
| `PtraceTest.SetRegSetKeepsTLS` | failed | failed |
| `PtraceTest.TraceDescendantsAllowed` | failed | failed |
| `PtraceTest.TraceNonDescendantWithCapabilityAllowed` | failed | failed |
| `Seize/PtraceAttachTest.AttachingConvertsGroupStopToPtraceStop/0` | failed | failed |
| `Seize/PtraceAttachTest.AttachingConvertsGroupStopToPtraceStop/1` | failed | failed |
| `TraceExec/PtraceExecveTest.Execve_GetRegs_PeekUser_SIGKILL_TraceClone_TraceExit/0` | failed | failed |
| `TraceExec/PtraceExecveTest.Execve_GetRegs_PeekUser_SIGKILL_TraceClone_TraceExit/1` | failed | failed |

## Ordinary workload performance

Mac release binaries, two alternating-order runs, 64 timed samples per binary per workload. Positive change means more elapsed time.

| Workload | Previous median (ms) | Candidate median (ms) | Change |
| --- | ---: | ---: | ---: |
| memory | 170.455 | 170.755 | +0.18% |
| mmap_fault_unmap | 127.396 | 126.640 | -0.59% |
| file_pread_pwrite | 97.733 | 97.827 | +0.10% |
| fork_wait | 18.590 | 18.579 | -0.06% |
| map_unmap_file | 14.785 | 14.939 | +1.04% |
| map_read_unmap_file | 81.473 | 82.395 | +1.13% |
| fork_shared_file | 15.703 | 15.683 | -0.13% |

Previous executable SHA-256 `5044c4a4a1d45ca86906e898d63d54d9d5b90ca41fcb4f7486f96c886605e798`. Candidate `e81b2dbec49c632c1ef03413fd224764d4dcbe87c14605411b69d6131c92a0c5`. Local logs and the reconciled inventory are in `target/gvisor-ptrace-policy` in the iPad checkout.
