# Parent debugger stops and vfork completion

## November 23, 2026

The Mac hardware executor ran 241 original gVisor cases in 17 suites. The selection includes all 25 open process-debugging cases from the preceding inventory. Five closed. The final selection contains 211 passes, 19 failures, ten skips and one timeout. No previous pass became a native-pass gap. The rolling native-pass gap count across all categories changed from 151 to 146. Six neighboring PIDFD_THREAD cases that pass on native Linux remain skipped in the broader inventory. They are outside the original 25. Only the selected cases were rerun. The builds, case selection, original test executable hashes and completed Google Test XML results were checked locally.

| Newly passing upstream case | Mac | iPad product interpreter on Mac |
| --- | --- | --- |
| `ProcPidMem.DifferentUserAttached` | pass | pass |
| `PtraceTest.AccessVmUsesAttachCreds_CapGainedAfterAttach` | pass | pass |
| `PtraceTest.SeizeSetOptions` | pass | pass |
| `Seize/PtraceAttachTest.AttachingConvertsGroupStopToPtraceStop/0` | pass | pass |
| `Seize/PtraceAttachTest.AttachingConvertsGroupStopToPtraceStop/1` | pass | pass |

## Guest behavior

The guest parent can attach to or seize the leader of its own child process, interrupt a seized child, inspect its stopped state, listen for job-control changes and resume or detach. The tracee publishes its own stop through the existing execution worker and its parent consumes a wait event. Job control and debugger stops retain separate state. Resuming one traced task leaves the rest of the stopped group under job control.

The checks for reading a stopped child bind the original attach credentials and the current credentials to the same observed memory image. A capability gained after attachment cannot grant access to a child that has since disabled dumpability. Holding the capability only at attachment still differs from Linux for later access to such a child.

The vfork completion object retains the child PID translation through memory release, including in a nested PID namespace. When a traced parent requests VFORK_DONE, its worker publishes event 5 at completion. Switching from CONT to SYSCALL at that stop exposes the clone return before the parent executes another instruction.

## Executed checks

The [guest fixture](../../tests/fixtures/ptrace-observer.rs) runs as a standalone aarch64-unknown-linux-musl binary. The following checks ran locally on the Mac hardware executor and iPad product interpreter.

| Exercise | Observed result |
| --- | --- |
| `listen` | The child stopped before seizure. Sending SIGCONT before LISTEN and sending it after LISTEN both produced a second wait event. The detached child exited with status 42 in both runs. |
| `vfork-done` | With TRACEVFORKDONE enabled, child exit and successful exec each produced event 5. GETEVENTMSG, the clone syscall exit stop, and the natural parent all reported the same guest child PID. Both release paths also passed in a nested PID namespace on both executors. |
| Packaged strace | One failing close, a successful nanosleep and normal exit. |
| Packaged GDB | Two distinct SIGUSR1 stops, readable registers and stack, two deliveries to the handler and normal exit. |
| Exit notification | exit, exit_group and fatal self-signal yielded the expected TRACEEXIT message and final wait status. |

All eight local runtime CI stages passed. The ARM64 iOS FFI passed cargo check. Physical iPad deployment was outside this run.

## Remaining original cases

The full upstream ptrace binary produced 20 passes, 15 failures and one skip. The combined VFORK/VFORK_DONE test also requires automatic tracing of the new grandchild and distinct tracer and natural-parent wait rights. The standalone VFORK_DONE checks above cover the completion half. The upstream SEIZE/INTERRUPT/LISTEN case requires a successful word write before reaching LISTEN. The set-ID exec timeout occurs after sibling attachment returns ENOSYS.

| Original case | Final result | Dependency observed |
| --- | --- | --- |
| `ExecTest.SUIDExecDoesntGainUIDWithPtracerAttached` | timeout | Sibling attach returned ENOSYS before the exec handshake. |
| `ElfTest.PtraceExecuteOnlyBinary` | failed | Writing a word in the stopped process. |
| `ExecveTest.BrkAfterBinary` | failed | Replacing the stopped register set. |
| `PtraceTest.AccessVmUsesAttachCreds_CapDroppedAfterAttach` | failed | Reading and writing a newly non-dumpable image after the tracer drops its capability. |
| `PtraceTest.AttachParent_PeekData_PokeData_SignalSuppression` | failed | Attaching to the parent, writing memory and suppressing a signal. |
| `PtraceTest.ExitWhenParentIsNotTracer_Syscall_TraceVfork_TraceVforkDone` | failed | VFORK auto-attachment and separate tracer and natural-parent waits for the grandchild. |
| `PtraceTest.GetSiginfo_SetSiginfo_SignalInjection` | failed | Replacing the selected signal information and delivery. |
| `PtraceTest.PrctlClearPtracerDoesNotAffectCurrentTracer` | failed | A designated external tracer, its wait ownership and lifetime. |
| `PtraceTest.PrctlSetPtracer` | failed | A designated external tracer, its wait ownership and lifetime. |
| `PtraceTest.PrctlSetPtracerPersistsPastLeaderExec` | failed | A designated external tracer, its wait ownership and lifetime. |
| `PtraceTest.PrctlSetPtracerPersistsPastTraceeThreadExit` | failed | A designated external tracer, its wait ownership and lifetime. |
| `PtraceTest.PrctlSetPtracerRespectsTracerThreadID` | failed | A designated external tracer, its wait ownership and lifetime. |
| `PtraceTest.Seize_Interrupt_Listen` | failed | Writing a word in the stopped process. |
| `PtraceTest.SetRegSetKeepsTLS` | failed | Replacing the stopped register set. |
| `PtraceTest.TraceDescendantsAllowed` | failed | Attaching to both threads of a grandchild. |
| `PtraceTest.TraceNonDescendantWithCapabilityAllowed` | failed | A capability-authorized non-parent debugger. |
| `TraceExec/PtraceExecveTest.Execve_GetRegs_PeekUser_SIGKILL_TraceClone_TraceExit/0` | failed | TRACECLONE inheritance, per-thread waits and nonleader exec. |
| `TraceExec/PtraceExecveTest.Execve_GetRegs_PeekUser_SIGKILL_TraceClone_TraceExit/1` | failed | TRACECLONE inheritance, per-thread waits and nonleader exec. |
| `SysretTest.BadRip` | failed | Replacing the stopped register set. |
| `SysretTest.BadRsp` | failed | Replacing the stopped register set. |

## Ordinary Mac workload performance

Median elapsed time in milliseconds. Each column pools 64 timed samples across two interleaved runs in opposite order after removing warm-up samples. Positive change means more elapsed time.

| Workload | Previous | Candidate | Change |
| --- | ---: | ---: | ---: |
| memory | 204.708 | 204.069 | -0.31% |
| mmap_fault_unmap | 160.910 | 161.401 | +0.30% |
| file_pread_pwrite | 111.628 | 111.382 | -0.22% |
| fork_wait | 23.537 | 23.797 | +1.11% |
| map_unmap_file | 17.468 | 17.603 | +0.77% |
| map_read_unmap_file | 104.055 | 103.755 | -0.29% |
| fork_shared_file | 19.112 | 19.202 | +0.47% |

Previous Mac runner SHA-256 `e81b2dbec49c632c1ef03413fd224764d4dcbe87c14605411b69d6131c92a0c5`. Candidate `c28599ee0c837f2dc3ce3b49af1534d5edf4679f6c1cb37d88e1aae1715dfb1f`. The raw evidence is in `target/gvisor-parent-stops` in the iPad checkout.
