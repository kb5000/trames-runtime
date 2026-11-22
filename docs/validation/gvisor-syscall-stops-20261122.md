# Observing ARM64 guest syscalls, signals and exit (2026-11-22)

## Working debugger paths

The Mac hardware executor and the iPad product's interpreter both ran the same ARM64 Linux guest fixture with Alpine's packaged GDB and strace. The interpreter ran locally on the Mac. The fixture has three modes and uses the guest's own parent/child relationship.

| Exercise | Observed on both backends |
| --- | --- |
| strace of the fixture in `workload` mode | One `close(-1) = -1 EBADF`, one three-millisecond `nanosleep` returning zero, completion marker once, exit status zero |
| GDB with `handle SIGUSR1 stop print pass` in `signal` mode | Two distinct signal stops, both reporting signal 10. PC, SP and the stack were readable. Continuing twice delivered the original signals to the child handler exactly twice. The inferior exited normally. |
| Exit observation in the default mode | A parent received event 6 before reaping each voluntary tracee. The messages for `exit(37)`, `exit_group(38)` and self-directed SIGKILL were 9472, 9728 and 9. Each final wait returned the same status. |

The [fixture](../../tests/fixtures/ptrace-observer.rs) builds as a standalone `aarch64-unknown-linux-musl` program. For GDB, load the fixture, set `args signal`, set the signal handling above, then run and continue at both stops. For strace, run `strace -e trace=close,nanosleep ./ptrace-observer workload`.

## Implementation and limits

* A voluntary tracee's own worker retains the decoded syscall on entry, resumes its original submission and publishes the result after completion. A queued or retried syscall keeps its phase. The immutable ARM64 syscall snapshot includes PC, SP, audit architecture, syscall number and six entry arguments, or the return value and Linux errno flag. A short user buffer only gets the prefix it requested.
* Exit observation retains the actual pending retirement and its wait status. The parent can query the event before resuming the child. An untraced task keeps its ordinary worker and allocates no debugger state.
* A selected signal retains its original payload and sender identity through continue, syscall tracing or detach. Normal signal delivery takes the returned record once. A later arrival of the same signal still produces its own stop.
* GDB’s native `catch syscall` also requests fork, vfork and clone options in one transaction. The runtime rejects the unsupported mask. Stock strace is the verified frontend for syscall observation. GDB's signal, stack and register paths above work independently.

## Compatibility

155 distinct original upstream tests ran on Mac against the native ARM64 reference. There were 122 passes, 19 failures, 13 skips and one timeout. Each non-timeout status was checked against its per-case Google Test XML. All 32 previous process-debugging gaps were included. The restart test now passes, including syscall arguments that resemble Linux internal restart codes. The eight previously unmeasured cases all produced results. The remaining 31 comprise 19 failures, 11 skips and one timeout. Two other conditional skips in the 155-case selection are outside that native-pass category.

The rolling inventory across all suites changes from 158 to 157 native-pass gaps. Only the 155 selected cases were replaced in that inventory. The interpreter also passed five original focused cases individually. All eight local runtime CI stages passed and the ARM64 iOS FFI target compiled.

| Remaining case | Result |
| --- | --- |
| `ExecTest.SUIDExecDoesntGainUIDWithPtracerAttached` | timeout |
| `ElfTest.PtraceExecuteOnlyBinary` | failed |
| `ExecveTest.BrkAfterBinary` | failed |
| `ProcPidMem.DifferentUserAttached` | failed |
| `PtraceTest.AccessVmUsesAttachCreds_CapDroppedAfterAttach` | failed |
| `PtraceTest.AccessVmUsesAttachCreds_CapGainedAfterAttach` | failed |
| `PtraceTest.AttachParent_PeekData_PokeData_SignalSuppression` | failed |
| `PtraceTest.ExecvePtraceLockStress` | skipped |
| `PtraceTest.ExitWhenParentIsNotTracer_Syscall_TraceVfork_TraceVforkDone` | failed |
| `PtraceTest.GetSiginfo_SetSiginfo_SignalInjection` | failed |
| `PtraceTest.PrctlClearPtracerDoesNotAffectCurrentTracer` | skipped |
| `PtraceTest.PrctlNotInherited` | skipped |
| `PtraceTest.PrctlSetPtracer` | skipped |
| `PtraceTest.PrctlSetPtracerDoesNotPersistPastNonLeaderExec` | skipped |
| `PtraceTest.PrctlSetPtracerDoesNotPersistPastTracerThreadExit` | skipped |
| `PtraceTest.PrctlSetPtracerPersistsPastLeaderExec` | skipped |
| `PtraceTest.PrctlSetPtracerPersistsPastTraceeThreadExit` | skipped |
| `PtraceTest.PrctlSetPtracerRespectsTracerThreadID` | skipped |
| `PtraceTest.SeizeSetOptions` | failed |
| `PtraceTest.Seize_Interrupt_Listen` | failed |
| `PtraceTest.SetRegSetKeepsTLS` | failed |
| `PtraceTest.TraceDescendantsAllowed` | failed |
| `PtraceTest.TraceNonDescendantNotAllowed` | skipped |
| `PtraceTest.TraceNonDescendantWithCapabilityAllowed` | failed |
| `PtraceTest.TraceParentNotAllowed` | skipped |
| `Seize/PtraceAttachTest.AttachingConvertsGroupStopToPtraceStop/0` | failed |
| `Seize/PtraceAttachTest.AttachingConvertsGroupStopToPtraceStop/1` | failed |
| `TraceExec/PtraceExecveTest.Execve_GetRegs_PeekUser_SIGKILL_TraceClone_TraceExit/0` | failed |
| `TraceExec/PtraceExecveTest.Execve_GetRegs_PeekUser_SIGKILL_TraceClone_TraceExit/1` | failed |
| `SysretTest.BadRip` | failed |
| `SysretTest.BadRsp` | failed |

The eleven conditional skips require a Yama mode absent from this guest. The set-ID exec test timed out waiting for the attach handshake. Other failures cover external attach/seize, traced descendant and nonleader events, register or memory modification, and signal substitution. The ELF heap case reaches the register-change assertion. Its failure alone does not establish an incorrect initial heap address.

## Ordinary guest workloads

Two interleaved release runs in opposite order, two warm-up pairs excluded from each, 64 timed samples per version per workload. Positive change means higher elapsed time.

| Workload | Previous median (ms) | Candidate median (ms) | Change |
| --- | ---: | ---: | ---: |
| memory | 169.996 | 169.952 | -0.03% |
| mmap_fault_unmap | 124.772 | 123.983 | -0.63% |
| file_pread_pwrite | 95.836 | 97.102 | +1.32% |
| fork_wait | 18.402 | 18.342 | -0.33% |
| map_unmap_file | 14.410 | 14.423 | +0.10% |
| map_read_unmap_file | 79.333 | 79.525 | +0.24% |
| fork_shared_file | 15.205 | 15.289 | +0.55% |

Previous signed Mac executable SHA-256 `dd94c92d7a203435ce4ab8828ae572a46578b64a1624d2e19e36e7717332f8f1`. Candidate `5044c4a4a1d45ca86906e898d63d54d9d5b90ca41fcb4f7486f96c886605e798`. Raw local evidence is under `target/gvisor-syscall-stops` in the iPad checkout.
