# Process tracing, exec and proc memory on ARM64

A guest thread-group leader can request tracing by its real parent with `PTRACE_TRACEME`. The tracee worker publishes a register snapshot when it stops. The parent can wait for a traced stop, read the ARM64 general registers or signal mask, continue the child, or detach. A successful exec publishes the new image before the exec stop. Set-ID execution while traced suppresses privilege gain without setting a permanent no-new-privileges flag. Parent retirement releases stopped children and honors the supported exit-kill option. Stop notifications use the original child wait queue and keep job-control and trace events distinct. Both products use this implementation.

`/proc/PID/mem` and the corresponding task path check the opener's filesystem credentials, capability and target dumpability against the original address space. An open file stays bound to that image across exec and exit. Same-image writes use the ordinary guest memory permissions. Remote reads use the target's existing page reporting and wakeup machinery, bounded to 64 KiB per read. The guest worker handles local memory I/O directly.

Two compatibility fixes surfaced after execution progressed through the new stops. Fully anonymous ELF BSS pages use Linux brk permissions. File-backed mapping names in `maps` and `smaps` on the chroot's original mount are displayed relative to the root at proc-file open. The mount identity and a directory-component boundary qualify the prefix. Unrooted readers reuse the existing cached maps. This does not implement live path reconstruction across mount aliases, root changes after opening the proc file, or renames.

## Scope of the tracing interface

The tested relationship starts from a consenting guest process leader. It supports stop signals and exec, ARM64 `NT_PRSTATUS` reads with truncated iovecs, `GETSIGMASK`, `TRACEEXEC`, `EXITKILL`, and zero-signal continue/detach. External attach/seize, enrollment by a nonleader, syscall entry/exit stops, tracing clone/vfork descendants, signal or register changes, and writing another address space are outstanding. Some negative tests verify an error response without exercising a successful attach.

## Verification

The final Mac HVF binary ran 72 unchanged upstream GoogleTest cases across ten suites with two guest CPUs. There were 69 passes, one failure, one timeout and one skip. The failure was `ProcPidMem.DifferentUserAttached`, which requires successful seize. `ExecTest.SUIDExecDoesntGainUIDWithPtracerAttached` timed out. The `ProcPidSmapsTest.GvisorFields` skip matches the native Linux reference. Each completed case was matched against its individual XML result. The guest test binaries and candidate executable were checked against the hashes in the run plan.

Using the previous rolling ledger plus its access-denial recheck, the number of reference-passing cases without a Trames pass fell from 78 to 38 in this category and from 204 to 164 in the full native inventory. These totals include previously unmeasured cases. The whole inventory was not rerun. Seventeen ELF cases that previously timed out now pass.

| Category | Previous gaps | Newly passing | Remaining |
| --- | ---: | ---: | ---: |
| ptrace | 33 | 6 | 27 |
| ELF and interpreter execution | 25 | 19 | 6 |
| ProcPidMem | 11 | 10 | 1 |
| exec | 3 | 2 | 1 |
| syscall return | 3 | 1 | 2 |
| chroot | 1 | 1 | 0 |
| wait | 1 | 1 | 0 |
| signal restart (kill suite) | 1 | 0 | 1 |

On the Mac-hosted iPad interpreter, all 12 selected upstream cases passed individually, including partial and full reads of the general registers, traced exec/wait, BSS permissions, proc memory and the chrooted mapping case. The iOS ARM64 FFI target compiled. All eight local runtime CI stages passed, including the full workspace test suite and release build. Physical iPad behavior was not measured.

<details>
<summary>Remaining reference-passing cases and latest Trames evidence</summary>

| Original case | Latest evidence |
| --- | --- |
| `ExecTest.SUIDExecDoesntGainUIDWithPtracerAttached` | timeout (this candidate) |
| `ElfTest.ExecuteOnlyScriptReadableInterpreter` | failed (previous ledger) |
| `ElfTest.ExecuteOnlyScriptReadableInterpreterEmptyPathFd` | failed (previous ledger) |
| `ElfTest.ExecuteOnlyScriptReadableInterpreterRelativeDirfd` | failed (previous ledger) |
| `ElfTest.PtraceExecuteOnlyBinary` | failed (previous ledger) |
| `ElfTest.UsernsAttachExecuteOnlyBinary` | failed (previous ledger) |
| `ExecveTest.BrkAfterBinary` | timeout (previous ledger) |
| `KillTest.RestartArgumentNotExecutedTwice` | failed (previous ledger) |
| `ProcPidMem.DifferentUserAttached` | failed (this candidate) |
| `PtraceTest.AccessVmUsesAttachCreds_CapDroppedAfterAttach` | unmeasured |
| `PtraceTest.AccessVmUsesAttachCreds_CapGainedAfterAttach` | unmeasured |
| `PtraceTest.AttachParent_PeekData_PokeData_SignalSuppression` | unmeasured |
| `PtraceTest.ExecvePtraceLockStress` | unmeasured |
| `PtraceTest.ExitWhenParentIsNotTracer_Syscall_TraceVfork_TraceVforkDone` | unmeasured |
| `PtraceTest.GetSigMask` | unmeasured |
| `PtraceTest.GetSiginfo_SetSiginfo_SignalInjection` | unmeasured |
| `PtraceTest.PrctlClearPtracerDoesNotAffectCurrentTracer` | unmeasured |
| `PtraceTest.PrctlNotInherited` | unmeasured |
| `PtraceTest.PrctlSetPtracer` | unmeasured |
| `PtraceTest.PrctlSetPtracerDoesNotPersistPastNonLeaderExec` | unmeasured |
| `PtraceTest.PrctlSetPtracerDoesNotPersistPastTracerThreadExit` | unmeasured |
| `PtraceTest.PrctlSetPtracerPersistsPastLeaderExec` | unmeasured |
| `PtraceTest.PrctlSetPtracerPersistsPastTraceeThreadExit` | unmeasured |
| `PtraceTest.PrctlSetPtracerRespectsTracerThreadID` | unmeasured |
| `PtraceTest.PtraceKill` | unmeasured |
| `PtraceTest.SeizeSetOptions` | unmeasured |
| `PtraceTest.Seize_Interrupt_Listen` | unmeasured |
| `PtraceTest.SetRegSetKeepsTLS` | unmeasured |
| `PtraceTest.TraceDescendantsAllowed` | unmeasured |
| `PtraceTest.TraceNonDescendantNotAllowed` | unmeasured |
| `PtraceTest.TraceNonDescendantWithCapabilityAllowed` | unmeasured |
| `PtraceTest.TraceParentNotAllowed` | unmeasured |
| `Seize/PtraceAttachTest.AttachingConvertsGroupStopToPtraceStop/0` | unmeasured |
| `Seize/PtraceAttachTest.AttachingConvertsGroupStopToPtraceStop/1` | unmeasured |
| `TraceExec/PtraceExecveTest.Execve_GetRegs_PeekUser_SIGKILL_TraceClone_TraceExit/0` | unmeasured |
| `TraceExec/PtraceExecveTest.Execve_GetRegs_PeekUser_SIGKILL_TraceClone_TraceExit/1` | unmeasured |
| `SysretTest.BadRip` | failed (previous ledger) |
| `SysretTest.BadRsp` | failed (previous ledger) |

</details>

## Ordinary guest workloads

Each executable ran two alternating series in opposite orders on the same Mac with two guest CPUs. Each series discarded two warm-up pairs and kept 32 pairs. The table pools 64 measured samples per version. Positive values mean longer elapsed time.

| Workload | Previous median (ms) | Updated median (ms) | Change |
| --- | ---: | ---: | ---: |
| memory | 165.586 | 165.952 | +0.22% |
| mmap fault unmap | 121.902 | 121.966 | +0.05% |
| file pread pwrite | 94.574 | 95.086 | +0.54% |
| fork wait | 17.996 | 17.959 | -0.21% |
| map unmap file | 14.118 | 14.155 | +0.26% |
| map read unmap file | 79.339 | 78.803 | -0.68% |
| fork shared file | 15.055 | 14.852 | -1.35% |

Previous executable SHA-256 `eb2a3132c6b8bb57b7647a309a5c4037feafc67677998460db195cd7776cadf6`. Candidate `3bc2308c23ffc9271cb08afe997cfdc21e391a8015c3fbca4988ce818df18e32`.
