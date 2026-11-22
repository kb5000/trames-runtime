# Debugger wait ownership and nonleader exec

On November 23, 2026 the Mac hardware executor ran 241 original gVisor cases from 17 suites, including all 20 outstanding process-debugging cases. Eight of the 20 now pass, and the other twelve fail. Across the 241 cases, 219 passed, twelve failed, ten skipped, and none timed out. All 211 previous passes remained green. The rolling count of gaps among cases that passed on native Linux decreased from 146 to 138. This uses prior results outside the 241-case selection.

## Implementation

A nominated debugger and a debugger following a clone or vfork get their own wait records. A debugger can observe an exit repeatedly with WNOWAIT. Consuming that exit, detaching or retiring the debugger releases the deferred natural-parent notification. The natural parent receives the final wait status and accounts for the child once. Debugger records retain the identity of the original thread through retirement.

A nonleader exec prepares its image, publishes the retiring leader’s exit event when requested, then releases its CPU and group custody. Acknowledging the stop wakes the original exec caller by TID. The replacement inherits the group PID and reports its former TID in the exec event. Competing exec requests share the pending acknowledgement. Cancellation releases the hold. The regular execution workers and wait queues deliver these events.

The additional observer modes support lifecycle events for explicitly nominated tracers and inherited tracees. Admission still checks guest credentials. These modes do not grant additional access to memory or register contents. Traced set-ID exec suppresses privilege elevation.

## Upstream cases newly passing on both executors

All eight passed separately on the Mac hardware executor and on the iPad product interpreter running locally on the Mac. No physical iPad was used.

- `ExecTest.SUIDExecDoesntGainUIDWithPtracerAttached`
- `PtraceTest.ExitWhenParentIsNotTracer_Syscall_TraceVfork_TraceVforkDone`
- `PtraceTest.PrctlSetPtracer`
- `PtraceTest.PrctlSetPtracerPersistsPastLeaderExec`
- `PtraceTest.PrctlSetPtracerPersistsPastTraceeThreadExit`
- `PtraceTest.PrctlSetPtracerRespectsTracerThreadID`
- `TraceExec/PtraceExecveTest.Execve_GetRegs_PeekUser_SIGKILL_TraceClone_TraceExit/0`
- `TraceExec/PtraceExecveTest.Execve_GetRegs_PeekUser_SIGKILL_TraceClone_TraceExit/1`

## Outstanding original cases

| Original case | Operation at issue |
| --- | --- |
| `ElfTest.PtraceExecuteOnlyBinary` | Writing a word in an execute-only mapping. |
| `ExecveTest.BrkAfterBinary` | Replacing registers, including PC or SP. |
| `PtraceTest.AccessVmUsesAttachCreds_CapDroppedAfterAttach` | Accessing nondumpable memory with a capability held only at attachment. |
| `PtraceTest.AttachParent_PeekData_PokeData_SignalSuppression` | Attaching to the parent, writing a word, and controlling signal delivery. |
| `PtraceTest.GetSiginfo_SetSiginfo_SignalInjection` | Replacing signal information and injecting a signal. |
| `PtraceTest.PrctlClearPtracerDoesNotAffectCurrentTracer` | Opening the process memory file after withdrawal of the nomination. |
| `PtraceTest.Seize_Interrupt_Listen` | Writing the child’s control variable with POKEDATA. |
| `PtraceTest.SetRegSetKeepsTLS` | Writing the general register set while preserving TLS. |
| `PtraceTest.TraceDescendantsAllowed` | Attaching to either thread of an undesignated grandchild. |
| `PtraceTest.TraceNonDescendantWithCapabilityAllowed` | Capability-based attachment to an undesignated sibling. |
| `SysretTest.BadRip` | Replacing registers, including PC or SP. |
| `SysretTest.BadRsp` | Replacing registers, including PC or SP. |

## Validation

Local runtime CI passed all eight stages. The iOS ARM64 FFI passed its target check. The thread-clone fixture verified distinct thread and process exit records on both executors. Packaged GDB observed two SIGUSR1 stops, read registers and a backtrace, and resumed to normal exit. Packaged strace observed the expected failing close and successful nanosleep on both executors.

## Ordinary Mac workloads

Each column is the median of 64 timed samples from two interleaved runs in opposite order, excluding warm-up. Values are milliseconds. Positive change means longer elapsed time.

| Workload | Previous | Candidate | Change |
| --- | ---: | ---: | ---: |
| memory | 180.052 | 180.096 | +0.02% |
| mmap_fault_unmap | 143.495 | 143.577 | +0.06% |
| file_pread_pwrite | 104.429 | 104.125 | -0.29% |
| fork_wait | 20.866 | 20.787 | -0.38% |
| map_unmap_file | 15.687 | 15.648 | -0.25% |
| map_read_unmap_file | 89.675 | 89.321 | -0.39% |
| fork_shared_file | 17.242 | 17.091 | -0.88% |

Previous Mac runner SHA-256 `c28599ee0c837f2dc3ce3b49af1534d5edf4679f6c1cb37d88e1aae1715dfb1f`. Candidate `433ad83332434b7a7c171cb61d04d9893032f488475a5740d89db19f11f8941d`. Raw local evidence is under `target/gvisor-wait-handoff` in the iPad checkout.
