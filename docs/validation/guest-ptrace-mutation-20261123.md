# Guest ptrace modification and single stepping — November 23, 2026

Follow-up: [proc memory completion and the remaining upstream ptrace skip](guest-proc-mem-20261123.md).

The remaining twelve original process-debugging gaps are closed. The Mac hardware executor and the iPad product interpreter running locally on the Mac each produced **96 passes and two upstream skips across 98 original gVisor cases in seven suites**. The complete ptrace binary produced **35 passes and one skip** on each executor. Original Google Test XML, requested case identities and upstream executable hashes were checked. No previous native-pass case in this selection became a gap. Reusing the previous inventory outside this selection changes the rolling native-pass gap count from **138 to 126**.

## Implemented behavior

* A debugger can attach or seize an eligible process or individual thread, including an external task admitted by guest credentials and Yama. Voluntary tracing and inherited fork, vfork and clone tracing use the same original task and wait ownership. Nonleader TRACEME uses a separate thread wait record.
* GETREGSET and SETREGSET expose ARM64 general registers, FPSIMD state and TLS. Partial writes preserve the rest of the state, including TLS when replacing general registers. User-mode validation prevents privileged execution state from reaching an executor. Register changes are returned to the original worker before execution; automatic detach on tracer retirement preserves already accepted changes.
* PEEKTEXT/PEEKDATA and POKETEXT/POKEDATA address the original stopped image. Forced debugger access retains mapping protection, ordinary COW and code-cache invalidation. Process-vm copies keep their ordinary permission checks. Memory access uses saved attach credentials, so gaining or dropping a capability later cannot rewrite the original admission.
* GETSIGINFO/SETSIGINFO, signal suppression/substitution and GETSIGMASK/SETSIGMASK retain the selected delivery and its payload. The resumed delivery is consumed once. A synchronous exception reaches a debugger even when the tracee has no handler, allowing a BRK breakpoint to be removed or its PC repaired.
* CONT, SYSCALL, SINGLESTEP, DETACH, KILL, SEIZE/INTERRUPT/LISTEN and the existing syscall/event queries share the stopped task state. FORK joins VFORK, CLONE, EXEC, VFORK_DONE, EXIT, TRACESYSGOOD and EXITKILL options.
* An opened `/proc/PID/mem` retains the exact admitted address space for writes as well as reads. Remote writes use bounded original-mm transfers, including COW of RX text. Writes, partial failures, cancellation and retirement commit the original OFD offset once; positioned operations retain their own offsets. Closing or reusing an FD cannot redirect an accepted write.

No coordinator or resource-service thread is added. Waiting transfers release the execution slot. Ordinary untraced execution allocates no trace state and performs no trace-state mutex operation. The Mac arms ARM single-step exceptions for EL0 through its existing HVF mailbox; the interpreter executes one instruction. Single stepping a syscall stops after its actual completion, including a parked syscall.

## Original gaps closed

| Upstream case | Mac | iPad interpreter |
| --- | --- | --- |
| `ElfTest.PtraceExecuteOnlyBinary` | pass | pass |
| `ExecveTest.BrkAfterBinary` | pass | pass |
| `PtraceTest.AccessVmUsesAttachCreds_CapDroppedAfterAttach` | pass | pass |
| `PtraceTest.AttachParent_PeekData_PokeData_SignalSuppression` | pass | pass |
| `PtraceTest.GetSiginfo_SetSiginfo_SignalInjection` | pass | pass |
| `PtraceTest.PrctlClearPtracerDoesNotAffectCurrentTracer` | pass | pass |
| `PtraceTest.Seize_Interrupt_Listen` | pass | pass |
| `PtraceTest.SetRegSetKeepsTLS` | pass | pass |
| `PtraceTest.TraceDescendantsAllowed` | pass | pass |
| `PtraceTest.TraceNonDescendantWithCapabilityAllowed` | pass | pass |
| `SysretTest.BadRip` | pass | pass |
| `SysretTest.BadRsp` | pass | pass |

The two skips are `KillTest.CanKillAllPIDs` and `PtraceTest.SetYAMAPtraceScope`; both also skip in the native reference.

## Product fixtures and debugger tools

The [standalone guest fixture](../../tests/fixtures/ptrace-observer.rs) builds with:

```sh
rustc --target aarch64-unknown-linux-musl -C linker=rust-lld -O --edition 2021   tests/fixtures/ptrace-observer.rs -o /tmp/ptrace-observer
```

Its `modify` mode writes the child's RX text without changing the parent's private text, replaces registers/PC, steps ALU operations, a load, a COW store and a syscall, checks TRAP_TRACE information, then suppresses a BRK trap and exits with status 42. Its `traceme-thread` mode checks that a voluntary nonleader stop and exit can be waited independently from the process. Both modes are checked on the two executors.

Alpine GDB 15.2 places a software breakpoint in `ptrace_observer::main`, stops there, executes `stepi`, writes x19 to 4660, and continues the workload to its completion marker and normal exit on both executors. This exercises GDB's real `/proc/PID/mem` writes in addition to direct ptrace writes. Hardware breakpoint/watchpoint regsets, SVE/SME debugger regsets and seccomp tracing/checkpoint extensions remain outside this implementation; GDB reports its unavailable hardware breakpoint resources.

## Checks and existing failures

All eight standalone runtime CI stages passed, including formatting, clippy with warnings denied, workspace tests and the release build. The ARM64 iOS FFI compilation passed. Physical iPad deployment is outside this validation.

The additional interpreter kernel conformance target produced 498 passes, four failures and three ignored tests. All four failures reproduced on the exact pre-change runtime `8d2d519be8da324055c1448df2a61d4e60cb7398` and product source snapshot, with the same assertions:

* `process::job_tests::background_nonblocking_read_stops_and_resumes_on_the_only_slot_without_owner`
* `process::job_tests::filtered_tty_control_adoption_retains_original_fd_after_close_and_reuse`
* `process::job_tests::serial_background_write_and_ioctl_waits_wake_on_ignored_continue`
* `workers::tests::thread_group_stop_wait_continue_runs_on_one_slot_without_owner_requests`

These are existing terminal job-control fixture failures, not new ptrace passes or regressions. Their logs remain with the evidence.

## Ordinary workload performance

Each version has 32 timed samples after two warm-up samples, with version order alternated on every pair. Median elapsed milliseconds; positive change means more time.

| Workload | Before | Final candidate | Change |
| --- | ---: | ---: | ---: |
| memory | 178.161 | 177.911 | -0.14% |
| mmap_fault_unmap | 137.042 | 136.759 | -0.21% |
| file_pread_pwrite | 99.503 | 100.206 | +0.71% |
| fork_wait | 19.962 | 19.877 | -0.43% |

No slowdown above 1% was observed in these four untraced workloads. Raw samples and executable/fixture hashes are retained in `performance-final.json`. The earlier cohort and its different candidate hash remain separately recorded.

## Evidence

Local evidence, original per-case XML, reconciled inventory, debugger output and performance samples are under `target/ptrace-mutation` in the iPad checkout. The 98-case Mac batch runner SHA-256 is `71f6cfbc09a83f298e303efc4494e28aa1de1aa4d2c0d0385c058071c7c05d1e`. The final combined guest fixture SHA-256 is `5a802cfb9e72c6a31f4141d752d79fe0ee6c2dc2eab96a4500aa471d0dbc0cef`. The final Mac runner used for nonleader TRACEME, direct stepping and performance is `3e07afac0c900deb65f136e20b7be8076cc4f2831319da45e301607f7cd5871e`; only nonleader TRACEME admission changed after the 98-case batch. That additional path was validated separately on both executors. The performance baseline was rebuilt from the exact pre-change runtime and Mac source snapshot, without modifying the source repositories.
