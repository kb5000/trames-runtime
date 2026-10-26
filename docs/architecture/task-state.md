# Shared task state and signal boundaries

`trames-kernel` contains execution-independent Linux task policy. It depends on
the architectural execution contract, Memory and VFS, and has no interpreter,
accelerator, Hypervisor or product dependency. The dependency-boundary check
covers its complete normal dependency graph.

The existing iPad/Core process object now owns a `Signals` value from this
crate. Its dispositions, blocked mask, private pending queue, process pending
queue, alternate stack and frame depth no longer live in the interpreter
composition. The Mac single-task adapter uses the same state and ABI functions.
This is a task-state integration step; the complete process table and executor
scheduler have not moved out of Core yet.

## Ownership and scheduling

Fork copies the blocked mask, alternate stack and active frame depth, starts
with empty queues, and copies dispositions unless `CLONE_SIGHAND` shares the
existing table. `CLONE_THREAD` additionally adopts its thread group's pending
queue. Exec resets caught dispositions, alternate stack and frame depth while
retaining ignored dispositions and the existing pending/mask rules. Core keeps
task-group routing, namespace permissions and stop/continue lifecycle effects.

The signal table keeps its existing object-local mutex and complete-record
exchange. Query-only worker admission uses the same shared table; mutation still
belongs to the owner that can clear all affected private queues. Pending queues
remain task-owner state, without new locks, atomics or worker messages.

Ready-task affinity placement also lives in the common crate. It retains the
existing queue priority and relocates an earlier flexible task when a later
pinned task needs its slot. Host worker lifetime, persistent contexts, VM-local
checkpoints and blocked-task wakeups are unchanged. This extraction does not
introduce another scheduling or resource-service thread.

## Architectural signal delivery

Signal entry and `rt_sigreturn` use `Aarch64State`. The interpreter materializes
its deferred flags only at this cold architectural boundary, then restores the
result; normal execution keeps its existing CPU representation and decode
caches. Hardware already exposes the same architectural state at VM exits.

The shared Linux frame preserves integer registers, PC, interrupted SP, NZCV,
SIMD registers and FP control/status. TLS remains the current task's TLS because
Linux does not place it in this frame. Handler frames are aligned, but returning
to interrupted leaf assembly accepts its temporary non-call-aligned SP. Alternate
stacks, nesting, `SS_AUTODISARM`, blocked standard-signal coalescing and
`SA_RESETHAND` follow the existing runtime ABI.

Frame bytes are published before changing task/register state. Return validates
the address range, PC, FP context header and restored alternate stack before
changing registers. Unit acceptance checks complete-state preservation on failed
publication and malformed return, not just the first restored register.

Memory-fault classification and forced-fault queue selection are shared. A
synchronous fault keeps its precise context over a previously queued asynchronous
signal of the same number; masked or ignored fatal faults terminate rather than
remaining pending indefinitely. Product/backend adapters translate their own
transport exceptions to this Linux policy.

## Hardware acceptance and limits

The Mac adapter now routes its sole task's signal calls and identity queries
through this common state. It supports handlers and return from real BRK,
undefined/privileged instruction, unmapped load/fetch, write protection and
ordered-access alignment faults. Non-repairable hardware aborts must not be
retried as demand mappings. Backend admission/transport failures remain host
errors, rather than being fabricated guest memory faults.

The same original static-musl ELFs run under hardware, the interpreter, pinned
QEMU and native ARM64 Linux. The native Linux oracle covers `SS_AUTODISARM`,
which QEMU omits. The task fixture deliberately clobbers SIMD, FP state and
flags inside a handler, and checks their restoration together with TLS and
integer state. An isolated negative control discards restored SIMD values;
the actual hardware fixture must fail.

The Mac runner is still single-process. Multi-process/thread lifecycle,
clone/exec image integration, external signal/wait routing, shared hardware
mapping providers and full application scheduling remain integration gates.
A stopped sole task waits until the runner's timeout; no periodic polling bus
or new coordinator is created. Host-pressure reclamation and restoration of
live anonymous pages remain separate memory work.

See [execution backends](execution-backends.md) for the three-project target and
[source-bound validation](../validation/kernel-task-boundaries-summary.json)
for this step's local CI and original-ELF evidence.
