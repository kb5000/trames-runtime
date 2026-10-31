# Shared Linux runtime and execution backends

The accepted target is three projects: one common Linux userspace runtime, the
iPad interpreter product, and an Apple Silicon Mac hardware-execution product.
Work starts in this workspace so boundaries can be checked before repository
extraction. [Issue #44](https://github.com/kb5000/trames/issues/44) tracks the
remaining integration and extraction gates. This foundation is not feature
parity between the Mac bring-up runner and the iPad application.

## Current boundaries

| Component | Responsibility |
| --- | --- |
| `trames-execution` | AArch64 architectural state, register access, advertised features and honest instruction-count availability. No dependencies, decoder or OS VM. |
| `trames-kernel` | Shared task signal state/ABI, fault policy and ready-task affinity placement. No interpreter or host execution transport. |
| `trames-linux`, `trames-elf`, `trames-memory`, VFS/network/storage | Shared Linux syscall and image ABI, virtual mappings and actual byte ownership. No interpreter/native-accelerator dependency. |
| `trames-cpu` and current `trames-core`/iPad composition | Existing interpreter, decoded state and product integration. Core's task/signal scheduler still needs its execution dependency extracted. |
| `trames-hvf`, `trames-mac` | Thread-affine Hypervisor transport and single-process Mac bring-up CLI. Hardware CPU execution; common Linux syscalls and process-entry stack. |

Task-state integration moves signal ownership, dispositions/queues,
alternate stacks and architectural frame entry/return into `trames-kernel`,
used by both Core and the Mac adapter. Real hardware fault handlers now recover
through that shared code. [Task-state boundaries](task-state.md) describes the
completed extraction and the process/scheduler work that remains.

`scripts/check-execution-boundaries.py` checks normal transitive dependencies.
The bridge's opt-in SHA-256 service is platform-neutral host functionality;
keeping it in `trames-accel` previously pulled native instruction helpers into
the entire VFS/Linux graph. Its implementation now lives in the bridge and the
old accelerator API re-exports it. Algorithms and wire accounting are unchanged.

Linux dispatch is generic over register access, rather than `trames_cpu::Cpu`.
The interpreter implements that small interface without changing normal slices,
deferred flags or decode caches. Architectural state is materialized only at an
explicit handoff; a regression preserves deferred carry, SIMD, TLS, FP state and
resume PC. The shared Linux stack builder receives the executor's HWCAP values
and caller-supplied extension auxv entries. Mac must not advertise the
interpreter's larger emulated ISA. Hardware reports instruction count as
unavailable; it does not invent an exact software instruction budget.

## External native completions

An asynchronous native producer retains the actual eventfd object, independently
of its descriptor number. A shared producer lease marks that event as an external
source while a live descriptor still refers to it. Plain guest eventfds do not
prevent deadlock detection; closing/reusing a descriptor does not make an old
callback signal its replacement. Cloning a callback shares the existing lease,
without changing per-frame liveness counters.

Completion uses the event counter's ordinary readiness subscriptions for workers
and unparks the joined owner captured when it created the native producer. The
park token survives completion between the final readiness check and idle wait.
With no native sockets to wait on, the joined scheduler parks until completion
or its existing deadline instead of sleeping in one-millisecond increments. Mixed
native-socket waits retain the existing bounded network wait. No new service
thread, polling bus or guest-wide lock is introduced. This fixes FFmpeg reporting
`all virtual processes are blocked without an event source` while VideoToolbox
still owns an outstanding hardware decode.

## Mac hardware path

The Mac adapter creates a hardware VM/vCPU object without booting a Linux kernel,
firmware, initramfs or virtual device stack. Guest ARM64 runs at EL0. A small EL1
exception vector returns SVC and page faults to the host Linux implementation.
Four-level guest page tables preserve Linux's 4 KiB mappings independently of
the host's 16 KiB physical allocation granule. Host buffers are never executable;
the signed Mac executable needs the Hypervisor entitlement, not a JIT entitlement.

The vCPU remains on its creator thread. A virtual timer bounds each run, with no
polling message bus or service thread. A timer may exit after EL0 entered an EL1
exception vector but before its HVC. The adapter must recover the saved EL0
PC/PSTATE/exception in that case; treating the vector PC as EL0 would resume at
an inaccessible kernel address. The long memory fixture exposed this race.

The first access binds physical bytes to the existing Memory page, replacing
its earlier byte owner; there is no permanent second guest RAM image. Canonical
permissions, first-write quota admission and private COW remain in Memory.
Hardware runs while that Memory is exclusively owned, with no Rust byte slice
or concurrent View/pin spanning execution. Shared providers/pins that cannot
meet this contract are rejected explicitly. Host accesses use the established
SharedPage guards. Stopped hardware writes publish existing data, exclusive and
code invalidation state at the execution boundary, not on ordinary instructions.

Private file shadows preserve the backing until COW and refresh after backing
changes. Fork byte owners force a new physical binding before a parent write.
Partial unmap, protection and discard retire stage-one aliases before stage-two
unmap and physical release. Empty page tables retire and guest physical addresses
are reused. The sparse host allocation is independent of the configured RAM cap.

Instruction-cache maintenance applies only to initialized executable pages.
Applying it to the entire data RAM range prematurely populated that memory and
raised the measured 64 MiB fixture's peak physical footprint from roughly
76–79 MiB to roughly 141 MiB. An isolated negative control restores that mistake
and the physical-footprint test rejects it.

## Reclaimable physical memory

A RAM limit or low initial footprint is insufficient. The common runtime must
return released storage while the runtime/VM remains alive, and preserve data
that remains valid. These are separate responsibilities:

- Unmap, heap shrink, discard and exit retire actual byte owners. Cached
  preparation cannot extend an obsolete page's lifetime after its last View.
- A physical host granule is reclaimable only after all its 4 KiB byte/slot
  owners finish. Fork, pins and active snapshots retain their legitimate leases.
- Slot creation/final retirement uses an object-local metadata lock. Ordinary
  CPU/native loads and stores retain the existing ARM/region model.
- Linux punches empty granules in the shared memfd. Darwin marks them reusable
  and reactivates them before publishing a new slot. A partially occupied arena
  no longer keeps every previously touched granule charged until whole-arena drop.
- A unique quiescent snapshot retires unmapped/discarded frames and affected CPU
  aliases while retaining incremental preparation for surviving pages.

The existing interpreter-memory test fills 64 MiB, keeps one host granule in
every 1 MiB arena, frees the rest, and verifies three reuse cycles. On this Mac,
physical footprint falls from about 70 MiB to 8 MiB; the old implementation stays
near 70 MiB and fails. This checks OS accounting, not just the guest quota.

The actual static-musl hardware guest fills 64 MiB, blocks for a host footprint
sample, discards the range, verifies zero refill, unmaps and repeats without
process restart. A final private-file mapping verifies that COW does not alter
the file and discard restores its original contents. Current samples fall from
about 76–79 MiB populated to 13 MiB discarded. Remaining metadata/allocator
overhead is visible; these are bounded correctness probes, not product throughput
or whole-application memory guarantees.

Memory-pressure reclamation of reconstructible caches and live anonymous paging
remain separate gates. `free()` does not itself tell the kernel that an allocator
has returned a page. Still-live anonymous bytes cannot be discarded: reclaiming
their RAM needs preserved contents and a correct fault-recovery path. Host
pressure notifications must use existing host/event infrastructure, without an
extra coordinator thread or ordinary-access barriers.

## Build and validation

On Apple Silicon macOS, run `bash scripts/build-mac.sh` and then
`target/release/trames-mac-run --rootfs <verified-Alpine-archive> /bin/busybox echo hello`.
The archive uses the existing pinned distribution verification. A host static
ARM64 ELF can be passed directly without `--rootfs`. The same ELF loader and
Linux stack/syscall implementation serve both products.

The hardware entry example additionally verifies real SVC entry, sparse access,
resumed registers, fork COW, write protection and live VM reclamation. Sign its
executable with `apps/macos/Trames.entitlements` before running it. The original
musl memory fixture runs against the hardware backend, interpreter and independent
native Linux semantic oracle. `tests/integration/mac-execution.py` samples the
live child's physical footprint and rejects premature data-RAM population.

Full local CI precedes pushing. Preserve unchanged passing results; after a
test-only waiting correction, rerun that case and affected TSan checks rather
than repeating unrelated CPU/network/graphics acceptance. An older persistent
wait test cancelled after a fixed number of control checks; under TSan load that
could precede a reader's completion. Its guest now acknowledges both completed
reads before cancellation, retaining the original FD-reuse/cohort assertions.

The [source-bound validation summary](../validation/execution-backends-summary.json)
records the complete 80-stage native ARM64 Linux workflow, 71 passed iPad
simulator tests with one existing opt-in skip, hardware and interpreter memory
measurements, negative controls and the scoped test-only follow-ups. Physical
iPad release acceptance remains a separate gate.

## Remaining integration and repository extraction

The Mac runner currently covers one process, private mappings and shared signal
frame/state semantics. Common process scheduling and signal routing, clone/exec,
shared mapping/provider export, native
syscall admission and full application integration must move behind the executor
boundary before feature-parity claims or independent repository releases.
Hardware and interpreter capabilities/interrupt accounting remain distinct.

Keep the current iPad runtime as the reference while migrating these gates. After
both products run through the common task/memory model, extract the common
runtime, iPad product and Mac product into independently buildable repositories,
pin dependencies and preserve source pairing. Do not fork Linux semantics into
two product copies or infer completion from a renamed crate/backend selector.

## Guest and compositor clocks

A Linux session with Wayland uses the server's shared monotonic origin. The
server retains that origin across commands in its namespace. Input receipt and
presentation acknowledgements are timestamped against it before entering the
compositor command queue. Host uptime, UIKit event epochs and frontend timestamps
must not be forwarded as guest monotonic milliseconds: GTK clients reconstruct
input timestamps using their own `CLOCK_MONOTONIC`, including 32-bit wraparound.
A standalone native compositor keeps caller-supplied timestamps until it is
bound to a guest clock. This preserves native peer and presentation tests.

## Host input during indefinite waits

An owner-side ppoll/pselect or epoll wait can depend on host standard input even
when no PTY or native socket remains. The scheduler queries accepted poll/select
OFD identities and armed epoll watches before diagnosing an event-source deadlock.
It does not re-import mutable guest fd arrays, consume edge/one-shot events, or
assume every poll is external merely because fd 0 exists. Ordinary internal-pipe
waits retain the original deadlock behavior. This is shared Linux/session policy
for both interpreter/iPad and hardware/Mac adapters; it adds no platform branch,
resource thread, or new polling mechanism.

A regression covers infinite ppoll, pselect, epoll_pwait and epoll_pwait2 followed
by delayed input, mutation of an already accepted guest poll buffer, and an
internal-pipe control. Real Mac window acceptance also verifies that closing the
last native windows leaves the parent shell able to wait for and read new input.


## Resource scope during interactive execution

Anonymous and open-unlinked inodes have no directory-tree membership. Path
lookup returns immediately for them, and their metadata mutations do not commit
a persistent namespace. A memfd resize uses its shared-memory budget without
scanning persistent disk usage. A linked resize checkpoints its owning
filesystem, so named tmpfs buffers cannot serialize the persistent root's
manifest. Inode admission collects expired weak handles only when the node
limit is reached; the exact live-node quota remains enforced. Failure-injection
tests keep the root manifest unwritable while exercising anonymous and tmpfs
operations, and verify named persistent writes still report commit failures.

Timer deadline discovery keeps a membership-versioned index of unique weak
timer objects. Scheduler queries read current deadlines from those objects;
rearm/disarm never copies or caches a deadline. Closing/reusing descriptors,
fork and CLONE_FILES invalidate membership through the existing FD identity.
An empty index avoids walking unrelated descriptors. This creates no polling
bus, service thread or additional timer authority, and weak entries cannot keep
a closed timer alive.


## Optional SME streaming context (2026-10-29)

`Aarch64State` remains 816 bytes. `Cpu` has optional SME hooks with unsupported
interpreter defaults; iPad gains no capability bit, per-task matrix allocation,
or platform dependency. The bounded extended register profile holds up to
64-byte streaming vectors, predicates, ZA and one ZT register. A hardware backend
owns the optional buffer and supplies its actual supported vector lengths.
Non-streaming SVE and SME FA64/FFR are outside this profile.

The shared session implements Linux SME vector-length prctl, deferred/inherited
exec policy, CLONE_VM ZA/TPIDR2 clearing and fork preservation. Unused prctl
arguments are ignored, matching Linux. Syscall return clears streaming mode,
preserves low vector lanes and retains live ZA/ZT. Exec resets register state.
The signal kernel emits and validates streaming SVE, ZA, ZT and TPIDR2 records;
large contexts use Linux's contiguous `extra_context` layout. Handlers start
with SM/ZA/TPIDR2 cleared. Full frame validation precedes task/register changes.
An SME image receives AT_MINSIGSTKSZ=8192 for the bounded profile. Existing
non-SME signal and interpreter behavior remains available without these records.
Debugger regsets are not implemented by the session's existing ptrace boundary.

The Mac product validates actual EL0 matrix instructions, private context
permissions, preemption and host-thread migration. Its Linux fixture additionally
checks streaming signal restoration after a clobbering handler, fork, pthread
creation and exec. The common ABI follows the
[Linux SME documentation](https://docs.kernel.org/arch/arm64/sme.html) and
[signal-record layout](https://github.com/torvalds/linux/blob/master/arch/arm64/include/uapi/asm/sigcontext.h).


## Bounded address-space checkpoint batches (2026-10-29)

Mapping checkpoints still quiesce their actual mm/backing closure, including
in-flight native and resource operations. A backend may publish a retained
`ExecutionInterrupt` for its worker assignment. Pause and publication share a
per-domain object lock, closing both pre-entry orders; no lock covers guest
execution or ordinary memory. The handle carries only exit authority and must
become inert before destruction or CPU identifier reuse. Interpreters return
`None` and retain their existing polling path.

Once these views have drained, an optional `run_quiesced` hook lets the existing
owner coalesce consecutive mapping syscalls in a 250 microsecond window shared
by all requesters in that checkpoint. This requires every admitted cohort job
to be in the checkpoint, reserving logical CPU capacity while unrelated address
spaces continue on the normal path. Mac supplies the remaining window duration to its hardware timer. Calls remain in the common Linux kernel and each accepted
mapping operation completes even when the window or epoch ends. All non-mapping
syscalls, native exits and faults are stored on the same job for ordinary worker
dispatch, or joined-kernel handling on stop, exactly once. Native bodies do not
run in this batch. A hardware-borrow yield can retry and park on its normal
worker. Preempted peers are requeued before mapping requesters. No extra worker,
resource service, polling bus or guest memory policy is introduced.

Checkpoint metrics separate quiescence, owner queue delay, commit, Linux calls,
view rebuild, resume and exclusive CPU time. Quiescence histograms and batch
counts distinguish shorter waits from excessive stop/wake cycles. Times can
overlap across independent domains; summing them is not session wall time.
Measured tradeoffs and the reproducible fixture are in the Mac
[execution design](https://github.com/kb5000/trames-mac/blob/main/docs/architecture/execution-backends.md).


## Worker wakeups and optional clock vDSO (2026-10-29)

The shared run queue retains its existing mutex and blocking event sources.
Each idle worker registers its slot under that mutex before atomically releasing
it in a condition-variable wait. Publication selects sleeping slots that can run
the ready jobs, honoring initial placement and affinity and preferring the last
worker. Each selected slot receives one notification. A claimant passes remaining
ready work on, covering flexible/pinned placement overlap. When no ready task is
eligible, one idle worker still observes I/O, deadline or control changes. Stop
wakes every registered sleeper. Existing host-event wakeups remain; no polling
bus, resource-service thread or lock around guest/native bodies is introduced.

`Cpu::clock_sample` is optional and defaults to unsupported. A backend that
supplies it must expose the same counter domain and frequency as guest
`CNTVCT_EL0`, including migration and host sleep behavior. Such images receive
an AArch64 ELF vDSO through `AT_SYSINFO_EHDR`, with versioned `LINUX_2.6.39`
symbols and ordinary guest RX code / read-only calibration pages. The common
Linux/session code owns the ELF, stack ABI, permissions and clock semantics;
platform counter APIs stay in the executor. The iPad interpreter advertises no
vDSO and retains its existing syscall behavior and capability profile.

The ELF has one zero-based RX `PT_LOAD`; the adjacent read-only calibration
page is a separate mapping. This also supports older glibc vDSO registration,
whose [zero-address sentinel](https://github.com/bminor/glibc/blob/glibc-2.31/elf/setup-vdso.h)
miscomputes the load bias if a second nonzero `PT_LOAD` follows it. A real
glibc-interpreted PIE is a regression, alongside static/dynamic musl lookup.

Initialization and exec bind the counter to the same session `Instant` origin
used by syscalls and Wayland. Eight bounded calibration brackets select the
narrowest sample; a bracket wider than one microsecond disables the fast clock.
While tasks are stopped, initialization preserves the data page's guest
permissions and skips a removed/replaced optional mapping. No recurring updater
or shared fast-path lock is needed. The generated machine code is checked in;
`crates/trames-linux/src/vdso/rebuild.py` reproduces it with Clang and rust-lld,
without adding an assembler dependency to normal Cargo builds.

The current session's monotonic IDs 1/4/6/7 use a counter read and integer
conversion, with quotient/remainder arithmetic before multiplication to avoid
long-uptime overflow. Realtime IDs 0/5 retain the syscall so host wall-clock
adjustments remain observable. Unsupported IDs, `gettimeofday`, unavailable
calibration and unsupported executors retain syscall fallback. Resolution
queries retain the existing 1 ns ABI value; this is not a precision guarantee.
Clock IDs use Linux's low 32-bit `clockid_t` argument on both paths. These hooks
do not change the session's existing clock-ID/suspend policy.

Regression coverage includes actual blocked affinity/stop wakeups, dynamic
metadata state, real Linux libc/versioned symbol lookup, clock/syscall agreement,
concurrent callers, fork/exec, long elapsed-time arithmetic and realtime fallback.
The Mac product records full-application and targeted measurements in its
[execution design](https://github.com/kb5000/trames-mac/blob/main/docs/architecture/execution-backends.md).
