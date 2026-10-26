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
