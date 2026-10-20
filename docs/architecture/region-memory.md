# Guarded guest memory regions

Owner direction: reduce the memory regression and coarse page exclusion. Ordinary
guest races may produce different allowed results on different runs; the runtime
does not invent a race error or deterministic global ordering. Synchronized
programs retain ARM atomic/exclusive/acquire/release/fence constraints. One cached
CPU interpreter remains, with no JIT or extra execution backend.

Owner clarification, 2026-10-14: native conversion preserves each original
function's thread-safety contract. A non-thread-safe guest function is not owed
an algorithm/global lock, deterministic winner or invented race error. Existing
guest locks and CPU atomic/memory-order requirements remain. Audited unsafe is
permitted; suspected host undefined behavior needs a concrete impact analysis,
including compiler transformations and effects on other host/guest state. A
contained, supported low-level implementation may be used, but observing one
successful run does not establish containment. Persistent working instructions
are in [AGENTS.md](../../AGENTS.md).

## Scoped ownership

Coordinator `Memory` pages retain `Rc<PageBytes>` for fork ownership, while
published CPU/native views retain an `Arc<SharedPage>` **over the same physical
bytes**. Moving an owned heap Box into UnsafeCell storage preserves its address;
mapped pages transfer their existing physical owner/slot lease. Publishing more
cores does not copy bytes or change the Rc fork count. No coordinator Rc, VFS
provider, or unguarded borrowed slice crosses to workers. Immutable mapping
snapshots and per-worker software TLBs still describe permissions and lifetimes.

Coordinator reads/writes, hardware CPU aliases, native fragments, atomic RMW and
exclusive monitors share one physical ownership protocol. Mutable shared bytes
acquire region guards; admitted exclusive or immutable private bytes skip that
acquisition, as described below. Byte writes become
visible without commit or refresh. The coordinator uses scoped shared borrows;
its optional unguarded native page-borrow API declines a shared page. Pair reads
and moves handle physical aliases under a union guard or ordered page guards.
No native function gains an algorithm-level lock.

The primary guest and host are both AArch64. Protected scalar/SIMD access already
uses native LDR/STR and needs no additional per-access fence; explicit guest
acquire/release/fence instructions retain their required ordering. Region guards
remain for scoped Rust/native borrows, mixed atomics and monitor bookkeeping;
they currently admit a stronger subset of ARM interleavings and are a future
optimization boundary, not a requirement to strengthen every guest access.
Quota membership is not a byte-publication fence: its warm state uses relaxed
loads, software/native stores reuse the paid per-view TLB bit, and reads consume
initialized shared storage directly without a second residency/acquire check.

Shared anonymous mappings, shared file mappings and memfd/shm buffers expose
resident `SharedPage` handles through `PageBacking::shared_page`. File cache pages
move their original allocations into that domain; memfd retains its existing
mapped allocation, including native display/GPU leases. Read-only private file
mappings can read the same backing storage until COW. Mutable undetached private
file mappings and custom providers without this opt-in retain bounded shadows
and dirty-copy commit; their live EOF, fallible I/O and private-COW behavior are
not bypassed. A private page that has detached rejoins the common shared path.

A real fork retains Rc COW ownership, rather than treating CPU views as fork
owners. Its epoch invalidates the parent's cached mapping view even if no bytes
changed. Before writable fork pages return to workers, they detach once into
owned physical storage; read-only shared storage can stay shared. A safe fork
with an externally retained writer snapshots the child's private bytes, because
the old view still has a writable capability. Normal runtime fork joins workers
first. `CLONE_VM` never detaches or duplicates bytes. Source mapping changes
retire CPU windows if any external View survives, including views from previous
snapshot generations. A VM-level lifetime counter changes only when a View is
created/dropped; ordinary CPU/native byte accesses do not update it. This keeps
retired physical slots from being zeroed/reused under an older reader/writer.
Normal joined runtime mapping paths reuse their existing windows. Remap/protect/
truncate/discard and persistence still use joined checkpoints.

Anonymous zeros remain unpaid and physically sparse in mapped storage. If the
optional MMU arena is unavailable, a shared zero page's software allocation is
also lazy: reads borrow immutable zeros, and the first guarded write publishes
one zero-initialized allocation. Quota admission still precedes stores and
kernel/native output effects; sharing a worker view does not charge again.

`parallel/page.rs` owns stable heap or mapped byte storage and an atomic held
mask: one bit for each 64-byte region in a 4 KiB page. A guard atomically acquires
the complete mask it needs using acquire ordering; release clears only its own
bits. Disjoint masks can coexist. Overlapping ordinary, atomic and native accesses
use the same protocol, so mixed widths cannot bypass each other's protection.

After a short bounded spin, overlapping waiters yield the host thread rather
than busy-loop indefinitely. This is a region lock, not a claim of lock-free or
starvation-free execution. A bulk operation touching the whole page needs every
bit, but acquires that mask in one operation. Different regions of one page can
progress while a smaller native borrow is held. Native functions remain bounded;
kernel mutation and persistence still use joined checkpoints.

The module's `unsafe impl Sync` has one invariant: every non-atomic byte and local
reservation-row access has exclusive or immutable range ownership, from a live
region lock or the scheduler's private-epoch proof. Slices expose
only their checked subrange, never a mutable reference to the entire page.
Mutable slices borrow the guard mutably and cannot outlive it. Same-page moves
use overlap-safe raw copy under one union mask; different pages retain physical
identity lock ordering. Guards release on unwind. Rc backing hooks stay on the
coordinator. Tests and fully instrumented ThreadSanitizer check this boundary.

This implementation does not form racing Rust/C byte slices. Guest
nondeterminism comes from allowed instruction/fragment
interleavings. Aligned loads/stores and 128-bit RMWs remain protected; failed CAS
and LL/SC semantics, code tokens and dirty-byte publication are preserved. Region
guards can still exclude some weak outcomes that physical ARM allows. This is a
stronger subset, not a complete enumeration of ARM's weak-memory outcomes.

## Exclusive private epochs

When different address spaces execute in parallel, each can have a single active
CPU. The scheduler now admits a lock-free private-page path for those epochs:

1. Prepare **all** chosen Views before admission. Count dispatches by actual
   address-space identity, not PID or `vm_id`; require precisely one for this VM.
2. Compare the actual coordinator `Memory` owner count with the Kernel's handles
   for that root. A host callback retaining `Memory::share()` blocks admission.
   Count real roots, including blocked tasks and retired zombie memories, so an
   unrelated process record cannot substitute for an external alias.
3. Require the all-generations View user count to be one. An externally retained
   View, including one from a previous mapping generation, blocks admission.
4. Each eligible frame must be anonymous or a detached private copy, with one
   coordinate Rc owner and exactly the coordinate/ConcurrentPage physical Arc
   owners. This additional physical test rejects retained read-only fork Views
   after their coordinator has gone. Writable fork pages detach before dispatch.
   Shared mappings, live private file shadows and custom providers stay guarded.

These are checkpoint checks, not per-operand refcount loads or permission walks.
An admitted frame uses an unlocked scoped guard: checked subranges, reference
lifetimes, alias-aware pair/move behavior, unwind cleanup and monitor invalidation
remain the same. Scalar hardware/software reads and writes, instruction fetch,
native fragments/fill/copy, atomic RMW and LL/SC all use this single boundary.
The acquisition mode is stored in two unused aligned page-pointer bits, keeping
the guard at two words on supported 64-bit hosts. Rust `map_addr` preserves
provenance, the lifetime marker retains the page, and every dereference clears
the tag; no tagged pointer escapes. This avoids widening hot guard return values.
Private version increments, dirty masks and reservation-row publication use
single-writer relaxed load/store instead of atomic RMW. Global executable epochs
remain atomic; explicit guest acquire/release/fence behavior remains intact.

Only this actor may access the VM's private bytes/monitor metadata until the View
is dropped. The coordinator performs no guest byte inspection, mapping mutation,
fork, signal delivery or futex operation while it executes. Ready I/O can **move
the same View** to a service actor while the CPU is parked, after ending scoped
borrows; asynchronous disk jobs use host buffers and scatter through that View
before returning it. Channels and joined completion publish bytes and relaxed
metadata, so private stores need no extra inter-CPU publication fence. View
cloning during this unsafe admission is forbidden; normal clones start guarded.

The metric `exclusive_private_views` counts admitted dispatches, not accesses or
cores. [Private-memory validation](../validation/private-memory.md) retains the
fixed-work comparison and source hashes. Mutable shared-VM frames, shared physical
backings and the ordinary coordinator `Memory` path remain guarded. Extending
lock-free ordinary ARM64 accesses there requires a separate protocol for native
slice borrows, mixed-width atomics and exclusive-monitor metadata; simply
removing their guards would not establish those requirements. Aligned raw-asm
loads/stores are a candidate, rather than an obligation to simulate stronger ARM
ordering. No global native-function safety lock or new race errno is introduced.

## Immutable private pages in a shared VM

Multiple CPUs of one VM can now read its physically private, non-writable pages
without a region acquisition/release. This includes private RX code and R data;
execute-only pages still permit instruction fetch only. It does not depend on
the absence of writes observed in a profile. The frozen mapping must prohibit
writing, and the same physical-ownership proof used above must reject shared
backings, COW peers and retained other-VM storage. A read-only VMA over a writable
file is not immutable storage: fd/backing writers remain possible, so it stays
guarded even if no current guest VMA can write it.

The scheduler prepares one frozen View per actual Memory root per epoch and
clones worker-local translations for its other selected CPUs. This avoids
repeated mapping/backing checks and prevents unrelated global backing epochs
from giving a VM's peers different snapshots. These reuses count as cache hits.
After preparing all selected Views, it accounts for every coordinate handle.
`try_private_epoch` also requires
the **same Snapshot Arc** and an all-generation live-View count exactly equal to
the group size. A missing/external View or a different mapping generation rejects
the entire admission. One actor receives the previous exclusive mode; multiple
actors receive immutable-read mode. Clones start guarded, and admission forbids
cloning, mapping/fork/protection changes and coordinate byte/monitor access until
every admitted View is dropped. Ready services still move their parked CPU's
own View, rather than introducing another byte owner.

Joined incremental snapshots index versioned file backings by a stable inode
change domain. A global backing notification queries one live representative
per domain; an unchanged generation skips that file's pages entirely. Changed
files still receive per-page version and live EOF checks, including detached
private COW mappings. File I/O, truncation, coordinator/native mapped writes and
joined worker publication advance the inode generation. The index contains only
identities and virtual addresses, so it does not extend VFS/page lifetimes or
send Rc metadata to workers. Mapping removal/replacement updates the index
incrementally. Unknown providers retain individual checks and conservative
refresh; retained external Views keep the full immutable snapshot path. This
changes coordinator metadata work, with no extra ordinary CPU-store operation,
byte lock, permission rule or memory-order fence.

Each immutable frame has no writable alias/capability among these actors. All
CPU and native write paths retain their existing Write permission check before
creating a mutable byte reference. RW frames keep normal guards, atomic RMW,
dirty publication and exclusive invalidation. For reads, a view-mode byte and
precomputed frame-access mask select an unlocked read-only guard; no per-operand
refcount, page scan, added permission walk or fence is required. Pair reads and
the source of native copies share this protocol. Native slices can overlap
between readers, including reentrant immutable reads. The 16-byte guard uses
mode tags for locked, exclusive and read-only ownership; read-only drop performs
no unlock RMW and never grants mutation or monitor invalidation.

LDXR on an R mapping is legal and needs a monitor token. Its first use publishes
the reservation table through the existing OnceLock, so parallel first readers
initialize it once. Subsequent row/override reads are immutable for this epoch;
no byte writer or monitor invalidator exists for that page. Atomics and STXR
require Write access and cannot enter this route. After every View and native
borrow has ended, a joined protection change can admit writers again, using the
same version/monitor invalidation protocol. Acquire/release/fence instructions
retain their guest behavior. This neither adds a function-wide safety lock nor
converts a guest data race into a special result.

`readonly_private_views` counts admitted shared-VM dispatches, not lock-free
pages or individual operations. [Shared-readonly validation](../validation/shared-readonly.md)
records overlap, monitor, alias/lifetime tests and the fixed-work comparison,
including a guarded RW control. Shared **mutable** ordinary accesses still need
a compatible raw-ARM/native-borrow/atomic/monitor protocol before they can skip
region locks; they are not covered by this immutable proof.

## Reservation and commit costs

The page's monotonically wrapping version still authorizes code/cache changes.
The first exclusive read lazily allocates a page's reservation rows. Before any
monitor exists, ordinary writes need no reservation table. Publication occurs
under the reader's region guard; an overlapping earlier writer must unlock
before that reader can capture a token. Once published, the table remains live
for the page. Each 64-byte region has four 16-byte reservation values and a small override mask.
A full page uses one inherited epoch; a full region replaces its base once.
Partial writes only update touched granules. Replacing the base for granule zero
first materializes unaffected inherited values, so neighbors retain valid tokens.
Override/region masks, rather than numerical comparisons, handle epoch wrap.
Local metadata rows use the same region guard; only page-wide epochs/masks need
atomic storage. This avoids per-granule atomic/version writes for bulk interiors.

Joined commit publishes source generations and dirty metadata for shared
resident storage without moving bytes. Shared providers receive coalesced dirty
ranges through `publish_write` to retain mtime, persistence and backing epochs.
Legacy/custom shadow providers still combine adjacent 64-byte dirty bits into
one checked backing write; sparse runs never overwrite clean alias holes.
Live EOF, retryable writeback and executable invalidation remain enforced.
Dirty publication skips the RMW when all touched regions are already marked in
the joined epoch. Only a quiescent coordinator clears those bits.

Worker writes also mark a sparse page bitmap indexed by stable root-frame IDs.
Commit scans one bitmap word per 64 frame slots, then visits only marked pages;
virtual mapping order and recycled frame indices do not change publication.
CPU stores, atomic/exclusive writes, native fill and both copy paths use the same
marker. Bitmap storage follows the cached mapping domain across backing-epoch
refreshes, including earlier views retaining the same physical pages. Mapping
changes require joined workers and create a new bitmap. Worker completion/join
publishes bytes and relaxed bitmap marks before the coordinator clears them.
The original physical 64-byte dirty mask still coalesces runs and handles aliases;
failed backing hooks retain outstanding fragments and frame bits for retry.

[Shared-storage comparison](../validation/shared-memory.md) records source/worker
physical memory and dirty commit before and after the change. RSS alone can
count multiple aliases of a page; PSS counts their physical share once.

The coordinator commits each selected shared VM once per round, before processing
any returned syscall, signal or exit. Fork address spaces remain distinct, even
when they share file-backed physical pages. CPU dispatch placeholders and newly
forked CPUs allocate no decode-slot table until the first nonzero interpreter slice;
moving a warm CPU to a worker keeps its existing cache. Guest instruction budgets,
kernel checkpoint triggers and original musl synchronization remain unchanged.

[Checkpoint measurements and validation](../validation/checkpoint-cost.md) record
the fixed-work comparison for default and experimental allocator routing.

Native permission/backing/admission checks collect facts in one traversal while
retaining the first fault address and full validation before effects. Single-page
CPU accesses validate once; checked native control reads share the transport
helper. Coordinator Memory also combines copy admission with range validation,
reducing repeated BTreeMap lookups in the single-CPU direct path.
Built-in anonymous/VFS backings explicitly promise their CPU check/read/write/
version and scoped native-span methods cannot re-enter Memory. CLONE_VM then
borrows the local address space once per CPU slice or native entry, dropping
that borrow before every returned event or guest callback.
Custom backings default to individual access borrows; a reentrant readonly
provider test verifies their existing behavior. Admission is conservatively
latched on mapping changes, with no per-instruction page-table scan.

CPU and native worker scalar reads now enter the same checked implementation.
A single-page native read resolves the frame once, retaining the CPU permission,
EOF and region-access behavior; only live private backing adds native checkpoint
admission. Cross-page validation finishes before bytes are exposed, and CPU
faults take precedence over checkpoint deferral. Original-source allocator
loads/stores use the same fixed-width 1/2/4/8-byte operand interfaces. Fallback
output preflight remains a publication rule, separate from memory permissions.

[Validation and one alternating before/after batch](../validation/region-memory.md)
include disjoint held borrows, overlapping masks/unwind, atomic pairs, aliases,
reservation wrap, complete musl and an ordinary same-page CPU workload.

## Permission TLB

[The permission-cached TLB](soft-tlb.md) packs virtual-page identity and access
rights into one 16-byte entry. Hits reuse validated permission facts, with
coordinator mapping/protection flushes and immutable worker snapshots. This
changes translation work only: region guards, live backing faults, COW, native
admission, dirty publication and ARM atomic ordering keep the model above.

## Hardware-protected ordinary RAM

[Hardware MMU mappings](hardware-mmu.md) share physical bytes between protected CPU
aliases and RW native aliases. A per-view single-level page TLB caches eligible
CPU alias addresses, avoiding repeated sparse-window and group lookups. Hardware-compatible groups use native scalar
operands; special mappings and cross-page operations retain the checked software
path. Region guards, COW, reservations and dirty/code publication are unchanged.

## Sparse zeros and first-write budgets

Untouched private anonymous pages use immutable zero storage. Reads and snapshot
preparation do not copy a full page; fresh worker physical slots retain the host
zero-fill behavior. Reused slots clear retired data. File/EOF errors retain their
precise faults while their inaccessible snapshot bytes need no allocation.

CPU and native first stores reserve the same per-VM and aggregate quota before
changing bytes. A page charge is retained by both its coordinator mapping and
worker frames, so concurrent stores pay once, joined commit does not pay again,
and retained views cannot release their charge early. Later ordinary hardware
stores use a resident bit in the existing TLB tag, without a quota RMW on each
store. A first-touch quota failure terminates the faulting guest group with
SIGKILL; mmap/fork admission still returns its ordinary errno. This is a bounded
OOM policy, not Linux victim selection.

File mappings preflight available quota before VFS page storage is created.
Fixed file replacements reuse charged destination slots. File mappings and
materialized fork COW pages are still charged conservatively per address space;
CLONE_VM shares one account and now builds a shared task directly, avoiding an
intermediate page-table clone and MMU retirement. The per-process mapped-page
cap still bounds page-table metadata, including untouched readable mappings.
This is not complete Linux demand paging or exact host RSS/PSS accounting.
Runtime shadow storage, COW windows and host allocator bookkeeping are outside
the guest byte quota and remain further memory work.

The [Firefox memory investigation](../validation/firefox-memory.md) records the
original Scudo ELF, the 512MiB BSS oracle, budgets, complete/partial diagnostics
and the remaining first-frame failure.
