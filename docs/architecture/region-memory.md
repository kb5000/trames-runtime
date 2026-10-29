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

Virtual mappings and RAM accounting are separate. Creating an accessible VMA,
changing its protection, retaining a snapshot, querying permissions or obtaining
a futex identity does not charge the mapped length to the guest RAM budget.
Private anonymous VMAs larger than 64 KiB now use interval metadata, including
accessible mappings. Their virtual size does not spend a per-page descriptor
budget. Small mappings retain direct frame indexing and software CPU aliases.
File/shared mappings retain the 4,194,304-page (16 GiB) descriptor bound, while
PROT_NONE reservations retain their separate interval bound.

PlainFile-backed VFS pages retain an Arc-owned page source, offset and live EOF
capability. Creating a mapping or worker frame does not read file bytes. CPU or
native byte access loads the reached page under its existing object lock and
charges that page; a private writable file view detaches bytes only when reached.
Only Send + Sync resource handles cross to workers, never the coordinator's Rc
provider. Shared aliases retain the same published SharedPage and the original
version, dirty and truncation hooks. Unknown/custom providers retain their
conservative preparation path. Cold quota preflight rejects a known-full budget
before file I/O; the final atomic charge remains authoritative under contention.

Anonymous software zero reads remain uncharged. A hardware executor that needs
a physical zero-page slot must charge that real allocation too; no global
hardware zero-page alias is implemented. File mappings and materialized fork COW
pages are still charged conservatively per address space; CLONE_VM shares one
account and avoids an intermediate page-table clone. Retained Views keep their
charges until their byte owners end. This is demand allocation with a bounded
OOM policy, not exact unique-physical-page RSS/PSS accounting. Runtime shadow
storage, page descriptors, COW windows and host allocator bookkeeping remain
outside the guest byte quota.

The [Firefox memory investigation](../validation/firefox-memory.md) records the
original Scudo ELF, the 512MiB BSS oracle, budgets, complete/partial diagnostics
and the remaining first-frame failure.

## Hardware execution through frozen Views

Hardware backends now use the same frozen `View` frames, permissions, first-write
charges, backing identities and joined dirty publication as interpreter/native
workers. `SharedPage::export_hardware` transfers a page into stable physical
storage once, under all of its region bits. Untouched logical zeros still need
no physical allocation. The cold `Memory::prepare_hardware` boundary retires
native MMU aliases **and their cached translations** before any transfer. A
hardware View never uses the former native aliases or unlocked private epochs.
Admission skips the resident-page pin search when the fixed-buffer registration
table is empty. A live registration still requires the original mapped-page
check; dropped or unmapped pins do not exclude unrelated hardware execution.
This keeps repeated admission independent of resident image size for the common
case without adding per-page metadata or changing byte-access synchronization.
Externally pinned/GPU raw mappings remain unsupported by this export contract.
Shared providers without a canonical `shared_page()` export are also rejected:
conservative hardware page dirtiness must never copy clean shadow bytes over a
concurrent backing alias. Existing interpreter fragment transport is unchanged.

`HardwareStorage` is an unsafe backend contract, not extra guest permissions.
Before exposing any Rust byte reference, its host-borrow gate must synchronously
exclude hardware accesses to the containing host physical granule. The original
64-byte region guards continue to arbitrate overlapping host borrows. Disjoint
host borrows can coexist; unrelated granules and CPUs continue executing. The
last borrow restores hardware access and fires one-shot `HardwareWait` tickets.
The existing epoch queue parks those tasks, releases their execution slots, and
handles release-before-park, VM checkpoints and stop without a new service thread
or a polling message bus. Normal hardware loads/stores acquire no Rust lock and
execute with the host ARM memory model.

Byte storage changes only under the complete region lock, with native aliases
and unpublished actors excluded. Once exported, it does not move while its VM
is live. The backend must retain the VM during a host borrow, retain canonical
physical ownership through every executing View, and invalidate any stopped
weak PTE cache before reuse. After the former VM has permanently ended, a joined
export can transfer retained bytes into a replacement VM. These conditions bound
the `UnsafeCell` storage mutation; neither a concurrent enum read nor a stale
native pointer is allowed by the admission contract.

A hardware write admission marks the existing dirty fragments conservatively;
joined publication still invokes original file persistence/version hooks. COW
is prepared by the existing frozen-View ownership boundary. This currently can
copy writable fork pages before their actual first guest write. It remains a
fork cost to optimize; it is not an additional permission or race policy.
Instruction counters stay unavailable for hardware execution. Worker fairness
uses completed slices as progress without inventing retired instructions.

The Mac adapter owns the platform paging implementation, including preserved
file-backed physical storage and memory-pressure events. The common runtime does
not claim an exact process RSS limit or impose a second paging policy on iPad.


### Concurrent raw transfers and hardware translation versions

Hardware guest RAM has three distinct capabilities. Metadata retention holds the
existing region mask without exposing bytes or revoking hardware. Ordinary
copy-in/out uses `RawGuard`, which has no guest slice accessor. Explicit Rust
slice callbacks retain the original region and hardware exclusion gates.

On AArch64 and x86-64, ordinary copies execute audited inline-assembly loads and
stores over the exact checked range. Guest bytes never become LLVM loads/stores
or Rust references, including scalar read results. Host input/output buffers
retain normal Rust ownership. Aligned 64-bit transfers use one ordinary host
load/store; longer transfers may observe normal guest races and are not promised
an atomic snapshot. There is no added fence, global native-call lock or guest
race error. Other architectures retain exclusion and the original copy path.

Region ownership still stabilizes storage and excludes overlapping host slice
borrows. It protects monitor bookkeeping; it does not exclude hardware ordinary
access. Stable physical storage retains its initialized host mapping through
page-out; OS page-in and writeback do not recycle the virtual allocation. Cold
exports and rebinding still acquire every region and the original byte gate
before copying or replacing storage. These are the lifetime/compiler conditions
of this implementation, not an assumption that raw pointers make Rust races safe.

`HardwareStorage::publish_host_write` publishes the affected code range after an
actual host raw write. Scoped callbacks conservatively publish their page before
ending exclusion, including unwind. The Mac backend skips data-only slots and
uses the existing instruction-cache operation for code. Guest self-modifying
code retains its architectural IC/DC maintenance responsibility. Initial
executable mappings, executable permission transitions, physical page-in and
changed executable backing still publish code. A global interpreter code epoch
is not a reason for a hardware consumer to flush every executable page.

The common frozen View exposes a mapping token independently of joined dirty
publication. Data-only refresh preserves that token. Incremental metadata
updates record changed intervals in a bounded history (32 batches and
4,096 intervals). A lagging consumer can compare persistent 2 MiB chunk stamps
when that history expires. Full snapshot replacement changes all live stamps.
This metadata neither retains physical
RAM nor adds per-instruction tracking. Checked write-frame tokens use stable
root indices plus VM/VA/storage identity to publish dirty metadata without a
repeated virtual-address lookup; stale or revoked membership is rejected.

Ordinary hardware View reads/writes, coordinator concurrent-page transfers and
VFS mapped-file copies use this protocol. Native/scoped reference callbacks and
atomic update APIs still use their existing exclusion contract. This is not a
claim that every source of hardware protection changes has been removed.


Canonical private hardware RAM, including writable executable pages, has no
joined provider copyback or instruction publication work: a hardware store
already changes the coordinator's bytes.
Its admitted writable mappings now set one conservative VM-dirty flag per joined
epoch. Commit advances the VM generation once, preserving coordinator monitor
invalidation and fork's existing canonical-byte COW source. It does not invent
per-page writes, touch every private frame's counters, or rebuild their metadata.
Shared backings and non-direct providers retain their original
dirty/persistence/code hooks. Software interpreter and native View writes retain
their existing region, monitor and dirty-fragment protocol. All execution Views
of a hardware VM must still use hardware mode; mixed interpreter/hardware
exclusive-monitor execution is outside this admission contract.


### Content publication without mapping churn

At a joined checkpoint, canonical direct data frames can refresh their content
revision and native-access eligibility in place. They keep their slab position,
alias/backing indices and hardware mapping generation. Eligibility requires the
same physical allocation, quota owner, guest permissions and versioned backing
domain, successful live backing validation, and non-executable data. Explicit
mapping changes, COW, EOF/errors, executable changes and unknown providers still
use normal frame preparation and translation invalidation. Regression coverage
includes shared writes, truncate/grow and independent private COW mappings.

The session also passes its registration domain to serial CPU dispatch through
`Cpu::run_coordinated`. Hardware backends must use that domain for both solo and
worker execution. Otherwise a runnable-count change switches code/alias domains
and discards the complete cached View even when the mappings are unchanged.
The default implementation retains the interpreter's existing direct Memory
execution. Standalone hardware executors may own an independent registry when
they are not participating in a session.


### Hardware-owned private code

Executable permission does not imply that an admitted hardware CPU has written
a page. Private canonical RWX mappings use the same single VM-dirty notice as
private data, rather than advancing every page's instruction generation at each
joined epoch. This removes invented writes, frame reconstruction, mapping
reconciliation and host instruction-cache publication for unchanged JIT pages.

Guest code writers retain the AArch64 self-modifying-code protocol, including
the required cache operations, barriers and receiving CPU synchronization.
Actual host writes publish their affected range through `HardwareStorage`.
Initial executable mappings, permission changes, page-in and physical replacement
still perform the backend's existing code publication. Shared file/provider
dirty hooks remain necessary for durability and non-canonical backing caches.
No new first-write exception or global memory fence is introduced.

This policy applies only to admitted hardware execution. All execution Views
of that VM must use hardware mode; it does not promise an interpreter decode
cache can follow unannounced hardware stores. The iPad interpreter's software
write, monitor and instruction-generation paths remain unchanged. Regression
coverage checks stable private RWX metadata across joined rounds, real guest
IC/DC publication between two host-thread-affine vCPUs, host code writes,
permission revocation, physical replacement and preserved page-out/page-in.

## Local mapping commits and backing range history

A content-change domain is separate from a quiescence dependency. Local mapping
syscalls still join every CPU and retained service of the affected address
space. Nonvolatile VFS file mappings opt into
`PageBacking::parallel_commit_isolated`: their published pages retain physical
ownership independently of coordinator mapping/provider lifetime, and all
coordinator byte access and writeback use the existing SharedPage gates.
Consequently a read-only library or canonical shared file does not connect
otherwise independent mapping checkpoints. Same-mm threads remain joined;
unknown/custom providers retain the original transitive pause closure. Truncate,
provider storage replacement and other nonlocal operations keep their joined
owner boundary. No provider Rc moves to a worker.

An isolated commit can harvest a shared ConcurrentPage's atomic dirty mask while
another address space runs. It only clears its own joined snapshot's publication
bitmap; other spaces retain theirs. The provider dirty/version hooks still run,
and canonical bytes already contain the writes. This adds no ordinary byte
barrier or per-access permission policy.

Versioned providers may expose a stable page-aligned domain offset and
`parallel_changes_since`. Snapshot metadata indexes file offsets and every
virtual alias, so a one-page update visits its aliases rather than all pages of
the file. The VFS keeps at most 128 invalidation records per backing, allocated
on demand. Repeated identical ranges coalesce; different ranges remain separate
so an old whole-file write cannot permanently widen later small updates.
Generation gaps, expired history, EOF/layout changes and replaced volatile inode
sources request the original full-domain check. Unknown providers also retain
that fallback. This journal describes metadata invalidation, not byte visibility
or deferred durability. Executable aliases, interpreter monitors, private COW,
EOF faults and persistence hooks retain their original semantics.

Local validation covers readonly-library peers and active shared-file writers
continuing during an unrelated local mapping commit; coupled custom providers
and CLONE_VM peers still stop. A 1-page update checks exactly three mapped
aliases (including a private COW alias) at 8, 256 and 1024 file pages. Truncation
checks all aliases and preserves SIGBUS. The Mac
[mapping-scope checkpoint](https://github.com/kb5000/trames-mac/blob/main/docs/validation/mac-windows.md#local-mapping-scope-and-backing-ranges-2026-10-28)
records the real Linux comparison and platform acceptance.


### Hardware mapping change intervals

Hardware-only mapping history coalesces ordered changed pages into address
intervals. Its metadata budget counts intervals, with the existing bounded
update history, rather than counting pages in a large contiguous VMA. Backends
can intersect these intervals with their retained PTEs without walking untouched
pages or unrelated code/data. Overlapping updates can repeat intervals; consumers
merge/intersect them before inspecting leaves. The compatibility page iterator
expands the same intervals for older consumers.

A persistent metadata stamp per currently mapped 2 MiB chunk bounds the fallback
for CPUs that miss more than the journal retains. `hardware_mapping_chunk_version`
returns the stamp, or None for a chunk with no mapped pages. Backends compare
cached stamps and inspect leaves only in changed chunks. Installing a single
leaf must not acknowledge old unchecked leaves in the same chunk. This is a
coarse invalidation hint, never a substitute for existing per-page permissions,
storage identity or live EOF checks. A full snapshot replacement assigns fresh
stamps to every live chunk. Removed chunks leave no tombstones, byte owners or
quota charges; metadata stays bounded by currently mapped chunks under sparse
address churn. Software interpreter Views build neither the journal nor chunk
stamps. No byte-visibility, permission or concurrency rule changes.

Validation includes 80 missed updates, journal interval overflow, sparse chunk
removal/reuse, snapshot replacement and zero untouched-page residency. The Mac
signed acceptance also checks that late CPUs skip unrelated cached chunks while
still observing read-only protection, unmap and fresh bytes after address reuse.


### Host-managed policy and hardware-only coordinator mappings

`MemoryLimits::host_managed()` selects the guest architectural ceiling for
resident accounting, rather than a fixed product RAM quota. It allocates no RAM.
The host adapter opts in through `GuestOutput::host_memory`; startup rejects a
missing adapter. `sysinfo` and procfs use the adapter's physical/free/available
snapshot, while numeric bounded policies retain their original guest-budget
reports and enforcement. Host-managed data/RSS/address rlimits are unlimited;
proc address-space limits now follow the same policy instead of a fixed 512 MiB.
Common/iPad defaults remain bounded and unchanged. The Mac product's default is
host-managed, with `--memory-mib N` retaining an explicit resident-byte cap.

Resident policy and mapping representation are independent. Large private
anonymous mappings now have sparse accessible intervals as described below;
file/shared mappings retain their descriptor ceiling. Host-managed sessions
share the host memory pool across VMs. This does not provide unique-physical
RSS/PSS accounting; fork accounting/copies remain conservative.

Hardware admission now leaves the coordinator software CPU-alias arena disabled
across subsequent map/protect/write operations and fork. Previously admission
cleared it, but later mapping operations recreated protected host CPU windows
that hardware execution would discard again. `prepare_frame` already transfers
canonical owned bytes and detaches true writable fork COW pages, so hardware
preparation skips the redundant software mapped-slot promotion. Software/iPad
registries retain their original alias path. Hardware snapshots already skipped
worker CPU aliases; they now also skip collecting unused full-refresh addresses.

Every hardware admission still invalidates coordinator cached byte pointers:
canonical storage can transfer from Heap to hardware during an epoch even when
no mapping changed. Region/permission/EOF checks, host borrow gates, mapped pin
rejection and hardware export ownership remain unchanged. Validation covers
mapping/protection/kernel writes without recreated windows, writable child COW
isolation, retained data, and a fresh interpreter arena retaining its fast path.

### Sparse accessible anonymous ranges (2026-10-29)

An untouched large private anonymous VMA owns interval metadata and an immutable
zero-page template. Worker snapshots freeze those intervals without constructing
a Frame/ConcurrentPage graph per 4 KiB. First accesses create descriptors only
for reached addresses. Linux private anonymous mmap, brk and mremap can exceed
the former 16 GiB virtual descriptor ceiling. File/shared mapping and mincore
output bounds remain independent and unchanged.

Every interval owns a shared, object-sharded sparse store of canonical bytes and
quota charges. Successive snapshot generations clone that store identity;
backing-epoch refreshes cannot create competing bytes for the same address.
Only initial descriptor lookup takes a store shard lock. Byte operations retain
the existing shared-page region/atomic protocol, with no whole-call lock or
additional ordinary memory barrier. CPU, native output, bulk copies, exclusive
operations and pins use that same reached storage and charge.

Canonical sparse stores remain authoritative across ordinary execution handoffs.
Commit publishes one VM dirty-generation bit, without converting reached worker
pages into a duplicate coordinator descriptor graph. Unchanged range fragments
reuse their immutable worker-frame cache. Fork epoch changes, remap and account
rebinding retain the existing explicit-frame/COW boundary when needed; native
coordinator accesses materialize only their reached descriptors. Retained Views
keep old byte owners through unmap/discard. Retirement tickets retain the exact
old stores and address intervals; canonical storage is pruned after every View
generation joins. The current snapshot's independent frame cache is pruned through
its overlap index while that snapshot is unique. Cold/full snapshot construction
creates fresh frame caches, so no other generation can retain those Frame
addresses. The retirement backlog survives snapshot replacement while old Views
remain live. The anonymous dirty bit is shared by
those snapshot generations, so their late canonical writes remain publishable.
Retirement releases the removed pages' quota.
Fork copies a live writer's reached pages and otherwise uses Rc COW. Large remap
and protection operations visit affected intervals plus explicit reached pages,
rather than all virtual pages. Joined snapshots update their interval index in
place, preserve unchanged frame caches and maintain an executable-range count.
Mmap search queries mapping collisions directly; mprotect and coordinator-cache
retirement avoid constructing or scanning the process-wide region list. Hardware
chunk stamps visit only changed visited chunks. Software alias refresh skips
absent physical windows; a first scalar store can describe its one host granule
without charging or populating untouched neighboring pages.

Worker TLB tokens may contain a tagged pointer to an immutable lazy Frame. Each
Frame has an Arc owner in an insertion-only snapshot cache; a live View prevents
unique snapshot replacement, and inserts never move/remove Frame allocations.
Coordinator wrappers have the equivalent Rc ownership and mapping mutations
invalidate translations before retirement. No guest address becomes a host
pointer, and mapped/permission/EOF checks still precede access.

Hardware mapping journals combine explicit-page and VMA intervals into compact
ranges. Explicit cached chunks and actually visited anonymous chunks retain persistent
stamps. Unvisited chunks obtain a range-snapshot generation on demand; no stamp
is allocated per virtual chunk. Sparse VMA changes update only intersecting
visited stamps, so missed journal history does not turn an unrelated mapping
edit into a scan of every cached leaf. Both direct deltas and expired-history fallback revalidate
permissions/storage after sparse changes. Hardware physical exports and S1
translations still use the existing per-page fault path: native range backing
and hardware block mappings are a separate subsequent optimization.

Regression coverage includes 64 GiB accessible VMAs with a two-page resident
budget, large grow/move/shrink, partial permissions/unmap, retained-writer fork,
cross-generation canonical atomics, eight concurrent sparse atomic writers,
ordinary handoffs without descriptor conversion, discard and delayed quota
release across retained snapshot generations. Counters cover visited stores,
frame caches, rebuilt index rows and complete region-list construction. A
2,000-VMA regression bounds local retirement to its target store/cache and an
incremental update to at most two range records, independent of unrelated VMAs.
A separate test preserves software CPU aliases while charging only the reached
4 KiB page of a 16 KiB host granule. The total
allocation request for mapping, freezing and partially protecting an untouched
1 GiB VMA is bounded below 128 KiB by an allocator-instrumented test.

### Native anonymous extents and additive publication (2026-10-29)

Hardware-only host-managed address spaces can export an untouched uniform RW
private anonymous 2 MiB extent through HardwareRange. The provider retains one
stable demand-zero host allocation and linear physical-address range. Hardware
can reach any page without a SharedPage/Frame export at each 4 KiB. Later
CPU/native/coordinator accesses create subpage wrappers referring to those same
bytes, with the existing region and hardware-borrow gates. A store-level lock
serializes only first extent admission against first page creation; normal byte
operations add no range lock, ordinary barrier or new permission policy.

Only architectural-ceiling local and aggregate budgets admit this path. Explicit
resident-byte caps retain per-page admission. Native extent wrappers do not charge
all virtual bytes: their owning account queries provider residency metadata when
reporting resident_bytes. This is host-granule residency rather than unique
physical/PSS accounting. Old page budgets remain conservative across fork. Fork
and account rebinding materialize provider-reported populated host granules through
the existing COW boundary, preserving untouched zero intervals. Population must
include nonresident contents: the Mac provider queries Mach dispositions, including
compressed/paged-out pages, rather than relying on mincore. Query failure retains
the conservative full-extent fallback. Changing a live native account to a smaller
strict cap can still fail conservatively. Unchanged interpreter/iPad defaults never
create hardware extents.

An extent owns its bytes independently of the worker generation. Exact retirement
tickets prune only intersecting extent keys. Retained Views and subpage/pin owners
keep their legitimate allocations alive, and final release withdraws hardware
before releasing addresses. Partial changes retain complete extent storage while
any fragment/subpage owner survives; pressure can evict its hardware registration
without discarding contents. There is no claim of 4 KiB host physical reclamation
inside a retained 2 MiB extent.

New private-anonymous RW mmap requests may publish an append-only range index
while same-mm peers keep running. Linux reuses the original mmap validation and
address allocator on the existing coordinator; the requesting task returns its
execution slot through the existing queue. No resource-service thread or polling
bus is added. The publication index owns insertion-stable Range/Frame allocations.
Old Views consult it only after a cold lookup misses their frozen index; existing
TLB entries and byte accesses are unchanged. Published entries are never replaced,
pruned, or permission-edited in place.

Destructive generations rotate that publication owner. Retained Views keep their
old immutable index and bytes; current snapshots receive the new owner. Shared
publication frame caches are never reused by the unique-snapshot pruning path.
Permission withdrawal, unmap, discard, fixed/file/shared mappings, tracing and
seccomp retain their joined boundaries. This removes the same-mm pause for pure
additions, not every mapping synchronization operation.

Regression tests cover late native bytes, quota exclusion, retained-view release,
COW, concurrent exclusive operations, cross-generation cache lifetimes, and a real
interpreter CLONE_VM peer reading a newly published mapping with zero VM
checkpoints. Mac acceptance separately verifies one data translation fault for all
512 pages, sparse host residency, partial protection/discard/reuse, migration and
pressure recovery.

Residency observations are batched by real address-space owner for each proc
snapshot and reused by its aggregate total and thread rows. Hardware can populate
or reclaim native pages without a mapping-generation change, so results are not
cached between observations. A 13-task shared-mm regression bounds the provider
query to one per snapshot and verifies changed live values on the next request.
This keeps host pager queries from multiplying with the number of guest threads;
normal CPU/native byte accesses still perform no residency query.

Proc observation also declares the fields it consumes along the actual VFS
traversal. Independent kernel endpoints (including missing sysctl keys and the
fresh read-only random UUID endpoint) do not rebuild a task snapshot. Maps and
other process metadata refresh without host residency queries; statm/status/stat
and meminfo retain live memory observations. Unknown process lookups stay
conservative so newly-published tasks can resolve. Alias, cwd and dirfd tests
cover this classification. The shared-mm provider test verifies that UUID,
CPU-info and maps reads make zero residency calls, then a statm read observes
new hardware residency. No cross-request timer cache is introduced.

The UUID endpoint uses the existing host CSPRNG and generates a new UUID v4 on
retrieval, matching the documented [Linux random sysctl semantics](https://docs.kernel.org/admin-guide/sysctl/kernel.html#random).
Its directory and file are runtime pseudo nodes outside disk storage quotas.
