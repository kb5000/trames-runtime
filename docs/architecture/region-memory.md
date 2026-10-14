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

`parallel/page.rs` owns a stable Box of per-byte UnsafeCells and an atomic held
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
reservation-row access is covered by a live guard for that region. Slices expose
only their checked subrange, never a mutable reference to the entire page.
Mutable slices borrow the guard mutably and cannot outlive it. Same-page moves
use overlap-safe raw copy under one union mask; different pages retain physical
identity lock ordering. Guards release on unwind. Rc backing hooks stay on the
coordinator. Tests and fully instrumented ThreadSanitizer check this boundary.

Unsafe permits controlled raw access; it does not legalize an unguarded Rust/C
data race. Guest nondeterminism comes from allowed instruction/fragment
interleavings. Aligned loads/stores and 128-bit RMWs remain protected; failed CAS
and LL/SC semantics, code tokens and dirty-byte publication are preserved. Region
guards can still exclude some weak outcomes that physical ARM allows. This is a
stronger subset, not a complete enumeration of ARM's weak-memory outcomes.

## Reservation and commit costs

The page's monotonically wrapping version still authorizes code/cache changes.
Each 64-byte region has four 16-byte reservation values and a small override mask.
A full page uses one inherited epoch; a full region replaces its base once.
Partial writes only update touched granules. Replacing the base for granule zero
first materializes unaffected inherited values, so neighbors retain valid tokens.
Override/region masks, rather than numerical comparisons, handle epoch wrap.
Local metadata rows use the same region guard; only page-wide epochs/masks need
atomic storage. This avoids per-granule atomic/version writes for bulk interiors.

Joined commit combines adjacent 64-byte dirty bits into one checked write. A
fully dirty page needs one backing write instead of 64; sparse dirty runs never
publish clean holes over another backing alias. COW, live EOF, mtime/writeback,
reservation and executable invalidation hooks remain on the original paths.
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
failed backing writes retain outstanding fragments and frame bits for retry.

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
