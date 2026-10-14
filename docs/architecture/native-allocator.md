# Original-source native mallocng

Status: first hot-path batch implemented in development, tracked in
[#18](https://github.com/kb5000/trames/issues/18). Complete musl still owns the
guest heap. Existing-group malloc reservation/slot framing and atomic fast free
can execute as signed-in native code; cold paths remain original guest code.
Routing is experimental and defaults off: CLI `--accelerator pure
--native-allocator`, or embedding JSON `pure_accelerator: true,
native_allocator: true`, opts in. Fork/exec retain this routing. Measurements
showed regressions in short-call and contended allocation workloads, so ordinary
pure acceleration continues to use the original guest allocator.

Owner direction, 2026-10-14 (UTC): preserve musl's original implementation with
minimal changes and move its execution to precompiled host code. The objective
is to remove allocator instruction interpretation while keeping the existing
guest heap, algorithm, data layout and synchronization. Trames remains one
cached ARM64 interpreter with signed-in ahead-of-time acceleration and no JIT.

## Source and compatibility

Use the same musl 1.2.5 archive as the full guest libc build, SHA-256
`a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4`.
The unchanged vendored source set covers:

| Original file under `src/malloc/` | Role |
| --- | --- |
| `mallocng/malloc.c` | Size classes, active groups, metadata allocation and heap growth |
| `mallocng/free.c` | Atomic free fast path, group reuse and unmapping |
| `mallocng/meta.h` | Metadata layout, queues, slot framing, validation and size helpers |
| `mallocng/glue.h` | Namespace, locks/atfork, auxv, errno and Linux memory operations |
| `mallocng/realloc.c` | In-place resize, mremap and allocate/copy/free |
| `mallocng/aligned_alloc.c` | Alignment and original slot metadata updates |
| `mallocng/malloc_usable_size.c` | Original nominal-size and metadata validation |
| `calloc.c`, `posix_memalign.c` | Overflow/zeroing and public wrapper semantics |

Original files are vendored unchanged with per-file provenance hashes.
`crates/trames-native/allocator/generate.py` verifies those hashes and extracts
original helpers/loops into an inspectable build-time C translation. Its checked
scalar-access lowering replaces guest pointer arithmetic/dereferences; original
tables, coarse-class policy, slot framing and free checks remain source-derived.
The guest build adds checked entry/continuation hooks to malloc.c/free.c.
The full-musl source package includes the upstream archive, adapters, checked
patch builder and its required vendored inputs. Preserve musl's MIT notices
alongside the GPL-3.0-or-later integration.
Do not introduce new size classes, a different allocator or host malloc pointers.
An intentional change needs its own stated contract and evidence.

Activation uses the separately negotiated auxv key `0x54520007 = 0x10005` and
the existing exact-stub executable/code-version checks. A source/layout cookie
`0x1250004003a00012`, compile-time size/offset/glue assertions and a guest bitfield
packing probe bind this first profile to the pinned adapter contract. Relocated
guest roots are passed by the instrumented original functions. Checked accesses
still constrain a fabricated call to its own guest address space; recognizing a
stub does not grant host pointer or kernel authority. This is not a general
ELF-hash resolver for arbitrary third-party allocator builds.

The verified ARM64 layout includes:
`__malloc_context`, `__malloc_lock`, group/meta/meta-area layouts, bitfields,
constants and required libc/TLS hooks. Match guest compiler layout against the
native build; do not assume matching pointer widths prove bitfield compatibility.
An ordinary/older host, replaced allocator or unsupported startup stage stays
original. Broader allocator builds need a new layout/source contract.

## One guest heap

The guest `__malloc_context`, metadata areas, group headers and slot headers
remain the single authoritative state. Stored pointers and returned pointers
remain guest virtual addresses. Native allocation must be consumable by original
free/realloc, and native free must accept allocations made by original malloc.
This includes loader allocations made before accelerator initialization.

Do not maintain a host shadow allocator context or independently allocate host
metadata. Copying the whole context out and back could lose concurrent free/CAS
updates. Temporary decoded field values are permitted only under the original
synchronization and lifetime rules. Fork copies the existing guest state through
COW; CLONE_VM shares it. Existing `__malloc_atfork` continues to coordinate the
same guest lock and resets that lock in the child.

## Minimal execution-boundary adaptation

Original C cannot simply be compiled and called with numeric guest pointers.
Current guest pages are sparse, independently backed and sometimes COW; a valid
guest struct or allocation is not necessarily one contiguous host allocation.
Even pointer arithmetic needs a defined guest-address representation, rather
than assuming an unmapped integer cast is a normal C allocation pointer.

The implementation uses a small checked access shim for guest scalar
fields and metadata atomics. Preserve original control flow,
tables and arithmetic; translate guest addresses at memory accesses. Native
stack locals and constants use ordinary host accesses. Prefer adapting the glue
and access expressions over reimplementing mallocng as a separate Rust algorithm.
Any later source/IR transformation must be ahead of time, reviewable, preserve
guest address arithmetic, and cover loads/stores, atomics and memory intrinsics;
it is not an assumption that an ordinary C compiler already provides this.

Scoped host spans retain the existing permission, COW, backing, code-token and
dirty-publication hooks. They cannot escape a call, block while held, or survive
a mapping/scheduler checkpoint. Invalid guest metadata/assertions must produce
guest fault/termination behavior, never an unchecked host dereference or a host
process crash. Audited unsafe is permitted at this boundary; guest races do not
authorize host C/Rust undefined behavior.

## Synchronization and kernel operations

Preserve mallocng's actual synchronization. In this version, small malloc takes
the guest allocator lock when `libc.need_locks` is set; read and write lock modes
are exclusive. Some frees update `freed_mask` with CAS without taking that lock.
Native CAS and ordinary metadata accesses must use the same coherent guest-memory
protocol as interpreted ARM atomic/exclusive/acquire/release accesses. The normal
allocator lock serializes the paths it already protects; no additional global
stop is needed merely because allocator code executes natively.

On contention, use the guest lock/futex path or a resumable request. A host worker
must not block waiting for a guest lock whose owner needs that worker or a joined
checkpoint to run. Cross-thread frees retain the original bitmask/lifetime rules.
Other guest CPU workers can continue through admitted native fast paths.

Route brk, mmap, mprotect, munmap, mremap and any enabled madvise through the
emulated Linux kernel. They change guest mappings and retain coordinated
checkpoints; never call Darwin mmap for a guest heap operation. The current
original glue disables MADV_FREE. Preserve the guest page size and existing
mapping/accounting semantics, rather than importing the host page size.

Original wrappers or checked hooks own guest errno/TLS, auxv randomness,
`libc.need_locks` and allocator replacement flags. Free preserves errno where
the original source does. Host errno is not the guest errno variable.

## Implemented profile

| Function ID | Work | Guest arguments |
| --- | --- | --- |
| 1 | Original coarse-class/available-slot reservation under the original guest lock | n, context address, source/layout cookie |
| 2 | Original metadata validation/header invalidation and atomic fast free | pointer, context address, 32-byte state address |
| 3 | Original enframe/set_size after the guest unlock | 40-byte state address, 0, 0 |

Malloc state is cookie/n/group/index/counter. Successful reservation packs a checked 48-bit metadata address, 5-bit index
and low 8 counter bits into x0. Enframe uses exactly those counter bits. The
guest decodes the original locals and unlocks before writing its state frame
and entering ID 3, matching upstream. Wider metadata addresses select original
code before effects. No result-frame stores extend the allocator lock interval.
If framing cannot execute natively, only original enframe runs on the reserved
slot. The allocator is not restarted. The first implementation held the lock
through framing and regressed the four-CPU allocation workload; that diagnostic
led to restoring the original unlock boundary.

Scalar stores initially form a bounded journal (at most 16 operations), with
read-after-write forwarding. All destinations are checked before publication.
No whole-context snapshot is copied back. Native per-call caching covers only
nonvolatile mem/control fields stable under the original lock or live-slot
lifetime, and every staged store invalidates that cache. Volatile availability
and freed masks always read current guest bytes. Free's first CAS publishes original
header writes before the atomic update; failed CAS retries observe current guest
masks. A slow decision before publication discards the journal and chooses the
original function. After publication, event 2 returns group/index and the guest
continues at original wrlock/nontrivial_free without repeating validation or
header invalidation. After 64 failed CAS attempts the same slow boundary bounds
native work. Both worker View and joined Memory use the same transport; no
allocator-specific global stop or page lock is added.

### Shared interpreter/native memory access

Native scalar accesses use the interpreter's fixed-width load/store interfaces
and its translation cache, permission/EOF checks, COW and publication hooks.
Worker CPU and native reads enter the same `View::read_checked` implementation.
An in-page scalar read resolves and validates one frame, then reads its bytes
under the ordinary CPU region guard. It no longer runs a separate native range
walk followed by a second frame lookup. Constant-width 1/2/4/8-byte allocator
operands preserve fixed-size host copies rather than variable-length transport.

Native entry uses `cpu_slice`, as an interpreter slice does, borrowing a local
CLONE_VM address space once when its backings permit it. Custom/reentrant
backings retain the original per-access borrow path. The borrow ends when the
native call returns, before any guest callback or mapping/scheduler checkpoint.
No additional page permissions or allocator-specific lock are introduced.

Native admission remains separate from CPU access validation. Live private
backing can request a coordinator checkpoint; cross-page CPU permission/EOF
faults take precedence over that request, and no output is exposed on failure.
The allocator journal still preflights all output before its first mutation:
this protects original-code fallback and is not a second memory permission
policy. Scoped host pointers and region guards never survive a guest callback.
Per-field C/Rust callbacks, original allocator locking and cold-path fallback
remain costs to address; sharing the access model alone is not a speed claim.

Malformed/extreme metadata must not invoke host C undefined behavior. Checked
class indexes, input sizes, signed-offset bounds and framing stride admission
select original code before effects. C callback failures use ordinary checked
returns, with no longjmp/unwinding across Rust and no fabricated host pointers.
Original scalar memory accesses retain region guards, COW, atomic reservations,
code invalidation and dirty commit hooks.

Metrics distinguish allocator_calls, allocator_slot_reservations,
allocator_allocations (native framing completions), allocator_frees and
allocator_free_resumes. The existing bulk byte counters describe the earlier
copy/scan/parser transports, not these scalar metadata accesses.

## Next implementation batches

1. Completed: original-source provenance, guest/native layout checks, existing
   group allocation, original atomic free and unlock-before-framing boundaries.
2. Unsupported cases choose the original path before any mutation. Upstream free
   invalidates slot headers before deciding to take its slow path, so selecting
   native versus original needs a reviewed pre-effect admission step; pasting a
   fallback return after those writes is unsafe. Concurrent observations used
   for admission must be revalidated under the original synchronization.
3. Add cold paths through resumable guest-kernel requests while retaining the
   original C algorithm. Once mutation begins, resume the same operation; do not
   replay original malloc/free after partially changing lists or slot headers.
   A suspension must capture locals/control state before unwinding host frames;
   no borrowed span or ordinary native stack pointer can serve as continuation.
4. Extend the same implementation to realloc/calloc/alignment and public aliases.
   Original guest wrappers can remain while compatible allocator entry points
   become native. Add profiling evidence before broadening the default profile.

The existing 1 MiB pure-copy limit is not an allocation-size limit. Metadata
work and any realloc/calloc payload movement need their own bounded/resumable
contract; larger allocations must remain supported through original cold paths.

## Acceptance

Compare the native-enabled path against the pinned original allocator for zero
sizes, overflow/ENOMEM, size-class boundaries, alignment, zeroing, realloc data
preservation, usable-size results and errno. Exercise original-to-native and
native-to-original allocation/free/realloc transitions, early loader allocation,
cross-thread frees, concurrent allocation, fork/COW/atfork, shared VM and actual
mapping growth/shrink. Fault injection must verify no replay after side effects.

Check memory safety with sanitizer coverage of both the access shim and compiled
native C, and test on actual ARM64 as well as development hosts. Then run one
allocation-heavy microbenchmark and unchanged Vim/Python/Node workloads with
acceleration off/on on the same build. Report entry/translation/lock/checkpoint
costs and regressions; source reuse alone is not proof of a speedup.

[Validation](../validation/native-allocator.md) records the actual batch and its
measured limits. Cold allocator/kernel operations remain original guest code;
this is not a fully native allocator release.
