# Shared software execution

`trames-interpreter` and `trames-host-compute` are the canonical software CPU
implementation, extracted from `project-trames/trames-ipad` commit `a042d8d8ea5f6e94676682fe5a721f509f6a67da`
(`crates/trames-cpu` and `crates/trames-compute`). The implementation and its
existing tests moved together. Product compatibility crates re-export these
types; there is no additional dispatch or memory layer.

`trames-jit` is a second `trames-engine::Cpu` composition over that interpreter.
The `native-aarch64` feature is off by default and must be explicitly enabled
by the Android product. iPad depends only on `trames-interpreter`, so JIT and
executable-cache code are absent from its compilation graph. It uses the same checked memory views, Linux runtime, register state, feature
profile, worker ownership and syscall exits. CPU crates are optional workspace
members: shared kernel/session/memory crates never depend on them. An independent
CPU repository would complicate paired versions without providing an API benefit.

The initial native compiler targets AArch64 hosts on Linux/Android. Other hosts
use the interpreter and report native availability as false. Native blocks now cover baseline integer arithmetic/logic, SP forms, NZCV,
carry/conditional operations, multiply/divide, bitfields/variable shifts and
fixed, conditional and register branches. CRC, FlagM/FlagM2 and CSSC use their
actual host instructions only when the process-host HWCAP provides them.
There are no new software replacements or emulated extension registers.
Scalar, paired and ordered memory, LSE CAS/CASP/RMW and RCpc accesses now use
native memory paths as described below.
Common scalar FP and NEON arithmetic also execute natively. Vector memory,
exclusive reservations, traps and remaining untranslated families still retain
the legacy interpreter path. Full host-ISA native coverage remains in progress;
this is not yet a claim that every host instruction has a native lowering.

Original guest instructions are never changed. Derived code is private to each
worker, bounded, and published RW -> RX, never RWX. Guest page identities drive
invalidation at block entry, using the existing decoder invalidation model.
Blocks do not cross 4 KiB guest pages; host allocations use the actual host page
size, including 16 KiB Android hosts. x0 retains the register-frame pointer; x1-x13 hold block-local guest values.
x14/x15/x16 carry linked-block count, remaining budget and execution context;
x17 is the jump scratch. Dirty evictions and block exits write values back. Host x18, TLS, FP state and
callee-saved registers remain intact. Allocation runs only during compilation;
ordinary translated instructions perform no dynamic register/feature checks.

Guest SVC is compiled as a terminal block exit, with register writeback and
exact instruction retirement/PC advancement. It returns `SliceOutcome::Syscall`
without entering the interpreter or executing a host SVC. The common Session
worker's syscall dispatcher still owns guest syscall policy, arguments, results,
blocking/retry and tracing. Android's initial app currently validates the CPU
exit only; its full shared Session integration is a separate milestone.

Register choices follow [AAPCS64](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
and [Android's reserved-x18 requirement](https://developer.android.com/ndk/guides/abis#arm64-v8a).


## Same-page links and syscall continuation cache

Each worker owns 128 stable RW jump slots alongside bounded RX code mappings.
A cold lookup resolves a fixed, same-guest-page edge; later entries branch
through its slot without returning to the Rust block-dispatch loop. Natural
blocks use canonical cache keys. Exact-budget prefixes remain available for
stepping but cannot replace full-block hot edges.

A 120-byte native entry frame supplies GPR storage, budget and borrowed existing
instruction epochs. Budget and block counts stay in caller-saved registers while
chained; every exit publishes the actual guest PC and retirement count. No full
architectural-state copy occurs. Ordinary translated accesses acquire no new
checks or barriers. Entry guards use acquire only for the existing parallel-code
publication counter and relaxed loads for backing/external notifications.

`CpuMemory::instruction_epochs` is an optional cold observation capability.
Memory/View expose only counters already used by instruction identities, for the
current borrow. Unknown embeddings default to no chaining. Native code retains
no memory/epoch pointers after returning. An epoch change unwinds the chain and
invalidates links before revalidation. Mapping/permission changes between
entries use the existing checked memory identities.

A terminal SVC preserves its lightweight scalar entry. For stable same-page code,
a fixed ordinary block followed by an SVC block can tail-jump directly into the
latter's scalar entry when the complete pair fits the budget. Mutable code keeps
per-block epoch guards. Every SVC still returns to the ordinary Runtime syscall
dispatcher; no pair can execute two SVCs without that return.

After syscall handling, the next entry can use a generation-checked cached
continuation if guest PC, memory identity and budget match. Registers and syscall
numbers remain current; results and policy decisions are not cached. Blocking,
signal redirection, restart and worker migration retain the existing scheduler
path, with cache misses falling back to lookup. Incoming links are cleared before
RX eviction; generation handles reject slot/address reuse. Only RW link data is
updated after publication; guest bytes and RX instructions remain unchanged.


## Host-driven ISA and integer/control-flow coverage

The native backend reads process `AT_HWCAP`/`AT_HWCAP2` once. Its dynamic
`Cpu::features()` / `feature_names()` no longer advertise the interpreter's
fixed software-only capabilities. During migration, the guest mask is the
intersection of actual host capabilities and the existing shared CPU ABI;
`host_features()` exposes the unfiltered process-host mask for diagnostics.
Stateful extensions require their real context-save path before advertisement.
The target is complete coverage of the host ISA, not a second virtual extension
model. Platform/interpreter-only builds keep their existing software profile.

Capability gates for the newly translated extension families execute only in
cold translation. Missing CRC/CSSC/FlagM/FlagM2, RNDR, MOPS and LSE128 instructions
fault when reached rather than acquiring a software replacement. A preceding
translated prefix retires before that fault. Added scalar extensions emit the
host opcode with compile-time register remapping; no per-instruction feature
probe or additional extension state is maintained.

The entry frame carries temporary SP/NZCV values for the existing task state.
Virtual SP uses a compiler-only register binding; generated code never changes
host SP or x18/TLS. Guest NZCV uses the hardware flags, materialized into existing
CPU state at entry/exit. Block guards may clobber host flags, so an instruction
that reads flags restores guest NZCV first; dirty flags are captured before the
next guard. No full architectural-state copy or additional per-task register bank
is introduced.

A dynamic block publishes its selected guest PC and follows its stable RW link
only if that PC matches the resolved edge. Register branches never jump to a
raw guest address as host code. Cold resolution still enforces checked identity,
same-page ownership, canonical budgets and generation handles. Both conditional
outcomes remain exact; repeated loop edges chain natively, while a different
outcome returns to normal lookup. Original guest bytes and published RX words
remain unchanged.

See [native scalar validation](../validation/jit-host-scalars-20261127.md).


## Native scalar memory blocks

Integer LDR/STR byte/halfword/word/doubleword, signed loads, immediate/unscaled,
pre/post-index, extended register offsets, literal loads and optional PRFM hints
have cached native fragments. Cold decode selects the exact baseline host LDR/STR
opcode. The helper computes the decoded guest address and commits result/base
writeback only after success. The checked slow path uses the existing `CpuMemory` read/full-write
callback. The hardware-alias path below retains bounded, entry-scoped operands
without placing data pointers in the compiled-code cache.

`cpu_store_chunk` is a full-overwrite contract. Memory/View reuse existing write
borrowing and dirty/code/exclusive publication. Staging-only providers need not
read old bytes. Cross-page data uses canonical read/write staging before the same
exact-width native fragment; CPU results remain precise on faults. Ordinary
Memory read/write paths acquire no new fields, probes or permission policy.

Embeddings with instruction-epoch capability now compile mixed integer/memory
blocks. A generated call flushes dirty bindings before a typed, monomorphized
helper and reloads a fresh register sub-borrow afterward. The helper takes one
scoped access, checks current code identity, and returns either to the next native
instruction or a precise fault/code-change exit. Faults publish the dirty prefix,
SP/NZCV, reached PC and retired count without replay. Helpers return faults as
values; Rust unwinding cannot cross the generated native stack.

Same-block backedges stay inside the native entry through the existing budget
and epoch guards. LDR and STR still release independent borrows: merging code
never makes their read/modify/write algorithm atomic. Unknown epoch embeddings
retain the existing single-access path. Helper-bearing blocks keep a separate
entry-frame ABI; generation-checked metadata edges can point to them, but ordinary
native machine links cannot. Boxed decoded operands remain stable and worker-owned
until the code node is evicted. The existing node/block limits bound the cache.

Cold indices, compilation totals and memory diagnostics are kept outside the hot
entry state. Steady-state short SVC hits bypass the general block result path;
the published scalar/SVC machine-entry ABI and existing Stats fields are retained.
`Engine::memory_stats()` adds fused-entry/block counts to native-memory/staging
counts; these are updated only by memory execution. No extension register model,
algorithm lock, coordinator, guest code rewrite or ordinary-memory fence is added.

The following sections extend this original scalar lowering with paired/ordered
accesses, LSE and RCpc. Vector memory fusion and exclusive-reservation lowering remain pending.

### Entry-scoped hardware aliases

Native scalar memory blocks first try the register-held affine path described
below, then an inline 64-slot guest-page tag lookup. Both retain guest-page
containment and LDR/STR through the existing protected CPU alias. The final translation and page protection use the
host MMU. Cache hits keep guest registers bound in host registers, skip the Rust
helper and do not acquire a region lock or add a memory fence. Guest TBI follows
the shared memory model; the remaining guest address is compared in full, never
masked into a host arena or a different guest page.

Cold entry admission selects this lowering. Direct Memory exports only unique,
resident, anonymous, non-executable pages with a protected alias, and discards
all operands before the next checked helper. Frozen worker Views retain operands
across scalar helpers only under existing private-epoch admission: one actor can
read/write eligible private pages; multiple actors may read immutable pages.
Shared writable/COW pages, backing providers, unpaid pages, userfault/async policy
and software-only host-page groups decline. The existing checked lowering stays
available, including its permissions, independent read/store borrows and staging.

A successful checked store admits further writes and publishes private-page dirty
fragments/reservation invalidation once before returning the alias. No write
admission is inferred from a read. All potentially writable fragments of that
private page are marked; there are no concurrent private actors or backing
writeback providers to overwrite. Exclusive-reservation instructions, syscalls and
native callbacks end the generated block/operand loan. Native stores therefore
cannot hide a write from a later guest exclusive operation. Direct Memory also
advances its existing data/revision and parallel-write metadata. Alias pointers
never outlive their canonical owner, entry, frozen mapping or permissions.

Each generated faulting instruction registers its exact native PC and local slow
continuation using the opt-in memory `native-code` feature. The existing handler
recovers only hardware faults inside a registered CPU alias; unrelated signals
continue through the existing handler chain. The dynamic registry is bounded,
uses only lock-free atomics in signal context and is retired by the thread-affine
code owner before RX unmap. Recovery flushes the pre-instruction bindings, runs
the checked access, reloads the helper's fresh register-array borrow, and rejoins
without replaying the prefix. SP/writeback/results retire only after success.
No Rust stack frame or destructor is skipped.

A 16/64 KiB host page is used directly only when the existing alias layer can
represent its entire group without guest permission leaks. Mixed 4 KiB groups,
holes and cross-guest-page operands use the established slow path. The guest
page size remains 4 KiB. iPad/interpreter builds do not enable `native-code` or
compile the JIT/executable allocator. The scalar/SVC frame and tail fast path
remain separate from the larger helper frame.

`MemoryStats::hardware` counts actual inline accesses; other public instruction,
staging and fused-entry counts retain their meanings. See
[hardware-memory validation](../validation/jit-hardware-memory-20261128.md).

See [fusion validation and complete measurements](../validation/jit-memory-fusion-20261127.md).

### Register-held affine regions

The hardware entry now keeps a connected admitted region's guest base, final
legal start offset and fixed host bias in x19/x20/x21. Successful exports grow a
region only when adjacent/overlapping pages have the same bias and sufficient
rights, with a 1 MiB bound. No virtual arena or physical copy is added. Mixed
read/store blocks require both read and prepared write rights; load-only blocks
can use read-only exports. A read cannot invent dirty/write admission. Unknown
pages, holes and different biases never become part of the region.

Region hits replace indexed page-cache lookup with register subtraction/range
comparison and fixed-bias addition. The existing page cache and checked helper
remain the fallback. Every non-reused access retains one-guest-page containment,
including unaligned operands, so a faulting cross-page store cannot partially
retire through this optimization. The block's widest memory operand supplies a
conservative region bound; narrower boundary operands can use the fallback.

Cold compiler register-definition versions identify unchanged effective addresses
(base/SP, index, extension/shift and offset), not just equal register names.
x22 holds the derived host address and x23 marks a valid direct proof. A later
same-address access of no greater width can reuse it; a helper always clears the
proof, reloads the affine descriptor and refreshes the CPU register-array borrow.
Pre/post-index addresses are normalized for checking, while guest base writeback
still retires after the actual access and invalidates future base proofs.

For a same-block backedge whose first guest instruction is memory, a verified
invariant first/last address can retain the proof through the existing epoch and
budget guards. The base/index must be unwritten throughout the whole block and
the final proof must cover the first operand width. First entry and helper
recovery have x23=0 and recheck. This is a cold proof; it adds no per-instruction
ISA probes, register-version counters, new CPU state or synchronization.

Hardware-memory entries save x19..x23 in a balanced 48-byte AAPCS64 frame and
restore them on normal, helper/fault, epoch and budget returns. Scalar/SVC entries
retain their original frame/layout and tail path. Exact native fault recovery
sites cover reused addresses as well as region/page-cache accesses; all routes
preserve guest NZCV and retire result/SP/base changes only after success.

`MemoryStats::direct` counts actual region/reused-address accesses and remains a
subset of `hardware`. Its selected counter replaces the page-path increment,
without adding another increment per access. `CompilationStats::address_reuses`
counts emitted reuse sites, not dynamic executions. The original counters and
JNI layout remain unchanged. See [affine validation and full measurements](../validation/jit-affine-memory-20261128.md).

### Paired and ordered native memory

Integer LDP/STP (W/X), LDPSW and LDNP/STNP share the scalar page/affine/address
reuse path. Total operand width is 8 or 16 bytes, covering both registers. The
emitter remaps both registers into **one original host pair instruction**; it
does not synthesize two singles, stronger atomicity or a software extension state.
Offset/pre/post-index, sign extension, non-temporal hints and architectural
zero-register behavior remain native. Cold decoding excludes reserved and
constrained-unpredictable forms. Cross-page and non-borrowable operands retain
the existing checked whole-operand transfer and fault publication boundaries.

LDAR/STLR B/H/W/X execute their actual host instruction against canonical shared
bytes. Native hits add no software alignment preflight, stronger fence or new
lock. The original page-custody bound remains shared with ordinary accesses;
same-address width proofs still skip it. Hardware controls alignment behavior
on native hits, including the host's LSE2 rules; there is no new strict software
alignment model for buggy guest programs. Checked recovery keeps the existing
interpreter fault boundary. Acquire/release does not terminate a private alias
loan; exclusive-reservation operations still do. LSE is described below.

The cold embedding capability `cpu_hardware_ordering` admits Memory/View, while
unknown CpuMemory implementations retain their abstract interpreter/fence hooks.
Scoped ordered borrows use actual aligned RAM directly. Providers that cannot
lend storage or whose host pointer cannot represent the operand use the existing
staging transport: acquire follows the canonical read, release precedes canonical
writeback. An ordered access on a temporary alone cannot publish real bytes.
Those exceptional transports use no new algorithm/global lock. Const-generic
ordinary access paths retain their old behavior and emit no additional fence.
All ordered hooks/storage helpers are opt-in through `native-code`.

Valid DMB/DSB domain/type options and ISB SY are emitted unchanged. They preserve
GPR/NZCV bindings and do not invoke a catch-all SeqCst Rust helper. No ISA-support
probe is added to execution. The pair helper uses AAPCS64 x0/x1/x2 arguments and
a two-u64 x0/x1 result, without touching host x18/TLS or callee-saved registers.
The existing exact-site native fault recovery covers pair/ordered instructions.
See [paired/ordered validation and matched measurement](../validation/jit-pairs-ordering-20261128.md).

### Native LSE and RCpc

Host HWCAP gates CAS/CASP, SWP, LDADD/LDCLR/LDEOR/LDSET and signed/unsigned min/max
(including byte/halfword, discard-result aliases and all acquire/release variants)
in the cold compiler. LDAPR requires LRCPC; LDAPUR/STLUR and signed unscaled loads
require ILRCPC. An absent extension faults when reached instead of acquiring an
interpreter implementation. No hot feature probe, software CAS loop, stronger
ordinary fence or additional CPU extension state is added.

Private hardware aliases use the existing page/affine/address proof and a single
original LSE instruction. Write admission publishes dirty/reservation metadata
before allowing inline RMW, as for native stores; no exclusive-reservation
instruction can overlap that loan. Independent shared writers cannot obtain a
private alias. Shared Views execute the actual instruction on canonical bytes
inside their existing region transaction and publish existing version/code
metadata conditionally. Quiescent Memory lends its existing anonymous/COW bytes
with write intent; a failed CAS may conservatively lose an earlier reservation
or prepare a private page, consistent with hardware write intent. Backing-only
providers retain their previous transaction/staging boundary; release precedes
canonical publication and acquire follows observation. The native-only hook is
compiled out of ordinary interpreter/iPad builds.

CAS/CASP inputs are captured before any guest output is changed, including base,
compare/replacement aliases and W/X zero registers. CASP remaps onto fixed even
pairs x10/x11 and x6/x7, keeps the selected diagnostic counter in x13 and leaves
NZCV recovery in x12. It remains one atomic 64/128-bit host operation. Reserved
registers are excluded by the cold allocator even when their slots are vacant;
this also fixes ordinary memory code under high register pressure. No new guest
error recovery precheck is emitted. The existing exact native fault site rejoins
checked access before publishing outputs or replaying a dirty prefix.

RCpc accesses retain their actual opcode and ordering; native hits do not
substitute the interpreter's stronger abstract fence. Signed/unscaled offsets
share ordinary address computation. See [LSE/RCpc validation and full matched
measurement](../validation/jit-lse-rcpc-20261128.md).

### FP/NEON register blocks

The cold decoder classifies scalar FP arithmetic, precision/integer conversion,
comparisons/selects/FMA/moves and common NEON integer/logical/saturating/FP
arithmetic. Each operation preserves its original opcode, rounding and fused
semantics. Baseline FP, AdvSIMD and optional scalar FP16 use the process-host
capability profile. H<->S/D precision conversion is baseline FP, separately from
FP16 arithmetic. No per-instruction capability query or software arithmetic
replacement runs in these generated bodies.

A cold LRU allocator binds the existing 32 guest vectors to host v16..v31. Loads,
dirty evictions and final stores address the existing interpreter vector bank;
V31 is a real vector, independent of XZR. Sources/accumulators are pinned before
destination allocation. Callee-saved d8..d15, host x18/TLS and host callee GPRs are
untouched. Dirty vector flush uses x11 after GPR/NZCV publication, preserving x17
when a dynamic guest PC has already been selected. Compiler traffic counters now
include vector-register loads/stores. A 31-FADD chain needs two vector loads and
one store, rather than copying a full architectural state around each operation.

FP entries use a separate 128-byte VectorFrame with the original 120-byte Frame
prefix and one vector-bank pointer. Scalar/SVC and memory-frame layouts stay
unchanged. The CPU exposes its two existing disjoint register banks in one borrow;
no reborrow of the CPU parent overlaps a live child pointer. Both raw pointers
expire at native return and are never retained by the cache. There is no new
per-task vector or extension-state model.

The existing host-compute Scope installs the established guest FPCR/FPSR policy
once around a native entry; the final hardware FPSR is merged into existing guest
status, and host FP environment is restored. There is no call between translated
FP instructions. Same-block loops reuse the existing budget/epoch guard, and
FP comparisons share the GPR compiler's live NZCV model. Memory/provider/native
callbacks and untranslated system instructions terminate the FP block before
entry into Rust. FP/memory blocks currently use generation-checked metadata edges
and distinct frame types; vector memory fusion is deliberately still pending.
This leaves no guest FP environment active across a Rust/provider callback.

[Validation, ABI canaries and matched measurements](../validation/jit-fp-neon-20261128.md)
cover rounding, NaNs, infinities, denormals, alternative half conversion, FPSR/QC,
source/destination aliases, spills, dynamic PC, syscall/yield/fault restoration,
and concurrent code replacement at a running FP loop's existing epoch guard.
