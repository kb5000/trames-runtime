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
Scalar LDR/STR now use checked native memory fragments as described below.
FP/SIMD, atomics, traps and remaining untranslated families still retain
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
writeback only after success. Each real same-page access stays inside the existing
`CpuMemory` read/full-write callback; no host data pointer or lease is cached.

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

Fusion removes repeated main-dispatch returns but still calls the checked helper
and a tiny native fragment for each access. The cached interpreter's scalar path
already uses decoded tail handlers and its canonical fixed-width memory access;
executing a host LDR/STR alone does not make the surrounding JIT machinery faster.
Further memory-helper/translation integration remains necessary. Pairs, SIMD,
acquire/release and atomics keep their existing path until separately lowered.

See [fusion validation and complete measurements](../validation/jit-memory-fusion-20261127.md).
