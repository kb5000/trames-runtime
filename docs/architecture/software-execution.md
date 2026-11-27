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
use the interpreter and report native availability as false. Native blocks cover
non-flag integer operations and direct branches. Memory, flags, FP/SIMD, atomics,
traps and unsupported operations retain interpreter semantics. This is an initial
backend, not a claim of full JIT coverage or native-equivalent performance.

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

A 96-byte native entry frame supplies GPR storage, budget and borrowed existing
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
