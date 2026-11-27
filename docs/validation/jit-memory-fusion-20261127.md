# Mixed native memory blocks — 2026-11-27

Scalar memory now shares a generated execution block with surrounding integer
instructions and same-block backedges. This removes repeated returns through the
main JIT dispatcher. The controlled memory-loop median falls from **4.462 ms to
1.854 ms (2.41x)**, while the cached interpreter takes **0.931 ms**. Fusion closes
much of the gap but native memory remains about **1.99x slower** on this workload.
Short SVC boundary microbenchmarks still regress; they are retained below.

## Why native fragments lost to the interpreter

The previous lowering returned to Rust between memory fragments and surrounding
ALU/branch blocks. Entry preparation, identity/handle checks and register binding
publication/reload surround a three-word BTI/LDR-or-STR/RET fragment. The interpreter
already caches decoded instructions, uses tail-call dispatch, and uses the shared
fixed-width scalar memory path; on this AArch64 host those accesses also execute
native loads/stores. Avoiding interpreter decode alone did not pay for the extra
fragment machinery. These source-level costs explain the direction; no per-function
cycle profile or percentage attribution is claimed.

The fixed five-instruction LDR/add/STR/SUBS/B.NE loop took about 68.1 ns per iteration
before fusion, 28.3 ns after, and 14.2 ns in the cached interpreter. These are whole
loop times, not the latency of an individual hardware memory instruction. The new
path still calls a typed checked-memory helper and the tiny native fragment for
each access. Further helper/translation integration is needed before claiming a
memory advantage over the interpreter or any host/KVM performance ceiling.

## Implementation and boundaries

- Existing instruction-epoch embeddings compile mixed blocks; unknown embeddings
  keep their checked single-access path. Same-block loops re-enter budget/epoch
  guards without a main-dispatch return. Normal scalar/SVC native-entry ABI and
  the existing Stats fields remain unchanged; hot short SVC hits are separated
  from the general block Result path.
- Every guest memory instruction retains its own Memory/View read or full-store
  borrow. No lease or translated data pointer is retained in compiled metadata;
  no widened algorithm lock, strengthened guest RMW, extra ordinary-memory fence,
  coordinator, guest code rewrite or extension-state emulator is introduced.
- Helpers publish dirty bindings before borrowing CPU/mm. Generated code refreshes
  the register pointer from the helper's last CPU sub-borrow before reuse. The
  original raw CPU parent stays suspended during the native entry. Boxed decoded
  operands cannot move while generated literals reference them.
- Errors and code identity changes exit at the exact reached/post-store PC, with
  precise SP/NZCV, successful prefix and retirement accounting. Failed operations
  do not commit base/result writeback or replay an earlier successful store.
- Helper-bearing entries use a typed larger frame. Generation-checked metadata
  edges may resolve them; ordinary native links cannot jump into that ABI. Cold
  compilation/memory metadata is kept outside the hot cache state. Cache size is
  still bounded by the existing 128-node/64-instruction limits.
- Android's existing flag 6 additionally requires its load/add/store/SVC probe to
  complete in one fused entry. JNI remains schema 1 / 40 bytes. Android app-UID,
  4/16 KiB devices and ART signal coexistence remain separate device acceptance.

## Validation

Actual ARM64 Linux/4096-byte pages passes **5 native/capability tests and 31
semantic differential tests**, plus strict all-target JIT Clippy. The added tests
exercise all budget cuts in mixed loops, carry flags across helper calls, SP,
Memory and parallel View state, dirty-prefix faults at each instruction, repeated
faults without replay, and concurrent code writes interrupting a running fused
loop. Existing cross-page, permissions, COW, exclusive invalidation, generation
revocation and allowed lost-update coverage also passes.

macOS passes 31 JIT differential cases and the Android core JIT build/test; scoped
macOS Clippy and compile-time backend graph checks pass. Real ARM64 Linux runs the
strengthened Android core probe, requiring one fused entry, two native accesses
and zero fallback. Shared Memory/interpreter sources and the iPad dependency graph
are unchanged; their prior passing suites and iOS interpreter compile are reused.
The preceding d764fc7 global Runtime CI ultimately passed on both Linux and Mac:
[run 46016924642](https://github.com/project-trames/trames-runtime/actions/runs/46016924642).

## Controlled CPU-only measurements

Base Runtime is `d764fc7b920aa73e31b7a91c88512b36c349c5eb`. Both independent
release binaries run the **unchanged exact fixture**. Five alternating process
pairs run on VM vCPU 2 after task-owned compilation ends. Each process has one
warm-up and five timed samples; the table uses medians of its five process medians.
Toolchain nightly-2026-10-16, release thin LTO, overflow checks, incremental off.

| Workload | Previous JIT ms | Fused JIT ms | Previous/fused |
| --- | ---: | ---: | ---: |
| integer-loop | 3.601 | 3.531 | 1.020x |
| svc-round-trip | 0.603 | 0.641 | 0.941x |
| svc-only | 0.548 | 0.598 | 0.917x |
| svc-continuation | 0.852 | 0.941 | 0.905x |
| integer-countdown-compare | 1.820 | 1.766 | 1.031x |
| integer-countdown-flags | 1.788 | 1.799 | 0.994x |
| scalar-memory-loop | 4.462 | 1.854 | 2.407x |

SVC-only latency is **9.1% slower**, continuation **10.5% slower** and round-trip
6.3% slower in this cohort. For 100,000 exits these differences amount to about
0.50, 0.89 and 0.38 ns per exit respectively. They remain a follow-up, not a claim
of zero SVC regression. These CPU-only boundaries exclude real syscall handlers,
JNI, startup, Android lifecycle and scheduler interactions; no application-level
speedup or KVM/bare-metal ranking is inferred.

Each memory pass retires 327,681 instructions: 65,536 loop iterations and one SVC.
Six passes including warm-up verify 786,432 native memory operations, zero memory
interpreter fallback and final counter 393,216. The interpreter/new JIT memory
medians are 0.931/1.854 ms. All final raw outputs, source/binary fingerprints and
exact fixture are [frozen here](jit-memory-fusion-20261127/). Earlier development
runs, including scheduling/clock variation, are archived separately and never
spliced into the final cohort. Their intermediate sources are not presented as
the final implementation. No new VM, Android SDK/NDK/JDK or emulator was installed.
