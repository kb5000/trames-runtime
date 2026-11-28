# Complete native exclusive-memory category — 2026-11-28

Baseline Runtime `767b92efb81251861576cefdf676a8bb4f15a4e3`; paired Android
baseline `5155eef901031f71f1f35cb5a732b81819600f1c`. This batch completes every
existing fixed-width shared-CPU exclusive encoding without interpreter entry:

| Family | Covered forms |
|---|---|
| LDXR / LDAXR | B, H, W, X, including zero-register destinations and SP bases |
| STXR / STLXR | B, H, W, X; real W status, discarded status and zero data |
| LDXP / LDAXP | W pairs (8 bytes), X pairs (16 bytes), independent/zero registers |
| STXP / STLXP | W and X pairs; original alias constraints and status behavior |
| CLREX | All 16 immediate options, clearing the existing CPU reservation |

## Execution and ownership

Cold compilation selects valid encodings, base/width stability, register aliases,
initial GPR/NZCV preloads and spill-free native windows. Closed same-address
straight-line windows up to 16 instructions use the original host LR/SC and shared
native ALU lowering on resident private RW protected CPU aliases. No Rust helper,
frame load/spill, global/algorithm lock or full CPU copy enters the monitor window.
The sole-executor proof admits unique serial pages, including previously promoted
reservation pages, and exclusive worker epochs. It does not grant shared pointers
that race Rust byte references. Existing publication occurs before the raw loan.
The scalar/SVC frame remains 120 bytes and normal cache nodes keep their layout.

Open/shared sequences, other memory operations, helpers, slices and worker changes
join the original Memory/View reservation domain. Native LR/SC fragments operate
on the same checked bytes, permissions, COW, versions, ABA granules and backing
publication as the interpreter. An LR fragment closes its hardware monitor before
Rust returns. A token-admitted SC fragment uses an adjacent native LR/SC inside
the original byte guard. Its actual failure status changes neither canonical
bytes nor monitor/dirty publication. Staging remains limited to existing provider
transactions or physically unaligned host storage; it is not an interpreter or
software RMW implementation. No host capability is emulated or added.

The existing natural guest-alignment constraint is checked once at window loan
admission instead of once for each LR/SC. The test VM accepts misaligned halfword
exclusives directly as well; using its behavior alone would violate the current
shared-CPU contract. Capability, encoding and allocation decisions remain cold;
address ownership and permissions remain the original dynamic memory boundary.
Both hardware fault sites use the existing native fixup registry. An LR fault
retires nothing; an SC fault publishes exactly the dirty LR/ALU prefix, preserves
old status and rejoins the checked reservation boundary. Guest instruction bytes,
host TLS/x18 and callee-saved registers are preserved. Hardware SC spurious
failures remain valid observable results; guest retry loops handle them.

Arm's [synchronization guidance](https://documentation-service.arm.com/static/68c223238a337a2bc6645c0a)
and [instruction definitions](https://documentation-service.arm.com/static/67e40f3398aa3c3b6eea6a85)
provide the hardware monitor/ordering rules. The [DynamicRIO exclusive-monitor
reference](https://dynamorio.org/page_ldstex.html) also describes why arbitrary
instrumentation between LR and SC cannot rely on a surviving host monitor. The
implementation uses neither guest-text rewriting nor a second monitor algorithm.

## Acceptance

- ARM64 Linux Debug and Release: **18 native unit/capability + 96 differential
  tests (114)** pass. Existing interpreter **48+2+1** passes with the explicit
  reservation representation; no later interpreter semantic change was made.
- Linux memory: **284 unit + 2 metadata + 4 translation** pass; 3 existing ignored
  cases stay ignored. This covers original COW, monitor, backing/truncation,
  mapping identity, residency/accounting, native handoff and region ownership.
- Apple: **92 JIT fallback tests**, interpreter **48+2+1**, memory **281 unit + 2
  metadata + 4 translation** pass, with 3 existing ignored unit cases. Strict
  scoped all-target Clippy passes on Linux and Apple. iOS interpreter compilation
  passes. Interpreter and actual iPad dependency trees contain neither JIT nor
  `native-code`; no iPad worktree/pin was modified.
- Android core default and explicit JIT probes pass on Linux ARM64 and Apple,
  together with strict Clippy and compile-time feature isolation. The new probe
  executes all single/pair widths, real retry status, native CLREX and a fresh
  engine/sliced monitor handoff, checks exact exit/retirement and unchanged text.
  SDK/NDK/JDK/APK work remains on Windows CI. These are CPU probes, not Android
  app-UID/ART, physical device or 16-KiB Android acceptance.

The new category suite includes **720 full-state/byte/slice combinations** across
all widths/orderings, GPR/SP bases, five budgets, serial RAM, guarded workers and
private epochs. It also covers every CLREX option, zero/aliased/high registers,
register pressure, no-reservation stores, dirty-prefix alignment/permission/unmapped
faults, warm-cache budget cuts and already-promoted pages. Cross-thread task
migration preserves the original token; same-value/ABA writes invalidate it while
other granules do not. Four workers perform 800 successful guest-retried updates
without introducing an algorithm lock. Failure comparisons admit real hardware
spurious SC failure rather than forcing deterministic success.

Real revoked-alias LR and SC tests check both raw fixups and end-to-end original
fault classification, whole CPU state, exact retired prefix and unchanged bytes.
A generated-code audit rejects frame memory traffic/helper calls between LR and
SC. Callback-failure and misaligned-provider tests separately verify no false
publication and preserved original tokens.

LLVM 18 independently assembles [400 fixture encodings](jit-exclusive-20261128/category.S),
including all families/widths/orderings, SP bases, high/zero registers and CLREX
options. Its frozen [words](jit-exclusive-20261128/category.words) execute in the
native suite. Reproduce offline with:

```sh
python3 scripts/audit-jit-exclusives.py --llvm-mc llvm-mc-18
cargo test --locked -p trames-jit --features native-aarch64 -p trames-memory -p trames-interpreter
cargo test --release --locked -p trames-jit --features native-aarch64
cargo clippy --locked -p trames-jit --features native-aarch64 -p trames-memory -p trames-interpreter --all-targets -- -D warnings
```

LLVM is not a production dependency. The fixture closes the declared category;
it is not exhaustive enumeration of every 32-bit instruction word.

## Matched CPU-only measurements

Same Lima ARM64 Linux VM, 6 vCPUs/8 GiB, 4-KiB pages, kernel
7.0.0-44-generic, rustc 1.101.0-nightly (4ebd25825), thin LTO, overflow checks and
no incremental build/affinity. No build overlaps timing. Both binary identities
and actual fallback/native counts are audited; stale shared-target example
outputs detected during preparation were discarded before these measurements.

The [benchmark](../../crates/trames-jit/examples/exclusive-category.rs) runs
262,144 successful guest updates per exclusive sample, including guest retry
branches and CPU slice boundaries. Four balanced old/new and new/old pairs use
8 processes, **200 timed + 40 warm-up samples**. Integer/scalar-memory controls
aggregate 64 runs per sample because one control run is too short for stable
frequency-sensitive measurement; resets occur outside timing. Every sample
compares complete CPU state and the canonical 4-KiB data page to an untimed
interpreter reference, verifies original text and derives actual retirement from
successful trips plus real retries. All candidate fallback counts are zero.

| Workload | Previous JIT, ms | New JIT, ms | Speedup |
|---|---:|---:|---:|
| Private LDAXR/STLXR | 44.206 | 11.659 | **3.79×** |
| Private LDAXP/STLXP, 128-bit pair | 45.226 | 11.754 | **3.85×** |
| Guarded shared LDAXR/STLXR | 36.042 | 29.487 | **1.22×** |

Medians are the median of four process medians. The scalar-memory control takes
about 1.0% less time and the integer control about 0.8% more time. This compares
the previous JIT's interpreter-exclusive fallback to this batch, not complete
applications, Android/JNI or native/KVM execution latency. Shared guarded memory
still pays its original byte-ownership/version transaction; further loop/alias
amortization is a separate optimization.

Reproduction, raw samples, exact binary hashes, process medians and source hashes:
[runner](jit-exclusive-20261128/run-benchmark.py),
[raw samples](jit-exclusive-20261128/benchmark.jsonl),
[summary](jit-exclusive-20261128/benchmark-summary.json),
[source manifest](jit-exclusive-20261128/source-sha256.json). Copy the same
benchmark source onto baseline `767b92e`, build both variants and retain each
binary before switching sources. With a shared Cargo target, refresh the affected
source mtimes/rebuild before copying; verify distinct hashes and expected
fallback counts. Then run:

```sh
python3 docs/validation/jit-exclusive-20261128/run-benchmark.py \
  --old /absolute/path/old-binary --new /absolute/path/new-binary \
  --out /absolute/path/results
```

Remaining native categories are special memory (MOPS and explicitly admitted
LOR/LSE128/LS64) and the existing non-hint PAC/MTE compatibility operations.
Unowned stateful SVE/SME and full hardware protection ABIs remain unadvertised.
