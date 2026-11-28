# Mixed vector memory / FP / NEON — 2026-11-28

B/H/S/D/Q scalar vector loads/stores and S/D/Q paired transfers now fuse with
native FP/NEON and integer instructions. Addressing includes unsigned/unscaled,
register offset, pre/post writeback and S/D/Q literals; pairs include LDNP/STNP.
Each hit uses the original-width hardware load/store and existing CPU aliases,
affine region and unchanged-address proof. Q pairs remain one 32-byte operand.
There is no guest code rewrite, new access preflight, ordinary-memory fence,
global lock or per-instruction capability query. Admission and allocation run
in the compiler. [Implementation and ownership](../architecture/software-execution.md#mixed-vector-memory).

FP entries use the original 120-byte Frame, with its offset-96 pointer carrying
the existing vector bank instead of the native edge-PC table. FP interblock
edges use checked metadata; same-block loops keep the budget/epoch guard.
Ordinary scalar/SVC and MemoryFrame offsets remain unchanged. Mixed entries
append a local FP callback tail to MemoryFrame. A checked helper publishes dirty
GPR/NZCV/vector values and switches to the caller's original host FP environment
before Rust/provider execution. It refreshes both existing register-bank loans,
then restores guest FP state and reloads live bindings on return, including fault
and code-change exits. The runner receives a raw whole-frame pointer; its CPU
reborrow begins only after native return. Alias hits skip this bridge entirely.

Load destination reservations preserve the previous dirty value until the
native instruction succeeds. The existing one-guest-4-KiB boundary routes
cross-page operands through checked staging; vector outputs and base writeback
retire only after the full operand succeeds. Existing registered CPU-alias fault
recovery resumes at that exact instruction without replaying its dirty prefix.

Structure/lane/replicate vector transfers, remaining SIMD arithmetic, SVE/SME
memory, native exclusive reservations and native FPCR/FPSR system instructions
remain outside this batch. This is not complete ISA or Android product acceptance.

## Validation

ARM64 Linux passes **11 unit/capability + 64 differential tests (75)** in Debug
and Release, plus strict all-target JIT Clippy. Apple passes **61 differential
fallback tests**, 4 host-compute tests and scoped strict Clippy; Apple does not
execute this native JIT. Linux host-compute also passes 4 tests. Formatting,
execution boundaries, iOS interpreter compilation and its dependency isolation
pass. The iOS interpreter graph excludes JIT/native-code allocation. Shared
interpreter and memory implementation are unchanged; the preceding interpreter
48+2+1 and memory Linux 282+6 / Apple 279+6 results (3 ignored each) are reused.

Matrices cover every scalar width, scalar/pair addressing, load/store direction,
SP/TBI, real V31, independent X/V numbering, exact writeback and retirement,
cross-page success/failure, Memory and private View execution, and slice budgets.
Pressure cases exceed sixteen vector bindings, force dirty evictions and reload
live banks across checked helpers. A fault after dirty FP/NEON work preserves
old load targets. Forced revoked aliases test precise hardware recovery for
scalar, vector and pair instructions with a dirty FP prefix. Staging-only full
stores do not read the previous provider bytes. A shared provider asserts that
callbacks see the host FP environment, raises host FP exceptions, and verifies
that guest status remains isolated on both success and EIO fault exits.

Android core default/JIT probes pass on Linux ARM64 and Apple. Added Q LDR/STR
and Q LDP/STP loops include NEON ADD and V31, complete canonical lane checks,
exact retirement, zero fallback/staging, at least 62 of 64 direct hardware
accesses, address-proof reuse and one fused entry per loop. Existing probes
continue to pass. JNI schema 1 / 40-byte layout / flags remain unchanged. Android
SDK/NDK/JDK/APK work stays on Windows CI. These tests do not establish real
Android app-UID/ART/16-KiB device behavior.

## Matched measurement

Baseline Runtime `05c4fc1d1065d1d8fdde3e1fd52a9ce90a31b89d`; candidate is that
base plus this batch's hashed sources. Same Lima ARM64 Linux VM, kernel
`7.0.0-44-generic`, 4-KiB pages, 6 vCPUs, rustc
`1.101.0-nightly (4ebd25825 2026-10-15)`, thin LTO, overflow checks, no incremental
compilation or imposed affinity. No other VM compilation runs during timing.

Four balanced old/new pairs alternate execution order. Each process runs all six
workloads with one warm-up and five timed samples: **8 processes, 240 timed and
48 warm-up samples**. Table values are medians of four process medians. Every
loop runs 1,048,576 iterations; scalar vector cases do load/add/store/SUBS/B.NE,
pairs add both vectors, and the stream advances by 16 bytes through 16 MiB.
Initialization/validation is outside timing. Original guest words, exact
retirement, complete canonical bytes, all final vectors and PC agree across
builds. Memory is committed and checked again after dropping the worker View.

| Workload | Previous JIT | New JIT | Speedup |
|---|---:|---:|---:|
| Q load / NEON ADD 4S / store, hot address | 96.152 ms | 1.177 ms | 81.68× |
| Q load / NEON FADD 4S / store, hot address | 96.010 ms | 1.193 ms | 80.50× |
| Q pair load / two ADD 4S / pair store | 106.664 ms | 2.699 ms | 39.51× |
| Q load / ADD 4S / post-index store, 16 MiB | 97.506 ms | 1.980 ms | 49.25× |
| Integer load/add/store control | 1.238 ms | 1.183 ms | 1.05× |
| Scalar FADD loop control | 1.872 ms | 1.865 ms | 1.00× |

All new mixed workloads have zero interpreter fallback/staging, over 99% direct
hardware memory accesses, and one fused entry per sample. Previous vector memory
instructions fell back individually and split arithmetic blocks. Gains include
removing those dispatch/entry boundaries; they are specific CPU loops, not
application speedups or evidence of KVM/native equivalence. Controls move by
−4.42% and −0.33%; do not treat that variation as a general optimization claim.

[Exact fixture/build lockfiles, raw cohort, source/binary hashes, logs and summary](jit-vector-memory-20261128/)
are retained. Run `python3 jit-vector-memory-20261128/audit.py` to verify hashes,
paired work/counters and recompute all numbers; an optional Runtime source path
verifies the final candidate sources. No VM image, SDK or build cache is committed.
