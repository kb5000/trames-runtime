# Native FP / NEON register blocks — 2026-11-28

Common scalar FP and NEON arithmetic now execute their original host instruction
with a cold vector-register allocator. Guest V0..V31 bind to host v16..v31;
[AAPCS64](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst) d8..d15 and host x18/TLS remain intact. Dirty spills and final writeback
use the existing CPU vector bank. A 31-FADD chain compiles to two register loads
and one store. No full-state copy, per-operation bridge, hot capability check,
software arithmetic replacement or new CPU extension state is introduced.
[Implementation and borrowing contracts](../architecture/software-execution.md#fpneon-register-blocks).

Scope includes scalar S/D and host-admitted H arithmetic, FMA, comparisons,
conditional comparison/select, rounding, precision/integer conversion and bit
moves; common NEON integer/logical/saturating/shift/min-max and F32/F64 arithmetic,
comparisons, FMLA/FMLS and conversions. This is a first arithmetic batch, not
complete FP/AdvSIMD ISA coverage. Precision conversion H<->S/D uses baseline FP,
not the separate FP16 arithmetic capability ([Arm FCVT specification](https://support.arm.com/documentation/111108/2026-09/SIMD-FP-Instructions/FCVT--Floating-point-convert-precision--scalar--?lang=en)). Original instructions/flags and
hardware fused rounding are preserved.

A separate 128-byte VectorFrame retains the original 120-byte scalar/SVC prefix;
existing memory-frame offsets remain unchanged. Host FPCR/FPSR switch through the
existing common Scope once per native entry and restore on return. The common
control masks/trap policy are unchanged. Memory/provider/system fallback exits
happen outside the guest FP scope. Vector loads/stores, FPCR/FPSR system-register
lowerings, remaining lane/indexed/crypto families and exclusive reservations are
still pending. Their existing fallbacks retain precise state/permissions.

## Validation

ARM64 Linux passes **11 unit/capability + 58 differential tests (69)** in Debug
and Release, plus strict all-target JIT Clippy. Matrices cover arithmetic,
conversion, conditions, aliases, real V31, rounding controls, signed zero,
NaNs/signaling NaNs, infinities, denormals, sticky FPSR, QC and AHP/FZ16 conversion.
Register-pressure cases force dirty evictions. A dynamic branch checks that
vector flushing does not overwrite its selected PC. Existing scalar/memory/LSE
cases pass. ABI asm canaries preserve d8..d15; host FP environment is restored
on yield, syscall and subsequent guest instruction/memory faults. A parallel
code writer interrupts an already running FP loop at its original epoch guard,
with exact retirement and no prefix replay. Whole-state comparisons retain
SP/NZCV/TLS and all vectors at slice boundaries.

Apple fallback suite passes 55 cases plus the final added precision-conversion
case; Apple does not execute this JIT. Shared interpreter tests pass **48+2+1**
on Linux and Apple. Apple scoped Clippy, formatting, iOS interpreter compilation,
execution boundaries and dependency notice checks pass. The iOS interpreter graph
contains no JIT/native-code feature. Memory implementation is unchanged, so the
preceding Linux 282+6 / Apple 279+6 results (3 ignored each) are reused.

Android core default/JIT probes pass on Linux ARM64 and Apple. The added FP probe
requires scalar FP, integer conversion, NEON arithmetic, real V31 and optional
host scalar FP16, correct vector/GPR values, zero fallback, and exactly one native
entry. The VM executes 16 guest instructions including SVC. Existing memory probe
continues to pass. JNI schema 1 / 40-byte layout / flags remain unchanged. SDK,
NDK and packaging stay on Windows CI; these checks do not establish real Android
app-UID/ART/16 KiB device execution. Internal dependency-edge changes regenerate
lockfile notice inputs; no new third-party package/license text is introduced.

## Matched measurement

Baseline Runtime `a4fe0eb0f744987bd0e8b315567ce3663aaff0c1`; candidate is that base
plus this implementation. Identical isolated CPU fixture, existing Lima ARM64 VM,
Linux `7.0.0-44-generic`, 4 KiB pages, 6 vCPUs, rustc
`1.101.0-nightly (4ebd25825 2026-10-15)`, thin LTO / overflow checks / no incremental
compilation and no imposed CPU affinity. No KVM/native comparison is made here.

Four paired orders alternate old/new and new/old. All 18 workloads run in each
process with one warm-up and five timed samples: **8 processes, 720 timed + 144
warm-up samples**. Values are medians of four process medians. New cases execute
65,536 iterations of 31 arithmetic instructions plus SUBS/B.NE, followed by a
scalar result extraction and SVC. Guest work/words/retirement, final x0/PC/data
and code immutability are identical. The harness also asserts the complete final
V0, including all four SIMD lanes. Initialization is outside timing. Every new
FP case has zero fallback/staging and no memory-helper entries.

| 65,536 × 31 arithmetic instructions | Previous JIT | New JIT | Speedup |
|---|---:|---:|---:|
| Scalar FADD D chain | 130.404 ms | 0.991 ms | 131.58× |
| NEON FADD 4S chain | 118.328 ms | 0.986 ms | 119.98× |
| NEON ADD 4S chain | 149.735 ms | 0.965 ms | 155.17× |

These gains include removing fallback dispatch/operand marshalling and scalar
reference arithmetic work. They are specific CPU loops, not whole-application
speedups or proof of KVM/native equivalence. Existing control medians move between
−10.80% and −0.13% in this cohort; do not attribute all of that variation to a
change in their machine instructions or infer a general improvement from it.

[All raw samples, source/build hashes, exact fixture/lockfile, tests and summary](jit-fp-neon-20261128/)
are retained. Run `python3 jit-fp-neon-20261128/audit.py` here to verify hashes,
paired work/retirement/counters and recompute all results. An optional Runtime
source path verifies the final candidate source hashes. No VM image, rootfs,
SDK or temporary build cache is committed.
