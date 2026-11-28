# Native execution invalidation boundaries — 2026-11-28

Baseline Runtime `77a2f4716c2231cc3956eb8253b3dda7506f83a4`, paired Android
`31a1c75ec932d63a56cb0af02313f1a334345bba`.

This closes the execution-epoch boundary category. Previously a native entry
that observed a changed epoch before executing its first block returned the
same result as an untranslated instruction, causing a one-instruction
interpreter entry. Scalar/linked, vector and fused scalar/vector-memory entries
now return a private retry exit. The existing identity/page cache revalidates
the reached PC; unchanged pages reuse their existing native translation.

The first empty invalidation gets one cold extra native entry. A second empty
invalidation yields the execution slot. Const `true`/`false` specializations
bound the retry without a hot runtime counter, recursive polling or another
thread. A completed prefix retains its exact retirement across retry, yield,
SVC, native call and fault. The original CPU publication, FP restoration, slice
custody, data borrows and exclusive-reservation domain stay in their original
order. There is no new CPU bank, full-state copy, guest-text instrumentation,
ordinary-data fence, global lock or additional generated epoch check.

The assembler, renderer and compiler source sections are byte-identical to the
baseline, and the existing native Frame ABI remains 120 bytes. The
[source audit](jit-execution-boundaries-20261128/codegen-source.json) records
section hashes; it is a source comparison, not a new generated-code dump.

## Acceptance

The eight new category tests contain **618 scenarios**:

| Boundary | Scenarios |
|---|---:|
| All three epoch channels, identity/page publication, checked/hardware loans, vector/scalar/mixed entries and exact budgets | 108 |
| Warm linked scalar revalidation, unchanged page and no interpreter fetch/recompile | 6 |
| Repeated empty invalidation, bounded yield and exact later resume | 54 |
| Dirty GPR/NZCV prefix before yield, syscall, native call, trap or memory fault | 48 |
| Repeated target-entry invalidation after a committed prefix | 6 |
| All sixteen architectural NZCV combinations on empty entries | 288 |
| Exclusive reservation across cooperative invalidation yield | 48 |
| Guest-authorized code changes to arithmetic, SVC, trap, native call or fault, in serial/guarded/private modes | 60 |

Whole CPU state, canonical data/text, per-slice retirement and host FP state are
checked. Reservation tests allow real spurious store-exclusive failure and
require successful attempts. The self-modification tests use an explicit guest
store into its own W+X mapping; the backend never patches guest executable bytes.
The existing concurrent-code-write chain test now also requires zero fallback.

On the baseline production sources, the new exact repeated-invalidation test
fails at the expected `Yield { instructions: 0 }` assertion: one test runs and
fails, rather than being skipped or failing to compile. Its
[expected-red log](jit-execution-boundaries-20261128/baseline-regression.log)
is retained separately from passing evidence.

- Actual ARM64 Linux, 4-KiB host: **26 unit + 120 differential tests (146)** pass
  in both Debug and Release. Scoped native all-target strict Clippy and amd64
  cross-Clippy pass. The amd64 check verifies fallback compilation, not native
  x86 execution. The existing independent LLVM compatibility audit still passes.
- Apple: **115 JIT fallback tests**, native-feature strict Clippy and default-
  feature strict Clippy pass. A test wrapper method needed the same feature cfg
  as its CpuMemory trait method; that feature-off fixture correction is covered
  by default Clippy. It does not change native-feature execution.
- The Android CPU probe adds **20** guest-authorized code-change programs:
  five target outcomes at budgets 1/2/3/64, including an FP prefix and dirty
  GPR/NZCV. It checks the independent interpreter reference, exact exits/faults,
  whole state, unchanged unmodified text and zero fallback. Linux runs all
  **4** JIT core tests natively; Apple passes the same 4 tests with native emission
  excluded. Default core **1** test and strict scoped lint pass on both hosts.
  The Linux core/lint result was observed directly in the tool session; no raw
  transcript is fabricated for it. The retained Apple log covers its JIT tests.
- Actual iPad dependency-tree and execution-boundary checks pass. Neither JIT
  nor memory `native-code` occurs in the iPad CPU graph. No iPad source or pin
  changes; the source-unchanged prior iOS interpreter build is reused.

The shared test/example initial NZCV fixtures now use the public architectural
bits 31..28 (`0xb0000000`, not the internal four-bit value `0xb`); RNDR expectations
use that same ABI. This corrects the tests, not a production NZCV corruption.
Native execution acceptance already used the corrected architectural values.

Source hashes, host/capability provenance, accepted logs and the source audit are
frozen in the [receipt](jit-execution-boundaries-20261128/receipt.json).
Apple/Linux production memory interfaces, feature admission and instruction
lowering are unchanged, so unrelated passing memory/network/graphics acceptance
is reused. Android SDK/NDK/JDK/APK/device work remains Windows-only.

## CPU-only controls

Baseline/current use distinct Cargo target directories and uniquely copied
binaries. Both use identical benchmark harnesses with valid architectural NZCV.
Four balanced pairs run before/after, after/before, before/after, after/before on
vCPU 0 of the same ARM64 Linux VM. Each process records 32 samples with 8 warmups
(24 timed). Ordinary controls use 64 rounds of 65,536 guest loop trips; each SVC
sample uses 200,000 backend calls and includes a simulated return-value update.
Full state, exact retirement, native exits and zero fallback are checked outside
timing. The 1,280 retained sample rows include warmups and all measured runs.

Ratios are geometric means of four paired median before/current time ratios;
values above one mean current is faster.

| CPU-only workload | Time ratio | Paired ratio range |
|---|---:|---:|
| Ordinary integer loop | 0.987x | 0.959–1.022x |
| Ordinary scalar-memory loop | 0.951x | 0.826–1.000x |
| Cached SVC-only exit | 0.999x | 0.989–1.018x |
| ADD + SVC round trip | 0.999x | 0.951–1.056x |
| Native branch continuation + ADD + SVC | 1.015x | 0.962–1.074x |

The scalar-memory cohort includes a 0.826x pair; this is retained, not discarded.
The other three pairs are approximately 0.993x/1.000x/1.000x. These measurements
show variability and do not establish a no-regression bound or a new ordinary-
path speedup. Generated lowering source is unchanged, but wrapper compilation,
cache layout and VM scheduling remain part of the observed measurements.
This change removes an interpreter entry on invalidation; the controls do not
measure a speedup for adversarial invalidation traffic.

[Raw samples](jit-execution-boundaries-20261128/benchmark-samples.jsonl),
[summary](jit-execution-boundaries-20261128/benchmark-summary.json) and
[binary/build provenance](jit-execution-boundaries-20261128/benchmark-provenance.json)
retain the comparison. SVC tests measure backend exits, not real Linux syscall
handlers, KVM, JNI, Android lifecycle, graphics or application throughput.

## Remaining interpreter entry and unowned capabilities

The generic one-instruction fallback remains for an instruction not recognized
by native lowering. Some such entries only report a reserved/unsupported
instruction fault. Unknown CpuMemory embeddings without hardware memory-order
ownership also retain their conservative ordered/atomic path; product
Memory/View supplies that ownership. Interpreter-only build configurations
intentionally exclude native execution. Memory callbacks, checked staging,
syscall/native-call dispatch and guest faults do not themselves imply fallback.

Full hardware PAC/BTI/MTE, stateful SVE/SME, Device-memory LS64 and tag-setting
MOPS SETG still need real shared CPU/context/memory ownership. They remain
unadvertised rather than being supplied by a software extension model. Positive
optional-extension hardware, Option-B MOPS/migration and actual Android app-UID,
ART/signal and large-page acceptance remain outstanding. See the
[coverage plan](../roadmap/native-jit-coverage.md).
