# Complete fixed-width SIMD/FP arithmetic — 2026-11-28

This completes the arithmetic category in the [coverage plan](../roadmap/native-jit-coverage.md),
including scalar SIMD, widening/narrowing and saturation, shifts/inserts, indexed
multiply/add, pairwise/across-lane reductions, reciprocal estimate/step families,
precision/scaled conversions, FP16/BF16/DotProd/I8MM/RDM/FCMA/FHM, JSCVT and
FRINT32/64. Two valid X/H FP16 move forms are also closed. Native execution uses
original instructions, existing architectural banks and the process-host ISA.
Absent optional extensions still fault in cold compilation; no software ISA or
extension-state replacement is added. This is the current fixed-width profile,
not a claim of SVE/SME or every future host extension. Exclusive reservations,
special memory and compatibility/stateful work remain active.

The cold allocator now uses all 24 normal caller-saved vector registers:
V16–V31 and V0–V7. Restricted indexed half operands retain the lane's M bit and
use a real low register. Binding migration uses a native register move and keeps
its dirty value, instead of writing it to the CPU bank and loading it again.
Sources/accumulators are pinned, upper-half narrowing retains the old low half,
and packed memory/table groups respect the allowed physical runs. D8–D15,
host TLS, the scalar ABI, 120-byte chain frame and CPU state layout remain intact.
There are no hot capability branches, new locks, FP scopes per instruction,
full-state copies, JNI transitions, guest-text changes or software arithmetic.
[Implementation contract](../architecture/software-execution.md#complete-fixed-width-simdfp-arithmetic).

Arm's [ISA reference](https://documentation-service.arm.com/static/67e40f3398aa3c3b6eea6a85)
describes indexed register/lane fields and destructive/widening/narrowing forms.
Its [FJCVTZS flag definition](https://support.arm.com/documentation/ddi0487/md/-Part-C-The-AArch64-Instruction-Set/-Chapter-C7-A64-Advanced-SIMD-and-Floating-point-Instruction-Descriptions/-C7-1-About-the-A64-Advanced-SIMD-and-floating-point-instructions/-C7-1-4-Condition-flags-and-related-instructions)
requires hardware NZCV publication, in addition to its GPR result and FPSR.

## Encoding and category closure

The native unit audit enumerates all 14 middle bits for 15 scalar-FP/AdvSIMD
prefixes, with representative Rn=1/Rd=0. Independent LLVM 20 decoding, with the
listed fixed-width extensions enabled, accepts **68,214 native admissions**
covering **303 observed mnemonics**, with **zero invalid admissions**. It also
scans outside native admission: **zero LLVM-valid unadmitted forms** remain in
that matrix. This covers fixed unary selectors as well as size/Q/opcode and
immediate/lane fields; it is not exhaustive enumeration of all 2^32 words or a
claim about unowned stateful/later encodings. LLVM 18 independently assembles
register-alias programs, including architectural restrictions on indexed Rm.
LLVM is an offline verification tool and is absent from production dependencies.

The frozen integration suite executes **10,640 distinct encoding/arrangement/lane
forms** against the independent interpreter. A further **7,129 alias programs**
run five data/control combinations after dirtying all 32 guest vector registers.
They force 24-register pressure, high-to-low migration, GPR/vector aliases,
cross-page checked callbacks, raw NaN/subnormal/zero/integer saturation patterns,
rounding/FZ/DN/FZ16/AHP controls, mixed FP status reads, exact sliced budgets,
private views and dynamic branch exits. Sampled aliases also fault after the
dirty arithmetic prefix and compare exact PC, retirement, every register, FP
status and canonical bytes. Native cases require zero interpreter fallback.
A callee-vector canary now fills the whole caller bank before checking D8–D15.
Each frozen encoding independently checks every required capability bit in cold
compilation, including second-word and compound FCMA-half requirements.

The shared interpreter fixes scalar SSHR dispatch, which previously reached the
vector-width path, and adds missing scalar S/D floating mask comparisons. These
are architectural oracle corrections, not JIT software replacements.

## Platform verification

ARM64 Linux: **16 unit/capability + 86 differential tests (102)** pass in Debug
and Release. Interpreter **48+2+1** passes. Apple: **83 JIT fallback tests** and
interpreter **48+2+1** pass. Strict scoped all-target Clippy, iOS interpreter
compilation and dependency/execution boundaries pass. Prior unaffected memory
and host-compute package validation is reused.

The VM advertises FP16, BF16, DotProd, I8MM, RDM, FCMA, FHM, JSCVT and FRINT, so
these new families execute positively as native instructions. Existing absent-
crypto and unowned-state gates remain covered. Android default/JIT core probes
and feature isolation pass on Linux ARM64 and Apple, with strict Clippy. The
added native probe combines all arithmetic families, current host admission,
low-register pressure, cross-page callbacks, complete reference state/data,
exact retirement, zero fallback and unchanged code. JNI flags/schema are
unchanged. Android SDK/NDK/JDK/APK builds remain on Windows CI; these checks do
not constitute app-UID/ART or 16-KiB Android device acceptance.

## Matched CPU-only measurements

Baseline `1ef4b02bdc53059abd15aadbba3f2dc67dea32ab`; candidate is that commit plus
the hashed category sources. Same Lima ARM64 Linux VM, 6 vCPUs/8 GiB, 4-KiB pages,
kernel 7.0.0-44-generic, rustc 1.101.0-nightly (4ebd25825), thin LTO, overflow checks
and no incremental build/affinity. There are no concurrent builds during timing.

Four balanced old/new and new/old pairs execute six finite programs, each with
one warm-up and five timed samples: **8 processes, 240 timed + 48 warm-up samples**.
Each program runs 65,536 trips of 28 body operations plus SUBS/B.NE, followed by
SVC. After each sample both variants run the same interpreter untimed and check
complete CPU state and the full canonical 4-KiB data page. The table uses medians
of four process medians. Original instructions, final results and raw samples
are frozen; these constant-input programs allow ordinary hardware overlap of
independent operations and include overwriting destinations.

| Program | Previous JIT | New JIT | Speedup |
|---|---:|---:|---:|
| extension-arithmetic | 139.047 ms | 0.174 ms | 799.26× |
| fp-control | 0.943 ms | 0.930 ms | 1.01× |
| indexed-arithmetic | 162.938 ms | 0.102 ms | 1591.46× |
| integer-control | 0.409 ms | 0.403 ms | 1.02× |
| reciprocal | 148.865 ms | 0.203 ms | 731.62× |
| widen-narrow | 202.198 ms | 0.102 ms | 1982.58× |

All candidate programs have zero interpreter fallback/staging and no guest-memory
instructions. The added loops need at most 18 native entries across six samples.
The old interpreter could already call native arithmetic helpers for some
families; others used scalar lane loops. Gains remove that per-instruction
dispatch/marshalling and retain hardware operands inside native blocks. Controls
vary by about −1.5% and −1.4%; these programs do not establish application-wide
speedups, startup/compilation performance, or KVM/native equivalence.

[Frozen fixtures, independent encoding/assembly evidence, lockfiles, raw logs,
source/binary/tool hashes and audit](jit-arithmetic-20261128/) are retained.
`python3 jit-arithmetic-20261128/audit.py [Runtime-root]` verifies the frozen
cohort and reconstructs both test corpora from independent oracle outputs.
For reproduction, use sibling `jit-arithmetic-base`/`jit-arithmetic-source`
checkouts and `jit-arithmetic-old`/`jit-arithmetic-new` packages from the frozen
manifests/lockfiles, with `benchmark.rs` as `main.rs`. Execute release binaries
in the receipt order. The optional native unit environment variables and
`scripts/audit-jit-arithmetic.py --outside` reproduce the encoding closure audit
using the existing Linux libLLVM; no Android tooling is needed.
