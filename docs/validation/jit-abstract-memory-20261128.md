# Abstract ordered/atomic native category — 2026-11-28

Baseline Runtime `e8d9d339e5a3d78db0f7e3410538a4d48d97c846`, paired Android
`025e4e2a5cd038091db02665bf1d2c0d7e9bf7a0`. This closes the whole existing
ordered/atomic fallback category for abstract CpuMemory embeddings. It does not
grant an unknown provider the product Memory/View native-alias contract.

## Execution contract

The existing native memory fragments now compile for abstract providers as well
as product RAM. They execute the actual host-admitted instruction inside the
original checked read/write or atomic-update transport. The callback supplies
canonical permissions, publication and reservation authority. No Rust RMW
algorithm, new extension state, global lock, resource thread or guest-code patch
is introduced. Existing missing-extension admission remains cold and faults at
the reached PC rather than acquiring the interpreter's software implementation.

Unknown providers can have ordering semantics beyond ordinary host RAM. The cold
compiler therefore ends a mixed block before their ordered/atomic operation,
using the existing single-operation boundary. Offering epochs or native aliases
alone does not bypass those canonical callbacks. Actual instruction execution
still uses a native fragment; declining inline fusion is not interpreter fallback.

The default acquire/release transports now call the provider's original `fence`
hook around canonical access instead of substituting a host-only fence around a
temporary. A successful read precedes Acquire; Release precedes the original
write, including a write fault. The duplicate staged-store permission preflight
is removed; final `write` retains the original fault/publication behavior. The
existing aligned 16-byte atomic transport already preserves Release, transaction,
conditional publication and Acquire in that order. Failed CAS does not invent a
write or invalidate the original reservation. The real host instruction computes
the result; the transport does not emulate the RMW algorithm.

Product Memory/View keeps its unchanged concrete ordered/atomic overrides and
direct hardware/fused lowering. Operation/Block/Frame acquire no new field. The
outer JIT dispatcher, native execution entries, assembler/renderer, Memory trait
implementation and entire View source are byte-identical to the baseline in
the retained [source audit](jit-abstract-memory-20261128/product-source-audit.json).
The only new ordering decision is in cold compilation, not the generated hot
path. That audit establishes source identity, not a new machine-code dump.

## Closed encoding and behavior matrix

The [LLVM assembly](jit-abstract-memory-20261128/category.S),
[words](jit-abstract-memory-20261128/category.words) and
[case list](jit-abstract-memory-20261128/category.cases) contain **795 encodings**:

| Family | Encodings |
|---|---:|
| LDAR/STLR, LDAPR and host-admitted LDLAR/STLLR, every B/H/W/X width | 60 |
| LDAPUR/STLUR and signed B/H/W forms, all declared widths and five signed offsets | 195 |
| CAS and all nine LSE RMW families, every width and ordering, including ZR/store aliases | 480 |
| W/X CASP, every ordering and legal pair alias | 24 |
| SWPP/LDCLRP/LDSETP, every ordering and independent in/out registers | 36 |

Operand combinations include high/zero registers, SP, destination/base aliases
and compare/replacement aliases. Reassemble with
`python3 scripts/audit-jit-abstract-memory.py --llvm-mc llvm-mc-18`.
The same script independently verifies both benchmark programs and branch offsets.

Four differential tests compare whole GPR/SP/NZCV/FP/vector/TLS state, canonical
bytes/text, exact per-slice outcomes/fault retirement and the complete provider
callback trace. The trace records reads, writes, permission checks, fences,
transactions, conditional publication and reservation operations, including the
faulting call. Each program has a dirty GPR/NZCV and FP prefix, two actual memory
instructions and a native SVC exit. Tests cover budgets 1/2/3/64 and three provider
modes: no epochs, epochs without aliases, and epochs plus offered aliases while
hardware-order ownership remains false. Ordered/atomic operations must never
export an alias in any of those modes.

On this actual ARM64 Linux host, **735** encodings are admitted; LSE128 and LOR
are absent. These run **17,640** successful/reference programs and **26,460**
read-only/write-only/unmapped/unaligned programs: **44,100** total. Six additional
reservation programs check successful and failed CAS through the original
reservation domain. The 60 absent-host encodings run 180 reached-PC rejection
programs and must fault before any data callback, state mutation or alias export.
Every successful admitted path requires zero interpreter fallback.

An opaque-provider cold unit test assembles **771** native operations using an
explicit all-feature test mask, including the 36 LSE128 encodings, with all data
callbacks set to panic. LOR remains gated by its actual sanitized host ID field.
This is code-generation/ownership evidence; it does not execute LSE128/LOR on
unsupported hardware or supply positive hardware acceptance.

The exact new whole-category test on unchanged baseline production sources
executes and fails at `fallback_instructions == 0`, observing **2** interpreter
instructions on its first ordinary LDAR program. The
[expected-red log](jit-abstract-memory-20261128/baseline-regression.log) confirms
one failed test and exit 101; it is separate from passing evidence.

## Platform acceptance

- Actual ARM64 Linux, 4-KiB host: the full **27 unit + 123 differential (150)**
  suite passes in Debug and Release. A subsequently added absent-extension test
  passes separately in both profiles; source-unchanged passing tests are reused,
  yielding **151 distinct** accepted tests per profile. Memory passes **287**
  tests with 3 pre-existing ignored cases. Scoped all-target strict Clippy and
  amd64 cross-Clippy pass. amd64 checks compilation, not x86 native JIT execution.
- Apple: the full **118** fallback tests pass, followed by the new absent-
  extension test compiled with native execution excluded (**119 distinct**).
  Memory passes **283** tests with 3 pre-existing ignored cases. Native-feature
  and default-feature scoped strict Clippy pass. The Memory default transports
  remain behind the existing `native-code` feature.
- Android core: explicit JIT **5** and default **1** tests, plus scoped strict
  lint, pass on Linux and Apple. The new Linux-native probe executes **21**
  programs over LDAR/STLR, CASAL, LDADDAL, LDAPR, LDAPURSW and STLUR at budgets
  1/3/64. It compares independent interpreter state/data/exits, original fence
  hooks, unchanged guest code and zero fallback. Apple compiles the same probe
  with native execution excluded. JNI schema 1 / 40 bytes and flags are unchanged.
- The actual iPad CPU dependency tree excludes JIT and memory `native-code`.
  Execution-boundary, feature-selection, notice and formatting checks pass. No
  iPad source/pin, runtime manifest, native allocation policy or platform-specific
  import changes. Prior source-unchanged iOS interpreter acceptance is reused.

The source-bound [receipt](jit-abstract-memory-20261128/receipt.json) freezes all
source hashes, passing logs, the negative proof and benchmark provenance. Android
SDK/NDK/JDK/APK/device work remains Windows-only. Actual Android app-UID, ART/signal
coexistence and large-page-device acceptance remain separate work. No new ISA
model run is claimed; positive LSE128/LOR hardware remains outstanding.

## Matched CPU-only measurements

Baseline/current use separate physical source snapshots and separate Cargo
targets, identical harness sources and uniquely copied binary hashes. On vCPU 0
of the same actual ARM64 Linux VM, four balanced pairs run before/after,
after/before, before/after, after/before. Each process records 32 samples with
8 warmups (24 timed). Abstract loops use 65,536 trips/sample; ordinary controls
use 64 rounds of 65,536 trips/sample. State, canonical bytes, exact retirement
and original text are verified outside timing. Abstract loops use the original
fence hooks without tracing/recording inside the timed region.

Baseline ordered and atomic loops respectively require exactly 131,072 and
65,536 fallback instructions/sample; current loops and both ordinary-control
versions require zero. The 1,024 retained rows include warmups and all runs.
Ratios are geometric means of four paired median before/current time ratios;
greater than one means current is faster.

| CPU-only loop | Time ratio | Paired ratio range |
|---|---:|---:|
| Abstract LDAR/add/STLR | 1.987x | 1.954–2.024x |
| Abstract LDADDAL | 1.498x | 1.439–1.589x |
| Product ordinary integer control | 1.018x | 0.893–1.133x |
| Product ordinary scalar-memory control | 1.006x | 0.997–1.023x |

The controls show measurement variability, not a proven product speedup or
invariant regression bound. The abstract improvements apply to these CPU loops,
not equivalent Linux application multipliers. They do not measure actual syscall
handlers, KVM, graphics, JNI or Android lifecycle. Product hot-path source
identity is recorded independently of these timings.

[Raw samples](jit-abstract-memory-20261128/benchmark-samples.jsonl),
[summary](jit-abstract-memory-20261128/benchmark-summary.json) and
[build/binary provenance](jit-abstract-memory-20261128/benchmark-provenance.json)
retain the comparison.

## Remaining work

The generic one-instruction interpreter entry remains for encodings not
recognized by native lowering, including entries which only diagnose an
unsupported/reserved instruction. Deliberate interpreter-only builds remain.
Full hardware PAC/BTI/MTE, SVE/SME, Device-memory LS64 and MOPS SETG still require
real shared CPU/context/memory ownership and remain unadvertised. They are not
provided by a software extension model. See the
[coverage plan](../roadmap/native-jit-coverage.md).
