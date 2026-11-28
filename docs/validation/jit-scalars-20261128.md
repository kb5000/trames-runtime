# Base scalar integer decoding and fault category — 2026-11-28

Baseline Runtime `dcdf3218cebed423a6466eca59b4a11d118e1eee`, paired Android
`315b75c177a3b3b8962db3bedad7b832db2cbbfb`. This closes the existing base scalar
integer decoding/error category, including a real ignored-field coverage gap.
It does not claim every current/future host ISA extension.

The former integer compiler chain is now a pure cold `scalar_ops` decoder and
lowerer. It covers move/address, add/sub immediate/shift/extend, logical
immediate/shift, bitfield/extract, select/compare/carry, multiply, divide/variable
shift, unary operations, CRC, CSSC, FlagM/FlagM2 and NZCV. Existing hardware
instructions and the original CPU banks/allocator remain in use. Capability
admission stays in translation; no instruction-by-instruction check, software
extension state, guest-code instrumentation or new synchronization is added.

## Real gap and original fault closure

The independent LLVM sweep found 1,984 valid noncanonical SMULH/UMULH selector
words previously declined by both JIT and interpreter: their Ra field is ignored
by the processor. LLVM's [code emitter](https://raw.githubusercontent.com/llvm/llvm-project/main/llvm/lib/Target/AArch64/MCTargetDesc/AArch64MCCodeEmitter.cpp)
also documents that rule in `fixMulHigh`. A standalone native C probe executes
both instructions with **all 32 Ra values** and six-by-six operand values:
**2,304 programs** match independent signed/unsigned 128-bit products on the
actual ARM64 Linux VM. Its source and binary identity are retained; the pass was
observed directly in the tool session, without fabricating an unretained raw log.

Both shared interpreter decoders now accept those fields. JIT selects canonical
ZR during cold lowering and never binds/loads the unused guest register. A
separate shared-interpreter test covers five alias/zero-register layouts and the
same value cross-product: **11,520 programs in each of the cached and stepped
engines**, with complete state preservation. Native emission checks require all
64 signed/unsigned ignored-field forms to generate the same words and register
loads as their canonical form.

The native negative cache now stores an instruction-error descriptor for
untranslated **scalar primary groups 5/8/9/13** after the existing compatibility,
system and memory classification. The descriptor returns the original
`CpuFault::Instruction`, retains PC and exact retired-prefix accounting, and uses
the same identity/page invalidation authority. It adds no CPU bank or native
Frame field. Other primary groups retain their generic interpreter entry pending
their own complete audit. Valid guest instructions are not replaced with faults
merely to obtain a zero fallback counter.

## Independent selector and native execution acceptance

The sweep enumerates **1,048,576** words across all high/middle selector fields
in those four primary groups, holding Rn=1 and Rd=0. Seven special flag/NZCV
forms supplement fixed low-bit encodings. LLVM 18 independently decodes the
candidate words with the declared v9.4 feature mask:

- **464,344 admitted words including the seven supplements**; no invalid
  admissions and no missing valid integer forms in the declared sweep.
- **2,216** other valid words belong to the separately completed PAC/MTE
  compatibility lowering. This distinction is explicit in the oracle report.
- Every remaining **582,023** untranslated selector is executed through the
  original interpreter step path and must return the original instruction fault,
  without a data-memory callback. No valid interpretation was discarded.

This is a closed selector audit, not enumeration of every register choice,
literal value, all 2^32 instruction words or future extensions. Operand aliases,
literal boundaries and precise execution are checked separately.

The independently rechecked [execution fixture](jit-scalars-20261128/execution.words)
contains **102,472** semantic selector words. It retains all logical/bitfield and
condition controls, expands all conditional-compare/RMIF NZCV masks, and folds
free source-register/immediate-value duplicates where their control is unchanged.
The native test runs **204,944** programs at budgets 1/64 with a dirty GPR/NZCV
and FP prefix and two actual scalar instructions. Host-admitted words must reach
SVC with four retired native non-SVC instructions, complete reference state and
unchanged text; unavailable host features must fault at the reached PC after
the exact prefix, without using interpreter emulation.

A further 1,057 sampled selectors run four register-alias layouts, budgets 1/64,
and serial/guarded/private modes after 31 dirty GPR writes, FP execution and a
checked memory callback, excluding only absent host features. All admitted paths
require zero fallback. **9,095** sampled original-invalid words use a traced
provider whose first extra decoder-page query detects interpreter fault entry.
Cold and warmed faults preserve whole state and exact PC, avoid data callbacks,
and warmed descriptors do not fetch or recompile. Non-chaining providers retain
their original exact-budget cache keys. Subsamples change code to valid arithmetic
and then remove execute permission, checking original revalidation/fault precedence.

Two baseline diagnostics each run one real test and fail: the invalid-scalar
test observes interpreter page entry; the independent high-product test observes
the old rejection. Neither negative result is a build error or a zero-test run.

## Platforms and generated code

- Actual ARM64 Linux, 4-KiB host: full **31 unit + 127 differential (158)** JIT
  tests pass in Debug and Release. The shared interpreter passes **49 unit + 3
  integration (52)** tests, including its bounded-stack test. Scoped native
  strict Clippy and amd64 cross-Clippy pass. amd64 verifies compilation, not
  native x86 JIT execution.
- Apple: **122** JIT fallback tests and **52** interpreter tests pass. Scoped
  native-feature/default-feature strict Clippy and a fresh
  `cargo check --locked --target aarch64-apple-ios -p trames-interpreter` pass.
  Native JIT remains compile-time excluded from Apple/iPad execution.
- Android core: explicit JIT **6**, default **1** and strict scoped lint pass
  on Linux and Apple. The new probe checks all 21 scalar forms, all 64 high-
  multiply ignored-field forms and additional flag/CSSC forms when host-admitted,
  at budgets 1/3/64. On this Linux host that is **264** valid programs plus five
  invalid programs repeated at cold/warm boundaries. Complete reference state,
  exact outcomes/retirement and unchanged guest text are required. JNI schema
  1 / 40 bytes and flags stay unchanged.

The current iPad root's `--locked` graph query reported a lockfile update was
needed during parallel owner work. The owner's lock and Runtime pin were left
untouched. An isolated copy of **all current workspace manifests**, with read-only
source links, resolves its copied lock offline; its selected iPad CPU graph
contains neither JIT nor memory `native-code`. Original manifest/lock hashes and
the resulting graph are retained. This is identified as isolated current-manifest
resolution, not a successful `--locked` query in the owner's working tree.
The separately checked current interpreter iOS source compiles successfully.

Before/after code-generation receipts compare **838 actual compiled programs**
across all 21 forms, ordinary and full GPR pressure. Existing canonical forms
are compared on both versions; newly admitted high multiply fields have the
independent hardware/state tests above. The native word streams are **byte-for-
byte identical**, with Operation/Block/Node/Frame layouts **192/152/264/120 bytes**.
No process-pointer normalization is needed for these scalar streams. Source,
binary, fixture and accepted-log hashes are frozen in the
[receipt](jit-scalars-20261128/receipt.json).

## Matched CPU-only controls

The same two harness sources run on separate baseline/current source snapshots
and Cargo targets, with uniquely copied binary hashes. Four balanced pairs use
before/after, after/before, before/after, after/before on vCPU 0 of the same ARM64
Linux VM. Each process records 32 samples with 8 warmups (24 timed). Ordinary
controls use 64 rounds of 65,536 guest trips/sample; cached SVC controls use
200,000 calls/sample with a simulated return update. Whole state/data, exact
retirement, unchanged code and zero fallback are verified outside timing.

Ratios are geometric means of four paired median before/current time ratios;
greater than one means current is faster. All **1,280 rows**, including warmups,
are retained.

| CPU-only workload | Time ratio | Paired ratio range |
|---|---:|---:|
| Ordinary integer | 1.003x | 0.866–1.121x |
| Ordinary scalar memory | 1.006x | 1.004–1.008x |
| Cached SVC-only exit | 1.014x | 1.005–1.026x |
| ADD + SVC round trip | 1.002x | 0.982–1.029x |
| Branch continuation + ADD + SVC | 0.992x | 0.972–1.013x |

These controls do not establish an invariant regression bound or an ordinary-
path speedup; the wide integer paired range remains visible. Generated code
identity is separate evidence. The cohort does not measure illegal-instruction
traffic, Linux syscall handlers, KVM, graphics, JNI or Android lifecycle, nor
does it establish application-level multipliers.

The remaining generic entry outside the closed scalar groups, full hardware
PAC/BTI/MTE, SVE/SME, LS64/SETG ownership, positive optional-extension hardware
and actual Android app-UID/ART/large-page acceptance remain explicit work in the
[coverage plan](../roadmap/native-jit-coverage.md). Android tooling stays Windows-
only. Unrelated source-unchanged memory/network/graphics acceptance is reused.
