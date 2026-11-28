# Existing PAC/MTE compatibility category — 2026-11-28

CPU baseline Runtime `be8bfedfe1450c060d2fc5e03ab051605a7b1432`, paired Android
`fb54156b1b010a0d461af47ebab9b567921c8d0e`. Integration also includes
`9a6979362f2971a1571118e5ca9832264df5eaf4`, the independent
[AES architecture-acceptance correction](compute-aes-ci-20261128.md).
The final integration fast-forwards over independent upstream `8842c81`
(Vulkan command batching/login defaults). Its six changed files do not modify
the tested CPU sources or their dependencies; those passing results are reused.

This closes the whole existing non-hint category under the shared CPU's
[disabled-authentication/zero-allocation-tag policy](../../crates/trames-interpreter/src/compatibility.rs).
It does not enable hardware PAC/BTI/MTE or claim a new protection model.

| Existing family | Lowering and preserved effects |
|---|---|
| PACIA/IB/DA/DB, AUTIA/IB/DA/DB and all zero-modifier forms | Retire with their original no-authentication effects; never sign or poison a pointer with host keys. |
| XPACI/XPACD, PACGA | Native pointer extraction or zero result, matching the existing profile. |
| BRAA/BRAB/BLRAA/BLRAB, all Z forms, RETAA/RETAB | Mask the actual target before an aliased link-register write; existing dynamic native linking and exact guest PC/LR. |
| LDRAA/LDRAB | Real native 8-byte loads, signed scaled offsets and optional pre-index; destination/writeback publish only after a successful original Memory access. |
| IRG/GMI/SUBP/SUBPS/ADDG/SUBG | Native masks, shifts, arithmetic and real NZCV. SP/ZR, signed 56-bit differences, destination/source aliases and tag fields follow the original profile. |
| LDG/STG/ST2G | Original translation/write-permission and 16-byte tag-granule fault semantics; no tag array, artificial write, reservation invalidation or algorithm lock. |
| STZG/STZ2G/STGP | Native zero/pair stores and all post/offset/pre-index forms, using original permissions, COW, partial-publication and reservation rules. |

The independent LLVM 18 [assembly](jit-compatibility-20261128/category.S),
[word list](jit-compatibility-20261128/category.words) and
[case manifest](jit-compatibility-20261128/category.cases) contain **836 encodings**
across the 43 named instructions. They cover high/zero registers, SP, legal
aliases, both authentication keys, positive/negative/extreme offsets, every
tag field used by the matrix and every supported memory addressing mode.
Reassemble with `python3 scripts/audit-jit-compatibility.py --llvm-mc llvm-mc-18`.
The script also independently verifies all seven benchmark programs and their
branch offsets against LLVM.

## Execution and memory

Classification, target policy, scratch allocation, pointer/address lowering,
alignment-branch placement and fragment construction are cold compilation work.
No decoder, host-capability preflight, new CPU bank or full-state copy is added
to the generated integer path. Discarded non-flag results become empty bodies;
SUBP/SUBPS reuse the destination rather than spilling another scratch binding.
Host x18/TLS, callee-saved state, guest executable bytes and JNI layout remain
unchanged. JIT source is still compiled only by explicit ARM64 Linux/Android opt-in.

Masked data addresses join the existing fused memory path, protected CPU aliases,
independent data borrows and precise recovery. The base is stripped before
offset arithmetic, including overflow and pre/post writeback; no host virtual
address width is inferred. The existing profile's 48-bit pointer rule is retained.
Actual loads/pair/zero stores can use the original page/affine/address reuse.
Tag-only operations retain the original metadata authority and do not perform
data writes just to obtain a permission check.

The zero-tag profile still requires a 16-byte alignment fault. An ordinary STP
does not impose that requirement, so only tag-zero lowering emits the required
alignment branch to the original checked fault boundary. Ordinary loads/stores
receive no new alignment check. The check also covers an alias reused from a
valid unaligned STGP. Multi-pair zero fragments register every possible fault
site. Cross-page zeroing uses bounded native staging and the original Memory
publication order, including faults after a completed prefix; writeback remains
uncommitted on failure. No extra fence, coordinator/resource thread, global lock,
polling loop, executable guest rewrite or software allocation-tag state is added.

## Source-bound acceptance

- Actual ARM64 Linux, 4-KiB host: **26 unit + 112 differential tests (138)** pass
  in Debug and Release. The final category has seven tests; its main 836-word
  matrix alone runs **7,524 programs** across budgets 1/2/64 and serial, guarded
  and private modes. Non-branch words are repeated to exercise checked and
  inline paths. Every valid native category program requires zero fallback.
- Additional category cases compare whole state/data/retirement at signed
  boundaries and aliases, full caller-saved pressure with FP/vector memory,
  missing/protected/no-access pages, failed writeback, cross-page 16/32-byte
  zeroing, unaligned alias recovery and preserved/invalidation reservation cases.
  Native alias acceptance separately requires at least 56 hardware accesses per
  repeated-load/zero/pair program and zero staging. Alias loans stay within the
  original CPU entry; they are not cached across slices.
- Apple: **107 JIT fallback tests** and scoped all-target strict Clippy pass.
  Native emission is excluded at compile time. The actual iPad CPU dependency
  tree contains neither JIT nor memory `native-code`; no iPad source or pin was
  changed. The source-unchanged prior iOS interpreter build remains valid.
- Linux strict scoped Clippy passes; amd64 cross-Clippy checks the compile-time
  fallback composition, not x86 native JIT execution. Memory/feature/system ISA
  ownership and the platform-independent interfaces remain unchanged.
- Android core default **1** and explicit-JIT **3** tests pass on Linux/Apple.
  The new Linux-native probe runs 75 representative forms at budgets 1/64:
  **150 programs**, whole state/data/exits, unchanged text and zero fallback.
  Apple compiles the probe while excluding native execution. SDK/NDK/JDK/APKs
  remain Windows work. Real Android app-UID/ART and 16-KiB-device acceptance are
  still outstanding.

During snapshot comparison a shared Cargo target directory incorrectly reused
an executable from the other source root. A diagnostic expected to write an
`after` artifact instead wrote the `before` artifact; that observation is not
passing evidence. Final native acceptance uses the batch's independent CPU target
directory, with the temporary code-generation diagnostic removed. Binary hashes,
source hashes, actual capabilities and accepted logs are frozen in the
[receipt](jit-compatibility-20261128/receipt.json).

## CPU-only measurements

Matched CPU-only Release runs compare the same 65,536-trip programs and exact
harness source on baseline/current, on the same real ARM64 Linux VM and pinned
vCPU 0. Each workload runs in a separate process; four balanced pairs use
before/after, after/before, before/after, after/before. Each process records 18
samples with 4 warmups (14 timed); each sample contains 64 rounds for controls
and 8 for category loops. Complete state, canonical bytes, exact retirement and
unchanged guest text are checked outside timing. Current category loops and
both control versions require zero fallback. LLVM independently verifies every
benchmark opcode and branch offset.

Ratios are geometric means of the four paired median speed ratios; greater than
one means current is faster. The comparison is against the previous JIT's
interpreter compatibility path, not against interpreter-only or KVM throughput.

| CPU loop | Before/current time ratio | Paired ratio range |
|---|---:|---:|
| Pointer/tag arithmetic | 230.265x | 219.103–240.155x |
| Authenticated load + pair store | 101.575x | 97.979–105.610x |
| Tag-zero store | 96.587x | 93.703–100.760x |
| PAC/XPAC compatibility | 115.319x | 100.665–132.989x |
| Authenticated branch | 68.779x | 65.551–71.055x |
| Ordinary integer control | 1.058x | 1.038–1.111x |
| Ordinary scalar-memory control | 0.986x | 0.978–0.995x |

The preliminary shorter mixed-process cohort reported integer/scalar control
ratios of 0.745x/0.890x. Those raw results and the exact old harness are retained
under `preliminary/`; they are not silently replaced by the later cohort. The
longer isolated cohort reports +5.8% integer and −1.4% scalar-memory differences.
These observations do not establish an ordinary-path speedup or an invariant
regression bound: they vary with measurement context. A separate generated-code
audit finds identical integer/scalar instruction sequences after normalizing
only MOVN/MOVZ/MOVK immediate fields containing process-specific operand addresses.
Operation/Block/Node layouts are unchanged at 192/152/264 bytes. The temporary
audit is removed before final production-source acceptance. No ordinary native
instruction or new hot check was added. Retained artifacts allow the timing
variation to remain visible rather than attributing it to a proven mechanism.

[Raw samples](jit-compatibility-20261128/isolated-samples.jsonl),
[summary](jit-compatibility-20261128/benchmark-summary.json),
[build/binary provenance](jit-compatibility-20261128/benchmark-provenance.json)
and both generated control streams are source-bound evidence. They show large
improvements in these repeated compatibility microbenchmarks, not equivalent
application-level multipliers.

These loops measure CPU execution and backend exits with checked guest state;
they do not measure Linux syscall handlers, KVM throughput, graphics, JNI,
Android lifecycle or application speed. The no-authentication/zero-tag policy
is unchanged on both sides of the comparison. The measurements are not evidence
for full hardware PAC/MTE or unsupported host extensions.

## Remaining work

The existing shared-CPU categories listed in the
[coverage plan](../roadmap/native-jit-coverage.md) now have native instruction
paths. Changed code epochs can still use a one-instruction boundary fallback;
unknown embeddings without hardware memory-order ownership retain conservative
atomic/barrier behavior. Full PAC/BTI/MTE, SVE/SME and LS64/SETG remain unadvertised
pending their real CPU/context/memory ABI ownership. This category completion
does not imply every host ISA extension or future encoding is implemented.
