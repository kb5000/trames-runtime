# Native JIT category completion

Owner direction: each iteration completes at least one entire category; a small
instruction group is an intermediate checkpoint, not the end of the task.
Continue across categories without requiring another owner confirmation.

A completed category has a closed instruction/encoding list, cold host-capability
and allocation decisions, real native instructions using existing CPU/memory
state, exact retirement/fault behavior, Linux native and Apple/iPad isolation
checks, Android CPU-probe coverage, and committed/pushed paired Runtime pins.
Compilation, Linux execution and Android app-UID/device acceptance are distinct.

## Completed category additions

- SIMD copy/immediate/permute: scalar/vector DUP, INS from GPR/vector, UMOV/SMOV,
  MOV/MVN aliases, MOVI/MVNI/ORR/BIC immediates, FMOV vector immediates including
  host-admitted FP16, EXT, TBL/TBX (one to four wrapped tables), ZIP/UZP/TRN,
  REV16/32/64 and existing RBIT/NOT. Includes ignored INS selector bits and exact
  vector/GPR namespace pinning. See [validation](../validation/jit-move-crypto-20261128.md).
- Stateless crypto: AESE/AESD/AESMC/AESIMC, PMULL/PMULL2 P8/P64, all shared-CPU
  SHA1/SHA256, SHA512, SHA3 EOR3/BCAX/RAX1/XAR, SM3 and SM4 forms. Native lowering
  and cold gates cover the entire list. Hardware execution is tested where the
  host advertises the extension; absent SM3/SM4 test reached-PC SIGILL without
  software emulation. Real SM3/SM4-positive execution still needs suitable hardware.

- System registers and control boundaries: guest TLS/TLS2, FPCR/FPSR, NZCV,
  read-only cache geometry, host-domain virtual counters and RNDR/RNDRRS;
  DC ZVA and all supported cache maintenance, barriers/hints, precise BRK/HLT
  and typed native-call exits. The entire existing shared-CPU list is covered
  without interpreter entry. PAC/BTI hints retain the unadvertised compatibility
  profile; this does not implement authenticated branches, MTE, SVE or SME.
  See [system-category validation](../validation/jit-system-20261128.md).

- Remaining fixed-width SIMD/FP arithmetic: scalar SIMD, saturating and
  widening/narrowing operations, immediate/variable shifts and inserts, indexed
  multiply/add, pairwise/across-lane reductions, reciprocal families, precision
  and fixed-point conversions, FP16/BF16/DotProd/I8MM/RDM/FCMA/FHM, JSCVT and
  FRINT32/64. Cold capability masks include both HWCAP words and compound FCMA
  half requirements. Low-index operands use the host's real caller-saved vector
  bank, with no software arithmetic or extension state. The independent LLVM
  matrix has 68,214 admitted encodings, zero invalid admissions and zero valid
  unadmitted forms in the declared FP/AdvSIMD matrix. See
  [arithmetic validation](../validation/jit-arithmetic-20261128.md).

- Exclusive reservations: every single-register B/H/W/X LDXR/LDAXR and
  STXR/STLXR, W/X paired LDXP/LDAXP and STXP/STLXP, plus all CLREX options.
  Closed private windows retain the hardware monitor across shared native GPR
  lowering with no helper/frame traffic between LR and SC. Open/shared/sliced
  sequences execute native fragments through the original reservation domain,
  preserving ABA invalidation and worker migration. See
  [exclusive-category validation](../validation/jit-exclusive-20261128.md).

- Special memory: all CPYF/CPY/SET P/M/E option combinations use real MOPS
  instructions, protected canonical aliases or the original checked byte
  transport, and original GPR/NZCV progress. LSE128 SWPP/LDCLRP/LDSETP retain two
  independent in/out registers, all orderings and the original atomic domain.
  LDLAR/STLLR retain real opcodes behind safe host admission. Missing/unowned
  capabilities fault when reached; LS64 and tag-setting MOPS SETG remain rejected
  without their Device-memory/MTE contracts. The independent LLVM fixture has
  548 encodings. Actual Linux/Apple checks and MOPS-positive model acceptance
  are distinguished from outstanding positive MOPS/LSE128/LOR hardware and
  Android app-UID/large-page acceptance. See
  [special-memory validation](../validation/jit-special-memory-20261128.md).

- Existing non-hint PAC/MTE compatibility profile: every PAC/AUT register and
  zero-modifier form, XPAC/PACGA, authenticated branches/returns and loads,
  IRG/GMI/SUBP/SUBPS/ADDG/SUBG, LDG and every STG/STZG/ST2G/STZ2G/STGP addressing
  form now avoids interpreter entry. Disabled authentication and zero allocation
  tags remain the existing shared-CPU policy, rather than host PAC keys or new
  tag state. Register/address/data effects use native baseline instructions;
  tag-only permissions/translation reuse Memory/View. Actual data transfers
  fuse into protected native aliases. An independent LLVM fixture contains
  836 encodings, with whole-state/data/budget/fault and reservation acceptance.
  See [compatibility validation](../validation/jit-compatibility-20261128.md).

- Execution invalidation boundaries: scalar/linked, vector and fused-memory
  entries that observe a changed execution epoch now revalidate and retry
  natively. One cold extra entry is selected by const specialization; continued
  invalidation yields the execution slot without interpreting an instruction.
  Existing CPU publication, FP scope, memory loans and reservation ownership
  remain unchanged. Whole-state/retirement tests include all NZCV combinations,
  dirty-prefix exits and guest-authorized self-modification. See
  [execution-boundary validation](../validation/jit-execution-boundaries-20261128.md).

- Abstract CpuMemory ordered/atomic category: all existing LDAR/STLR,
  LDAPR/LDAPUR/STLUR and signed forms, CAS/CASP, LSE RMW/store aliases and
  host-admitted LSE128/LOR now use real native fragments through the original
  read/write/atomic-update/fence authority, without interpreter entry. Cold
  compilation keeps abstract ordered accesses at their callback boundary even
  when aliases are offered. Product Memory/View retains its existing direct
  hardware/fused path. The independent LLVM matrix has 795 encodings; full
  callback/state/fault/reservation acceptance and absent-host rejection are
  recorded in [validation](../validation/jit-abstract-memory-20261128.md).

- Base scalar integer decoding and error boundaries: all existing move/address,
  arithmetic/logical/bitfield, conditional/carry, multiply/divide/shift, CRC,
  CSSC and flag forms share a pure cold decoder. SMULH/UMULH accept every
  hardware-ignored Ra value in both shared interpreter paths and JIT, without
  loading that field. A 1,048,576-selector LLVM audit admits 464,344 words
  including seven special system forms, with no invalid admissions or missing
  integer forms; 2,216 separate PAC/MTE compatibility words retain their existing
  lowering. Every untranslated selector in the declared sweep is confirmed to
  be an original interpreter instruction fault. Those scalar errors now use
  original cache/page revalidation and direct faults without interpreter entry.
  Real execution, alias/pressure/budget coverage, generated-code identity and
  scope limits are recorded in [validation](../validation/jit-scalars-20261128.md).

- Fixed-state branch/call category: existing B/BL, all conditional/zero/bit
  branches and BR/BLR/RET retain their native paths; HBC BC.cond and all CMPBR
  register/immediate/byte/halfword forms now keep actual host opcodes. Their
  gates use only the kernel's process HWCAP/HWCAP2 and run in cold translation.
  No new NZCV/extension bank is introduced. The independent LLVM 23 matrix has
  19,568 encodings and all 4,096 CMPBR selectors (1,536 valid). Owned untranslated
  conditional/compare/register-branch/exception selectors have original-fault
  closure and a direct negative cache; this does not advertise privileged/GCS
  branches or new authentication state. See
  [control-category validation](../validation/jit-control-20261128.md).

LSE128 is exposed only when the process host provides it. LS64 and full hardware
PAC/BTI/MTE remain unadvertised without their required shared-CPU/memory ownership.
This does not change the interpreter-only backend's compatibility policy. New
stateful/later ISA features still need explicit ABI ownership; a closed fixed-width
category is not full host-ISA coverage.

## Remaining ownership and execution work

The previously listed existing shared-CPU instruction categories are covered.
This is not a claim of every host ISA extension or every future encoding.

1. Full hardware PAC/BTI/MTE and stateful SVE/SME still require explicit shared
   CPU/context/memory ABI ownership. LS64 needs its Device-memory contract and
   SETG needs allocation-tag ownership. These capabilities remain unadvertised;
   do not substitute software extension state or interpret them as simpler ops.
2. The generic one-instruction interpreter entry remains for encodings not
   recognized outside the closed scalar and owned control/exception spaces; it can report an
   instruction fault rather than successfully execute an instruction. Scalar
   groups 5/8/9/13 and the audited owned control/exception selectors now diagnose
   those errors directly. This is not full host-ISA
   coverage, and the selector audit does not enumerate all operand/literal bits.
   Changed execution epochs now retry/yield natively, not through that fallback.
   Abstract ordered/atomic embeddings now retain their own fence/transaction
   semantics through native fragments, rather than interpreter stepping.
3. Positive extension hardware, Option-B MOPS/migration and real Android app-UID,
   ART interaction and large-page devices remain acceptance work. Linux native,
   independent ISA-model execution and Windows APK compilation are distinct.

Compile-time interpreter-only configurations (including iPad and non-AArch64
hosts) intentionally omit native execution. Checked Memory/View callbacks,
cross-page staging, syscall/native-call dispatch and guest faults are not by
themselves interpreter fallback. The direct SVC exit remains native.

Keep native capability admission and reserved-encoding decisions in compilation.
Do not add guest-text rewrites, hot preflights, stronger ordinary-memory ordering,
global locks, resource/coordinator threads or full-state copies. Reuse existing
CPU banks, memory aliases, precise recovery and FP callback suspension. Android
SDK/NDK/JDK/device work stays on Windows. Preserve the owner's iPad worktree and
clean only batch-owned temporary artifacts.
