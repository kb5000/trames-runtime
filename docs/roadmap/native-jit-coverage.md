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

LSE128 is exposed only when the process host provides it. LS64 and full hardware
PAC/BTI/MTE remain unadvertised without their required shared-CPU/memory ownership.
This does not change the interpreter-only backend's compatibility policy. New
stateful/later ISA features still need explicit ABI ownership; a closed fixed-width
category is not full host-ISA coverage.

## Remaining categories

1. Existing non-hint PAC/MTE compatibility paths: authenticated branches/returns,
   authenticated loads, pointer/tag arithmetic and allocation-tag operations.
   PAC/BTI hints are already covered; full hardware PAC/BTI/MTE and stateful
   SVE/SME remain unadvertised pending shared-CPU ABI ownership. Do not substitute
   new software extension state. Unowned LS64/SETG and absent host extensions
   fault when reached; they are not interpreter-provided JIT features.

Keep native capability admission and reserved-encoding decisions in compilation.
Do not add guest-text rewrites, hot preflights, stronger ordinary-memory ordering,
global locks, resource/coordinator threads or full-state copies. Reuse existing
CPU banks, memory aliases, precise recovery and FP callback suspension. Android
SDK/NDK/JDK/device work stays on Windows. Preserve the owner's iPad worktree and
clean only batch-owned temporary artifacts.
