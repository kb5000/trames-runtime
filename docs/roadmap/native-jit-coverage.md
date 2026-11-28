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

Cold gate closure also covers untranslated JSCVT, BF16, FHM, FCMA (including its
FP16 dependency), DotProd, I8MM, RDM, FP16 and FRINT32/64. Their presence does not
yet imply full native lowering. LS64 is rejected because this profile does not
own the HWCAP3/device-memory contract; LSE128 remains unadvertised. This does not
change the interpreter-only backend's compatibility policy.

## Remaining categories

1. Remaining SIMD/FP arithmetic: scalar SIMD, widening/narrowing, shifts,
   indexed multiply/add, reductions/pairwise forms, reciprocal families and
   precision conversions; FP16/BF16/DotProd/I8MM/RDM/FCMA/FHM native forms.
2. Exclusive reservations: all LDXR/LDAXR/LDXP/LDAXP and STXR/STLXR/STXP/STLXP
   widths, CLREX, precise faults and transitions through helpers/slices/workers.
3. Special memory: MOPS, optional LSE128 and LS64 only with a host ABI and memory
   contract that can actually execute their hardware semantics.
4. Existing PAC/BTI/MTE compatibility paths and stateful SVE/SME require explicit
   hardware/ABI ownership. Do not substitute new software extension state.

Keep native capability admission and reserved-encoding decisions in compilation.
Do not add guest-text rewrites, hot preflights, stronger ordinary-memory ordering,
global locks, resource/coordinator threads or full-state copies. Reuse existing
CPU banks, memory aliases, precise recovery and FP callback suspension. Android
SDK/NDK/JDK/device work stays on Windows. Preserve the owner's iPad worktree and
clean only batch-owned temporary artifacts.
