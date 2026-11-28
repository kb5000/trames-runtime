# Native structure, lane and replicate transfers — 2026-11-28

The native compiler now covers LD1/ST1 lists of one to four registers,
interleaved LD2/3/4 and ST2/3/4, single-lane LD/ST1..4, and LD1R..LD4R.
Base-only, immediate post-index and X-register post-index forms retain original
arrangements, lane indices, V31-to-V0 wrap, SP/TBI and writeback. Transfers range
from 1 to 64 bytes. The original host instruction owns interleaving, broadcasting,
untouched lane bits, ordering and atomicity. The decode follows the Arm
[multiple-structure reference](https://support.arm.com/documentation/111108/2026-03/SIMD-FP-Instructions/LD1--multiple-structures---Load-multiple-single-element-structures-to-one--two--three--or-four-registers-)
and [single-structure and replicate definitions](https://documentation-service.arm.com/static/67e40f3398aa3c3b6eea6a85).
[Implementation and ownership](../architecture/software-execution.md#structure-lane-and-replicate-transfers).

The cold allocator reserves contiguous groups inside host v16..v31. Already
packed groups emit no register movement or CPU-bank traffic. When a group must
move, all displaced dirty values are published before loading relocated members,
including overlaps and wrapped guest lists. Full loads reserve outputs without
reading old destinations; lane loads bind the old full vector. The checked stub
uses only caller-saved v0..v3 and paired Q marshalling where possible. Register
enumeration uses allocation-free iterators, with at most four vector values and
64 staged operand bytes. No new guest extension state or software permutation
loop is introduced on the native path.

Capability/encoding/arrangement and register-allocation decisions remain in cold
translation. Hardware hits reuse the existing affine aliases, address proof,
one-guest-4-KiB bound, registered exact-PC recovery and mixed FP callback bridge.
No extra access preflight, ordinary-memory fence, aggregate lock, coordinator or
guest-code rewrite is added. Checked operations commit outputs and post-index
writeback only after the complete operand succeeds. Scalar/SVC and memory-frame
ABIs, JNI flags/schema and feature isolation remain unchanged.

## Validation

ARM64 Linux passes **12 unit/capability + 69 differential tests (81)** in Debug
and Release, plus strict all-target JIT Clippy. Apple passes **66 differential
fallback tests** and scoped strict Clippy; it does not execute this native JIT.
iOS interpreter compilation, its feature graph, execution-boundary checks and
formatting pass. The graph contains neither JIT nor native-code allocation.
Interpreter/host-compute/memory source is unchanged, so prior interpreter
48+2+1, host-compute 4, and memory Linux 282+6 / Apple 279+6 results (3 ignored each)
are reused instead of rerunning unaffected suites.

New successful matrices cover 5,616 arrangement/lane/replicate combinations,
including both 64/128-bit widths, all B/H/S/D lane indices, one-to-four lists,
interleaving, V31 wrap, SP, tags, immediate/register post-index and base/index
aliases. They compare every architectural field, canonical bytes and exact
retirement at slice boundaries, and require one actual native memory operation.
Another 630 pressure/cross-page/fault cases scramble dirty bindings before
group allocation and check slow-helper reloads, preserved old targets and
uncommitted writeback. Reserved encodings retain reached-PC faults. Revoked
hardware aliases exercise exact recovery for multiple/lane/replicate operations
after a dirty FP prefix. A write-only staging provider confirms that a 64-byte
full overwrite does not read old provider bytes. Compiler tests require no
emitted loads/stores when an already packed wrapped group is reused.

The Android core's interpreter/JIT probes pass on Linux ARM64 and Apple. New
LD1-four, interleaved LD4, LD4-lane and LD4R loops each wrap V31 to V0, perform
native NEON arithmetic and verify all output bytes/vectors, exact retirement of
257 guest instructions, zero fallback/staging, at least 62/64 direct hardware
accesses, address-proof reuse and one fused entry. JNI remains schema 1 / 40
bytes with the existing flags. Android tools and APK packaging stay on Windows
CI. Real app-UID/ART coexistence and 16-KiB Android device acceptance remain
separate work.

## Matched measurement

Baseline Runtime `367358df0a0eb25394a4af3146d4ce0d7950690e`; candidate is that
base plus the hashed implementation. Same Lima ARM64 Linux VM, kernel
`7.0.0-44-generic`, 4-KiB pages, 6 vCPUs, rustc
`1.101.0-nightly (4ebd25825 2026-10-15)`, thin LTO, overflow checks and no
incremental compilation or imposed affinity. No other VM compilation runs
during measurement.

Four balanced old/new pairs alternate execution order. Each process runs all six
workloads with one warm-up and five timed samples: **8 processes, 240 timed and
48 warm-up samples**. Values below are medians of four process medians. Each new
workload runs 1,048,576 iterations of load, four ADD 4S instructions, store,
SUBS/B.NE, followed by SVC. Initialization and validation are outside timing.
Full canonical bytes match independent expected values, original guest words
remain unchanged, exact retirement and all final vectors/PC agree across builds,
and committed memory is checked again after dropping the private worker View.

| Workload | Previous JIT | New JIT | Speedup |
|---|---:|---:|---:|
| LD1/ST1 four Q registers, 64 bytes | 428.342 ms | 3.075 ms | 139.31× |
| LD4/ST4 interleaved 4S, 64 bytes | 206.650 ms | 4.839 ms | 42.71× |
| LD4/ST4 S[0] lane, 16 bytes | 169.445 ms | 3.885 ms | 43.61× |
| LD4R 4S / ST4 S[0], 16 bytes | 174.250 ms | 3.919 ms | 44.46× |
| Integer load/add/store control | 1.185 ms | 1.218 ms | 0.97× |
| Scalar FADD control | 1.854 ms | 1.852 ms | 1.00× |

New mixed loops have zero fallback/staging, 12,582,900 direct hardware accesses
out of 12,582,912 memory instructions across six samples, and one fused entry per
sample. The previous implementation fell back for each structure instruction
and split arithmetic blocks. Gains include removing software layout work and
dispatch/entry boundaries; they are specific CPU loops rather than application
speedups or KVM/native equivalence. Controls move by +2.77% and −0.10%; the cohort
does not establish a general improvement in unaffected instructions.

[Frozen fixture/build lockfiles, raw samples, source/binary hashes, tests and summary](jit-structures-20261128/)
are retained. Run `python3 jit-structures-20261128/audit.py` to verify hashes and
paired work/counters and recompute all numbers. An optional Runtime source path
verifies candidate hashes. No VM image, SDK or build cache is committed.

Remaining native coverage includes exclusive reservations, FPCR/FPSR system
instructions, additional SIMD/indexed/crypto arithmetic and separately owned
stateful extensions. This batch completes these AdvSIMD structure memory classes.
