# Native scalar memory fragments — 2026-11-27

Scalar LDR/STR now execute real host memory instructions through the existing
Runtime borrow model, without entering the interpreter's fetch/decode loop.
The initial load/add/store loop improves about **1.66x over the old JIT** in the
controlled cohort; it remains about five times slower than the cached interpreter.
This batch advances native coverage and does not claim fully fused memory code.

## Scope and safety

- B/H/W/X unsigned stores/loads and signed byte/halfword/word loads; scaled
  unsigned and signed unscaled offsets, pre/post-index, UXTW/SXTW/LSL/SXTX register
  offsets and literal loads. PRFM remains an optional no-read hint.
- Cold translation caches exact-width W^X host fragments. The helper handles
  decoded address calculation, existing memory borrows and precise base/result
  commit. Host x18/TLS, SP and callee-saved/FP state are untouched. No new extension
  simulation state, guest instruction rewrite or executable RX patch is added.
- Single-page transfers borrow current guest bytes; cross-page and nonresident
  embeddings use canonical staging. Both are separately counted. No host byte
  pointer, provider lease or translated data address survives the callback.
- The new full-overwrite hook uses the same write borrow as existing native
  operations, preserving COW, dirty publication, executable epochs and exclusive
  invalidation. Its const-generic staging path skips old-byte reads; write-only
  pages/backings do not acquire a read-permission requirement. Ordinary memory
  reads/writes acquire no additional fields, lock, barrier or feature probe.
- Cached continuation handles retain all identity/page/mode/generation gates.
  Memory fragments have a different ABI: machine links never target them. Native
  stores return to normal identity checking before later guest code executes.
  Independent LDR/STR borrows do not make guest read/modify/write atomic.

## Validation

Actual ARM64 Linux passes **5 native/capability tests and 28 differential tests**:
32 earlier tests plus the exact ABI/eviction follow-up, reusing unchanged passes.
The memory unit suite passes 281 cases with three existing ignores, plus its
existing integration tests. Scoped all-target/all-feature JIT/memory Clippy passes.

The added matrix covers 1,456 width/address/register cases plus literal loads,
112 permission/fault combinations, successful cross-page staging, tag stripping,
SP/ZR and sign extension, precise failed pre/post-index writeback, write-only
legacy embeddings and a provider that rejects every read. Memory and View tests
cover COW, scalar stores invalidating exclusive monitors, executable stores
revalidating warmed code, and two live guests retaining an allowed lost update.
ABI tests require metadata-only memory edges and reject evicted slot generations.

macOS passes 28 non-native differential tests (27 unchanged plus the exact new
interleaving recheck), 278 memory unit tests with three original ignores, scoped
Clippy and the Android core probe. iOS ARM64 interpreter compile passes, confirming
shared API portability without compiling the JIT into iPad. Actual ARM64 Linux
runs Android's new load/add/store probe with zero fallback and two direct native
memory operations. JNI remains 40 bytes; app instrumentation now requires flag 6.
Android device app-UID and 4/16 KiB device execution remain separate acceptance.

The preceding global Runtime CI failure at `f3f45e5` was an existing perf-pacing
test module placed before production declarations in workers.rs. This batch moves
that test module unchanged to the end; it changes no worker execution logic.

## Controlled CPU-only measurements

Base Runtime is `f3f45e5`; old/new independent release binaries use the same
expanded fixture. The old compiler's post-timing checks expect the real fallback
count rather than the new API's native-memory counters. Five process pairs
alternate lane order on VM vCPU 2. Within each process, each workload has one
warm-up and five timed samples. Below are medians of those five process medians.
Release thin LTO, overflow checks, `nightly-2026-10-16`, incremental disabled.

| Fixed workload | Old JIT ms | New JIT ms | Old/new |
| --- | ---: | ---: | ---: |
| integer-loop | 3.578 | 3.551 | 1.007x |
| svc-round-trip | 0.599 | 0.589 | 1.017x |
| svc-only | 0.533 | 0.546 | 0.975x |
| svc-continuation | 0.831 | 0.837 | 0.992x |
| scalar-memory-loop | 7.308 | 4.399 | 1.661x |

Each memory pass executes 65,536 LDR/add/STR/SUBS/B.NE iterations and one terminal
SVC. Six passes including warm-up verify 786,432 memory operations and final
stored counter 393,216. Old JIT fallback is 786,432; new fallback is zero. The
cached interpreter finishes the same pass in roughly 0.9 ms in this cohort,
so native fragment dispatch/borrowing still needs block-level fusion. A single
borrow is never extended across separate guest load/store instructions merely
to improve a benchmark, since that would strengthen their algorithm's races.

The SVC-only median is 2.5% slower and continuation 0.8% slower; round-trip is
1.7% faster. Earlier two pairs showed larger scheduling/clock variation; their
complete raw outputs remain separately archived. No guarantee of zero SVC
regression or general application speedup follows from these short samples.
Neither SVC nor memory timings include Linux syscall handlers, JNI, Android
lifecycle or process startup. No KVM or bare-metal ranking is inferred here.

[All frozen raw outputs](jit-memory-20261127/),
[cohort medians](jit-memory-20261127/summary.json),
[source/build fingerprints](jit-memory-20261127/receipt.json) and both exact
benchmark sources are retained. Tests, ordinary memory and CPU/session backends
outside the affected scope are not rerun solely for this record. No SDK/NDK,
emulator, rootfs image or VM was installed on the Mac.
