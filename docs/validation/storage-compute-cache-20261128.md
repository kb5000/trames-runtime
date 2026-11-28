# Shared storage, compute and pathname changes — 2026-11-28

## Scope and defaults

Private-store WAL/checkpoints and the private name cache are shared by Apple and
Linux. Computation follows the existing `pure_accelerator` option: iPad interpreter
sessions can use it; Mac HVF/Linux KVM defaults remain disabled. No UI option,
service/coordinator thread, host callback or persistent host stream handle is added.

See [storage](../architecture/private-storage-sync.md),
[compute](../architecture/native-compute.md) and
[name cache](../architecture/path-cache.md) for format and compatibility limits.
The exact 12 approved original AArch64 library hashes are in
`crates/trames-accel/src/compute-catalog.tsv`; package upgrades not in that catalog
retain original execution until reviewed. Adaptation is at session creation.

## Validation

Final affected checks were repeated after fast-forwarding to published runtime
`f595ae2a78e81a316fb842dd093c8c5c1eee005a`. Existing unrelated dirty files were
excluded from this batch. The remote changes include native-memory helpers;
the iPad composition continues to keep their executable-code feature disabled.

- Apple ARM64: `cargo test -p trames-accel --offline`: 33 passed.
- Apple ARM64: `cargo test -p trames-vfs --offline storage`: 87 passed, 2 ignored
  fixture/measurement helpers. Covers failed append repair, checkpoint errors,
  resource byte accounting, reopening, unlinked/retained objects and recovery.
- Linux ARM64, hostfs enabled: corresponding storage filter: 90 passed, 2 ignored;
  compute: 33 passed. Ran in the existing local Linux VM, not through emulation.
- `cargo check -p trames-vfs -p trames-accel --features trames-vfs/hostfs
  --target aarch64-apple-ios --locked --offline`: passed.
- `cargo clippy -p trames-accel -p trames-vfs --all-targets --offline
  --no-deps -- -D warnings`: passed. Dependency warnings remain outside this
  selected-crate lint gate. The standalone runtime's reviewed notice generator
  also passes with the seven new native/build dependencies.
- Earlier affected namespace/host-edit checks: host_files 13, import_work 5,
  idmap_resource 6, overlay copy_up 16, path_cache 1 passed. Unchanged passes reused.
- The existing kernel-conformance target with `compute_tests` passed both tests.
  Its ignored library runner was explicitly enabled with three original-library
  fixture directories. All 12 cases (three library sets × one/two CPUs × off/on)
  exited 0. Enabled cases each recorded 96 compute dispatches on workers,
  including 92 completed native operations; disabled cases recorded zero.
  Four empty SHA_Update calls
  intentionally used original fallback per enabled case. Audio auxv key uniqueness
  is checked for every audio/pure-option combination.
- The fixtures included the Debian 13 library set used by the local rootfs,
  Alpine 3.22 musl libraries and a supplementary glibc set from the existing
  vaapi-build fixture. The last directory's historical name is not an independent
  assertion of its distribution provenance. Both glibc and AArch64 musl execute
  the new INIT_ARRAY capability initializer.
- Latest adapted Debian and Alpine libraries passed the same C ABI probe on native
  Linux without a Trames capability; all four libraries in each set also restored
  byte-for-byte to their original SHA256 identities.

The public ABI probe source is `tests/fixtures/native-compute.c`. It exercises
checksums, zlib/xz/zstd buffers, the nine-argument xz decoder, public SHA256 context
updates/finalization and AES known vectors/CBC. Other SHA families, invalid public
context indices and allocation-callback fallback have unit coverage. The adapter
example can produce or exactly restore an approved derivative; unknown hashes
are also rejected by the runner.

A concrete extra generic Runtime example triggered an existing pinned-nightly
Arc/closure unsizing compiler ICE. It was removed, no workaround was shipped,
and acceptance used the established kernel-conformance target instead.

## Measurement and limits

The 200-file store fixture appends 32-byte file objects. Its equivalent old full
manifest publications total 2,055,900 bytes; WAL is approximately 137,125 bytes
(timestamp bytes vary), about 93.3% fewer manifest bytes. Object bytes and fsync
latency are not included. Full manifest serialization/checksumming still has
linear CPU cost; this is an I/O amplification measurement, not an apt benchmark.

Recovery carries immutable spans through a 128-record chain and checks the final
image once. Torn tails, stale checkpoint/WAL pairs, insertion/deletion deltas and
complete-frame corruption are covered. The matching iPad Swift reader was compiled
and executed against a Rust-generated 41-record WAL/checkpoint fixture, verifying changed
revision/signature, hard-link identity, torn tail, stale checkpoint and corruption.

No fresh physical-iPad acceptance, IPA installation, KVM/HVF hardware run, or
apt/apk/git/curl/code-server end-to-end speed measurement is claimed here.
Compression streaming/EVP/TLS contexts remain original, as documented in compute.
