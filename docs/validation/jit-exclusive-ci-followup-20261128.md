# Exclusive-category CI follow-up — 2026-11-28

Runtime `08bc623868ab03599c5bd4be9b2b88c0874b71be` passed its
`software-jit` workflow; paired Android `30b9ca282646d4dd71b405d6db844c87df25aca7`
passed Windows APK, Linux ARM64 and Apple CPU jobs. Runtime's full verify run
46113702149 failed in the musl GNU-C-frontend network test step, after its earlier
workspace tests and Clippy passed. The fail-fast matrix cancelled Apple verify.

`shared_resolver_dispatches_concurrent_endpoints_and_reclaims_dead_requests`
incorrectly assumed a real resolver callback's temporary strong endpoint reference
had disappeared immediately after sending a query and dropping the caller's Arc.
A received reply also precedes the callback's return. The revised test retains
the 64 real concurrent queries and separately inserts a queued weak request into
the existing pending table. It proves the endpoint dies, the request is present,
and the original service tick reclaims it. Production resolver behavior is
unchanged; there is no sleep, retry loop or new synchronization.

The follow-up also restores the missing `native-code` cfg on the memory crate's
ordered helper module, removing a duplicated cfg on its exclusive helper. The
default/iPad graph no longer compiles unused native-only ordered helpers.

Scoped acceptance on the same source:

- ARM64 Linux GNU: all 213 network library tests pass.
- ARM64 Linux musl with the CI GNU C frontend/linker: all 213 pass.
- Apple ARM64: all 213 pass with localhost sockets enabled. The first sandboxed
  run's socket tests were denied by the host sandbox; the affected DNS test itself
  passed there too. The permitted rerun passes the entire package.
- Scoped Linux all-target/all-feature network Clippy with `-D warnings` passes;
  pre-existing third-party smoltcp warnings remain dependency warnings.
- Apple-hosted `cargo check -p trames-interpreter --target aarch64-apple-ios`
  passes without the earlier native-only helper warnings.

The CPU/JIT implementation and probes are unchanged. Their passing category
results are reused; this test/cfg correction does not repeat unrelated graphics,
syscall, networking integration or performance campaigns.
