# Trames Runtime

Shared Linux userspace runtime for [Trames iPad](https://github.com/kb5000/trames-ipad)
and [Trames Mac](https://github.com/kb5000/trames-mac).

This repository owns execution contracts, guest memory and reclamation, ELF
loading, Linux syscall/image ABI, the complete process/thread kernel, terminal
control, VFS/network/storage,
distribution loading and shared Wayland protocol services. It contains neither
the CPU interpreter nor the Hypervisor transport/product application.

```sh
git clone https://github.com/kb5000/trames-runtime.git
cd trames-runtime
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo build --workspace --all-features --release --locked
cargo run --release -p trames-memory --example reclaim-footprint --locked
```

The pinned Rust toolchain is declared in `rust-toolchain.toml`. Each product pins
this repository as a `runtime/` Git submodule; changing a product's runtime
requires an explicit submodule commit update. Do not maintain product-specific
copies of common Linux semantics.

`SOURCE.json` identifies the original source commit. Related Git history and
original authors were retained during extraction. The implementations are
unchanged at the initial split. `trames-session` now owns the shared process table,
clone/fork/exec/wait lifecycle, signals, futexes, PTYs and scheduler. It is generic
over `trames-engine::Cpu`; iPad instantiates the original interpreter state and
Mac instantiates hardware task state. Each execution thread owns its engine, so
an HVF vCPU never acquires `Send` or migrates between host threads. Interpreter
instructions keep their existing decoder, deferred flags and memory path.

Native acceleration and Vulkan services also live here because they operate on
guest memory/values without a decoder dependency. Products opt into their guest
profiles independently; the hardware shell executes original ARM64 code.

The process conformance suite runs with the real interpreter in the iPad product:
`cargo test -p trames-core --test kernel-conformance --locked`. Its test target
compiles the shared source directly, preserving access to the existing internal
invariants without adding an interpreter dependency to this workspace. Product
CI must run that target as well as standalone common tests.

Live-anonymous host-pressure paging remains tracked by
[issue 44](https://github.com/kb5000/trames-ipad/issues/44).
