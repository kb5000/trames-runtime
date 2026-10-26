# Trames Runtime

Shared Linux userspace runtime for [Trames iPad](https://github.com/kb5000/trames-ipad)
and [Trames Mac](https://github.com/kb5000/trames-mac).

This repository owns execution contracts, guest memory and reclamation, ELF
loading, Linux syscall/image ABI, task signal state, VFS/network/storage,
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
unchanged at the split; process/executor scheduling integration and live-anonymous
pressure paging remain tracked by the iPad repository's issue 44.
