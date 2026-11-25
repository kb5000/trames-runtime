<p align="center">
  <img src="https://raw.githubusercontent.com/project-trames/.github/main/assets/trames-icon.png" alt="Trames icon" width="112">
</p>

<h1 align="center">Trames Runtime</h1>

<p align="center">
  <strong>A shared userspace Linux kernel for pluggable execution engines and platforms.</strong>
</p>

<p align="center">
  Pure-Rust implementation of Linux system calls, virtual memory, process models, VFS, and networking.<br>
  Decoupled from instruction execution backends and shared across all Trames products.
</p>

<p align="center">
  <a href="https://github.com/project-trames/trames-runtime/actions/workflows/runtime.yml"><img src="https://github.com/project-trames/trames-runtime/actions/workflows/runtime.yml/badge.svg?branch=main" alt="Runtime CI on Linux and macOS"></a>
  <a href="https://github.com/project-trames/trames-runtime/actions/workflows/acceptance.yml"><img src="https://github.com/project-trames/trames-runtime/actions/workflows/acceptance.yml/badge.svg?branch=main" alt="Acceptance harness and native references"></a>
</p>

<p align="center">
  <a href="rust-toolchain.toml"><img src="https://img.shields.io/badge/Rust-nightly-b65437?style=flat-square&amp;logo=rust&amp;logoColor=white" alt="Rust nightly"></a>
  <a href=".github/workflows/runtime.yml"><img src="https://img.shields.io/badge/hosts-Linux%20%7C%20macOS-30303d?style=flat-square" alt="Linux and macOS host builds"></a>
  <a href="docs/architecture/execution-backends.md"><img src="https://img.shields.io/badge/guest%20ISA-ARM64-f0ad43?style=flat-square" alt="Current ARM64 guests"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0--or--later-7c5269?style=flat-square" alt="GPL-3.0-or-later"></a>
</p>

<p align="center">
  <a href="#features">Features</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#workspace-crates">Crates</a> ·
  <a href="#building-and-testing">Building</a> ·
  <a href="#validation">Validation</a> ·
  <a href="#documentation">Documentation</a>
</p>

---

## Features

`trames-runtime` provides userspace operating system semantics for unmodified Linux binaries, completely isolated from host kernel dependencies:

* **Process & Concurrency Subsystem**: Task and thread lifecycle, POSIX signals, `clone`/`fork`/`exec`/`wait`, futexes, priority scheduling, and tty/pty job control.
* **Virtual Memory Architecture**: ELF loading, guest address-space isolation, soft-page tables, memory mapping (`mmap`/`mprotect`), copy-on-write, and memory reclamation.
* **VFS & Storage**: Extensible virtual filesystem, file descriptor management, mounts, pipes, epoll, persistent storage backends, and host pass-through mappings.
* **Userspace Network Stack**: Socket layer implementation, raw IP packet routing, virtual interfaces, and TCP/UDP protocol processing in user space.
* **Execution Engine Interface**: Clean abstractions for CPU state, page faults, syscall intercepts, and interrupts, decoupling OS logic from hypervisors or interpreters.
* **Display & Graphics Services**: Wayland compositor protocols, Xwayland support, headless display handling, and bridge contracts for Vulkan/OpenGL acceleration.

---

## Architecture

The core architectural principle of Trames is the strict separation of **Operating System Behavior**, **Instruction Execution**, and **Host Presentation**:

```text
┌──────────────────────────────────────────────────────────────┐
│                  Unmodified Linux Binaries                   │
└──────────────────────────────┬───────────────────────────────┘
                               │ Guest Syscalls / Faults
┌──────────────────────────────┴───────────────────────────────┐
│                        trames-runtime                        │
│   ┌───────────────┐  ┌───────────────┐  ┌────────────────┐   │
│   │ VFS & Storage │  │ Task / Futex  │  │ Memory / Paging│   │
│   └───────────────┘  └───────────────┘  └────────────────┘   │
│   ┌───────────────┐  ┌───────────────┐  ┌────────────────┐   │
│   │ Userspace Net │  │ Wayland Host  │  │ Acceleration   │   │
│   └───────────────┘  └───────────────┘  └────────────────┘   │
└──────────────────────────────┬───────────────────────────────┘
                               │ Execution Engine Contracts
┌──────────────────────────────┴───────────────────────────────┐
│               Pluggable Execution Engines                    │
│   ┌───────────────────┐  ┌───────────────┐  ┌────────────┐   │
│   │    AArch64 CPU    │  │ Apple Silicon │  │ Linux KVM  │   │
│   │ Interpreter (iPad)│  │   HVF (Mac)   │  │  (Server)  │   │
│   └───────────────────┘  └───────────────┘  └────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

* **OS Emulation Boundary**: `trames-runtime` handles high-level Linux semantics. A compatibility fix here immediately benefits all platforms.
* **Pluggable Backends**: Product repositories link this runtime alongside their preferred execution backend:
  * [**trames-ipad**](https://github.com/project-trames/trames-ipad): Pairs Runtime with a pure-software AArch64 interpreter.
  * [**trames-mac**](https://github.com/project-trames/trames-mac): Integrates with macOS `Hypervisor.framework` (HVF).
  * [**trames-linux**](https://github.com/project-trames/trames-linux): Integrates with Linux KVM for near-native hardware virtualization.

---

## Workspace Crates

The repository is organized into focused, modular Rust crates:

| Subsystem | Crates | Description |
| :--- | :--- | :--- |
| **Kernel Core** | `trames-kernel`, `trames-session`, `trames-linux` | Syscall dispatching, task coordination, and Linux ABI definitions. |
| **Execution Abstraction** | `trames-engine`, `trames-execution` | Engine lifecycle, register state contracts, interrupts, and traps. |
| **Memory & Binaries** | `trames-memory`, `trames-elf` | Address spaces, page tables, memory regions, and ELF64 loader. |
| **IO & Network** | `trames-vfs`, `trames-net` | Virtual filesystem, file descriptors, packet routing, and socket layers. |
| **Graphics & Windows** | `trames-graphics`, `trames-wayland`, `trames-vulkan` | Shared display surfaces, Wayland protocol services, and GPU hooks. |
| **Media Subsystems** | `trames-audio`, `trames-video` | Host-agnostic audio/video playback and capture pipelines. |
| **Acceleration** | `trames-accel`, `trames-native` | Memory-copy fast paths and native call thunking interfaces. |
| **Environment & Tools** | `trames-distro`, `trames-bridge`, `trames-control`, `trames-shared` | Rootfs bootstrap helpers, IPC channels, and interop glue. |

---

## Building and Testing

### Prerequisites

* Rust nightly toolchain (defined in [`rust-toolchain.toml`](rust-toolchain.toml)) with `rustfmt` and `clippy`.
* Python 3 and a native C compiler (`clang` or `gcc`).
* **Linux**: `libasound2-dev` for audio subsystem verification.
* **macOS**: Xcode Command Line Tools.

### Quickstart

```sh
git clone https://github.com/project-trames/trames-runtime.git
cd trames-runtime

# Build guest interop helpers (targets aarch64-unknown-linux-musl)
python3 scripts/build-guest-cli.py
```

### Running Tests & Verification

```sh
# Run execution boundary checks
python3 scripts/check-execution-boundaries.py

# Formatting and lints
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

# Workspace unit tests
cargo test --workspace --all-features --locked

# Build all workspace crates in release mode
cargo build --workspace --all-features --release --locked
```

For testing memory pressure and footprint reclamation routines:
```sh
cargo run --release -p trames-memory --example reclaim-footprint --locked
```

---

## Validation

`trames-runtime` relies on a multi-tiered validation pipeline to prevent regressions and systematically verify Linux semantics:

* **Subsystem Unit Tests**: Isolated test suites within each crate validating individual syscall semantics, page fault models, and VFS invariants.
* **Syscall Conformance**: Regression suites validating behavioral diffs against native Linux, including tests adapted from [gVisor](tests/gvisor/).
* **Workload Acceptance**: Self-contained rootfs environments running real-world CLI toolchains and compilers with automated output verification.
* **Cross-Submodule Conformance**: End-to-end integration tests run from consuming product repositories (e.g., interpreter execution tests in `trames-ipad`).

Detailed test matrices, architectural decision records, and acceptance run logs are documented under [`docs/validation/`](docs/validation/).

---

## Documentation

| Domain | Deep Dives |
| :--- | :--- |
| **Execution & Dispatch** | [Execution Backends](docs/architecture/execution-backends.md) · [Coordination Boundaries](docs/architecture/coordination-boundaries.md) |
| **Concurrency & State** | [Task State Machine](docs/architecture/task-state.md) · [Environment Boot](docs/architecture/environment-boot.md) |
| **Memory Architecture** | [Region Memory Model](docs/architecture/region-memory.md) · [Native Allocator Fastpath](docs/architecture/native-allocator.md) |
| **Storage & IO** | [Native Resource Management](docs/architecture/native-resources.md) · [Storage Synchronization](docs/architecture/private-storage-sync.md) |
| **Networking** | [Userspace Packet Networking](docs/architecture/packet-networking.md) |
| **Graphics & Compositor**| [Display Lifecycle](docs/architecture/display-lifecycle.md) · [Audio Subsystem](docs/architecture/audio.md) |
| **Validation Architecture**| [Acceptance Framework](docs/architecture/acceptance.md) · [Validation Evidence](docs/validation/) |

---

## Contributing

Contributions, bug reports, and conformance tests are warmly welcomed. Please review our [Contribution Guidelines](https://github.com/project-trames/.github/blob/main/CONTRIBUTING.md) and [`AGENTS.md`](AGENTS.md) before submitting patches.

* **Issues**: [GitHub Issue Tracker](https://github.com/project-trames/trames-runtime/issues)
* **Security**: For private vulnerability reporting, see [SECURITY.md](https://github.com/project-trames/.github/blob/main/SECURITY.md)
* **Conduct**: We adhere to the [Project Code of Conduct](https://github.com/project-trames/.github/blob/main/CODE_OF_CONDUCT.md)

---

## License

Trames Runtime is licensed under the **GNU General Public License v3.0 or later** ([GPL-3.0-or-later](LICENSE)).<br>
Third-party component notices and source provenance are tracked in [SOURCE.json](SOURCE.json).

---

<p align="center">
  Part of <a href="https://github.com/project-trames">Project Trames</a> · A portable userspace Linux runtime with pluggable execution engines.
</p>
