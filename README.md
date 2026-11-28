<p align="center">
  <img src="https://raw.githubusercontent.com/project-trames/.github/main/assets/trames-icon.png" alt="Trames icon" width="108">
</p>

<h1 align="center">Trames Runtime</h1>

<p align="center">
  <strong>A shared pure-Rust userspace Linux kernel and execution foundation for Project Trames.</strong>
</p>

<p align="center">
  Linux syscalls, virtual memory, process/thread lifecycle, VFS, userspace networking, Wayland/Vulkan/media services,<br>
  plus the shared AArch64 interpreter and opt-in JIT—shared across iPad, macOS, and Linux hosts.
</p>

<p align="center">
  <a href="https://github.com/project-trames/trames-runtime/actions/workflows/runtime.yml"><img src="https://github.com/project-trames/trames-runtime/actions/workflows/runtime.yml/badge.svg?branch=main" alt="Runtime CI"></a>
  <a href="https://github.com/project-trames/trames-runtime/actions/workflows/acceptance.yml"><img src="https://github.com/project-trames/trames-runtime/actions/workflows/acceptance.yml/badge.svg?branch=main" alt="Acceptance CI"></a>
  <a href="rust-toolchain.toml"><img src="https://img.shields.io/badge/Rust-nightly-b65437?style=flat-square&amp;logo=rust&amp;logoColor=white" alt="Rust nightly"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0--or--later-7c5269?style=flat-square" alt="GPL-3.0-or-later"></a>
</p>

<p align="center">
  <a href="#features">Features</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#workspace-crates">Crates</a> ·
  <a href="#building-and-testing">Building</a> ·
  <a href="#documentation">Docs</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

## Features

`trames-runtime` implements userspace Linux OS semantics for unmodified ARM64 Linux binaries across Linux and Apple hosts:

- **Process & Concurrency**: Task/thread lifecycle, POSIX signals, `clone`/`fork`/`exec`/`wait`, `futex`/`futex2`, cgroups, namespaces, `ptrace`, software `perf` events, and PTY/job control.
- **Virtual Memory & Reclamation**: ELF64 loading, 48-bit guest address spaces, region memory access, `mmap`/`mprotect`, copy-on-write, sparse `PROT_NONE` reservations, and memory reclamation.
- **VFS & Storage**: Persistent private disk storage, atomic manifests, `tmpfs`, `overlayfs`, FUSE, `io_uring`, `epoll`, `inotify`, and `/proc`/`/sys`/`/dev` emulation.
- **Userspace Networking**: Isolated packet fabric (`smoltcp`), virtual interfaces, NAT/netfilter, DNS, and nonblocking host TCP/UDP/ICMP egress.
- **Pluggable Execution Backends**: Clean `trames-engine` / `trames-execution` contracts decoupling OS semantics from instruction execution, alongside the shared non-JIT AArch64 interpreter (`trames-interpreter`) and opt-in integer JIT (`trames-jit`, never linked on iPadOS).
- **Graphics & Media**: Wayland compositor services, Vulkan ICD/bridge contracts, VA-API video, and host-agnostic audio pipelines.

---

## Architecture

Trames separates **Linux OS semantics**, **instruction execution**, and **host presentation** so compatibility fixes in `trames-runtime` immediately benefit every product:

```text
┌──────────────────────────────────────────────────────────────┐
│                 Unmodified ARM64 Linux Binaries              │
└──────────────────────────────┬───────────────────────────────┘
                               │ Syscalls / Faults / Signals
┌──────────────────────────────┴───────────────────────────────┐
│                        trames-runtime                        │
│   ┌───────────────┐  ┌───────────────┐  ┌────────────────┐   │
│   │ VFS & Storage │  │ Tasks / Futex │  │ Memory / ELF   │   │
│   └───────────────┘  └───────────────┘  └────────────────┘   │
│   ┌───────────────┐  ┌───────────────┐  ┌────────────────┐   │
│   │ Userspace Net │  │ Wayland / GPU │  │ Native Accel   │   │
│   └───────────────┘  └───────────────┘  └────────────────┘   │
└──────────────────────────────┬───────────────────────────────┘
                               │ Execution Engine Contract
┌──────────────────────────────┴───────────────────────────────┐
│                 Pluggable Execution Backends                 │
│   ┌────────────────────┐ ┌────────────────┐ ┌────────────┐   │
│   │ Shared Interpreter │ │ Apple Silicon  │ │ Linux KVM  │   │
│   │  (+ Opt-in JIT)    │ │   HVF (Mac)    │ │  (Planned) │   │
│   └────────────────────┘ └────────────────┘ └────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

- [**trames-ipad**](https://github.com/project-trames/trames-ipad): Links `trames-runtime` with `trames-interpreter` (no JIT) for App Store sandbox compliance.
- [**trames-mac**](https://github.com/project-trames/trames-mac): Links `trames-runtime` with macOS `Hypervisor.framework` (HVF).

---

## Workspace Crates

| Subsystem | Crates | Responsibility |
| :--- | :--- | :--- |
| **Kernel Core** | `trames-kernel`, `trames-session`, `trames-linux` | Syscall dispatch, process/thread scheduler, signals, futexes, and Linux ABI definitions. |
| **Execution & Engines** | `trames-engine`, `trames-execution`, `trames-interpreter`, `trames-jit`, `trames-host-compute` | Engine contracts, shared non-JIT AArch64 interpreter, opt-in integer JIT, and static host compute helpers. |
| **Memory & Binaries** | `trames-memory`, `trames-elf` | Guest address spaces, region memory, reclamation, and ELF64 loader. |
| **VFS & Networking** | `trames-vfs`, `trames-net` | Virtual filesystem, persistent stores, mounts, FUSE, and userspace packet networking. |
| **Graphics & Media** | `trames-graphics`, `trames-wayland`, `trames-vulkan`, `trames-video`, `trames-audio` | Display surfaces, Wayland compositor services, Vulkan bridging, and audio/video pipelines. |
| **Acceleration** | `trames-accel`, `trames-native` | NativeCall dispatch, direct guest-memory fast paths, and native allocator/stdlib adapters. |
| **Host & Control** | `trames-host`, `trames-distro`, `trames-bridge`, `trames-control`, `trames-shared` | Host abstractions, rootfs bootstrap, control/IPC channels, and shared types. |

---

## Building and Testing

### Prerequisites
- Rust nightly toolchain (pinned in [`rust-toolchain.toml`](rust-toolchain.toml)) with `rustfmt` and `clippy`
- Python 3 and a C compiler (`clang` or `gcc`)
- **Linux**: `libasound2-dev` for audio subsystem tests
- **macOS**: Xcode Command Line Tools

### Quick Verification

```sh
# Build guest interop helper (aarch64-unknown-linux-musl)
python3 scripts/build-guest-cli.py

# Verify execution boundaries
python3 scripts/check-execution-boundaries.py

# Format, lint, and test
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

---

## Documentation

| Domain | Architecture & Validation |
| :--- | :--- |
| **Execution & Coordination** | [Execution Backends](docs/architecture/execution-backends.md) · [Coordination Boundaries](docs/architecture/coordination-boundaries.md) |
| **Tasks & Boot** | [Task State Machine](docs/architecture/task-state.md) · [Environment Boot](docs/architecture/environment-boot.md) |
| **Memory & Acceleration** | [Region Memory Model](docs/architecture/region-memory.md) · [Native Allocator](docs/architecture/native-allocator.md) |
| **Storage & Resources** | [Native Resources](docs/architecture/native-resources.md) · [Private Storage Sync](docs/architecture/private-storage-sync.md) |
| **Networking & Media** | [Packet Networking](docs/architecture/packet-networking.md) · [Display Lifecycle](docs/architecture/display-lifecycle.md) · [Audio](docs/architecture/audio.md) |
| **Validation** | [Acceptance Framework](docs/architecture/acceptance.md) · [Validation Records](docs/validation/) |

---

## Contributing & Security

- **Contributing**: See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`AGENTS.md`](AGENTS.md). Public issues and PRs are normally analyzed with AI tools—do not post secrets or personal data.
- **Security**: Report vulnerabilities privately per [`SECURITY.md`](SECURITY.md).

---

## License

Trames Runtime is licensed under the **GNU General Public License v3.0 or later** ([`LICENSE`](LICENSE)).
Third-party dependency notices and provenance are recorded in [`THIRD_PARTY_NOTICES.txt`](THIRD_PARTY_NOTICES.txt) and [`SOURCE.json`](SOURCE.json).

---

<p align="center">
  Part of <a href="https://github.com/project-trames">Project Trames</a> · A portable userspace Linux runtime with pluggable execution engines.
</p>
