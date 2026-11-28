# Contributing to Trames Runtime

Thank you for contributing to **`trames-runtime`**—the shared userspace Linux kernel for Project Trames.

---

## Scope

All shared Linux OS semantics (syscalls, VFS, networking, memory, tasks/signals/futexes, Wayland/Vulkan/media services, and the shared interpreter) belong in this repository so fixes automatically benefit `trames-ipad`, `trames-mac`, and future platforms.

Keep platform-specific Apple/Linux code behind existing `#[cfg(...)]` boundaries and verify both Linux and Apple host builds whenever touching platform paths. See [`AGENTS.md`](AGENTS.md) for the project's core engineering principles.

---

## Verification

Before opening a pull request against `main`, run the checks covering your changes:

```sh
python3 scripts/check-execution-boundaries.py
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

After merging to `main`, consuming product repositories (`trames-ipad`, `trames-mac`) explicitly update their `runtime/` submodule pin and `runtime-version.json`.

---

## AI-Assisted Workflow Disclosure

Trames is an AI-driven open-source project. Unless explicitly stated otherwise, public GitHub issues, pull requests, and discussions are normally analyzed with external AI tools. **Do not post passwords, private keys, or personal data in public threads.** Public submission does not transfer copyright or grant model-training permission.

---

## Licensing

Contributions are licensed under **GNU General Public License v3.0 or later** ([`LICENSE`](LICENSE)). Ensure any new third-party dependency is license-compatible and documented in `third-party/` and `THIRD_PARTY_NOTICES.txt`.
