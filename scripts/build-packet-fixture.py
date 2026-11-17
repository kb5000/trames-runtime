#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build the standalone Linux packet/TUN ABI fixture with the pinned Rust musl target."""
import pathlib
import subprocess
import sys
root = pathlib.Path(__file__).resolve().parents[1]
output = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else root / 'target/packet-tun/packet-tun'
sysroot = pathlib.Path(subprocess.check_output(['rustc', '--print', 'sysroot'], cwd=root, text=True).strip())
host = next(line[6:] for line in subprocess.check_output(['rustc', '-vV'], cwd=root, text=True).splitlines() if line.startswith('host: '))
linker = sysroot / 'lib/rustlib' / host / 'bin/rust-lld'
output.parent.mkdir(parents=True, exist_ok=True)
subprocess.run(['rustc', '--edition=2024', '--target=aarch64-unknown-linux-musl', '-C', f'linker={linker}', '-C', 'link-self-contained=yes', '-C', 'target-feature=+crt-static', '-C', 'opt-level=1', str(root / 'tests/fixtures/packet-tun.rs'), '-o', str(output)], cwd=root, check=True)
print(output)
