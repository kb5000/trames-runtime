#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Record a successful build with exact source, configuration and binary bytes."""
import argparse
import os
from pathlib import Path
import subprocess
from common import digest, identity, save, source_identity


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--product', type=Path, required=True)
    p.add_argument('--runtime', type=Path, required=True)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--receipt', type=Path, required=True)
    p.add_argument('command', nargs=argparse.REMAINDER)
    a = p.parse_args()
    command = a.command[1:] if a.command[:1] == ['--'] else a.command
    if not command:
        p.error('a build argv is required after --')
    before = {name: source_identity(path) for name, path in [('product', a.product), ('runtime', a.runtime)]}
    toolchain = subprocess.check_output(['rustc', '-vV'], cwd=a.product, text=True)
    flags = {k: v for k, v in os.environ.items() if k in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CC', 'CXX', 'TRAMES_VULKAN_LINKAGE') or k.startswith('CARGO_PROFILE_') or k=='CARGO_INCREMENTAL' or k.startswith('CARGO_TARGET_') and k.endswith('_LINKER')}
    subprocess.run(command, cwd=a.product, check=True)
    after = {name: source_identity(path) for name, path in [('product', a.product), ('runtime', a.runtime)]}
    if before != after:
        raise RuntimeError('source changed during build; no receipt issued')
    fingerprint = dict(sources={k: v['inputs_sha256'] for k, v in before.items()}, command=command,
                       toolchain=toolchain, flags=flags, binary_sha256=digest(a.binary))
    a.receipt.parent.mkdir(parents=True, exist_ok=True)
    save(a.receipt, dict(schema_version=1, sources=before, fingerprint=fingerprint, fingerprint_sha256=identity(fingerprint)))


if __name__ == '__main__':
    main()
