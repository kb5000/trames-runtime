#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare host BSD, Trames native and internal Ethernet UDP library paths.

Uses cached dependencies and one existing target directory. Output is CSV;
Cargo diagnostics stay on stderr. This measures library calls, not guest CPU
execution or the throughput of a physical network.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='trames-ethernet-bench-') as tmp:
    project = Path(tmp)
    (project / 'src').mkdir()
    (project / 'Cargo.toml').write_text(
        '[package]\nname="trames-ethernet-bench"\nversion="0.1.0"\nedition="2024"\n'
        '[dependencies]\ntrames-net={path=' + json.dumps(str(root / 'crates/trames-net')) + '}\n'
    )
    shutil.copy2(root / 'tests/fixtures/ethernet-throughput.rs', project / 'src/main.rs')
    env = dict(os.environ)
    env.setdefault('CARGO_TARGET_DIR', str(root / 'target'))
    subprocess.run(['cargo', 'run', '--manifest-path', str(project / 'Cargo.toml'),
                    '--release', '--offline'], cwd=root, env=env, check=True)
