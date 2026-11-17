#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Measure TCP/UDP library throughput, RTT and UDP burst delivery.

CSV goes to stdout; build/progress messages go to stderr. Incomplete TCP drains
are explicitly marked in the CSV. Uses existing caches, pinned dependencies and
production release options; no guest executor or physical NIC is involved.
"""
import argparse
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('samples', nargs='?', type=int, default=3, help='samples per case (default: 3)')
parser.add_argument('seconds', nargs='?', type=float, default=0.5, help='bulk-send window per sample')
parser.add_argument('rtt_iterations', nargs='?', type=int, default=2000, help='timed echoes per RTT sample')
parser.add_argument('--filter', default='', help='optional path:protocol:test:flows case key')
parser.add_argument('--check-only', action='store_true', help='run Clippy without measurements')
args = parser.parse_args()
if args.samples < 1 or args.rtt_iterations < 1 or not math.isfinite(args.seconds) or args.seconds <= 0:
    parser.error('samples, seconds and rtt_iterations must be positive finite values')

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='trames-ethernet-bench-') as tmp:
    project = Path(tmp)
    (project / 'src').mkdir()
    (project / 'Cargo.toml').write_text(
        '[package]\nname="trames-ethernet-bench"\nversion="0.1.0"\nedition="2024"\n'
        '[dependencies]\n'
        'trames-net={path=' + json.dumps(str(root / 'crates/trames-net')) + '}\n'
        'trames-shared={path=' + json.dumps(str(root / 'crates/trames-shared')) + '}\n'
        'socket2="=0.6.1"\n'
        '[patch.crates-io]\nsmoltcp={path=' + json.dumps(str(root / 'vendor/smoltcp')) + '}\n'
        '[profile.release]\noverflow-checks=true\nlto="thin"\n'
    )
    shutil.copy2(root / 'Cargo.lock', project / 'Cargo.lock')
    shutil.copy2(root / 'tests/fixtures/ethernet-throughput.rs', project / 'src/main.rs')
    env = dict(os.environ)
    env.setdefault('CARGO_TARGET_DIR', str(root / 'target'))
    common = ['--manifest-path', str(project / 'Cargo.toml'), '--release', '--offline']
    if args.check_only or os.environ.get('TRAMES_BENCH_CLIPPY') == '1':
        subprocess.run(['cargo', 'clippy', *common, '--', '-D', 'warnings'],
                       cwd=root, env=env, check=True)
    if not args.check_only:
        subprocess.run(['cargo', 'run', *common, '--', str(args.samples), str(args.seconds),
                        str(args.rtt_iterations), args.filter], cwd=root, env=env, check=True)
