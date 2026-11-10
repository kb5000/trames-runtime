#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host embedding may initialize once, observe, submit original work or cancel.

It cannot request a cohort join or execute guest CPUs on the waiting thread.
"""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
session = root / 'crates/trames-session/src'
linux = (root / 'crates/trames-linux/src/lib.rs').read_text()
host = linux.split('pub trait GuestOutput {', 1)[1].split('pub mod execution_io {', 1)[0]
live = linux.split('pub trait Output {', 1)[1].split('#[derive(Default)]', 1)[0]
assert len(re.findall(r'fn initialize\(', host)) == 1
assert not re.search(r'fn initialize\(|&mut trames_vfs::Vfs', live)
for text in (host, live):
    text = re.sub(r'//[^\n]*', '', text)
    assert not re.search(r'\b(?:poll_control|control|live_host_processes)\b', text)

bootstrap = (session / 'lib.rs').read_text().split('\n#[cfg(all(test, trames_interpreter_conformance))]\nmod tests {')[0]
assert len(re.findall(r'\.initialize\(', bootstrap)) == 1
assert bootstrap.index('.initialize(') < bootstrap.index('let workers = workers::Pool')
process = (session / 'process.rs').read_text().split('\n#[cfg(all(test, trames_interpreter_conformance))]\nmod tests {')[0]
assert 'execution_io::Output as GuestOutput' in process
assert not re.search(r'\.cpu\s*\.run\w*\(|run_coordinated|serial_quantum|C::PARALLEL', process)
for path in session.glob('process*.rs'):
    if path.name.startswith('.') or path.name.endswith('_tests.rs'):
        continue
    text = path.read_text().split('\n#[cfg(all(test, trames_interpreter_conformance))]\nmod tests {')[0]
    assert not re.search(r'\.initialize\(|trames_linux::GuestOutput|\.poll_control\(|io\.control\(', text), path
    if not path.name.startswith('process_lifecycle'):
        assert not re.search(r'\.cpu\s*\.run\w*\(|kernel\.engine|self\.engine', text), path
assert not re.search(r'\bPARALLEL\b|run_coordinated', (root / 'crates/trames-engine/src/lib.rs').read_text())
print('Host execution verified: one bootstrap, live-only execution interface, no host CPU loop or stopped callback')
