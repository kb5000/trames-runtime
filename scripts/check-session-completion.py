#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep terminal lifecycle completion out of the legacy guest-dispatch protocol."""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
source = root / 'crates/trames-session/src'
# The remaining compatibility class is an explicit debt ceiling. Adding an
# implicit owner return, even in a new subsystem, must fail the architecture gate.
allowed = {'execution_control.rs': 1, 'workers.rs': 3, 'run_queue.rs': 4, 'process.rs': 1}
found = {}
for path in source.rglob('*.rs'):
    if path.name.startswith('.') or path.name.endswith('_tests.rs'):
        continue
    text = path.read_text().split('\n#[cfg(all(test, trames_interpreter_conformance))]\nmod tests {')[0]
    text = re.sub(r'#\[cfg\(all\(test, trames_interpreter_conformance\)\)\]\s*pub\(crate\) fn stop\(&self\)\s*\{[^}]*\}', '', text)
    count = len(re.findall(r'\.handoff\(\)', text))
    if count:
        found[path.name] = count
assert found == allowed, ('legacy handoff boundary changed; migrate the authority instead', found)
control = (source / 'execution_control.rs').read_text()
assert 'phase < CLOSING' in control and 'phase.store(' not in control
completion = (source / 'process_lifecycle_completion.rs').read_text()
assert not re.search(r'\b(Kernel|GuestOutput|SliceOutcome::Syscall)\b|finish_slice|\.handoff\(', completion)
workers = (source / 'workers.rs').read_text()
assert re.search(r'Complete\(Arc<crate::run_queue::Epoch<C>>,\s*mpsc::Sender<\(\)>\)', workers)
process = (source / 'process.rs').read_text()
closed = process.split('        if control.closing() {', 1)[1].split('        if let Some(error) = epoch.collect_lifecycle', 1)[0]
assert not re.search(r'finish_slice|restore_worker_return|adopt_worker_return|process_exits|cancel_host_io_requests|\.drain\(', closed)
print('Session completion verified: source cleanup, payload-free host reply, no new legacy handoffs')
