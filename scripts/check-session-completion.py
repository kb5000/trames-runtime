#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep terminal lifecycle completion out of the legacy guest-dispatch protocol."""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
source = root / 'crates/trames-session/src'
def production(text):
    """Remove the bounded interpreter fixtures, including cfg-only statements."""
    text = text.split('\n#[cfg(all(test, trames_interpreter_conformance))]\nmod tests {')[0]
    marker = re.compile(r'#\[cfg\(all\(test, trames_interpreter_conformance\)\)\]\s*')
    while match := marker.search(text):
        start = match.end()
        if re.match(r'(?:pub(?:\([^)]*\))?\s+)?fn\s', text[start:]):
            end = text.index('{', start) + 1
            depth = 1
            while depth:
                depth += (text[end] == '{') - (text[end] == '}')
                end += 1
        else:
            end = text.index(';', start) + 1
        text = text[:match.start()] + text[end:]
    return text

# There is no generic production guest-dispatch handoff. A missing embedding
# capability is attached to its accepted original operation before suspension.
for path in source.rglob('*.rs'):
    if path.name.startswith('.') or path.name.endswith('_tests.rs'):
        continue
    text = production(path.read_text())
    assert not re.search(r'\.handoff\(\)', text), path
control = production((source / 'execution_control.rs').read_text())
assert len(re.findall(r'\.suspend\(\)', control)) == 1
assert re.search(r'fn missing_capability\(&self, _: .*::Missing\)\s*\{\s*self.suspend\(\);', control)
queue = production((source / 'run_queue.rs').read_text())
assert 'done.missing = Some(missing)' in queue
assert 'self.control.missing_capability(missing)' in queue
assert 'self.control.stopped()' in queue.split('pub fn join(&self)', 1)[1].split('fn test_handoff', 1)[0]
cold = production((source / 'process_lifecycle_dispatch.rs').read_text())
assert 'crate::syscall_dispatch::execute(' in cold and '&mut p.memory' in cold
assert not re.search(r'Kernel::new|Kernel\s*\{|processes\.clone|GuestOutput', cold)
assert 'Missing::HostStatistics' in cold
workers = production((source / 'workers.rs').read_text())
assert 'crate::syscall_dispatch::execute(' in workers
process = production((source / 'process.rs').read_text())
assert 'missing.is_none()' in process and '.pending_cpu = Some(outcome)' in process
control = (source / 'execution_control.rs').read_text()
assert 'phase < CLOSING' in control and 'phase.store(' not in control
completion = (source / 'process_lifecycle_completion.rs').read_text()
assert not re.search(r'\b(Kernel|GuestOutput|SliceOutcome::Syscall)\b|finish_slice|\.handoff\(', completion)
workers = (source / 'workers.rs').read_text()
assert re.search(r'Complete\(Arc<crate::run_queue::Epoch<C>>,\s*mpsc::Sender<\(\)>\)', workers)
process = (source / 'process.rs').read_text()
closed = process.split('        if control.closing() {', 1)[1].split('        if let Some(error) = epoch.collect_lifecycle', 1)[0]
assert not re.search(r'finish_slice|restore_worker_return|adopt_worker_return|process_exits|cancel_host_io_requests|\.drain\(', closed)
print('Session completion verified: source dispatch, explicit missing resources, no generic production handoff')
