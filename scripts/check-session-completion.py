#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep terminal lifecycle completion out of the legacy guest-dispatch protocol."""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
source = root / 'crates/trames-session/src'
import runpy
production = runpy.run_path(str(Path(__file__).with_name('production-source.py')))['production']

# Production admission is one-way: there is no provider or generic handoff.
for path in source.rglob('*.rs'):
    if path.name.startswith('.') or path.name.endswith('_tests.rs'):
        continue
    text = production(path.read_text())
    assert not re.search(r'\.(?:handoff|missing_capability)\(|\bMissing\b', text), path
control = production((source / 'execution_control.rs').read_text())
assert not re.search(r'fn (?:suspend|handoff|missing_capability)\b|\bHANDOFF\b', control)
queue = production((source / 'run_queue.rs').read_text())
assert 'self.control.closing()' in queue.split('pub fn join(&self)', 1)[1].split('fn test_handoff', 1)[0]
cold = production((source / 'process_lifecycle_dispatch.rs').read_text())
assert 'crate::syscall_dispatch::execute(' in cold and '&mut p.memory' in cold
assert 'progress_original(' in cold and 'start_original_poll(' in cold and 'start_original_byte(' in cold
assert not re.search(r'Kernel::new|Kernel\s*\{|processes\.clone|GuestOutput', cold)
for path in (root / 'crates/trames-linux/src').rglob('*.rs'):
    if path.name.startswith('.'):
        continue
    assert not re.search(r'fn (?:require_owner|owner_required|uring_requires_owner(?:_for)?)\b', path.read_text()), path
linux = (root / 'crates/trames-linux/src/lib.rs').read_text()
assert not re.search(r'fn host_memory\(', linux)
workers = production((source / 'workers.rs').read_text())
assert 'crate::syscall_dispatch::execute(' in workers
process = production((source / 'process.rs').read_text())
assert 'source execution cannot return guest work to the host' in process
mode = process.split('enum ExecutionMode {', 1)[1].split('}', 1)[0]
assert mode.strip() == 'Source,'
drive = process.split('    fn drive(', 1)[1].split('\n}\n', 1)[0]
assert not re.search(r'finish_slice|self\.call\(|State::Blocked|State::Sleep', drive)

control = (source / 'execution_control.rs').read_text()
assert 'phase < CLOSING' in control and 'phase.store(' not in control
completion = (source / 'process_lifecycle_completion.rs').read_text()
assert not re.search(r'\b(Kernel|GuestOutput|SliceOutcome::Syscall)\b|finish_slice|\.handoff\(', completion)
workers = (source / 'workers.rs').read_text()
assert re.search(r'Complete\(Arc<crate::run_queue::Epoch<C>>,\s*mpsc::Sender<\(\)>\)', workers)
process = (source / 'process.rs').read_text()
closed = production(process).split('        if control.closing() {', 1)[1]
assert not re.search(r'finish_slice|restore_worker_return|adopt_worker_return|process_exits|cancel_host_io_requests|\.drain\(', closed)
print('Session completion verified: source-only completion, original providers, zero production suspension routes')

# A release host cannot consume or dispatch a guest checkpoint at all.
assert not re.search(r'fn (?:vm_checkpoint|parallel_timeout(?:_for)?|call|call_with|finish_slice|pump_guest_ptys)\b', production(process))
for name in ('process_vm.rs', 'process_exit.rs', 'process_proc.rs', 'process_host.rs', 'futex.rs'):
    body = production((source / name).read_text())
    assert not re.search(r'\.unpark\(|Event(?:::[^:]+)?::(?:VmReady|Retired|Idle)', body), name
body = production((source / 'workers.rs').read_text())
events = body.split('enum Event<C: Cpu> {', 1)[1].split('}', 1)[0]
assert not re.search(r'\b(?:VmReady|Retired|Idle)\b', events)
linux = (root / 'crates/trames-linux/src/lib.rs').read_text()
assert 'control_poll_interval' not in linux
host = production((source / 'process_vm.rs').read_text()).split('fn wait_source(', 1)[1].split('fn cohort_live_control(', 1)[0]
assert 'wait.wait()' in host
assert not re.search(r'event_timeout|processes|vm_checkpoint|parallel_timeout|finish_slice', host)
print('Host wait verified: native events, no release checkpoint receiver, task scans or periodic control timer')
