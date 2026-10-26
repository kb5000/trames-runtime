#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject interpreter or platform dependencies in the common Linux runtime."""
import json
import subprocess

metadata = json.loads(subprocess.check_output(
    ['cargo', 'metadata', '--format-version', '1', '--locked'], text=True))
names = {p['id']: p['name'] for p in metadata['packages']}
nodes = {n['id']: n for n in metadata['resolve']['nodes']}
ids = {p['name']: p['id'] for p in metadata['packages'] if p['name'].startswith('trames-')}

def closure(name):
    pending, found = [ids[name]], set()
    while pending:
        identity = pending.pop()
        if identity in found:
            continue
        found.add(identity)
        pending.extend(d['pkg'] for d in nodes[identity]['deps']
                       if any(k['kind'] is None for k in d['dep_kinds']))
    return {names[i] for i in found}

for name in ['trames-kernel', 'trames-linux', 'trames-memory', 'trames-elf', 'trames-distro', 'trames-engine', 'trames-session', 'trames-hvf', 'trames-mac']:
    if name not in ids:
        continue
    forbidden = closure(name) & {'trames-cpu', 'trames-compute', 'trames-core', 'trames-ffi'}
    assert not forbidden, (name, 'depends on the interpreter/product:', sorted(forbidden))
assert closure('trames-execution') == {'trames-execution'}
for name in ['trames-kernel', 'trames-linux', 'trames-memory', 'trames-elf', 'trames-distro', 'trames-engine', 'trames-session']:
    assert not closure(name) & {'trames-hvf', 'trames-mac'}, (name, 'depends on a hardware/product transport')
members = {names[i] for i in metadata['workspace_members']}
common = {'trames-engine', 'trames-session', 'trames-native', 'trames-accel', 'trames-vulkan', 'trames-execution', 'trames-kernel', 'trames-memory', 'trames-elf', 'trames-linux', 'trames-vfs', 'trames-net', 'trames-distro', 'trames-bridge', 'trames-shared', 'trames-wayland'}
if 'trames-core' in members:
    assert not members & common
    assert {'trames-cpu', 'trames-linux', 'trames-execution', 'trames-kernel'} <= closure('trames-core')
    assert 'trames-session' in closure('trames-core')
    assert not closure('trames-core') & {'trames-hvf', 'trames-mac'}
elif 'trames-mac' in members:
    assert members == {'trames-hvf', 'trames-mac'}
    assert {'trames-hvf', 'trames-linux', 'trames-kernel'} <= closure('trames-mac')
else:
    assert members == common, members
print('Project boundaries verified: standalone common runtime, iPad interpreter composition, Mac hardware composition')
