# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate the composed idmapped-layer OCI acceptance configuration."""
import argparse
import json
from pathlib import Path
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('output', type=Path)
a = p.parse_args()
x = {
    'ociVersion': '1.2.1',
    'process': {
        'terminal': False,
        'user': {'uid': 100000, 'gid': 200000},
        'args': ['/bin/sh', '-ec', 'test "$(stat -c %u:%g /etc/hostname)" = 100000:200000; echo modern-overlay > /etc/hostname; touch /tmp/overlay-created; test "$(stat -c %u:%g /tmp/overlay-created)" = 100000:200000'],
        'env': ['PATH=/bin:/usr/bin:/sbin:/usr/sbin'],
        'cwd': '/',
        'noNewPrivileges': True,
        'capabilities': {'bounding': [], 'effective': [], 'permitted': []},
    },
    'root': {'path': 'rootfs', 'readonly': False},
    'hostname': 'modern-overlay',
    'linux': {'namespaces': [{'type': n} for n in ['pid', 'mount', 'uts', 'ipc']]},
    'mounts': [
        {'destination': '/proc', 'type': 'proc', 'source': 'proc', 'options': ['nosuid', 'noexec', 'nodev']},
        {'destination': '/dev', 'type': 'tmpfs', 'source': 'tmpfs', 'options': ['nosuid', 'mode=755']},
        {'destination': '/dev/pts', 'type': 'devpts', 'source': 'devpts', 'options': ['nosuid', 'noexec', 'newinstance', 'ptmxmode=0666', 'mode=0620', 'gid=5']},
    ],
}
a.output.parent.mkdir(parents=True, exist_ok=True)
a.output.write_text(json.dumps(x, indent=2) + '\n')
