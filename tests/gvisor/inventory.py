#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Record enabled/disabled original cases without changing upstream selection."""
import argparse
import json
from pathlib import Path
import subprocess

from run import digest, discover_cases, save


def inventory(binaries):
    record = json.loads((binaries.parent / 'build-record.json').read_text())
    groups, errors = [], []
    for entry in record['binaries']:
        name = entry['suite']
        binary = binaries / (name + '_test')
        try:
            if digest(binary) != entry['sha256']:
                raise ValueError('ELF hash differs from build record')
            enabled, disabled = discover_cases(binary)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            errors.append(dict(suite=name, error=str(error)))
            continue
        groups.append(dict(suite=name, sha256=entry['sha256'], enabled=enabled,
                           disabled=disabled, list_exit_code=0))
    return dict(groups=groups, enabled=sum(len(r['enabled']) for r in groups),
                disabled=sum(len(r['disabled']) for r in groups), discovery_errors=errors)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binaries', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    report = inventory(args.binaries)
    save(args.output, report)
    print('Enabled:', report['enabled'], 'Upstream disabled:', report['disabled'],
          'Discovery failures:', len(report['discovery_errors']))
    return int(bool(report['discovery_errors']))


if __name__ == '__main__':
    raise SystemExit(main())
