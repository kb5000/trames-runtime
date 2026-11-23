#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run selected original cases with the product interpreter in isolated stores."""
import argparse
import collections
import fnmatch
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from run import classify, digest, execute, guest_binary, guest_wrapper, save, suite_flags


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner', type=Path, required=True, help='Product interpreter CLI (trames-run)')
    parser.add_argument('--rootfs', type=Path, required=True, help='Pinned Alpine archive')
    parser.add_argument('--binaries', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True, help='Original reference plan.json')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--suites', help='Comma-separated suite selection from the reference')
    parser.add_argument('--case-filter', default='*', help='Select original GoogleTest names by glob')
    parser.add_argument('--timeout', type=float, default=30)
    parser.add_argument('--cpus', type=int, default=2)
    parser.add_argument('--test-on-gvisor', action='store_true', help='Use the original userspace-kernel ABI mode')
    parser.add_argument('--mount-fusectl', action='store_true', help='Mount fusectl for the fuse suite')
    args = parser.parse_args()
    if args.timeout <= 0 or args.cpus < 1:
        parser.error('timeout and CPU count must be positive')

    plan = json.loads(args.reference.read_text())
    requested = set(args.suites.split(',')) if args.suites else None
    if requested is not None:
        unknown = requested - {suite['name'] for suite in plan['suites']}
        if unknown:
            parser.error('suites absent from reference: ' + ', '.join(sorted(unknown)))
    suites = []
    for suite in plan['suites']:
        name = suite['name']
        if requested is not None and name not in requested:
            continue
        cases = [case for case in suite['cases'] if fnmatch.fnmatchcase(case, args.case_filter)]
        if not cases:
            continue
        if name == 'host_pty':
            parser.error('the host_pty suite requires the Mac runner with an inherited host PTY')
        binary = args.binaries / (name + '_test')
        if digest(binary) != suite['sha256']:
            parser.error(f'reference/guest binary mismatch: {name}')
        suites.append(dict(suite, cases=cases))
    if not suites:
        parser.error('no original cases selected')

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    logs = output / 'logs'
    logs.mkdir()
    binaries = args.binaries.resolve()
    runfiles = [path for path in sorted((binaries / 'runfiles').rglob('*')) if path.is_file()]
    plan.update(
        suites=suites, executor='interpreter', network='internal', process_context='pid2',
        cpus=args.cpus, timeout=args.timeout, fresh_store=True,
        writable_sysfs_fixture=any(s['name'] in ('mount', 'rename') for s in suites),
        runtime_sha256=digest(args.runner), rootfs_sha256=digest(args.rootfs),
        runfiles_sha256={str(p.relative_to(binaries)): digest(p) for p in runfiles},
    )
    if args.test_on_gvisor:
        plan['upstream_userspace_abi'] = True
    if args.mount_fusectl and any(s['name'] == 'fuse' for s in suites):
        plan['fusectl_fixture'] = True
    save(output / 'plan.json', plan)
    command = [
        str(args.runner.resolve()),
        '--network', 'off', '--virtual-network', '2', '--cpus', str(args.cpus),
        '--memory-budget', '5GiB', '--process-memory-budget', '4GiB',
        '--max-instructions', '200000000000',
    ]
    with tempfile.TemporaryDirectory(prefix='stores-', dir=output) as temporary:
        seed = Path(temporary) / 'seed'
        imports = []
        for path in runfiles:
            imports += ['--exec-file', f'/opt/gvisor/{path.relative_to(binaries)}={path}']
        for suite in suites:
            binary = suite['name'] + '_test'
            imports += ['--exec-file', f'/opt/gvisor/{binary}={binaries / binary}']
        setup = [*command, '--storage', str(seed), '--rootfs', str(args.rootfs.resolve()),
                 *imports, '--guest', '--', '/bin/true']
        code, timed, _ = execute(setup, logs / 'setup.stdout', logs / 'setup.stderr', 180)
        if code or timed:
            raise RuntimeError(f'interpreter fixture import failed, see {logs / "setup.stderr"}')

        rows = []
        for suite in suites:
            name = suite['name']
            for case in suite['cases']:
                stem = str(len(rows))
                xml = logs / (stem + '.xml')
                guest_output = '/tmp/gvisor/result.xml'
                storage = Path(temporary) / 'guest'
                if sys.platform == 'darwin':
                    subprocess.run(['/bin/cp', '-cR', str(seed), str(storage)], check=True)
                else:
                    shutil.copytree(seed, storage)
                try:
                    argv = [
                        *command, '--storage', str(storage), '--export', f'{guest_output}={xml}',
                        '--guest', '--', '/bin/sh', '-ec', guest_wrapper(
                            name, pid2=True, test_on_gvisor=args.test_on_gvisor,
                            mount_fusectl=args.mount_fusectl),
                        'trames-gvisor', '/tmp/gvisor', *guest_binary(name), *suite_flags(name),
                        '--gtest_color=no', '--gtest_filter=' + case, '--gtest_output=xml:' + guest_output,
                    ]
                    code, timed, seconds = execute(argv, logs / (stem + '.stdout'),
                                                   logs / (stem + '.stderr'), args.timeout)
                finally:
                    shutil.rmtree(storage)
                status, messages = classify(xml, code, timed, case)
                rows.append(dict(suite=name, case=case, status=status, code=code,
                                 seconds=seconds, messages=messages, log_stem=stem))
                save(output / 'results.json', rows)
                print(f'interpreter {len(rows)}: {case}: {status}', flush=True)
    counts = dict(collections.Counter(row['status'] for row in rows))
    save(output / 'summary.json', dict(platform='interpreter', cases=len(rows), counts=counts))
    print(json.dumps(counts), flush=True)
    return int(any(status not in ('passed', 'skipped') for status in counts))


if __name__ == '__main__':
    raise SystemExit(main())
