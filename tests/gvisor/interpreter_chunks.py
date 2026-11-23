# SPDX-License-Identifier: GPL-3.0-or-later
"""Original interpreter GTest chunks with cold stores and audited XML results."""
import shutil
import subprocess
import sys

from chunks import Progress, xml_rows
from run import TRACEE_WAIT, SINGLE_CASE_SUITES, classify, execute, guest_binary, guest_terminal, guest_wrapper, save, suite_flags, watchdog


def run(args, output, suites, command, seed):
    rows = []
    serial = 0
    single = set(SINGLE_CASE_SUITES)
    disk_stopped = False

    def checkpoint():
        save(output / 'results.json', rows)

    def record(suite, selected, status, stem, code, seconds, messages=None):
        rows.extend(dict(suite=suite, case=case, status=status, code=code, seconds=seconds,
                         messages=messages or [], log_stem=stem) for case in selected)
        checkpoint()

    def attempt(suite, selected):
        nonlocal serial, disk_stopped
        if not selected:
            return
        if disk_stopped:
            record(suite, selected, 'not_run_disk_limit', None, None, 0)
            return
        if len(selected) > 1 and TRACEE_WAIT in selected:
            at = selected.index(TRACEE_WAIT)
            attempt(suite, selected[:at])
            attempt(suite, [TRACEE_WAIT])
            attempt(suite, selected[at + 1:])
            return
        if suite in single and len(selected) > 1:
            for case in selected:
                attempt(suite, [case])
            return
        stem = 'chunk-%06d' % serial
        serial += 1
        storage = seed.parent / 'guest'
        if sys.platform == 'darwin':
            subprocess.run(['/bin/cp', '-cR', str(seed), str(storage)], check=True)
        else:
            shutil.copytree(seed, storage)
        work = '/tmp/gvisor-' + stem
        guest_xml = work + '/result.xml'
        xml = output / 'logs' / (stem + '.xml')
        stdout = xml.with_suffix('.stdout')
        stderr = xml.with_suffix('.stderr')
        terminal, wrapper = guest_terminal(suite, guest_wrapper(
            suite, pid2=True, test_on_gvisor=args.test_on_gvisor, mount_fusectl=args.mount_fusectl))
        argv = [*command, *(['--pty'] if terminal == '--pty' else []), '--storage', str(storage),
                '--export', f'{guest_xml}={xml}', '--guest', '--', '/bin/sh', '-ec', wrapper,
                'trames-gvisor', work, *guest_binary(suite), *suite_flags(suite), '--gtest_color=no',
                '--gtest_filter=' + ':'.join(selected), '--gtest_output=xml:' + guest_xml]
        timeout = lambda case: watchdog(args, suite, case) if case else 30
        progress = Progress(stdout, selected, timeout)
        try:
            code, timed, seconds = execute(
                argv, stdout, stderr, 30 + sum(timeout(case) for case in selected), progress=progress,
                min_free=int(args.min_free_gib * 1024**3))
        finally:
            shutil.rmtree(storage)
        progress.remaining()
        parsed = xml_rows(xml, code, selected, stderr) if not timed else None
        if parsed is not None:
            rows.extend(dict(row, suite=suite, code=code, log_stem=stem, process_seconds=seconds,
                             chunk_cases=len(selected)) for row in parsed)
            checkpoint()
            print('interpreter', len(rows), suite, 'chunk', len(selected),
                  {row['status'] for row in parsed}, flush=True)
            return
        if timed == 'disk_limit':
            disk_stopped = True
            record(suite, selected, 'disk_limit', stem, code, seconds)
            return
        if len(selected) == 1:
            status, messages = classify(xml, code, timed, selected[0])
            record(suite, selected, status, stem, code, seconds, messages)
            print('interpreter', len(rows), suite, selected[0], status, flush=True)
            return
        completed = [case for case in selected if case in progress.completed]
        active = progress.active if progress.active in selected and progress.active not in completed else None
        if not completed and active == selected[0]:
            single.add(suite)
        if completed and len(completed) < len(selected):
            attempt(suite, completed)
            if active:
                attempt(suite, [active])
            attempt(suite, [case for case in selected if case not in completed and case != active])
        elif active:
            attempt(suite, [active])
            attempt(suite, [case for case in selected if case != active])
        else:
            middle = len(selected) // 2
            attempt(suite, selected[:middle])
            attempt(suite, selected[middle:])

    for suite in suites:
        selected = suite['cases']
        for start in range(0, len(selected), args.chunk_size):
            attempt(suite['name'], selected[start:start + args.chunk_size])
    return rows
