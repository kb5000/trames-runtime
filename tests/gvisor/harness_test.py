# SPDX-License-Identifier: GPL-3.0-or-later
"""Guard against false passes and lost cases in the external test harness."""
import argparse
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import subprocess

from inventory import inventory
from run import digest
from batch import case_keys, missing_cases, partition
from chunks import Progress, xml_rows
from run import classify, execute, guest_terminal, reuse_rows, watchdog


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def xml(self, body):
        path=self.root/'result.xml';path.write_text('<testsuites><testsuite>'+body+'</testsuite></testsuites>');return path
    def test_watchdog_allows_intentional_wait_and_preserves_suite_override(self):
        args = argparse.Namespace(timeout=20, suite_timeouts={})
        self.assertEqual(watchdog(args, 'ppoll', 'PpollTest.SignalMaskBlocksSignal'), 45)
        self.assertEqual(watchdog(args, 'ppoll', 'PpollTest.SignalMaskAllowsSignal'), 20)
        self.assertEqual(watchdog(args, 'vfork', 'VforkTest.ParentStopsUntilChildExecves'), 40)
        self.assertEqual(watchdog(args, 'flock', 'FlockTest.BlockingLockNoBlockingForSharedLocks'), 45)
        self.assertEqual(watchdog(args, 'flock', 'FlockTest.Basic'), 20)
        self.assertEqual(watchdog(args, 'inotify', 'Inotify.EpollNoDeadlock'), 60)
        self.assertEqual(watchdog(args, 'inotify', 'Inotify.Basic'), 20)
        self.assertEqual(watchdog(args, 'sigstop', 'SigstopTest.Correctness'), 45)
        self.assertEqual(watchdog(args, 'itimer', 'ItimerTest.DeliversSIGPROFToThreadsRoughlyFairlyIdle'), 220)
        args.timeout = 7
        self.assertEqual(watchdog(args, 'vfork', 'VforkTest.ExecedChildExitDoesntUnstopParent'), 30)
        self.assertEqual(watchdog(args, 'vfork', 'VforkTest.ParentStopsUntilChildExits'), 20)
        self.assertEqual(watchdog(args, 'vfork', 'VforkTest.SigchldReceivedDuringVforkIsDelivered'), 20)
        args.suite_timeouts['ppoll'] = 15
        self.assertEqual(watchdog(args, 'ppoll', 'PpollTest.SignalMaskBlocksSignal'), 15)
        args.suite_timeouts['inotify'] = 12
        self.assertEqual(watchdog(args, 'inotify', 'Inotify.EpollNoDeadlock'), 12)
    def test_mixed_results_need_matching_xml_and_exit(self):
        path=self.xml('<testcase classname="T" name="Pass" time="0.01"/><testcase classname="T" name="Fail"><failure message="original assertion"/></testcase><testcase classname="T" name="Skip"><skipped message="upstream gate"/></testcase>')
        rows=xml_rows(path,1,['T.Pass','T.Fail','T.Skip'])
        self.assertEqual([r['status'] for r in rows],['passed','failed','skipped'])
        self.assertIsNone(xml_rows(path,0,['T.Pass','T.Fail','T.Skip']))
        self.assertIsNone(xml_rows(path,134,['T.Pass','T.Fail','T.Skip']))
    def test_partial_duplicate_and_wrong_case_xml_never_pass(self):
        path=self.xml('<testcase classname="T" name="Pass"/>')
        self.assertIsNone(xml_rows(path,0,['T.Pass','T.Missing']))
        self.assertIsNone(xml_rows(path,0,['T.Other']))
        path=self.xml('<testcase classname="T" name="Pass"/><testcase classname="T" name="Pass"/>')
        self.assertIsNone(xml_rows(path,0,['T.Pass','T.Pass']))
    def test_tracee_child_setup_failure_overrides_parent_xml(self):
        path = self.xml('<testcase classname="WaitTest" name="TraceeWALL"/>')
        stderr = path.with_suffix('.stderr')
        stderr.write_text('Check failed: ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == 0 (errno 38)\n')
        self.assertEqual(xml_rows(path, 0, ['WaitTest.TraceeWALL'], stderr)[0]['status'], 'fixture_failed')
        self.assertEqual(classify(path, 0, False, 'WaitTest.TraceeWALL')[0], 'fixture_failed')
        stderr.write_text('')
        self.assertEqual(xml_rows(path, 0, ['WaitTest.TraceeWALL'], stderr)[0]['status'], 'passed')

    def test_host_pty_is_inherited_and_other_suites_keep_piped_stdio(self):
        out, err = self.root/'stdout', self.root/'stderr'
        probe = 'import os; assert os.isatty(int(os.environ["TEST_HOST_PTY_FD"]))'
        code, timed, _ = execute([sys.executable, '-c', probe], out, err, 5, host_pty=True)
        self.assertFalse(timed)
        self.assertEqual(code, 0, err.read_text())
        self.assertEqual(guest_terminal('pty', 'command'), ('--no-pty', 'command'))
        self.assertEqual(guest_terminal('host_pty', 'command')[0], '--pty')

    def test_itimer_child_fairness_failure_overrides_only_its_own_xml_case(self):
        case = 'ItimerTest.DeliversSIGALRMToMainThread'
        body = '<testcase classname="ItimerTest" name="DeliversSIGALRMToMainThread"/>'
        path = self.xml(body)
        stderr = path.with_suffix('.stderr')
        stderr.write_text('Check failed: num <= worker_threshold: worker received too many samples\n')
        self.assertEqual(classify(path, 0, False, case)[0], 'failed')
        path = self.xml(body + '<testcase classname="T" name="Other"/>')
        rows = xml_rows(path, 0, [case, 'T.Other'], stderr)
        self.assertEqual([row['status'] for row in rows], ['failed', 'passed'])

    def test_global_fixture_failure_never_becomes_a_passing_skip(self):
        path=self.xml('<testcase classname="T" name="A"><skipped/></testcase><testcase classname="" name=""><failure message="missing prerequisite"/></testcase>')
        rows=xml_rows(path,1,['T.A'])
        self.assertEqual(rows[0]['status'],'fixture_failed')
        self.assertEqual(classify(path,1,False,'T.A')[0],'fixture_failed')
    def test_failure_wins_over_skip_in_the_same_case(self):
        path=self.xml('<testcase classname="T" name="A"><skipped/><failure message="teardown assertion"/></testcase>')
        self.assertEqual(classify(path,1,False,'T.A')[0],'failed')
        self.assertEqual(xml_rows(path,1,['T.A'])[0]['status'],'failed')
    def test_missing_identity_is_not_a_success(self):
        path=self.xml('<testcase/>')
        self.assertIsNone(xml_rows(path,0,['T.A']))
        self.assertEqual(classify(path,0,False,'T.A')[0],'mismatched_result')
    def test_stdout_is_not_evidence_of_success(self):
        path=self.root/'stdout';path.write_text('[ RUN      ] T.Pass\n[       OK ] T.Pass (1 ms)\n')
        progress=Progress(path,['T.Pass'],lambda _:5);progress.remaining()
        self.assertEqual(progress.completed,{'T.Pass'})
        self.assertIsNone(xml_rows(self.root/'missing.xml',0,['T.Pass']))
        self.assertEqual(classify(self.root/'missing.xml',0,False,'T.Pass')[0],'no_result')
    def test_interpreter_retries_abnormal_chunks_and_keeps_the_exact_case_set(self):
        from interpreter_chunks import run
        seed = self.root / 'seed'
        seed.mkdir()
        output = self.root / 'output'
        (output / 'logs').mkdir(parents=True)
        calls = []
        def execute_chunk(argv, stdout, stderr, *args, **kwargs):
            selected = next(arg.split('=', 1)[1].split(':') for arg in argv if arg.startswith('--gtest_filter='))
            calls.append(selected)
            stdout.write_text('[ RUN      ] ' + selected[0] + '\n')
            stderr.write_text('')
            xml = Path(argv[argv.index('--export') + 1].split('=', 1)[1])
            xml.write_text('<testsuites><testsuite>' + ''.join(
                '<testcase classname="T" name="' + case.split('.', 1)[1] + '"/>'
                for case in selected) + '</testsuite></testsuites>')
            return (134 if len(selected) > 1 else 0), False, 0.1
        args = argparse.Namespace(timeout=5, suite_timeouts={}, min_free_gib=0, chunk_size=50,
                                  test_on_gvisor=False, mount_fusectl=False)
        with patch('interpreter_chunks.execute', side_effect=execute_chunk):
            rows = run(args, output, [dict(name='example', cases=['T.A', 'T.B'])], ['runner'], seed)
        self.assertEqual(calls, [['T.A', 'T.B'], ['T.A'], ['T.B']])
        self.assertEqual([(row['case'], row['status']) for row in rows], [('T.A', 'passed'), ('T.B', 'passed')])
        self.assertTrue(all(row['code'] == 0 and row['chunk_cases'] == 1 for row in rows))
        calls.clear()
        with patch('interpreter_chunks.execute', side_effect=execute_chunk):
            rows = run(args, output, [dict(name='socket_stress', cases=['T.A', 'T.B'])], ['runner'], seed)
        self.assertEqual(calls, [['T.A'], ['T.B']], 'port-exhaustion cases must start isolated')
        self.assertEqual([row['status'] for row in rows], ['passed', 'passed'])
    def test_child_noise_does_not_extend_the_active_case(self):
        path=self.root/'stdout';path.write_text('[ RUN      ] T.Parent\n')
        progress=Progress(path,['T.Parent'],lambda _:5);progress.remaining();since=progress.since
        with path.open('a') as stream:stream.write('[ RUN      ] Child.Other\n[       OK ] Child.Other (1 ms)\n')
        progress.remaining();self.assertEqual(progress.active,'T.Parent');self.assertEqual(progress.since,since)
    def test_discovery_keeps_disabled_cases_and_reports_missing_modified_or_failed_suites(self):
        binaries = self.root / 'bin'
        binaries.mkdir()
        entries = []
        for name in ('ok', 'disabled', 'exit', 'duplicate', 'modified', 'missing'):
            binary = binaries / (name + '_test')
            binary.write_bytes(name.encode())
            entries.append(dict(suite=name, sha256=digest(binary)))
        (binaries/'missing_test').unlink()
        (binaries/'modified_test').write_bytes(b'different build')
        (self.root/'build-record.json').write_text(json.dumps(dict(binaries=entries)))
        def listing(argv, **kwargs):
            suite = Path(argv[0]).stem
            if suite == 'exit_test':
                raise subprocess.CalledProcessError(1, argv, output='T.\n  Partial\n')
            stdout = {'ok_test':'T.\n  A/0  # parameter\n  DISABLED_B\n',
                      'disabled_test':'DISABLED_T.\n  B\n',
                      'duplicate_test':'T.\n  A\n  A\n'}[suite]
            return subprocess.CompletedProcess(argv, 0, stdout=stdout)
        with patch('run.subprocess.run', side_effect=listing):
            result = inventory(binaries)
        self.assertEqual((result['enabled'], result['disabled']), (1, 2))
        self.assertEqual(result['groups'][0]['enabled'], ['T.A/0'])
        self.assertEqual({r['suite'] for r in result['discovery_errors']},
                         {'exit', 'duplicate', 'modified', 'missing'})

    def test_batch_rejects_duplicate_requests_and_unexpected_worker_results(self):
        with self.assertRaises(ValueError):
            case_keys([dict(name='a', cases=['T.A', 'T.A'])])
        expected = {('a', 'T.A'), ('a', 'T.B')}
        row = dict(suite='a', case='T.A')
        self.assertEqual(missing_cases(expected, [row]), [('a', 'T.B')])
        with self.assertRaises(ValueError):
            missing_cases(expected, [row, row])
        with self.assertRaises(ValueError):
            missing_cases(expected, [dict(suite='a', case='T.C')])

    def test_partition_is_complete_without_duplicates(self):
        suites=[dict(name=name,sha256=name,cases=[name+'.'+str(i) for i in range(count)]) for name,count in [('large',1464),('medium',913),('small',11),('tiny',4)]]
        groups=partition(suites,4)
        expected={(s['name'],case) for s in suites for case in s['cases']}
        observed=[(s['name'],case) for g in groups for s in g for case in s['cases']]
        self.assertEqual(set(observed),expected);self.assertEqual(len(observed),len(expected))
    def test_reuse_rejects_another_runtime_or_elf(self):
        plan={'suites':[{'name':'one','sha256':'elf-a','cases':['T.Pass']}],'runtime_sha256':'runtime-a','cpus':2,'fresh_store':True}
        (self.root/'plan.json').write_text(json.dumps(plan));(self.root/'results.json').write_text(json.dumps([dict(suite='one',case='T.Pass',status='passed',code=0)]))
        args=argparse.Namespace(reuse=self.root,reuse_completed=False)
        (self.root/'logs').mkdir()
        (self.root/'logs/0.xml').write_text('<testsuite><testcase classname="T" name="Pass"/></testsuite>')
        self.assertEqual(len(reuse_rows(args,plan)),1)
        with self.assertRaises(RuntimeError):reuse_rows(args,dict(plan,runtime_sha256='runtime-b'))
        with self.assertRaises(RuntimeError):reuse_rows(args,dict(plan,suites=[{'name':'one','sha256':'elf-b','cases':['T.Pass']}]))

    def test_suppressed_xml_with_successful_exit_cannot_pass(self):
        path = self.xml('<testcase classname="T" name="A" status="notrun" result="suppressed"/>')
        self.assertIsNone(xml_rows(path, 0, ['T.A']))
        self.assertEqual(classify(path, 0, False, 'T.A')[0], 'invalid_result')

    def test_isolated_loopback_rejects_results_from_a_shared_namespace(self):
        suite = dict(name='socket_inet_loopback_isolated', sha256='elf', cases=['T.Bind'])
        previous = dict(suites=[suite])
        (self.root / 'plan.json').write_text(json.dumps(previous))
        args = argparse.Namespace(reuse=self.root, reuse_completed=True)
        with self.assertRaisesRegex(RuntimeError, 'isolated_loopback_per_case'):
            reuse_rows(args, dict(previous, isolated_loopback_per_case=True))

    def test_repartition_and_second_reuse_keep_the_original_xml(self):
        plan = dict(suites=[dict(name='a', sha256='a', cases=['T.A']), dict(name='memfd', sha256='m', cases=['M.Test'])],
                    memfd_tmpfs_fixture=True)
        (self.root/'plan.json').write_text(json.dumps(plan))
        stem = self.root/'worker-01/logs/chunk-000004'
        stem.parent.mkdir(parents=True)
        stem.with_suffix('.xml').write_text('<testsuite><testcase classname="T" name="A"/></testsuite>')
        row = dict(suite='a', case='T.A', status='passed', code=0, logs='worker-01/logs/chunk-000004')
        (self.root/'results.json').write_text(json.dumps([row]))
        args = argparse.Namespace(reuse=self.root, reuse_completed=False)
        subset = dict(suites=[plan['suites'][0], dict(name='new', sha256='b', cases=['B.Test'])])
        first = reuse_rows(args, subset)
        self.assertEqual(first['a','T.A']['reused_from'], str(stem.resolve()))
        second = self.root/'second'
        second.mkdir()
        (second/'plan.json').write_text(json.dumps(subset))
        (second/'results.json').write_text(json.dumps(list(first.values())))
        args.reuse = second
        self.assertEqual(reuse_rows(args, subset), first)
        stem.with_suffix('.xml').write_text('<testsuite><testcase classname="U" name="B"/></testsuite>')
        self.assertFalse(reuse_rows(args, subset))
        stem.with_suffix('.xml').unlink()
        self.assertFalse(reuse_rows(args, subset))
        args.reuse = self.root
        with self.assertRaisesRegex(RuntimeError, 'memfd_tmpfs_fixture'):
            reuse_rows(args, dict(suites=[plan['suites'][1]]))
        with self.assertRaisesRegex(RuntimeError, 'custom_rootfs'):
            reuse_rows(args, dict(subset, custom_rootfs=True))


if __name__=='__main__':unittest.main()
