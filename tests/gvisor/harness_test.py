# SPDX-License-Identifier: GPL-3.0-or-later
"""Guard against false passes and lost cases in the external test harness."""
import argparse
import json
from pathlib import Path
import sys
import tempfile
import unittest

from batch import partition
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
        args.suite_timeouts['ppoll'] = 15
        self.assertEqual(watchdog(args, 'ppoll', 'PpollTest.SignalMaskBlocksSignal'), 15)
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
    def test_child_noise_does_not_extend_the_active_case(self):
        path=self.root/'stdout';path.write_text('[ RUN      ] T.Parent\n')
        progress=Progress(path,['T.Parent'],lambda _:5);progress.remaining();since=progress.since
        with path.open('a') as stream:stream.write('[ RUN      ] Child.Other\n[       OK ] Child.Other (1 ms)\n')
        progress.remaining();self.assertEqual(progress.active,'T.Parent');self.assertEqual(progress.since,since)
    def test_partition_is_complete_without_duplicates(self):
        suites=[dict(name=name,sha256=name,cases=[name+'.'+str(i) for i in range(count)]) for name,count in [('large',1464),('medium',913),('small',11),('tiny',4)]]
        groups=partition(suites,4)
        expected={(s['name'],case) for s in suites for case in s['cases']}
        observed=[(s['name'],case) for g in groups for s in g for case in s['cases']]
        self.assertEqual(set(observed),expected);self.assertEqual(len(observed),len(expected))
    def test_reuse_rejects_another_runtime_or_elf(self):
        plan={'suites':[{'name':'one','sha256':'elf-a'}],'runtime_sha256':'runtime-a','cpus':2,'fresh_store':True}
        (self.root/'plan.json').write_text(json.dumps(plan));(self.root/'results.json').write_text(json.dumps([dict(suite='one',case='T.Pass',status='passed')]))
        args=argparse.Namespace(reuse=self.root,reuse_completed=False)
        self.assertEqual(len(reuse_rows(args,plan)),1)
        with self.assertRaises(RuntimeError):reuse_rows(args,dict(plan,runtime_sha256='runtime-b'))
        with self.assertRaises(RuntimeError):reuse_rows(args,dict(plan,suites=[{'name':'one','sha256':'elf-b'}]))


if __name__=='__main__':unittest.main()
