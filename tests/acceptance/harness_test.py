#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Acceptance must not manufacture passes, reuse stale inputs or lose failures."""
import argparse
import copy
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from common import digest, identity, load_manifest, save, tree_digest
import run


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.case=dict(id='case',domain='files',tier='smoke',script='true',stdout='ok\n',artifacts=['/work/out'])

    def tearDown(self):
        self.temp.cleanup()

    def evidence(self):
        output=self.root/'evidence'; folder=output/'cases/case';folder.mkdir(parents=True)
        (folder/'stdout').write_bytes(b'ok\n');(folder/'stderr').write_bytes(b'')
        artifact=folder/'artifacts/work/out';artifact.parent.mkdir(parents=True);artifact.write_bytes(b'payload')
        row=dict(id='case',status='passed',fingerprint='fp',exit_code=0,artifacts_validated=True,
                 artifacts={'/work/out':digest(artifact)},logs={name:digest(folder/name) for name in ['stdout','stderr']})
        save(folder/'result.json',row)
        return output,folder,row

    def test_stale_or_nonpassing_results_and_forged_output_are_not_reused(self):
        output,folder,row=self.evidence()
        self.assertTrue(run.verified_evidence(output,row,self.case,'fp'))
        self.assertFalse(run.verified_evidence(output,row,self.case,'changed'))
        for state in ['failed','timed_out','blocked','reference_failed','infrastructure_error','not_run']:
            changed=dict(row,status=state);save(folder/'result.json',changed)
            self.assertFalse(run.verified_evidence(output,changed,self.case,'fp'))
        # Even coherent tampering with both JSON records/log digests cannot turn
        # output that violates the manifest into passing evidence.
        (folder/'stdout').write_bytes(b'wrong\n');row['logs']['stdout']=digest(folder/'stdout');save(folder/'result.json',row)
        self.assertFalse(run.verified_evidence(output,row,self.case,'fp'))

    def test_missing_or_changed_artifacts_invalidate_evidence(self):
        output,folder,row=self.evidence(); artifact=folder/'artifacts/work/out'
        artifact.write_bytes(b'changed')
        self.assertFalse(run.verified_evidence(output,row,self.case,'fp'))
        artifact.unlink()
        self.assertFalse(run.verified_evidence(output,row,self.case,'fp'))

    def test_manifest_rejects_duplicate_and_escaping_artifacts(self):
        path=self.root/'manifest.json'
        for cases in [[self.case,self.case],[dict(self.case,artifacts=['/work/../etc/passwd'])],[dict(self.case,timeout=0)]]:
            save(path,dict(schema_version=1,cases=cases))
            with self.assertRaises(ValueError):load_manifest(path)

    def test_tree_identity_includes_permissions_and_symlinks(self):
        root=self.root/'tree';root.mkdir();p=root/'data';p.write_bytes(b'value');before=tree_digest(root)
        p.chmod(0o700);self.assertNotEqual(tree_digest(root),before)
        p.chmod(0o644);before=tree_digest(root);(root/'alias').symlink_to('data');self.assertNotEqual(tree_digest(root),before)
        (root/'alias').unlink();(root/'alias').symlink_to('/host-data');self.assertNotEqual(tree_digest(root),before)

    def test_timeout_kills_descendant_process_group_and_keeps_raw_logs(self):
        output=self.root/'timeout';output.mkdir()
        code='import os,time; print("before-timeout",flush=True); p=os.fork(); time.sleep(30)'
        row=run.execute([sys.executable,'-c',code],dict(PATH='/usr/bin:/bin'),output,0.1)
        self.assertEqual(row['status'],'timed_out');self.assertLess(row['seconds'],3)
        self.assertEqual((output/'stdout').read_bytes(),b'before-timeout\n')

    def test_exit_failure_is_not_hidden_by_expected_text(self):
        output=self.root/'exit';output.mkdir()
        row=run.execute([sys.executable,'-c','print("ok"); raise SystemExit(7)'],dict(PATH='/usr/bin:/bin'),output,2)
        self.assertFalse(run.check_outputs(self.case,output,row['exit_code']))

    def test_build_receipt_requires_actual_binary_bytes(self):
        binary=self.root/'runner';binary.write_bytes(b'first')
        path=self.root/'receipt.json';fp=dict(binary_sha256=digest(binary))
        save(path,dict(schema_version=1,fingerprint=fp,fingerprint_sha256=identity(fp)))
        run.receipt(path,binary);binary.write_bytes(b'replaced')
        with self.assertRaises(ValueError):run.receipt(path,binary)

    def test_existing_result_directory_is_never_overwritten(self):
        output=self.root/'existing';output.mkdir();marker=output/'infrastructure-error.json';marker.write_text('old evidence')
        bundle=self.root/'bundle';(bundle/'rootfs').mkdir(parents=True)
        save(bundle/'bundle.json',dict(rootfs_sha256=tree_digest(bundle/'rootfs'),machine=run.platform.machine()))
        manifest=self.root/'manifest.json';save(manifest,dict(schema_version=1,cases=[self.case]))
        args=['run.py','--backend','native','--manifest',str(manifest),'--bundle',str(bundle),'--output',str(output)]
        with patch.object(sys,'argv',args):self.assertEqual(run.main(),2)
        self.assertEqual(marker.read_text(),'old evidence')

    def test_report_reaudits_logs_and_marks_a_missing_lane_as_failure(self):
        import report
        output,folder,row=self.evidence()
        case_key=identity(dict(case=self.case,rootfs='bundle',harness='harness'))
        row['fingerprint']=identity(dict(inputs=case_key,provider={},host={}))
        save(folder/'result.json',row)
        save(output/'plan.json',dict(cases=[self.case],bundle_sha256='bundle',harness_sha256='harness',provider={},host={}))
        save(output/'results.json',dict(cases=[row]))
        self.assertEqual(report.generate([('native',output)],self.root/'report-good'),0)
        (folder/'stdout').unlink()
        self.assertEqual(report.generate([('native',output),('missing',self.root/'missing')],self.root/'report-bad'),1)

    def test_unknown_schema_fields_cannot_silently_disable_a_requirement(self):
        path=self.root/'manifest.json';save(path,dict(schema_version=1,cases=[dict(self.case,requires_hardware=['gpu'])]))
        with self.assertRaises(ValueError):load_manifest(path)


if __name__=='__main__':unittest.main()
