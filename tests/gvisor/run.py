#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run identical unmodified gVisor binaries on native Linux and Trames.

Each case owns a fresh PID/mount/UTS/IPC/network namespace (native) or a fresh
Trames runtime process/private registry. No running product environment is used.
"""
import argparse
import collections
import hashlib
import fnmatch
import json
import os
from pathlib import Path
import re
import signal
import shutil
import subprocess
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET

SUITES = ['brk', 'clock_getres', 'clock_gettime', 'dup', 'eventfd', 'getrandom', 'pipe', 'epoll', 'mmap', 'futex', 'uname']

def save(path, value):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value, indent=2) + '\n')
    tmp.replace(path)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def execute(argv, stdout, stderr, timeout, env=None, cwd=None):
    start = time.monotonic()
    with stdout.open('wb') as out, stderr.open('wb') as err:
        child = subprocess.Popen(argv, stdout=out, stderr=err, env=env, cwd=cwd, start_new_session=True)
        timed_out = False
        try:
            child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:pass
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:pass
                child.wait(timeout=5)
    return child.returncode, timed_out, time.monotonic() - start

def list_cases(binary):
    result = subprocess.run([str(binary), '--gtest_list_tests'], capture_output=True, text=True, timeout=20, check=True)
    suite = None
    cases = []
    for raw in result.stdout.splitlines():
        line = raw.split('#', 1)[0].rstrip()
        if not line:
            continue
        if not raw.startswith(' ') and line.endswith('.'):
            suite = line[:-1]
        elif raw.startswith('  ') and suite:
            case = line.strip()
            name = suite + '.' + case
            if not any(part.startswith('DISABLED_') for part in re.split(r'[./]', name)):
                cases.append(name)
    if not cases:
        raise RuntimeError('No gtest cases listed: ' + str(binary))
    return cases

def classify(xml, code, timed_out, expected):
    if timed_out:
        return 'timeout', []
    if not xml.is_file():
        return 'no_result', []
    try:
        tree = ET.parse(xml)
    except ET.ParseError:
        return 'invalid_result', []
    cases = tree.findall('.//testcase')
    if len(cases) != 1 or cases[0].get('classname') + '.' + cases[0].get('name') != expected:
        return 'mismatched_result', []
    case = cases[0]
    failures = [f.get('message', '') for f in case.findall('failure')]
    if case.find('skipped') is not None:
        return 'skipped', [case.find('skipped').get('message', '')]
    if failures:
        return 'failed', failures
    return ('passed' if code == 0 else 'crashed'), []

def reuse_rows(args, plan):
    if not args.reuse:
        return {}
    previous = json.loads((args.reuse/'plan.json').read_text())
    old = {s['name']:s['sha256'] for s in previous['suites']}
    if old != {s['name']:s['sha256'] for s in plan['suites']}:
        raise RuntimeError('Cannot reuse results from different binaries')
    for key in ['kernel','uid','runtime_sha256','nofile']:
        if key in plan and previous.get(key) != plan[key]:
            raise RuntimeError('Cannot reuse results with a different '+key)
    return {(r['suite'],r['case']):dict(r,reused_from=str(args.reuse.resolve()/'logs'/str(i)))
            for i,r in enumerate(json.loads((args.reuse/'results.json').read_text())) if r['status'] in ['passed','skipped']}


def native(args, output):
    if os.geteuid() != 0:
        raise RuntimeError('Run native references as root inside the disposable Linux CI instance')
    import resource
    resource.setrlimit(resource.RLIMIT_NOFILE,(1048576,1048576))
    binaries = args.binaries.resolve()
    plan = {'schema_version': 1, 'kernel': os.uname().release, 'machine': os.uname().machine,
            'uid': os.geteuid(), 'nofile':list(resource.getrlimit(resource.RLIMIT_NOFILE)), 'max_cases_per_suite': args.max_cases_per_suite, 'suites': []}
    for name in SUITES:
        path = binaries / (name + '_test')
        cases = list_cases(path)
        selected = cases[:args.max_cases_per_suite] if args.max_cases_per_suite else cases
        if args.case_filter: selected=[case for case in selected if fnmatch.fnmatchcase(case,args.case_filter)]
        plan['suites'].append({'name': name, 'sha256': digest(path), 'available': len(cases), 'cases': selected})
    if not any(s['cases'] for s in plan['suites']):raise RuntimeError('No cases selected')
    save(output / 'plan.json', plan)
    cache=reuse_rows(args,plan)
    rows = []
    with tempfile.TemporaryDirectory(prefix='trames-gvisor-native-') as temp:
        temp = Path(temp)
        for suite in plan['suites']:
            binary = binaries / (suite['name'] + '_test')
            for case in suite['cases']:
                if (suite['name'],case) in cache:
                    rows.append(cache[(suite['name'],case)]);save(output/'results.json',rows);continue
                index = len(rows)
                work = temp / str(index)
                work.mkdir()
                xml = output / 'logs' / (str(index) + '.xml')
                argv = ['unshare', '--mount', '--uts', '--ipc', '--net', '--pid', '--fork', '--kill-child=KILL', '--mount-proc',
                        '--', '/usr/bin/env', '-u', 'TEST_ON_GVISOR', '-u', 'GVISOR_SAVE_TEST', 'TEST_TMPDIR=' + str(work),
                        str(binary), '--gtest_color=no', '--gtest_filter=' + case, '--gtest_output=xml:' + str(xml)]
                code, timed, seconds = execute(argv, output/'logs'/(str(index)+'.stdout'), output/'logs'/(str(index)+'.stderr'), args.timeout, cwd=work)
                status, messages = classify(xml, code, timed, case)
                rows.append(dict(suite=suite['name'], case=case, status=status, code=code, seconds=seconds, messages=messages))
                save(output/'results.json', rows)
                print(f'native {index+1}: {case}: {status}', flush=True)
    return rows

def trames(args, output):
    plan = json.loads(args.reference.read_text())
    if args.case_filter:
        for suite in plan['suites']:suite['cases']=[case for case in suite['cases'] if fnmatch.fnmatchcase(case,args.case_filter)]
    binaries = args.binaries.resolve()
    for suite in plan['suites']:
        if digest(binaries/(suite['name']+'_test')) != suite['sha256']:
            raise RuntimeError('Reference/guest binary mismatch: '+suite['name'])
    if not any(s['cases'] for s in plan['suites']):raise RuntimeError('No cases selected')
    plan['runtime_sha256']=digest(args.runner.resolve())
    plan.pop('kernel',None);plan.pop('uid',None)
    save(output/'plan.json',plan)
    cache=reuse_rows(args,plan)
    registry = output/'registry'
    env = dict(os.environ, TRAMES_HOME=str(registry))
    runner = str(args.runner.resolve())
    name = 'gvisor'
    def control(*argv):
        return subprocess.run([runner,*argv], env=env, capture_output=True, text=True, timeout=90, check=True)
    control('env','create',name,'--archive',str(args.rootfs.resolve()),'--cpus','6','--memory','8GiB','--vulkan','false','--network','none')
    control('-e',name,'config','set','display.windows','false','components.audio','false','components.audio_input','false','components.vaapi','false','components.thunking','false')
    control('-e',name,'files','cp','-r',str(binaries),'guest:/opt/gvisor')
    control('-e',name,'permissions','deny','--all')
    rows = []
    token = uuid.uuid4().hex[:12]
    for suite in plan['suites']:
        for case in suite['cases']:
            if (suite['name'],case) in cache:
                rows.append(cache[(suite['name'],case)]);save(output/'results.json',rows);continue
            index = len(rows)
            work = '/tmp/gvisor-'+token+'-'+str(index)
            guest_xml = work+'/result.xml'
            xml = output/'logs'/(str(index)+'.xml')
            wrapper = 'mkdir -p "$1"; cd "$1"; export TEST_TMPDIR="$1"; unset TEST_ON_GVISOR GVISOR_SAVE_TEST; shift; exec "$@"'
            argv = [runner,'debug','env-run',name,'--no-windows','--no-pty','--','/bin/sh','-ec',wrapper,'trames-gvisor',work,
                    '/opt/gvisor/'+suite['name']+'_test','--gtest_color=no','--gtest_filter='+case,'--gtest_output=xml:'+guest_xml]
            code, timed, seconds = execute(argv,output/'logs'/(str(index)+'.stdout'),output/'logs'/(str(index)+'.stderr'),args.timeout,env=env)
            if not timed:
                exported = subprocess.run([runner,'debug','env-run',name,'--fs','get',guest_xml,str(xml)],env=env,capture_output=True,timeout=20)
                if exported.returncode:
                    (output/'logs'/(str(index)+'.export-error')).write_bytes(exported.stderr)
            status, messages = classify(xml,code,timed,case)
            rows.append(dict(suite=suite['name'],case=case,status=status,code=code,seconds=seconds,messages=messages))
            save(output/'results.json',rows)
            print(f'trames {index+1}: {case}: {status}',flush=True)
    return rows

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('platform',choices=['native','trames'])
    p.add_argument('--binaries',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--timeout',type=float,default=20)
    p.add_argument('--keep-registry',action='store_true',help='Keep the disposable Trames store for debugging')
    p.add_argument('--max-cases-per-suite',type=int,default=0,help='0 runs all non-disabled cases; references record any explicit sampling')
    p.add_argument('--reference',type=Path)
    p.add_argument('--case-filter',help='Select exact gtest names/globs without changing assertions')
    p.add_argument('--reuse',type=Path,help='Reuse passed/skipped cases only after matching binary and runtime fingerprints')
    p.add_argument('--runner',type=Path)
    p.add_argument('--rootfs',type=Path)
    a = p.parse_args()
    if a.timeout<=0 or a.max_cases_per_suite<0:p.error('timeout must be positive and case limit nonnegative')
    out = a.output.resolve()
    out.mkdir(parents=True,exist_ok=False)
    (out/'logs').mkdir()
    if a.platform=='trames' and not all([a.reference,a.runner,a.rootfs]):p.error('trames needs --reference, --runner and --rootfs')
    rows = native(a,out) if a.platform=='native' else trames(a,out)
    summary=dict(platform=a.platform,cases=len(rows),counts=dict(collections.Counter(r['status'] for r in rows)))
    save(out/'summary.json',summary)
    print(json.dumps(summary),flush=True)
    if a.platform=='trames' and not a.keep_registry:shutil.rmtree(out/'registry')

if __name__ == '__main__':main()
