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

def execute(argv, stdout, stderr, timeout, env=None, cwd=None, min_free=0, progress=None):
    start = time.monotonic()
    with stdout.open('wb') as out, stderr.open('wb') as err:
        child = subprocess.Popen(argv, stdout=out, stderr=err, env=env, cwd=cwd, start_new_session=True)
        timed_out = False
        try:
            while child.poll() is None:
                if min_free and min(shutil.disk_usage(stdout.parent).free, shutil.disk_usage(cwd or stdout.parent).free) < min_free:
                    raise OSError('disk_limit')
                remaining = timeout - (time.monotonic() - start)
                if progress:remaining=min(remaining,progress.remaining())
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                try:
                    child.wait(timeout=min(0.25, remaining))
                except subprocess.TimeoutExpired:
                    pass
        except (subprocess.TimeoutExpired, OSError) as error:
            timed_out = 'disk_limit' if isinstance(error, OSError) else 'timeout'
            try:os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:pass
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:pass
                child.wait(timeout=5)
        except BaseException:
            try:os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:pass
            child.wait(timeout=5)
            raise
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
        return str(timed_out), []
    if not xml.is_file():
        return 'no_result', []
    try:
        tree = ET.parse(xml)
    except ET.ParseError:
        return 'invalid_result', []
    cases = tree.findall('.//testcase')
    global_failures=[c for c in cases if not c.get('classname') and not c.get('name') and c.findall('failure')]
    cases=[c for c in cases if c not in global_failures]
    if len(cases) != 1 or cases[0].get('classname','') + '.' + cases[0].get('name','') != expected:
        return 'mismatched_result', []
    if global_failures:
        return 'fixture_failed',[f.get('message','') for c in global_failures for f in c.findall('failure')]
    case = cases[0]
    failures = [f.get('message', '') for f in case.findall('failure')]
    if failures:
        return 'failed', failures
    if case.find('skipped') is not None:
        return 'skipped', [case.find('skipped').get('message', '')]
    return ('passed' if code == 0 else 'crashed'), []

def reuse_rows(args, plan):
    if not args.reuse:
        return {}
    previous = json.loads((args.reuse/'plan.json').read_text())
    old = {s['name']:s['sha256'] for s in previous['suites']}
    if old != {s['name']:s['sha256'] for s in plan['suites']}:
        raise RuntimeError('Cannot reuse results from different binaries')
    for key in ['kernel','uid','runtime_sha256','nofile','network','cpus','rootfs_sha256','runfiles_sha256','process_context','native_init_sha256','fresh_store']:
        if key in plan and previous.get(key) != plan[key]:
            raise RuntimeError('Cannot reuse results with a different '+key)
    return {(r['suite'],r['case']):dict(r,reused_from=str(args.reuse.resolve()/'logs'/(r.get('log_stem') or str(i))))
            for i,r in enumerate(json.loads((args.reuse/'results.json').read_text())) if r['status'] in (['passed','skipped','failed','no_result','crashed','invalid_result','mismatched_result'] if args.reuse_completed else ['passed','skipped'])}


def native(args, output):
    if os.geteuid() != 0:
        raise RuntimeError('Run native references as root inside the disposable Linux CI instance')
    import resource
    resource.setrlimit(resource.RLIMIT_NOFILE,(1048576,1048576))
    binaries = args.binaries.resolve()
    plan = {'schema_version': 1, 'kernel': os.uname().release, 'machine': os.uname().machine,
            'uid': os.geteuid(), 'nofile':list(resource.getrlimit(resource.RLIMIT_NOFILE)), 'max_cases_per_suite': args.max_cases_per_suite, 'network':args.network, 'process_context':'pid2' if args.native_init else 'pid1', 'suites': []}
    requested=json.loads(args.case_plan.read_text()) if args.case_plan else None
    requested_suites={r['name']:r for r in requested['suites']} if requested else {}
    for name in (list(requested_suites) if requested else args.suites.split(',') if args.suites else SUITES):
        path = binaries / (name + '_test')
        cases = list_cases(path)
        selected = requested_suites[name]['cases'] if requested else cases[:args.max_cases_per_suite] if args.max_cases_per_suite else cases
        if requested:
            assert requested_suites[name]['sha256']==digest(path) and set(selected)<=set(cases)
        if args.case_filter: selected=[case for case in selected if fnmatch.fnmatchcase(case,args.case_filter)]
        plan['suites'].append({'name': name, 'sha256': digest(path), 'available': len(cases), 'cases': selected})
    if not any(s['cases'] for s in plan['suites']):raise RuntimeError('No cases selected')
    if args.native_init:plan['native_init_sha256']=digest(args.native_init)
    save(output / 'plan.json', plan)
    cache=reuse_rows(args,plan)
    rows = []
    started=time.monotonic()
    with tempfile.TemporaryDirectory(prefix='trames-gvisor-native-') as temp:
        temp = Path(temp)
        # Tests deliberately drop individual thread UIDs. Their own working
        # directory permissions, not a private harness ancestor, govern access.
        temp.chmod(0o755)
        for suite in plan['suites']:
            binary = binaries / (suite['name'] + '_test')
            for case in suite['cases']:
                if (suite['name'],case) in cache:
                    rows.append(cache[(suite['name'],case)]);save(output/'results.json',rows);continue
                if args.time_budget and time.monotonic()-started >= args.time_budget:
                    rows.append(dict(suite=suite['name'],case=case,status='not_run_budget',code=None,seconds=0,messages=[]))
                    continue
                index = len(rows)
                work = temp / str(index)
                work.mkdir()
                xml = output / 'logs' / (str(index) + '.xml')
                argv = ['unshare', '--mount', '--uts', '--ipc', '--net', '--pid', '--fork', '--kill-child=KILL', '--mount-proc',
                        '--', *([str(args.native_init)] if args.native_init else []), '/usr/bin/env', '-u', 'TEST_ON_GVISOR', '-u', 'GVISOR_SAVE_TEST', 'TEST_TMPDIR=' + str(work), 'TEST_SRCDIR='+str(binaries/'runfiles'), 'RUNFILES_DIR='+str(binaries/'runfiles'),
                        str(binary), '--gtest_color=no', '--gtest_filter=' + case, '--gtest_output=xml:' + str(xml)]
                code, timed, seconds = execute(argv, output/'logs'/(str(index)+'.stdout'), output/'logs'/(str(index)+'.stderr'), args.suite_timeouts.get(suite['name'],args.timeout), cwd=work, min_free=int(args.min_free_gib*1024**3))
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
    plan['process_context']='pid2' if args.network=='internal' else 'pid1'
    plan['case_execution']={'chunk_size':args.chunk_size,'fresh_store':args.fresh_store,'timeout_base':args.timeout,'suite_timeouts':args.suite_timeouts,'reference_timing_extension':'max(base,min(90,native_seconds*3+2))'}
    plan['fresh_store']=args.fresh_store
    plan['network']=args.network
    plan['cpus']=args.cpus
    plan['rootfs_sha256']=digest(args.rootfs.resolve())
    plan['runfiles_sha256']={str(p.relative_to(binaries)):digest(p) for p in (binaries/'runfiles').rglob('*') if p.is_file()}

    plan.pop('kernel',None);plan.pop('uid',None);plan.pop('nofile',None);plan.pop('native_init_sha256',None)
    save(output/'plan.json',plan)
    cache=reuse_rows(args,plan)
    registry = output/'registry'
    env = dict(os.environ, TRAMES_HOME=str(registry))
    runner = str(args.runner.resolve())
    name = 'gvisor'
    def control(*argv):
        return subprocess.run([runner,*argv], env=env, capture_output=True, text=True, timeout=90, check=True)
    control('env','create',name,'--archive',str(args.rootfs.resolve()),'--cpus',str(args.cpus),'--memory','8GiB','--vulkan','false','--network','none')
    if args.network == 'internal':
        control('network','create','gvisor','--internal')
        control('-e',name,'config','set','network.mode','bridge','network.bridge','gvisor')
    control('-e',name,'config','set','display.windows','false','components.audio','false','components.audio_input','false','components.vaapi','false','components.thunking','false')
    # Import only this worker's suites, sharing immutable host binaries via hard links.
    with tempfile.TemporaryDirectory(prefix='selected-',dir=output) as selected:
        selected=Path(selected)
        for suite in plan['suites']:
            if not suite['cases']:continue
            os.link(binaries/(suite['name']+'_test'), selected/(suite['name']+'_test'))
        if (binaries/'runfiles').is_dir():
            shutil.copytree(binaries/'runfiles',selected/'runfiles')
        control('-e',name,'files','cp','-r',str(selected),'guest:/opt/gvisor')
    control('-e',name,'permissions','deny','--all')
    store, snapshot = None, output/'clean-store'
    if args.fresh_store:
        stores=list((registry/'environments').glob('*/store'))
        assert len(stores)==1
        store=stores[0]
        subprocess.run(['/bin/cp','-cR',str(store),str(snapshot)],check=True)
        plan['clean_store_manifest_sha256']=digest(snapshot/'manifest')
        save(output/'plan.json',plan)
    reference_times={}
    checked_at=0
    def case_timeout(suite,case):
        nonlocal checked_at
        if args.reference_timings and time.monotonic()-checked_at>10:
            for path in args.reference_timings.glob('worker-*/results.json'):
                for row in json.loads(path.read_text()):
                    if row['status']=='passed':reference_times[(row['suite'],row['case'])]=row['seconds']
            checked_at=time.monotonic()
        return max(args.suite_timeouts.get(suite,args.timeout), min(90,reference_times.get((suite,case),0)*3+2))
    if args.chunk_size>1:
        from chunks import run
        rows=run(args,output,plan,env,runner,name,store,snapshot,cache,case_timeout)
        if snapshot.is_dir():shutil.rmtree(snapshot)
        if args.network=='internal':control('network','remove','gvisor')
        return rows
    rows = []
    token = uuid.uuid4().hex[:12]
    started=time.monotonic()
    for suite in plan['suites']:
        for case in suite['cases']:
            if (suite['name'],case) in cache:
                rows.append(cache[(suite['name'],case)]);save(output/'results.json',rows);continue
            if args.time_budget and time.monotonic()-started >= args.time_budget:
                rows.append(dict(suite=suite['name'],case=case,status='not_run_budget',code=None,seconds=0,messages=[]))
                continue
            if store is not None:
                shutil.rmtree(store)
                subprocess.run(['/bin/cp','-cR',str(snapshot),str(store)],check=True)
            index = len(rows)
            work = '/tmp/gvisor-'+token+'-'+str(index)
            guest_xml = work+'/result.xml'
            xml = output/'logs'/(str(index)+'.xml')
            wrapper = 'export TEST_SRCDIR=/opt/gvisor/runfiles RUNFILES_DIR=/opt/gvisor/runfiles; mkdir -p "$1"; cd "$1"; export TEST_TMPDIR="$1"; unset TEST_ON_GVISOR GVISOR_SAVE_TEST; shift; exec "$@"'
            if args.network=='internal':
                wrapper=wrapper.replace('exec "$@"', '"$@" & child=$!; wait "$child"')
            argv = [runner,'debug','env-run',name,'--no-windows','--no-pty','--','/bin/sh','-ec',wrapper,'trames-gvisor',work,
                    '/opt/gvisor/'+suite['name']+'_test','--gtest_color=no','--gtest_filter='+case,'--gtest_output=xml:'+guest_xml]
            code, timed, seconds = execute(argv,output/'logs'/(str(index)+'.stdout'),output/'logs'/(str(index)+'.stderr'),case_timeout(suite['name'],case),env=env,min_free=int(args.min_free_gib*1024**3))
            if not timed:
                exported = subprocess.run([runner,'debug','env-run',name,'--fs','get',guest_xml,str(xml)],env=env,capture_output=True,timeout=20)
                if exported.returncode:
                    (output/'logs'/(str(index)+'.export-error')).write_bytes(exported.stderr)
            status, messages = classify(xml,code,timed,case)
            rows.append(dict(suite=suite['name'],case=case,status=status,code=code,seconds=seconds,messages=messages))
            save(output/'results.json',rows)
            print(f'trames {index+1}: {case}: {status}',flush=True)
    if snapshot.is_dir():shutil.rmtree(snapshot)
    if args.network=='internal':control('network','remove','gvisor')
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
    p.add_argument('--chunk-size',type=int,default=1,help='Original GTest cases per process; aborted chunks are retried separately')
    p.add_argument('--reuse-completed',action='store_true',help='Also retain completed assertion/abort outcomes with matching executable/environment identities')
    p.add_argument('--fresh-store',action='store_true',help='APFS-clone the clean imported store for each Trames case')
    p.add_argument('--reference-timings',type=Path,help='Native results used only to extend timeout for original slow cases')
    p.add_argument('--suite-timeout',action='append',default=[],help='Upstream groups needing a longer timeout: NAME=SECONDS')
    p.add_argument('--time-budget',type=float,default=0,help='Wall seconds per worker; remaining cases stay explicitly unrun')
    p.add_argument('--native-init',type=Path,help='Reference namespace init; tests run as PID 2 with loopback up')
    p.add_argument('--case-plan',type=Path,help='Explicit native case partition with checked ELF hashes')
    p.add_argument('--suites',help='Comma-separated upstream suite names for native discovery')
    p.add_argument('--network',choices=['none','internal'],default='none',help='Trames-only bridge, no host networking or NAT')
    p.add_argument('--cpus',type=int,default=6)
    p.add_argument('--min-free-gib',type=float,default=8,help='Stop a test before the host filesystem fills')
    p.add_argument('--reuse',type=Path,help='Reuse passed/skipped cases only after matching binary and runtime fingerprints')
    p.add_argument('--runner',type=Path)
    p.add_argument('--rootfs',type=Path)
    a = p.parse_args()
    a.suite_timeouts={name:float(seconds) for name,seconds in (v.split('=',1) for v in a.suite_timeout)}
    if any(v<=0 for v in a.suite_timeouts.values()):p.error('suite timeouts must be positive')
    if a.chunk_size<1:p.error('chunk size must be positive')
    if a.time_budget<0:p.error('time budget must be nonnegative')
    if a.timeout<=0 or a.max_cases_per_suite<0 or a.cpus<1 or a.min_free_gib<0:p.error('timeout must be positive and case limit nonnegative')
    out = a.output.resolve()
    out.mkdir(parents=True,exist_ok=False)
    (out/'logs').mkdir()
    if a.platform=='trames' and not all([a.reference,a.runner,a.rootfs]):p.error('trames needs --reference, --runner and --rootfs')
    def stop(signum,frame):raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,stop)
    rows = native(a,out) if a.platform=='native' else trames(a,out)
    summary=dict(platform=a.platform,cases=len(rows),counts=dict(collections.Counter(r['status'] for r in rows)))
    save(out/'summary.json',summary)
    print(json.dumps(summary),flush=True)
    if a.platform=='trames' and not a.keep_registry:shutil.rmtree(out/'registry')

if __name__ == '__main__':main()
