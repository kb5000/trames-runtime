#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run identical unmodified gVisor binaries on native Linux and Trames.

Each case owns a fresh PID/mount/UTS/IPC/network namespace (native) or a fresh
Trames runtime process/private registry. No running product environment is used.
"""
import argparse
import collections
from contextlib import ExitStack
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

def execute(argv, stdout, stderr, timeout, env=None, cwd=None, min_free=0, progress=None, host_pty=False):
    start = time.monotonic()
    with ExitStack() as stack, stdout.open('wb') as out, stderr.open('wb') as err:
        inherited = ()
        if host_pty:
            master, slave = os.openpty()
            stack.callback(os.close, master)
            stack.callback(os.close, slave)
            env = dict(os.environ if env is None else env, TEST_HOST_PTY_FD=str(slave))
            inherited = (slave,)
        child = subprocess.Popen(argv, stdout=out, stderr=err, env=env, cwd=cwd, start_new_session=True, pass_fds=inherited)
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

def suite_flags(suite):
    # Isolated root can switch between these mapped groups. The upstream
    # fixture otherwise skips all setgid cases on a single-group rootfs.
    return ['--groups=0,1'] if suite == 'setgid' else []

def guest_binary(suite):
    # The TUN/TAP fixtures own 10.0.0.1/24 and use .2 as the remote peer.
    # Run in an empty netns, matching the native harness, to avoid eth0's subnet.
    prefix = ['/usr/bin/unshare', '-n'] if suite == 'tuntap' else []
    return [*prefix, '/opt/gvisor/' + suite + '_test']

def guest_test_work(suite):
    if suite == 'memfd':
        # Keep the original XML on persistent storage for the later export.
        return 'mkdir -p "$1/tmpfs"; mount -t tmpfs -o mode=1777 tmpfs "$1/tmpfs"; cd "$1/tmpfs"; export TEST_TMPDIR="$PWD"; '
    work = 'mkdir -p "$1"; cd "$1"; export TEST_TMPDIR="$1"; '
    if suite == 'concurrency':
        return work + 'export GVISOR_PLATFORM_SUPPORT=MULTIPROCESS:TRUE; '
    if suite in ('rename','mount'):
        # The native reference has writable sysfs. Linux rejects even a
        # same-inode rename on an explicitly read-only mount.
        return work + 'mount -t sysfs -o remount,rw,nodev,nosuid,noexec sysfs /sys; '
    return work


def guest_wrapper(suite, *, pid2, test_on_gvisor=False, mount_fusectl=False):
    wrapper = (
        'export TEST_SRCDIR=/opt/gvisor/runfiles RUNFILES_DIR=/opt/gvisor/runfiles; '
        + guest_test_work(suite)
        + 'unset TEST_ON_GVISOR GVISOR_SAVE_TEST; shift; '
    )
    if suite == 'posix_acl':
        wrapper = 'mkdir -p /dev/shm; mount -t tmpfs -o mode=1777 tmpfs /dev/shm; ' + wrapper
    if suite == 'fuse' and mount_fusectl:
        wrapper = 'mkdir -p "$1/fusectl"; mount -t fusectl fusectl "$1/fusectl"; ' + wrapper
    if test_on_gvisor:
        wrapper += 'export TEST_ON_GVISOR=trames; '
    return wrapper + ('"$@" & child=$!; wait "$child"' if pid2 else 'exec "$@"')


def guest_terminal(suite, wrapper):
    if suite == 'host_pty':
        # Keep an inherited copy even when the shell backgrounds the test and
        # redirects its standard input. The Mac runner supplies this actual PTY.
        return '--pty', 'exec 3<&0; test -t 3; export TEST_HOST_PTY_FD=3; ' + wrapper
    return '--no-pty', wrapper

def discover_cases(binary):
    result = subprocess.run([str(binary), '--gtest_list_tests'], capture_output=True,
                            text=True, timeout=20, check=True)
    suite = None
    enabled, disabled = [], []
    seen = set()
    for raw in result.stdout.splitlines():
        line = raw.split('#', 1)[0].rstrip()
        if not line:
            continue
        if not raw.startswith(' ') and line.endswith('.'):
            suite = line[:-1]
        elif raw.startswith('  ') and suite:
            name = suite + '.' + line.strip()
            if name in seen:
                raise RuntimeError(f'{binary}: duplicate GoogleTest case {name}')
            seen.add(name)
            is_disabled = any(part.startswith('DISABLED_') for part in re.split(r'[./]', name))
            (disabled if is_disabled else enabled).append(name)
    if not seen:
        raise RuntimeError('No gtest cases listed: ' + str(binary))
    return enabled, disabled


def list_cases(binary):
    enabled, _ = discover_cases(binary)
    if not enabled:
        raise RuntimeError('No enabled gtest cases: ' + str(binary))
    return enabled


TRACEE_WAIT = 'WaitTest.TraceeWALL'


# Some upstream parents can accept a child terminated by a signal. Each
# diagnostic here belongs to a specific child and test in the pinned source.
CHILD_CHECKS = {
    TRACEE_WAIT: ('fixture_failed', 'Check failed: ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == 0'),
    'ItimerTest.DeliversSIGALRMToMainThread': ('failed', 'Check failed: num <= worker_threshold: worker received too many samples'),
}


def child_check_failure(case, stderr):
    check = CHILD_CHECKS.get(case)
    if check is None or stderr is None or not stderr.is_file():
        return None
    status, prefix = check
    with stderr.open(errors='replace') as stream:
        for line in stream:
            if line.startswith(prefix):
                return status, [line.rstrip()]
    return None


def executed_case(case):
    # Older GoogleTest versions omitted these attributes. Modern XML also
    # lists suppressed tests, which have neither a failure nor a skip child.
    expected = 'skipped' if case.find('skipped') is not None else 'completed'
    return case.get('status', 'run') == 'run' and case.get('result', expected) == expected


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
    if not executed_case(case):
        return 'invalid_result', []
    if case.find('skipped') is not None and code == 0:
        return 'skipped', [case.find('skipped').get('message', '')]
    if code == 0 and (failure := child_check_failure(expected, xml.with_suffix('.stderr'))):
        return failure
    return ('passed' if code == 0 else 'crashed'), []

# These flags describe the named suites, not the worker or its other tests.
UDP_INTERFACE_SUITES = {'socket_ipv4_udp_unbound_external_networking',
                       'socket_ipv6_udp_unbound_external_networking'}
# Port-exhaustion tests shrink the namespace ephemeral range and leave TCP
# TIME_WAIT state. Native Linux also fails when these cases share one process.
SINGLE_CASE_SUITES = frozenset({'affinity', 'socket_inet_loopback_isolated', 'socket_stress', 'tuntap'})
NATIVE_UDP_INTERFACES = Path(__file__).with_name('native-udp-interfaces.sh').resolve()
SUITE_FIXTURES = {
    'native_udp_interfaces_sha256': UDP_INTERFACE_SUITES,
    'tun_netns_per_case': {'tuntap'},
    'host_pty_fixture': {'host_pty'},
    'isolated_loopback_per_case': {'socket_inet_loopback_isolated'},
    'isolated_socket_stress_per_case': {'socket_stress'},
    'setgid_fixture': {'setgid'},
    'multiprocess_fixture': {'concurrency'},
    'memfd_tmpfs_fixture': {'memfd'},
    'writable_sysfs_fixture': {'mount', 'rename'},
    'fusectl_fixture': {'fuse'},
}

def evidence_stem(directory, row, index):
    if row.get('reused_from'):
        return Path(row['reused_from'])
    if row.get('evidence_stem'):
        return Path(row['evidence_stem'])
    if row.get('logs'):
        return directory / row['logs']
    return directory / 'logs' / (row.get('log_stem') or str(index))

def reusable_xml(stem):
    try:
        cases = ET.parse(stem.with_suffix('.xml')).findall('.//testcase')
    except (FileNotFoundError, ET.ParseError):
        return None, {}
    outcomes = {}
    for case in cases:
        name = case.get('classname', '') + '.' + case.get('name', '')
        if name in outcomes or name == '.' and case.find('failure') is not None:
            return None, {}
        outcomes[name] = None
        if executed_case(case) and case.find('failure') is None:
            outcomes[name] = 'skipped' if case.find('skipped') is not None else 'passed'
    return int(any(c.find('failure') is not None for c in cases)), outcomes


def reuse_rows(args, plan):
    if not args.reuse:
        return {}
    directory = args.reuse.resolve()
    previous = json.loads((directory / 'plan.json').read_text())
    old = {s['name']: s['sha256'] for s in previous['suites']}
    suites = {s['name']: s['sha256'] for s in plan['suites']}
    selected = {s['name']: set(s['cases']) for s in plan['suites']}
    shared = old.keys() & suites.keys()
    if not shared:
        return {}
    if any(old[name] != suites[name] for name in shared):
        raise RuntimeError('Cannot reuse results from different binaries')
    for key in ('kernel', 'uid', 'runtime_sha256', 'nofile', 'machine', 'network',
                'cpus', 'rootfs_sha256', 'runfiles_sha256', 'process_context',
                'native_init_sha256', 'fresh_store', 'custom_rootfs', 'upstream_userspace_abi'):
        if previous.get(key) != plan.get(key):
            raise RuntimeError('Cannot reuse results with a different ' + key)
    for key, owners in SUITE_FIXTURES.items():
        if owners & shared and previous.get(key) != plan.get(key):
            raise RuntimeError('Cannot reuse results with a different ' + key)

    eligible = {'passed', 'skipped'}
    if args.reuse_completed:
        eligible.update(('failed', 'no_result', 'crashed', 'invalid_result', 'mismatched_result'))
    rows = {}
    reports = {}
    for index, row in enumerate(json.loads((directory / 'results.json').read_text())):
        if row['suite'] in shared and row['status'] in eligible and row['case'] in selected[row['suite']]:
            stem = evidence_stem(directory, row, index)
            if row['status'] in ('passed', 'skipped'):
                if stem not in reports:
                    reports[stem] = reusable_xml(stem)
                exit_code, outcomes = reports[stem]
                if row.get('code') != exit_code or outcomes.get(row['case']) != row['status']:
                    continue
                if row['status'] == 'passed' and child_check_failure(row['case'], stem.with_suffix('.stderr')):
                    continue
            key = (row['suite'], row['case'])
            if key in rows:
                raise ValueError(f'Duplicate cached result for {key}')
            rows[key] = dict(row, reused_from=str(stem))
    return rows


# These upstream cases include a deliberate wait. Allow it to finish and
# leave time for guest startup and XML export.
UPSTREAM_WAIT_TIMEOUTS = {
    # Creates 1000 watched directories before a five-second epoll workload.
    # The original case takes about 22s on the private-store guest fixture.
    'inotify': {'Inotify.EpollNoDeadlock': 60},
    'mmap_eternal': {'MmapEternalTest.PageTableLeak': 90},
    'flock': {'FlockTest.BlockingLockNoBlockingForSharedLocks': 45},
    'ppoll': {'PpollTest.SignalMaskBlocksSignal': 45},
    'vfork': {
        # The original children sleep for 10s before exit, and the two-child
        # case adds a preceding 5s wait. Keep startup and scheduling headroom.
        'VforkTest.ParentStopsUntilChildExits': 20,
        'VforkTest.ParentStopsUntilChildExecves': 40,
        'VforkTest.ExecedChildExitDoesntUnstopParent': 30,
        'VforkTest.SigchldReceivedDuringVforkIsDelivered': 20,
    },
    'sigstop': {'SigstopTest.Correctness': 45},
    # The workers take turns to accrue 20 CPU seconds each. The idle
    # variant also sleeps between turns, extending the wall time further.
    'itimer': {
        'ItimerTest.DeliversSIGALRMToMainThread': 45,
        'ItimerTest.DeliversSIGPROFToThreadsRoughlyFairlyActive': 100,
        'ItimerTest.DeliversSIGPROFToThreadsRoughlyFairlyIdle': 220,
    },
    'pselect': {'PselectTest.SignalMaskBlocksSignal': 45},
}

def watchdog(args, suite, case):
    if suite in args.suite_timeouts:
        return args.suite_timeouts[suite]
    return max(args.timeout, UPSTREAM_WAIT_TIMEOUTS.get(suite, {}).get(case, 0))


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
    plan['case_execution'] = dict(timeout_base=args.timeout, suite_timeouts=args.suite_timeouts, upstream_wait_timeouts=UPSTREAM_WAIT_TIMEOUTS)
    if args.native_init:plan['native_init_sha256']=digest(args.native_init)
    if any(s['name'] in UDP_INTERFACE_SUITES for s in plan['suites']):
        plan['native_udp_interfaces_sha256'] = digest(NATIVE_UDP_INTERFACES)
    if any(s['name'] == 'concurrency' for s in plan['suites']):
        plan['multiprocess_fixture'] = 'MULTIPROCESS:TRUE'
    if any(s['name'] == 'tuntap' for s in plan['suites']):
        plan['tun_netns_per_case'] = True
    if any(s['name'] == 'host_pty' for s in plan['suites']):
        plan['host_pty_fixture'] = True
    if any(s['name'] == 'setgid' for s in plan['suites']):
        plan['setgid_fixture'] = suite_flags('setgid')
    if any(s['name'] == 'memfd' for s in plan['suites']):
        plan['memfd_tmpfs_fixture'] = True
    save(output/'plan.json', plan)
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
                fixture = []
                if suite['name'] in UDP_INTERFACE_SUITES:
                    fixture = ['/bin/sh', str(NATIVE_UDP_INTERFACES)]
                elif suite['name'] == 'memfd':
                    # unshare creates a fresh mount namespace for this case.
                    fixture = ['/bin/sh', '-ec', 'mount -t tmpfs -o mode=1777 tmpfs "$TEST_TMPDIR"; cd "$TEST_TMPDIR"; exec "$@"', 'gvisor-memfd']
                argv = ['unshare', '--mount', '--uts', '--ipc', '--net', '--pid', '--fork', '--kill-child=KILL', '--mount-proc',
                        '--', *([str(args.native_init)] if args.native_init else []), '/usr/bin/env', '-u', 'TEST_ON_GVISOR', '-u', 'GVISOR_SAVE_TEST', 'TEST_TMPDIR=' + str(work), 'TEST_SRCDIR='+str(binaries/'runfiles'), 'RUNFILES_DIR='+str(binaries/'runfiles'),
                        *(['GVISOR_PLATFORM_SUPPORT=MULTIPROCESS:TRUE'] if suite['name'] == 'concurrency' else []), *fixture, str(binary), *suite_flags(suite['name']), '--gtest_color=no', '--gtest_filter=' + case, '--gtest_output=xml:' + str(xml)]
                code, timed, seconds = execute(argv, output/'logs'/(str(index)+'.stdout'), output/'logs'/(str(index)+'.stderr'), watchdog(args, suite['name'], case), cwd=work, min_free=int(args.min_free_gib*1024**3), host_pty=suite['name']=='host_pty')
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
    plan['case_execution']={'chunk_size':args.chunk_size,'fresh_store':args.fresh_store,'timeout_base':args.timeout,'suite_timeouts':args.suite_timeouts,'upstream_wait_timeouts':UPSTREAM_WAIT_TIMEOUTS,'reference_timing_extension':'max(base,min(90,native_seconds*3+2))'}
    plan['fresh_store']=args.fresh_store
    plan['network']=args.network
    plan['cpus']=args.cpus
    plan['rootfs_sha256']=digest(args.rootfs.resolve())
    if any(s['name'] == 'tuntap' for s in plan['suites']):plan['tun_netns_per_case'] = True
    if args.custom_rootfs:plan['custom_rootfs'] = True
    if args.test_on_gvisor:plan['upstream_userspace_abi'] = True
    if args.mount_fusectl and any(s['name'] == 'fuse' for s in plan['suites']):plan['fusectl_fixture'] = True
    if any(s['name'] in ('rename','mount') for s in plan['suites']):plan['writable_sysfs_fixture'] = True
    plan['runfiles_sha256']={str(p.relative_to(binaries)):digest(p) for p in (binaries/'runfiles').rglob('*') if p.is_file()}

    plan.pop('kernel',None);plan.pop('uid',None);plan.pop('nofile',None);plan.pop('native_init_sha256',None);plan.pop('native_udp_interfaces_sha256',None)
    if any(s['name'] == 'concurrency' for s in plan['suites']):
        plan['multiprocess_fixture'] = 'MULTIPROCESS:TRUE'
    if any(s['name'] == 'host_pty' for s in plan['suites']):
        plan['host_pty_fixture'] = True
    if any(s['name'] == 'setgid' for s in plan['suites']):
        plan['setgid_fixture'] = suite_flags('setgid')
    if any(s['name'] == 'socket_inet_loopback_isolated' for s in plan['suites']):
        plan['isolated_loopback_per_case'] = True
    if any(s['name'] == 'socket_stress' for s in plan['suites']):
        plan['isolated_socket_stress_per_case'] = True
    if any(s['name'] == 'memfd' for s in plan['suites']):
        plan['memfd_tmpfs_fixture'] = True
    save(output/'plan.json', plan)
    cache=reuse_rows(args,plan)
    selected = [(s['name'], case) for s in plan['suites'] for case in s['cases']]
    if all(key in cache for key in selected):
        rows = [cache[key] for key in selected]
        save(output/'results.json', rows)
        return rows
    registry = output/'registry'
    env = dict(os.environ, TRAMES_HOME=str(registry))
    runner = str(args.runner.resolve())
    name = 'gvisor'
    def control(*argv):
        return subprocess.run([runner,*argv], env=env, capture_output=True, text=True, timeout=90, check=True)
    control('env','create',name,'--rootfs' if args.custom_rootfs else '--archive',str(args.rootfs.resolve()),'--cpus',str(args.cpus),'--memory','8GiB','--vulkan','false','--network','none')
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
        return max(watchdog(args, suite, case), min(90,reference_times.get((suite,case),0)*3+2))
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
            wrapper = guest_wrapper(suite['name'], pid2=args.network == 'internal',
                                    test_on_gvisor=args.test_on_gvisor, mount_fusectl=args.mount_fusectl)
            terminal, wrapper = guest_terminal(suite['name'], wrapper)
            argv = [runner,'debug','env-run',name,'--no-windows',terminal,'--','/bin/sh','-ec',wrapper,'trames-gvisor',work,
                    *guest_binary(suite['name']),*suite_flags(suite['name']),'--gtest_color=no','--gtest_filter='+case,'--gtest_output=xml:'+guest_xml]
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
    p.add_argument('--test-on-gvisor',action='store_true',help='Run selected original cases in their userspace-kernel ABI mode')
    p.add_argument('--mount-fusectl',action='store_true',help='Mount the guest FUSE control filesystem for the fuse suite')
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
    p.add_argument('--custom-rootfs',action='store_true',help='Import --rootfs as a custom fixture instead of the pinned Alpine distribution')
    a = p.parse_args()
    if a.platform == 'native' and (a.test_on_gvisor or a.mount_fusectl):
        p.error('the selected guest fixtures apply only to Trames')
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
    if a.platform == 'trames' and not a.keep_registry and (out/'registry').is_dir():
        shutil.rmtree(out/'registry')

if __name__ == '__main__':main()
