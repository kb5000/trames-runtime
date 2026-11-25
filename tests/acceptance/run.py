#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run pinned application workflows and audit exact per-case acceptance evidence."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from common import canonical, digest, identity, guest_path, load_manifest, save, tree_digest

HERE = Path(__file__).resolve().parent
STATUSES = ('passed', 'failed', 'timed_out', 'blocked', 'infrastructure_error', 'reference_failed')


def host():
    return dict(os=platform.system(), arch=platform.machine(), kernel=platform.release(),
                page_size=os.sysconf('SC_PAGE_SIZE'), libc=list(platform.libc_ver()),
                cpu=Path('/proc/cpuinfo').read_text() if Path('/proc/cpuinfo').exists() else platform.processor(),
                cpu_identity=sorted(set(line.strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if ':' in line and line.split(':',1)[0].strip().lower() not in {'processor','cpu mhz','bogomips','core id','apicid','initial apicid'})) if Path('/proc/cpuinfo').exists() else [platform.processor()])


def stop_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def execute(argv, environment, output, timeout, console=False):
    begin = time.monotonic()
    if console:(output/'stdout').write_bytes(b'')
    with (output / ('console' if console else 'stdout')).open('wb') as stdout, (output / 'stderr').open('wb') as stderr:
        try:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                       env=environment, start_new_session=True)
        except OSError as error:
            return dict(status='infrastructure_error', error=str(error), exit_code=None, seconds=time.monotonic()-begin)
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            stop_group(process)
            process.wait()
    return dict(status='timed_out' if timed_out else 'completed', exit_code=process.returncode,
                seconds=time.monotonic()-begin)


def artifact_hashes(root, case, output):
    result = {}
    for name in case.get('artifacts', []):
        p = guest_path(root, name)
        if not p.is_file() or p.is_symlink() or root not in p.resolve().parents:
            raise ValueError('missing or escaped regular artifact: ' + name)
        target = output / 'artifacts' / name.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, target)
        result[name] = digest(target)
    return result


def check_outputs(case, output, code):
    if code != case.get('exit_code', 0):
        return False
    return all((output / stream).read_bytes() == case.get(stream, '').encode()
               for stream in ('stdout', 'stderr'))


def verified_evidence(directory, row, case, fingerprint):
    """A 'passed' label alone is never cache/reference evidence."""
    if (directory/'infrastructure-error.json').exists() or row.get('status') != 'passed' or row.get('fingerprint') != fingerprint:
        return False
    folder = directory / 'cases' / case['id']
    try:
        data = json.loads((folder / 'result.json').read_text())
        if data != row or not check_outputs(case, folder, data['exit_code']):
            return False
        return all(digest(folder / name) == row['logs'][name] for name in (('stdout','stderr','console') if case.get('console') else ('stdout','stderr'))) and row.get('artifacts_validated') is True and set(row['artifacts']) == set(case.get('artifacts', [])) and all(digest(folder/'artifacts'/name.lstrip('/')) == value for name,value in row['artifacts'].items())
    except (OSError, ValueError, KeyError):
        return False


def receipt(path, binary):
    value = json.loads(path.read_text())
    if value.get('schema_version') != 1 or identity(value['fingerprint']) != value['fingerprint_sha256']:
        raise ValueError('invalid build receipt')
    if digest(binary) != value['fingerprint']['binary_sha256']:
        raise ValueError('runner binary differs from successful build receipt')
    return value


def namespace_command(root, helper=HERE/'native.py'):
    command = ['/usr/bin/unshare', '--mount', '--pid', '--fork', '--kill-child=SIGKILL', '--net', '--uts', '--ipc',
               '--mount-proc=' + str(root / 'proc'), sys.executable, str(helper), str(root)]
    return command if os.geteuid() == 0 else ['/usr/bin/sudo', '-n', '--', *command]


def freeze_runner(binary, expected, output):
    target = output/'runner'
    shutil.copyfile(binary,target)
    target.chmod(0o555)
    if digest(target) != expected:
        raise ValueError('runner changed while freezing build evidence')
    return target


def export_store(runner, store, names, output, required):
    result = {}
    for name in names:
        target = output / ('artifacts' if required else 'diagnostics') / name.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('wb') as stream:
            p = subprocess.run([str(runner), 'read-file', '--store', str(store), '--', name], stdout=stream, stderr=subprocess.PIPE, timeout=30)
        if p.returncode:
            target.unlink()
            if required: raise ValueError('cannot export store artifact: ' + name + ': ' + p.stderr.decode(errors='replace'))
        else: result[name] = digest(target)
    return result


def run(a):
    manifest = load_manifest(a.manifest)
    bundle = json.loads((a.bundle / 'bundle.json').read_text())
    base = (a.bundle / 'rootfs').resolve()
    if tree_digest(base) != bundle['rootfs_sha256']:
        raise ValueError('rootfs changed since preparation')
    if bundle['machine'] != platform.machine():
        raise ValueError('bundle architecture differs from this native host')
    selected = [c for c in manifest['cases'] if (not a.case or c['id'] in a.case) and (not a.tier or c['tier'] in a.tier)]
    if not selected or a.case and set(a.case) - {c['id'] for c in selected}:
        raise ValueError('empty or unknown case selection')
    a.output.mkdir(parents=True, exist_ok=False)
    a.created_output = True
    a.output = a.output.resolve()
    hardware = host()
    # Dynamic CPU MHz/BogoMIPS are diagnostics, not semantic input identity.
    hardware_key = {k:v for k,v in hardware.items() if k != 'cpu'}
    harness_inputs={p.name:digest(p) for p in [HERE/'common.py', HERE/'run.py', HERE/'native.py']}
    harness = identity(harness_inputs)
    build = receipt(a.receipt, a.runner) if a.backend == 'kvm' else None
    if build:a.runner=freeze_runner(a.runner,build['fingerprint']['binary_sha256'],a.output)
    native_helper=a.output/'native-entry.py'
    shutil.copyfile(HERE/'native.py',native_helper)
    if digest(native_helper)!=harness_inputs['native.py']:raise ValueError('native helper changed while freezing inputs')
    provider = dict(backend=a.backend, cpus=a.cpus, transport=a.transport if a.backend=='kvm' else None,
                    build=build['fingerprint_sha256'] if build else None, filesystem=a.filesystem if a.backend=='kvm' else None, network=a.network if a.backend=='kvm' else None, native_container=digest(a.native_container) if a.native_container else None,
                    native_tools={str(p):digest(p) for p in [Path('/usr/bin/unshare'), Path('/usr/bin/mount'), Path(sys.executable).resolve()]} if a.backend=='native' else None)
    plan = dict(schema_version=1, bundle_sha256=bundle['rootfs_sha256'], harness_sha256=harness,
                host=hardware, provider=provider, build=build, cases=selected,
                performance_qualified=False, selected_scope='subset' if a.case or a.tier else 'complete')
    save(a.output/'plan.json', plan)
    reference = None
    if a.backend == 'kvm':
        if not a.reference:
            raise ValueError('KVM requires an exact native reference')
        reference = json.loads((a.reference/'results.json').read_text())
        reference_plan = json.loads((a.reference/'plan.json').read_text())
        if reference_plan['provider']['backend'] != 'native' or reference_plan['bundle_sha256'] != bundle['rootfs_sha256'] or reference_plan['harness_sha256'] != harness or {k:v for k,v in reference_plan['host'].items() if k!='cpu'} != hardware_key:
            raise ValueError('native reference inputs/host differ')
        doctor = subprocess.run([str(a.runner), 'doctor', '--json', '--require-kvm'], capture_output=True, timeout=10)
        (a.output/'doctor.stdout').write_bytes(doctor.stdout); (a.output/'doctor.stderr').write_bytes(doctor.stderr)
        if doctor.returncode:
            raise RuntimeError('KVM preflight failed; see doctor logs')
        info = json.loads(doctor.stdout)
        embedded = info['runtime'].get('commit', info['runtime'].get('revision'))
        if embedded != build['sources']['runtime']['commit']:
            raise ValueError('embedded runtime pin differs from the build receipt checkout')
        if info['host']['host_page_size'] != hardware['page_size'] or not info['host']['backend_implemented']:
            raise ValueError('doctor did not establish the actual supported KVM host profile')
    previous = json.loads((a.reuse/'results.json').read_text()) if a.reuse else dict(cases=[])
    previous_rows = {row['id']:row for row in previous['cases']}
    rows = [dict(id=c['id'], status='not_run', reused=False) for c in selected]
    def report():
        summary = dict(schema_version=1, cases=rows, counts={s:sum(r['status']==s for r in rows) for s in (*STATUSES,'not_run')},
                       planned=len(selected), completed=sum(r['status']!='not_run' for r in rows), reused=sum(r['reused'] for r in rows))
        save(a.output/'results.json',summary)
    report()
    for index, case in enumerate(selected):
        folder = a.output/'cases'/case['id']; folder.mkdir(parents=True)
        case_key = identity(dict(case=case, rootfs=bundle['rootfs_sha256'], harness=harness))
        fingerprint = identity(dict(inputs=case_key, provider=provider, host=hardware_key))
        row = dict(id=case['id'], case_inputs=case_key, fingerprint=fingerprint,
                   domain=case['domain'], tier=case['tier'], reused=False)
        if a.backend=='kvm':
            native = next((r for r in reference['cases'] if r['id']==case['id']),None)
            expected=identity(dict(inputs=case_key,provider=reference_plan['provider'],host=hardware_key))
            if native is None or not verified_evidence(a.reference,native,case,expected):
                row.update(status='reference_failed',reason='missing/nonpassing/invalid native evidence; guest not executed')
                save(folder/'result.json',row);rows[index]=row;report()
                print(f'{case["id"]}: reference_failed (guest not executed)',flush=True)
                continue
        old = previous_rows.get(case['id'])
        if old and verified_evidence(a.reuse, old, case, fingerprint):
            original = a.reuse/'cases'/case['id']
            for name in (['stdout','stderr','console'] if case.get('console') else ['stdout','stderr']):
                shutil.copy2(original/name, folder/name)
            for name in ['artifacts','diagnostics']:
                if (original/name).exists():shutil.copytree(original/name, folder/name)
            row = dict(old, reused=True, reused_from=str(original.resolve()))
        else:
            missing = [name for name in case.get('requires', []) if not guest_path(base,name).is_file()]
            if missing:
                row.update(status='blocked', reason='missing bundle programs', missing=missing)
            else:
                with tempfile.TemporaryDirectory(prefix='trames-acceptance-') as scratch:
                    root = Path(scratch)/'rootfs'
                    subprocess.run(['cp','-a','--reflink=auto',str(base),str(root)], check=True)
                    script = 'set -eu\ncd /work\n' + case['script'] + '\n'
                    (root/'acceptance/case.sh').write_text(script)
                    environment = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', LANG='C', LC_ALL='C', TZ='UTC')
                    if a.backend == 'native':
                        if a.native_container:
                            argv = ['/usr/bin/sudo','-n',str(a.native_container),'--quiet','--settings=no','--register=no','--machine='+root.parent.name.replace('_','-'),'--capability=CAP_NET_ADMIN,CAP_SYS_ADMIN,CAP_SYS_RESOURCE,CAP_BPF,CAP_PERFMON','--system-call-filter=add_key keyctl request_key bpf','--private-network','--console=read-only','--resolv-conf=off','--timezone=off','--link-journal=no','--directory='+str(root),'--chdir=/work','--setenv=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','--setenv=LC_ALL=C','--setenv=TZ=UTC','--setenv=HOME=/work','--setenv=TMPDIR=/tmp','--setenv=PYTHONHASHSEED=0','/bin/sh','/acceptance/case.sh']
                        else: argv = namespace_command(root,native_helper)
                    else:
                        environment['TRAMES_KVM_TRANSPORT'] = a.transport
                        argv = [str(a.runner), 'run', '--rootfs',str(root),'--cpus',str(a.cpus),'--timeout-ms',str(int(case.get('timeout',30)*1000))]
                        if a.network:argv.extend(['--network',a.network])
                        if case.get('pty'): argv.append('--pty')
                        if a.filesystem=='store': argv.extend(['--store',str(Path(scratch)/'store')])
                        for entry in ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG=C','LC_ALL=C','TZ=UTC','HOME=/work','TMPDIR=/tmp','PYTHONHASHSEED=0']:
                            argv.extend(['--setenv',entry])
                        argv.extend(['--','/bin/sh','/acceptance/case.sh'])
                    row.update(execute(argv, environment, folder, case.get('timeout',30)+2,bool(case.get('console'))))
                    if a.backend=='kvm' and a.filesystem=='store':
                        export_store(a.runner,Path(scratch)/'store',case.get('diagnostics',[]),folder,False)
                    else:
                        for name in case.get('diagnostics',[]):
                            source=guest_path(root,name)
                            if source.is_file():
                                target=folder/'diagnostics'/name.lstrip('/');target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
                    if row['status'] == 'completed':
                        row['status'] = 'passed' if check_outputs(case,folder,row['exit_code']) else 'failed'
                        if row['exit_code']==125 and (folder/'stderr').read_bytes().startswith(b'acceptance infrastructure:'):
                            row['status']='infrastructure_error'
                    row['logs'] = {name:digest(folder/name) for name in (['stdout','stderr','console'] if case.get('console') else ['stdout','stderr'])}
                    if row['status']=='passed':
                        try:
                            row['artifacts'] = export_store(a.runner,Path(scratch)/'store',case.get('artifacts',[]),folder,True) if a.backend=='kvm' and a.filesystem=='store' else artifact_hashes(root,case,folder)
                            row['artifacts_validated']=True
                        except ValueError as error:
                            row.update(status='failed',reason=str(error))
        if a.backend=='kvm':
            native = next((r for r in reference['cases'] if r['id']==case['id']),None)
            expected_fingerprint=identity(dict(inputs=case_key,provider=reference_plan['provider'],host=hardware_key))
            if native is None or not verified_evidence(a.reference,native,case,expected_fingerprint):
                row.update(guest_status=row['status'],status='reference_failed',reason='missing/nonpassing/invalid native evidence')
            elif row['status']=='passed' and row['artifacts'] != native['artifacts']:
                row.update(status='failed',reason='native/guest artifacts differ')
        save(folder/'result.json',row); rows[index]=row
        report()
        print(f'{case["id"]}: {row["status"]}' + (' (reused)' if row['reused'] else ''),flush=True)
    if tree_digest(base) != bundle['rootfs_sha256']:
        raise ValueError('immutable base rootfs was modified during acceptance')
    return 0 if all(r['status']=='passed' for r in rows) else 1


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--backend',choices=['native','kvm'],required=True)
    p.add_argument('--manifest',type=Path,default=HERE/'cli.json')
    p.add_argument('--bundle',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--runner',type=Path)
    p.add_argument('--receipt',type=Path)
    p.add_argument('--network',choices=['off','loopback','outbound','full'])
    p.add_argument('--filesystem',choices=['host','store'],default='host')
    p.add_argument('--native-container',type=Path,help='Pinned systemd-nspawn for full PID1/cgroup reference')
    p.add_argument('--reference',type=Path)
    p.add_argument('--reuse',type=Path)
    p.add_argument('--cpus',type=int,choices=range(1,33),default=1)
    p.add_argument('--transport',choices=['smccc','mmio'],default='smccc')
    p.add_argument('--case',action='append')
    p.add_argument('--tier',action='append',choices=['smoke','apps'])
    a=p.parse_args()
    if a.backend=='kvm' and (not a.runner or not a.receipt or not a.reference):
        p.error('KVM requires --runner, --receipt and --reference')
    for key in ['bundle','runner','receipt','reference','reuse','native_container']:
        value=getattr(a,key)
        if value is not None:setattr(a,key,value.resolve())
    try:return run(a)
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError,KeyError) as error:
        if getattr(a,'created_output',False):save(a.output/'infrastructure-error.json',dict(status='infrastructure_error',error=str(error)))
        print(f'acceptance infrastructure: {error}',file=sys.stderr)
        return 2


if __name__=='__main__':
    sys.exit(main())
