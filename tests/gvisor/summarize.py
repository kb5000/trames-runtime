#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Export compact, complete compatibility status without committing binaries."""
import argparse
import collections
import csv
import hashlib
import json
from pathlib import Path


def family(name):
    if name.startswith(('socket','packet_','raw_socket','accept_bind','bind','tuntap','tcp_','udp_','ip6tables','iptables','connect_external')) or name in ('bridge','network_namespace','ping_socket'):
        return 'Networking and sockets'
    if name.startswith(('mmap','mremap','madvise','mlock','memory_')) or name in ('brk','munmap','msync','mincore','mempolicy','membarrier','fault'):
        return 'Memory and mappings'
    if name.startswith(('clock_','timer')) or name in ('time','alarm','itimer','getrusage','vdso_clock_gettime'):
        return 'Clocks and timers'
    if name in ('futex','shm','semaphore','msgqueue','mq','eventfd'):
        return 'Synchronization and IPC'
    if name.startswith(('proc','cgroup','prctl','landlock')) or name in ('mount','mount_fd','unshare','setns','capabilities','setgid','rlimits','seccomp','ptrace','keys','kcov','sysinfo','syslog','sysfs_cpu_topology','personality','chroot'):
        return 'Isolation, security and procfs'
    if name.startswith(('sig','fpsig','exec')) or name in ('fork','vfork','exit','wait','kill','tkill','tgkill','rtsignal','processes','concurrency','exceptions','affinity','sched','sched_yield','getcpu','priority','sysret','pointer_auth'):
        return 'Processes, signals and scheduling'
    return 'Files, descriptors and I/O'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--comparison',type=Path,required=True)
    p.add_argument('--inventory',type=Path,required=True)
    p.add_argument('--build-record',type=Path,required=True)
    p.add_argument('--graph',type=Path,required=True)
    p.add_argument('--confirmations',type=Path)
    p.add_argument('--output',type=Path,required=True,help='Output prefix')
    a=p.parse_args();data=json.loads(a.comparison.read_text());inventory=json.loads(a.inventory.read_text());build=json.loads(a.build_record.read_text());graph=json.loads(a.graph.read_text())
    output=a.output;output.parent.mkdir(parents=True,exist_ok=True)
    families={}
    for row in data['details']:
        name=family(row['suite'])
        entry=families.setdefault(name,dict(cases=0,native_passes=0,all=collections.Counter(),on_native_passes=collections.Counter()))
        entry['cases']+=1;entry['all'][row['trames']['status']]+=1
        if row['native']['status']=='passed':
            entry['native_passes']+=1;entry['on_native_passes'][row['trames']['status']]+=1
    with output.with_suffix('.csv').open('w',newline='') as stream:
        writer=csv.writer(stream,lineterminator="\n");writer.writerow(['suite','case','native_status','trames_status','native_passes','native_seconds','trames_seconds'])
        for row in data['details']:
            n,t=row['native'],row['trames'];writer.writerow([row['suite'],row['case'],n['status'],t['status'],n['status']=='passed',n['seconds'],t['seconds']])
    result={k:v for k,v in data.items() if k not in ('details',)}
    result.update(families=families,build_blockers=graph['blocked'],build_failures=build['unavailable'],built_groups=len(build['binaries']),enabled_groups=sum(bool(r['enabled']) for r in inventory['groups']),upstream_disabled_cases=[dict(suite=r['suite'],case=c) for r in inventory['groups'] for c in r['disabled']],empty_built_groups=[r['suite'] for r in inventory['groups'] if not r['enabled']],upstream=build['inputs'],binary_hashes={r['suite']:r['sha256'] for r in build['binaries']},compiler=build['compiler'],reference_kernel=build['kernel'],csv_sha256=hashlib.sha256(output.with_suffix('.csv').read_bytes()).hexdigest())
    if a.confirmations:
        confirm=json.loads(a.confirmations.read_text());result['standalone_confirmations']={k:v for k,v in confirm.items() if k not in ('details','groups')};result['representative_gaps']=[dict(suite=r['suite'],case=r['case'],status=r['trames']['status'],messages=r['trames'].get('messages',[])) for r in confirm['details']]
    output.with_suffix('.json').write_text(json.dumps(result,indent=2)+'\n')
    lines=['| Area | Native-passing cases | Trames pass | Assertion fail | Fixture / abort | Timeout | Skip |','| --- | ---: | ---: | ---: | ---: | ---: | ---: |']
    for name,e in families.items():
        c=e['on_native_passes'];other=sum(v for k,v in c.items() if k not in ('passed','failed','timeout','skipped'))
        lines.append(f"| {name} | {e['native_passes']} | {c['passed']} | {c['failed']} | {other} | {c['timeout']} | {c['skipped']} |")
    print('\n'.join(lines))


if __name__=='__main__':main()
