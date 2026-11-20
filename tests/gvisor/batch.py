#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run broad original gVisor cases in bounded, independent test workers.

Workers are harness processes, not production runtime services. Every case
retains a fresh runtime process or native namespace. Large parameterized groups
are partitioned, not sampled; all enabled names remain in the plan.
"""
import argparse
import collections
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys

from run import digest, list_cases, save

HERE=Path(__file__).resolve().parent


def partition(suites, jobs):
    groups=[[] for _ in range(jobs)]
    loads=[0]*jobs
    for suite in sorted(suites,key=lambda s:(-len(s['cases']),s['name'])):
        chunks=[suite['cases'][i:i+250] for i in range(0,len(suite['cases']),250)] or [[]]
        for chunk in chunks:
            worker=min(range(jobs),key=lambda n:loads[n])
            present=next((s for s in groups[worker] if s['name']==suite['name']),None)
            if present is None:
                present=dict(suite,cases=[]);groups[worker].append(present)
            present['cases'].extend(chunk);loads[worker]+=len(chunk)
    return [sorted(g,key=lambda s:s['name']) for g in groups if g]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('platform',choices=['native','trames'])
    p.add_argument('--binaries',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--reference',type=Path)
    p.add_argument('--runner',type=Path)
    p.add_argument('--rootfs',type=Path)
    p.add_argument('--fresh-store',action='store_true')
    p.add_argument('--reference-timings',type=Path)
    p.add_argument('--chunk-size',type=int,default=1)
    p.add_argument('--reuse',type=Path)
    p.add_argument('--reuse-completed',action='store_true')
    p.add_argument('--suite-timeout',action='append',default=[])
    p.add_argument('--native-init',type=Path)
    p.add_argument('--jobs',type=int,default=4)
    p.add_argument('--cpus',type=int,default=2)
    p.add_argument('--timeout',type=float,default=20)
    p.add_argument('--time-budget',type=float,default=0)
    p.add_argument('--min-free-gib',type=float,default=8)
    a=p.parse_args()
    if a.jobs<1:p.error('jobs must be positive')
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    binaries=a.binaries.resolve()
    discovery_errors=[]
    if a.platform=='native':
        if os.geteuid()!=0:p.error('native batch needs root in the disposable Linux VM')
        record=json.loads((binaries.parent/'build-record.json').read_text())
        suites=[]
        for binary in record['binaries']:
            name=binary['suite'];path=binaries/(name+'_test')
            try:
                assert digest(path)==binary['sha256']
                cases=list_cases(path)
                suites.append(dict(name=name,sha256=binary['sha256'],available=len(cases),cases=cases))
            except (subprocess.SubprocessError,AssertionError,RuntimeError) as error:
                discovery_errors.append(dict(suite=name,error=str(error)))
        plan=dict(schema_version=1,suites=suites,discovery_errors=discovery_errors)
    else:
        if not all([a.reference,a.runner,a.rootfs]):p.error('trames needs reference, runner and rootfs')
        reference=a.reference/'plan.json'
        if not reference.is_file():reference=a.reference/'requested-plan.json'
        plan=json.loads(reference.read_text())
    save(out/'requested-plan.json',plan)
    groups=partition(plan['suites'],a.jobs)
    print('Selected',sum(len(s['cases']) for s in plan['suites']),'cases in',len(plan['suites']),'groups;',len(groups),'workers',flush=True)

    def worker(index,suites):
        part=out/('partition-%02d.json'%index);save(part,dict(plan,suites=suites))
        destination=out/('worker-%02d'%index)
        cmd=[sys.executable,str(HERE/'run.py'),a.platform,'--binaries',str(binaries),'--output',str(destination),'--network','internal','--cpus',str(a.cpus),'--timeout',str(a.timeout),'--time-budget',str(a.time_budget),'--min-free-gib',str(a.min_free_gib)]
        if a.fresh_store:cmd+=['--fresh-store']
        if a.reference_timings:cmd+=['--reference-timings',str(a.reference_timings.resolve())]
        if a.platform=='trames':cmd+=['--chunk-size',str(a.chunk_size)]
        if a.reuse:
            cmd+=['--reuse',str((a.reuse/('worker-%02d'%index)).resolve())]
            if a.reuse_completed:cmd+=['--reuse-completed']
        for override in a.suite_timeout:cmd+=['--suite-timeout',override]
        if a.platform=='native':
            cmd+=['--case-plan',str(part)]
            if a.native_init:cmd+=['--native-init',str(a.native_init.resolve())]
        else:cmd+=['--reference',str(part),'--runner',str(a.runner.resolve()),'--rootfs',str(a.rootfs.resolve())]
        with (out/('worker-%02d.log'%index)).open('w') as log:
            result=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
        return dict(worker=index,exit_code=result.returncode,output=str(destination))

    with ThreadPoolExecutor(max_workers=len(groups)) as pool:
        outcomes=list(pool.map(lambda pair:worker(*pair),enumerate(groups)))
    save(out/'workers.json',outcomes)
    merged=[];plans=[]
    for outcome in outcomes:
        directory=Path(outcome['output'])
        if (directory/'plan.json').is_file():plans.append(json.loads((directory/'plan.json').read_text()))
        if (directory/'results.json').is_file():
            for index,row in enumerate(json.loads((directory/'results.json').read_text())):
                merged.append(dict(row,logs=str(Path(directory.name)/'logs'/(row.get('log_stem') or str(index)))))
    expected={(s['name'],case) for s in plan['suites'] for case in s['cases']}
    observed={(r['suite'],r['case']) for r in merged}
    assert len(observed)==len(merged),'duplicate cases in partitions'
    for suite,case in sorted(expected-observed):merged.append(dict(suite=suite,case=case,status='not_run_worker_error',code=None,seconds=0,messages=[]))
    merged.sort(key=lambda r:(r['suite'],r['case']))
    final=dict(plans[0] if plans else plan,suites=plan['suites'],discovery_errors=discovery_errors,workers=outcomes)
    for worker_plan in plans:
        for fixture in ('host_pty_fixture', 'setgid_fixture'):
            if fixture in worker_plan:
                final[fixture] = worker_plan[fixture]
    save(out/'plan.json',final);save(out/'results.json',merged)
    counts=dict(collections.Counter(r['status'] for r in merged))
    summary=dict(platform=a.platform,groups=len(plan['suites']),cases=len(merged),counts=counts,discovery_errors=discovery_errors,worker_errors=[r for r in outcomes if r['exit_code']])
    save(out/'summary.json',summary);print(json.dumps(summary,indent=2),flush=True)
    return 1 if summary['worker_errors'] else 0


if __name__=='__main__':raise SystemExit(main())
