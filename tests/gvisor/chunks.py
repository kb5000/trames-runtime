# SPDX-License-Identifier: GPL-3.0-or-later
"""Original GTest chunks with strict XML, active-case deadlines and cold stores.

Stdout guides retry partitioning only; a passing result always requires XML.
"""
import json
from pathlib import Path
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET

from run import executed_case, TRACEE_WAIT, classify, execute, guest_terminal, guest_test_work, save, suite_flags, child_check_failure


class Progress:
    def __init__(self, path, cases, timeout):
        self.path, self.cases, self.timeout = path, set(cases), timeout
        self.offset, self.pending = 0, b''
        self.active, self.since, self.completed = None, time.monotonic(), set()

    def remaining(self):
        if self.path.exists():
            with self.path.open('rb') as stream:
                stream.seek(self.offset);data=stream.read();self.offset=stream.tell()
            lines=(self.pending+data).split(b'\n');self.pending=lines.pop()
            for raw in lines:
                line=raw.decode('utf-8','replace')
                match=re.match(r'^\[ RUN      \] (.+)$',line)
                if match and match[1] in self.cases:
                    self.active,self.since=match[1],time.monotonic()
                match=re.match(r'^\[\s+(?:OK|FAILED|SKIPPED)\s+\] (.+?) \(\d+ ms\)$',line)
                if match and match[1] in self.cases:
                    self.completed.add(match[1])
                    if self.active==match[1]:self.active=None;self.since=time.monotonic()
        return self.timeout(self.active)- (time.monotonic()-self.since) if self.active else 30-(time.monotonic()-self.since)


def xml_rows(xml, code, expected, stderr=None):
    if not xml.is_file() or code not in (0,1):return None
    try:cases=ET.parse(xml).findall('.//testcase')
    except ET.ParseError:return None
    global_failures=[c for c in cases if not c.get('classname') and not c.get('name') and c.findall('failure')]
    cases=[c for c in cases if c not in global_failures]
    names=[c.get('classname','')+'.'+c.get('name','') for c in cases]
    if sorted(names)!=sorted(expected) or len(names)!=len(set(names)):return None
    failures=sum(bool(c.findall('failure')) for c in cases)+len(global_failures)
    if (code==1)!=(failures>0):return None
    if global_failures:
        messages=[f.get('message','') for c in global_failures for f in c.findall('failure')]
        return [dict(case=name,status='fixture_failed',messages=messages,seconds=float(c.get('time','0'))) for c,name in zip(cases,names)]
    if not all(executed_case(case) for case in cases):return None
    rows=[]
    for case,name in zip(cases,names):
        failed=case.findall('failure');skipped=case.find('skipped')
        status='failed' if failed else 'skipped' if skipped is not None else 'passed'
        messages=[c.get('message','') for c in failed] if failed else [skipped.get('message','')] if skipped is not None else []
        rows.append(dict(case=name,status=status,messages=messages,seconds=float(case.get('time','0'))))
    for row in rows:
        if row['status'] == 'passed' and (failure := child_check_failure(row['case'], stderr)):
            row['status'], row['messages'] = failure
    return rows


def run(args,output,plan,env,runner,name,store,snapshot,cache,timeout):
    rows=[];serial=0;started=time.monotonic();disk_stopped=False
    # Affinity cases narrow the test process's mask without restoring it. A
    # later case must start with the environment's full configured CPU set.
    single={'affinity'}
    remaining_budget=lambda: not args.time_budget or time.monotonic()-started<args.time_budget

    def checkpoint():save(output/'results.json',rows)

    def record(suite,selected,status,stem,code,seconds,messages=None):
        for case in selected:
            rows.append(dict(suite=suite,case=case,status=status,code=code,seconds=seconds,messages=messages or [],log_stem=stem))
        checkpoint()

    def attempt(suite,selected):
        nonlocal serial,disk_stopped
        if not selected:return
        if not remaining_budget():record(suite,selected,'not_run_budget',None,None,0);return
        if disk_stopped:record(suite,selected,'not_run_disk_limit',None,None,0);return
        # TraceeWALL may leave its aborted child for a later wait(-1).
        if len(selected) > 1 and TRACEE_WAIT in selected:
            split = selected.index(TRACEE_WAIT)
            attempt(suite, selected[:split])
            attempt(suite, [TRACEE_WAIT])
            attempt(suite, selected[split + 1:])
            return
        if suite in single and len(selected)>1:
            for case in selected:attempt(suite,[case])
            return
        if store is not None:
            shutil.rmtree(store);subprocess.run(['/bin/cp','-cR',str(snapshot),str(store)],check=True)
        stem='chunk-%06d'%serial;serial+=1
        work='/tmp/gvisor-'+stem;guest_xml=work+'/result.xml';xml=output/'logs'/(stem+'.xml')
        wrapper='export TEST_SRCDIR=/opt/gvisor/runfiles RUNFILES_DIR=/opt/gvisor/runfiles; ' + guest_test_work(suite) + 'unset TEST_ON_GVISOR GVISOR_SAVE_TEST; shift; "$@" & child=$!; wait "$child"'
        if suite=='posix_acl':
            # Match native Linux's existing tmpfs fixture, without changing the
            # original binary or treating an unexercised ACL as a passing case.
            wrapper='mkdir -p /dev/shm; mount -t tmpfs -o mode=1777 tmpfs /dev/shm; '+wrapper
        terminal, wrapper = guest_terminal(suite, wrapper)
        argv=[runner,'debug','env-run',name,'--no-windows',terminal,'--','/bin/sh','-ec',wrapper,'trames-gvisor',work,'/opt/gvisor/'+suite+'_test',*suite_flags(suite),'--gtest_color=no','--gtest_filter='+':'.join(selected),'--gtest_output=xml:'+guest_xml]
        stdout=output/'logs'/(stem+'.stdout');stderr=output/'logs'/(stem+'.stderr')
        budget=lambda case:timeout(suite,case) if case else 30
        progress=Progress(stdout,selected,budget)
        code,timed,seconds=execute(argv,stdout,stderr,30+sum(timeout(suite,c) for c in selected),env=env,min_free=int(args.min_free_gib*1024**3),progress=progress)
        progress.remaining()
        if not timed:
            exported=subprocess.run([runner,'debug','env-run',name,'--fs','get',guest_xml,str(xml)],env=env,capture_output=True,timeout=20)
            if exported.returncode:(output/'logs'/(stem+'.export-error')).write_bytes(exported.stderr)
        parsed=xml_rows(xml,code,selected,stderr) if not timed else None
        if parsed is not None:
            for row in parsed:rows.append(dict(row,suite=suite,code=code,log_stem=stem,process_seconds=seconds,chunk_cases=len(selected)))
            checkpoint();print('trames',len(rows),suite,'chunk',len(selected),{r['status'] for r in parsed},flush=True);return
        if timed=='disk_limit':
            disk_stopped=True;record(suite,selected,'disk_limit',stem,code,seconds);return
        if len(selected)==1:
            status,messages=classify(xml,code,timed,selected[0]);record(suite,selected,status,stem,code,seconds,messages)
            print('trames',len(rows),suite,selected[0],status,flush=True);return
        # No result is accepted from stdout. Retry completed prefixes for XML,
        # isolate the active abort/timeout, then run the untouched remainder.
        completed=[c for c in selected if c in progress.completed]
        active=progress.active if progress.active in selected and progress.active not in completed else None
        if not completed and active==selected[0]:single.add(suite)
        if completed and len(completed)<len(selected):
            attempt(suite,completed)
            if active:attempt(suite,[active])
            attempt(suite,[c for c in selected if c not in completed and c!=active])
        elif active:
            attempt(suite,[active]);attempt(suite,[c for c in selected if c!=active])
        else:
            middle=len(selected)//2;attempt(suite,selected[:middle]);attempt(suite,selected[middle:])

    for suite in plan['suites']:
        pending=[]
        for case in suite['cases']:
            key=(suite['name'],case)
            if key in cache:rows.append(cache[key])
            else:pending.append(case)
        checkpoint()
        for start in range(0,len(pending),args.chunk_size):attempt(suite['name'],pending[start:start+args.chunk_size])
    return rows
