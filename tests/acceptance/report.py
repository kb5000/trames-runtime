#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Merge application acceptance lanes without counting missing work as success."""
import argparse
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from common import save, identity
from run import verified_evidence


def generate(inputs, output):
    output.mkdir(parents=True,exist_ok=False)
    lanes={}; case_ids=set()
    for label,directory in inputs:
        if label in lanes:raise ValueError('duplicate lane: '+label)
        if not (directory/'plan.json').exists():
            lanes[label]=dict(plan=None,rows={},evidence=str(directory.resolve()),infrastructure_error='missing lane plan')
            continue
        plan=json.loads((directory/'plan.json').read_text())
        path=directory/'results.json'
        result=json.loads(path.read_text()) if path.exists() else dict(cases=[])
        rows={r['id']:r for r in result['cases']}
        if len(rows)!=len(result['cases']):raise ValueError('duplicate case in '+label)
        expected={c['id'] for c in plan['cases']}
        if set(rows)-expected:raise ValueError('unexpected cases in '+label)
        for case in plan['cases']:
            case_id=case['id']
            row=rows.setdefault(case_id,dict(id=case_id,status='not_run'))
            if row['status']=='passed':
                inputs=identity(dict(case=case,rootfs=plan['bundle_sha256'],harness=plan['harness_sha256']))
                fp=identity(dict(inputs=inputs,provider=plan['provider'],host={k:v for k,v in plan['host'].items() if k!='cpu'}))
                if not verified_evidence(directory,row,case,fp):
                    rows[case_id]=dict(row,status='infrastructure_error',reason='passing evidence failed independent audit')
        lanes[label]=dict(plan=plan,rows=rows,evidence=str(directory.resolve()))
        case_ids.update(expected)
    for lane in lanes.values():
        if lane['plan'] is None:
            lane['rows']={name:dict(id=name,status='infrastructure_error',reason=lane['infrastructure_error']) for name in case_ids or {'__infrastructure__'}}
    lines=['# Runtime application acceptance','','Each cell is one workflow in one execution configuration. Missing/blocked/reference failures do not count as passes.','','| Workflow | '+' | '.join(lanes)+' |','| --- | '+' | '.join('---' for _ in lanes)+' |']
    xml=ET.Element('testsuites'); counts={}; total_failed=0
    for label,lane in lanes.items():
        suite=ET.SubElement(xml,'testsuite',name=label,tests=str(len(lane['rows'])))
        counts[label]={}
        for case_id,row in sorted(lane['rows'].items()):
            status=row['status'];counts[label][status]=counts[label].get(status,0)+1
            node=ET.SubElement(suite,'testcase',name=case_id,classname=label,time=str(row.get('seconds',0)))
            if status!='passed':
                total_failed+=1
                failure=ET.SubElement(node,'failure',type=status,message=row.get('reason',status))
                folder=Path(lane['evidence'])/'cases'/case_id
                failure.text='\n'.join((folder/name).read_text(errors='replace')[:4000] for name in ['stdout','stderr'] if (folder/name).exists())
        suite.set('failures',str(sum(v for k,v in counts[label].items() if k!='passed')))
    for case_id in sorted(case_ids):
        values=[]
        for lane in lanes.values():
            row=lane['rows'].get(case_id)
            values.append(row['status']+(' (reused)' if row.get('reused') else '') if row else 'not_selected')
        lines.append('| '+case_id+' | '+' | '.join(values)+' |')
    lines.extend(['','Timing includes setup/startup and is not a qualified performance comparison.',''])
    (output/'report.md').write_text('\n'.join(lines))
    ET.ElementTree(xml).write(output/'junit.xml',encoding='utf-8',xml_declaration=True)
    save(output/'summary.json',dict(schema_version=1,counts=counts,lanes=lanes,workflow_count=len(case_ids),failed_cells=total_failed,performance_qualified=False))
    print('\n'.join(lines));return 1 if total_failed else 0


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',action='append',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    inputs=[]
    for value in a.input:
        label,path=value.split('=',1);inputs.append((label,Path(path)))
    raise SystemExit(generate(inputs,a.output))
