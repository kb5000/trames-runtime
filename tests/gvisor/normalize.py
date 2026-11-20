#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Audit saved XML and refine GTest global fixture failures without rerunning.

Raw evidence is immutable. This never promotes a missing/mismatched report to
success; every reported pass must have its exact original passing XML case.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import shutil
import xml.etree.ElementTree as ET

from run import tracee_fixture_error


def normalize(source,output):
    output.mkdir(parents=True,exist_ok=False)
    rows=json.loads((source/'results.json').read_text());cache={};refined=0;passes=0
    for row in rows:
        stem=Path(row['reused_from']) if row.get('reused_from') else source/row['logs']
        row['evidence_stem']=str(stem.resolve());xml=stem.with_suffix('.xml')
        if xml.exists() and xml not in cache:
            try:cache[xml]=ET.parse(xml).findall('.//testcase')
            except ET.ParseError:cache[xml]=[]
        cases=cache.get(xml,[])
        matching=[c for c in cases if c.get('classname','')+'.'+c.get('name','')==row['case']]
        fixture=[c for c in cases if c.get('classname')=='' and c.get('name')=='' and c.findall('failure')]
        if fixture and len(matching)==1:
            row['classification_refined_from']=row['status'];row['status']='fixture_failed'
            row['messages']=[f.get('message','') for c in fixture for f in c.findall('failure')];refined+=1
        elif row['status']=='passed':
            assert len(matching)==1 and not matching[0].findall('failure') and matching[0].find('skipped') is None, ('Missing original passing XML',row['suite'],row['case'])
            assert row['code'] in (0,1),row
            if row['code']==1:assert any(c.findall('failure') for c in cases),row
            if error := tracee_fixture_error(row['case'], stem.with_suffix('.stderr')):
                row.update(classification_refined_from='passed',status='fixture_failed',messages=[error])
                refined+=1
            else:
                passes+=1
        elif row['status']=='skipped' and len(matching)==1 and matching[0].findall('failure'):
            row['classification_refined_from']='skipped';row['status']='failed'
            row['messages']=[f.get('message','') for f in matching[0].findall('failure')];refined+=1
    assert len({(r['suite'],r['case']) for r in rows})==len(rows)
    shutil.copy2(source/'plan.json',output/'plan.json')
    (output/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
    report=dict(cases=len(rows),counts=dict(collections.Counter(r['status'] for r in rows)),original_passing_xml_verified=passes,fixture_classifications_refined=refined,raw_results_sha256=hashlib.sha256((source/'results.json').read_bytes()).hexdigest(),raw_source=str(source.resolve()))
    (output/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();normalize(a.source,a.output)
