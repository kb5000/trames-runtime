#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare case outcomes, keeping reference failures/skips out of the oracle."""
import argparse
import collections
import json
from pathlib import Path


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--native',type=Path,required=True)
    p.add_argument('--native-retry',type=Path,action='append',default=[])
    p.add_argument('--trames',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    native=json.loads((a.native/'results.json').read_text())
    guest=json.loads((a.trames/'results.json').read_text())
    reference=json.loads((a.native/'plan.json').read_text())
    target=json.loads((a.trames/'plan.json').read_text())
    def identities(plan):return {s['name']:s['sha256'] for s in plan['suites']}
    if identities(reference)!=identities(target):raise RuntimeError('The native and guest binaries differ')
    key=lambda r:(r['suite'],r['case'])
    oracle={key(r):dict(r,source=str(a.native)) for r in native}
    for directory in a.native_retry:
        retry_plan=json.loads((directory/'plan.json').read_text())
        if identities(reference)!=identities(retry_plan):raise RuntimeError('Retry used different binaries')
        for row in json.loads((directory/'results.json').read_text()):
            if key(row) not in oracle:raise RuntimeError('Retry case was not in the original selection')
            oracle[key(row)]=dict(row,source=str(directory),retried=True)
    if set(oracle)!={key(r) for r in guest}:raise RuntimeError('Native and guest selections differ')
    pairs=[dict(suite=r['suite'],case=r['case'],native=oracle[key(r)],trames=r) for r in guest]
    groups=[]
    for suite in reference['suites']:
        selected=[r for r in pairs if r['suite']==suite['name']]
        groups.append(dict(name=suite['name'],cases=len(selected),native=dict(collections.Counter(r['native']['status'] for r in selected)),trames=dict(collections.Counter(r['trames']['status'] for r in selected))))
    comparable=[r for r in pairs if r['native']['status']=='passed']
    counts=dict(collections.Counter(r['trames']['status'] for r in comparable))
    result=dict(schema_version=1,cases=len(pairs),native_counts=dict(collections.Counter(r['native']['status'] for r in pairs)),trames_counts=dict(collections.Counter(r['trames']['status'] for r in pairs)),native_passed_cases=len(comparable),outcomes_on_native_passed=counts,strict_pass_fraction=counts.get('passed',0)/len(comparable) if comparable else None,groups=groups,details=pairs)
    a.output.mkdir(parents=True,exist_ok=True)
    (a.output/'comparison.json').write_text(json.dumps(result,indent=2)+'\n')
    lines=['| Group | Cases | Native pass / nonpass | Pass | Assertion | Fixture | Abnormal | Timeout | Skip | Unrun/resource |','|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for g in groups:
        n,t=g['native'],g['trames']
        abnormal=sum(t.get(k,0) for k in ['no_result','crashed','invalid_result','mismatched_result'])
        unrun=sum(v for k,v in t.items() if k.startswith('not_run') or k=='disk_limit')
        lines.append(f"| {g['name']} | {g['cases']} | {n.get('passed',0)} / {sum(n.values())-n.get('passed',0)} | {t.get('passed',0)} | {t.get('failed',0)} | {t.get('fixture_failed',0)} | {abnormal} | {t.get('timeout',0)} | {t.get('skipped',0)} | {unrun} |")
    (a.output/'table.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ['groups','details']},indent=2))

if __name__=='__main__':main()
