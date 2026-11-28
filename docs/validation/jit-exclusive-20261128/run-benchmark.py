#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Four balanced same-host CPU-only old/new pairs; no build during timing."""
import argparse
import hashlib
import json
import statistics
import subprocess
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--old',type=Path,required=True)
p.add_argument('--new',type=Path,required=True)
p.add_argument('--out',type=Path,required=True)
a=p.parse_args()
assert a.old.read_bytes()!=a.new.read_bytes(), 'identical binaries invalidate the comparison'
raw=[]
for pair in range(4):
    order=['old','new'] if pair%2==0 else ['new','old']
    for ordinal,kind in enumerate(order):
        result=subprocess.run([str(getattr(a,kind))],text=True,capture_output=True,check=True)
        rows=[json.loads(line) for line in result.stdout.splitlines()]
        assert len(rows)==30
        for row in rows:
            if kind=='new':
                assert row['fallback']==0
                assert row['native']==row['retired']-row['rounds']
            elif not row['workload'].startswith('control'):
                assert row['fallback']>=2*262144
            row.update(variant=kind,pair=pair,ordinal=ordinal)
        raw+=rows
workloads=sorted({row['workload'] for row in raw})
summary={}
for workload in workloads:
    medians={kind:[statistics.median(r['ns'] for r in raw if r['variant']==kind and r['pair']==pair and r['workload']==workload and not r['warmup']) for pair in range(4)] for kind in ['old','new']}
    summary[workload]={'process_medians_ns':medians,
        'median_old_ns':statistics.median(medians['old']),
        'median_new_ns':statistics.median(medians['new']),
        'speedup':statistics.median(medians['old'])/statistics.median(medians['new'])}
a.out.mkdir(parents=True,exist_ok=True)
(a.out/'benchmark.jsonl').write_text(''.join(json.dumps(row,sort_keys=True)+'\n' for row in raw))
report={'baseline':'767b92efb81251861576cefdf676a8bb4f15a4e3',
    'trips':262144,'control_rounds':64,'processes':8,'timed_samples':200,'warmups':40,
    'binary_sha256':{kind:hashlib.sha256(getattr(a,kind).read_bytes()).hexdigest() for kind in ['old','new']},
    'workloads':summary}
(a.out/'benchmark-summary.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps(report,indent=2))
