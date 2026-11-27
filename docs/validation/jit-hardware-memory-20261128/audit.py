#!/usr/bin/env python3
"""Audit frozen, balanced four-lane samples; optionally verify owning sources."""
import argparse,copy,gzip,hashlib,json,statistics
from collections import Counter
from pathlib import Path

ROOT=Path(__file__).resolve().parent

def audit(records,receipt):
    expected={(i,j,lane) for i,order in enumerate(receipt['orders'],1) for j,lane in enumerate(order,1)}
    assert set(records)==expected
    positions=Counter((lane,j) for _,j,lane in records)
    assert all(n==2 for n in positions.values()) and len(positions)==16
    groups={}; references={}
    for (i,j,lane),rows in records.items():
        if lane=='kvm':
            h=next(r['doctor'] for r in rows if r['kind']=='host')
            assert h['kvm_api_version']==12 and h['host_page_size']==4096 and h['smccc_forwarding']
        workloads=[r for r in rows if r['kind']=='workload']
        assert len(workloads)==6 and len({r['workload'] for r in workloads})==6
        for r in workloads:
            assert r['backend']==('jit' if lane in ('new','old') else lane)
            assert r['mode']=='worker-private' and r['exact_instructions']==(lane!='kvm')
            ss=r['samples']; assert len(ss)==6 and ss[0]['warmup'] and not any(s['warmup'] for s in ss[1:])
            assert all(s['ns']>0 for s in ss)
            assert r['median_ns']==statistics.median(s['ns'] for s in ss[1:])
            identity={k:r[k] for k in ['mode','words','iterations','trips','logical_guest_instructions','final_data','final_pc','final_x0']}
            identity['states']=[(s['x0'],s['pc']) for s in ss]
            name=r['workload']; assert references.setdefault(name,identity)==identity
            for s in ss:
                assert s['pc']==r['final_pc'] and s['calls']==s['syscalls']+s['yields'] and s['syscalls']==r['trips']
                assert s['observed_instructions']==(r['logical_guest_instructions'] if lane!='kvm' else None)
            if lane in ('new','old'):
                d=r['diagnostics']; assert d['fallback_instructions']==0 and d['staged']==0
                assert 0<=d['hardware']<=d['memory_instructions']
                if lane=='new' and name.startswith('memory'):
                    assert d['hardware']>=d['memory_instructions']*.999
            groups.setdefault(name,{}).setdefault(lane,[]).append(r['median_ns'])
    return {name:{lane:{'median_ns':statistics.median(values),'process_medians_ns':values} for lane,values in lanes.items()} for name,lanes in groups.items()}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-source',type=Path)
    args=parser.parse_args()
    receipt=json.loads(gzip.decompress((ROOT/'receipt.json.gz').read_bytes()))
    records={}
    for p in sorted(ROOT.glob('round-*.jsonl')):
        _,i,j,lane=p.stem.split('-')
        records[int(i),int(j),lane]=[json.loads(line) for line in p.read_text().splitlines()]
    summary=audit(records,receipt)
    assert summary==json.loads((ROOT/'summary.json').read_text())
    negatives=[]
    for kind in ['missing-process','changed-instructions','false-median','false-kvm-count','false-hardware-hit']:
        bad=copy.deepcopy(records)
        key=next(k for k in bad if k[2]=='new')
        r=next(r for r in bad[key] if r.get('workload')=='memory-1m')
        if kind=='missing-process': del bad[key]
        elif kind=='changed-instructions': r['words'][0]^=1
        elif kind=='false-median': r['median_ns']+=1
        elif kind=='false-hardware-hit': r['diagnostics']['hardware']=0
        else:
            key=next(k for k in bad if k[2]=='kvm')
            next(r for r in bad[key] if r['kind']=='workload')['samples'][0]['observed_instructions']=1
        try: audit(bad,receipt)
        except AssertionError: negatives.append(kind)
        else: raise AssertionError('accepted negative case: '+kind)
    verified=0
    if args.runtime_source:
        for rel,sha in receipt['inputs']['new'].items():
            if rel.startswith('runtime/'):
                assert hashlib.sha256((args.runtime_source/rel[8:]).read_bytes()).hexdigest()==sha,rel
                verified+=1
    print(json.dumps({'processes':len(records),'workloads':len(summary),'timed_samples':960,'warmup_samples':192,'negative_cases_rejected':negatives,'runtime_source_files_verified':verified},indent=2))
if __name__=='__main__': main()
