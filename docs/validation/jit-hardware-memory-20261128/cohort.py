import hashlib,json,os,statistics,subprocess
from pathlib import Path
out=Path('/mnt/trames-output/jit-hardware-results')
orders=[['old','new','interpreter','kvm'],['new','kvm','old','interpreter'],['interpreter','old','kvm','new'],['kvm','interpreter','new','old']]*2
refs={}; groups={}
for round_,order in enumerate(orders,1):
    for position,lane in enumerate(order,1):
        binary=Path('/mnt/trames-output/jit-hardware-old' if lane=='old' else '/mnt/trames-output/jit-hardware-new')
        backend='jit' if lane in ('new','old') else lane
        command=['taskset','-c','2',str(binary),backend,'worker-private']
        r=subprocess.run(command,env=dict(os.environ,TRAMES_KVM_TRANSPORT='smccc'),capture_output=True,timeout=90)
        p=out/f'round-{round_}-{position}-{lane}.jsonl'
        p.write_bytes(r.stdout); p.with_suffix('.stderr').write_bytes(r.stderr)
        assert r.returncode==0,(lane,r.returncode,r.stderr)
        records=[json.loads(line) for line in r.stdout.splitlines()]
        if lane=='kvm':
            host=next(r['doctor'] for r in records if r['kind']=='host')
            assert host['kvm_api_version']==12 and host['host_page_size']==4096 and host['smccc_forwarding']
        rows=[r for r in records if r['kind']=='workload']; assert len(rows)==6
        for row in rows:
            name=row['workload']; samples=row['samples']; assert len(samples)==6
            assert samples[0]['warmup'] and not any(s['warmup'] for s in samples[1:])
            assert row['median_ns']==statistics.median(s['ns'] for s in samples[1:])
            identity={k:row[k] for k in ['mode','words','iterations','trips','logical_guest_instructions','final_data','final_pc','final_x0']}
            identity['states']=[(s['x0'],s['pc']) for s in samples]
            assert refs.setdefault(name,identity)==identity,(name,lane,'work mismatch')
            for s in samples:
                assert s['pc']==row['final_pc'] and s['calls']==s['syscalls']+s['yields'] and s['syscalls']==row['trips']
                assert s['observed_instructions']==(row['logical_guest_instructions'] if lane!='kvm' else None)
            if backend=='jit': assert row['diagnostics']['fallback_instructions']==0 and row['diagnostics']['staged']==0
            if lane=='new' and name.startswith('memory'):
                d=row['diagnostics']; assert d['hardware']>=d['memory_instructions']*0.999
            groups.setdefault(name,{}).setdefault(lane,[]).append(row['median_ns'])
        print(f'round {round_}/8 {lane}: payload/state/hardware audit passed',flush=True)
summary={name:{lane:{'median_ns':statistics.median(values),'process_medians_ns':values} for lane,values in lanes.items()} for name,lanes in groups.items()}
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
receipt={'orders':orders,'mode':'worker-private','data':'resident zero before View construction','cpu':2,'warmups_per_process':1,'timed_per_process':5,'runtime_baseline':'89c5abd57ce5cc8341f17fcea35a339b0f991595','linux_source':'9db947eba448b871f31ca06511c46430bfb35387','binaries':{lane:hashlib.sha256(Path('/mnt/trames-output/jit-hardware-'+lane).read_bytes()).hexdigest() for lane in ['old','new']},'inputs':{}}
for label,source in [('old',Path('/mnt/trames-output/jit-hardware-baseline')),('new',Path('/mnt/trames-output/jit-hardware-benchmark'))]:
    hashes={}
    for directory in ['runtime/crates','crates/trames-kvm','tools/cpu-backends']:
        for p in (source/directory).rglob('*'):
            if p.is_file() and p.suffix in ['.rs','.toml','.lock','.S','.c','.h']: hashes[str(p.relative_to(source))]=hashlib.sha256(p.read_bytes()).hexdigest()
    for name in ['Cargo.toml','Cargo.lock','rust-toolchain.toml','runtime/Cargo.toml','runtime/Cargo.lock']:
        hashes[name]=hashlib.sha256((source/name).read_bytes()).hexdigest()
    receipt['inputs'][label]=hashes
(out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(summary,indent=2))
