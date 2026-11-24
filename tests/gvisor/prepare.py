#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prepare pinned, unmodified C++ syscall sources; optionally build on ARM64 Linux."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile
import urllib.request

HERE = Path(__file__).resolve().parent

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def fetch(url, expected, path):
    if path.is_file() and sha(path) == expected:
        return path
    if path.exists():
        raise RuntimeError('Cached source checksum differs: '+str(path))
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.download-'+str(os.getpid()))
    try:
        with urllib.request.urlopen(url,timeout=60) as response, temp.open('wb') as output:
            shutil.copyfileobj(response,output,1024*1024)
        if sha(temp)!=expected:raise RuntimeError('Source checksum mismatch: '+url)
        temp.replace(path)
    finally:
        if temp.exists():temp.unlink()
    return path

def extract(archive, root, test_only=False):
    root.mkdir(parents=True,exist_ok=True)
    with tarfile.open(archive) as tar:
        for item in tar:
            parts=Path(item.name).parts[1:]
            if not parts or not item.isfile():continue
            relative=Path(*parts)
            if relative.is_absolute() or '..' in parts:raise RuntimeError('Invalid source path')
            if test_only and str(relative) not in ['LICENSE','.bazelrc','MODULE.bazel'] and not str(relative).startswith(('test/syscalls/','test/util/')):continue
            path=root/relative
            data=tar.extractfile(item).read()
            if path.exists():
                if path.read_bytes()!=data:raise RuntimeError('Source was edited; refusing to replace '+str(path))
            else:
                path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);path.chmod(item.mode&0o777)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--cache',type=Path)
    p.add_argument('--build',action='store_true')
    p.add_argument('--jobs',type=int,default=4)
    p.add_argument('--export',type=Path)
    p.add_argument('--expanded',action='store_true',help='Resolve all ARM64 C++ syscall targets and record build blockers')
    a=p.parse_args()
    if a.jobs<1:p.error('jobs must be positive')
    root=a.output.resolve();root.mkdir(parents=True,exist_ok=True)
    cache=(a.cache or root/'downloads').resolve()
    spec=json.loads((HERE/'upstream.json').read_text())
    source=fetch(spec['gvisor']['url'],spec['gvisor']['sha256'],cache/'gvisor.tar.gz')
    extract(source,root/'source',test_only=True)
    names={}
    for dep in spec['dependencies']:
        name=dep['name'];archive=fetch(dep['url'],dep['sha256'],cache/(name+'-pinned.tar.gz'))
        extract(archive,root/(name+'-pinned'));names[name]=root/(name+'-pinned')
    for source in spec['runfiles']:
        name=Path(source['url']).name
        cached=fetch(source['url'],source['sha256'],cache/name)
        destination=root/'source/tools/cpp/runfiles'/name
        destination.parent.mkdir(parents=True,exist_ok=True)
        if destination.exists() and destination.read_bytes()!=cached.read_bytes():raise RuntimeError('Edited runfiles source')
        if not destination.exists():shutil.copyfile(cached,destination)
    (root/'inputs.json').write_text(json.dumps(spec,indent=2)+'\n')
    if not a.build:
        print('Prepared checksum-verified source:',root);return
    args=['cmake','-S',str(HERE),'-B',str(root/'build'),'-G','Ninja','-DCMAKE_BUILD_TYPE=Release',
          '-DGVISOR_SOURCE='+str(root/'source'),'-DABSL_SOURCE='+str(names['abseil']),
          '-DGTEST_SOURCE='+str(names['googletest']),'-DBENCHMARK_SOURCE='+str(names['benchmark'])]
    manifest = None
    if a.expanded:
        from build_graph import generate
        manifest = generate(root/'source', root/'graph')
        args.append('-DGVISOR_EXPANDED_GRAPH='+str(root/'graph/expanded.cmake'))
    subprocess.run(args,check=True)
    from run import SUITES
    if manifest:
        targets=[s['target'] for s in manifest['suites']]+[s.get('build_target',s['target']) for s in manifest['runfiles'] if 'target' in s]
        result=subprocess.run(['cmake','--build',str(root/'build'),'--parallel',str(a.jobs),'--target',*targets,'--','-k','0'])
        suites=[s['name'] for s in manifest['suites']]
    else:
        subprocess.run(['cmake','--build',str(root/'build'),'--parallel',str(a.jobs),'--target']+[s+'_test' for s in SUITES],check=True)
        suites=SUITES
    records=[]
    if a.export:a.export.mkdir(parents=True,exist_ok=True)
    unavailable=[]
    for suite in suites:
        binary=root/'build'/(suite+'_test')
        if not binary.is_file():
            unavailable.append(suite);continue
        data=binary.read_bytes()
        if data[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<H',data,18)[0]!=183:raise RuntimeError('Expected little-endian ARM64 ELF')
        phoff=struct.unpack_from('<Q',data,32)[0];size,count=struct.unpack_from('<HH',data,54)
        if any(struct.unpack_from('<I',data,phoff+i*size)[0]==3 for i in range(count)):raise RuntimeError('Test must be statically linked')
        records.append(dict(suite=suite,sha256=sha(binary),bytes=len(data)))
        if a.export:shutil.copy2(binary,a.export/binary.name)
    record=dict(unavailable=unavailable, expanded=bool(manifest), inputs=spec,kernel=os.uname().release,compiler=subprocess.check_output(['c++','--version'],text=True),binaries=records)
    (root/'build-record.json').write_text(json.dumps(record,indent=2)+'\n')
    if a.export:
        shutil.copy2(root/'build-record.json',a.export.parent/'build-record.json')
        if manifest:
            for asset in manifest['runfiles']:
                src=root/'build'/asset['target'] if 'target' in asset else root/'source'/asset['source']
                if src.is_file():
                    dest=a.export/'runfiles/_main'/asset['path'];dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dest);dest.chmod(0o755)
            shutil.copy2(root/'graph/expanded.json',a.export.parent/'expanded.json')
    print('Built',len(records),'static ARM64 syscall binaries')

if __name__=='__main__':main()
