# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate the three pinned OCI inputs for modern-mount-oci.sh."""
from pathlib import Path
import json,copy,hashlib
import argparse
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('output', type=Path)
out = p.parse_args().output
out.mkdir(parents=True, exist_ok=True)
base={'ociVersion':'1.2.1','process':{'terminal':False,'user':{'uid':0,'gid':0},'args':[], 'env':['PATH=/bin:/usr/bin:/sbin:/usr/sbin'],'cwd':'/','noNewPrivileges':True,'capabilities':{'bounding':[],'effective':[],'permitted':[]}},'root':{'path':'rootfs','readonly':False},'hostname':'modern','linux':{'namespaces':[{'type':n} for n in ['pid','mount','uts','ipc']]},'mounts':[{'destination':'/proc','type':'proc','source':'proc','options':['nosuid','noexec','nodev']},{'destination':'/dev','type':'tmpfs','source':'tmpfs','options':['nosuid','mode=755','size=16m']},{'destination':'/dev/pts','type':'devpts','source':'devpts','options':['nosuid','noexec','newinstance','ptmxmode=0666','mode=0620','gid=5']}]}
for name in ['recursive','idmap','recursive-idmap']:
 x=copy.deepcopy(base)
 m={'destination':'/mapped','type':'none','source':'/work/src','options':[]}
 if name=='recursive':
  m['options']=['rbind','rro','rnoexec','rnosuid'];payload='test "$(cat /mapped/file)" = root; test "$(cat /mapped/child/file)" = child; ! touch /mapped/no; ! touch /mapped/child/no'
 else:
  x['process']['user']={'uid':100000,'gid':200000}
  m['uidMappings']=[{'containerID':0,'hostID':100000,'size':65536}];m['gidMappings']=[{'containerID':0,'hostID':200000,'size':65536}]
  m['options']=['bind','idmap'] if name=='idmap' else ['rbind','ridmap','rro','rnoexec','rnosuid']
  payload='test "$(stat -c %u:%g /mapped/file)" = 100000:200000; test "$(cat /mapped/file)" = root; '
  if name=='idmap':payload+='touch /mapped/new; test "$(stat -c %u:%g /mapped/new)" = 100000:200000'
  else:payload+='test "$(stat -c %u:%g /mapped/child/file)" = 100000:200000; test "$(cat /mapped/child/file)" = child; ! touch /mapped/no; ! touch /mapped/child/no'
 x['mounts'].append(m);x['process']['args']=['/bin/sh','-ec',payload]
 (out/(name+'.json')).write_text(json.dumps(x,indent=2)+'\n')
(out/'manifest.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.glob('*.json') if p.name!='manifest.json'},indent=2)+'\n')
