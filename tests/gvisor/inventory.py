#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Record enabled/disabled original cases without changing upstream selection."""
import argparse
import json
from pathlib import Path
import re
import subprocess

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--binaries',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();record=json.loads((a.binaries.parent/'build-record.json').read_text())
rows=[]
for entry in record['binaries']:
    result=subprocess.run([str(a.binaries/(entry['suite']+'_test')),'--gtest_list_tests'],capture_output=True,text=True,timeout=20)
    enabled,disabled=[],[];suite=None
    for raw in result.stdout.splitlines():
        line=raw.split('#',1)[0].rstrip()
        if not line:continue
        if not raw.startswith(' ') and line.endswith('.'):suite=line[:-1]
        elif raw.startswith('  ') and suite:
            case=suite+'.'+line.strip()
            target=disabled if any(part.startswith('DISABLED_') for part in re.split(r'[./]',case)) else enabled
            target.append(case)
    rows.append(dict(suite=entry['suite'],sha256=entry['sha256'],enabled=enabled,disabled=disabled,list_exit_code=result.returncode))
a.output.write_text(json.dumps(dict(groups=rows,enabled=sum(len(r['enabled']) for r in rows),disabled=sum(len(r['disabled']) for r in rows)),indent=2)+'\n')
print('Enabled:',sum(len(r['enabled']) for r in rows),'Upstream disabled:',sum(len(r['disabled']) for r in rows))
