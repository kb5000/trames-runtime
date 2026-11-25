#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Evidence and input identity for offline acceptance; never imported by runtime."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def identity(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def save(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    temporary.replace(path)


def extended_attributes(path):
    if hasattr(os, 'listxattr'):
        return {name:os.getxattr(path,name,follow_symlinks=False).hex()
                for name in sorted(os.listxattr(path,follow_symlinks=False))}
    # macOS Python has no os xattr API. This path is test tooling only.
    if __import__('sys').platform == 'darwin':
        names=subprocess.check_output(['/usr/bin/xattr','-s',str(path)],text=True).splitlines()
        return {name:''.join(subprocess.check_output(['/usr/bin/xattr','-p','-s','-x',name,str(path)],text=True).split()).lower()
                for name in sorted(names)}
    raise ValueError('no extended-attribute reader for this acceptance host')


def tree_digest(root):
    """Hash bytes and permission-relevant metadata without following symlinks."""
    root = Path(root)
    h = hashlib.sha256()
    info=root.lstat()
    h.update(canonical(['.',stat.S_IMODE(info.st_mode),info.st_uid,info.st_gid,info.st_mtime_ns,extended_attributes(root)]))
    for directory, names, files in os.walk(root, followlinks=False):
        names.sort()
        for name in sorted(names + files):
            p = Path(directory) / name
            info = p.lstat()
            mode = info.st_mode
            if stat.S_ISLNK(mode):
                value = ['link', os.readlink(p)]
            elif stat.S_ISDIR(mode):
                value = ['dir']
            elif stat.S_ISREG(mode):
                value = ['file', digest(p)]
            else:
                raise ValueError(f'unsupported bundle entry: {p}')
            attributes = extended_attributes(p)
            h.update(canonical([str(p.relative_to(root)), stat.S_IMODE(mode), info.st_uid, info.st_gid, info.st_mtime_ns, attributes, value]))
            h.update(b'\0')
    return h.hexdigest()


def source_identity(root):
    root = Path(root).resolve()
    paths = subprocess.check_output(
        ['git', 'ls-files', '-c', '-o', '--exclude-standard', '-z'], cwd=root).split(b'\0')
    entries = []
    for raw in sorted(set(paths)):
        if not raw:
            continue
        name = os.fsdecode(raw)
        if name.startswith(('docs/', 'tests/', '.github/')) or name.endswith('.md'):
            continue
        p = root / name
        if p.is_symlink():
            entries.append([name, 'link', os.readlink(p)])
        elif p.is_file():
            entries.append([name, p.stat().st_mode & 0o777, digest(p)])
        elif p.is_dir() and (p/'.git').exists():
            entries.append([name, 'submodule', source_identity(p)['inputs_sha256']])
        elif not p.exists():
            entries.append([name, 'deleted'])
        # Gitlinks are separate, explicitly fingerprinted source repositories.
    return dict(
        commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
        dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=root)),
        inputs_sha256=identity(entries),
    )


def guest_path(root, name):
    """Resolve image symlinks using guest /, never the host filesystem's /."""
    from collections import deque
    root = Path(root).resolve()
    pending = deque(Path(name).parts); parts = []; hops = 0
    while pending:
        part = pending.popleft()
        if part in ('/', '.', ''): continue
        if part == '..':
            if parts: parts.pop()
            continue
        candidate = root.joinpath(*parts, part)
        if candidate.is_symlink():
            hops += 1
            if hops > 40: raise ValueError('image symlink loop: ' + name)
            target = Path(os.readlink(candidate))
            if target.is_absolute(): parts.clear()
            pending.extendleft(reversed(target.parts))
        else: parts.append(part)
    return root.joinpath(*parts)


def load_manifest(path):
    data = json.loads(Path(path).read_text())
    if data.get('schema_version') != 1 or not isinstance(data.get('cases'), list) or not data['cases']:
        raise ValueError('expected a nonempty version 1 acceptance manifest')
    if set(data)-{'schema_version','description','cases'}:
        raise ValueError('unknown manifest fields')
    seen = set()
    import re
    for case in data['cases']:
        if set(case)-{'id','domain','tier','requires','script','stdout','stderr','exit_code','timeout','artifacts','diagnostics','pty','console'}:
            raise ValueError('unknown case fields')
        if not isinstance(case.get('domain'),str) or not case['domain'] or case.get('tier') not in ('smoke','apps'):
            raise ValueError('invalid case domain/tier')
        if not re.fullmatch(r'[a-z0-9][a-z0-9_.-]*', case.get('id', '')) or case['id'] in seen:
            raise ValueError('invalid or duplicate case id')
        seen.add(case['id'])
        if not isinstance(case.get('script'), str) or not case['script'].strip():
            raise ValueError(f'{case["id"]}: missing script')
        if not isinstance(case.get('stdout'), str) or not isinstance(case.get('stderr', ''), str):
            raise ValueError(f'{case["id"]}: expected exact text output')
        if not isinstance(case.get('exit_code', 0), int):
            raise ValueError(f'{case["id"]}: invalid exit code')
        if case.get('console') not in (None,'diagnostic') or case.get('console') and (case.get('stdout') != '' or not case.get('artifacts')): raise ValueError('diagnostic console requires empty asserted stdout')
        if not isinstance(case.get('pty',False),bool): raise ValueError('invalid pty flag')
        timeout = case.get('timeout', 30)
        if not isinstance(timeout, (float, int)) or not 0 < timeout <= 600:
            raise ValueError(f'{case["id"]}: invalid timeout')
        for key in ('requires', 'artifacts', 'diagnostics'):
            values = case.get(key, [])
            if not isinstance(values, list) or not all(isinstance(v, str) and v.startswith('/') and '..' not in Path(v).parts for v in values):
                raise ValueError(f'{case["id"]}: invalid {key}')
        if any(not p.startswith('/work/') for p in case.get('artifacts', []) + case.get('diagnostics', [])):
            raise ValueError(f'{case["id"]}: artifacts must be under /work')
    return data
