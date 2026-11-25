#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build an offline rootfs from installed Linux programs; pin all copied bytes."""
import argparse
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
from common import digest, save, tree_digest

TOOLS = '''sh bash env printf cat cmp diff mkdir rmdir rm cp mv ln stat find wc tr sort uniq grep sed awk cut tar gzip bzip2 xz sha256sum base64 python3 git git-upload-pack git-receive-pack curl ssh-keygen node gcc make as ld ip bridge ping mount umount sleep seq touch chmod head tail readlink'''.split()


def prepare(output):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    root = output / 'rootfs'
    for name in ['bin', 'usr/bin', 'tmp', 'work', 'dev', 'proc', 'sys', 'acceptance', 'run', 'var/run']:
        (root / name).mkdir(parents=True, exist_ok=True)
    (root / 'tmp').chmod(0o1777)
    copied = set()

    def copy(source, guest=None):
        source = Path(source)
        guest = Path(guest) if guest else source
        if not source.is_file():
            return
        target = root / str(guest).lstrip('/')
        if str(guest) in copied:
            return
        copied.add(str(guest))
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target, follow_symlinks=True)
        with source.open('rb') as f:
            elf = f.read(4) == b'\x7fELF'
        if elf:
            result = subprocess.run(['ldd', str(source)], capture_output=True, text=True)
            if result.returncode and not any(t in result.stdout + result.stderr for t in ['not a dynamic executable', 'statically linked']):
                raise RuntimeError(f'ldd failed for {source}: {result.stderr}')
            if 'not found' in result.stdout:
                raise RuntimeError(f'missing dependency for {source}: {result.stdout}')
            for line in result.stdout.splitlines():
                for item in line.split():
                    if item.startswith('/'):
                        copy(Path(item))

    tools = {}
    for name in TOOLS:
        path = str(Path('/usr/bin') / name) if (Path('/usr/bin') / name).is_file() else shutil.which(name)
        if path:
            copy(path, '/usr/bin/' + name)
            tools[name] = dict(source=str(Path(path).resolve()), sha256=digest(path))
        else:
            tools[name] = dict(missing=True)
    copy('/bin/sh', '/bin/sh')
    # Bind actual kernel devices only inside native.py's disposable mount ns.
    # Trames uses its own original pseudo devices.
    for name in ['null', 'zero', 'random', 'urandom']:
        (root / 'dev' / name).touch()
    for name in ['passwd', 'group', 'nsswitch.conf', 'hosts', 'services', 'protocols']:
        copy('/etc/' + name)
    for directory in ['/usr/share/git-core/templates', '/usr/share/nodejs', '/usr/share/zoneinfo']:
        source = Path(directory)
        if source.is_dir() and (directory != '/usr/share/nodejs' or 'missing' not in tools['node']):
            shutil.copytree(source, root / source.relative_to('/'), dirs_exist_ok=True)
    if 'missing' not in tools['python3']:
        command = [tools['python3']['source'], '-c', 'import sysconfig; print(sysconfig.get_path("stdlib"))']
        stdlib = Path(subprocess.check_output(command, text=True).strip())
        dest = root / stdlib.relative_to('/')
        shutil.copytree(stdlib, dest, ignore=shutil.ignore_patterns('__pycache__', 'site-packages', 'dist-packages'), dirs_exist_ok=True)
        for library in stdlib.rglob('*.so'):
            if not any(p in ('site-packages', 'dist-packages') for p in library.parts):
                copy(library)
    if 'missing' not in tools['gcc']:
        compiler = tools['gcc']['source']
        include = Path('/usr/include')
        shutil.copytree(include, root / include.relative_to('/'), dirs_exist_ok=True)
        gcc_lib = Path(subprocess.check_output([compiler, '-print-libgcc-file-name'], text=True).strip()).parent
        shutil.copytree(gcc_lib, root / gcc_lib.relative_to('/'), dirs_exist_ok=True)
        for library in gcc_lib.rglob('*'):
            if library.is_file() and (os.access(library, os.X_OK) or '.so' in library.name):
                copy(library)
        for name in ['cc1', 'collect2', 'lto-wrapper']:
            path = subprocess.check_output([compiler, '-print-prog-name=' + name], text=True).strip()
            if Path(path).is_absolute():copy(path)
        for name in ['Scrt1.o', 'crt1.o', 'crti.o', 'crtn.o', 'libc.so', 'libc.so.6', 'libc_nonshared.a', 'libm.so', 'libm.so.6', 'libmvec.so', 'libgcc_s.so.1']:
            path = subprocess.check_output([compiler, '-print-file-name=' + name], text=True).strip()
            if path != name:
                copy(path)
    record = dict(schema_version=1, machine=platform.machine(), host_kernel=platform.release(),
                  rootfs_sha256=tree_digest(root), tools=tools,
                  packages=subprocess.check_output(['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\n'], text=True).splitlines())
    save(output / 'bundle.json', record)
    print(f'bundle: {output}; {record["rootfs_sha256"]}; missing: {[k for k,v in tools.items() if v.get("missing")]}')
    return record


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if platform.system() != 'Linux':
        p.error('prepare on native Linux, then transfer the pinned bundle')
    prepare(a.output)
