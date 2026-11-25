#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Private-namespace native reference entry. Invoked by run.py, never a daemon."""
import os
from pathlib import Path
import subprocess
import sys


def main():
    root = Path(sys.argv[1]).resolve()
    # netns exec changes root mount propagation; chroot alone is not a
    # mountpoint. Preserve the private proc mount while giving / its own mount.
    subprocess.run(['/usr/bin/mount','--rbind',str(root),str(root)],check=True)
    # This helper runs only under unshare --mount --pid --net --uts --ipc.
    # Actual kernel devices preserve native semantics without privileged nodes
    # in the portable bundle. All mounts disappear with this process namespace.
    for name in ('null', 'zero', 'random', 'urandom'):
        subprocess.run(['/usr/bin/mount', '--bind', '/dev/' + name, str(root / 'dev' / name)], check=True)
    os.chroot(root)
    os.chdir('/work')
    environment = dict(PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', LANG='C', LC_ALL='C', TZ='UTC', HOME='/work', TMPDIR='/tmp', PYTHONHASHSEED='0')
    os.execve('/bin/sh', ['/bin/sh', '/acceptance/case.sh'], environment)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'acceptance infrastructure: {error}', file=sys.stderr)
        sys.exit(125)
