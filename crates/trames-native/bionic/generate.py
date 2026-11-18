# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep pinned gdtoa arithmetic; give its caches per-invocation ownership."""
import hashlib
import json
from pathlib import Path
import sys
root = Path(__file__).resolve().parents[1]
source = root / 'upstream/bionic-android13'
out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
manifest = json.loads((source / 'provenance.json').read_text())
for name, expected in manifest['files'].items():
    data = (source / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == expected, name
    text = data.decode()
    if name == 'arith.h':
        assert text.count('#define MULTIPLE_THREADS') == 1
        text = text.replace('#define MULTIPLE_THREADS', '// Cache ownership is per native invocation.')
    elif name == 'misc.c':
        for declaration in [' static Bigint *freelist[Kmax+1];', ' static Bigint *p5s;']:
            assert text.count(declaration) == 1
            text = text.replace(declaration, '')
    elif name == 'hd_init.c':
        assert text.count(' unsigned char hexdig[256];') == 1
        text = text.replace(' unsigned char hexdig[256];', '')
    elif name == 'gdtoaimp.h':
        assert text.count(' extern unsigned char hexdig[];') == 1
        text = text.replace(' extern unsigned char hexdig[];', '')
        text += '\n#include "gdtoa-state.h"\n'
    (out / name).write_text(text)
