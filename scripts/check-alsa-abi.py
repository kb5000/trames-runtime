#!/usr/bin/env python3
"""Compile Linux PCM's Rust FFI declarations against ALSA's actual public C ABI.
No generated checks or header dependency enter the runtime binary.
"""
from pathlib import Path
import os, re, subprocess, tempfile
root = Path(__file__).resolve().parents[1]
source = (root / 'crates/trames-audio/src/linux.rs').read_text()
block = source.split('api! {', 1)[1].split('\n}', 1)[0]
types = dict(Pcm='snd_pcm_t', Hw='snd_pcm_hw_params_t', Sw='snd_pcm_sw_params_t', Status='snd_pcm_status_t', c_int='int', c_uint='unsigned int', c_long='long', c_ulong='unsigned long', c_char='char', c_void='void', pollfd='struct pollfd', u16='unsigned short')
def c_type(t):
    t = t.strip()
    if t == '()': return 'void'
    if t.startswith('*mut '): return c_type(t[5:]) + ' *'
    if t.startswith('*const '): return 'const ' + c_type(t[7:]) + ' *'
    return types[t]
lines=['#include <alsa/asoundlib.h>', '#include <poll.h>']
functions = re.findall(r'(\w+)\((.*?)\)\s*->\s*([^;]+);', block, re.S)
assert len(functions) >= 35, 'incomplete ALSA FFI scan'
for name, args, result in functions:
    args = ','.join(c_type(a) for a in args.split(','))
    lines.append(f'_Static_assert(__builtin_types_compatible_p(__typeof__(&snd_pcm_{name}), {c_type(result)} (*)({args})), "snd_pcm_{name}");')
for name, value in dict(SND_PCM_NONBLOCK=1, SND_PCM_STREAM_PLAYBACK=0, SND_PCM_STREAM_CAPTURE=1, SND_PCM_ACCESS_RW_INTERLEAVED=3, SND_PCM_FORMAT_S16_LE=2, SND_PCM_FORMAT_FLOAT_LE=14, SND_PCM_STATE_RUNNING=3, SND_PCM_STATE_XRUN=4, SND_PCM_STATE_PAUSED=6, SND_PCM_STATE_SUSPENDED=7, SND_PCM_STATE_DISCONNECTED=8).items():
    lines.append(f'_Static_assert({name} == {value}, "{name}");')
with tempfile.TemporaryDirectory() as folder:
    c=Path(folder)/'alsa-abi.c'; c.write_text('\n'.join(lines)+'\n')
    subprocess.run([os.environ.get('CC','cc'), '-std=c11','-D_GNU_SOURCE','-Werror','-c',str(c),'-o',str(Path(folder)/'alsa-abi.o')], check=True)
print(f'ALSA ABI: {len(functions)} FFI signatures and constants compiled against host headers')
