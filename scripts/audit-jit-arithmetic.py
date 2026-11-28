#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline LLVM oracle for cold native arithmetic admission, never a runtime dependency.

Generate input with TRAMES_JIT_ENCODING_AUDIT=<file> cargo test -p trames-jit
--features native-aarch64 cold_encoding_admission. Run on the existing Linux
build host with its libLLVM. Input/output and tool identity belong in validation.
"""
import argparse
import collections
import ctypes
import ctypes.util
import json
from pathlib import Path

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('input',type=Path)
parser.add_argument('--library',default=ctypes.util.find_library('LLVM-20'))
parser.add_argument('--outside',type=Path,help='Write LLVM-valid encodings outside current admission for the optional reference closure check')
args=parser.parse_args()
llvm=ctypes.CDLL(args.library)
for name in ['LLVMInitializeAArch64TargetInfo','LLVMInitializeAArch64TargetMC','LLVMInitializeAArch64Disassembler']:
    getattr(llvm,name)()
features='+v9.4a,+neon,+fp-armv8,+fullfp16,+fp16fml,+bf16,+i8mm,+complxnum,+rdm,+dotprod,+jsconv,+fptoint,+crypto,+sha3,+sm4'
llvm.LLVMCreateDisasmCPUFeatures.restype=ctypes.c_void_p
llvm.LLVMCreateDisasmCPUFeatures.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p]
context=llvm.LLVMCreateDisasmCPUFeatures(b'aarch64-unknown-linux-gnu',b'generic',features.encode(),None,0,None,None)
assert context,'LLVM AArch64 disassembler unavailable'
llvm.LLVMDisasmInstruction.restype=ctypes.c_size_t
llvm.LLVMDisasmInstruction.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_size_t]
llvm.LLVMDisasmDispose.argtypes=[ctypes.c_void_p]
counts=collections.Counter();unknown=[];rows=[];admitted=set()
for row in args.input.read_text().splitlines():
    word=int(row.split()[0],16)
    admitted.add(word)
    data=ctypes.create_string_buffer(word.to_bytes(4,'little'))
    text=ctypes.create_string_buffer(512)
    n=llvm.LLVMDisasmInstruction(context,data,4,0,text,len(text))
    if n!=4:
        unknown.append(row)
    else:
        assembly=text.value.decode().strip();counts[assembly.split()[0]]+=1
        rows.append({'encoding':row,'assembly':assembly})
outside={}
if args.outside:
    import re
    for prefix in [0x0e000000,0x2e000000,0x4e000000,0x6e000000,0x5e000000,0x7e000000,0x0f000000,0x2f000000,0x4f000000,0x6f000000,0x5f000000,0x7f000000,0x1e000000,0x9e000000,0x1f000000]:
        for middle in range(16384):
            word=prefix|(middle<<10)|(1<<5)
            if word in admitted:continue
            data=ctypes.create_string_buffer(word.to_bytes(4,'little'));text=ctypes.create_string_buffer(512)
            if llvm.LLVMDisasmInstruction(context,data,4,0,text,len(text))==4:
                assembly=text.value.decode().strip()
                key=re.sub(r'\b([vdsbhqwx])\d+\b',r'\g<1>REG',assembly)
                outside.setdefault(key,f'{word:08x} {assembly}')
    args.outside.write_text('\n'.join(outside.values())+'\n')
llvm.LLVMDisasmDispose(context)
print(json.dumps({'library':args.library,'features':features,'admitted':len(rows)+len(unknown),'unknown':unknown,'instructions':dict(sorted(counts.items())),'decoded':rows,'unadmitted_distinct_forms':len(outside)},indent=2,sort_keys=True))
raise SystemExit(bool(unknown))
