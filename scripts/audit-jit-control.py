#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent LLVM 23 assembly/disassembly oracle using the existing Rust toolchain."""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

parser=argparse.ArgumentParser()
parser.add_argument('--write',action='store_true')
args=parser.parse_args()
root=Path(__file__).resolve().parents[1]
dest=root/'docs/validation/jit-control-20261128'
rows=[]
def add(kind,condition,bits,left,right,immediate,offset,text):
    rows.append((kind,condition,bits,left,right,immediate,offset,text))
def reg(n,bits=64):return ('xzr' if bits==64 else 'wzr') if n==31 else f"{'x' if bits==64 else 'w'}{n}"
offset19=[-1048576,-4096,-4,0,4,64,1048572]
for name in ['b','bl']:
    for offset in [-134217728,-4096,-4,0,4,64,134217724]:add(name,0,64,0,0,0,offset,f'{name} #{offset}')
for family,name in [('cond','b'),('hbc','bc')]:
    for condition,cc in enumerate(['eq','ne','hs','lo','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','al','nv']):
        for offset in offset19:add(family,condition,64,0,0,0,offset,f'{name}.{cc} #{offset}')
for name in ['cbz','cbnz']:
    for bits in [32,64]:
        for r in [0,18,30,31]:
            for offset in offset19:add('zero',int(name=='cbnz'),bits,r,0,0,offset,f'{name} {reg(r,bits)}, #{offset}')
for name in ['tbz','tbnz']:
    for bit in range(64):
        for r in [0,18,30,31]:
            for offset in [-32768,-4,0,4,32764]:add('bit',int(name=='tbnz'),bit,r,0,0,offset,f'{name} {reg(r,64 if bit>=32 else 32)}, #{bit}, #{offset}')
for name in ['br','blr','ret']:
    for r in [0,1,18,29,30,31]:add(name,0,64,r,0,0,0,f'{name} {reg(r)}')
conditions=['eq','ne','gt','ge','lt','le','hi','hs','lo','ls']
offset9=[-1024,-4,0,4,1020]
for bits,prefix in [(32,'cb'),(64,'cb'),(8,'cbb'),(16,'cbh')]:
    for cc in conditions:
        for left,right in [(0,1),(18,30),(31,31),(30,30)]:
            for offset in offset9:add('cmp',conditions.index(cc),bits,left,right,0,offset,f'{prefix}{cc} {reg(left,64 if bits==64 else 32)}, {reg(right,64 if bits==64 else 32)}, #{offset}')
for bits in [32,64]:
    for cc in ['eq','ne','gt','lt','hi','lo']:
        for r in [0,18,30,31]:
            for immediate in range(64):
                for offset in offset9:add('cmp',conditions.index(cc),bits,r,immediate,1,offset,f'cb{cc} {reg(r,bits)}, #{immediate}, #{offset}')
    for cc in ['ge','le','hs','ls']:
        for r in [0,18,30,31]:
            for immediate in [1,31,62]:
                for offset in offset9:add('cmp',conditions.index(cc),bits,r,immediate,1,offset,f'cb{cc} {reg(r,bits)}, #{immediate}, #{offset}')
assembly='.arch_extension hbc\n.arch_extension cmpbr\n.text\n'+'\n'.join(row[-1] for row in rows)+'\n'
rust='#![no_std]\ncore::arch::global_asm!(r###"'+assembly+'"###,options(raw));\n'
with tempfile.TemporaryDirectory(prefix='trames-control-llvm-') as directory:
    directory=Path(directory);source=directory/'fixture.rs';obj=directory/'fixture.o';source.write_text(rust)
    subprocess.run(['rustc','--edition=2021','--crate-type=lib','--emit=obj',str(source),'-o',str(obj)],check=True)
    data=obj.read_bytes()
assert data[:6]==b'\x7fELF\x02\x01'
shoff=struct.unpack_from('<Q',data,40)[0];entsize,count,strindex=struct.unpack_from('<HHH',data,58)
sections=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+i*entsize) for i in range(count)]
strings=sections[strindex];names=data[strings[4]:strings[4]+strings[5]]
text=[]
for section in sections:
    name=names[section[0]:].split(b'\0',1)[0]
    if name==b'.text':text.append(data[section[4]:section[4]+section[5]])
assert len(text)==1 and len(text[0])==len(rows)*4,(len(rows),[len(s) for s in text])
words=struct.unpack('<'+'I'*len(rows),text[0])
files={'category.S':assembly,'category.words':''.join(f'{word:08x}\n' for word in words),
       'category.cases':''.join(' '.join(str(x) for x in row[:-1])+'\n' for row in rows)}
toolchain=Path(subprocess.check_output(['rustc','--print','sysroot'],text=True).strip())
library=next((toolchain/'lib').glob('libLLVM.so.23*'));llvm=ctypes.CDLL(str(library))
for name in ['LLVMInitializeAArch64TargetInfo','LLVMInitializeAArch64TargetMC','LLVMInitializeAArch64Disassembler']:getattr(llvm,name)()
llvm.LLVMCreateDisasmCPUFeatures.restype=ctypes.c_void_p
llvm.LLVMCreateDisasmCPUFeatures.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p]
context=llvm.LLVMCreateDisasmCPUFeatures(b'aarch64-linux-gnu',b'generic',b'+cmpbr,+hbc,+pauth,+v9.6a',None,0,None,None)
llvm.LLVMDisasmInstruction.restype=ctypes.c_size_t
llvm.LLVMDisasmInstruction.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_size_t]
def decode(word):
    data=ctypes.create_string_buffer(word.to_bytes(4,'little'));out=ctypes.create_string_buffer(256)
    return out.value.decode() if llvm.LLVMDisasmInstruction(context,data,4,0,out,256)==4 else None
for word in words:assert decode(word),f'{word:08x}'
selectors=[]
for sf in [0,1]:
    for immediate in [0,1]:
        for cc in range(8):
            for operand in range(64):
                for bit14 in [0,1]:
                    word=0x74000000|(sf<<31)|(immediate<<24)|(cc<<21)|(operand<<15)|(bit14<<14)
                    selectors.append((word,int(decode(word) is not None)))
assert len(selectors)==4096
files['compare-selectors.words']=''.join(f'{w:08x} {valid}\n' for w,valid in selectors)
files['category.json']=json.dumps({'encodings':len(words),'cmpbr_selectors':len(selectors),'cmpbr_valid':sum(v for _,v in selectors),
 'rustc':subprocess.check_output(['rustc','-Vv'],text=True),'llvm_library':str(library),'llvm_library_sha256':hashlib.sha256(library.read_bytes()).hexdigest()},indent=2)+'\n'
if args.write:dest.mkdir(parents=True,exist_ok=True)
for name,content in files.items():
    if args.write:(dest/name).write_text(content)
    elif name!='category.json':assert (dest/name).read_text()==content,name
print(files['category.json'])
