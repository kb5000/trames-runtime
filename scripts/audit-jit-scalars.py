#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline independent LLVM audit of scalar primary-group admission."""
import argparse
import collections
import ctypes
import ctypes.util
import json
from pathlib import Path
import re

parser = argparse.ArgumentParser()
parser.add_argument("input", type=Path)
parser.add_argument("--library", default=ctypes.util.find_library("LLVM-18"))
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--execution-output", type=Path)
args = parser.parse_args()
llvm = ctypes.CDLL(args.library)
for name in ["LLVMInitializeAArch64TargetInfo", "LLVMInitializeAArch64TargetMC", "LLVMInitializeAArch64Disassembler"]:
    getattr(llvm, name)()
llvm.LLVMCreateDisasmCPUFeatures.restype = ctypes.c_void_p
llvm.LLVMCreateDisasmCPUFeatures.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
features = "+v9.4a,+crc,+pauth,+mte,+cssc,+flagm,+altnzcv"
context = llvm.LLVMCreateDisasmCPUFeatures(b"aarch64-unknown-linux-gnu", b"generic", features.encode(), None, 0, None, None)
assert context
llvm.LLVMDisasmInstruction.restype = ctypes.c_size_t
llvm.LLVMDisasmInstruction.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t]
llvm.LLVMDisasmDispose.argtypes = [ctypes.c_void_p]
admitted = {int(line.split()[0], 16): line.split()[1] for line in args.input.read_text().splitlines()}
counts = collections.Counter()
invalid = collections.Counter()
invalid_examples = {}
missing = collections.Counter()
examples = {}
compatibility = collections.Counter()
compatibility_names = {"pacia", "pacib", "pacda", "pacdb", "autia", "autib", "autda", "autdb", "paciza", "pacizb", "pacdza", "pacdzb", "autiza", "autizb", "autdza", "autdzb", "xpaci", "xpacd", "pacga", "irg", "gmi", "subp", "subps", "addg", "subg"}
valid = 0
candidates = 0
for high in range(512):
    if (high >> 2) & 15 not in [5, 8, 9, 13]:
        continue
    for middle in range(8192):
        word = high << 23 | middle << 10 | 1 << 5
        candidates += 1
        data = ctypes.create_string_buffer(word.to_bytes(4, "little"))
        text = ctypes.create_string_buffer(512)
        decoded = llvm.LLVMDisasmInstruction(context, data, 4, 0, text, len(text)) == 4
        if decoded:
            valid += 1
            assembly = text.value.decode().strip()
            mnemonic = assembly.split()[0]
            if word in admitted:
                counts[mnemonic] += 1
            elif mnemonic in compatibility_names:
                compatibility[mnemonic] += 1
            else:
                missing[mnemonic] += 1
                examples.setdefault(mnemonic, f"{word:08x} {assembly}")
        elif word in admitted:
            form = admitted[word]
            invalid[form] += 1
            invalid_examples.setdefault(form, f"{word:08x}")
for word, form in admitted.items():
    if word & 1023 == 32:
        continue
    data = ctypes.create_string_buffer(word.to_bytes(4, "little"))
    text = ctypes.create_string_buffer(512)
    if llvm.LLVMDisasmInstruction(context, data, 4, 0, text, len(text)) != 4:
        invalid[form] += 1
        invalid_examples.setdefault(form, f"{word:08x}")

execution = {}
for word, form in admitted.items():
    key = word
    if form == "Move":
        key &= ~0x1fffe0
    elif form == "AddImmediate":
        key &= ~0x3ffc00
    elif form == "Address":
        key &= ~((0x7ffff << 5) | (3 << 29))
    elif form in {"Crc", "AddShift", "AddExtended", "LogicalShift", "Extract", "Select", "Carry", "Binary", "Multiply"}:
        key &= ~(31 << 16)
        if form == "Multiply" and (word >> 21) & 7 not in [2, 6]:
            key &= ~(31 << 10)
    elif form == "Compare" and word & (1 << 11) == 0:
        key &= ~(31 << 16)
    elif form == "MinMax" and word & 0x7ff00000 != 0x11c00000:
        key &= ~(31 << 16)
    masks = range(16) if form == "Compare" or form == "FlagValue" and word & 0xffe07c10 == 0xba000400 else [None]
    for mask in masks:
        actual = key if mask is None else key | mask
        execution[(actual, form)] = True
if args.execution_output:
    for word, _ in execution:
        data = ctypes.create_string_buffer(word.to_bytes(4, "little"))
        text = ctypes.create_string_buffer(512)
        assert llvm.LLVMDisasmInstruction(context, data, 4, 0, text, len(text)) == 4, f"execution fixture {word:08x}"
    args.execution_output.write_text("".join(f"{word:08x} {form}\n" for word, form in sorted(execution)))
llvm.LLVMDisasmDispose(context)
result = {"library": args.library, "features": features, "candidates": candidates, "llvm_valid": valid,
          "admitted_words_including_specials": len(admitted), "admitted_mnemonics": dict(sorted(counts.items())),
          "invalid_admissions": dict(invalid), "invalid_examples": invalid_examples,
          "separate_compatibility_forms": dict(sorted(compatibility.items())),
          "missing_forms": dict(sorted(missing.items())), "missing_examples": examples,
          "execution_selector_programs": len(execution)}
args.output.write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({k:v for k,v in result.items() if k != "admitted_mnemonics"}, indent=2))

assert not invalid and not missing, "scalar closure failed; inspect the retained report"
