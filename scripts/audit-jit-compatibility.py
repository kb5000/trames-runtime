#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent LLVM assembly oracle for the complete current PAC/MTE profile."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--llvm-mc", default=shutil.which("llvm-mc") or shutil.which("llvm-mc-18"))
parser.add_argument("--write", action="store_true", help="write the reviewed fixture, rather than verify it")
args = parser.parse_args()
if not args.llvm_mc:
    parser.error("LLVM mc is required")
root = Path(__file__).resolve().parents[1]
dest = root / "docs/validation/jit-compatibility-20261128"
cases = []


def reg(n, sp=False):
    return "sp" if n == 31 and sp else "xzr" if n == 31 else f"x{n}"


def add(kind, text):
    cases.append((kind, text))


registers = [(0, 1, 2), (18, 17, 29), (30, 30, 30), (31, 31, 31), (17, 31, 18), (0, 0, 0)]
for d, n, m in registers:
    for op in ["pacia", "pacib", "pacda", "pacdb", "autia", "autib", "autda", "autdb"]:
        add("identity", f"{op} {reg(d)}, {reg(n, True)}")
    for op in ["paciza", "pacizb", "pacdza", "pacdzb", "autiza", "autizb", "autdza", "autdzb"]:
        add("identity", f"{op} {reg(d)}")
    for op in ["xpaci", "xpacd"]:
        add("strip", f"{op} {reg(d)}")
    add("code", f"pacga {reg(d)}, {reg(n)}, {reg(m, True)}")
    for op in ["braa", "brab", "blraa", "blrab"]:
        add("branch", f"{op} {reg(n)}, {reg(m, True)}")
    for op in ["braaz", "brabz", "blraaz", "blrabz"]:
        add("branch", f"{op} {reg(n)}")
    add("irg", f"irg {reg(d, True)}, {reg(n, True)}, {reg(m)}")
    add("gmi", f"gmi {reg(d)}, {reg(n, True)}, {reg(m)}")
    for op in ["subp", "subps"]:
        add("subp", f"{op} {reg(d)}, {reg(n, True)}, {reg(m, True)}")
    for op in ["addg", "subg"]:
        for offset in [0, 16, 1008]:
            for tag in [0, 1, 15]:
                add("addg", f"{op} {reg(d, True)}, {reg(n, True)}, #{offset}, #{tag}")
for op in ["retaa", "retab"]:
    add("branch", op)

# Memory writeback aliases forbidden by the shared profile are tested separately.
for d, n, m in [(0, 1, 2), (18, 17, 29), (30, 31, 30), (31, 31, 31), (0, 0, 0), (17, 18, 17)]:
    for op in ["ldraa", "ldrab"]:
        for offset in [-4096, -8, 0, 8, 4088]:
            add("load", f"{op} {reg(d)}, [{reg(n, True)}, #{offset}]")
            if n == 31 or n != d:
                add("load", f"{op} {reg(d)}, [{reg(n, True)}, #{offset}]!")
    for offset in [-4096, -16, 0, 16, 4080]:
        add("tag", f"ldg {reg(d)}, [{reg(n, True)}, #{offset}]")
        for op in ["stg", "stzg", "st2g", "stz2g"]:
            add("tag", f"{op} {reg(d, True)}, [{reg(n, True)}, #{offset}]")
            if n == 31 or n != d:
                add("tag", f"{op} {reg(d, True)}, [{reg(n, True)}, #{offset}]!")
                add("tag", f"{op} {reg(d, True)}, [{reg(n, True)}], #{offset}")
    for offset in [-1024, -16, 0, 16, 1008]:
        add("stgp", f"stgp {reg(d)}, {reg(m)}, [{reg(n, True)}, #{offset}]")
        if n == 31 or n not in [d, m]:
            add("stgp", f"stgp {reg(d)}, {reg(m)}, [{reg(n, True)}, #{offset}]!")
            add("stgp", f"stgp {reg(d)}, {reg(m)}, [{reg(n, True)}], #{offset}")

assembly = ".arch armv8.5-a+pauth+memtag\n.text\n" + "".join(text + "\n" for _, text in cases)
result = subprocess.run([args.llvm_mc, "-triple=aarch64-linux-gnu", "-show-encoding"],
                        input=assembly, text=True, capture_output=True)
if result.returncode:
    raise SystemExit(result.stderr)
words = []
for line in result.stdout.splitlines():
    encoding = re.search(r"encoding: \[([^]]+)\]", line)
    if encoding:
        data = bytes(int(part.strip(), 16) for part in encoding[1].split(","))
        words.append(int.from_bytes(data, "little"))
assert len(words) == len(cases)
files = {
    "category.S": assembly,
    "category.words": "".join(f"{word:08x}\n" for word in words),
    "category.cases": "".join(f"{kind} {word:08x} {text}\n" for (kind, text), word in zip(cases, words)),
}
counts = {}
for kind, _ in cases:
    counts[kind] = counts.get(kind, 0) + 1
files["category.json"] = json.dumps({"encodings": len(words), "families": counts,
    "words_sha256": hashlib.sha256(files["category.words"].encode()).hexdigest()}, indent=2) + "\n"
benchmarks = [
    ("pointer-arithmetic", 6, 1, ["irg x18,x1,xzr", "addg x18,x18,#16,#15", "gmi x17,x18,x29", "subps x30,x18,x1", "subs x2,x2,#1", "b.ne #-20", "svc #0"]),
    ("authenticated-load-pair-store", 5, 1, ["ldraa x18,[x1]", "add x18,x18,#1", "stgp x18,x29,[x1]", "subs x2,x2,#1", "b.ne #-16", "svc #0"]),
    ("tag-zero", 4, 1, ["stz2g x0,[x1]", "add x18,x18,#1", "subs x2,x2,#1", "b.ne #-12", "svc #0"]),
    ("authentication-profile", 5, 1, ["pacia x18,x1", "xpaci x18", "add x18,x18,#1", "subs x2,x2,#1", "b.ne #-16", "svc #0"]),
    ("authenticated-branch", 4, 0, ["add x18,x18,#1", "subs x2,x2,#1", "b.eq #8", "braaz x17", "svc #0"]),
    ("control-integer", 3, 1, ["add x18,x18,#1", "subs x2,x2,#1", "b.ne #-8", "svc #0"]),
    ("control-scalar-memory", 5, 1, ["ldr x18,[x1]", "add x18,x18,#1", "str x18,[x1]", "subs x2,x2,#1", "b.ne #-16", "svc #0"]),
]
bench_assembly = ".arch armv8.5-a+pauth+memtag\n.text\n" + "".join(
    f"// {name}\n" + "\n".join(instructions) + "\n" for name, _, _, instructions in benchmarks)
result = subprocess.run([args.llvm_mc, "-triple=aarch64-linux-gnu", "-show-encoding"],
    input=bench_assembly, text=True, capture_output=True, check=True)
bench_words = []
for line in result.stdout.splitlines():
    encoding = re.search(r"encoding: \[([^]]+)\]", line)
    if encoding:
        bench_words.append(int.from_bytes(bytes(int(p.strip(), 16) for p in encoding[1].split(",")), "little"))
source = (root / "crates/trames-jit/examples/compatibility-category.rs").read_text()
entries = re.findall(r'\(\s*"([^"]+)",\s*&\[(.*?)\]\[\.\.\],\s*(\d+),\s*(\d+),?\s*\)', source, re.S)
assert len(entries) == len(benchmarks)
offset = 0
bench_metadata = []
for (name, stride, tail, instructions), (actual, raw, actual_stride, actual_tail) in zip(benchmarks, entries):
    count = len(instructions)
    words = bench_words[offset:offset + count]
    assert (name, stride, tail) == (actual, int(actual_stride), int(actual_tail))
    assert [int(w, 16) for w in re.findall(r"0x[0-9a-f]+", raw)] == words, name
    bench_metadata.append({"name": name, "stride": stride, "tail": tail, "words": [f"{w:08x}" for w in words]})
    offset += count
assert offset == len(bench_words)
files["benchmarks.S"] = bench_assembly
files["benchmarks.json"] = json.dumps(bench_metadata, indent=2) + "\n"
if args.write:
    dest.mkdir(parents=True, exist_ok=True)
for name, content in files.items():
    path = dest / name
    if args.write:
        path.write_text(content)
    else:
        assert path.read_text() == content, name
print(files["category.json"].strip())
