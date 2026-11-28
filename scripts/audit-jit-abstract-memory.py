#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent LLVM fixture for all abstract ordered/atomic memory families."""
import argparse
from pathlib import Path
import re
import shutil
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--llvm-mc", default=shutil.which("llvm-mc") or shutil.which("llvm-mc-18"))
parser.add_argument("--write", action="store_true")
args = parser.parse_args()
if not args.llvm_mc:
    parser.error("LLVM mc is required")
root = Path(__file__).resolve().parents[1]
path = root / "docs/validation/jit-abstract-memory-20261128"
rows = []


def reg(n, wide):
    return ("xzr" if wide else "wzr") if n == 31 else f"{'x' if wide else 'w'}{n}"


def base(n):
    return "sp" if n == 31 else f"x{n}"


for size in range(4):
    for rn, rt in [(1, 0), (31, 31), (1, 1)]:
        suffix = ["b", "h", "", ""][size]
        for name in ["ldar", "stlr", "ldlar", "stllr", "ldapr"]:
            rows.append((name, 0, f"{name}{suffix} {reg(rt, size == 3)}, [{base(rn)}]"))
        for opc in range(4):
            if opc == 2 and size == 3 or opc == 3 and size >= 2:
                continue
            name = "stlur" if opc == 0 else "ldapur"
            suffix = ["b", "h", "", ""][size]
            if opc >= 2:
                suffix = ["sb", "sh", "sw"][size]
            for offset in [-256, -8, 0, 7, 255]:
                rows.append((name, offset, f"{name}{suffix} {reg(rt, size == 3 or opc == 2)}, [{base(rn)}, #{offset}]"))
    for order in ["", "a", "l", "al"]:
        suffix = ["b", "h", "", ""][size]
        for rn, rs, rt in [(1, 4, 0), (31, 30, 31), (1, 0, 0)]:
            operands = f"{reg(rs, size == 3)}, {reg(rt, size == 3)}, [{base(rn)}]"
            for name in ["cas", "ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin", "swp"]:
                rows.append((name, 0, f"{name}{order}{suffix} {operands}"))
for wide in [False, True]:
    for order in ["", "a", "l", "al"]:
        for rs, rt, rn in [(4, 0, 2), (30, 28, 31), (0, 0, 2)]:
            operands = f"{reg(rs, wide)}, {reg(rs+1, wide)}, {reg(rt, wide)}, {reg(rt+1, wide)}, [{base(rn)}]"
            rows.append(("casp", 0, f"casp{order} {operands}"))
for name in ["swpp", "ldclrp", "ldsetp"]:
    for order in ["", "a", "l", "al"]:
        for first, second, rn in [(0, 4, 1), (18, 30, 29), (4, 0, 31)]:
            rows.append((name, 0, f"{name}{order} x{first}, x{second}, [{base(rn)}]"))
assembly = ".arch armv9.4-a\n.arch_extension lse128\n.arch_extension lor\n\n" + "\n".join(row[2] for row in rows) + "\n"
result = subprocess.run([args.llvm_mc, "-triple=aarch64-linux-gnu", "-show-encoding"],
                        input=assembly, text=True, capture_output=True, check=True)
words = []
for line in result.stdout.splitlines():
    found = re.search(r"encoding: \[([^]]+)\]", line)
    if found:
        data = bytes(int(x.strip(), 16) for x in found[1].split(","))
        words.append(int.from_bytes(data, "little"))
assert len(words) == len(rows) == 795, len(words)
files = {
    "category.S": assembly,
    "category.words": "".join(f"{w:08x}\n" for w in words),
    "category.cases": "".join(f"{name} {offset}\n" for name, offset, _ in rows),
}
benchmarks = [
    ("abstract-release-acquire", ["ldar x0,[x1]", "add x0,x0,#1", "stlr x0,[x1]", "subs x2,x2,#1", "b.ne #-16", "svc #0"]),
    ("abstract-atomic", ["ldaddal x4,x0,[x1]", "subs x2,x2,#1", "b.ne #-8", "svc #0"]),
]
bench_assembly = ".arch armv8.2-a+lse\n.text\n" + "".join(
    f"// {name}\n" + "\n".join(instructions) + "\n" for name, instructions in benchmarks)
result = subprocess.run([args.llvm_mc, "-triple=aarch64-linux-gnu", "-show-encoding"],
                        input=bench_assembly, text=True, capture_output=True, check=True)
bench_words = []
for line in result.stdout.splitlines():
    found = re.search(r"encoding: \[([^]]+)\]", line)
    if found:
        bench_words.append(int.from_bytes(bytes(int(x.strip(), 16) for x in found[1].split(",")), "little"))
source = (root / "crates/trames-jit/examples/abstract-memory.rs").read_text()
entries = re.findall(r'\(\s*"([^"]+)",\s*&\[(.*?)\]\[\.\.\],\s*(false|true),?\s*\)', source, re.S)
assert len(entries) == len(benchmarks)
offset = 0
for (name, instructions), (actual_name, raw, atomic) in zip(benchmarks, entries):
    words = bench_words[offset:offset + len(instructions)]
    assert actual_name == name
    assert (atomic == "true") == (name == "abstract-atomic")
    assert [int(x, 16) for x in re.findall(r"0x[0-9a-f]+", raw)] == words, name
    offset += len(instructions)
assert offset == len(bench_words)
files["benchmarks.S"] = bench_assembly
if args.write:
    path.mkdir(parents=True, exist_ok=True)
for name, content in files.items():
    if args.write:
        (path / name).write_text(content)
    else:
        assert (path / name).read_text() == content, name
print(f"LLVM abstract ordered/atomic category: {len(rows)} independently assembled encodings; both benchmark loops match")
