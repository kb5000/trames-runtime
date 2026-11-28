#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reassemble the independent closed special-memory instruction fixture."""
import argparse
import hashlib
from pathlib import Path
import re
import shutil
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--llvm-mc", default=shutil.which("llvm-mc") or shutil.which("llvm-mc-18"))
args = parser.parse_args()
if not args.llvm_mc:
    parser.error("LLVM mc is required for offline ISA verification")
root = Path(__file__).resolve().parents[1]
fixture = root / "docs/validation/jit-special-memory-20261128/category.S"
expected = fixture.with_suffix(".words")
result = subprocess.run([args.llvm_mc, "-triple=aarch64-linux-gnu", "-show-encoding", str(fixture)],
                        check=True, text=True, capture_output=True)
words = []
for line in result.stdout.splitlines():
    encoding = re.search(r"encoding: \[([^]]+)\]", line)
    if encoding:
        data = bytes(int(part.strip(), 16) for part in encoding[1].split(","))
        words.append(int.from_bytes(data, "little"))
assert len(words) == 548
assert "".join(f"{word:08x}\n" for word in words) == expected.read_text()
print(f"LLVM special memory: {len(words)} encodings match; sha256={hashlib.sha256(expected.read_bytes()).hexdigest()}")
