#!/usr/bin/env python3
"""Verify and recompute the frozen complete-category CPU-only cohort offline."""
import gzip
import hashlib
import json
from pathlib import Path
import statistics
import sys

root = Path(__file__).resolve().parent
receipt = json.loads(gzip.decompress((root / "receipt.json.gz").read_bytes()))
for name, digest in receipt["files"].items():
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, name
oracle=json.loads(gzip.decompress((root/"llvm.json.gz").read_bytes()))
assert oracle["admitted"]==68214 and not oracle["unknown"]
assert oracle["unadmitted_distinct_forms"]==0 and len(oracle["instructions"])==303
assert not gzip.decompress((root/"outside.txt.gz").read_bytes()).strip()
import re
seen={}
for row in oracle["decoded"]:
    fields=row["encoding"].split()
    key=re.sub(r"\b([vdsbhqwx])\d+\b",r"\g<1>REG",row["assembly"])+" "+" ".join(fields[1:3])
    seen.setdefault(key,fields[:3])
corpus=("# SPDX-License-Identifier: GPL-3.0-or-later\n# word hwcap hwcap2; LLVM 20 encoding/arrangement/lane corpus.\n"+"\n".join(" ".join(f) for f in seen.values())+"\n").encode()
assert len(seen)==10640
assert hashlib.sha256(corpus).hexdigest()==receipt["variants"]["new"]["runtime_sources"]["crates/trames-jit/tests/data/arithmetic-encodings.txt"]
metadata=json.loads(gzip.decompress((root/"alias-metadata.json.gz").read_bytes()))
assembled=gzip.decompress((root/"aliases-assembled.txt.gz").read_bytes()).decode()
encodings=re.findall(r"encoding: \[([^]]+)\]",assembled)
assert len(encodings)==len(metadata)==7160
aliases={}
for row,encoding in zip(metadata,encodings):
    word=int.from_bytes(bytes(int(x.strip(),16) for x in encoding.split(",")),"little")
    fields=row["original"].split();aliases.setdefault(word,fields[1:3])
corpus=("# SPDX-License-Identifier: GPL-3.0-or-later\n# Independent LLVM 18 assembly of aliased arithmetic operands.\n"+"\n".join(f"{w:08x} {h} {h2}" for w,(h,h2) in aliases.items())+"\n").encode()
assert len(aliases)==7129
assert hashlib.sha256(corpus).hexdigest()==receipt["variants"]["new"]["runtime_sources"]["crates/trames-jit/tests/data/arithmetic-aliases.txt"]
cohort = {}
for pair in range(1, 5):
    variants = {}
    for version in ["old", "new"]:
        rows = [json.loads(s) for s in (root / f"pair-{pair}-{version}.jsonl").read_text().splitlines()]
        assert len(rows) == 6
        variants[version] = {r["workload"]: r for r in rows}
        assert len(variants[version]) == 6
        for r in rows:
            assert r["trips"] == 65536 and r["mode"] == "direct"
            assert r["logical_guest_instructions"] == (len(r["words"]) - 1) * r["trips"] + 1
            assert [s["warmup"] for s in r["samples"]] == [True, False, False, False, False, False]
            assert all(s["instructions"] == r["logical_guest_instructions"] for s in r["samples"])
            assert statistics.median(s["ns"] for s in r["samples"][1:]) == r["median_ns"]
            if version == "new":
                assert r["diagnostics"]["fallback"] == r["diagnostics"]["staged"] == 0
                assert r["diagnostics"]["memory"] == 0
                assert r["diagnostics"]["native"] == 6 * (r["logical_guest_instructions"] - 1)
                assert r["diagnostics"]["entries"] <= 18
            elif not r["workload"].endswith("-control"):
                assert r["diagnostics"]["fallback"] > 0
            cohort.setdefault(r["workload"], {}).setdefault(version, []).append(r["median_ns"])
    assert variants["old"].keys() == variants["new"].keys()
    for name, a in variants["old"].items():
        b = variants["new"][name]
        for key in ["words", "trips", "logical_guest_instructions", "registers", "vectors",
                    "pc", "sp", "nzcv", "fpsr", "fpcr", "tls", "tls2", "data"]:
            assert a[key] == b[key], (pair, name, key)
summary = {}
for name, variants in cohort.items():
    old, new = (statistics.median(variants[v]) for v in ["old", "new"])
    summary[name] = {"old_median_ns": old, "new_median_ns": new, "speedup": old / new,
                     "change_percent": 100 * (new / old - 1), "process_medians": variants}
result = {"processes": 8, "timed_samples": 240, "warmup_samples": 48, "workloads": summary}
if (root / "summary.json").exists():
    assert json.loads((root / "summary.json").read_text()) == result
if len(sys.argv) > 1:
    source = Path(sys.argv[1])
    for name, digest in receipt["variants"]["new"]["runtime_sources"].items():
        assert hashlib.sha256((source / name).read_bytes()).hexdigest() == digest, name
print(json.dumps(result, sort_keys=True, indent=2))
