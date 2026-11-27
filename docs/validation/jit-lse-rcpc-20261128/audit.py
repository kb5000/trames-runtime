#!/usr/bin/env python3
"""Audit the frozen paired cohort; no benchmark execution or network access."""
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

cases = {}
timed = warmup = 0
for pair in range(1, 5):
    records = {}
    for variant in ["old", "new"]:
        rows = [json.loads(line) for line in (root / f"pair-{pair}-{variant}.jsonl").read_text().splitlines()]
        assert len(rows) == 15
        records[variant] = {r["workload"]: r for r in rows}
        assert len(records[variant]) == 15
        for r in rows:
            assert r["backend"] == "jit" and r["mode"] == "worker-private"
            assert r["exact_instructions"]
            assert [s["warmup"] for s in r["samples"]] == [True, False, False, False, False, False]
            assert all(s["observed_instructions"] == r["logical_guest_instructions"] for s in r["samples"])
            assert statistics.median(s["ns"] for s in r["samples"][1:]) == r["median_ns"]
            if variant == "new":
                assert r["diagnostics"]["fallback_instructions"] == 0
                assert r["diagnostics"]["staged"] == 0
            if r["workload"] in ["ldadd-1m", "cas-1m", "casp-1m", "rcpc-1m", "rcpc-unscaled-1m"]:
                if variant == "old":
                    assert r["diagnostics"]["fallback_instructions"] > 0
                else:
                    assert r["diagnostics"]["hardware"] > 0.99 * r["diagnostics"]["memory_instructions"]
                    assert r["diagnostics"]["direct"] > 0.99 * r["diagnostics"]["memory_instructions"]
            cases.setdefault(r["workload"], {}).setdefault(variant, []).append(r["median_ns"])
            timed += 5
            warmup += 1
    assert records["old"].keys() == records["new"].keys()
    for name, a in records["old"].items():
        b = records["new"][name]
        for key in ["words", "trips", "iterations", "logical_guest_instructions", "final_data", "final_x0", "final_pc"]:
            assert a[key] == b[key], (pair, name, key)

summary = {}
for name, variants in cases.items():
    old, new = (statistics.median(variants[v]) for v in ["old", "new"])
    summary[name] = {"old_median_ns": old, "new_median_ns": new,
                     "speedup": old / new, "change_percent": 100 * (new / old - 1),
                     "process_medians": variants}

# Optional owning source verification, useful before publication. The receipt
# excludes docs and tests only in its claim about executed machine code; all
# Rust files are still hashed so the precise tested tree can be reproduced.
if len(sys.argv) > 1:
    source = Path(sys.argv[1])
    for name, digest in receipt["variants"]["new"]["runtime_sources"].items():
        assert hashlib.sha256((source / name).read_bytes()).hexdigest() == digest, name

result = {"processes": 8, "timed_samples": timed, "warmup_samples": warmup, "workloads": summary}
print(json.dumps(result, indent=2, sort_keys=True))
