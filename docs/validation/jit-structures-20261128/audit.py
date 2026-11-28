#!/usr/bin/env python3
"""Recompute the frozen cohort and check its source/build evidence offline."""
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

cohort = {}
for pair in range(1, 5):
    records = {}
    for variant in ["old", "new"]:
        rows = [json.loads(s) for s in (root / f"pair-{pair}-{variant}.jsonl").read_text().splitlines()]
        assert len(rows) == 6
        records[variant] = {r["workload"]: r for r in rows}
        assert len(records[variant]) == 6
        for r in rows:
            assert r["mode"] == "worker-private" and r["trips"] == 1_048_576
            assert [s["warmup"] for s in r["samples"]] == [True, False, False, False, False, False]
            assert all(s["instructions"] == r["logical_guest_instructions"] for s in r["samples"])
            assert r["logical_guest_instructions"] == (len(r["words"]) - 1) * r["trips"] + 1
            assert statistics.median(s["ns"] for s in r["samples"][1:]) == r["median_ns"]
            d = r["diagnostics"]
            if variant == "new":
                assert d["fallback"] == d["staged"] == 0
            if r["workload"].startswith("vector-"):
                if variant == "old":
                    assert d["fallback"] == 12 * r["trips"]
                    assert d["memory"] == 0
                else:
                    assert d["memory"] == 12 * r["trips"]
                    assert d["direct"] == d["hardware"] > d["memory"] * .99
                    assert d["fused_entries"] == 6 and d["address_reuses"] > 0
            cohort.setdefault(r["workload"], {}).setdefault(variant, []).append(r["median_ns"])
    assert records["old"].keys() == records["new"].keys()
    for name, a in records["old"].items():
        b = records["new"][name]
        for key in ["words", "trips", "data_bytes", "checksum", "logical_guest_instructions",
                    "final_x1", "final_pc", "vectors"]:
            assert a[key] == b[key], (pair, name, key)

summary = {}
for name, variants in cohort.items():
    old, new = (statistics.median(variants[v]) for v in ["old", "new"])
    summary[name] = {"old_median_ns": old, "new_median_ns": new,
                     "speedup": old / new, "change_percent": 100 * (new / old - 1),
                     "process_medians": variants}
result = {"processes": 8, "timed_samples": 240, "warmup_samples": 48, "workloads": summary}
if (root / "summary.json").exists():
    assert json.loads((root / "summary.json").read_text()) == result
if len(sys.argv) > 1:
    source = Path(sys.argv[1])
    for name, digest in receipt["variants"]["new"]["runtime_sources"].items():
        assert hashlib.sha256((source / name).read_bytes()).hexdigest() == digest, name
print(json.dumps(result, indent=2, sort_keys=True))
