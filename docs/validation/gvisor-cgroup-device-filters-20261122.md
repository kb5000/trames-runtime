# Guest cgroup device filters, November 22, 2026

The Mac hardware runner executed the 39 original gVisor `cgroup2_ebpf` cases on both revisions. Each invocation ran an individually named case. The inventory check matched each result to its test XML, test binary hash and runner hash.

| Runner | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| Previous Trames | 21 | 15 | 3 |
| Updated Trames | 36 | 0 | 3 |
| Native ARM64 Linux reference | 37 | 0 | 2 |

Two tests require gVisor itself. The revision-counter test requires an advertised kernel version of at least 6.17 and skips on Trames. This batch covers device attachment and query semantics. Packet program execution, newer revision attributes and additional program types remain outside that coverage.

The guest uses the original cgroup and verified program descriptors for attachment. Creating programs and acquiring one by ID still require privilege. Each group has a local attach mode and can hold up to 64 multi-attach programs. A child can supersede an overridable parent; mandatory multi-attach ancestors still participate. The runtime rebuilds affected groups' effective lists on policy changes. Device access and effective queries read the same per-group snapshot. Regressions exercise actual device opens, task migration, rule replacement, close, detach and concurrent removal.

The syscall distinguishes nonzero extensions past the known attribute union from invalid command fields. Count-only queries return the full count, and short nonempty ID arrays report the required count after copying the available prefix. Ingress and egress queries return their own empty slots.

All 15 newly passing original cases also passed on the iPad interpreter running locally on Mac. The ARM64 iOS FFI build check passed. The local macOS runtime workflow completed all eight stages, reusing three unchanged checks. Physical iPad testing and installation were outside this run.

All 87 adjacent `cgroup2` cases retained their recorded outcomes (69 passes, 3 failures and 15 skips). The three failures concern memory accounting, charging to the nearest enabled memory controller and the v1/v2 controller mount conflict. Cumulative inventory across builds now covers 14,372 of 14,530 cases, with 13,769 passed, 63 failed, 23 timed out, 516 skipped and one fixture failure.

## Performance

Each old/new pair ran sequentially on the same two-CPU guest configuration, reversing execution order between pairs and discarding two warm-up pairs. Timings are medians in milliseconds, with 32 pairs for the four general workloads and 16 for device access. Each device sample opens and closes `/dev/null` 12,000 times per scenario. The inherited case uses an actual allow filter seven levels above the leaf in an eight-level hierarchy.

| Workload | Previous | Updated | Change |
| --- | ---: | ---: | ---: |
| memory | 170.284 | 170.076 | -0.12% |
| mmap fault unmap | 124.683 | 124.480 | -0.16% |
| file pread pwrite | 93.095 | 92.350 | -0.80% |
| fork wait | 18.309 | 18.323 | +0.07% |
| root device open | 75.244 | 75.573 | +0.44% |
| nested device open | 74.851 | 74.910 | +0.08% |
| inherited filter device open | 74.426 | 74.546 | +0.16% |

Baseline runner SHA-256 `d21c02cba420490210dcabce6d65267f18898bfa6fddcd5f03f10f0f309bffc1`. Updated runner SHA-256 `19908b03cc2cc879ce065e66a0ed30adc0440ccfa34145ee1a6bbc40bb70ddcc`.
