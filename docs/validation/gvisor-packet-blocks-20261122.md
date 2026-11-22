# AF_PACKET V3 receive blocks and file lookup, 2026-11-22

## Capture on both execution backends

The guest can select TPACKET_V3, configure a receive ring with tpacket_req3, and map variable-length records. Each block carries a sequence number, offsets and timestamps. The producer preserves the application's private area and publishes ownership after writing the records. The existing network timer retires a partially filled block while the guest sleeps. Reader wakeups follow block publication. PACKET_STATISTICS includes the V3 freeze count and resets the counters on read. This work covers receive rings. Transmit rings remain unimplemented. [Linux packet ring ABI](https://docs.kernel.org/networking/packet_mmap.html)

The same ARM64 guest probe ran on the Mac hardware backend and the iPad interpreter hosted on the Mac. Each captured six loopback packets in three blocks and checked payloads, consistent flow hashes, the idle timer, poll readiness, reserved space, release and reuse, and all three statistics. The runtime unit test also covers cross-page records, truncation, a held block and the drop indication after a freeze.

| Original gVisor cases | Passed | Failed | Timed out | Skipped |
| --- | ---: | ---: | ---: | ---: |
| packet_mmap, previous hardware runner | 11 | 1 | 1 | 0 |
| packet_mmap, updated hardware runner | 12 | 0 | 1 | 0 |
| packet_mmap, native ARM64 Linux reference | 12 | 0 | 1 | 0 |
| Adjacent packet socket cases | 63 | 0 | 1 | 6 |
| Open, openat2 and selected proc and mount cases | 102 | 0 | 0 | 1 |

SetVersion now passes. MmapCopy waits for a conventional receive after a truncated capture without enabling PACKET_COPY_THRESH. It timed out on native Linux and both hardware runners. The twelve completing packet_mmap cases also passed on the interpreter. All 173 adjacent packet and file cases retained their previous individual outcomes, including the existing BasicCookedPacketTest.WrongType timeout. No physical iPad was used.

## Feature discovery

The first measurement of six KCOV cases exposed a file lookup error. Opening a missing file for writing without O_CREAT could return EROFS on a read-only filesystem. The error path now returns ENOENT on lookup and checks write policy when creation is actually requested. A regression checks missing sysfs opens in four modes and rejected creation. The final six originals explicitly skipped on both Trames and native Linux because KCOV was absent.

An additional 38 original Landlock v1 through v6 cases explicitly skipped because Trames does not implement the guest Landlock ABI. All 38 passed on the native reference. The cumulative cross-build inventory covers 14,416 of 14,530 discovered cases, with 13,770 passed, 62 failed, 23 timed out, 560 skipped and one fixture failure. There are 114 unmeasured cases.

The runtime CI completed all eight stages locally, reusing three unchanged checks. The ARM64 iOS FFI build check passed.

## Main-path performance

The old and new signed Mac runners alternated order over 32 measured pairs after two warm-up pairs. Each sample used the same two-CPU guest configuration with packet capture inactive. Values are median elapsed milliseconds. These timings measure the usual workloads rather than V3 capture throughput.

| Workload | Previous (ms) | Updated (ms) | Change |
| --- | ---: | ---: | ---: |
| udp bind close | 92.693 | 92.471 | -0.24% |
| udp connected delivery | 143.843 | 144.268 | +0.30% |
| tcp connect accept send | 19.363 | 19.517 | +0.79% |
| unix socketpair | 12.083 | 12.070 | -0.11% |
| unix stream send recv | 19.392 | 19.461 | +0.35% |
| unix datagram send recv | 20.881 | 21.119 | +1.14% |
| memory | 169.739 | 168.872 | -0.51% |
| mmap fault unmap | 124.999 | 124.998 | -0.00% |
| file pread pwrite | 95.017 | 95.106 | +0.09% |
| fork wait | 18.334 | 18.229 | -0.57% |

Previous runner SHA-256 `19908b03cc2cc879ce065e66a0ed30adc0440ccfa34145ee1a6bbc40bb70ddcc`. Updated runner SHA-256 `4725b4ee070dc313ba91f142b2544ab9b420e723c1cd821f14eb36f3b7d19d0f`. Guest capture probe SHA-256 `9cb7e5e072a9e7515b5a83604673d9c4cb837d26b1fcfa8bb2dfbd7c9f3c2b58`.
