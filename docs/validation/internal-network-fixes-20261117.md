# Internal network transport and queue fixes — 2026-11-17

Private-link TCP now completes every bulk transfer, and 60 KB UDP no longer
stalls after a handful of sends. The former 16-datagram receive ceiling is
removed. The shared-fabric transaction remains a concurrency limit; this is
not a claim that internal networking matches native BSD throughput.

## Changes and failure mechanisms

- Replace the 4 KiB receive/unchecked Unix datagram wire with length-framed Unix
  streams. Complete Ethernet frames survive short reads and short writes.
  Actual retained output is bounded to 2 MiB per peer; blocked writers register
  writable readiness with the existing resource executor. The private protocol
  requires matching runtimes. No new coordinator or protocol service is added.
- Apply UDP byte-buffer settings and derive descriptor capacity from that
  budget. Live resizing retains queued messages, including across a shrink.
  A 64-message burst now retains 64/64 on both internal paths (formerly 16/64).
- Preserve the protocol library's single active IPv4 fragmentation buffer.
  Previously, another datagram could replace it while its first owner still
  needed fragments: a 60 KB datagram exceeds one bounded fabric slice.
  Transient exhaustion now retains the next socket datagram for retry.
- Advance the original pending protocol work when a nonblocking UDP/TCP writer
  exhausts its queue. Without this, repeated UDP EAGAIN could strand the final
  fragments on a separate fabric. The new private-link regression fails on the
  old writer and passes after repair.
- Replace two permanently occupied reassembly slots with a 512 KiB retained-data
  budget, allocation to received extent and pressure eviction of the least
  recently updated incomplete datagram. Lost or overlapping datagrams cannot
  prevent every new fragmented datagram from entering for 60 seconds.
- Avoid no-op checksum/NAT rewrites, empty-policy rule locks and duplicate route
  lookup. Use one fabric transaction per socket call, skip unrelated idle node
  polls, and consume buffered UDP without advancing the entire fabric.

The tiny local changes to the 0BSD smoltcp dependency are recorded in
[TRAMES-PATCHES.md](../../vendor/smoltcp/TRAMES-PATCHES.md). The 2.1 MiB vendor
snapshot is existing upstream code; three source files contain local changes.
The iPad and Mac workspace roots must both select this same patched dependency.

## Measurement conditions

Production source: `cc7bd05ad73174cac6f19e26e88f48dd350e0699`. Three samples per case, medians shown below.
The workload, path rotation, build profile, 0.75-second bulk window, 64-byte
RTT payload and 3,000 echoes match the [baseline](internal-network-tcp-udp-20261117.md).
TCP allows a bounded two-second tail drain and checks received bytes against
accepted sends: **all 12 internal TCP bulk samples complete**, including all
six previously failing private-link samples. The full matrix has 108 rows.

The benchmark runs native host threads; it excludes guest syscall/CPU cost.
The private case uses two independent fabrics in one host process. Host
loopback MTU is 16,384, internal MTU 1,500. UDP is unpaced overload: offered
rates differ, and loss must accompany received goodput. No core affinity or
exclusive machine reservation was used. TCP message counts are application
read/write calls, so only byte counts indicate TCP completion.

## TCP received goodput

Decimal Gbit/s; before/after are the original and repaired three-sample medians.

| Path | Before, one flow | After, one flow | Before, four flows | After, four flows |
| --- | ---: | ---: | ---: | ---: |
| Host BSD loopback | 116.57 | 115.86 | 110.75 | 112.47 |
| Trames native BSD | 94.79 | 94.32 | 115.41 | 114.40 |
| Internal Ethernet / shared fabric | 2.37 | 3.23 | 2.23 | 3.07 |
| Private link / two fabrics | incomplete | 2.52 | incomplete | 2.61 |

## UDP received goodput and loss

1,400-byte datagrams. Each cell is Gbit/s / lost datagrams.

| Path | Before, one flow | After, one flow | Before, four flows | After, four flows |
| --- | ---: | ---: | ---: | ---: |
| Host BSD loopback | 6.17 / 1.71% | 6.29 / 1.58% | 7.51 / 0.00% | 7.69 / 0.34% |
| Trames native BSD | 3.03 / 32.72% | 2.83 / 39.85% | 5.83 / 0.34% | 5.84 / 0.70% |
| Internal Ethernet / shared fabric | 1.38 / 27.14% | 1.14 / 62.23% | 0.92 / 0.87% | 2.21 / 2.98% |
| Private link / two fabrics | 1.43 / 0.03% | 1.89 / 0.00% | 0.93 / 1.39% | 1.61 / 0.00% |

The shared-fabric single-flow UDP overload case regresses in this run, with
about 62% loss. Four-flow shared UDP improves substantially; native BSD single
UDP also loses heavily under this unpaced workload. Faster enqueue is not a
lossless capacity result. Do not advertise a universal UDP speedup. The remaining
shared mutable fabric and producer/consumer scheduling need separate profiling
before a concurrency redesign; this patch does not replace that owner with a
broker or hide contention with extra threads.

60,000-byte fragmented datagrams, same Gbit/s / loss convention:

| Path | Before | After |
| --- | ---: | ---: |
| Host BSD loopback | 80.65 / 12.23% | 82.18 / 6.97% |
| Trames native BSD | 59.65 / 31.10% | 58.09 / 52.69% |
| Internal Ethernet / shared fabric | 0.84 / 78.33% | 3.84 / 31.35% |
| Private link / two fabrics | 0.00 / 99.98% | 7.98 / 0.00% |

All three private-link 60 KB samples receive every accepted datagram. This is
the measured workload, not a guarantee against overload loss at arbitrary rates.

## Small-message RTT

Median sample P50 / median sample P99, microseconds:

| Path | TCP | UDP |
| --- | ---: | ---: |
| Host BSD loopback | 17.50 / 82.46 | 17.38 / 82.00 |
| Trames native BSD | 26.25 / 85.75 | 18.75 / 83.33 |
| Internal Ethernet / shared fabric | 11.62 / 61.58 | 10.29 / 67.50 |
| Private link / two fabrics | 16.75 / 31.92 | 14.42 / 29.21 |

## Validation

- Shared runtime complete local CI: 8/8 shell steps pass, 1,644 tests pass and
  31 existing tests are ignored. Includes format, all-target/all-feature Clippy,
  release build and physical reclaim. Published smoltcp code retains upstream
  dependency warnings; Trames checks pass.
- Interpreter kernel conformance: 490 pass, three existing skips. Packet/TUN/TAP
  ABI acceptance passes with one and two CPUs using the repaired runtime.
- iOS `trames-ffi` checks for `aarch64-apple-ios`; physical iPad acceptance is
  outside this network benchmark.
- Mac workflow checks 1–10 and the signed embedded-Vulkan Dev build are checked
  with the repaired runtime. Installed Stable apps/environments are not replaced.
- Two independent Mac HVF Linux processes verify all bytes of an 8 MiB TCP
  transfer and a 60 KB UDP roundtrip with separate stores and a private wire.
  Both have two CPUs and exit successfully; the client measured 21.086 ms for
  the TCP transfer and acknowledgement. This is functional guest acceptance,
  separate from the host-thread throughput tables.

## Reproduction and evidence

```sh
python3 scripts/benchmark-ethernet.py 3 0.75 3000 > repaired-network.csv
python3 scripts/benchmark-ethernet.py --check-only
```

The Linux ABI fixture can also be built from the iPad checkout:

```sh
python3 runtime/scripts/build-packet-fixture.py target/ethernet/network-guest runtime/tests/fixtures/network-transfer.rs
```

Put that static binary at `/usr/bin/network-guest` in a disposable ARM64 rootfs
tar. Start the Mac hardware runner with `--network full --network-link DIR
--network-nat false --cpus 2 --no-windows --no-pty`, separate stores, network IDs
2 (server) and 3 (client). Run `/usr/bin/network-guest server`, wait for `READY`,
then run `/usr/bin/network-guest client` in the other guest. Each must print
`UDP_60000_OK`, with matching TCP byte counts.

- [All repaired samples](internal-network-fixes-20261117.csv)
- [Source hashes and measurement metadata](internal-network-fixes-20261117.json)
- [Baseline samples](internal-network-tcp-udp-20261117.csv)
- [Original-resource ownership and limits](../architecture/packet-networking.md)
