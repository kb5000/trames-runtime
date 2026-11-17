# Internal TCP/UDP measurements — 2026-11-17

The internal stack is functional, but these measurements expose two transport/queue defects and a parallel scaling limit. Private-link TCP bulk transfer is not healthy; its incomplete samples must not be presented as successful throughput.

## Conditions and reproduction

- Apple M6, 12 CPUs, 24 GiB RAM; macOS 27.0.1 / ARM64. Shared runtime production source `efb44a93f13a7ff4f1f48940f77a84072ccea43b`.
- Optimized Rust build, thin LTO and overflow checks, matching the product release profiles. The benchmark uses cached dependencies; the wrapper seeds its lockfile from the runtime.
- Three samples per case with path order rotated between samples. Bulk send window: 0.75 seconds; RTT: 64 warm-up echoes plus 3,000 measured echoes per sample. Tables show medians across samples, not pooled percentiles.
- A producer and consumer run concurrently for each flow. Four-flow figures are aggregate goodput across four pairs. No affinity or exclusive host reservation was used.
- Same-fabric tests use two internal environments. Private-link tests use two independent fabrics joined by real Unix datagram endpoints in the same host process. They exercise the wire transport, but do not include guest syscalls, CPU emulation/HVF, separate-process address-space switching or physical Ethernet.
- Neighbor resolution is warmed before bulk timing. No firewall rules or packet observers are enabled. TCP uses `TCP_NODELAY`; both endpoints request 256 KiB send/receive buffers. Internal sockets currently retain their actual fixed 64 KiB backing buffers, despite accepting these option values.
- Host loopback MTU is 16,384; internal Ethernet MTU is 1,500. The native loopback and internal stack have different segmentation/offload behavior. These are current-path observations, not an equal-MTU CPU-efficiency ratio.
- TCP goodput counts received bytes and checks them against accepted sends, allowing a bounded two-second tail drain. Incomplete drains are explicitly marked. UDP is an **unpaced overload test**: report received goodput together with loss; the offered rate differs between paths. A 20 ms idle receive drain is excluded from UDP throughput timing.

```sh
python3 scripts/benchmark-ethernet.py 3 0.75 3000 > tcp-udp.csv
python3 scripts/benchmark-ethernet.py --check-only
```

Run from the runtime checkout (prefix the paths with `runtime/` in the iPad checkout). The CSV retains every sample, sent/received bytes and message counts, RTT percentiles and completion status. TCP unit counters are application writes/reads, not wire packet counts.

## TCP bulk goodput

Application write size is 64 KiB. Units below are decimal Gbit/s.

| Path | One flow | Four flows, aggregate | Completion |
| --- | ---: | ---: | --- |
| Host BSD loopback | 116.57 | 110.75 | 3/3 single-flow; 3/3 four-flow |
| Trames native BSD path | 94.79 | 115.41 | 3/3 single-flow; 3/3 four-flow |
| Internal Ethernet / one fabric | 2.37 | 2.23 | 3/3 single-flow; 3/3 four-flow |
| Private Unix link / two fabrics | incomplete | incomplete | 0/3 single-flow; 0/3 four-flow |

All six private-link TCP bulk samples failed to deliver all accepted bytes within the bounded drain. Small TCP echo traffic still completes; the failure is exposed by bulk traffic, not by connection setup. Raw partial counts remain in the CSV.

## UDP bulk received goodput and loss

Payload is 1,400 bytes, without IP fragmentation. Values are median received Gbit/s / median lost datagrams under unpaced load. A high number with heavy loss is not a lossless operating point.

| Path | One flow | Four flows, aggregate |
| --- | ---: | ---: |
| Host BSD loopback | 6.17 / 1.71% | 7.51 / 0.00% |
| Trames native BSD path | 3.03 / 32.72% | 5.83 / 0.34% |
| Internal Ethernet / one fabric | 1.38 / 27.14% | 0.92 / 0.87% |
| Private Unix link / two fabrics | 1.43 / 0.03% | 0.93 / 1.39% |

## Small-message round-trip latency

64-byte payload, concurrent echo server. Values are median sample P50 / median sample P99, in microseconds.

| Path | TCP | UDP |
| --- | ---: | ---: |
| Host BSD loopback | 19.25 / 82.46 | 17.67 / 82.21 |
| Trames native BSD path | 26.38 / 84.58 | 17.33 / 82.08 |
| Internal Ethernet / one fabric | 15.58 / 78.08 | 14.38 / 75.50 |
| Private Unix link / two fabrics | 25.54 / 42.92 | 19.25 / 34.92 |

## UDP packet rate, fragmentation and burst retention

| Path | 64-byte payload, received kpps / loss | 60,000-byte datagram, received Gbit/s / loss | 64-message paused-reader burst, received |
| --- | ---: | ---: | ---: |
| Host BSD loopback | 581.4 / 0.83% | 80.6455 / 12.23% | 64/64 |
| Trames native BSD path | 375.2 / 5.87% | 59.6530 / 31.10% | 64/64 |
| Internal Ethernet / one fabric | 184.6 / 12.85% | 0.8376 / 78.33% | 16/64 |
| Private Unix link / two fabrics | 135.0 / 0.00% | 0.0006 / 99.98% | 16/64 |

The burst case deliberately sends all 64 messages while the application reader is paused, then drains the receiver. It tests buffering capacity rather than sustained throughput.

## Findings and next work

1. **Private wire backpressure is currently lossy.** `Fabric::attach` leaves Unix datagram buffers at their defaults. A separate local probe measured 2,048-byte send and 4,096-byte receive buffers. Only two 1,442- or 1,514-byte frames fit before `ENOBUFS` (55); 106-byte frames fit 30. `external_frame` ignores `send_to` errors. Together with bulk TCP failure and nearly complete loss of fragmented 60 KB UDP, this is strong evidence that queue pressure is losing frames. Packet-by-packet TCP retransmission tracing is still needed to attribute every stall. Preserve pending frames on the original link and use existing executor writable readiness; do not add a service/coordinator thread. Merely enlarging buffers will not eliminate the backpressure requirement.
2. **The UDP receive queue has a fixed 16-descriptor limit.** `udp_socket` allocates 16 receive metadata entries and 64 KiB of data. Both internal paths retain exactly 16/64 messages in every burst. `SO_RCVBUF` currently validates the value without resizing this storage. Make metadata/data capacity follow the original socket buffer budget and normal Linux controls, rather than another unrelated hard ceiling.
3. **Four flows do not scale the shared internal stack.** Internal TCP and UDP aggregate goodput drops instead of increasing. `FabricState` serializes a complete mutable fabric transaction; source inspection makes this a candidate bottleneck, but this run does not assign time percentages to lock waits, copies or packet processing. Profile those costs separately and compare matched MTUs before choosing the next concurrency/packet-processing change.

This change adds measurements and tooling only. It does not fix these production paths or update installed apps. The benchmark fixture passes targeted Clippy and formatting checks; the Python wrapper compiles. Existing full runtime/product CI results remain applicable to the unchanged production code.

## Evidence

- [Raw samples](internal-network-tcp-udp-20261117.csv)
- [Machine, command, source hashes and queue probe](internal-network-tcp-udp-20261117.json)
- [Benchmark wrapper](../../scripts/benchmark-ethernet.py)
- [Benchmark fixture](../../tests/fixtures/ethernet-throughput.rs)
