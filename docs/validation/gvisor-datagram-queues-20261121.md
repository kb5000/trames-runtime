# UDP receive queues, reconnect and shutdown

Linux FIONREAD on a UDP socket reports the payload length of the next
datagram. A zero-length record and an empty queue both return zero. Only
receiving a record consumes it. The virtual backend reads the packet metadata
ring, handles padding at wraparound and preserves empty records. A mixed-route
socket checks the guest queue before the host queue in receive order. An
in-process DNS reply contributes its first pending payload length.

On macOS, SO_NREAD supplies the length of the first native socket record.
In a host loopback probe, an already-arrived pair with payloads of three and
five bytes reported 72 via FIONREAD and three via SO_NREAD. With an empty
first record followed by five bytes, the same queries returned 69 and zero.
A separate ARM64 Linux guest probe on the host network read queue lengths of
zero, three and five for both IPv4 and IPv6. Each measurement was repeated
before consuming the record.

The guest UDP stack applies peer selection at packet arrival. Datagrams
already queued at connect time remain readable. A read shutdown wakes
readers and preserves queued datagrams. After draining them, blocking reads
return zero and nonblocking receives report EAGAIN. File-description
O_NONBLOCK participates in receive processing alongside MSG_DONTWAIT.

## Upstream validation

The Mac hardware runner used the same 58 cases on both revisions, with an
internal bridge, two guest CPUs and a 25-second watchdog. The previous build
passed 38 and failed 20. The current build passed 52 and failed six. All 52
passes have matching original gTest XML. Fourteen cases changed from fail
to pass and none regressed. The Mac-hosted iPad interpreter passed the same
52 selected queue and stream control cases. The iOS device target compiled.

The remaining six cases exercise per-message IPv4/IPv6 traffic class and
TTL/hop-limit ancillary data, across three address-family combinations.
They failed on both builds. All 58 cases are new to the cumulative inventory.
It now records 3,463 cases with 3,292 passes, 59 failures, 91 skips, 20
timeouts and one fixture failure. Earlier results cover the other 3,405.

## Internal loopback timing

Identical release guest code alternated between hardware runners on the same
Mac. Each build had two warmups and 16 measured samples. Values are median
milliseconds per batch.

| Operation | Iterations | Before | After | Change |
| --- | ---: | ---: | ---: | ---: |
| Bind and close a UDP port | 2,000 | 97.479 | 96.293 | -1.22% |
| Connected UDP send and receive | 5,000 | 150.898 | 151.675 | +0.51% |
| TCP connect, accept and transfer two bytes | 100 | 21.689 | 21.632 | -0.26% |
