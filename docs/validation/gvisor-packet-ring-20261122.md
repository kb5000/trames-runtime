# AF_PACKET memory-mapped receive rings

The comparison uses runtime `36e427d3` as the baseline, the same Linux ARM64 gVisor binaries and the same Alpine image. Traffic stays on the guest loopback device. The hardware-backed and interpreter runs use the original GTest cases.

## Receive path

- TPACKET_V1 and V2 accept `PACKET_RX_RING`, validate the block/frame geometry, and map the ring using the guest memory subsystem. Block padding is excluded from frame indexing. Aliases share the original page objects. A mapping pins the original socket description and prevents ring replacement until unmapping.
- The producer writes the timestamp, socket address, captured length and payload before releasing frame ownership to the guest. The ownership word is 64 bits in the ARM64 V1 ABI and 32 bits in V2. The producer checks ownership before reusing a frame. A full ring increments the drop counter. Reading `PACKET_STATISTICS` returns and resets the counters.
- `PACKET_RESERVE` selects the packet offset. With nonzero `PACKET_COPY_THRESH`, a truncated packet can also enter the ordinary receive queue when it has space. With the default threshold of zero the ring receives the truncated frame. The end-to-end socket test covers both settings and the copy flag for both ABIs. [Linux packet ring documentation](https://docs.kernel.org/networking/packet_mmap.html)
- A blocking packet read now parks the calling guest task through the existing socket wait path. The saved operation retains its original socket. The direct-call regression verifies a nonblocking empty receive, a parked blocking receive, a wakeup on a new frame and completion with the expected length.

## Results

| packet_mmap | Passed | Failed | Timed out |
| --- | ---: | ---: | ---: |
| Previous runtime | 0 | 13 | 0 |
| Current Mac hardware runner | 11 | 1 | 1 |
| Native Linux ARM64 reference | 12 | 0 | 1 |

`SetVersion` reaches the check for TPACKET_V3. The runtime rejects V3 because it does not implement its block-level capture format and retirement timer. `MmapCopy` expects an additional packet on a blocking `recvfrom` without enabling `PACKET_COPY_THRESH`. Both the native reference and the final Trames runner time out there. This result is excluded from the pass count.

All 11 newly passing cases also passed on the iPad interpreter running on the Mac. The iOS arm64 FFI compiled. Runtime CI passed all eight stages locally.

Across the three final runs, all 979 cases outside packet_mmap retained their previous individual outcomes. The cumulative inventory covers 13,450 of 14,530 cases. It now contains 12,879 passes, 114 failures, 432 skips, 24 timeouts and one fixture failure.

## Main-path performance

The Mac ran the same guest fixtures on an isolated internal network, alternating the old and new runners for 32 measured pairs after two warm-up pairs. Results are median elapsed milliseconds with packet capture inactive.

| Workload | Before (ms) | After (ms) | Change |
| --- | ---: | ---: | ---: |
| udp bind close | 90.927 | 90.914 | -0.01% |
| udp connected delivery | 142.702 | 143.119 | +0.29% |
| tcp connect accept send | 18.954 | 18.863 | -0.48% |
| unix socketpair | 11.870 | 11.929 | +0.50% |
| unix stream send recv | 19.306 | 19.540 | +1.21% |
| unix datagram send recv | 20.884 | 21.032 | +0.71% |
| get link | 2.234 | 2.244 | +0.45% |
| dump addr | 6.518 | 6.505 | -0.19% |
| dump route | 8.413 | 8.420 | +0.08% |
