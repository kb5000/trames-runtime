# nftables packet classes and interface metadata

Internal Ethernet ingress now carries its Linux packet class through IP filtering. Packet sockets and the firewall use the same destination-MAC classification. UDP group delivery preserves the class on local loopback and received frames. The evaluator reads packet class, interface hardware type and link kind directly into nftables registers. Interface names, kinds and scalar values are padded to their ABI width. The existing protocol, length and interface-index reads also use the allocation-free path. Malformed keys and conflicting source/destination registers return the corresponding Netlink errors. See the [Linux nftables metadata implementation](https://github.com/torvalds/linux/blob/master/net/netfilter/nft_meta.c).

## Compatibility

The reference is runtime `7f20ff9`. Both signed Mac guest runners used the same original gVisor binaries. Case identities, binary hashes, runner hashes and individual GoogleTest XML outcomes were verified.

| Original cases | Before | After |
| --- | ---: | ---: |
| Six Netfilter metadata cases | 1 pass, 5 failures | 5 passes, 1 failure |
| All 268 Netlink Netfilter cases | 249 passes, 12 failures, 7 skips | 253 passes, 8 failures, 7 skips |
| UDP interface cases (IPv4 and IPv6) | 46 passes | 46 passes |
| Previously passing packet socket, packet mmap and TUN/TAP cases | 93 passes | 93 passes |

The recovered cases are `GetValid`, `SetValid`, `WithSregAndDregSet` and `WithInvalidKey`. Despite its name, the upstream `SetValid` case loads the packet class into a destination register. Packet marks (`GetMarkValid`) and seven payload-expression cases remain open. Metadata writes via a source register are still unsupported.

Runtime tests check actual UDP unicast, multicast and broadcast delivery with accept/drop rules and verify register padding, missing interfaces and bridge link kind. All eight local CI steps passed (1,892 tests). The iPad interpreter running on Mac reproduced the same five passes and the packet-mark failure. The iOS ARM64 FFI compiled. No physical iPad run was performed.

The cumulative inventory contains 14,372 measured cases out of 14,530. It records 13,726 passes, 106 failures, 23 timeouts, 516 skips and one fixture failure. Results outside this batch retain their previous measurements.

## Performance

Each series alternated the previous and current signed Mac runners, with two warmup pairs followed by 32 measured pairs. The guest had two CPUs. The interface-match workload loads the output interface index, compares it to loopback and verifies exactly 5,000 counter hits per sample. Times are median guest milliseconds per workload. Positive change means longer elapsed time.

| Workload | Before (ms) | After (ms) | Change |
| --- | ---: | ---: | ---: |
| udp_meta_oif_match_counter | 151.53 | 151.69 | +0.11% |
| udp_active_output_counter | 152.00 | 151.85 | -0.10% |
| udp_64B | 45.55 | 45.97 | +0.91% |
| udp_1400B | 47.05 | 46.64 | -0.87% |
| udp_8KiB | 36.27 | 36.24 | -0.10% |
| tcp_16KiB | 71.51 | 72.30 | +1.11% |
| memory | 175.32 | 178.15 | +1.61% |
| mmap_fault_unmap | 131.26 | 137.51 | +4.76% |
| file_pread_pwrite | 99.13 | 99.89 | +0.77% |
| fork_wait | 19.50 | 19.39 | -0.57% |

The memory, file and process suite was repeated because the first mapping/fault/unmap series was 4.76% slower. The independent 32-pair repeat measured the following changes: memory -0.32%, mmap_fault_unmap -1.24%, file_pread_pwrite -1.25%, fork_wait -0.75%. Both runs are retained.
