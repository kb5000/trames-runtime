# nftables chain ownership and batch-local IDs

The reference runtime for this comparison is `5472141`. Netlink batches can now create an anonymous binding chain, add rules to it by chain ID and jump or go to it before committing. A rule can refer to a previously added rule by ID to position or delete it within the same chain. Dumps report the resolved jump target and the binding flag. Object handles keep IDs scoped to the original object when names are reused. These operations use the existing ruleset transaction and packet evaluator.

A binding chain has one owner. Deleting or replacing its owning rule, deleting the parent chain or flushing its rules releases the bound chain. An unbound chain at commit fails the transaction. A committed binding chain rejects independent edits and another reference. A failed transaction preserves the published ruleset and its filtering behavior. The reference for object lookup, binding and rule placement is the [Linux nf_tables implementation](https://github.com/torvalds/linux/blob/master/net/netfilter/nf_tables_api.c).

## Compatibility

| Original gVisor coverage | Before | After |
| --- | ---: | ---: |
| Chain-ID and anonymous-chain cases | 5 passed, 3 failed | 8 passed |
| All 268 Netlink Netfilter cases | 246 passed, 15 failed, 7 skipped | 249 passed, 12 failed, 7 skipped |

The three recovered cases are `AddRuleWithAnonymousChainJump`, `ErrDeleteChainByID` and `ErrUpdateBindingChain`. The other 265 cases retained their previous classifications. Seven payload-expression and five packet-metadata failures remain. Binary hashes and original GoogleTest XML were checked for each case. The iPad interpreter on Mac passed all eight focused cases and the iOS ARM64 FFI compiled. This batch did not include a physical iPad run.

The additional runtime tests build a rule ahead of another by ID, verify drop and delivery between two virtual UDP sockets, reject a second owner, exercise stale and cross-chain IDs, and verify cleanup and rollback. The eight local runtime CI steps passed, including 1,889 tests. The cumulative inventory covers 14,372 of 14,530 original cases, with 13,722 passes, 110 failures, 23 timeouts, 516 skips and one fixture failure.

## Performance

Each signed Mac release runner used the same two-CPU guest configuration. Two warmup pairs preceded 32 measured pairs, with alternating runner order. Times below are median guest milliseconds.

| Workload | Before | After | Change |
| --- | ---: | ---: | ---: |
| udp_active_output_counter | 154.93 | 154.45 | -0.31% |
| udp_64B | 45.79 | 45.92 | +0.28% |
| udp_1400B | 46.78 | 46.63 | -0.31% |
| udp_8KiB | 36.30 | 36.73 | +1.20% |
| tcp_16KiB | 71.96 | 72.08 | +0.16% |
| memory | 176.03 | 175.84 | -0.11% |
| mmap_fault_unmap | 132.23 | 134.59 | +1.78% |
| file_pread_pwrite | 98.69 | 100.33 | +1.66% |
| fork_wait | 19.85 | 19.81 | -0.17% |
