# Atomic rename and exchange

The local Mac ARM64 runner executed 473 gVisor cases across ten complete suites
using disposable guest stores. The tests are from upstream revision
`89cacadae21eca4270a8f7c79281d0426d33ac5f`. The baseline runtime was
`163e3210356dd4ae0b49ea6e96671c7e5cfd8fbf`.

| Selection | Cases | Previously passed | Passed | Failed | Skipped | Missing result |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| rename | 44 | 34 | 42 | 2 | 0 | 0 |
| chdir, inotify, link, mkdir, mount, open, overlay, stat, unlink | 429 | 344 | 345 | 50 | 33 | 1 |
| Total | 473 | 378 | 387 | 52 | 33 | 1 |

All 387 passes have matching upstream XML records. Eight conversions in the
rename suite cover final dot components, missing exchange targets, exchanging
files and populated directories, and getcwd during concurrent exchanges.
The ninth conversion, nested overlay inode uniqueness, also passed in a
one-case rerun on the baseline binary. The change to rename accounts for eight
new passes. The mount suite still lacks a result for TmpfsSizeMmap.

Trames mounts sysfs read-only. The two remaining rename failures expect success
when renaming a sysfs file or directory to itself. The runner returns EROFS.
Linux obtains mount write access before the same-inode shortcut, so an
explicitly read-only mount and a writable sysfs mount have different outcomes.
See [Linux do_renameat2](https://github.com/torvalds/linux/blob/v6.12/fs/namei.c#L4797-L4808).

Updating the [preceding inventory](gvisor-inotify-20261119.md) with these 473
results gives 2,406 passes, 444 failures, 120 skips, 24 timeouts and four missing
results. The remaining 2,525 observations were carried forward.

## Namespace and storage

Private filesystems apply both directory-entry moves under the existing
filesystem lock. The rollback log and subtree search cover the affected names.
The store writes one checkpoint for the transaction. A forced checkpoint
failure test checks both names, timestamps, the current working directory and
the absence of watcher events. The successful case checks retained handles,
the two move-cookie pairs and both names after reopening the store.

Shared directories exchange names with the host's atomic rename operation. An
APFS regression test checks both host paths and exercises a retained guest file
descriptor and working directory across an exchange.

## Performance

The two runners alternated order. Each had two warmups. The tmpfs benchmark
used eight measured runs per runner and set the inode quota to 4,096. Each
sample timed 512 single-file renames. Sibling creation and mount setup were
outside the timed interval. The four common workloads used 16 measured runs per
runner. Values are median guest milliseconds.

| Workload | Baseline | Candidate | Change |
| --- | ---: | ---: | ---: |
| Rename, zero unrelated entries | 1.910 | 1.930 | +1.0% |
| Rename, 1,024 unrelated entries | 11.277 | 1.873 | −83.4% |
| Ordinary memory | 177.33 | 177.82 | +0.28% |
| Map, fault and unmap | 133.07 | 134.97 | +1.43% |
| 20,000 unwatched 4 KiB pwrite/pread pairs | 95.16 | 96.00 | +0.89% |
| 150 fork/wait pairs | 20.07 | 20.32 | +1.26% |

The rename timings isolate the in-memory namespace. A persistent private store
still has its checkpoint cost. Local raw evidence is under
`target/gvisor-rename-20261119` in the iPad checkout. The candidate runner
SHA-256 is `b51776a9317751c3bc55f82e5bf96dc315530bd7688bb124671177ed7ac70a56`.
