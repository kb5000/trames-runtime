# Private store synchronization

The private store retains the version 4 manifest and independent inode objects.
No new journal, on-disk record, service thread or execution coordinator is needed
for this optimization. Mac and iPad use the same implementation.

## Data-only synchronization

The manifest persists inode identity, permissions, timestamps, attributes and
namespace topology. It does not encode regular-file length: reopening obtains
length from the original host object. A regular private `fdatasync` therefore
flushes that object, including its host length metadata, without replacing the
manifest solely to publish timestamps.

Both original descriptor execution and retained asynchronous disk jobs use this
rule. Mapped files flush their shared pages before the underlying data sync.
Overlay copy-up retains its checkpoint path, directories retain namespace sync,
and anonymous/unlinked files retain their original data-only lifetime behavior.
Actual host I/O errors are still returned.

On Apple platforms the existing Rust `File::sync_data` remains a full device
flush. This change does not weaken the established file-data barrier. It also
does not promise native macOS `fdatasync` performance, whose host operation is
less expensive. Optimizing that policy requires an explicit durability design.

## Namespace durability generations

Each store tracks object-directory changes and manifest publication generations.
Creating or finally removing a private object changes the object generation;
recovery also marks orphan cleanup. A successful object-directory flush covers
only the generation observed before it. An unchanged object directory needs no
additional flush for a timestamp-only manifest update.

Manifest publication still writes and fully synchronizes `manifest.new`,
synchronizes any changed object directory, atomically renames the manifest, then
fully synchronizes the store directory. The last successful directory generation
allows an explicit `fsync` or shutdown to reuse that completed durability step.
A failed post-rename flush does not advance it: subsequent explicit sync retries
and reports a persistent failure without rolling back a committed namespace.
Completion uses a monotonic maximum, so it cannot acknowledge a later concurrent
mutation or overwrite another completion with an older generation.

Generation bookkeeping is confined to namespace publication and private-object
creation/destruction. Ordinary byte reads and writes gain no generation counter,
permission check, barrier, message or lock. Relaxed atomics track scalar flush
coverage; existing filesystem and checkpoint ownership still protects the data.

## File-specific manifest preparation

Each store retains the last accepted serialized manifest and a compact sorted
inode/offset vector under the existing checkpoint mutex. A regular file fsync
uses the original retained inode, updates only its fixed-width v4 metadata
header, and recalculates the existing whole-manifest checksum. It does not walk
paths, reconstruct the namespace/attribute tables or borrow unrelated inodes.
Metadata that already matches the accepted snapshot needs no new publication;
the original file-data synchronization and any pending directory retry remain.

Namespace and attribute transactions still construct a complete snapshot and
replace its offset index on success. Consequently hard links, replacement,
rename and variable-size attribute records cannot leave stale positions behind.
The cache is private to the original store, so equal inode numbers from different
stores do not share an index. Unlinked retained objects do not update a new inode
that happens to occupy their former pathname.

If publication fails before rename, both the cached 64-byte header and checksum
are restored. After rename, the cache describes the newly committed manifest;
directory-generation retry handles any remaining durability failure. Concurrent
file syncs merge into the latest snapshot through the original commit mutex.
Tests also hold an unrelated inode's metadata locked while completing target
file sync, ensuring whole-namespace traversal cannot return through this path.

This is CPU-side incremental preparation. The on-disk v4 file, checksum and
atomic-replacement protocol remain unchanged: each dirty metadata publication
still writes a complete manifest. The retained buffer is proportional to actual
manifest bytes and inode count, with no new work on ordinary byte reads/writes.

## Validation and remaining costs

Regressions exercise both descriptor/worker paths, hard links, file growth,
mapped writeback, unchanged manifests, namespace failure, post-rename durability
retry, and process exit without VFS shutdown. The complete Runtime workflow runs
locally on macOS; VFS also compiles for the physical iPad target.

Mac fio measurements and limitations are recorded in the product repository:
[storage synchronization acceptance](https://github.com/kb5000/trames-mac/blob/main/docs/validation/mac-storage-sync-20261115.md).
Data-only synchronization improves substantially. File-specific preparation also
reduces full-sync cost, while full file synchronization still replaces the whole
manifest with distinct data/manifest/directory barriers. Reducing those costs
further needs incremental on-disk metadata or a proven ordered barrier batch,
rather than silently removing durability steps.
