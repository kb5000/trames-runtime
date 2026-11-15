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

## Validation and remaining costs

Regressions exercise both descriptor/worker paths, hard links, file growth,
mapped writeback, unchanged manifests, namespace failure, post-rename durability
retry, and process exit without VFS shutdown. The complete Runtime workflow runs
locally on macOS; VFS also compiles for the physical iPad target.

Mac fio measurements and limitations are recorded in the product repository:
[storage synchronization acceptance](https://github.com/kb5000/trames-mac/blob/main/docs/validation/mac-storage-sync-20261115.md).
Data-only synchronization improves substantially. Full file synchronization still
serializes and replaces the whole manifest, with distinct data/manifest/directory
barriers. Reducing those costs further needs an incremental metadata design or a
proven ordered barrier batch, rather than silently removing durability steps.
