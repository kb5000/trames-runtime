# Private store synchronization

The shared private store uses the existing version 4 `manifest` as a checkpoint
and `manifest.wal` for incremental publications. Apple and Linux hosts share the
same format and durability path. RAM filesystems and host filesystem mounts do
not acquire a private journal. No coordinator, timer, service thread or UI setting
is added.

## Publication and checkpoints

A namespace/metadata transaction remains under the original per-store checkpoint
mutex. It prepares the next v4 image, then appends a delta against the last
accepted image instead of replacing the complete manifest. Unchanged spans refer
to the previous image; changed bytes are inline. Insertions/deletions can
resynchronize at exact byte anchors. The anchor index is bounded to 65,536 slots;
small contiguous edits bypass it. Snapshot construction and checksumming still
have CPU cost proportional to the image: this change removes disk write
amplification, rather than claiming an incremental in-memory namespace serializer.

Before synchronizing a record, any newly created/removed object directory entries
are synchronized. A complete record followed by successful `File::sync_all` is
the namespace commit point. Its first creation also makes the store directory
generation dirty. Later appends reuse the existing directory entry and need no
new directory flush. A failed post-commit directory flush remains pending for an
explicit sync; it does not roll back an already accepted namespace.

A failed append/sync truncates and synchronizes the unaccepted tail before the
caller rolls back its original metadata. If that repair itself fails, the store
rejects further metadata publication until recovery. Actual I/O errors remain
visible. Native writes retain the original cgroup admission and actual-byte
accounting; opening a blocked journal refunds unissued credit.

After 4 MiB of records or 1,024 publications, the next transaction first checkpoints
the **previously accepted** image. Explicit filesystem synchronization and startup
are also maintenance boundaries. The existing protocol writes/synchronizes
`manifest.new`, synchronizes changed object entries, renames the checkpoint and
synchronizes its directory. Only after that succeeds may the WAL be truncated and
synchronized. Current-transaction admission can wait after this maintenance: its
namespace is still unpublished and can roll back normally. A checkpoint and its
following delta are separate real I/O requests.

## Journal format and recovery

All integers are little endian. A frame is:

- `TRMWAL01` (8 bytes), payload length (`u64`), payload, payload FNV-1a-64 checksum.
- Payload: previous whole-image FNV-1a-64, resulting whole-image FNV-1a-64,
  resulting image length (`u64` each), followed by operations.
- Operation 0: source offset and length (`u64` each) in the previous image.
- Operation 1: inline length (`u64`) followed by those bytes.

The resulting image retains its independent v4 manifest checksum. Lengths,
operations, source ranges and the declared checksum chain are validated before
the VFS decodes nodes or cleans up orphan objects. Recovery carries immutable
byte spans through the delta chain, then materializes and checksums the final
image once. This avoids copying and hashing the whole namespace for every small
record during startup or File Provider reads. Span metadata is bounded, with a
flattened prefix fallback for excessive fragmentation. An incomplete final frame is ignored;
a malformed complete frame is rejected. These are corruption checks, not a
cryptographic authentication protocol.

A crash can leave the new checkpoint alongside an older, not-yet-truncated WAL.
Recovery finds the already-covered prefix by its resulting image checksum, then
requires every remaining frame to continue the accepted chain. Startup publishes
a fresh checkpoint before accepting guest mutations. Existing v3/v4 checkpoints
are supported and upgraded through the normal writer. A store containing a WAL
requires a journal-aware reader; older Runtime allowlists reject the sidecar
instead of silently opening stale metadata.

The iPad read-only File Provider replays the same format without acquiring the
writer lock, running recovery or modifying objects. It retries a checkpoint/WAL
pair when concurrent publication makes their chain inconsistent. Both its cache
signature and app-side change polling include the WAL, so a metadata append is
visible even while `manifest` keeps its inode and contents. Rust-generated Swift
fixtures cover a real record, an incomplete tail, an already-covered checkpoint,
hard links, cache signatures and corruption rejection.

## File and concurrency behavior

File bytes remain independent inode objects. `fdatasync` still synchronizes those
bytes (including host length metadata) without publishing timestamp-only metadata.
Mapped writeback, retained descriptors, unlinked objects, overlay projection,
capability sidecars and directory-generation retry retain their existing owners.
Apple keeps the existing `File::sync_data` durability policy.

Regular-file `fsync` uses the retained inode and its indexed fixed-width metadata
header. Its accepted image is updated only after journal publication. A new image
or checkpoint never changes which inode an existing open description refers to.
Plain byte I/O adds no generation counter, extra permission policy or new lock.
The record byte/count counters are advisory relaxed scalars, under the original
publication ownership.
