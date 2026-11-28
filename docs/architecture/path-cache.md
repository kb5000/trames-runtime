# Private namespace name cache

The shared VFS keeps a bounded, 256-slot cache per executing host thread for
private namespace lookups. Each slot contains the exact path bytes, filesystem
identity, namespace generation and a weak inode reference (or a negative result).
Apple and Linux use the same implementation and existing filesystem read guard.

The private path index owns its generation. Every mutable map access invalidates
it under the original filesystem write guard, including rollback, rename,
replacement, hard-link edits, mount changes and overlay copy-up. Replacing the
whole index assigns a fresh identity. Ordinary lookups and file-byte writes do
not add atomics, memory barriers or a new lock. Bounded slots retain no strong
inode/backing ownership, so they do not extend descriptor or store lifetimes.

A hit avoids the private BTreeMap search but still returns the live inode.
Permissions, timestamps, size, links and other stat fields remain live and keep
their existing checks. Host mounts, FUSE and pseudo filesystems retain their
existing lookup paths. This deliberately avoids caching a complete stat response
whose invalidation would require observing every data or metadata change.

This reduces repeated name-lookup work. Path normalization, symlink traversal and
stat assembly still cost CPU time; no code-server or git-status end-to-end timing
claim follows from the cache's semantic regression test.
