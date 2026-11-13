# ext4-view 1.0.0

Upstream: https://github.com/nicholasbishop/ext4-view-rs
Registry source: ext4-view 1.0.0 (MIT OR Apache-2.0).

Local change: expose `DirEntry::inode_number` to preserve original hardlinks
when importing immutable Waydroid images. Filesystem parsing is unchanged.
