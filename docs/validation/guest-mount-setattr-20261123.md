# Recursive mount attributes in the ARM64 guest

Debian's stock util-linux 2.41.5 can recursively bind a tree with read-only and noexec attributes on Mac HVF and on the product interpreter. Both the target and its nested tmpfs reject writes. The source stays writable and the target sees source updates. For the tmpfs superblock created by `fsopen`, `mountinfo` shows the target mount as `ro,noexec` and the shared superblock as `rw`.

The same stock command on the previous Mac runner applies its legacy remount fallback to the outer target. The nested target remains writable. On native ARM64 Linux and the new interpreter, the trace shows the modern sequence for the recursive bind:

1. `open_tree` clones the source and submounts with `OPEN_TREE_CLONE | AT_RECURSIVE`.
2. `mount_setattr` applies `MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOEXEC` to the detached FD with `AT_EMPTY_PATH | AT_RECURSIVE`.
3. `move_mount` attaches the completed clone to the destination.

The command is `mount -o rbind,ro=recursive,noexec=recursive SOURCE TARGET` with an additional tmpfs mounted below `SOURCE`. The [libmount implementation](https://github.com/util-linux/util-linux/blob/v2.41.5/libmount/src/hook_mount.c) supplies these operations. The [runc 1.3.0 implementation](https://github.com/opencontainers/runc/blob/v1.3.0/libcontainer/rootfs_linux.go#L1231) uses an attached mount through its proc FD path for recursive attributes. The guest fixture exercises the proc FD path. A full runc container startup with these options still needs its own acceptance run.

## Implemented ABI

- AArch64 syscall 442 imports the [Linux mount attribute structure](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/mount.h#L104), validates size and flags, and accepts zero-filled extensions up to one guest page. A no-op request skips pathname resolution. Changes require guest mount namespace administration capability.
- Path, directory FD, empty path and proc FD selection use the existing mount resolver. The operation handles attached mount roots and detached trees. It applies read-only, nosuid, nodev, noexec, relatime/noatime/strictatime and nodiratime. Bind aliases have independent mount attributes.
- Recursive requests prepare the selected mounts before publishing changes. Inherited locked attributes and live writable mapping references can reject a request. Failure on a child leaves the root and sibling properties unchanged. Preparing a read-only transition excludes admission of new shared writable mappings for those mounts. Ordinary reads, writes and private mappings use their existing paths. The existing writer accounting follows shared writable mapping leases. An idle writable regular-file FD alone does not pin a mount writable as it can on Linux.
- Propagation through `mount_setattr`, ID mapping and nosymfollow return `EOPNOTSUPP`. Filesystem reconfiguration via `fspick` and mount queries via `statmount` / `listmount` remain separate roadmap work.

## Validation

The [standalone AArch64 fixture](../../tests/fixtures/mount-setattr.c) passed on native Linux, Mac HVF and the interpreter. It covers an attached and a detached recursive tree, flag removal, independent source and clone attributes, `EBUSY` with a writable child mapping, rollback before publication, malformed extended structures, nofollow, proc FD selection and denied unprivileged use. Build on Linux ARM64 with `cc -static -O2 -Wall -Wextra -Werror tests/fixtures/mount-setattr.c -o /tmp/mount-setattr`; run as root in a disposable guest or private mount namespace.

| Original gVisor mount and mount_fd selection | Pass | Fail | Skip |
| --- | ---: | ---: | ---: |
| Native ARM64 reference | 155 | 0 | 3 |
| Mac hardware executor | 153 | 0 | 5 |
| Product interpreter | 152 | 1 | 5 |

All 158 case identities and original XML results were verified against the unchanged upstream binaries. The Mac outcomes match the rolling baseline. The two overlay mount-FD gaps remain conditional skips. The interpreter's `MountTest.UserNamespaceSysfsMountOverEmptyDir` fails at the same sysfs mount permission assertion on the exact previous runtime (`dee47a7`). All eight standalone runtime CI checks and the ARM64 iOS FFI check passed. The interpreter ran locally on the Mac.

Local traces, original XML, executable hashes and CI results are under `target/modern-mount-attrs` in the iPad checkout. `final/verified.json` identifies the final runners and the guest fixture.

## Ordinary workloads

The previous Mac runner and the final runner executed the same probe in alternating order. Each version had two warmups and 32 timed runs. Times are medians in milliseconds.

| Workload | Previous | Final | Change |
| --- | ---: | ---: | ---: |
| `memory` | 177.496 | 177.197 | -0.17% |
| `mmap_fault_unmap` | 140.129 | 140.212 | +0.06% |
| `file_pread_pwrite` | 98.975 | 99.607 | +0.64% |
| `fork_wait` | 20.203 | 20.300 | +0.48% |

Raw samples and runner hashes are in `final/performance-final.json`.
