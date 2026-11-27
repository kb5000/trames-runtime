# Retained executable and O_PATH admission — 2026-11-27

Feature commit `5cc2476bea28f44af095752811c026868f1e442b` fixes two shared
pathname classifications exposed by original runc in managed private stores:

- Reopening `/proc/self/exe` after sealed memfd self-reexec uses the original
  retained executable inode, even when CLOEXEC closed its last numeric FD.
  Ordinary open/permission/seal checks create a fresh OFD. A missing prepared
  owner fallback no longer leaks EIO into this valid operation.
- O_PATH admits inode/mount identity without opening a device or rendering its
  volatile bytes. Original runc can retain a newly mounted devpts root and
  change propagation through its procfd. Actual PTY/device opens retain their
  original permission, task and capacity handling.

The regression exercises live ProcessView/proc resource publication, both
memory/private-disk VFS, seals, alias paths and inode identity. Devpts checks
require that O_PATH allocates no PTY; the existing actual-device rollback and
policy checks remain. All-feature VFS tests passed: Linux 1186 and Apple 1178,
with one existing ignored test per platform. Scoped all-target/all-feature
Clippy passed on both platforms.

The [owning Linux record](https://github.com/project-trames/trames-linux/blob/main/docs/validation/runc-managed-20261127.md)
retains a hash-bound pre-fix C self-reexec failure, native reference, exact final
runner/source receipts and six complete original Docker cohorts: systemd with
SMCCC/MMIO × one/four CPUs, plus shell with both transports/four CPUs. They cover
actual host HTTP, container DNS/exec/seccomp, persistent volumes, daemon restart
and native port release. Sixteen KVM sealed self-reexecs also passed. The
[paired Mac record](https://github.com/project-trames/trames-mac/blob/main/docs/validation/runc-fix-20261127.md)
adds six actual HVF self-reexecs with one/four CPUs.

No application/library patch, alternate OCI runtime, forced GOMAXPROCS,
coordinator/service thread, ordinary-memory barrier or CPU-loop check was added.
The source fix retains original resource authority rather than deriving it from
an executable's display name. Integrated main preserves the tested feature
commit; the independent memory-lifecycle integration received formatting-only
closure. The Mac adapter separately matches the shared compiler recursion limit
for its existing Send proofs; this is a compile-time setting.
