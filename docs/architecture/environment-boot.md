# Distribution import and optional systemd boot

The iPad interpreter and Mac HVF products share the same Linux process kernel.
`trames-distro` now owns the cold rootfs archive/directory importer, Debian package
profiles and systemd container preparation. Mac retains its CLI registry and stop
monitor integration; iPad retains its Files picker, environment catalog and app
lifecycle. No extra execution, resource-service or coordinator thread is added.

Pinned Alpine and Debian archives retain SHA-256 verification. Custom imports
snapshot archive/directory bytes, optionally verify a digest, validate paths and
links, and stream regular files into an unpublished VFS store. Nothing is
extracted into the host filesystem. Selected entrypoints must be executable Linux
ARM64 ELF files or scripts. Shell mode requires `/bin/sh`; systemd mode requires
original systemd, D-Bus and `setsid`. New imported environments renew an existing
machine identity once; ordinary restarts preserve it.

Systemd receives per-boot tmpfs/devpts, a guest console and the existing container
notify interface. Module loading and Linux seat management retain the established
container policy. Original service units keep their namespace, capability and
syscall protections. iPad's multi-terminal console launcher opens a per-boot FIFO
from the getty service, because PID 1 closes inherited numeric descriptors. This
uses the existing PTY masters and guest `setsid` shells; data is not proxied through
a new service thread. The app pauses the Linux scheduler in the background.

Masked `epoll_pwait` continuations retain their signal-mask authority on the
kernel owner. An asleep owner does not stop unrelated worker contexts: the
existing control boundary peeks at events, unmasked signals and the timeout
before joining. This observation preserves edge/one-shot watches and their
delivery cursor. The normal owner call still consumes events and restores the
temporary mask. No new polling loop, worker or syscall-filter exception is used.

`RLIMIT_NOFILE` is process-owned and inherited across fork/exec, shared by threads
independently of CLONE_FILES. The existing capability rules govern hard-limit
increases. `/proc/PID/limits` reports the values. Descriptor membership retains its
free-interval allocator; new allocations/duplication apply the caller's live soft
limit, including the worker FD fast path. Reducing a limit does not close existing
higher descriptors. Only allocation reads the relaxed atomic limit; ordinary
read/write, memory access and native calls gain no synchronization or check.

Bundled iPad Mesa/Xwayland/ICD binaries currently target musl. The frontend must
not inject those libraries into a glibc image. Debian/custom images retain their
own loaders and graphical libraries; the shared Wayland server remains available.
