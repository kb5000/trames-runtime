#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Isolated guest/rootfs; stock runc 1.3.0 and OCI inputs are supplied by the runner.
set -eu
inputs=${MODERN_INPUTS:-/opt/modern}
mount --make-rprivate /
mkdir -p /work /run /dev/shm /sys/fs/cgroup
test -f /sys/fs/cgroup/cgroup.controllers || mount -t cgroup2 none /sys/fs/cgroup
mount --bind /sys/fs/cgroup /sys/fs/cgroup
mount -o remount,bind,ro /sys/fs/cgroup
mount -t tmpfs -o mode=755 none /work
mount -t tmpfs -o mode=755 none /run
mkdir -p /work/src /work/bundle/rootfs
mount -t tmpfs -o mode=777 none /work/src
mkdir /work/src/child
mount -t tmpfs -o mode=777 none /work/src/child
printf root > /work/src/file
printf child > /work/src/child/file
chmod 600 /work/src/file /work/src/child/file
# Each container uses a real Alpine userspace, supplied unchanged to all backends.
tar -xzf "$inputs/rootfs.tar.gz" -C /work/bundle/rootfs
"$inputs/runc" --version
cd /work/bundle
for case in recursive idmap recursive-idmap; do
    cp "$inputs/$case.json" config.json
    if "$inputs/runc" --rootless=true --root /run/modern-runc --debug --log /run/$case.log run modern-$case; then
        printf 'OCI_CASE %s PASS\n' "$case"
    else
        code=$?
        cat /run/$case.log
        exit "$code"
    fi
    if test "$case" = idmap; then
        test "$(stat -c %u:%g /work/src/new)" = 0:0
    fi
done
printf '%s\n' 'OCI_MODERN_MOUNTS_RESULT:0'
