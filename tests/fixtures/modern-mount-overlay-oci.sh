#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
inputs=${MODERN_INPUTS:-/opt/modern}
mkdir -p /work /run
mount -t tmpfs -o mode=0777 tmpfs /work
mount -t tmpfs tmpfs /run
mkdir -p /work/lower /work/lower-map /work/store /work/upper-map /work/bundle/rootfs
cd /work
tar -xzf "$inputs/rootfs.tar.gz" -C lower
mkdir store/u store/w
chown 100000:200000 store/u store/w
"$inputs/overlay-check" map /work/lower /work/lower-map '0 100000 65536' '0 200000 65536'
"$inputs/overlay-check" map /work/store /work/upper-map '100000 0 262144' '200000 0 262144'
"$inputs/overlay-check" mount /work/lower-map /work/upper-map/u /work/upper-map/w /work/bundle/rootfs
cp "$inputs/overlay-oci.json" /work/bundle/config.json
mkdir -p /sys/fs/cgroup
mount --bind /sys/fs/cgroup /sys/fs/cgroup
mount -o remount,bind,ro /sys/fs/cgroup
cd /work/bundle
"$inputs/runc" --root /run/overlay-runc --rootless=true run modern-overlay
[ "$(stat -c %u:%g /work/store/u/etc/hostname)" = 200000:400000 ]
[ "$(cat /work/store/u/etc/hostname)" = modern-overlay ]
echo 'OCI_MAPPED_OVERLAY_RESULT:0'
