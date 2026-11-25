#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
ulimit -c 0
profile=$1
repeats=${2:-5}
workers=${3:-1}
diagnostic=${4:-0}
scale=${5:-1}
mkdir -p /work
mount -t tmpfs -o size=64m none /work
mkdir /work/source /work/view /work/plain
case "$profile" in
    lowlevel) tool=/opt/fuse-tool/passthrough_ll; options=source=/work/source,cache=auto,xattr; base=/work/view ;;
    writeback) tool=/opt/fuse-tool/passthrough_ll; options=source=/work/source,cache=auto,xattr,writeback; base=/work/view ;;
    highlevel) tool=/opt/fuse-tool/passthrough; options=default_permissions; base=/work/view/work/source ;;
    *) exit 2 ;;
esac
foreground=-f
test "$diagnostic" -eq 0 || foreground=-d
(
    code=0
    "$tool" "$foreground" -s -o "$options" /work/view >/tmp/fuse-daemon.stdout 2>/tmp/fuse-daemon.stderr || code=$?
    printf '%s\n' "$code" >/tmp/fuse-daemon.exit
    exit "$code"
) &
daemon=$!
cleanup() {
    umount /work/view 2>/dev/null || true
    kill "$daemon" 2>/dev/null || true
    wait "$daemon" 2>/dev/null || true
}
trap cleanup EXIT
timeout -s KILL 10 /opt/fuse-tool/client ready /work/view
sample=0
while test "$sample" -le "$repeats"; do
    timeout -s KILL 40 /opt/fuse-tool/client transfer "$base" "$sample"
    count=0
    children=
    while test "$count" -lt "$workers"; do
        if test "$scale" -eq 1; then
            timeout -s KILL 60 /opt/fuse-tool/client ordinary /work/plain "$sample" &
        else
            timeout -s KILL 60 /opt/fuse-tool/client ordinary /work/plain "$sample" "$scale" &
        fi
        children="$children $!"
        count=$((count + 1))
    done
    for child in $children; do wait "$child"; done
    sample=$((sample + 1))
done
timeout -s KILL 10 umount /work/view
timeout -s KILL 10 /bin/sh -ec 'while ! test -f /tmp/fuse-daemon.exit; do sleep 0.1; done'
wait "$daemon"
trap - EXIT
printf 'PERFORMANCE %s DONE\n' "$profile"
