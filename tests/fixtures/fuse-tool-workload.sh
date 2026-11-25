#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Identical BusyBox tools and static client under native Linux and Trames.
set -eu
ulimit -c 0
if test "$1" = --busybox; then
    cd "$2"
    mkdir directory
    printf 'a real busybox client\n' >directory/source
    cp directory/source directory/copied
    cmp directory/source directory/copied
    ln directory/source directory/hard
    ln -s source directory/symbolic
    test "$(cat directory/symbolic)" = 'a real busybox client'
    chmod 640 directory/copied
    test "$(stat -c %a directory/copied)" = 640
    mv directory/copied directory/moved
    find directory -type f | sort >/tmp/fuse-found
    test "$(wc -l </tmp/fuse-found)" -eq 3
    tar cf /tmp/fuse-copy.tar directory
    mkdir extracted
    tar xf /tmp/fuse-copy.tar -C extracted
    cmp directory/source extracted/directory/source
    test "$(readlink extracted/directory/symbolic)" = source
    rm -r directory extracted
    exit 0
fi
profile=$1
mkdir -p /work
mount -t tmpfs -o size=64m none /work
mkdir /work/source /work/view
case "$profile" in
    lowlevel) tool=/opt/fuse-tool/passthrough_ll; options=source=/work/source,cache=auto,xattr; base=/work/view ;;
    writeback) tool=/opt/fuse-tool/passthrough_ll; options=source=/work/source,cache=auto,xattr,writeback; base=/work/view ;;
    highlevel) tool=/opt/fuse-tool/passthrough; options=default_permissions; base=/work/view/work/source ;;
    *) exit 2 ;;
esac
(
    code=0
    "$tool" -d -s -o "$options" /work/view >/tmp/fuse-daemon.stdout 2>/tmp/fuse-daemon.stderr || code=$?
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
failed=0
run() {
    label=$1
    shift
    printf 'CASE %s START\n' "$label"
    if "$@"; then printf 'CASE %s PASS\n' "$label";
    else code=$?; printf 'CASE %s FAIL %s\n' "$label" "$code"; failed=1; fi
}
for scenario in ${2:-busybox mapping copyout metadata special aio copy transfer cached ring}; do
    case "$scenario" in
        busybox) run busybox timeout -s KILL 20 /bin/sh "$0" --busybox "$base" ;;
        transfer) run transfer timeout -s KILL 60 /opt/fuse-tool/client transfer "$base" ;;
        mapping|copyout|metadata|special|aio|copy|cached|ring) run "$scenario" timeout -s KILL 20 /opt/fuse-tool/client "$scenario" "$base" ;;
        *) exit 2 ;;
    esac
done
run unmount timeout -s KILL 10 umount /work/view
# Test-only bounded shutdown wait; production has no polling or helper thread.
run daemon-stop timeout -s KILL 10 /bin/sh -ec 'while ! test -f /tmp/fuse-daemon.exit; do sleep 0.1; done'
if ! test -f /tmp/fuse-daemon.exit; then
    exit 1
fi
run daemon-exit wait "$daemon"
trap - EXIT
printf 'WORKLOAD %s FAILED=%s\n' "$profile" "$failed"
exit "$failed"
