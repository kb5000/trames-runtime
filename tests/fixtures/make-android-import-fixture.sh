#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Linux-only fixture generation; run in a disposable native Linux CI directory.
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/root/bin" "$work/root/data"
printf preserved > "$work/root/bin/tool"
chmod 755 "$work/root/bin/tool"
ln "$work/root/bin/tool" "$work/root/bin/tool-hard"
ln -s tool "$work/root/bin/tool-soft"
ln -s /bin "$work/root/tools"
printf omitted > "$work/root/data/private"
chown 1000:1001 "$work/root/bin/tool"
truncate -s 8M "$work/image"
mkfs.ext4 -q -F -d "$work/root" "$work/image"
gzip -c "$work/image" > "${1:?output .ext4.gz path required}"
