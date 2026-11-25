#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Preserve the original workload exit and daemon evidence on every backend.
set -u
code=0
/bin/sh /opt/fuse-tool/workload.sh "$1" || code=$?
printf '\nFUSE_DAEMON_TRACE_BEGIN\n'
cat /tmp/fuse-daemon.stderr || code=1
printf '\nFUSE_DAEMON_TRACE_END\nFUSE_ACCEPTANCE_RESULT:%s\n' "$code"
exit "$code"
