#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
cd "$(dirname "$0")/.."
output="${TRAMES_VIDEO_OUTPUT:-$PWD/target/video-guest}"
compiler="${TRAMES_VIDEO_CC:-musl-gcc}"
headers="${TRAMES_VIDEO_HEADERS:-$(pkg-config --variable=includedir libva)}"
mkdir -p "$output/include"
# Copy only libva headers. Adding the system /usr/include to musl's search path
# would accidentally mix glibc declarations into a musl guest driver.
cp -R "$headers/va" "$output/include/"
"$compiler" -O2 -fPIC -fvisibility=hidden -shared -pthread \
  -Wall -Wextra -Werror -Wno-misleading-indentation \
  -I "$output/include" -I crates/trames-video/guest \
  crates/trames-video/guest/driver.c crates/trames-video/guest/h264.c \
  crates/trames-video/guest/calls.S -Wl,-z,noexecstack \
  -o "$output/trames_drv_video.so"
readelf -h "$output/trames_drv_video.so" | awk '/Machine:.*AArch64/ { found=1 } END { exit !found }'
python3 - "$output" <<'PY'
import hashlib,json,sys,subprocess
from pathlib import Path
p=Path(sys.argv[1]);driver=p/'trames_drv_video.so'
v={'profile':65543,'auxv_key':'0x54520009','wire_revision':1,
   'driver_init':'__vaDriverInit_1_0','experimental':True,
   'decode':'progressive H.264 8-bit 4:2:0; POC types 0/2',
   'host_backend':'VideoToolbox hardware-required',
   'completion':'per-surface guest eventfd; blocking guest poll',
   'frame_export':{'operation':8,'memory_type':'DRM_PRIME_2','access':'read-only','planes':['R8','GR88'],'modifier':'LINEAR','fd_ownership':'guest files_struct'},'sha256':hashlib.sha256(driver.read_bytes()).hexdigest(),
   'needed':subprocess.check_output(['readelf','-d',str(driver)],text=True)}
(p/'manifest.json').write_text(json.dumps(v,indent=2)+'\n')
PY
cp LICENSE "$output/GPL-3.0.txt"
