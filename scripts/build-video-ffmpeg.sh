#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Build a private, ABI-compatible FFmpeg overlay; never replace distro libraries.
set -euo pipefail
cd "$(dirname "$0")/.."
output="${TRAMES_FFMPEG_OUTPUT:-$PWD/target/video-ffmpeg}"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
jobs="${TRAMES_BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN)}"
archive="$output/ffmpeg-7.1.1.tar.xz"
mkdir -p "$output"
if [[ ! -f "$archive" ]]; then
  curl -fL --retry 2 https://ffmpeg.org/releases/ffmpeg-7.1.1.tar.xz -o "$archive"
fi
printf '%s  %s\n' 733984395e0dbbe5c046abda2dc49a5544e7e0e1e2366bba849222ae9e3a03b1 "$archive" | sha256sum -c -
patch_hash="$(sha256sum patches/ffmpeg/0001-vaapi-original-bitstream-v1.patch | cut -d' ' -f1)"
if [[ ! -d "$output/source" ]]; then
  mkdir -p "$output/source"
  tar -xJf "$archive" --strip-components=1 -C "$output/source"
  patch -d "$output/source" -p1 < patches/ffmpeg/0001-vaapi-original-bitstream-v1.patch
  printf '%s\n' "$patch_hash" > "$output/source/.trames-patch"
fi
if [[ "$(cat "$output/source/.trames-patch")" != "$patch_hash" ]]; then
  echo 'FFmpeg output contains a different source patch; choose a fresh TRAMES_FFMPEG_OUTPUT.' >&2
  exit 1
fi
mkdir -p "$output/build"
(
  cd "$output/build"
  "$output/source/configure" --prefix="$output/install" \
    --disable-doc --disable-debug --disable-static --enable-shared \
    --disable-autodetect --disable-ffplay --enable-vaapi --enable-libdrm "$@"
  make -j"$jobs"
  make install
)
python3 - "$output" <<'PY'
import hashlib,json,sys
from pathlib import Path
p=Path(sys.argv[1]);lib=p/'install/lib'
record={'ffmpeg':'7.1.1','libavcodec_major':61,'bitstream_protocol':1,
        'source_sha256':'733984395e0dbbe5c046abda2dc49a5544e7e0e1e2366bba849222ae9e3a03b1',
        'patch_sha256':hashlib.sha256(Path('patches/ffmpeg/0001-vaapi-original-bitstream-v1.patch').read_bytes()).hexdigest(),
        'libraries':{f.name:hashlib.sha256(f.read_bytes()).hexdigest()
                     for f in sorted(lib.glob('*.so.*')) if f.is_file() and not f.is_symlink()}}
(p/'install/manifest.json').write_text(json.dumps(record,indent=2)+'\n')
PY
cp "$output/source/COPYING.LGPLv2.1" "$output/install/"
