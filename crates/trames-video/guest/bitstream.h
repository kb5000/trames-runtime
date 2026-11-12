// SPDX-License-Identifier: LGPL-2.1-or-later
// Negotiated original-bitstream VA extension. Ordinary VA clients keep H.264.
#ifndef TRAMES_VIDEO_BITSTREAM_H
#define TRAMES_VIDEO_BITSTREAM_H
#include <stdint.h>
#define TRAMES_VIDEO_CONFIGURATION_BUFFER 0x54520001
#define TRAMES_VIDEO_PACKET_BUFFER 0x54520002
// configuration = BE32 codec (1 HEVC / 2 AV1), then codec configuration.
// HEVC: three BE32-length-prefixed escaped VPS/SPS/PPS NALs.
// AV1: av1C with the original sequence OBU. Packets retain original OBU headers.
#define TRAMES_VIDEO_BITSTREAM_VERSION 1
#endif
