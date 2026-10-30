// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <va/va.h>
#include <stddef.h>
#include <stdint.h>
typedef struct {
    uint8_t sps[256], pps[1024];
    size_t sps_size, pps_size;
    unsigned pps_id, refs[2];
} TramesH264;
int trames_h264_slice(TramesH264*, const VAPictureParameterBufferH264*,
    const VASliceParameterBufferH264*, const uint8_t*, size_t);
int trames_h264_parameters(TramesH264*, VAProfile, unsigned, unsigned,
    const VAPictureParameterBufferH264*, const VAIQMatrixBufferH264*);
