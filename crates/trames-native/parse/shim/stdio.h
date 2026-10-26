/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Private bounded string cursor, never a guest or host libc FILE. */
#ifndef TRAMES_SCAN_STDIO_H
#define TRAMES_SCAN_STDIO_H
#include <stddef.h>
typedef struct {
    const unsigned char *bytes;
    size_t len, pos, origin;
    int error, exhausted;
} FILE;
#endif
