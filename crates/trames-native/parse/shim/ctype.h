/* SPDX-License-Identifier: GPL-3.0-or-later */
static inline int trames_scan_space(int c) { return c==' ' || (unsigned)(c-'\t')<5; }
#define isspace(c) trames_scan_space(c)
