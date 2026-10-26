/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "stdio.h"
static inline int trames_scan_get(FILE *f) {
    if (f->pos < f->len) return f->bytes[f->pos++];
    f->exhausted=1;
    if (f->pos==f->len) f->pos++;
    return 0;
}
#define shgetc(f) trames_scan_get(f)
#define shunget(f) ((void)((f)->pos ? (f)->pos-- : 0))
#define shlim(f, lim) ((void)((f)->origin=(f)->pos))
#define shcnt(f) ((f)->pos >= (f)->origin ? (f)->pos-(f)->origin : 0)
