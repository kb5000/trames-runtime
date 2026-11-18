// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef TRAMES_GDTOA_STATE_H
#define TRAMES_GDTOA_STATE_H
typedef struct {
    Bigint *free_bins[10], *powers5;
    unsigned char hex_digits[256];
    void *allocations;
} TramesGdtoaState;
extern _Thread_local TramesGdtoaState *trames_gdtoa_state;
void *trames_gdtoa_malloc(size_t);
void trames_gdtoa_free(void *);
#define freelist (trames_gdtoa_state->free_bins)
#define p5s (trames_gdtoa_state->powers5)
#define __hexdig_D2A (trames_gdtoa_state->hex_digits)
#endif
