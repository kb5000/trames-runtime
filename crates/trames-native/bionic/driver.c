// SPDX-License-Identifier: GPL-3.0-or-later
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fenv.h>
#include "gdtoaimp.h"
_Thread_local TramesGdtoaState *trames_gdtoa_state;
typedef struct Allocation { struct Allocation *next; max_align_t alignment; } Allocation;
void *trames_gdtoa_malloc(size_t size) {
    Allocation *allocation = malloc(sizeof(*allocation) + size);
    if (!allocation) return NULL;
    allocation->next = trames_gdtoa_state->allocations;
    trames_gdtoa_state->allocations = allocation;
    return allocation + 1;
}
void trames_gdtoa_free(void *unused) { (void)unused; }
struct result { uint64_t bits, consumed; int error, exhausted; uint64_t fpsr; };
void trames_bionic_parse_float(const unsigned char *bytes, size_t len, int single, struct result *out) {
    int saved_errno = errno;
#if defined(__aarch64__)
    uint64_t fpcr, fpsr, selected = 0, zero = 0;
    __asm__ volatile("mrs %0, fpcr\n mrs %1, fpsr\n msr fpcr, %2\n msr fpsr, %3"
        : "=&r"(fpcr), "=&r"(fpsr) : "r"(selected), "r"(zero) : "memory");
#else
    fenv_t saved_env; feholdexcept(&saved_env);
    fesetround(FE_TONEAREST);
#endif
    TramesGdtoaState state = {0}, *saved_state = trames_gdtoa_state;
    trames_gdtoa_state = &state;
    char input[len + 1], *end;
    memcpy(input, bytes, len); input[len] = 0;
    errno = 0;
    if (single) {
        union { float value; uint32_t bits; } value = {.value = trames_bionic_strtof_native(input, &end)};
        out->bits = value.bits;
    } else {
        union { double value; uint64_t bits; } value = {.value = trames_bionic_strtod_native(input, &end)};
        out->bits = value.bits;
    }
    out->consumed = (uint64_t)(end - input); out->error = errno; out->exhausted = 0;
#if defined(__aarch64__)
    __asm__ volatile("mrs %0, fpsr" : "=r"(out->fpsr));
#else
    int flags = fetestexcept(FE_ALL_EXCEPT);
    out->fpsr = ((flags & FE_INVALID) ? 1 : 0) | ((flags & FE_DIVBYZERO) ? 2 : 0)
        | ((flags & FE_OVERFLOW) ? 4 : 0) | ((flags & FE_UNDERFLOW) ? 8 : 0) | ((flags & FE_INEXACT) ? 16 : 0);

#endif
    Allocation *allocation = state.allocations;
    while (allocation) { Allocation *next = allocation->next; free(allocation); allocation = next; }
    trames_gdtoa_state = saved_state;
#if defined(__aarch64__)
    __asm__ volatile("msr fpcr, %0\n msr fpsr, %1" :: "r"(fpcr), "r"(fpsr) : "memory");
#else
    fesetenv(&saved_env);
#endif
    errno = saved_errno;
}
