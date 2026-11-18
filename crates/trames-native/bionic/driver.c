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
// glibc AArch64 detects tininess before rounding. gdtoa exposes exact
// mathematical rounding direction, independently of host arithmetic side effects.
static void glibc_number(char *input, char **end, int single, struct result *out) {
    FPI fpi = single ? (FPI){24,-149,104,1,0} : (FPI){53,-1074,971,1,0};
    ULong words[2] = {0,0}; Long exponent=0;
    int kind=strtodg(input,end,&fpi,&exponent,words), tag=kind&STRTOG_Retmask;
    uint64_t mantissa=words[0]|((uint64_t)words[1]<<32), value=0;
    if(tag==STRTOG_Normal || tag==STRTOG_NaNbits) {
        unsigned fraction=single?23:52, bias=single?127:1023;
        value=(mantissa&((UINT64_C(1)<<fraction)-1))|((uint64_t)(exponent+bias+fraction)<<fraction);
    } else if(tag==STRTOG_Denormal) value=mantissa;
    else if(tag==STRTOG_Infinite) value=single?UINT64_C(0x7f800000):UINT64_C(0x7ff0000000000000);
    else if(tag==STRTOG_NaN) value=single?UINT64_C(0x7fc00000):UINT64_C(0x7ff8000000000000);
    int inexact=(kind&STRTOG_Inexact)!=0;
    int underflow=(kind&STRTOG_Underflow)!=0;
    // A tiny value rounded upward to the least normal number is still tiny
    // under glibc's AArch64 policy; a value rounded downward to it is not.
    uint64_t least_normal=single?UINT64_C(0x00800000):UINT64_C(0x0010000000000000);
    if(value==least_normal && (kind&STRTOG_Inexhi))underflow=1;
    out->fpsr=(inexact?16:0)|((kind&STRTOG_Overflow)?4:0)|(underflow?8:0);
    out->error=tag==STRTOG_NoMemory?ENOMEM:((kind&STRTOG_Overflow)||underflow)?ERANGE:0;
    if(kind&STRTOG_Neg)value|=UINT64_C(1)<<(single?31:63);
    out->bits=value;
}
static inline __attribute__((always_inline)) void parse_float(const unsigned char *bytes, size_t len, int single, struct result *out, int glibc) {
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
    out->fpsr=0;
    char *input = trames_gdtoa_malloc(len + 1), *end;
    if (!input) { out->bits = out->consumed = 0; out->error = ENOMEM; out->exhausted = 0; goto finished; }
    memcpy(input, bytes, len); input[len] = 0;
    errno = 0; end=input;
    if(glibc) glibc_number(input,&end,single,out);
    else if (single) {
        union { float value; uint32_t bits; } value = {.value = trames_bionic_strtof_native(input, &end)};
        out->bits = value.bits;
    } else {
        union { double value; uint64_t bits; } value = {.value = trames_bionic_strtod_native(input, &end)};
        out->bits = value.bits;
    }
    out->consumed = (uint64_t)(end - input); if(!glibc)out->error = errno; out->exhausted = 0;
finished: ;
#if defined(__aarch64__)
    if(!glibc) __asm__ volatile("mrs %0, fpsr" : "=r"(out->fpsr));
#else
    int flags = fetestexcept(FE_ALL_EXCEPT);
    if(!glibc) out->fpsr = ((flags & FE_INVALID) ? 1 : 0) | ((flags & FE_DIVBYZERO) ? 2 : 0)
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

void trames_bionic_parse_float(const unsigned char *bytes,size_t len,int single,struct result *out){parse_float(bytes,len,single,out,0);}
void trames_glibc_parse_float(const unsigned char *bytes,size_t len,int single,struct result *out){parse_float(bytes,len,single,out,1);}
