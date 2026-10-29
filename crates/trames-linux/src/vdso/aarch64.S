// SPDX-License-Identifier: GPL-3.0-or-later
// AArch64 Linux vDSO entry points. All data is immutable to guest EL0.
.text
.p2align 2
.global __kernel_clock_gettime
.type __kernel_clock_gettime,%function
__kernel_clock_gettime:
    cmp w0,#1
    b.eq .Lmono
    cmp w0,#4
    b.eq .Lmono
    cmp w0,#6
    b.eq .Lmono
    cmp w0,#7
    b.ne .Lclock_syscall
.Lmono:
    adr x9,vdso_data
    ldp x10,x11,[x9]
    cbz x11,.Lclock_syscall
    isb
    mrs x12,cntvct_el0
    subs x12,x12,x10
    b.lo .Lclock_syscall
    udiv x13,x12,x11
    msub x12,x13,x11,x12
    movz x14,#0xca00
    movk x14,#0x3b9a,lsl #16
    mul x12,x12,x14
    udiv x12,x12,x11
    ldp x10,x11,[x9,#16]
    add x12,x12,x11
    add x13,x13,x10
    cmp x12,x14
    cinc x13,x13,hs
    sub x10,x12,x14
    csel x12,x10,x12,hs
    stp x13,x12,[x1]
    mov x0,#0
    ret
.Lclock_syscall:
    mov x8,#113
    svc #0
    ret
.size __kernel_clock_gettime,.-__kernel_clock_gettime
.global __kernel_clock_getres
.type __kernel_clock_getres,%function
__kernel_clock_getres:
    cmp w0,#1
    b.ls .Lres
    sub w9,w0,#4
    cmp w9,#3
    b.hi .Lres_syscall
.Lres:
    cbz x1,.Lres_return
    mov x9,#1
    stp xzr,x9,[x1]
.Lres_return:
    mov x0,#0
    ret
.Lres_syscall:
    mov x8,#114
    svc #0
    ret
.size __kernel_clock_getres,.-__kernel_clock_getres
.global __kernel_gettimeofday
.type __kernel_gettimeofday,%function
__kernel_gettimeofday:
    mov x8,#169
    svc #0
    ret
.size __kernel_gettimeofday,.-__kernel_gettimeofday
.global __kernel_rt_sigreturn
.type __kernel_rt_sigreturn,%function
__kernel_rt_sigreturn:
    mov x8,#139
    svc #0
    ret
.size __kernel_rt_sigreturn,.-__kernel_rt_sigreturn
.section .note.GNU-stack,"",%progbits
