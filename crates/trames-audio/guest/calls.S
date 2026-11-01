/* SPDX-License-Identifier: GPL-3.0-or-later */
.text
.p2align 2
.hidden trames_audio_call
.global trames_audio_call
.type trames_audio_call,%function
trames_audio_call:
    movz x16, #8
    movk x16, #1, lsl #16
    movz x17, #1
    hlt #0x5452
    ret
.size trames_audio_call,.-trames_audio_call
.section .note.GNU-stack,"",%progbits
