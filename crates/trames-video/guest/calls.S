/* SPDX-License-Identifier: GPL-3.0-or-later */
.text
.p2align 2
.hidden trames_video_call
.global trames_video_call
.type trames_video_call,%function
trames_video_call:
    movz x16, #7
    movk x16, #1, lsl #16
    movz x17, #1
    hlt #0x5452
    ret
.size trames_video_call,.-trames_video_call
.section .note.GNU-stack,"",%progbits
