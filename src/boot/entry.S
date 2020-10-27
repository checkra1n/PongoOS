// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
//
//  Copyright (c) 2019-2020 checkra1n team
//  This file is part of pongoOS.
//
.globl start
.align 4
start:
// branch from x27 will end up here
    mov x9, x8
// branch from x29 here
    adr x4, start
    mov x5, #0x800000000
    movk x5, #0x1800, lsl#16
    and x30, x30, 0x4
    orr x30, x30, x5
    cmp x4, x5
    b.eq start$l0
    add x6, x4, #0x200000

copyloop:
    ldr x3, [x4], #8
    str x3, [x5], #8
    cmp x4, x6
    b.ne copyloop

#ifdef AUTOBOOT
    ldr x3, [x6]
    mov x4, #0x800000000
    movk x4, #0x1900, lsl#16
    mov x2, #0x7561
    movk x2, #0x6f74, lsl#16
    movk x2, #0x6f62, lsl#32
    movk x2, #0x746f, lsl#48
    cmp x3, x2
    b.ne nullsub
    ldr w2, [x6, #8]
    add w2, w2, #16
    and w2, w2, #(~15)

copyloop_2:
    cbz w2, copyloop_3
    sub w2, w2, #16
    ldp x10,x15, [x4], #16
    stp x10,x15, [x5], #16
    b copyloop_2
#endif
copyloop_3:
#ifdef AUTOBOOT
    str xzr, [x6]
#endif
    ret

start$l0:
    sub sp, x5, #0x400
    mov x1, x0
    mov x0, x9
    mov x29, xzr
    bl _trampoline_entry
    b .

.globl _smemcpy128
_smemcpy128:
    cbz w2, nullsub
    sub w2, w2, #1
    ldp x3,x4, [x1], #16
    stp x3,x4, [x0], #16
    b _smemcpy128

.globl _smemset
_smemset:
    and w1, w1, #0xFF
    mov x3, x0
memset$continue:
    cbz x2, nullsub
    strb w1, [x0], #1
    sub x2, x2, #1
    b memset$continue

nullsub:
    ret
