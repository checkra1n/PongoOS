/* 
 * pongoOS - https://checkra.in
 * 
 * Copyright (C) 2019-2021 checkra1n team
 *
 * This file is part of pongoOS.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */
.globl _sep_racer
_sep_racer:
    stp x29, x30, [sp, -0x60]!
    stp x20, x21, [sp, #0x10]
    stp x22, x23, [sp, #0x20]
    stp x24, x25, [sp, #0x30]
    stp x26, x27, [sp, #0x40]
    stp x28, x19, [sp, #0x50]

    msr daifset, #0xf

    mov x20, x0
    mov x21, x1
    ldr x24, [x2] // fetch b0 null
    mov x22, x3
    mov x23, x4
    mov x26, x5
    mov x28, x6
    mov x19, x7

    mov x29, #0x100
    mov x25, #0

    ldr x27, [x22]

1:
    // tight hot observation loop
    isb
    
    ldr x0, [x20] // fetch current b0 tz0
    cmp x0, x24
    b.ne 4f
    cbz x27, 5f

    ldr x0, [x21] // fetch current shc tz0
    cmp x0, x27
    b.ne 9f
5:
    sub x29, x29, #1
    cbz x29, 2f
    b 1b

2:
    bl _sep_check_mailbox
    ldr x8, =_sep_has_booted
    ldr w8, [x8]
    cbnz w8, 3f
    ldr x8, =_sep_has_panicked
    ldr w8, [x8]
    cbnz w8, 3f
    
    mov x29, #0x100
    b 1b

3:
    ldp x20, x21, [sp, #0x10]
    ldp x22, x23, [sp, #0x20]
    ldp x24, x25, [sp, #0x30]
    ldp x26, x27, [sp, #0x40]
    ldp x28, x19, [sp, #0x50]
    ldp x29, x30, [sp], 0x60
    ret

4:
    mov x24, x0
    add x25, x25, #1
    cmp x25, #1
    b.hi 11f
    b 5b
11:
    mov x29, #0x4
    ldr x8, =_seprom_has_left_to_sepos // if we got a 0x6a in slowpath, just skip 0x6a delay loop
    ldr w8, [x8]
    cbnz w8, 6f

12:
    bl _sep_fast_check_mailbox // 0x6a delay loop
    cbz x0, 12b
    and x0, x0, #0xff0000
    cmp x0, #0x6a0000
    b.ne 12b

    mov x0, x20
    mov x1, x23
    sub x2, x26, #0x1000
    bl _memcpy_blocks

    sub x2, x26, #0x1000
    add x0, x20, x2
    add x1, x23, x2
    mov x2, #0x1000
    bl _swap_blocks

    mov w0, #0xbabe
    movk w0, #0xcafe, lsl#16

6:
    ldr w1, [x19]
    cmp w1, w0
    b.eq 3b

7:
    sub x29, x29, #1
    cbz x29, 8f
    b 6b

8:
    bl _sep_check_mailbox
    ldr x8, =_sep_has_booted
    ldr w8, [x8]
    cbnz w8, 3b
    ldr x8, =_sep_has_panicked
    ldr w8, [x8]
    cbnz w8, 3b

    mov x29, #0x4
    mov w0, #0xbabe
    movk w0, #0xcafe, lsl#16
    b 6b

9:
    mov x0, x28
    mov x1, x21
    mov x2, #0x40
    bl _memcpy_blocks

    mov x27, xzr
    b 5b

_memcpy_blocks:
    cmp x2, #0x40
    b.lo 1f

    ldp q0, q1, [x1]
    ldp q2, q3, [x1,#0x20]
    stp q0, q1, [x0]
    stp q2, q3, [x0,#0x20]
    add x0, x0, #0x40
    add x1, x1, #0x40
    sub x2, x2, #0x40
    b _memcpy_blocks
1:
    ret
_swap_blocks:
    cmp x2, #0x40
    b.lo 1f

    ldp q0, q1, [x1]
    ldp q2, q3, [x1,#0x20]
    ldp q4, q5, [x0]
    ldp q6, q7, [x0,#0x20]
    stp q4, q5, [x1]
    stp q6, q7, [x1,#0x20]
    stp q0, q1, [x0]
    stp q2, q3, [x0,#0x20]

    add x0, x0, #0x40
    add x1, x1, #0x40
    sub x2, x2, #0x40
    b _swap_blocks
1:
    ret

