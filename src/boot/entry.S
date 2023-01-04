/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2019-2023 checkra1n team
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
.text
.globl start
.align 2
start:
    // Since version 2.6.0, Pongo lives in SRAM, is always invoked at the first
    // instruction and maintains the following ABI on the way in and out:
    // x30 = next-stage binary (iBoot/KPP/XNU)
    //  x0 = argument to next stage
    adr x4, start
    mov x5, 0x180000000
    cmp x4, x5
    b.eq L_relocated
    // Since we wanna be at the very start of SRAM, we don't need to check the direction of copying
    .loh AdrpAdd Lloh0, Lloh1
Lloh0:
    adrp x6, section$end$__DATA$__pongo_exports@PAGE
Lloh1:
    add x6, x6, section$end$__DATA$__pongo_exports@PAGEOFF
copyloop:
    ldp x7, x8, [x4], 0x10
    stp x7, x8, [x5], 0x10
    cmp x4, x6
    b.lo copyloop
    dsb sy
    mov x5, 0x180000000
    br x5

L_relocated:
    mov x1, x0
    mov x0, x30
    mov x29, xzr
    cbz x1, L_zeroed
    // Zero the zerofill sections
    .loh AdrpAdd Lloh2, Lloh3
    .loh AdrpAdd Lloh4, Lloh5
Lloh2:
    adrp x2, section$start$__DATA$__common@PAGE
Lloh3:
    add x2, x2, section$start$__DATA$__common@PAGEOFF
Lloh4:
    adrp x3, segment$end$__DATA@PAGE
Lloh5:
    add x3, x3, segment$end$__DATA@PAGEOFF
L_unaligned_zero:
    tst x2, 0xf
    b.eq L_aligned_zero
    cmp x2, x3
    b.hs L_zeroed
    strb wzr, [x2], 1
    b L_unaligned_zero
L_aligned_zero:
    cmp x2, x3
    b.hs L_zeroed
    stp xzr, xzr, [x2], 0x10
    b L_aligned_zero
L_zeroed:
    dsb sy
    bl _set_exception_stack_core0
    bl _set_execution_stack_core0
    bl _trampoline_entry
    b .

.globl _setup_el1
_setup_el1:
    stp x29, x30, [sp, #-0x10]!
    mrs x16, currentel
    cmp x16, (1 << 2)
    b.eq el1_entry
    cmp x16, (3 << 2)
    b.ne .

el3_entry:
    adr x16, _exception_vector_el3
    msr vbar_el3, x16
    mov x16, #0x430
    msr scr_el3, x16
    mov x16, #4
    msr spsr_el3, x16
    adr x16, el1_entry
    msr elr_el3, x16
    eret

el1_entry:
    blr x2
    b .

.globl _set_exception_stack_core0
_set_exception_stack_core0:
    msr spsel, #1
    adrp x8, _exception_stack@PAGE
    add x8, x8, _exception_stack@PAGEOFF
    add x8, x8, #0x4000
    and x8, x8, #~0xf
    mov sp, x8
    msr spsel, #0
    ret

.globl _set_execution_stack_core0
_set_execution_stack_core0:
    msr spsel, #0
    adrp x8, _sched_stack@PAGE
    add x8, x8, _sched_stack@PAGEOFF
    add x8, x8, #0x4000
    and x8, x8, #~0xf
    mov sp, x8
    ret

.align 11
.globl _exception_vector_el3
_exception_vector_el3:
    b .
.balign 128
    b .
.balign 128
    b .
.balign 128
    b .

.balign 128
    b .
.balign 128
    b .
.balign 128
    b .
.balign 128
    b .

.balign 128
    /* Lower EL with Aarch64 */
    mov x18, #0xc
    msr spsr_el3, x18
    eret
.balign 128
    b .
.balign 128
    b .
.balign 128
    b .

.balign 128
    b .
.balign 128
    b .
.balign 128
    b .
.balign 128
    b .
