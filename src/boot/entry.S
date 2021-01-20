 /*
 * pongoOS - https://checkra.in
 * 
 * Copyright (C) 2019-2020 checkra1n team, Corellium LLC
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
.globl start
.align 4
start:
    mov x9, x8
    b common_start // entry point for raw pongo images

iorvbar_start:
.align 12
    b iorvbar_core_start // entry point for secondary cores

.align 8
macho_start:
    b simple_start // entry point for macho pongo images

.align 8
iorvbar_core_start:
    dsb sy

    mrs x1, mpidr_el1
    lsr x0, x1, #14
    bfxil x0, x1, #0, #2
    and x0, x0, #7
    adr x1, _iorvbar_table
2:  dsb sy
    ldr x2, [x1, x0, lsl #3]
    tbz x2, #0, 1f
    and x2, x2, #0xFFFFFFFFFC

    bl _cpuinit

    blr x2
3:  wfe
    b 3b
1:  wfe
    b 2b

.align 12

.globl _iorvbar_table
_iorvbar_table:
.long 0xDEADB070, 0xDEADB070, 0xDEADB070, 0xDEADB070
.long 0xDEADB070, 0xDEADB070, 0xDEADB070, 0xDEADB070
.long 0xDEADB070, 0xDEADB070, 0xDEADB070, 0xDEADB070
.long 0xDEADB070, 0xDEADB070, 0xDEADB070, 0xDEADB070
.long 0xDEADB070, 0xDEADB070, 0xDEADB070, 0xDEADB070
.long 0xDEADB070, 0xDEADB070, 0xDEADB070, 0xDEADB070
.long 0xDEADB070, 0xDEADB070, 0xDEADB070, 0xDEADB070
.long 0xDEADB070, 0xDEADB070, 0xDEADB070, 0xDEADB070
.long 0xDEADB070, 0xDEADB070, 0xDEADB070, 0xDEADB070
.long 0xDEADB070, 0xDEADB070, 0xDEADB070, 0xDEADB070
.long 0xDEADB070, 0xDEADB070, 0xDEADB070, 0xDEADB070
.long 0xDEADB070, 0xDEADB070, 0xDEADB070, 0xDEADB070
.long 0xDEADB070, 0xDEADB070, 0xDEADB070, 0xDEADB070
.long 0xDEADB070, 0xDEADB070, 0xDEADB070, 0xDEADB070
.long 0xDEADB070, 0xDEADB070, 0xDEADB070, 0xDEADB070
.long 0xDEADB070, 0xDEADB070, 0xDEADB070, 0xDEADB070
.long 0xDEADB070, 0xDEADB070, 0xDEADB070, 0xDEADB070
.long 0xDEADB070, 0xDEADB070, 0xDEADB070, 0xDEADB070


#define SR_H13_MIGSTS        s3_4_c15_c0_4
#define SR_H13_HID0        s3_0_c15_c0_0
#define SR_H13_HID1        s3_0_c15_c1_0
#define SR_H13_HID3        s3_0_c15_c3_0
#define SR_H13_HID4        s3_0_c15_c4_0
#define SR_H13_EHID4        s3_0_c15_c4_1
#define SR_H13_HID5        s3_0_c15_c5_0
#define SR_H13_HID6        s3_0_c15_c6_0
#define SR_H13_HID7        s3_0_c15_c7_0
#define SR_H13_HID9        s3_0_c15_c9_0
#define SR_H13_EHID10        s3_0_c15_c10_1
#define SR_H13_HID11        s3_0_c15_c11_0
#define SR_H13_CYC_CFG        s3_5_c15_c4_0
#define SR_H13_CYC_OVRD        s3_5_c15_c5_0
#define SR_H13_LLC_ERR_STS    s3_3_c15_c8_0
#define SR_H13_LLC_ERR_ADR    s3_3_c15_c9_0
#define SR_H13_LLC_ERR_INF    s3_3_c15_c10_0
#define SR_H13_LSU_ERR_STS    s3_3_c15_c2_0
#define SR_H13_LSU_ERR_STS_P    s3_3_c15_c0_0
#define SR_H13_FED_ERR_STS    s3_4_c15_c0_2
#define SR_H13_FED_ERR_STS_P    s3_4_c15_c0_0
#define SR_H13_MMU_ERR_STS    s3_6_c15_c2_0
#define SR_H13_MMU_ERR_STS_P    s3_6_c15_c0_0
#define SR_H13_DPC_ERR_STS    s3_5_c15_c0_5
#define SR_H13_KTRR_LOCK    s3_4_c15_c2_2
#define SR_H13_KTRR_MODE    s3_4_c15_c2_5
#define SR_H13_KTRR_LOWER    s3_4_c15_c2_3
#define SR_H13_KTRR_UPPER    s3_4_c15_c2_4

.globl _cpuinit
_cpuinit:
    msr oslar_el1, xzr

    mrs x18, midr_el1
    and x18, x18, #0xfff0
    cmp x18, #0x0220
    beq cpuinit_h13e
    cmp x18, #0x0230
    beq cpuinit_h13p

    ret

cpuinit_h13e:
    msr oslar_el1, xzr
    mov x0, #1
    msr s3_6_c15_c1_0, x0
    tlbi vmalle1
    ldr x0, =0x2020a505f020f0f0
    msr s3_6_c15_c1_6, x0
    msr s3_6_c15_c1_0, xzr
    tlbi vmalle1
1:  mrs x0, s3_6_c15_c12_4
    tbz x0, #0, 1b
    mrs x0, SR_H13_MIGSTS
    bic x0, x0, #6
    orr x0, x0, #0x10
    orr x0, x0, #0x1
    msr SR_H13_MIGSTS, x0
    mrs x0, SR_H13_MIGSTS
    tbnz x0, #4, 1f
    orr x0, x0, #2
    msr SR_H13_MIGSTS, x0
1:  mrs x0, SR_H13_EHID4
    orr x0, x0, #0x800
    orr x0, x0, #0x100000000000
    msr SR_H13_EHID4, x0
    mrs x0, SR_H13_HID5
    orr x0, x0, #0x2000000000000000
    msr SR_H13_HID5, x0
    mrs x0, SR_H13_EHID10
    orr x0, x0, #0x100000000
    orr x0, x0, #0x2000000000000
    msr SR_H13_EHID10, x0
    mrs x0, s3_0_c15_c1_2
    orr x0, x0, #0x100
    msr s3_0_c15_c1_2, x0
    mrs x0, s3_0_c15_c9_1
    bic x0, x0, #0x20
    msr s3_0_c15_c9_1, x0
    mrs x0, s3_0_c15_c1_2
    orr x0, x0, #0x8000
    msr s3_0_c15_c1_2, x0
    mrs x0, s3_0_c15_c1_2
    orr x0, x0, #0x10000
    msr s3_0_c15_c1_2, x0
    mrs x0, s3_0_c15_c1_2
    orr x0, x0, #0x600000
    msr s3_0_c15_c1_2, x0
    mrs x0, mpidr_el1
    and x0, x0, #3
    msr s3_4_c15_c5_0, x0
    mov x0, #0x100
    msr s3_4_c15_c1_4, x0
    mrs x0, SR_H13_CYC_OVRD
    bic x0, x0, #0xf00000
    msr SR_H13_CYC_OVRD, x0
    mrs x0, actlr_el1
    orr x0, x0, #0x200 /* something to do with dsb? */
    msr actlr_el1, x0
    mrs x0, SR_H13_CYC_CFG
    orr x0, x0, #12
    msr SR_H13_CYC_CFG, x0
    msr SR_H13_LLC_ERR_STS, xzr

    ret

cpuinit_h13p:
    msr oslar_el1, xzr
    mov x0, #1
    msr s3_6_c15_c1_0, x0
    tlbi vmalle1
    ldr x0, =0x2020a505f020f0f0
    msr s3_6_c15_c1_6, x0
    msr s3_6_c15_c1_0, xzr
    tlbi vmalle1
    mrs x0, s3_0_c15_c14_0
    bic x0, x0, 0xf000000000000000
    orr x0, x0, 0xc000000000000000
    msr s3_0_c15_c14_0, x0
    mrs x0, s3_0_c15_c15_0
    orr x0, x0, 0x100000000
    msr s3_0_c15_c15_0, x0
1:  mrs x0, s3_6_c15_c12_4
    tbz x0, #0, 1b
    mrs x0, SR_H13_MIGSTS
    bic x0, x0, #6
    orr x0, x0, #0x10
    orr x0, x0, #0x1
    msr SR_H13_MIGSTS, x0
    mrs x0, SR_H13_MIGSTS
    tbnz x0, #4, 1f
    orr x0, x0, #2
    msr SR_H13_MIGSTS, x0
1:  mrs x0, SR_H13_HID4
    orr x0, x0, #0x800
    orr x0, x0, #0x100000000000
    msr SR_H13_HID4, x0
    mrs x0, SR_H13_HID5
    orr x0, x0, #0x2000000000000000
    msr SR_H13_HID5, x0
    mrs x0, s3_0_c15_c14_0
    bic x0, x0, #0x3c000
    orr x0, x0, #0x10000
    msr s3_0_c15_c14_0, x0
    mrs x0, SR_H13_HID0
    orr x0, x0, #0x200000000000
    msr SR_H13_HID0, x0
    mrs x0, SR_H13_HID3
    bic x0, x0, #0x8000000000000000
    bic x0, x0, #0x100000000000
    msr SR_H13_HID3, x0
    mrs x0, SR_H13_HID1
    orr x0, x0, #0x40000000000000
    msr SR_H13_HID1, x0
    mrs x0, s3_0_c15_c15_2
    orr x0, x0, #0x100000000000000
    orr x0, x0, #0x800000000000000
    orr x0, x0, #0x2000000000000000
    orr x0, x0, #0x4000000000000000
    msr s3_0_c15_c15_2, x0
    mrs x0, SR_H13_HID9
    orr x0, x0, #0x4000000
    msr SR_H13_HID9, x0
    mrs x0, SR_H13_HID4
    orr x0, x0, #0x30000000000
    msr SR_H13_HID4, x0
    mrs x0, SR_H13_HID11
    orr x0, x0, #0x800000000000000
    msr SR_H13_HID11, x0
    mrs x0, SR_H13_HID0
    orr x0, x0, #0x10000000
    orr x0, x0, #0x1000000000
    msr SR_H13_HID0, x0
    mrs x0, SR_H13_HID6
    bic x0, x0, #0x3e0
    msr SR_H13_HID6, x0
    mrs x0, SR_H13_HID7
    orr x0, x0, #0x100000
    orr x0, x0, #0x80000
    orr x0, x0, #0x3000000
    msr SR_H13_HID7, x0
    mrs x0, SR_H13_HID9
    orr x0, x0, #0x1000000000000
    orr x0, x0, #0x20000000
    msr SR_H13_HID9, x0
    mrs x0, s3_0_c15_c11_2
    orr x0, x0, #0x4000
    msr s3_0_c15_c11_2, x0
    mrs x0, s3_0_c15_c1_3
    bic x0, x0, #0x80000
    msr s3_0_c15_c1_3, x0
    mrs x0, SR_H13_HID4
    orr x0, x0, #0x2000000000000
    orr x0, x0, #0x20000000000000
    msr SR_H13_HID4, x0
    mrs x0, SR_H13_HID9
    orr x0, x0, #0x80000000000000
    msr SR_H13_HID9, x0
    mrs x0, SR_H13_HID11
    orr x0, x0, #0x8000
    msr SR_H13_HID11, x0
    mrs x0, SR_H13_HID1
    orr x0, x0, #0x400000000000000
    orr x0, x0, #0x1000000000000000
    msr SR_H13_HID1, x0
    mrs x0, s3_0_c15_c1_3
    orr x0, x0, #0x2000000000000
    msr s3_0_c15_c1_3, x0
    mrs x0, mpidr_el1
    and x0, x0, #3
    msr s3_4_c15_c5_0, x0
    mov x0, #0x100
    msr s3_4_c15_c1_4, x0
    mrs x0, SR_H13_CYC_OVRD
    bic x0, x0, #0xf00000
    msr SR_H13_CYC_OVRD, x0
    mrs x0, actlr_el1
    orr x0, x0, #0x200 /* something to do with dsb? */
    msr actlr_el1, x0
    mrs x0, SR_H13_CYC_CFG
    orr x0, x0, #12
    msr SR_H13_CYC_CFG, x0
    msr SR_H13_LLC_ERR_STS, xzr

    ret




.align 14
common_start:
    adr x4, start
    mov x5, #0x800000000
    movk x5, #0x1800, lsl#16
    cmp x4, x5
    b.eq direct_start

    mov x30, x5
    add x6, x4, #0x200000

copyloop:
    ldr x3, [x4], #8
    str x3, [x5], #8
    cmp x4, x6
    b.ne copyloop

    ret

direct_start:
    mov x1, x0
    mov x0, x9
    mov x29, xzr
    bl _set_exception_stack_core0
    bl _set_execution_stack_core0
    bl _trampoline_entry
    b .

simple_start:
    mov x29, xzr
    bl _set_exception_stack_core0
    bl _set_execution_stack_core0
    bl _simple_entry
    b .



.globl _setup_el1
_setup_el1:
    stp x29, x30, [sp, #-0x10]!
    mov x20, x1
    mov x21, x2
    mrs x16, currentel
    cmp x16, #0x8
    b.eq el2_entry
    cmp x16, #0x4
    b.eq el1_entry
    cmp x16, #0xc

    b.ne .

el3_entry:
    adr x16, _exception_vector_el3
    msr vbar_el3, x16
    mov x16, #0x430
    msr scr_el3, x16
    mov x16, #4
    msr spsr_el3, x16
    msr elr_el3, x0
    eret


el2_entry:
el1_entry:
    blr x0
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

.align 12
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

