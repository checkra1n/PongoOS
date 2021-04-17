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
.align 12
.globl _exception_vector
_exception_vector:
    /* Current EL with SP0, handle within SP0 */
    msr spsel, #1
    sub sp, sp, #0x340
    stp x0,x1,[sp]
    msr spsel, #0
    mov x1, sp
    msr spsel, #1
    adr x0, Jsync_exc
    b exc_handler /* Synchronous */
.balign 128
    msr spsel, #1
    sub sp, sp, #0x340
    stp x0,x1,[sp]
    msr spsel, #0
    mov x1, sp
    msr spsel, #1
    adr x0, Jirq_exc
    b exc_handler  /* IRQ/vIRQ */
.balign 128
    msr spsel, #1
    sub sp, sp, #0x340
    stp x0,x1,[sp]
    msr spsel, #0
    mov x1, sp
    msr spsel, #1
    adr x0, Jfiq_exc
    b exc_handler  /* FIQ/vFIQ */
.balign 128
    msr spsel, #1
    sub sp, sp, #0x340
    stp x0,x1,[sp]
    msr spsel, #0
    mov x1, sp
    msr spsel, #1
    adr x0, Jserror_exc
    b exc_handler /* SError/vSError */
.balign 128

    /* Current EL with SPn */
    sub sp, sp, #0x340
    stp x0,x1,[sp]
    adr x0, Jsync_exc
    add x1, sp, #0x340
    b exc_handler /* Synchronous */
.balign 128
    sub sp, sp, #0x340
    stp x0,x1,[sp]
    adr x0, Jirq_exc_el1sp1
    add x1, sp, #0x340
    b exc_handler  /* IRQ/vIRQ */
.balign 128
    sub sp, sp, #0x340
    stp x0,x1,[sp]
    adr x0, Jfiq_exc_el1sp1
    add x1, sp, #0x340
    b exc_handler  /* FIQ/vFIQ */
.balign 128
    sub sp, sp, #0x340
    stp x0,x1,[sp]
    adr x0, Jserror_exc
    add x1, sp, #0x340
    b exc_handler /* SError/vSError */
.balign 128

    /* Lower EL with Aarch64 */
    msr spsel, #1
    str x0, [sp, #-0x10]
    mrs x0, tpidr_el1
    ldr x0, [x0, #0x210] // struct task -> kernel_stack
    str x1, [x0, #8]
    ldr x1, [sp, #-0x10]
    str x1, [x0]
    msr spsel, #0
    mov x1, sp
    mov sp, x0
    adr x0, Jsync_exc_el0
    b exc_handler /* Synchronous */
.balign 128
    msr spsel, #1
    str x0, [sp, #-0x10]
    mrs x0, tpidr_el1
    ldr x0, [x0, #0x210] // struct task -> kernel_stack
    str x1, [x0, #8]
    ldr x1, [sp, #-0x10]
    str x1, [x0]
    msr spsel, #0
    mov x1, sp
    mov sp, x0
    adr x0, Jirq_exc
    b exc_handler  /* IRQ/vIRQ */
.balign 128
    msr spsel, #1
    str x0, [sp, #-0x10]
    mrs x0, tpidr_el1
    ldr x0, [x0, #0x210] // struct task -> kernel_stack
    str x1, [x0, #8]
    ldr x1, [sp, #-0x10]
    str x1, [x0]
    msr spsel, #0
    mov x1, sp
    mov sp, x0
    adr x0, Jfiq_exc
    b exc_handler  /* FIQ/vFIQ */
.balign 128
    msr spsel, #1
    str x0, [sp, #-0x10]
    mrs x0, tpidr_el1
    ldr x0, [x0, #0x210] // struct task -> kernel_stack
    str x1, [x0, #8]
    ldr x1, [sp, #-0x10]
    str x1, [x0]
    msr spsel, #0
    mov x1, sp
    msr spsel, #1
    mov sp, x0
    adr x0, Jserror_exc
    b exc_handler /* SError/vSError */
.balign 128

    /* Lower EL with Aarch32 */

.balign 128
    b . /* Synchronous */
.balign 128
    b .  /* IRQ/vIRQ */
.balign 128
    b .  /* FIQ/vFIQ */
.balign 128
    b . /* SError/vSError */


Jsync_exc:
    b _sync_exc
Jserror_exc:
    b _serror_exc
Jfiq_exc:
    b _fiq_exc
Jirq_exc:
    b _irq_exc
Jsync_exc_el0:
    b _sync_exc_el0
Jirq_exc_el1sp1:
    b _irq_exc
Jfiq_exc_el1sp1:
    b _fiq_exc

exc_handler:
    isb
    dmb sy
    str x1, [sp,#0x118]
    stp x2,x3,[sp,#0x10]
    stp x4,x5,[sp,#0x20]
    stp x6,x7,[sp,#0x30]
    stp x8,x9,[sp,#0x40]
    stp x10,x11,[sp,#0x50]
    stp x12,x13,[sp,#0x60]
    stp x14,x15,[sp,#0x70]
    stp x16,x17,[sp,#0x80]
    mov x16, x0
    stp x18,x19,[sp,#0x90]
    stp x20,x21,[sp,#0xa0]
    stp x22,x23,[sp,#0xb0]
    stp x24,x25,[sp,#0xc0]
    stp x26,x27,[sp,#0xd0]
    stp x28,x29,[sp,#0xe0]

    stp d0, d1, [sp,#0x130]
    stp d2, d3, [sp,#0x150]
    stp d4, d5, [sp,#0x170]
    stp d6, d7, [sp,#0x190]
    stp d8, d9, [sp,#0x1B0]
    stp d10, d11, [sp,#0x1D0]
    stp d12, d13, [sp,#0x1F0]
    str d14, [sp,#0x210]
    str d15, [sp,#0x220]
    str d16, [sp,#0x230]
    str d17, [sp,#0x240]
    str d18, [sp,#0x250]
    str d19, [sp,#0x260]
    str d20, [sp,#0x270]
    str d21, [sp,#0x280]
    str d22, [sp,#0x290]
    str d23, [sp,#0x2a0]
    str d24, [sp,#0x2b0]
    str d25, [sp,#0x2c0]
    str d26, [sp,#0x2d0]
    str d27, [sp,#0x2e0]
    str d28, [sp,#0x2f0]
    str d29, [sp,#0x300]
    str d30, [sp,#0x310]
    str d31, [sp,#0x320]

    mrs x29, esr_el1
    stp x30,x29,[sp,#0xf0]
    mrs x0, elr_el1
    mrs x1, far_el1
    stp x0,x1,[sp,#0x100]
    mrs x1, spsr_el1
    str x1, [sp, #0x110]

    // Need to keep x29 valid for panic()
    add x29, sp, #0xe8
    mov x0, sp
    blr x16

    cmp x0, #1
    b.ne exc_done
    bl _task_yield_preemption

exc_done:
    ldp x0,x1,[sp,#0x100]
    msr elr_el1, x0
    msr far_el1, x1

    ldr x1, [sp, #0x110]
    msr spsr_el1, x1
    
    mov x0, sp
    
    ldp x2,x3,[x0,#0x10]
    ldp x4,x5,[x0,#0x20]
    ldp x6,x7,[x0,#0x30]
    ldp x8,x9,[x0,#0x40]
    ldp x10,x11,[x0,#0x50]
    ldp x12,x13,[x0,#0x60]
    ldp x14,x15,[x0,#0x70]
    ldp x16,x17,[x0,#0x80]
    ldp x18,x19,[x0,#0x90]
    ldp x20,x21,[x0,#0xa0]
    ldp x22,x23,[x0,#0xb0]
    ldp x24,x25,[x0,#0xc0]
    ldp x26,x27,[x0,#0xd0]
    ldp x28,x29,[x0,#0xe0]
    ldr x30,[x0,#0xf0]

    ldp d0, d1, [x0,#0x130]
    ldp d2, d3, [x0,#0x150]
    ldp d4, d5, [x0,#0x170]
    ldp d6, d7, [x0,#0x190]
    ldp d8, d9, [x0,#0x1B0]
    ldp d10, d11, [x0,#0x1D0]
    ldp d12, d13, [x0,#0x1F0]
    ldr d14, [x0,#0x210]
    ldr d15, [x0,#0x220]
    ldr d16, [x0,#0x230]
    ldr d17, [x0,#0x240]
    ldr d18, [x0,#0x250]
    ldr d19, [x0,#0x260]
    ldr d20, [x0,#0x270]
    ldr d21, [x0,#0x280]
    ldr d22, [x0,#0x290]
    ldr d23, [x0,#0x2a0]
    ldr d24, [x0,#0x2b0]
    ldr d25, [x0,#0x2c0]
    ldr d26, [x0,#0x2d0]
    ldr d27, [x0,#0x2e0]
    ldr d28, [x0,#0x2f0]
    ldr d29, [x0,#0x300]
    ldr d30, [x0,#0x310]
    ldr d31, [x0,#0x320]

    add sp, sp, #0x340 // unwind frame in case we're returning to spsel 0 from spsel 1

    // switch back to correct spsel to restore SP upon exception return

    tbnz x1, #0, 1f
    msr spsel, #0
    b 2f
1:
    msr spsel, #1
2:
    ldr x1, [x0, #0x118] // restore sp
    mov sp, x1
    ldp x0, x1, [x0]
    eret
    b .

.globl _task_current
.globl __task_set_current
.globl __task_switch
.globl __task_switch_asserted
.globl _task_load
.globl _task_load_asserted
_task_current:
    mrs x0, tpidr_el1
    ret
__task_set_current:
    msr tpidr_el1, x0
    ret

__task_switch:
    mov x16, x0
    mov x17, x1
    bl _disable_interrupts
    mrs x2, tpidr_el1
    mov x0, x16
    mov x1, x17
__task_switch_asserted:
    isb
    dmb sy
    mrs x2, tpidr_el1
    stp x2, x3, [x2,#0x10]
    stp x4, x5, [x2,#0x20]
    stp x6, x7, [x2,#0x30]
    stp x8, x9, [x2,#0x40]
    
    mrs x1, ttbr1_el1
    str x1, [x2, #0x1C8]
    mrs x1, spsel
    str w1, [x2, #0x1C0]

    msr spsel, #1
    mov x3, sp
    str x3, [x2, #0x1B8]
    msr spsel, #0

    stp x10, x11, [x2,#0x50]
    stp x12, x13, [x2,#0x60]
    stp x14, x15, [x2,#0x70]
    stp xzr, xzr, [x2,#0x80]
    stp x18, x19, [x2,#0x90]
    stp x20, x21, [x2,#0xa0]
    stp x22, x23, [x2,#0xb0]
    stp x24, x25, [x2,#0xc0]
    stp x26, x27, [x2,#0xd0]
    stp x28, x29, [x2,#0xe0]
    mov x1, sp
    stp x30, x1, [x2, #0xf0]

    stp d8, d9, [x2,#0x120]
    stp d10, d11, [x2,#0x140]
    stp d12, d13, [x2,#0x160]
    stp d14, d15, [x2,#0x180]
    msr tpidr_el1, x0

    msr spsel, #1
    ldr x8, [x0, #0x1B8]
    mov sp, x8
    msr spsel, #0
    mrs x2, ttbr1_el1
    ldr x1, [x0, #0x1C8]
    cmp x2, x1
    isb
    msr ttbr1_el1, x1
    dsb sy
    ldp x2, x3, [x0,#0x10]
    ldp x4, x5, [x0,#0x20]
    ldp x6, x7, [x0,#0x30]
    ldp x8, x9, [x0,#0x40]
    ldp x10, x11, [x0,#0x50]
    ldp x12, x13, [x0,#0x60]
    ldp x14, x15, [x0,#0x70]
    ldp x16, x17, [x0,#0x80]
    ldp x18, x19, [x0,#0x90]
    ldp x20, x21, [x0,#0xa0]
    ldp x22, x23, [x0,#0xb0]
    ldp x24, x25, [x0,#0xc0]
    ldp x26, x27, [x0,#0xd0]
    ldp x28, x29, [x0,#0xe0]
    ldp x30, x1, [x0, #0xf0]

    ldp d8, d9, [x0,#0x120]
    ldp d10, d11, [x0,#0x140]
    ldp d12, d13, [x0,#0x160]
    ldp d14, d15, [x0,#0x180]

    msr tpidr_el1, x0
    mov sp, x1
    ldr x1, [x0, #0x100]
    add x1, x1, #1
    str x1, [x0, #0x100]
    ldr x1, [x0, #0x1C0]
    msr spsel, x1
    ldp x0, x1, [x0]

    b _enable_interrupts

_task_load:
    mov x16, x0
    mov x17, x1
    bl _disable_interrupts
    mrs x2, tpidr_el1
    mov x0, x16
    mov x1, x17
    b _task_load_asserted

_task_load_asserted:
    msr tpidr_el1, x0

    msr spsel, #1
    ldr x8, [x0, #0x1B8]
    mov sp, x8
    msr spsel, #0

    ldr x1, [x0, #0x1C8]
    isb
    msr ttbr1_el1, x1
    dsb sy

    ldp x2, x3, [x0,#0x10]
    ldp x4, x5, [x0,#0x20]
    ldp x6, x7, [x0,#0x30]
    ldp x8, x9, [x0,#0x40]
    ldp x10, x11, [x0,#0x50]
    ldp x12, x13, [x0,#0x60]
    ldp x14, x15, [x0,#0x70]
    ldp x16, x17, [x0,#0x80]

    ldp x18, x19, [x0,#0x90]
    ldp x20, x21, [x0,#0xa0]
    ldp x22, x23, [x0,#0xb0]
    ldp x24, x25, [x0,#0xc0]
    ldp x26, x27, [x0,#0xd0]
    ldp x28, x29, [x0,#0xe0]
    ldp x30, x1, [x0, #0xf0]

    ldp d8, d9, [x0,#0x120]
    ldp d10, d11, [x0,#0x140]
    ldp d12, d13, [x0,#0x160]
    ldp d14, d15, [x0,#0x180]
        
    msr tpidr_el1, x0
    mov sp, x1
    ldr x1, [x0, #0x100]
    add x1, x1, #1
    str x1, [x0, #0x100]
    ldr x1, [x0, #0x1C0]
    msr spsel, x1
    ldp x0, x1, [x0]

    b _enable_interrupts


.globl _task_entry_j
_task_entry_j:
    msr elr_el1, x0
    msr spsr_el1, x3
    mov sp, x1
    mov lr, x2
    mov x29, xzr
    mrs x0, tpidr_el1
    add x0, x0, #0x220 // -> struct task initial_state
    
    ldp x2, x3, [x0,#0x10]
    ldp x4, x5, [x0,#0x20]
    ldp x6, x7, [x0,#0x30]
    ldp x8, x9, [x0,#0x40]
    ldp x10, x11, [x0,#0x50]
    ldp x12, x13, [x0,#0x60]
    ldp x14, x15, [x0,#0x70]
    ldp x16, x17, [x0,#0x80]
    ldp x18, x19, [x0,#0x90]
    ldp x20, x21, [x0,#0xa0]
    ldp x22, x23, [x0,#0xb0]
    ldp x24, x25, [x0,#0xc0]
    ldp x26, x27, [x0,#0xd0]
    ldr x28, [x0,#0xe0]
    ldp d8, d9, [x0,#0x120]
    ldp d10, d11, [x0,#0x140]
    ldp d12, d13, [x0,#0x160]
    ldp d14, d15, [x0,#0x180]
    ldp x0, x1, [x0]

    eret
    b .

.globl _set_timer_reg
_set_timer_reg:
    msr cntp_ctl_el0, x0
    isb
    ret
.globl _set_timer_ctr
_set_timer_ctr:
    msr cntp_tval_el0, x0
    isb
    ret

.globl _get_spsr_el1
_get_spsr_el1:
    mrs x0, spsr_el1
    ret
.globl _set_spsr_el1
_set_spsr_el1:
    msr spsr_el1, x0
    ret
#if 0
.globl _set_l2c_err_sts
.globl _get_l2c_err_sts
.globl _set_l2c_err_adr
.globl _get_l2c_err_adr
.globl _set_l2c_err_inf
.globl _get_l2c_err_inf
.globl _set_lsu_err_sts
.globl _get_lsu_err_sts

// TODO: this is whack, and some were probably copied wrong...
_set_l2c_err_sts:
    .long 0xd51bf800
    isb sy
    ret
_get_l2c_err_sts:
    .long 0xd53bf800
    isb sy
    ret
_set_l2c_err_adr:
    .long 0xd51bf000
    isb sy
    ret
_get_l2c_err_adr:
    .long 0xd53bf900
    isb sy
    ret
_set_l2c_err_inf:
    .long 0xd51bf000
    isb sy
    ret
_get_l2c_err_inf:
    .long 0xd53bf900
    isb sy
    ret
set_lsu_err_sts:
    .long 0xd51bf000
    isb sy
    ret
get_lsu_err_sts:
    .long 0xd53bf000
    isb sy
    ret
.align 3
spsel_err:
.ascii "task_switch/load called on exception stack"
.align 3
#endif
