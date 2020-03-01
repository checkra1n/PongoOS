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
.align 12
.globl exception_vector
exception_vector:
    /* Current EL with SP0 */
    sub sp, sp, #0x340
    stp x0,x1,[sp]
    adr x0, Jsync_exc
    b exc_handler /* Synchronous */
.balign 128
    sub sp, sp, #0x340
    stp x0,x1,[sp]
    adr x0, Jirq_exc
    b exc_handler  /* IRQ/vIRQ */
.balign 128
    sub sp, sp, #0x340
    stp x0,x1,[sp]
    adr x0, Jfiq_exc
    b exc_handler  /* FIQ/vFIQ */
.balign 128
    sub sp, sp, #0x340
    stp x0,x1,[sp]
    adr x0, Jserror_exc
    b exc_handler /* SError/vSError */
.balign 128
    
    /* Current EL with SPn */
    sub sp, sp, #0x340
    stp x0,x1,[sp]
    adr x0, Jsync_exc
    b exc_handler /* Synchronous */
.balign 128
    sub sp, sp, #0x340
    stp x0,x1,[sp]
    adr x0, Jirq_exc
    b exc_handler  /* IRQ/vIRQ */
.balign 128
    sub sp, sp, #0x340
    stp x0,x1,[sp]
    adr x0, Jfiq_exc
    b exc_handler  /* FIQ/vFIQ */
.balign 128
    sub sp, sp, #0x340
    stp x0,x1,[sp]
    adr x0, Jserror_exc
    b exc_handler /* SError/vSError */
.balign 128

    /* Lower EL with Aarch64 */

    b . /* Synchronous */
.balign 128
    b .  /* IRQ/vIRQ */
.balign 128
    b .  /* FIQ/vFIQ */
.balign 128
    b . /* SError/vSError */
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
    b sync_exc
Jserror_exc:
    b serror_exc
Jfiq_exc:
    b fiq_exc
Jirq_exc:
    b irq_exc
    
exc_handler:
    isb
    dmb sy
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

    mrs x2, currentel
    cmp x2, #0x4
    b.eq exc_el1
    cmp x2, #0xc
    b.ne .

exc_el3:
    mrs x29, esr_el3
    stp x30,x29,[sp,#0xf0]
    mrs x0, elr_el3
    mrs x1, far_el3
    stp x0,x1,[sp,#0x100]

    mov x0, sp
    blr x16

    ldp x2,x1,[sp,#0x100]
    msr elr_el3, x2
    msr far_el3, x1
    mrs x1, spsr_el3
    str x1, [sp, #0x110]

    cmp x0, #1
    b.ne exc_done
    bl task_yield_preemption
    ldp x0,x1,[sp,#0x100]
    msr elr_el3, x0
    msr far_el3, x1
    ldr x0, [sp, #0x110]
    b exc_done
exc_el1:
    mrs x29, esr_el1
    stp x30,x29,[sp,#0xf0]
    mrs x0, elr_el1
    mrs x1, far_el1
    stp x0,x1,[sp,#0x100]

    mov x0, sp
    blr x16

    ldp x2,x1,[sp,#0x100]
    msr elr_el1, x2
    msr far_el1, x1
    mrs x1, spsr_el1
    str x1, [sp, #0x110]

    cmp x0, #1
    b.ne exc_done
    bl task_yield_preemption
    ldp x0,x1,[sp,#0x100]
    msr elr_el1, x0
    msr far_el1, x1
    ldr x0, [sp, #0x110]

exc_done:
    ldp x0,x1,[sp]
    ldp x2,x3,[sp,#0x10]
    ldp x4,x5,[sp,#0x20]
    ldp x6,x7,[sp,#0x30]
    ldp x8,x9,[sp,#0x40]
    ldp x10,x11,[sp,#0x50]
    ldp x12,x13,[sp,#0x60]
    ldp x14,x15,[sp,#0x70]
    ldp x16,x17,[sp,#0x80]
    ldp x18,x19,[sp,#0x90]
    ldp x20,x21,[sp,#0xa0]
    ldp x22,x23,[sp,#0xb0]
    ldp x24,x25,[sp,#0xc0]
    ldp x26,x27,[sp,#0xd0]
    ldp x28,x29,[sp,#0xe0]
    ldr x30,[sp,#0xf0]

    ldp d0, d1, [sp,#0x130]
    ldp d2, d3, [sp,#0x150]
    ldp d4, d5, [sp,#0x170]
    ldp d6, d7, [sp,#0x190]
    ldp d8, d9, [sp,#0x1B0]
    ldp d10, d11, [sp,#0x1D0]
    ldp d12, d13, [sp,#0x1F0]
    ldr d14, [sp,#0x210]
    ldr d15, [sp,#0x220]
    ldr d16, [sp,#0x230]
    ldr d17, [sp,#0x240]
    ldr d18, [sp,#0x250]
    ldr d19, [sp,#0x260]
    ldr d20, [sp,#0x270]
    ldr d21, [sp,#0x280]
    ldr d22, [sp,#0x290]
    ldr d23, [sp,#0x2a0]
    ldr d24, [sp,#0x2b0]
    ldr d25, [sp,#0x2c0]
    ldr d26, [sp,#0x2d0]
    ldr d27, [sp,#0x2e0]
    ldr d28, [sp,#0x2f0]
    ldr d29, [sp,#0x300]
    ldr d30, [sp,#0x310]
    ldr d31, [sp,#0x320]
    
    add sp, sp, #0x340
    eret

.globl task_current
.globl _task_switch 
.globl task_load
.globl task_load_asserted
.globl _task_switch_asserted
.globl _task_set_current
task_current:
    mrs x0, tpidr_el1
    ret
_task_set_current:
    msr tpidr_el1, x0
    ret
    
_task_switch:
    mrs x2, tpidr_el1
    stp x0, x30, [x2]
    bl disable_interrupts
    mrs x2, tpidr_el1
    ldp x0, x30, [x2]
_task_switch_asserted:
    isb
    dmb sy
    
    mrs x2, tpidr_el1
    stp x2, x3, [x2,#0x10]
    stp x4, x5, [x2,#0x20]
    stp x6, x7, [x2,#0x30]
    stp x8, x9, [x2,#0x40]
    stp x10, x11, [x2,#0x50]
    stp x12, x13, [x2,#0x60]
    stp x14, x15, [x2,#0x70]
    stp x16, x17, [x2,#0x80]
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

    mov sp, x1
    ldr x1, [x0, #0x100]
    add x1, x1, #1
    str x1, [x0, #0x100]
    isb
    dmb sy
    b enable_interrupts

task_load:
    mrs x2, tpidr_el1
    stp x0, x30, [x2]
    bl disable_interrupts
    mrs x2, tpidr_el1
    ldp x0, x30, [x2]
task_load_asserted:
    isb
    dmb ish
    msr tpidr_el1, x0
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
    ldp d11, d12, [x0,#0x160]
    ldp d13, d14, [x0,#0x180]
    ldr d15, [x0,#0x1a0]

    mov sp, x1
    ldr x1, [x0, #0x100]
    add x1, x1, #1
    str x1, [x0, #0x100]
    ldp x0, x1, [x0]
    isb
    dmb sy

    b enable_interrupts
.globl set_timer_reg
set_timer_reg:
.long 0xd51be220
isb
ret
.globl set_timer_ctr
set_timer_ctr:
.long 0xd51be200
isb
ret

.globl get_spsr_el1
get_spsr_el1:
    mrs x0, spsr_el1
    ret
.globl get_spsr_el3
get_spsr_el3:
    mrs x0, spsr_el3
    ret
.globl set_spsr_el1
set_spsr_el1:
    msr spsr_el1, x0
    ret
.globl set_spsr_el3
set_spsr_el3:
    msr spsr_el3, x0
    ret 

.globl set_l2c_err_sts
.globl get_l2c_err_sts
.globl set_l2c_err_adr
.globl get_l2c_err_adr
.globl set_l2c_err_inf
.globl get_l2c_err_inf
.globl set_lsu_err_sts
.globl get_lsu_err_sts

set_l2c_err_sts:
        .long 0xd51bf800
	isb sy
        ret
get_l2c_err_sts:
        .long 0xd53bf800
	isb sy
        ret
set_l2c_err_adr:
        .long 0xd51bf000
	isb sy
        ret
get_l2c_err_adr:
        .long 0xd53bf900
	isb sy
        ret
set_l2c_err_inf:
        .long 0xd51bf000
	isb sy
        ret
get_l2c_err_inf:
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
