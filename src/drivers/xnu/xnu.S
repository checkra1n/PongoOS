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
.globl _pf_jit_iter_loop_head_start
.globl _pf_jit_iter_loop_head_end
.globl _pf_jit_iter_loop_head_load32_start
.globl _pf_jit_iter_loop_head_load32_end
.globl _pf_jit_iter_loop_iter_load32_start
.globl _pf_jit_iter_loop_iter_load32_end
.globl _pf_jit_iter_loop_head_load64_start
.globl _pf_jit_iter_loop_head_load64_end
.globl _pf_jit_iter_loop_iter_load64_start
.globl _pf_jit_iter_loop_iter_load64_end
.globl _pf_jit_iter_loop_end_start
.globl _pf_jit_iter_loop_end_end

.globl _pf_jit_absolute_branch_start
.globl _pf_jit_absolute_branch_end

.align 3
_pf_jit_iter_loop_head_start:
    sub sp, sp, #0x60
    stp x20, x21, [sp]
    stp x22, x23, [sp,#0x10]
    stp x24, x25, [sp,#0x20]
    stp x26, x27, [sp,#0x30]
    stp x28, x29, [sp,#0x40]
    stp x30, x19, [sp,#0x50]
    mov x19, x0
    mov x28, x1
.align 3
_pf_jit_iter_loop_head_end:

.align 3
_pf_jit_absolute_branch_start:
    adr x1, _pf_jit_absolute_branch_end
    ldr x1, [x1]
    br x1
.align 3
_pf_jit_absolute_branch_end:

.globl _pf_jit_iter_loop_iter_load8_start
.globl _pf_jit_iter_loop_iter_load8_end
.globl _pf_jit_iter_loop_head_load8_start
.globl _pf_jit_iter_loop_head_load8_end

.align 3
_pf_jit_iter_loop_head_load8_start:
    mov x29, #0x8 // 8 bit
    ldrb w20, [x19], #1
    ldrb w21, [x19], #1
    ldrb w22, [x19], #1
    ldrb w23, [x19], #1
    ldrb w24, [x19], #1
    ldrb w25, [x19], #1
    ldrb w26, [x19], #1
    ldrb w27, [x19], #1
    cmp x19, x28
    b.lo Lnext81
_pf_jit_iter_loop_head_load8_end:
    nop
Lnext81:

.align 3
_pf_jit_iter_loop_iter_load8_start:
    mov w20, w21
    mov w21, w22
    mov w22, w23
    mov w23, w24
    mov w24, w25
    mov w25, w26
    mov w26, w27
    ldrb w27, [x19], #1
    cmp x19, x28
    b.hi Lnext82
_pf_jit_iter_loop_iter_load8_end:
    nop
Lnext82:

.globl _pf_jit_iter_loop_iter_load16_start
.globl _pf_jit_iter_loop_iter_load16_end
.globl _pf_jit_iter_loop_head_load16_start
.globl _pf_jit_iter_loop_head_load16_end

.align 3
_pf_jit_iter_loop_head_load16_start:
    mov x29, #0x10 // 16 bit
    ldrh w20, [x19], #2
    ldrh w21, [x19], #2
    ldrh w22, [x19], #2
    ldrh w23, [x19], #2
    ldrh w24, [x19], #2
    ldrh w25, [x19], #2
    ldrh w26, [x19], #2
    ldrh w27, [x19], #2
    cmp x19, x28
    b.lo Lnext161
_pf_jit_iter_loop_head_load16_end:
    nop
Lnext161:

.align 3
_pf_jit_iter_loop_iter_load16_start:
    mov w20, w21
    mov w21, w22
    mov w22, w23
    mov w23, w24
    mov w24, w25
    mov w25, w26
    mov w26, w27
    ldrh w27, [x19], #2
    cmp x19, x28
    b.hi Lnext162
_pf_jit_iter_loop_iter_load16_end:
    nop
Lnext162:

.align 3
_pf_jit_iter_loop_head_load32_start:
    mov x29, #0x20 // 32 bit
    ldr w20, [x19], #4
    ldr w21, [x19], #4
    ldr w22, [x19], #4
    ldr w23, [x19], #4
    ldr w24, [x19], #4
    ldr w25, [x19], #4
    ldr w26, [x19], #4
    ldr w27, [x19], #4
    cmp x19, x28
    b.lo Lnext1
_pf_jit_iter_loop_head_load32_end:
    nop
Lnext1:

.align 3
_pf_jit_iter_loop_iter_load32_start:
    mov w20, w21
    mov w21, w22
    mov w22, w23
    mov w23, w24
    mov w24, w25
    mov w25, w26
    mov w26, w27
    ldr w27, [x19], #4
    cmp x19, x28
    b.hi Lnext2
_pf_jit_iter_loop_iter_load32_end:
    nop
Lnext2:

.align 3
_pf_jit_iter_loop_head_load64_start:
    mov x29, #0x40 // 64 bit
    ldr x20, [x19], #8
    ldr x21, [x19], #8
    ldr x22, [x19], #8
    ldr x23, [x19], #8
    ldr x24, [x19], #8
    ldr x25, [x19], #8
    ldr x26, [x19], #8
    ldr x27, [x19], #8
    cmp x19, x28
    b.lo Lnext3
_pf_jit_iter_loop_head_load64_end:
    nop
Lnext3:

.align 3
_pf_jit_iter_loop_iter_load64_start:
    mov x20, x21
    mov x21, x22
    mov x22, x23
    mov x23, x24
    mov x24, x25
    mov x25, x26
    mov x26, x27
    ldr x27, [x19], #8
    cmp x19, x28
    b.hi Lnext4
_pf_jit_iter_loop_iter_load64_end:
    nop
Lnext4:

.align 3
_pf_jit_iter_loop_end_start:
    ldp x20, x21, [sp]
    ldp x22, x23, [sp,#0x10]
    ldp x24, x25, [sp,#0x20]
    ldp x26, x27, [sp,#0x30]
    ldp x28, x29, [sp,#0x40]
    ldp x30, x19, [sp,#0x50]
    add sp, sp, #0x60
    ret
.align 3
_pf_jit_iter_loop_end_end:


.globl _pf_jit_ptr_comparison_start
.globl _pf_jit_ptr_comparison_end

.align 3
_pf_jit_ptr_comparison_start:
    orr x8, x20, x2
    add x8, x8, x3
    cmp x8, x0
    b.lo _pf_jit_ptr_comparison_next
    cmp x8, x1
    b.hi _pf_jit_ptr_comparison_next
    ldr x0, _pf_jit_ptr_comparison_patch
    mov w1, w29
    sub x2, x19, #0x40
    mov x3, x2
    ldr x4, _pf_jit_ptr_comparison_slowpath
    blr x4
    b _pf_jit_ptr_comparison_next
    .align 3
_pf_jit_ptr_comparison_end:

_pf_jit_ptr_comparison_patch:
.quad 0x4141414142424200
_pf_jit_ptr_comparison_slowpath:
.quad 0x4141414142424201
_pf_jit_ptr_comparison_next:


.globl _pf_jit_slowpath_start
.globl _pf_jit_slowpath_end
.globl _pf_jit_slowpath_next

.align 3
_pf_jit_slowpath_start:
    ldr x0, _pf_jit_slowpath_patch
    mov w1, w29
    sub x2, x19, x29
    mov x3, x2
    ldr x4, _pf_jit_slowpath_slowpath
    blr x4
    nop
    nop
    nop
    nop
    b _pf_jit_slowpath_next
    .align 3
_pf_jit_slowpath_end:

_pf_jit_slowpath_patch:
.quad 0x4141414142424200
_pf_jit_slowpath_slowpath:
.quad 0x4141414142424201
_pf_jit_slowpath_next:


.globl _pf_jit_ptr_comparison_next
