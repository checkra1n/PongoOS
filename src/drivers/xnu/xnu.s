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
//  Copyright (c) 2020 checkra1n team
//  This file is part of pongoOS.
//

.globl pf_jit_iter_loop_head_start
.globl pf_jit_iter_loop_head_end
.globl pf_jit_iter_loop_head_load32_start
.globl pf_jit_iter_loop_head_load32_end
.globl pf_jit_iter_loop_iter_load32_start
.globl pf_jit_iter_loop_iter_load32_end
.globl pf_jit_iter_loop_head_load64_start
.globl pf_jit_iter_loop_head_load64_end
.globl pf_jit_iter_loop_iter_load64_start
.globl pf_jit_iter_loop_iter_load64_end
.globl pf_jit_iter_loop_end_start
.globl pf_jit_iter_loop_end_end

.globl pf_jit_absolute_branch_start
.globl pf_jit_absolute_branch_end

.align 3
pf_jit_iter_loop_head_start:
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
pf_jit_iter_loop_head_end:

.align 3
pf_jit_absolute_branch_start:
    adr x1, pf_jit_absolute_branch_end
    ldr x1, [x1]
    br x1
.align 3
pf_jit_absolute_branch_end:

.globl pf_jit_iter_loop_iter_load8_start
.globl pf_jit_iter_loop_iter_load8_end
.globl pf_jit_iter_loop_head_load8_start
.globl pf_jit_iter_loop_head_load8_end

.align 3
pf_jit_iter_loop_head_load8_start:
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
pf_jit_iter_loop_head_load8_end:
    nop
Lnext81:

.align 3
pf_jit_iter_loop_iter_load8_start:
    mov w20, w21
    mov w21, w22
    mov w22, w23
    mov w23, w24
    mov w24, w25
    mov w25, w26
    mov w26, w27
    ldrb w27, [x19], #1
    cmp x19, x28
    b.hi Lnext162
pf_jit_iter_loop_iter_load8_end:
    nop
Lnext82:

.globl pf_jit_iter_loop_iter_load16_start
.globl pf_jit_iter_loop_iter_load16_end
.globl pf_jit_iter_loop_head_load16_start
.globl pf_jit_iter_loop_head_load16_end

.align 3
pf_jit_iter_loop_head_load16_start:
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
pf_jit_iter_loop_head_load16_end:
    nop
Lnext161:

.align 3
pf_jit_iter_loop_iter_load16_start:
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
pf_jit_iter_loop_iter_load16_end:
    nop
Lnext162:

.align 3
pf_jit_iter_loop_head_load32_start:
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
pf_jit_iter_loop_head_load32_end:
    nop
Lnext1:

.align 3
pf_jit_iter_loop_iter_load32_start:
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
pf_jit_iter_loop_iter_load32_end:
    nop
Lnext2:

.align 3
pf_jit_iter_loop_head_load64_start:
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
pf_jit_iter_loop_head_load64_end:
    nop
Lnext3:

.align 3
pf_jit_iter_loop_iter_load64_start:
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
pf_jit_iter_loop_iter_load64_end:
    nop
Lnext4:

.align 3
pf_jit_iter_loop_end_start:
    ldp x20, x21, [sp]
    ldp x22, x23, [sp,#0x10]
    ldp x24, x25, [sp,#0x20]
    ldp x26, x27, [sp,#0x30]
    ldp x28, x29, [sp,#0x40]
    ldp x30, x19, [sp,#0x50]
    add sp, sp, #0x60
    ret
.align 3
pf_jit_iter_loop_end_end:


.globl pf_jit_ptr_comparison_start
.globl pf_jit_ptr_comparison_end

.align 3
pf_jit_ptr_comparison_start:
    orr x8, x20, x2
    add x8, x8, x3
    cmp x8, x0
    b.lo pf_jit_ptr_comparison_next
    cmp x8, x1
    b.hi pf_jit_ptr_comparison_next
    ldr x0, pf_jit_ptr_comparison_patch
    mov w1, w29
    sub x2, x19, #0x40
    mov x3, x2
    ldr x4, pf_jit_ptr_comparison_slowpath
    blr x4
    b pf_jit_ptr_comparison_next
    .align 3
pf_jit_ptr_comparison_end:

pf_jit_ptr_comparison_patch:
.quad 0x4141414142424200
pf_jit_ptr_comparison_slowpath:
.quad 0x4141414142424201
pf_jit_ptr_comparison_next:


.globl pf_jit_mask_comparison_1_start
.globl pf_jit_mask_comparison_1_end

.align 3
pf_jit_mask_comparison_1_start:
    and x8, x20, x1
    cmp x8, x0
    b.ne pf_jit_mask_comparison_1_next
    ldr x0, pf_jit_mask_comparison_1_patch
    mov w1, w29
    sub x2, x19, x29
    mov x3, x2
    ldr x4, pf_jit_mask_comparison_1_slowpath
    blr x4
    b pf_jit_mask_comparison_1_next
    .align 3
pf_jit_mask_comparison_1_end:

pf_jit_mask_comparison_1_patch:
.quad 0x4141414142424200
pf_jit_mask_comparison_1_slowpath:
.quad 0x4141414142424201
pf_jit_mask_comparison_1_next:


.globl pf_jit_mask_comparison_2_start
.globl pf_jit_mask_comparison_2_end

.align 3
pf_jit_mask_comparison_2_start:
    and x8, x20, x1
    cmp x8, x0
    b.ne pf_jit_mask_comparison_2_next
    and x8, x21, x3
    cmp x8, x2
    b.ne pf_jit_mask_comparison_2_next
    ldr x0, pf_jit_mask_comparison_2_patch
    mov w1, w29
    sub x2, x19, x29
    mov x3, x2
    ldr x4, pf_jit_mask_comparison_2_slowpath
    blr x4
    b pf_jit_mask_comparison_2_next
pf_jit_mask_comparison_2_end:

pf_jit_mask_comparison_2_patch:
.quad 0x4141414142424200
pf_jit_mask_comparison_2_slowpath:
.quad 0x4141414142424201
pf_jit_mask_comparison_2_next:

.globl pf_jit_mask_comparison_3_start
.globl pf_jit_mask_comparison_3_end

.align 3
pf_jit_mask_comparison_3_start:
    and x8, x20, x1
    cmp x8, x0
    b.ne pf_jit_mask_comparison_3_next
    and x8, x21, x3
    cmp x8, x2
    b.ne pf_jit_mask_comparison_3_next
    and x8, x22, x5
    cmp x8, x4
    b.ne pf_jit_mask_comparison_3_next
    ldr x0, pf_jit_mask_comparison_3_patch
    mov w1, w29
    sub x2, x19, x29
    mov x3, x2
    ldr x4, pf_jit_mask_comparison_3_slowpath
    blr x4
    b pf_jit_mask_comparison_3_next
pf_jit_mask_comparison_3_end:

pf_jit_mask_comparison_3_patch:
.quad 0x4141414142424200
pf_jit_mask_comparison_3_slowpath:
.quad 0x4141414142424201
pf_jit_mask_comparison_3_next:

.globl pf_jit_mask_comparison_4_start
.globl pf_jit_mask_comparison_4_end

.align 3
pf_jit_mask_comparison_4_start:
    and x8, x20, x1
    cmp x8, x0
    b.ne pf_jit_mask_comparison_4_next
    and x8, x21, x3
    cmp x8, x2
    b.ne pf_jit_mask_comparison_4_next
    and x8, x22, x5
    cmp x8, x4
    b.ne pf_jit_mask_comparison_4_next
    and x8, x23, x7
    cmp x8, x6
    b.ne pf_jit_mask_comparison_4_next
    ldr x0, pf_jit_mask_comparison_4_patch
    mov w1, w29
    sub x2, x19, x29
    mov x3, x2
    ldr x4, pf_jit_mask_comparison_4_slowpath
    blr x4
    b pf_jit_mask_comparison_4_next
    .align 3
pf_jit_mask_comparison_4_end:

pf_jit_mask_comparison_4_patch:
.quad 0x4141414142424200
pf_jit_mask_comparison_4_slowpath:
.quad 0x4141414142424201
pf_jit_mask_comparison_4_next:

.globl pf_jit_mask_comparison_5_start
.globl pf_jit_mask_comparison_5_end

.align 3
pf_jit_mask_comparison_5_start:
    and x8, x20, x1
    cmp x8, x0
    b.ne pf_jit_mask_comparison_5_next
    and x8, x21, x3
    cmp x8, x2
    b.ne pf_jit_mask_comparison_5_next
    and x8, x22, x5
    cmp x8, x4
    b.ne pf_jit_mask_comparison_5_next
    and x8, x23, x7
    cmp x8, x6
    b.ne pf_jit_mask_comparison_5_next
    and x8, x24, x10
    cmp x8, x9
    b.ne pf_jit_mask_comparison_5_next
    ldr x0, pf_jit_mask_comparison_5_patch
    mov w1, w29
    sub x2, x19, x29
    mov x3, x2
    ldr x4, pf_jit_mask_comparison_5_slowpath
    blr x4
    b pf_jit_mask_comparison_5_next
    .align 3
pf_jit_mask_comparison_5_end:

pf_jit_mask_comparison_5_patch:
.quad 0x4141414142424200
pf_jit_mask_comparison_5_slowpath:
.quad 0x4141414142424201
pf_jit_mask_comparison_5_next:


.globl pf_jit_mask_comparison_6_start
.globl pf_jit_mask_comparison_6_end

.align 3
pf_jit_mask_comparison_6_start:
    and x8, x20, x1
    cmp x8, x0
    b.ne pf_jit_mask_comparison_6_next
    and x8, x21, x3
    cmp x8, x2
    b.ne pf_jit_mask_comparison_6_next
    and x8, x22, x5
    cmp x8, x4
    b.ne pf_jit_mask_comparison_6_next
    and x8, x23, x7
    cmp x8, x6
    b.ne pf_jit_mask_comparison_6_next
    and x8, x24, x10
    cmp x8, x9
    b.ne pf_jit_mask_comparison_6_next
    and x8, x25, x12
    cmp x8, x11
    b.ne pf_jit_mask_comparison_6_next
    ldr x0, pf_jit_mask_comparison_6_patch
    mov w1, w29
    sub x2, x19, x29
    mov x3, x2
    ldr x4, pf_jit_mask_comparison_6_slowpath
    blr x4
    b pf_jit_mask_comparison_6_next
    .align 3
pf_jit_mask_comparison_6_end:

pf_jit_mask_comparison_6_patch:
.quad 0x4141414142424200
pf_jit_mask_comparison_6_slowpath:
.quad 0x4141414142424201
pf_jit_mask_comparison_6_next:


.globl pf_jit_mask_comparison_7_start
.globl pf_jit_mask_comparison_7_end

.align 3
pf_jit_mask_comparison_7_start:
    and x8, x20, x1
    cmp x8, x0
    b.ne pf_jit_mask_comparison_7_next
    and x8, x21, x3
    cmp x8, x2
    b.ne pf_jit_mask_comparison_7_next
    and x8, x22, x5
    cmp x8, x4
    b.ne pf_jit_mask_comparison_7_next
    and x8, x23, x7
    cmp x8, x6
    b.ne pf_jit_mask_comparison_7_next
    and x8, x24, x10
    cmp x8, x9
    b.ne pf_jit_mask_comparison_7_next
    and x8, x25, x12
    cmp x8, x11
    b.ne pf_jit_mask_comparison_7_next
    and x8, x26, x14
    cmp x8, x13
    b.ne pf_jit_mask_comparison_7_next
    ldr x0, pf_jit_mask_comparison_7_patch
    mov w1, w29
    sub x2, x19, x29
    mov x3, x2
    ldr x4, pf_jit_mask_comparison_7_slowpath
    blr x4
    b pf_jit_mask_comparison_7_next
    .align 3
pf_jit_mask_comparison_7_end:

pf_jit_mask_comparison_7_patch:
.quad 0x4141414142424200
pf_jit_mask_comparison_7_slowpath:
.quad 0x4141414142424201
pf_jit_mask_comparison_7_next:


.globl pf_jit_mask_comparison_8_start
.globl pf_jit_mask_comparison_8_end

.align 3
pf_jit_mask_comparison_8_start:
    and x8, x20, x1
    cmp x8, x0
    b.ne pf_jit_mask_comparison_8_next
    and x8, x21, x3
    cmp x8, x2
    b.ne pf_jit_mask_comparison_8_next
    and x8, x22, x5
    cmp x8, x4
    b.ne pf_jit_mask_comparison_8_next
    and x8, x23, x7
    cmp x8, x6
    b.ne pf_jit_mask_comparison_8_next
    and x8, x24, x10
    cmp x8, x9
    b.ne pf_jit_mask_comparison_8_next
    and x8, x25, x12
    cmp x8, x11
    b.ne pf_jit_mask_comparison_8_next
    and x8, x26, x14
    cmp x8, x13
    b.ne pf_jit_mask_comparison_8_next
    and x8, x27, x16
    cmp x8, x15
    b.ne pf_jit_mask_comparison_8_next
    ldr x0, pf_jit_mask_comparison_8_patch
    mov w1, w29
    sub x2, x19, x29
    mov x3, x2
    ldr x4, pf_jit_mask_comparison_8_slowpath
    blr x4
    b pf_jit_mask_comparison_8_next
    .align 3
pf_jit_mask_comparison_8_end:

pf_jit_mask_comparison_8_patch:
.quad 0x4141414142424200
pf_jit_mask_comparison_8_slowpath:
.quad 0x4141414142424201
pf_jit_mask_comparison_8_next:

.globl pf_jit_mask_comparison_8_next
.globl pf_jit_mask_comparison_7_next
.globl pf_jit_mask_comparison_6_next
.globl pf_jit_mask_comparison_5_next
.globl pf_jit_mask_comparison_4_next
.globl pf_jit_mask_comparison_3_next
.globl pf_jit_mask_comparison_2_next
.globl pf_jit_mask_comparison_1_next
.globl pf_jit_ptr_comparison_next
