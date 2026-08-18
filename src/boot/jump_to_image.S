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
.align 2
.global _jump_to_image_extended
.global _jump_to_image
_jump_to_image_extended:
    mov x8, x3
_jump_to_image:
    mov x30, x0
    mov x0, x1
    // If we were passed no tramp page, then oh well.
    // You better not be booting any kernel here.
    cbz x2, L_jump_to_image_raw
    // Kinda dirty, but:
    // If we have EL3, that means SRAM is the L3 cache.
    // If we don't have EL3, that means SRAM is the L2 cache.
    mrs x1, id_aa64pfr0_el1
    tst w1, 0xf000
    // If we have no EL3, then we always need to release SRAM.
    b.eq L_jump_to_image_by_tramp
    // If we have EL3, then we may or may not need to release SRAM.
    adrp x3, _need_to_release_L3_SRAM@PAGE
    ldrb w3, [x3, _need_to_release_L3_SRAM@PAGEOFF]
    cmp w3, 0x41
    b.eq L_jump_to_image_by_tramp
    // If SRAM is good in its current state, then we can just go.
L_jump_to_image_raw:
    dsb sy
    isb
    ic iallu
    isb
    b L_jump_to_image_epilogue

L_jump_to_image_by_tramp:
    adrp x7, _socnum@PAGE
    ldr w7, [x7, _socnum@PAGEOFF]
    adr x3, L_jump_to_image_tramp
#if (!defined(__apple_build_version__) && __clang_major__ >= 11) || (defined(__apple_build_version__) && (__clang_major__ > 12 || (__clang_major__ == 12 && (__clang_minor__ > 0 || (__clang_minor__ == 0 && __clang_patchlevel__ >= 5)))) )
    // This is the nice version, supported since clang 11 (or AppleClang-12.0.5 because apparently they lag behind by over a year)
    add x4, x3, (L_jump_to_image_tramp_end - L_jump_to_image_tramp)
#else
    // And this is the ghetto version for legacy clang
    .4byte (0x91000064 | (((L_jump_to_image_tramp_end - L_jump_to_image_tramp) & 0xfff) << 10))
#endif
    mov x5, x2
L_jump_to_image_copy:
    ldr w6, [x3], 4
    str w6, [x5], 4
    cmp x3, x4
    b.lo L_jump_to_image_copy
    dsb sy
    isb
    ic iallu
    isb
    br x2

L_jump_to_image_tramp:
    tst w1, 0xf000
    b.eq L_jump_to_image_release_L2
L_jump_to_image_release_L3:
    // L3 is convoluted
    mov x1, 0x200000000
    movk x1, 0x780
    ldr w2, [x1]
    and w2, w2, 0xfffffffd
    str w2, [x1]
    ldr w2, [x1]
    orr w2, w2, 0x10000
    str w2, [x1]
    ldr w2, [x1, 0x14]
    orr w2, w2, 1
    str w2, [x1, 0x14]
    mov w6, 0x8001
    cmp w7, w6
    b.ne L_jump_to_image_epilogue
    // Second AMCC for A9X
    add x1, x1, 0x200000
    ldr w2, [x1]
    and w2, w2, 0xfffffffd
    str w2, [x1]
    ldr w2, [x1]
    orr w2, w2, 0x10000
    str w2, [x1]
    ldr w2, [x1, 0x14]
    orr w2, w2, 1
    str w2, [x1, 0x14]
    b L_jump_to_image_epilogue
L_jump_to_image_release_L2:
    // L2 is easy
    mrs x2, s3_3_c15_c7_0
    and x2, x2, 0xffffffffffffffc0
    msr s3_3_c15_c7_0, x2
L_jump_to_image_release_L2_wait:
    mrs x2, s3_3_c15_c7_0
    tbnz x2, 63, L_jump_to_image_release_L2_wait

L_jump_to_image_epilogue:
    msr spsel, 1
    and sp, xzr, 1
    msr sp_el0, xzr
    mov x1, 0
    mov x2, 0
    mov x3, 0
    ret
L_jump_to_image_tramp_end:

.data
.global _need_to_release_L3_SRAM
_need_to_release_L3_SRAM:
    .byte 0x69 // [0x69 = no, 0x41 = yes] - don't want this in zerofill
