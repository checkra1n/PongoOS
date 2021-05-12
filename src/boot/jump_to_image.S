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
.align 2
.global _jump_to_image
_jump_to_image:
    mov x30, x0
    mov x0, x1
    isb
    dsb sy
    ic iallu
    dsb sy
    isb
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    ret

.global _jump_to_image_extended
_jump_to_image_extended:
    mov x30, x0
    mov x0, x1
    mov x8, x2
    isb
    dsb sy
    ic iallu
    dsb sy
    isb
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    ret

.global _tramp_hook
_tramp_hook:
    mov x8, x27
    mov x9, x29
    mov x27, #0x800000000
    movk x27, #0x1800, lsl#16
    add x29, x27, #0x4
