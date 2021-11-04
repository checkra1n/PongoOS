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
.globl _clear_hook
.globl _clear_hook_end
.globl _clear_hook_orig_backing


.align 4
_clear_hook:
mov x16, x30
mov x30, x5
mov x3, #0x800000000
movk x3, #0x1800, lsl#16
cmp x0, x3
b.hi _clear_hook_orig_backing
add x2, x1, x0
cmp x2, x3
b.lo _clear_hook_orig_backing
mov x3, #0x800000000
movk x3, #0x18e0, lsl#16
cmp x0, x3
b.hi _clear_hook_orig_backing
add x2, x1, x0
cmp x2, x3
b.lo _clear_hook_orig_backing
mov x1, #0
_clear_hook_orig_backing:
nop
nop
br x16
_clear_hook_end:
