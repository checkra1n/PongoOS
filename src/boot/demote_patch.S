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
// shellcode to patch out the img4 checks that verify if the image type is correct in order to boot a production image with demotion active
// assumptions:
// - we can write anywhere
// - x0 is the base address of the image we should search through

.align 2
.globl d$demote_patch
d$demote_patch:

	// the image 4 code sets a flag when it detects the EPRO tag
	// the first flag that is the "control flag" and gets checked later, if set it will check if the current production mode of the phone matches the one of the image
	// the second one is the flag that tells the img4 code that we found this tag
	// we only care about the first one, if it's patched out the code won't check and because of that also won't bail if it doesn't match

	// for that we first search for the place where the EPRO string is loaded into a register
	// there are multiple places (because it also checks if the tag exists etc), we only care about the one where it's put into w/x0

	// because of this we need to find sth like this:
	// 00aaa8d2       movz x0, 0x4550, lsl 16 
	// e0498af2       movk x0, 0x524f
	// or a variant
	// e0498a52       movz w0, 0x524f
	// 00aaa872       movk w0, 0x4550, lsl 16

	// as you can see there are four different variants the compiler can emit, either loading the higher bits first and then the lower ones and either using x0 or w0
	// because of that we need to do some masking to mask out the x/w and the movz/k as weel as the lsl

	// this means we first search for the movz
	// 528a49e0 with the mask 0xFFFFFF5F/5FFFFFFF (masks out the bit that decides between movk and movz (lower one) and the one that decides between w0 and x0)
	// x4 is 52a8aa00 aka the movk that has to follow after the movz, but we also need to mask this one to account for the variants
	// movz
    movz x1, 0x49e0
    movk x1, 0x528a, lsl 16
	// mask (to mask out movk/z and w/x)
    movz x2, 0x5fff, lsl 16
    movk x2, 0xffff
	// movk
    movz x4, 0xaa00
    movk x4, 0x52a8, lsl 16

_d$_next_instr:
    ldr w3, [x0], #4
    and w3, w3, w2
    cmp w3, w1
    b.ne _d$_next_instr
	// now we found one mov instruction, we need to check if the previous one or the next one is our other mov instruction
    ldr w3, [x0] // load the next instruction
    and w3, w3, w2
    cmp w3, w4 // check if it's the other mov
    b.eq _d$_found_first
    ldr w3, [x0,#-8] // load the prev instruction
    and w3, w3, w2
    cmp w3, w4 // check if it's the other mov
    b.ne _d$_next_instr

_d$_found_first:
    // now we found the mov instructions
    // we need to walk upwards to find the instructions that sets the flag to make sure the production state gets verified
	// we will just nop this instruction, because the img4 code will always zero the flags before running so it will always be 0 if we don't set it

    // we search for this
    // c8120039       strb w8, [x22, 4]

    // we do that by searching for 0x39000000 with the mask 0xFF000000
	// that way we will find all strb instructions, but we only care about the first one
    movz x1, 0x3900, lsl 16
    movz x2, 0xff00, lsl 16

_d$_find_strb:
    ldr w3, [x0], #-4 
    and w3, w3, w2
    cmp w3,w1
    b.ne _d$_find_strb
    add x0, x0, 4 // move back
    // nop
    movz w3, 0x201f
    movk w3, 0xd503, lsl 16
    str w3, [x0] // patch

	ret
