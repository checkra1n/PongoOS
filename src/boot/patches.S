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

// ************************************************************
// **                                                        **
// **         THIS FILE IS USED BY MULTIPLE PROJECTS!        **
// **                                                        **
// ** Before committing changes to this file, make sure both **
// ** PongoOS and the checkra1n payload project still build! **
// **                                                        **
// ************************************************************

#ifdef NO_GLOBAL
    .macro sym
    L_$0:
    .endmacro
#else
    .text
    .macro sym
    .globl $0
    $0:
    .endmacro
#endif

.align 2

// void iorvbar_yeet(volatile void *boot_image)

/*
RVBAR_ELx is controlled by the IORVBAR MMIO register.
Each CPU has one, obtainable from it's DeviceTree entry, "reg-private" property +0x40000.
Per SoC:

+------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+
| SoC  |   PCORE0    |   PCORE1    |   PCORE2    |   PCORE3    |   ECORE0    |   ECORE1    |   ECORE2    |   ECORE3    |
+------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+
| A7   | 0x202050000 | 0x202150000 |             |             |             |             |             |             |
+------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+
| A8   | 0x202050000 | 0x202150000 |             |             |             |             |             |             |
+------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+
| A8X  | 0x202050000 | 0x202150000 | 0x202450000 |             |             |             |             |             |
+------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+
| A9   | 0x202050000 | 0x202150000 |             |             |             |             |             |             |
+------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+
| A9X  | 0x202050000 | 0x202150000 |             |             |             |             |             |             |
+------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+
| A10  | 0x202050000 | 0x202150000 |             |             |             |             |             |             |
+------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+
| A10X | 0x202050000 | 0x202150000 | 0x202250000 |             |             |             |             |             |
+------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+
| T2   | 0x202050000 | 0x202150000 |             |             |             |             |             |             |
+------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+
| A11  | 0x208450000 | 0x208550000 |             |             | 0x208050000 | 0x208150000 | 0x208250000 | 0x208350000 |
+------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+
| A12  | 0x211050000 | 0x211150000 |             |             | 0x210050000 | 0x210150000 | 0x210250000 | 0x210350000 |
+------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+
| A12X | 0x211050000 | 0x211150000 | 0x211250000 | 0x211350000 | 0x210050000 | 0x210150000 | 0x210250000 | 0x210350000 |
+------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+
| A13  | 0x211050000 | 0x211150000 |             |             | 0x210050000 | 0x210150000 | 0x210250000 | 0x210350000 |
+------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+
| A14  | 0x211050000 | 0x211150000 |             |             | 0x210050000 | 0x210150000 | 0x210250000 | 0x210350000 |
+------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+
| M1   | 0x211050000 | 0x211150000 | 0x211250000 | 0x211350000 | 0x210050000 | 0x210150000 | 0x210250000 | 0x210350000 |
+------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+

Bits [63:36] seem to be readonly, but do hold a value.
Bits [35:11] are the RVBAR address (mask 0xffffff800).
Bits  [10:1] seem to be res0.
Bit      [0] locks the register against future writes.

iBoot issues a "dmb sy" after writing to those registers.


The patch works by finding this sequence of instructions:

+--------------------------------+
| and xN, x0, 0xfffffffffffff800 |
| orr xM, xN, 1                  |
+--------------------------------+

Starting with iOS 15, it seems the function has changed to instead
take an argument that is directly OR'ed into the value:

+--------------------------------+
| and xN, x0, 0xfffffffffffff800 |
| mov wK, w1                     |
| orr xM, xN, xK                 |
+--------------------------------+

In radare2, this can be found with the following masked hexsearch respectively:

/x 00d07592000040b2:e0ffffff00fcffff
/x 00d07592e003012a000000aa:e0ffffffe0ffffff00fce0ff

We just yeet out the orr, so that iBoot sets the RVBAR address but doesn't lock it.
This means we change the instruction from orr-immediate to orr-register, with xzr as 3rd operand.
*/

sym iorvbar_yeet
    mov x2, x0 // instr
    movz w5, 0x9275, lsl 16 // and xN, x0, 0xfffffffffffff800
    movk w5, 0xd000
    movz w6, 0xb240, lsl 16 // orr xM, xN, 1
    movz w7, 0xaa1f, lsl 16 // orr xM, xN, xzr
    movz w8, 0x2a01, lsl 16 // mov wK, w1
    movk w8, 0x03e0
1:
    // Match 0xfffffffffffff800
    ldr w3, [x2], 0x4
    and w4, w3, 0xffffffe0
    cmp w4, w5
    b.ne 1b
    // Match orr with immediate
    bfi w6, w3, 5, 5
    ldr w4, [x2]
    and w3, w4, 0xffffffe0
    cmp w3, w6
    b.eq 2f
    // Match arg1
    cmp w3, w8
    b.ne 1b
    // Match orr with reg
    and w9, w6, 0x3e0
    movk w9, 0xaa00, lsl 16 // orr xM, xN, xK
    bfi w9, w4, 16, 5
    ldr w4, [x2, 0x4]
    and w3, w4, 0xffffffe0
    cmp w3, w9
    b.ne 1b
    add x2, x2, 0x4
2:
    // Patch
    bfi w7, w4, 0, 10
    str w7, [x2]
    ret


// void aes_keygen(volatile void *boot_image)

/*
iDevices seem to have three builtin AES keys: UID, GID0 and GID1.
GID0 is used for firmware decryption and is disabled by iBoot,
the other two are usually left enabled. The bit configs are as follows:

#define AES_DISABLE_UID  (1 << 0)
#define AES_DISABLE_GID0 (1 << 1)
#define AES_DISABLE_GID1 (1 << 2)

Devices up to A8X need to clock/unclock the AES engine before/after setting the flag, later chips don't.
The following table shows the relevant MMIO addresses:

+------+-------------+-------------+
| SoC  | AES_DISABLE | PMGR_AES0   |
+------+-------------+-------------+
| A7   | 0x20a108004 | 0x20e020100 |
+------+-------------+-------------+
| A8   | 0x20a108004 | 0x20e0201e8 |
+------+-------------+-------------+
| A8X  | 0x20a108004 | 0x20e0201e8 |
+------+-------------+-------------+
| A9   | 0x2102d0000 |             |
+------+-------------+-------------+
| A9X  | 0x2102d0000 |             |
+------+-------------+-------------+
| A10  | 0x2102d0000 |             |
+------+-------------+-------------+
| A10X | 0x2102d0000 |             |
+------+-------------+-------------+
| T2   | 0x2112d0000 |             |
+------+-------------+-------------+
| A11  | 0x2352d0000 |             |
+------+-------------+-------------+
| A12  | 0x23d2d0000 |             |
+------+-------------+-------------+
| A12X |      ?      |             |
+------+-------------+-------------+
| A13  | 0x23d2d0000 |             |
+------+-------------+-------------+
| A14  | 0x23d2d0000 |             |
+------+-------------+-------------+
| M1   | 0x23d2d0000 |             |
+------+-------------+-------------+

Note that iBoot issues a "dmb sy" after writing to the AES register.

Also note that our iBoot patch is only meaningful on initial boot.
Before A9, devices go through ROM and LLB after deep sleep and relock, and
there's nothing we can do about that, except not entering deep sleep, ever.
On A9 and later this is handled by the AOP reconfig engine, which enables us to
actually keep this patch persistent, but obviously needs a separate patch (see below).
On a more curious note, the AES_DISABLE seems to actually persist across deep sleep
without the aid of the reconfig engine, yet some SoCs still re-lock it.


The AES patch works by finding two calls to security_allow_modes(), which immediately
precede the call to platform_disable_keys(). In assembly, this looks like this:

+----------------------+
| orr w0, wzr, 0x40000 |
| bl 0x(same)          |
| mov x{19-28}, x0     |
| orr w0, wzr, 0x80000 |
| bl 0x(same)          |
+----------------------+

Or, on newer clang, like this:

+------------------+
| mov w0, 0x40000  |
| bl 0x(same)      |
| mov x{19-28}, x0 |
| mov w0, 0x80000  |
| bl 0x(same)      |
+------------------+

And again in r2 hexsearch:

/x e0030e3200000094f00300aae0030d3200000094:ffffffff000000fcf0ffffffffffffff000000fc
/x 8000a05200000094f00300aa0001a05200000094:ffffffff000000fcf0ffffffffffffff000000fc

We find this sequence, seek to the next bl, then dereference it and write a "ret" there.
We do this rather than nop'ing the branch because there is more than one call site.
*/

sym aes_keygen
    mov x2, x0 // instr
    movz w7, 0x320e, lsl 16 // orr w0, wzr, 0x40000
    movk w7, 0x03e0
    movz w8, 0x52a0, lsl 16 // mov w0, 0x40000
    movk w8, 0x0080
    movz w9, 0xaa00, lsl 16 // mov x{16-31}, x0
    movk w9, 0x03f0
    sub w10, w7, 0x10, lsl 12 // orr w0, wzr, 0x80000
    add w11, w8, 0x80 // mov w0, 0x80000
    // First loop: search for call site
1:
    // +0x00: orr w0, wzr, 0x40000
    ldr w3, [x2], 0x4
    cmp w3, w7
    ccmp w3, w8, 4, ne
    b.ne 1b
    // +0x08: mov x{16-31}, x0
    // +0x0c: orr w0, wzr, 0x80000
    ldp w3, w4, [x2, 0x4]
    and w3, w3, 0xfffffff0
    // if((w4 == w10 || w4 == w11) && w3 == w9)
    cmp w4, w10
    ccmp w4, w11, 4, ne
    ccmp w3, w9, 0, eq
    b.ne 1b
    // +0x04: bl 0x(same)
    // +0x10: bl 0x(same)
    ldr w3, [x2]
    ldr w4, [x2, 0xc]
    sub w3, w3, w4
    ubfx w4, w4, 26, 6
    cmp w4, 0x25 // check for (... & 0xfc000000) == 0x94000000
    ccmp w3, 0x3, 0, eq // make sure both bl have same target
    b.ne 1b

    // Second loop: Search for following call
    add x2, x2, 0xc
2:
    ldr w3, [x2, 0x4]!
    ubfx w4, w3, 26, 6
    cmp w4, 0x25 // check for bl
    b.ne 2b
    sbfx w3, w3, 0, 26
    ldr w7, Lol
    str w7, [x2, w3, sxtw 2]
Lol:
    ret


// void recfg_yoink(volatile void *boot_image)

/*
The reconfig engine works by having eight separate config sequences that are run on different events.
At the top level there is an MMIO register in the AOP domain that points to an array of eight 32-bit values.
These are labelled as follows:

- [0] AWAKE_AOP_DDR_PRE
- [1] AWAKE_AOP_DDR_POST
- [2] AOP_DDR_S2R_AOP_PRE
- [3] AOP_DDR_S2R_AOP_POST
- [4] S2R_AOP_AOP_DDR_PRE
- [5] S2R_AOP_AOP_DDR_POST
- [6] AOP_DDR_AWAKE_PRE
- [7] AOP_DDR_AWAKE_POST

Each of those then points to a uint32 array that makes up the reconfig command sequence
for that event. All of those are typically laid out in AOP SRAM.

At first, iBoot has loose chunks of that sequence scattered through itself, and some parts
are generated on the fly. But before booting XNU, it builds the final sequences, writes
them to AOP SRAM and then locks that SRAM down (or possibly only parts thereof).

For us, attempting to touch this sequence before it has reached AOP SRAM is ridiculously
inconvenient, and would also bloat stage2 a ton. But thankfully all we need to do is
prevent lockdown, and then we can operate on the final sequence conveniently from PongoOS.

The relevant addresses are:

+------+---------------+--------------+-------------------------+---------------+---------------------+-------------------+
| SoC  | AOP_CFG_TABLE | AOP_CFG_LOCK |       RECFG_SRAM        | AOP_SRAM_BASE | AOP_SRAM_LOCK_RANGE | AOP_SRAM_LOCK_SET |
+------+---------------+--------------+-------------------------+---------------+---------------------+-------------------+
| A9   |  0x210000200  |              |                         |  0x210800008  |     0x21000021c     |    0x210000220    |
+------+---------------+--------------+-------------------------+---------------+---------------------+-------------------+
| A9X  |  0x210000200  |              |                         |  0x210800008  |     0x21000021c     |    0x210000220    |
+------+---------------+--------------+-------------------------+---------------+---------------------+-------------------+
| A10  |  0x210000100  |              |                         |  0x210800008  |     0x21000011c     |    0x210000120    |
+------+---------------+--------------+-------------------------+---------------+---------------------+-------------------+
| A10X |  0x210000100  |              |                         |  0x210800008  |     0x21000011c     |    0x210000120    |
+------+---------------+--------------+-------------------------+---------------+---------------------+-------------------+
| T2   |  0x2112c0200  | 0x2112c0214  | 0x211f00000-0x211f10000 |               |     0x211000200     |    0x211000204    |
+------+---------------+--------------+-------------------------+---------------+---------------------+-------------------+
| A11  |  0x2352c0200  | 0x2352c0214  | 0x235f00000-0x235f10000 |               |     0x235000200     |    0x235000204    |
+------+---------------+--------------+-------------------------+---------------+---------------------+-------------------+
| A12  |  0x23d2c0200  | 0x23d2c0214  |            ?            |               |     0x23d000200     |    0x23d000204    |
+------+---------------+--------------+-------------------------+---------------+---------------------+-------------------+
| A12X |       ?       |      ?       |            ?            |               |          ?          |         ?         |
+------+---------------+--------------+-------------------------+---------------+---------------------+-------------------+
| A13  |  0x23d2c0200  | 0x23d2c0214  | 0x23df00000-     ?      |               |     0x23d000200     |    0x23d000204    |
+------+---------------+--------------+-------------------------+---------------+---------------------+-------------------+
| A14  |  0x23d2c0200  | 0x23d2c021c  | 0x23df00000-     ?      |               |     0x23d000200     |    0x23d000204    |
+------+---------------+--------------+-------------------------+---------------+---------------------+-------------------+
| M1   |  0x23d2c0200  | 0x23d2c021c  | 0x23df00000-     ?      |               |     0x23d000200     |    0x23d000204    |
+------+---------------+--------------+-------------------------+---------------+---------------------+-------------------+

- AOP_CFG_TABLE is a 32-bit offset from the SRAM base. Mask pre-A11 0x1fff80, T2/A11+ 0xff80.
  At the address it points to is an uint32_t[8] array of 36-bit physical addresses >> 4.
- AOP_CFG_LOCK is a 1-bit register that locks down AOP_CFG_TABLE (T2/A11+ only).
  Before T2/A11, AOP_CFG_TABLE is locked down by AOP_SRAM_LOCK_SET instead.
- AOP_SRAM_BASE is the 32-bit physical address of AOP SRAM, minus 0x200000000.
  On T2/A11 and later, the AOP and the reconfig engine have separate SRAM, so this is irrelevant.
- AOP_SRAM_LOCK_RANGE has two ranges, [14:0] and [30:16], which are the
  start and end numbers (inclusive) of 0x40-blocks to lock down.
- AOP_SRAM_LOCK_SET is a 1-bit register that locks down AOP_SRAM_LOCK_RANGE,
  and before T2/A11 also AOP_CFG_TABLE.

Here too iBoot issues a "dmb sy" after writing.


Our patch works by finding the calls to reconfig_init(), platform_reconfig_sequence_insert()
and reconfig_lock() in platform_bootprep_darwin(). All of them are called with exactly
one argument: BOOT_DARWIN (== 3). In assembly, it looks like this:

+----------------+
| orr w0, wzr, 3 |
| bl 0x...       |
| orr w0, wzr, 3 |
| bl 0x...       |
| orr w0, wzr, 3 |
| bl 0x...       |
+----------------+

Or on new clang:

+-----------+
| mov w0, 3 |
| bl 0x...  |
| mov w0, 3 |
| bl 0x...  |
| mov w0, 3 |
| bl 0x...  |
+-----------+

In r2:

/x e007003200000094e007003200000094e007003200000094:ffffffff000000fcffffffff000000fcffffffff000000fc
/x 600080520000009460008052000000946000805200000094:ffffffff000000fcffffffff000000fcffffffff000000fc

The last bl is the call to reconfig_lock(), so we just deref and turn it into
a ret to nop the lock. Absolutely everything else is deferred to PongoOS.
*/

#ifndef NO_RECFG

sym recfg_yoink
    mov x2, x0 // instr
    movz w8, 0x3200, lsl 16 // orr w0, wzr, 3
    movk w8, 0x07e0
    movz w9, 0x5280, lsl 16 // mov w0, 3
    movk w9, 0x0060
    movz w10, 0x25 // bl top bits
    // Loop: search for call site
1:
    ldr w3, [x2], 0x4
    cmp w3, w8
    ccmp w3, w9, 4, ne
    b.ne 1b
    ldp w3, w4, [x2]
    ldp w5, w6, [x2, 0x8]
    ldr w7, [x2, 0x10]
    ubfx w3, w3, 26, 6
    ubfx w5, w5, 26, 6
    cmp w4, w8
    ccmp w4, w9, 4, ne
    b.ne 1b
    cmp w6, w8
    ccmp w6, w9, 4, ne
    ubfx w4, w7, 26, 6
    ccmp w3, w10, 0, eq
    ccmp w5, w10, 0, eq
    ccmp w4, w10, 0, eq
    b.ne 1b

    // Deref and patch
    add x2, x2, 0x10
    sbfx w7, w7, 0, 26
    ldr w3, Lul
    str w3, [x2, w7, sxtw 2]
Lul:
    ret

#endif


// void fuse_jump(volatile void *boot_image)

/*
We already coerce the ROM into leaving the fuse array unlocked and patch iBootStage1 to skip the check,
but nonetheless both iBootStage1 and iBootStage2 very stubbornly lock the fuse array again.

+------------------------+
| movk x8, 0x...         |
| ldr w9, [x8]           |
| orr w9, w9, 0x80000000 |
| str w9, [x8]           |
| {dsb sy | ret}         |
+------------------------+

In r2:

/x 080080f2090140b929010132090100b9c0035fd6:1f0080ffffffffffffffffffffffffffffffffff
/x 080080f2090140b929010132090100b99f3f03d5:1f0080ffffffffffffffffffffffffffffffffff

We search for the pattern, then seek backwards for a "cbz w0, ..." with positive offset. If we find none
within a short range, we skip this match, otherwise we replace that instruction with an unconditional branch.
*/

sym fuse_jump
    mov x2, x0 // instr
    mov w3, 0xb9400000 // ldr w9, [x8]
    movk w3, 0x0109
    mov w4, 0x32010000 // orr w9, w9, 0x80000000
    movk w4, 0x0129
    mov w5, 0xb9000000 // str w9, [x8]
    movk w5, 0x0109
    mov w6, 0xd5030000 // dsb sy
    movk w6, 0x3f9f
    mov w7, 0xd65f0000 // ret
    movk w7, 0x03c0
    mov w8, 0xf2800000 // movk x8, ...
    movk w8, 0x0008
    mov w9, 0x34000000 // cbz w0, ... (forward)
    // Search for pattern
1:
    ldp w10, w11, [x2, 0x4]!
    cmp w10, w3
    ccmp w11, w4, 0, eq
    b.ne 1b
    ldp w10, w11, [x2, 0x8]
    cmp w11, w6
    ccmp w11, w7, 4, ne
    ccmp w10, w5, 0, eq
    b.ne 1b
    ldr w10, [x2, -0x4]
    and w10, w10, 0xff80001f
    cmp w10, w8
    b.ne 1b

    // Search for preceding "cbz w0"
    sub x10, x2, 0x4
    sub x11, x10, 0x18
2:
    ldr w12, [x10, -0x4]!
    and w13, w12, 0xff80001f
    cmp w13, w9
    b.eq 3f
    cmp x10, x11
    b.hi 2b
    b 1b

    // Turn the branch unconditional
3:
    sbfx w12, w12, 5, 19
    mov w8, 0x14000000 // b
    bfi w8, w12, 0, 26
    str w8, [x10]
    ret


// void antitrust(volatile void *boot_image)

/*
Keep TrustZone unlocked.

There are a total of 4 variants of this patch, and this is just one of them.
In the matrix below:

- s2 = A10+ on iOS 14.0+. Stage2-only.
- XX = A7, any version, and A8-A9 on 10.x and lower. Pongo-only.
- YY = A9X, any version. Pongo-only.
- ZZ = The rest, this is us. The only patch that is shared between stage2 and Pongo.

For A8-A9, ZZ could be used on iOS 8 and 10 as well, but not on iOS 9.
But XX works on those too, so we don't care.

+--------+----+----+-----+----+-----+-----+------+----+-----+
|        | A7 | A8 | A8X | A9 | A9X | A10 | A10X | T2 | A11 |
+--------+----+----+-----+----+-----+-----+------+----+-----+
| iOS 7  | XX |    |     |    |     |     |      |    |     |
+--------+----+----+-----+----+-----+-----+------+----+-----+
| iOS 8  | XX | XX | XX  |    |     |     |      |    |     |
+--------+----+----+-----+----+-----+-----+------+----+-----+
| iOS 9  | XX | XX | XX  | XX | YY  |     |      |    |     |
+--------+----+----+-----+----+-----+-----+------+----+-----+
| iOS 10 | XX | XX | XX  | XX | YY  | ZZ  |  ZZ  |    |     |
+--------+----+----+-----+----+-----+-----+------+----+-----+
| iOS 11 | XX | ZZ | ZZ  | ZZ | YY  | ZZ  |  ZZ  | ZZ | ZZ  |
+--------+----+----+-----+----+-----+-----+------+----+-----+
| iOS 12 | XX | ZZ | ZZ  | ZZ | YY  | ZZ  |  ZZ  | ZZ | ZZ  |
+--------+----+----+-----+----+-----+-----+------+----+-----+
| iOS 13 |    | ZZ | ZZ  | ZZ | YY  | ZZ  |  ZZ  | ZZ | ZZ  |
+--------+----+----+-----+----+-----+-----+------+----+-----+
| iOS 14 |    | ZZ | ZZ  | ZZ | YY  | s2  |  s2  | s2 | s2  |
+--------+----+----+-----+----+-----+-----+------+----+-----+
| iOS 15 |    | ZZ | ZZ  | ZZ | YY  | s2  |  s2  | s2 | s2  |
+--------+----+----+-----+----+-----+-----+------+----+-----+
| iOS 16 |    | ZZ |     | ZZ | YY  | s2  |  s2  | s2 | s2  |
+--------+----+----+-----+----+-----+-----+------+----+-----+
| iOS 17 |    | ZZ |     |    |     | s2  |  s2  | s2 |     |
+--------+----+----+-----+----+-----+-----+------+----+-----+

We start by looking for these two instructions:

+---------------------+
| lsr xN, xN, 0xc     |
| stur wN, [xM, -0xc] |
+---------------------+

Where N < 16 and M >= 16.

In r2:

/x 00fc4cd300421fb8:10feffff10feffff

After that, we search for a "str wT, [xM]" (same base register, offset 0) within 20 instructions.
We expect one of the two following sequences there:

+----------------+
| str wT, [xM]   |
| ldr wS, [xM]   |
| tbz wS, 0, ... |
+----------------+
| str wT, [xM]   |
| bl ...         |
| ldr wS, [xM]   |
| tbz wS, 0, ... |
+----------------+

Where S < 16.

Right after that, devices with TZ1 have another block with the same base register but offset 4:

+-----------------+
| str wT, [xM, 4] |
| ldr wS, [xM, 4] |
| tbz wS, 0, ...  |
+-----------------+
| str wT, [xM, 4] |
| bl ...         |
| ldr wS, [xM, 4] |
| tbz wS, 0, ...  |
+-----------------+

Again with S < 16.

We NOP out the str, ldr and tbz in both blocks.

*/

sym antitrust
    mov x2, x0 // instr
    mov w7, 0xfffffe10
    mov w8, 0xd34c0000 // lsr xN, xN, 0xc
    movk w8, 0xfc00
    mov w9, 0xb81f0000 // stur wN, [xM, -0xc]
    movk w9, 0x4200
    // Search for pattern
1:
    ldr w3, [x2], 0x4
    and w4, w3, w7
    cmp w4, w8
    b.ne 1b

    bfi w9, w3, 0, 5
    ldr w3, [x2]
    and w4, w3, 0xfffffe1f
    cmp w4, w9
    b.ne 1b

    // Search for "str wT, [xM]"
    and w7, w3, 0x3e0
    movk w7, 0xb900, lsl 16 // str wT, [xM]
    add x3, x2, 0x50
2:
    ldr w5, [x2, 0x4]!
    and w4, w5, 0xffffffe0
    cmp w4, w7
    b.eq 3f
    cmp x2, x3
    b.lo 2b
    b . // XXX: fail

3:
    // Patch 1st write
    mov w10, 0xd5030000 // nop
    movk w10, 0x201f
    str w10, [x2]

    // Check for bl
    ldr w3, [x2, 0x4]!
    ubfx w4, w3, 26, 6
    cmp w4, 0x25 // bl
    b.ne 4f
    ldr w3, [x2, 0x4]!

4:
    // 1s load
    orr w7, w7, 0x00400000 // str to ldr
    and w4, w3, 0xfffffff0
    cmp w4, w7
    b.ne . // XXX: fail
    // Patch 1st load
    str w10, [x2]

    // 1s tbz
    mov w8, 0x36000000 // tbz wS, 0, ...
    bfi w8, w3, 0, 5
    ldr w3, [x2, 0x4]!
    and w3, w3, 0xfffc001f
    cmp w3, w8
    b.ne . // XXX: fail
    // Patch 1st tbz
    str w10, [x2]

    // Check for 2nd set of str, ldr, tbz
    orr w5, w5, 0x400 // [xM] to [xM, 4]
    ldr w3, [x2, 0x4]!
    cmp w3, w5
    b.ne Ligma
    // Patch 2nd write
    str w10, [x2]

    // Check for bl
    ldr w3, [x2, 0x4]!
    ubfx w4, w3, 26, 6
    cmp w4, 0x25 // bl
    b.ne 5f
    ldr w3, [x2, 0x4]!

5:
    // 2nd load
    orr w7, w7, 0x400 // [xM] to [xM, 4]
    and w4, w3, 0xfffffff0
    cmp w4, w7
    b.ne . // XXX: fail
    // Patch
    str w10, [x2]

    // 2nd tbz
    bfi w8, w3, 0, 5
    ldr w3, [x2, 0x4]!
    and w3, w3, 0xfffc001f
    cmp w3, w8
    b.ne . // XXX: fail
    // Patch
    str w10, [x2]

Ligma:
    ret
