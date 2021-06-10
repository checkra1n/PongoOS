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

// ********************************************************
// **                                                    **
// ** THIS FILE IS SHARED BETWEEN PONGOOS AND CHECKRA1N! **
// **                                                    **
// **   MAKE SURE ANY EDIT IS REFLECTED IN BOTH REPOS!   **
// **                                                    **
// ********************************************************

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

#ifndef NO_GLOBAL
.globl iorvbar_yeet
iorvbar_yeet:
#else
L_iorvbar_yeet:
#endif
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
    dmb sy
    isb sy
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
| A13  |      ?      |             |
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

#ifndef NO_GLOBAL
.globl aes_keygen
aes_keygen:
#else
L_aes_keygen:
#endif
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
    dmb sy
    isb sy
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

+------+---------------+--------------+---------------+---------------------+-------------------+
| SoC  | AOP_CFG_TABLE | AOP_CFG_LOCK | AOP_SRAM_BASE | AOP_SRAM_LOCK_RANGE | AOP_SRAM_LOCK_SET |
+------+---------------+--------------+---------------+---------------------+-------------------+
| A9   |  0x210000200  |              |  0x210800008  |     0x21000021c     |    0x210000220    |
+------+---------------+--------------+---------------+---------------------+-------------------+
| A9X  |  0x210000200  |              |  0x210800008  |     0x21000021c     |    0x210000220    |
+------+---------------+--------------+---------------+---------------------+-------------------+
| A10  |  0x210000100  |              |  0x210800008  |     0x21000011c     |    0x210000120    |
+------+---------------+--------------+---------------+---------------------+-------------------+
| A10X |  0x210000100  |              |  0x210800008  |     0x21000011c     |    0x210000120    |
+------+---------------+--------------+---------------+---------------------+-------------------+
| T2   |  0x2112c0200  | 0x2112c0214  |               |     0x211000200     |    0x211000204    |
+------+---------------+--------------+---------------+---------------------+-------------------+
| A11  |  0x2352c0200  | 0x2352c0214  |               |     0x235000200     |    0x235000204    |
+------+---------------+--------------+---------------+---------------------+-------------------+
| A12  |  0x23d2c0200  | 0x23d2c0214  |               |     0x23d000200     |    0x23d000204    |
+------+---------------+--------------+---------------+---------------------+-------------------+
| A12X |       ?       |      ?       |               |          ?          |         ?         |
+------+---------------+--------------+---------------+---------------------+-------------------+
| A13  |       ?       |      ?       |               |          ?          |         ?         |
+------+---------------+--------------+---------------+---------------------+-------------------+

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

#ifndef NO_GLOBAL
.globl recfg_yoink
recfg_yoink:
#else
L_recfg_yoink:
#endif
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
    dmb sy
    isb sy
Lul:
    ret

#endif
