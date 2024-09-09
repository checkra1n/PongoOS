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
#include "libc_workarounds.h"
#include <stdbool.h>
#include <stdint.h>
#include <pongo.h>

extern _Noreturn void jump_to_image(uint64_t image, uint64_t args, uint64_t tramp);
extern _Noreturn void setup_el1(uint64_t, uint64_t, void * entryp);
extern _Noreturn void main(void* boot_image, void* boot_args);

//volatile void d$demote_patch(void * image);

void iorvbar_yeet(volatile void *boot_image) __asm__("iorvbar_yeet");
void aes_keygen(volatile void *boot_image) __asm__("aes_keygen");
void recfg_yoink(volatile void *boot_image) __asm__("recfg_yoink");
void fuse_jump(volatile void *boot_image) __asm__("fuse_jump");
void antitrust(volatile void *boot_image) __asm__("antitrust");

extern uint8_t need_to_release_L3_SRAM;

// A value large enough to encompass the iBoot TEXT section,
// but small enough to not include the embedded firmware blobs.
// NOTE: Independent definition exists in stage2.
#define SAFE_TEXT_SIZE 0x7ff00

void patch_bootloader(void* boot_image)
{
    strcpy((void*)((uintptr_t)boot_image + 0x200), "Stage2 KJC Loader");

    // Trampoline patch
    bool tramp_done = false;
    for(volatile uint32_t *p = boot_image, *end = (volatile uint32_t*)((uintptr_t)boot_image + SAFE_TEXT_SIZE); p < end; ++p)
    {
        // Start by finding "movz x18, 0"
        if(*p == 0xd2800012)
        {
            // Make it load Pongo's base address instead
            *p = 0xb26107f2; // orr x18, xzr, 0x180000000
            // Now find the next ret
            for(; p < end; ++p)
            {
                if(*p == 0xd65f03c0)
                {
                    tramp_done = true;
                    break;
                }
            }
            if(!tramp_done)
            {
                goto fail;
            }
            // Patch it
            *p = 0xd61f0240; // br x18
            break;
        }
    }
    if(!tramp_done)
    {
        goto fail;
    }

    // Keep L3 SRAM around
    // /x 000040b900781e12000000b9000040b900001032000000b9001440b900000032001400b9:00fcffff00fcffff00fcffff00fcffff00fcffff00fcffff00fcffff00fcffff00fcffff
    for(volatile uint32_t *p = boot_image, *end = (volatile uint32_t*)((uintptr_t)boot_image + SAFE_TEXT_SIZE); p < end; ++p)
    {
        if
        (
            (p[0] & 0xfffffc00) == 0xb9400000 && // ldr wM, [xN]
            (p[1] & 0xfffffc00) == 0x121e7800 && // and wM, wM, 0xfffffffd
            (p[2] & 0xfffffc00) == 0xb9000000 && // str wM, [xN]
            (p[3] & 0xfffffc00) == 0xb9400000 && // ldr wM, [xN]
            (p[4] & 0xfffffc00) == 0x32100000 && // orr wM, wM, 0x10000
            (p[5] & 0xfffffc00) == 0xb9000000 && // str wM, [xN]
            (p[6] & 0xfffffc00) == 0xb9401400 && // ldr wM, [xN, 0x14]
            (p[7] & 0xfffffc00) == 0x32000000 && // orr wM, wM, 1
            (p[8] & 0xfffffc00) == 0xb9001400    // str wM, [xN, 0x14]
        )
        {
            need_to_release_L3_SRAM = 0x41;
            p[0] = 0xd65f03c0; // ret
            break;
        }
    }

    // Cursed fix for this god forsaken bootloader.
    // On A9 and A9X, if the code running between iBootStage1 and iBootStage2 takes more than
    // a given amount of time (1.5s?), then iBootStage2 will fail to initialise the APCIe link.
    // Hell knows why, but it can be fixed by resetting whatever underlying hardware there is,
    // and iBoot already contains the code to do that, but it only uses it in the iBEC profile.
    // So what we do here is find the function that sets the reset flag and patch it to always true.
    // This consists of:
    //  adr x8, 0x...
    //  nop
    //  {orr w9, wzr, 1 | mov w9, 1}
    //  strb w9, [x8]
    //  strb w0, [x8, 1]
    //  ret
    // We just turn the second store into "strb w9, [x8, 1]".
    // /x 080000101f2003d5e90300320901003900050039c0035fd6:1f00009fffffffffffffffffffffffffffffffffffffffff
    // /x 080000101f2003d5290080520901003900050039c0035fd6:1f00009fffffffffffffffffffffffffffffffffffffffff
    for(volatile uint32_t *p = boot_image, *end = (volatile uint32_t*)((uintptr_t)boot_image + SAFE_TEXT_SIZE); p < end; ++p)
    {
        if
        (
            (p[0] & 0x9f00001f) == 0x10000008 &&
             p[1] == 0xd503201f &&
            (p[2] == 0x52800029 || p[2] == 0x320003e9) &&
             p[3] == 0x39000109 &&
             p[4] == 0x39000500 &&
             p[5] == 0xd65f03c0
        )
        {
            p[4] = 0x39000509;
            break;
        }
    }

    // TrustZone patches.
    // We have two of them here, see patches.S for a device/version matrix.
    bool tz_done = false;
    for(volatile uint32_t *p = boot_image, *end = (volatile uint32_t*)((uintptr_t)boot_image + SAFE_TEXT_SIZE); p < end; ++p)
    {
        uint32_t op1 = p[0],
                 op2 = p[1],
                 op3 = p[2];

        // A7 (any version) and A8-A9 (iOS 10 and lower).
        // We look for the following sequence:
        //  str wN, [xM]
        //  ldr wT, [xM]
        //  tbz wT, 0, ...
        //  str wN, [xM, 4]
        //  ldr wS, [xM, 4]
        //  tbz wS, 0, ...
        // On iOS 7 specifically, there is an immediate generated in the middle,
        // and thus the second load and store have no offset:
        //  str wN, [xM]
        //  ldr wT, [xM]
        //  tbz wT, 0, ...
        //  movz xM, 0x200000000
        //  movk xM, 0x914
        //  str wN, [xM]
        //  ldr wS, [xM]
        //  tbz wS, 0, ...
        // We require that T and S are <16, and that the two tbz have positive offset.
        // /x 000000b9000040b900000036000400b9000440b900000036:00fcffff10fcffff0000fcff00fcffff10fcffff0000fcff
        // /x 000000b9000040b9000000364000c0d2802281f2000000b9000040b900000036:00fcffff10fcffff0000fcffe0ffffffe0ffffff00fcffff10fcffff0000fcff
        if((op1 & 0xfffffc00) == 0xb9000000 && (op2 & 0xfffffff0) == ((op1 & 0x000003e0) | 0xb9400000) && (op3 & 0xfffc001f) == ((op2 & 0x0000001f) | 0x36000000))
        {
            volatile uint32_t *one = p,
                              *two = p + 3;
            uint32_t op4 = two[0],
                     op5 = two[1];
            uint32_t imm = 1; // 1 << 2
            if(op4 == (((op1 & 0x000003e0) >> 5) | 0xd2c00040) && op5 == (((op1 & 0x000003e0) >> 5) | 0xf2812280))
            {
                two += 2;
                op4 = two[0];
                op5 = two[1];
                imm = 0;
            }
            if(op4 == ((op1 & 0x000003ff) | (imm << 10) | 0xb9000000) && (op5 & 0xfffffff0) == ((op1 & 0x000003e0) | (imm << 10) | 0xb9400000) && (two[2] & 0xfffc001f) == ((op5 & 0x0000001f) | 0x36000000))
            {
                // Nop them all out.
                one[0] = 0xd503201f;
                one[1] = 0xd503201f;
                one[2] = 0xd503201f;
                two[0] = 0xd503201f;
                two[1] = 0xd503201f;
                two[2] = 0xd503201f;
                tz_done = true;
                break;
            }
        }
        // A9X patch, any version.
        // The reason A9X is separate is because it has two sets of TZ registers
        // rather than just one, which makes for *very* different codegen!
        // The signature sequence we look for is:
        //  add xS, xD, 0x10
        //  orr xN, xM, xS
        //  str wT, [xN]
        // After that, there is a load from xN and a tbz based on bit 0 of the value.
        // Then we have another store, another load, but this time a tbnz because it's a loop.
        // In addition, there can be various other instructions scattered between these.
        // Only the block above seems to reliably get emitted contiguously.
        // /x c84200911a0308aa570300b9:00fcffff00fce0ff00fcffff
        else if((op1 & 0xfffffc00) == 0x91004000 && (op2 & 0xfffffc00) == (((op1 & 0x1f) << 16) | 0xaa000000) && (op3 & 0xffffffe0) == (((op2 & 0x1f) << 5) | 0xb9000000))
        {
            // Within a few instructions, there has to be a load from the same base reg as op3
            uint32_t ins = (op3 & 0x3e0) | 0xb9400000;
            uint32_t op = 0;
            volatile uint32_t *ldr = NULL;
            for(size_t i = 0; i < 4; ++i)
            {
                op = p[3 + i];
                if((op & 0xffffffe0) == ins)
                {
                    ldr = p + 3 + i;
                    break;
                }
            }
            if(!ldr)
            {
                goto fail;
            }
            // NOP the write and turn the load into an immediate move
            p[2] = 0xd503201f;
            *ldr = (op & 0x1f) | 0x52800020;

            // There is another store after this, with the same value register as op3, but possibly a different base register.
            ins = op3 & 0xfffffc1f;
            volatile uint32_t *str = NULL;
            for(size_t i = 1; i <= 8; ++i)
            {
                op = ldr[i];
                if((op & 0xfffffc1f) == ins)
                {
                    str = ldr + i;
                    break;
                }
            }
            if(!str)
            {
                goto fail;
            }
            // And another load like above
            ins = (op & 0x3e0) | 0xb9400000;
            ldr = NULL;
            for(size_t i = 1; i <= 4; ++i)
            {
                op = str[i];
                if((op & 0xffffffe0) == ins)
                {
                    ldr = str + i;
                    break;
                }
            }
            if(!ldr)
            {
                goto fail;
            }
            // Same patch
            *str = 0xd503201f;
            *ldr = (op & 0x1f) | 0x52800020;

            tz_done = true;
            break;
        }
    }

    iorvbar_yeet(boot_image);
    aes_keygen(boot_image);
    // Ultra dirty hack: 16K support = Reconfig Engine
    if(is_16k())
    {
        recfg_yoink(boot_image);
    }
    fuse_jump(boot_image);
    if(!tz_done)
    {
        antitrust(boot_image);
    }
    return;

fail:;
    __asm__ volatile("b ."); // TODO: better fail?
}

/* BSS is cleaned on _start, so we cannot rely on it. */
void* gboot_entry_point = (void*)0xddeeaaddbbeeeeff;
void* gboot_args = (void*)0xddeeaaddbbeeeeff;

_Noreturn void stage3_exit_to_el1_image(void *boot_args, void *boot_entry_point, void *trampoline) {
    if (*(uint8_t*)(gboot_args + 8 + 7)) {
        // kernel
        gboot_args = boot_args;
        gboot_entry_point = boot_entry_point;
    } else {
        // hypv
        *(void**)(gboot_args + 0x20) = boot_args;
        *(void**)(gboot_args + 0x28) = boot_entry_point;
        __asm__ volatile("smc 0"); // elevate to EL3
    }
    jump_to_image((uint64_t)gboot_entry_point, (uint64_t)gboot_args, (uint64_t)trampoline);
}

_Noreturn void trampoline_entry(void* boot_image, void* boot_args)
{
    if (!boot_args) {
        // bootloader
        patch_bootloader(boot_image);
        jump_to_image((uint64_t)boot_image, (uint64_t)boot_args, 0);
    } else {
        gboot_args = boot_args;
        gboot_entry_point = boot_image;
        setup_el1((uint64_t)boot_image, (uint64_t)boot_args, main);
    }
}
