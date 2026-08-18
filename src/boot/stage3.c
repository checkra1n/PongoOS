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

    iorvbar_yeet(boot_image);
    aes_keygen(boot_image);
    // Ultra dirty hack: 16K support = Reconfig Engine
    if(is_16k())
    {
        recfg_yoink(boot_image);
    }
    fuse_jump(boot_image);
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
