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

void patch_bootloader(void* boot_image)
{
    strcpy((void*)((uintptr_t)boot_image + 0x200), "Stage2 KJC Loader");

    // Trampoline patch
    // Start by finding "movz x18, 0"
    volatile uint32_t *p = boot_image;
    while(*p != 0xd2800012) ++p;
    // Find next ret;
    while(*p != 0xd65f03c0) ++p;
    // Patch it
    p[-1] = 0xb26107f2; // orr x18, xzr, 0x180000000
    p[0] = 0xd61f0240; // br x18

    // Keep L3 SRAM around
    // /x 000040b900781e12000000b9000040b900001032000000b9001440b900000032001400b9:00fcffff00fcffff00fcffff00fcffff00fcffff00fcffff00fcffff00fcffff00fcffff
    for(volatile uint32_t *p = boot_image, *end = (volatile uint32_t*)((uintptr_t)boot_image + 0x7ff00); p < end; ++p)
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

    iorvbar_yeet(boot_image);
    aes_keygen(boot_image);
    // Ultra dirty hack: 16K support = Reconfig Engine
    if(is_16k())
    {
        recfg_yoink(boot_image);
    }
    fuse_jump(boot_image);
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
