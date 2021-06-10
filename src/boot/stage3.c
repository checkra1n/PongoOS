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
#include "libc_workarounds.h"
#include <pongo.h>

extern uint32_t tramp_hook[5];

volatile void jump_to_image(uint64_t image, uint64_t args);
volatile void d$demote_patch(void * image);

void iorvbar_yeet(volatile void *boot_image) __asm__("iorvbar_yeet");
void aes_keygen(volatile void *boot_image) __asm__("aes_keygen");
void recfg_yoink(volatile void *boot_image) __asm__("recfg_yoink");

uint32_t* find_next_insn(uint32_t* from, uint32_t size, uint32_t insn, uint32_t mask)
{
    while (size) {
        if ((*from & mask) == (insn & mask)) {
            return from;
        }
        from++;
        size -= 4;
    }
    return NULL;
}
uint32_t* find_prev_insn(uint32_t* from, uint32_t size, uint32_t insn, uint32_t mask)
{
    while (size) {
        if ((*from & mask) == (insn & mask)) {
            return from;
        }
        from--;
        size -= 4;
    }
    return NULL;
}

extern uint32_t clear_hook_orig_backing[2];
extern uint8_t clear_hook, clear_hook_end;

void patch_bootloader(void* boot_image)
{
    // 1. disable DRAM clear

    uint32_t* sys_3_c7_c4_1 = find_next_insn(boot_image, 0x80000, 0xd50b7423, 0xFFFFFFFF);
    if (sys_3_c7_c4_1) {
        uint32_t* func_prolog = find_prev_insn(sys_3_c7_c4_1, 0x100, 0xaa0103e2, 0xffffffff);
        if (func_prolog) {
            for (int i = 0; i < 2; i++) {
                clear_hook_orig_backing[i] = func_prolog[i];
            }
            memcpy(((void*)0x180 + (uint64_t)boot_image), &clear_hook, &clear_hook_end - &clear_hook);
            int64_t offset = (0x180 + (int64_t)boot_image) - (4 + (int64_t)func_prolog);
            func_prolog[0] = 0xaa1e03e5;
            func_prolog[1] = 0x94000000 | ((((uint64_t)offset) >> 2) & 0x3FFFFFF);
        }
    }
    invalidate_icache();

    // 2. hook trampoline to jump into this again

    uint32_t* tramp = find_next_insn(boot_image, 0x80000, 0xd2800012, 0xFFFFFFFF);
    if (tramp) {
        for (int i = 0; i < 5; i++) {
            tramp[i] = tramp_hook[i];
        }
    }
//    d$demote_patch(boot_image);

    iorvbar_yeet(boot_image);
    aes_keygen(boot_image);
    // Ultra dirty hack: 16K support = Reconfig Engine
    if(is_16k())
    {
        recfg_yoink(boot_image);
    }

    invalidate_icache();
}

/* BSS is cleaned on _start, so we cannot rely on it. */
void* gboot_entry_point = (void*)0xddeeaaddbbeeeeff;
void* gboot_args = (void*)0xddeeaaddbbeeeeff;

void stage3_exit_to_el1_image(void* boot_args, void* boot_entry_point) {
    if (*(uint8_t*)(gboot_args + 8 + 7)) {
        // kernel
        gboot_args = boot_args;
        gboot_entry_point = boot_entry_point;
    } else {
        // hypv
        *(void**)(gboot_args + 0x20) = boot_args;
        *(void**)(gboot_args + 0x28) = boot_entry_point;
        asm("smc #0"); // elevate to EL3
    }
    jump_to_image((uint64_t)gboot_entry_point, (uint64_t)gboot_args);
}

void trampoline_entry(void* boot_image, void* boot_args)
{
    extern uint64_t __bss_start[] __asm__("section$start$__DATA$__common"),
                    __bss_end[] __asm__("segment$end$__DATA");
    if (__bss_start[0] == 0x746F6F626F747561) {
        uint32_t autoboot_sz = (uint32_t)(__bss_start[1]);
        extern volatile void smemcpy128(void*,void*,uint32_t);
        smemcpy128 ((void*)0x818e00000, __bss_start, (autoboot_sz + 64)/16);
        __bss_start[0] = 0;
    }

    if (!boot_args) {
        // bootloader
        strcpy(boot_image + 0x200, "Stage2 KJC Loader");
        patch_bootloader(boot_image);
    } else {

        gboot_args = boot_args;
        gboot_entry_point = boot_image;
        extern volatile void setup_el1(void * entryp,uint64_t,uint64_t);


        extern volatile void smemset(void*, uint8_t, uint64_t);
        smemset(&__bss_start, 0, ((uint64_t)__bss_end) - ((uint64_t)__bss_start));
        extern void main (void);
        setup_el1(main, (uint64_t)boot_image, (uint64_t)boot_args);
    }
    jump_to_image((uint64_t)boot_image, (uint64_t)boot_args);
}
