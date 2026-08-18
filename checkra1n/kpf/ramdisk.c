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

#include "kpf.h"
#include <kerninfo.h>
#include <pongo.h>
#include <xnu/xnu.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static bool have_ramdisk = false;
static char *rootdev_bootarg = NULL;
static uint32_t *rootdev_patchpoint = NULL;

static bool kpf_rootdev_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    uint32_t adrp = opcode_stream[0],
             add  = opcode_stream[1];
    const char *str = (const char *)(((uint64_t)(opcode_stream) & ~0xfffULL) + adrp_off(adrp) + ((add >> 10) & 0xfff));
    if(strcmp(str, "rootdev") != 0)
    {
        return false;
    }

    // Make sure this is the correct match
    uint32_t *bl = find_next_insn(opcode_stream + 2, 6, 0x94000000, 0xfc000000);
    if(!bl || (bl[1] & 0xff00001f) != 0x35000000 || (bl[2] & 0xfffffe1f) != 0x3900021f) // cbnz w0, ...; strb wzr, [x{16-31}]
    {
        return false;
    }

    if(rootdev_patchpoint)
    {
        panic("kpf_rootdev: Found twice");
    }
    rootdev_patchpoint = opcode_stream;

    puts("KPF: Found rootdev");
    return true;
}

static void kpf_rootdev_patch(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    // A ton of kexts check for "rd=md*" and "rootdev=md*" in order to determine whether we're restoring.
    // We previously tried to patch all of those, but that is really tedious to do, and it's basically
    // impossible to determine whether you found all instances.
    // What we do now is just change the place that actually boots off the ramdisk from "rootdev" to "nootdev",
    // and then patch the boot-args string to reflect that.
    //
    // Because codegen orders function args differently across versions and may or may not inline stuff,
    // we just match adrp+add to either x0 or x1, and check the string and the rest in the callback.
    //
    // /x 0000009000000091:1e00009fde03c0ff
    uint64_t matches[] =
    {
        0x90000000, // adrp x{0|1}, 0x...
        0x91000000, // add x{0|1}, x{0|1}, 0x...
    };
    uint64_t masks[] =
    {
        0x9f00001e,
        0xffc003de,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "rootdev", matches, masks, sizeof(matches)/sizeof(uint64_t), true, (void*)kpf_rootdev_callback);
}

static void kpf_ramdisk_patches(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    if(have_ramdisk)
    {
        kpf_rootdev_patch(xnu_text_exec_patchset);
    }
}

static void kpf_ramdisk_init(struct mach_header_64 *hdr, xnu_pf_range_t *cstring, checkrain_option_t kpf_flags, checkrain_option_t checkra1n_flags)
{
    char *bootargs = (char*)((uintptr_t)gBootArgs->iOS13.CommandLine - 0x800000000 + kCacheableView);
    rootdev_bootarg = strstr(bootargs, "rootdev=");
    if(rootdev_bootarg > bootargs && rootdev_bootarg[-1] != ' ' && rootdev_bootarg[-1] != '\t')
    {
        rootdev_bootarg = NULL;
    }
#ifdef DEV_BUILD
    have_ramdisk = true;
#else
    have_ramdisk = rootdev_bootarg != NULL;
#endif
}

static void kpf_ramdisk_bootprep(struct mach_header_64 *hdr, checkrain_option_t checkra1n_flags)
{
    if(rootdev_bootarg)
    {
        rootdev_bootarg[0] = 'n'; // rootdev -> nootdev
    }

    if(ramdisk_size)
    {
        puts("KPF: Found ramdisk, appending kerninfo");
        uint64_t slide = xnu_slide_value(hdr);

        ramdisk_buf = realloc(ramdisk_buf, ramdisk_size + sizeof(struct kerninfo));
        if(!ramdisk_buf)
        {
            panic("Failed to reallocate ramdisk with kerninfo");
        }

        *(struct kerninfo*)(ramdisk_buf + ramdisk_size) = (struct kerninfo)
        {
            .size  = sizeof(struct kerninfo),
            .base  = slide + 0xfffffff007004000,
            .slide = slide,
            .flags = checkra1n_flags,
        };

        *(uint32_t*)(ramdisk_buf) = ramdisk_size;
        ramdisk_size += sizeof(struct kerninfo);
    }
}

static uint32_t kpf_ramdisk_size(void)
{
    if(!have_ramdisk)
    {
        return 0;
    }
    return 2;
}

static uint32_t kpf_ramdisk_emit(uint32_t *shellcode_area)
{
    if(!have_ramdisk)
    {
        return 0;
    }

    // We emit a new string because it's possible that strings have
    // been merged with kexts, and we don't wanna patch those.
    const char str[] = "nootdev";
    memcpy(shellcode_area, str, sizeof(str));

    uint64_t shellcode_addr  = xnu_ptr_to_va(shellcode_area);
    uint64_t patchpoint_addr = xnu_ptr_to_va(rootdev_patchpoint);

    uint64_t shellcode_page  = shellcode_addr  & ~0xfffULL;
    uint64_t patchpoint_page = patchpoint_addr & ~0xfffULL;

    int64_t pagediff = (shellcode_page - patchpoint_page) >> 12;

    rootdev_patchpoint[0] = (rootdev_patchpoint[0] & 0x9f00001f) | ((pagediff & 0x3) << 29) | (((pagediff >> 2) & 0x7ffff) << 5);
    rootdev_patchpoint[1] = (rootdev_patchpoint[1] & 0xffc003ff) | ((shellcode_addr & 0xfff) << 10);

    return 2;
}

kpf_component_t kpf_ramdisk =
{
    .init = kpf_ramdisk_init,
    .bootprep = kpf_ramdisk_bootprep,
    .shc_size = kpf_ramdisk_size,
    .shc_emit = kpf_ramdisk_emit,
    .patches =
    {
        { NULL, "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_ramdisk_patches },
        {},
    },
};
