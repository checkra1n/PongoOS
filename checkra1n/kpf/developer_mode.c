/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2023 checkra1n team
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
#include <pongo.h>
#include <xnu/xnu.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool need_developer_mode_patch = false;

static bool kpf_developer_mode_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    static uint32_t *enable_developer_mode  = NULL,
                    *disable_developer_mode = NULL;

    const char enable[]  = "AMFI: Enabling developer mode since ",
               disable[] = "AMFI: Disable developer mode since ";

    uint32_t adrp = opcode_stream[0],
             add  = opcode_stream[1];
    const char *str = (const char *)(((uint64_t)(opcode_stream) & ~0xfffULL) + adrp_off(adrp) + ((add >> 10) & 0xfff));
    // Enable
    if(strncmp(str, enable, sizeof(enable) - 1) == 0)
    {
        uint32_t *func = follow_call(opcode_stream + 3);
        if(enable_developer_mode)
        {
            if(enable_developer_mode != func)
            {
                panic("kpf_developer_mode: Found multiple enable candidates");
            }
            return false;
        }
        enable_developer_mode = func;
    }
    // Disable
    else if(strncmp(str, disable, sizeof(disable) - 1) == 0)
    {
        uint32_t *func = follow_call(opcode_stream + 3);
        if(disable_developer_mode)
        {
            if(disable_developer_mode != func)
            {
                panic("kpf_developer_mode: Found multiple disable candidates");
            }
            return false;
        }
        disable_developer_mode = func;
    }
    // Ignore the rest
    else
    {
        return false;
    }

    // Only return success once we found both enable and disable
    if(!enable_developer_mode || !disable_developer_mode)
    {
        return false;
    }

    // Now that we have both, just redirect disable to enable :P
    disable_developer_mode[0] = 0x14000000 | ((enable_developer_mode - disable_developer_mode) & 0x03ffffff); // uint32 takes care of >> 2

    puts("KPF: Found developer mode");
    return true;
}

static void kpf_developer_mode_patch(xnu_pf_patchset_t *amfi_text_exec_patchset)
{
    // Force developer mode on.
    // Find calls to enable_developer_mode and disable_developer_mode in AMFI,
    // dereference the latter and patch it to call the former instead.
    // Same match on both callsites, just with different strings:
    //
    // 0xfffffff0056f9820      40b9ff90       adrp x0, string@PAGE
    // 0xfffffff0056f9824      00442b91       add x0, x0, string@PAGEOFF
    // 0xfffffff0056f9828      29650094       bl IOLog
    // 0xfffffff0056f982c      99660094       bl (en|dis)able_developer_mode
    //
    // /x 00000090000000910000009400000094:1f00009fff03c0ff000000fc000000fc
    uint64_t matches[] =
    {
        0x90000000,
        0x91000000,
        0x94000000,
        0x94000000,
    };
    uint64_t masks[] =
    {
        0x9f00001f,
        0xffc003ff,
        0xfc000000,
        0xfc000000,
    };
    xnu_pf_maskmatch(amfi_text_exec_patchset, "developer_mode", matches, masks, sizeof(matches)/sizeof(uint64_t), true, (void*)kpf_developer_mode_callback);
}

static void kpf_developer_mode_init(struct mach_header_64 *hdr, xnu_pf_range_t *cstring, checkrain_option_t kpf_flags, checkrain_option_t checkra1n_flags)
{
    struct mach_header_64 *amfi = xnu_pf_get_kext_header(hdr, "com.apple.driver.AppleMobileFileIntegrity");
    xnu_pf_range_t *amfi_cstring = xnu_pf_section(amfi, "__TEXT", "__cstring");
    xnu_pf_range_t *range = amfi_cstring ? amfi_cstring : cstring;

    const char dev_mode_string[] = "AMFI: developer mode is force enabled\n";
    const char *dev_mode_string_match = memmem(range->cacheable_base, range->size, dev_mode_string, sizeof(dev_mode_string));

    if(amfi_cstring)
    {
        free(amfi_cstring);
    }

#ifdef DEV_BUILD
    // 16.0 beta 1 onwards
    if((dev_mode_string_match != NULL) != (gKernelVersion.darwinMajor >= 22) && xnu_platform() == PLATFORM_IOS)
    {
        panic("Developer mode doesn't match expected XNU version");
    }
#endif

    need_developer_mode_patch = dev_mode_string_match != NULL;
}

static void kpf_developer_mode_patches(xnu_pf_patchset_t *amfi_text_exec_patchset)
{
    if(need_developer_mode_patch) // iOS 16+ only
    {
        kpf_developer_mode_patch(amfi_text_exec_patchset);
    }
}

kpf_component_t kpf_developer_mode =
{
    .init = kpf_developer_mode_init,
    .patches =
    {
        { "com.apple.driver.AppleMobileFileIntegrity", "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_developer_mode_patches },
        {},
    },
};
