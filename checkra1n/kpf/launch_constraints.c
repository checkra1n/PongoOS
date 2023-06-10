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
#include <stdint.h>
#include <string.h>

static bool need_launch_constraints_patch = false;

static bool kpf_launch_constraints_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    uint32_t adrp = opcode_stream[0],
             add  = opcode_stream[1];
    const char *str = (const char *)(((uint64_t)(opcode_stream) & ~0xfffULL) + adrp_off(adrp) + ((add >> 10) & 0xfff));
    if(strcmp(str, "AMFI: Validation Category info: current %s (%d) parent %s (%d) responsible %s (%d) launch type %d\n") != 0)
    {
        return false;
    }

    static bool found_launch_constraints = false;
    if(found_launch_constraints)
    {
        panic("kpf_launch_constraints: Found twice");
    }
    found_launch_constraints = true;

    uint32_t *stp = find_prev_insn(opcode_stream, 0x100, 0xa9007bfd, 0xffc07fff); // stp x29, x30, [sp, ...]
    if(!stp)
    {
        panic_at(opcode_stream, "kpf_launch_constraints: Failed to find stack frame");
    }

    uint32_t *start = find_prev_insn(stp, 10, 0xa98003e0, 0xffc003e0); // stp xN, xM, [sp, ...]!
    if(!start)
    {
        start = find_prev_insn(stp, 10, 0xd10003ff, 0xffc003ff); // sub sp, sp, ...
        if(!start)
        {
            panic_at(stp, "kpf_launch_constraints: Failed to find start of function");
        }
    }

    start[0] = 0x52800000; // mov w0, 0
    start[1] = RET;

    puts("KPF: Found launch constraints");
    return true;
}

static void kpf_launch_constraints_patch(xnu_pf_patchset_t *patchset)
{
    // Disable launch constraints.
    // We just match against a log string, seek to the start of the function, and make it return 0.
    uint64_t matches[] =
    {
        0x90000000, // adrp x0, ...
        0x91000000, // add x0, x0, ...
        0xf90003f0, // str x{16-31}, [sp]
        0x94000000, // bl IOLog
    };
    uint64_t masks[] =
    {
        0x9f00001f,
        0xffc003ff,
        0xfffffff0,
        0xfc000000,
    };
    xnu_pf_maskmatch(patchset, "launch_constraints", matches, masks, sizeof(matches)/sizeof(uint64_t), true, (void*)kpf_launch_constraints_callback);
}

static void kpf_launch_constraints_init(struct mach_header_64 *hdr, xnu_pf_range_t *cstring, checkrain_option_t kpf_flags, checkrain_option_t checkra1n_flags)
{
    const char constraints_string[] = "mac_proc_check_launch_constraints";
    const char *constraints_string_match = memmem(cstring->cacheable_base, cstring->size, constraints_string, sizeof(constraints_string));

#ifdef DEV_BUILD
    // 16.0 beta 1 onwards
    if((constraints_string_match != NULL) != (gKernelVersion.darwinMajor >= 22))
    {
        panic("Launch constraints presence doesn't match expected Darwin version");
    }
#endif

    need_launch_constraints_patch = constraints_string_match != NULL;
}

static void kpf_launch_constraints_patches(xnu_pf_patchset_t *amfi_text_exec_patchset)
{
    if(need_launch_constraints_patch) // iOS 16+ only
    {
        kpf_launch_constraints_patch(amfi_text_exec_patchset);
    }
}

kpf_component_t kpf_launch_constraints =
{
    .init = kpf_launch_constraints_init,
    .patches =
    {
        { "com.apple.driver.AppleMobileFileIntegrity", "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_launch_constraints_patches },
        {},
    },
};
