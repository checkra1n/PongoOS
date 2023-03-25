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
#include <xnu/xnu.h>

static bool need_developer_mode_patch = false;

static bool kpf_developer_mode_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    static bool found_developer_mode = false;
    if(found_developer_mode)
    {
        panic("kpf_developer_mode: Found twice");
    }
    found_developer_mode = true;

    uint32_t *func = follow_call(opcode_stream);
    func[0] = 0x52800020; // mov w0, 1
    func[1] = RET;

    puts("KPF: Found developer mode");
    return true;
}

static void kpf_developer_mode_patch(xnu_pf_patchset_t *amfi_text_exec_patchset)
{
    // Force developer mode on.
    // Find marker, dereference query function, patch it.
    //
    // 0xfffffff0057007c8      af4a0094       bl developer_mode_state
    // 0xfffffff0057007cc      08128052       mov w8, 0x90
    // 0xfffffff0057007d0      8803088a       and x8, x28, x8
    // 0xfffffff0057007d4      c0000037       tbnz w0, 0, 0xfffffff0057007ec
    //
    // /x 00000094081280520002088a00000037:000000fcffffffff00feffff1f00f8ff
    uint64_t matches[] =
    {
        0x94000000, // bl developer_mode_state
        0x52801208, // mov w8, 0x90
        0x8a080200, // and xN, x{16-31}, x8
        0x37000000, // tbnz w0, 0, 0x...
    };
    uint64_t masks[] =
    {
        0xfc000000,
        0xffffffff,
        0xfffffe00,
        0xfff8001f,
    };
    xnu_pf_maskmatch(amfi_text_exec_patchset, "developer_mode", matches, masks, sizeof(matches)/sizeof(uint64_t), true, (void*)kpf_developer_mode_callback);
}

static void kpf_developer_mode_init(struct mach_header_64 *hdr, xnu_pf_range_t *cstring)
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
