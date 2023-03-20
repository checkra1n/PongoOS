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
#include <xnu/xnu.h>

static bool need_convert_port_to_map_patch = false;
static bool found_convert_port_to_map = false;

static bool kpf_convert_port_to_map_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    // Only once
    if(found_convert_port_to_map)
    {
        panic("kpf_convert_port_to_map: Found twice");
    }
    found_convert_port_to_map = true;

    uint32_t *patchpoint = opcode_stream + 7;
    uint32_t op = *patchpoint;
    if(op & 1) // is b.ne
    {
        // Follow branch (convert to b.al)
        *patchpoint = op | 0xf;
        patchpoint += sxt32(op >> 5, 19); // uint32 takes care of << 2
    }
    else
    {
        // Don't follow branch
        *patchpoint = NOP;
        // Continue at next instr
        ++patchpoint;
    }

    // New in iOS 15: zone_require just to annoy us
    bool have_zone_require = (patchpoint[0] & 0xfffffe1f) == 0x52800000 &&  // movz w0, {0-15}
                             (patchpoint[1] & 0xffffe0ff) == 0x52800001 &&  // movz w1, {0x0-0x100 with granularity 8}
                             (patchpoint[2] & 0xfc000000) == 0x94000000;    // bl zone_require
#ifdef DEV_BUILD
    // 15.0 beta 2 through 15.3 final, and then again 16.4 beta 1 onwards
    if(have_zone_require != ((gKernelVersion.xnuMajor > 7938 && gKernelVersion.xnuMajor < 8020) || gKernelVersion.xnuMajor > 8792))
    {
        panic_at(patchpoint, "kpf_convert_port_to_map: zone_require doesn't match expected XNU version");
    }
#endif
    if(have_zone_require)
    {
        patchpoint[2] = NOP;
    }

    puts("KPF: Found convert_port_to_map");
    return true;
}

static void kpf_convert_port_to_map_patch(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    // This patch is required because in some iOS 14.0 beta, Apple started cracking down on tfp0 usage.
    // In particular, convert_port_to_map_with_flavor will be called when a `vm_map_t` is required for
    // write operations, and that function will panic if the map is backed by the kernel_pmap:
    //
    // panic(cpu 4 caller 0xfffffff007a3a57c): "userspace has control access to a "
    // "kernel map 0xfffffff0ec61a320 through task 0xffffffe19bad64f0"
    //
    // Example from N69 14.0GM kernel:
    //
    // 0xfffffff00713db84      f50301aa       mov x21, x1
    // 0xfffffff00713db88      3f080071       cmp w1, 2
    // 0xfffffff00713db8c      c0020054       b.eq 0xfffffff00713dbe4
    // 0xfffffff00713db90      bf060071       cmp w21, 1
    // 0xfffffff00713db94      e0000054       b.eq 0xfffffff00713dbb0
    // 0xfffffff00713db98      d5020035       cbnz w21, 0xfffffff00713dbf0
    // 0xfffffff00713db9c      21008052       mov w1, 1
    // 0xfffffff00713dba0      97fcff97       bl 0xfffffff00713cdfc
    // 0xfffffff00713dba4      f30300aa       mov x19, x0
    // 0xfffffff00713dba8      a00000b5       cbnz x0, 0xfffffff00713dbbc
    // 0xfffffff00713dbac      11000014       b 0xfffffff00713dbf0
    // 0xfffffff00713dbb0      acfdff97       bl 0xfffffff00713d260
    // 0xfffffff00713dbb4      f30300aa       mov x19, x0
    // 0xfffffff00713dbb8      c00100b4       cbz x0, 0xfffffff00713dbf0
    // 0xfffffff00713dbbc      681640b9       ldr w8, [x19, 0x14]
    // 0xfffffff00713dbc0      c8010034       cbz w8, 0xfffffff00713dbf8
    // 0xfffffff00713dbc4      741640f9       ldr x20, [x19, 0x28]
    // 0xfffffff00713dbc8      802640f9       ldr x0, [x20, 0x48]
    // 0xfffffff00713dbcc      1f2003d5       nop
    // 0xfffffff00713dbd0      c8eeb658       ldr x8, sym._kernel_pmap
    // 0xfffffff00713dbd4      1f0008eb       cmp x0, x8
    // 0xfffffff00713dbd8      80010054       b.eq 0xfffffff00713dc08
    //
    // Example from 15.4:
    //
    // 0xfffffff007887b84      e00313aa       mov x0, x19
    // 0xfffffff007887b88      e10315aa       mov x1, x21
    // 0xfffffff007887b8c      e20314aa       mov x2, x20
    // 0xfffffff007887b90      62fcff97       bl 0xfffffff007886d18
    // 0xfffffff007887b94      00feffb4       cbz x0, 0xfffffff007887b54
    // 0xfffffff007887b98      08504039       ldrb w8, [x0, 0x14]
    // 0xfffffff007887b9c      c8fdff34       cbz w8, 0xfffffff007887b54
    // 0xfffffff007887ba0      141440f9       ldr x20, [x0, 0x28]
    // 0xfffffff007887ba4      882240f9       ldr x8, [x20, 0x40]
    // 0xfffffff007887ba8      a9eaffd0       adrp x9, 0xfffffff0075dd000
    // 0xfffffff007887bac      29e544f9       ldr x9, [x9, 0x9c8]
    // 0xfffffff007887bb0      1f0109eb       cmp x8, x9
    // 0xfffffff007887bb4      c0000054       b.eq 0xfffffff007887bcc
    //
    // We look for the last 8 instructions then follow b.ne or nop b.eq.
    //
    // r2 masked search:
    // /x 0000403900000034000040f9002040f900000090000040f91f0000eb00000054:0000c07f000000ff00c0ffff00f8ffff0000009f0000c0ff1ffce0ff1e0000ff
    // or
    // /x 0000403900000034000040f9002040f91f2003d5000000581f0000eb00000054:0000c07f000000ff00c0ffff00f8ffffffffffff000000ff1ffce0ff1e0000ff
    uint64_t matches[] =
    {
        0x39400000, // ldr(b) wN, [xM, ...]
        0x34000000, // cbz
        0xf9400000, // ldr xN, [xM, {0x0-0x78}]
        0xf9402000, // ldr xN, [xM, {0x40|0x48}]
        0x90000000, // adrp
        0xf9400000, // ldr xN, [xM, ...]
        0xeb00001f, // cmp
        0x54000000, // b.ne / b.eq
    };
    uint64_t masks[] =
    {
        0x7fc00000,
        0xff000000,
        0xffffc000,
        0xfffff800,
        0x9f000000,
        0xffc00000,
        0xffe0fc1f,
        0xff00001e,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "convert_port_to_map", matches, masks, sizeof(matches)/sizeof(uint64_t), false, (void*)kpf_convert_port_to_map_callback);

    matches[4] = NOP;
    masks[4] = 0xffffffff;
    matches[5] = 0x58000000; // ldr (literal)
    masks[5] = 0xff000000;
    xnu_pf_maskmatch(xnu_text_exec_patchset, "convert_port_to_map", matches, masks, sizeof(matches)/sizeof(uint64_t), false, (void*)kpf_convert_port_to_map_callback);

    // iOS 15.5 changes the adrp+ldr to an adrp+add:
    //
    // 0xfffffff0071d11b0      08504039       ldrb w8, [x0, 0x14]
    // 0xfffffff0071d11b4      c8fdff34       cbz w8, 0xfffffff0071d116c
    // 0xfffffff0071d11b8      141440f9       ldr x20, [x0, 0x28]
    // 0xfffffff0071d11bc      882240f9       ldr x8, [x20, 0x40]
    // 0xfffffff0071d11c0      293500d0       adrp x9, 0xfffffff007877000
    // 0xfffffff0071d11c4      29e12a91       add x9, x9, 0xab8
    // 0xfffffff0071d11c8      1f0109eb       cmp x8, x9
    // 0xfffffff0071d11cc      c0000054       b.eq 0xfffffff0071d11e4
    //
    // /x 0000403900000034000040f9002040f900000090000000911f0000eb00000054:0000c0ff000000ff00c0ffff00f8ffff0000009f0000c0ff1ffce0ff1e0000ff
    uint64_t matches_variant[] =
    {
        0x39400000, // ldrb wN, [xM, ...]
        0x34000000, // cbz
        0xf9400000, // ldr xN, [xM, {0x0-0x78}]
        0xf9402000, // ldr xN, [xM, {0x40|0x48}]
        0x90000000, // adrp
        0x91000000, // add
        0xeb00001f, // cmp
        0x54000000, // b.ne / b.eq
    };
    uint64_t masks_variant[] =
    {
        0xffc00000,
        0xff000000,
        0xffffc000,
        0xfffff800,
        0x9f000000,
        0xffc00000,
        0xffe0fc1f,
        0xff00001e,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "convert_port_to_map", matches_variant, masks_variant, sizeof(matches_variant)/sizeof(uint64_t), false, (void*)kpf_convert_port_to_map_callback);
}

static void kpf_mach_port_init(xnu_pf_range_t *cstring)
{
    const char kmap_port_string[] = "userspace has control access to a"; // iOS 14 had broken panic strings
    const char *kmap_port_string_match = memmem(cstring->cacheable_base, cstring->size, kmap_port_string, sizeof(kmap_port_string) - 1); // don't match null byte

#ifdef DEV_BUILD
    // 14.0 beta 2 onwards
    if((kmap_port_string_match != NULL) != (gKernelVersion.xnuMajor > 7090))
    {
        panic("convert_to_port panic doesn't match expected XNU version");
    }
#endif

    need_convert_port_to_map_patch = kmap_port_string_match != NULL;
}

static void kpf_mach_port_patches(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    if(need_convert_port_to_map_patch) // iOS 14+ only
    {
        kpf_convert_port_to_map_patch(xnu_text_exec_patchset);
    }
}

static void kpf_mach_port_finish(struct mach_header_64 *hdr)
{
    if(need_convert_port_to_map_patch && !found_convert_port_to_map)
    {
        panic("Missing patch: convert_port_to_map");
    }
}

kpf_component_t kpf_mach_port =
{
    .init = kpf_mach_port_init,
    .finish = kpf_mach_port_finish,
    .patches =
    {
        { NULL, "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_mach_port_patches },
        {},
    },
};
