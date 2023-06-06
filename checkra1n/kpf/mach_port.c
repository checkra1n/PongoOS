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
    }
    else
    {
        // Don't follow branch
        *patchpoint = NOP;
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

static bool found_task_conversion_eval_ldr = false;
static bool found_task_conversion_eval_bl  = false;
static bool found_task_conversion_eval_imm = false;

static bool kpf_task_conversion_eval_callback_ldr(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    uint32_t * const orig = opcode_stream;
    uint32_t lr1 = opcode_stream[0],
             lr2 = opcode_stream[2];
    // Step 2
    // Make sure that the registers used in tbz are the ones actually
    // loaded by ldr, and that both ldr's use the same offset.
    if((lr1 & 0x1f) != (opcode_stream[1] & 0x1f) || (lr2 & 0x1f) != (opcode_stream[3] & 0x1f) || (lr1 & 0x3ffc00) != (lr2 & 0x3ffc00))
    {
        panic_at(orig, "kpf_task_conversion_eval: opcode check failed");
    }
    if(found_task_conversion_eval_bl || found_task_conversion_eval_imm)
    {
        panic_at(orig, "kpf_task_conversion_eval: found both bl/imm and ldr");
    }
    found_task_conversion_eval_ldr = true;

    // Step 3
    // Search backwards for the check "caller == victim".
    // If this is the case, then XNU always allows conversion, so we patch that to always be true.
    // Since this function can be inlined in a lot of different places, our search needs to be quite resilient.
    // Therefore, we start by noting which registers our ldr's above load, and keep track of which registers
    // are moved to which other registers while going backwards, since the check will almost certainly use
    // different registers. We also search for this instruction pattern:
    //
    // cmp xN, xM
    // ccmp xR, xT, {0|4}, ne   -- (optional)
    // ubfm ...                 -- (optional)
    // adrp ...                 -- (optional)
    // b.{eq|ne} ...
    //
    // Where either the cmp or ccmp registers must correspond to ours.
    // We simply patch the first check to always succeed.
    uint32_t regs = (1 << ((lr1 >> 5) & 0x1f)) | (1 << ((lr2 >> 5) & 0x1f));
    for(size_t i = 0; i < 128; ++i) // arbitrary limit
    {
        uint32_t op = *--opcode_stream;
        if((op & 0xffe0fc1f) == 0xeb00001f) // cmp xN, xM
        {
            uint32_t n1 = opcode_stream[1],
                     n2 = opcode_stream[2];
            size_t idx = 2;
            if((n2 & 0x7f800000) == 0x53000000) // ubfm
            {
                n2 = opcode_stream[++idx];
            }
            if((n2 & 0x9f000000) == 0x90000000) // adrp
            {
                n2 = opcode_stream[++idx];
            }
            if
            (
                // Simple case: just cmp + b.{eq|ne}
                (((n1 & 0xff00001e) == 0x54000000) && ((regs & (1 << ((op >> 5) & 0x1f))) != 0 && (regs & (1 << ((op >> 16) & 0x1f))) != 0)) ||
                // Complex case: cmp + ccmp + b.{eq|ne}
                (
                    (n1 & 0xffe0fc1b) == 0xfa401000 && (n2 & 0xff00001e) == 0x54000000 &&
                    (
                        ((regs & (1 << ((op >> 5) & 0x1f))) != 0 && (regs & (1 << ((op >> 16) & 0x1f))) != 0) ||
                        ((regs & (1 << ((n1 >> 5) & 0x1f))) != 0 && (regs & (1 << ((n1 >> 16) & 0x1f))) != 0)
                    )
                )
            )
            {
                *opcode_stream = 0xeb1f03ff; // cmp xzr, xzr
                puts("KPF: Found task_conversion_eval");
                return true;
            }
        }
        else if((op & 0xffe0ffe0) == 0xaa0003e0) // mov xN, xM
        {
            uint32_t src = (op >> 16) & 0x1f,
                     dst = op & 0x1f;
            regs |= ((regs >> dst) & 1) << src;
        }
    }
    panic_at(orig, "kpf_task_conversion_eval: failed to find cmp");
}

static bool kpf_task_conversion_eval_callback_common(uint32_t *opcode_stream, bool can_double_match)
{
    if(found_task_conversion_eval_ldr)
    {
        panic_at(opcode_stream, "kpf_task_conversion_eval: found both ldr and bl/imm");
    }

    static uint32_t *last_match = NULL;
    for(size_t i = 0; i < 0x48; ++i)
    {
        uint32_t *ldr = opcode_stream - i;
        // Already matched and patched
        if(can_double_match && ldr == last_match)
        {
            return false;
        }

        // Find ldr/cmp pattern
        if
        (!(
            (
                (ldr[0] == NOP && (ldr[1] & 0xff000000) == 0x58000000) // nop + ldr
                ||
                ((ldr[0] & 0x9f000000) == 0x90000000 && (ldr[1] & 0xffc003e0) == (0xf9400000 | ((ldr[0] & 0x1f) << 5))) // adrp + ldr
            )
            &&
            ((ldr[2] & 0xffe0ffff) == (0xeb00001f | ((ldr[1] & 0x1f) << 5))) // cmp
        ))
        {
            continue;
        }

        size_t idx = 3;
        if((ldr[idx] & 0xffe0fc1b) == 0xfa401000) // ccmp {eq|ne}
        {
            ++idx;
        }
        if((ldr[idx] & 0xff00001e) != 0x54000000) // b.{eq|ne}
        {
            panic_at(ldr, "kpf_task_conversion_eval: no b.{eq|ne} after cmp/ccmp?");
        }

        // Subsequent matches would fail to patch
        if(can_double_match)
        {
            last_match = opcode_stream;
        }
        ldr[2] = 0xeb1f03ff; // cmp xzr, xzr

        puts("KPF: Found task_conversion_eval");
        return true;
    }
    panic_at(opcode_stream, "kpf_task_conversion_eval: failed to find ldr of kernel_task");
}

static bool kpf_task_conversion_eval_callback_bl(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    uint32_t bl1 = opcode_stream[1],
             bl2 = opcode_stream[4];
    // Only match if funcs are the same
    uint32_t *f1 = opcode_stream + 1 + sxt32(bl1, 26), // uint32 takes care of << 2
             *f2 = opcode_stream + 4 + sxt32(bl2, 26); // uint32 takes care of << 2
    if(f1 != f2)
    {
        return false;
    }
    // Search for bitfield marker in target function. We can be quite restrictive here
    // because if this doesn't match, then nothing will and we'll get a KPF panic.
    // Also make sure we don't seek past the end of any function here.
    for(size_t i = 0; i < 48; ++i)
    {
        uint32_t op = f1[i];
        if(op == RET)
        {
            return false;
        }
        if(op == 0x530a2900) // ubfx w0, w8, 0xa, 1
        {
            found_task_conversion_eval_bl = true;
            return kpf_task_conversion_eval_callback_common(opcode_stream, false);
        }
    }
    return false;
}

static bool kpf_task_conversion_eval_callback_imm(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    found_task_conversion_eval_imm = true;
    return kpf_task_conversion_eval_callback_common(opcode_stream, true);
}

static void kpf_task_conversion_eval_patch(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    // This patch is here to allow the usage of the extracted tfp0 port from userland (see https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/#the-platform-binary-mitigation)
    // The task_conversion_eval function is often inlinded tho and because of that we need to find it across the kernel.
    // There is this line in the functon: if ((victim->t_flags & TF_PLATFORM) && !(caller->t_flags & TF_PLATFORM)) {
    // Which compiles to a very recognisable sequence of instructions that we match against (step 1). We do some sanity
    // checks (step 2) and then seek backwards from there to the check for "caller == victim" and make it always true.
    // Example from an iPhone 7 13.3:
    //
    // 0xfffffff00713dca4      3a2f00d0       adrp x26, sym.___stack_chk_guard
    // 0xfffffff00713dca8      5a233b91       add x26, x26, 0xec8
    // 0xfffffff00713dcac      392f00f0       adrp x25, 0xfffffff007724000
    // 0xfffffff00713dcb0      f5260310       adr x21, 0xfffffff00714418c
    // 0xfffffff00713dcb4      1f2003d5       nop
    // 0xfffffff00713dcb8      963640f9       ldr x22, [x20, 0x68]
    // 0xfffffff00713dcbc      08a747f9       ldr x8, [x24, 0xf48]
    // 0xfffffff00713dcc0      9f0316eb       cmp x28, x22                    <- Step 3: find this and patch it into cmp xzr, xzr
    // 0xfffffff00713dcc4      04115cfa       ccmp x8, x28, 4, ne
    // 0xfffffff00713dcc8      60010054       b.eq 0xfffffff00713dcf4
    // 0xfffffff00713dccc      df0200f1       cmp x22, 0
    // 0xfffffff00713dcd0      041156fa       ccmp x8, x22, 4, ne
    // 0xfffffff00713dcd4      c0060054       b.eq 0xfffffff00713ddac
    // 0xfffffff00713dcd8      218f47f9       ldr x1, [x25, 0xf18]
    // 0xfffffff00713dcdc      e00316aa       mov x0, x22
    // 0xfffffff00713dce0      4e0a0194       bl 0xfffffff007180618
    // 0xfffffff00713dce4      c8ba43b9       ldr w8, [x22, 0x3b8]            <- Step 1: find this sequence
    // 0xfffffff00713dce8      68005036       tbz w8, 0xa, 0xfffffff00713dcf4 <- Step 2: verify that the register is the same
    // 0xfffffff00713dcec      88bb43b9       ldr w8, [x28, 0x3b8]            <- Step 2: verify that the offset is the same
    // 0xfffffff00713dcf0      e8055036       tbz w8, 0xa, 0xfffffff00713ddac <- Step 2: same here
    // 0xfffffff00713dcf4      81d038d5       mrs x1, tpidr_el1
    // 0xfffffff00713dcf8      c82e4039       ldrb w8, [x22, 0xb]
    // 0xfffffff00713dcfc      1f890071       cmp w8, 0x22
    // 0xfffffff00713dd00      41070054       b.ne 0xfffffff00713dde8
    //
    // to find this with r2 run the following cmd:
    // /x 000040b900005036000040b900005036:0000c0ff0000f8ff0000c0ff0000f8fe
    uint64_t matches[] =
    {
        0xb9400000, // ldr x*, [x*]
        0x36500000, // tbz w*, 0xa, *
        0xb9400000, // ldr x*, [x*]
        0x36500000, // tbz w*, 0xa, *
    };
    uint64_t masks[] =
    {
        0xffc00000,
        0xfff80000,
        0xffc00000,
        0xfef80000, // match both tbz or tbnz
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "task_conversion_eval", matches, masks, sizeof(matches)/sizeof(uint64_t), false, (void*)kpf_task_conversion_eval_callback_ldr);

    // iOS 15.7.1 made this a whole lot more annoying because the flag check was moved to its own function.
    // Finding this in all inlined places is agony.
    //
    // 0xfffffff007193654      e00301aa       mov x0, xN
    // 0xfffffff007193658      dba30094       bl task_get_platform_binary
    // 0xfffffff00719365c      80fcff34       cbz w0, 0x...
    // 0xfffffff007193660      e00313aa       mov x0, x{16-31}
    // 0xfffffff007193664      d8a30094       bl task_get_platform_binary
    // 0xfffffff007193668      20fcff35       cb(n)z w0, 0x...
    //
    // /x e00300aa0000009400000034e00310aa0000009400000034:ffffe0ff000000fc1f0000fffffff0ff000000fc1f0000fe
    uint64_t matches_alt[] =
    {
        0xaa0003e0, // mov x0, xN
        0x94000000, // bl 0x{same}
        0x34000000, // cbz w0, 0x...
        0xaa1003e0, // mov x0, x{16-31}
        0x94000000, // bl 0x{same}
        0x34000000, // cb(n)z w0, 0x...
    };
    uint64_t masks_alt[] =
    {
        0xffe0ffff,
        0xfc000000,
        0xff00001f,
        0xfff0ffff,
        0xfc000000,
        0xfe00001f,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "task_conversion_eval", matches_alt, masks_alt, sizeof(matches_alt)/sizeof(uint64_t), false, (void*)kpf_task_conversion_eval_callback_bl);

    // In addition to the above "bl" case, there are also places where the calls to task_get_platform_binary were inlined.
    // Some kernels (tvOS and audioOS on 16.1+) only contain such matches.
    //
    // 0xfffffff00719f1ac      10260012       and w16, w16, 0x3ff
    // 0xfffffff00719f1b0      1f160071       cmp w16, 5
    // 0xfffffff00719f1b4      21050054       b.ne 0xfffffff00719f258
    // 0xfffffff00719f1b8      100540f9       ldr x16, [x8, 8]
    // 0xfffffff00719f1bc      1f0201eb       cmp x16, x1
    // 0xfffffff00719f1c0      01040054       b.ne 0xfffffff00719f240
    // 0xfffffff00719f1c4      08e54139       ldrb w8, [x8, 0x79]
    // 0xfffffff00719f1c8      88031036       tbz w8, 2, 0xfffffff00719f238
    //
    // /x 002400121f14007101000054000440f91f0000eb010000540004403900001036:00fcffff1ffcffff1f0000ff00fcffff1ffce0ff1f0000ff0004c0ff0000f8fe
    uint64_t matches_imm[] =
    {
        0x12002400, // and w*, w*, 0x3ff
        0x7100141f, // cmp w*, 5
        0x54000001, // b.ne 0x...
        0xf9400400, // ldr x*, [x*, 0x...]
        0xeb00001f, // cmp x*, x*
        0x54000001, // b.ne 0x...
        0x39400400, // ldrb w*, [x*, 0x... & 0x1]
        0x36100000, // tbz w*, 2, 0x...
    };
    uint64_t masks_imm[] =
    {
        0xfffffc00,
        0xfffffc1f,
        0xff00001f,
        0xfffffc00,
        0xffe0fc1f,
        0xff00001f,
        0xffc00400,
        0xfef80000,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "task_conversion_eval", matches_imm, masks_imm, sizeof(matches_imm)/sizeof(uint64_t), false, (void*)kpf_task_conversion_eval_callback_imm);
}

static void kpf_mach_port_init(struct mach_header_64 *hdr, xnu_pf_range_t *cstring, checkrain_option_t kpf_flags, checkrain_option_t checkra1n_flags)
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
    kpf_task_conversion_eval_patch(xnu_text_exec_patchset);
}

static void kpf_mach_port_finish(struct mach_header_64 *hdr, checkrain_option_t *checkra1n_flags)
{
    if(need_convert_port_to_map_patch && !found_convert_port_to_map)
    {
        panic("Missing patch: convert_port_to_map");
    }
    // TODO: Some kernels only contain one type of match, but some contain both bl and imm.
    //       For those, we have no reliably way to detect whether we matches all locations we need.
    if(!found_task_conversion_eval_ldr && !found_task_conversion_eval_bl && !found_task_conversion_eval_imm)
    {
        panic("Missing patch: task_conversion_eval");
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
