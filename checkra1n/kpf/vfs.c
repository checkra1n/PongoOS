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
#include <pongo.h>
#include <xnu/xnu.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

static uint64_t vfs_context_current, vnode_lookup, vnode_put;

static bool kpf_vfs_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    static bool found_vfs = false;
    if(found_vfs)
    {
        panic("kpf_vfs: Found twice");
    }
    found_vfs = true;

    uint32_t *try = opcode_stream + 8 + sxt32(opcode_stream[8] >> 5, 19); // uint32 takes care of << 2
    if
    (
        (try[0] & 0xfff0ffff) != 0xaa1003e0 || // mov x0, x{16-31}
        (try[1] & 0xfc000000) != 0x94000000 || // bl sfree
        (try[2] & 0xfff00fff) != 0xf85003a0 || // ldur x0, [x29, -0x...]
        (try[3] & 0xff80001f) != 0xB4000000 || // cbz x0, {forward}
        (try[4] & 0xfc000000) != 0x94000000    // bl vnode_put
    )
    {
        panic_at(opcode_stream, "kpf_vfs: Failed to find vnode_put");
    }

    vfs_context_current = xnu_ptr_to_va(follow_call(opcode_stream + 1));
    vnode_lookup = xnu_ptr_to_va(follow_call(opcode_stream + 6));
    vnode_put = xnu_ptr_to_va(follow_call(try + 4));

    puts("KPF: Found VFS");
    return true;
}

static void kpf_vfs_patches(xnu_pf_patchset_t *sandbox_text_exec_patchset)
{
    // We don't patch anything here, we merely find a bunch of VFS functions.
    // These are exported to other KPF components so that they can be used in shellcode.
    //
    // A neat place that uses the VFS functions we need is in the sandbox kext:
    //
    // 0xfffffff0064fa24c      00020035       cbnz w0, 0xfffffff0064fa28c
    // 0xfffffff0064fa250      24100094       bl vfs_context_current
    // 0xfffffff0064fa254      e30300aa       mov x3, x0
    // 0xfffffff0064fa258      a26300d1       sub x2, x29, 0x18
    // 0xfffffff0064fa25c      e00313aa       mov x0, x19
    // 0xfffffff0064fa260      01008052       mov w1, 0
    // 0xfffffff0064fa264      97100094       bl vnode_lookup
    // 0xfffffff0064fa268      f40300aa       mov x20, x0
    // 0xfffffff0064fa26c      00010035       cbnz w0, 0xfffffff0064fa28c
    //
    // /x 0000003500000094e30300aaa20300d1000000000000000000000094f00300aa00000035:000080ff000000fcffffffffff03c0ff0000000000000000000000fcf0ffffff000080ff
    uint64_t matches[] =
    {
        0x35000000, // cbnz w*, {forward}
        0x94000000, // bl vfs_context_current
        0xaa0003e3, // mov x3, x0
        0xd10003a2, // sub x2, x29, 0x...
        0x00000000, // {mov x0, x{16-31} | mov w1, 0}
        0x00000000, // {mov x0, x{16-31} | mov w1, 0}
        0x94000000, // bl vnode_lookup
        0xaa0003f0, // mov x{16-31}, x0
        0x35000000, // cbnz w*, {forward}
    };
    uint64_t masks[] =
    {
        0xff800000,
        0xfc000000,
        0xffffffff,
        0xffc003ff,
        0x00000000,
        0x00000000,
        0xfc000000,
        0xfffffff0,
        0xff800000,
    };
    // Mark patch as not required - the getters below will panic if needed
    xnu_pf_maskmatch(sandbox_text_exec_patchset, "vfs", matches, masks, sizeof(matches)/sizeof(uint64_t), false, (void*)kpf_vfs_callback);
}

uint64_t kpf_vfs__vfs_context_current(void)
{
    if(!vfs_context_current)
    {
        panic("kpf_vfs: Missing vfs_context_current");
    }
    return vfs_context_current;
}

uint64_t kpf_vfs__vnode_lookup(void)
{
    if(!vnode_lookup)
    {
        panic("kpf_vfs: Missing vnode_lookup");
    }
    return vnode_lookup;
}

uint64_t kpf_vfs__vnode_put(void)
{
    if(!vnode_put)
    {
        panic("kpf_vfs: Missing vnode_put");
    }
    return vnode_put;
}

kpf_component_t kpf_vfs =
{
    .patches =
    {
        { "com.apple.security.sandbox", "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_vfs_patches },
        {},
    },
};
