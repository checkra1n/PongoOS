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

#if 0
// XXX doesn't work like this, needs new strat

static bool kpf_aprr_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    // We recognise two types of matches here.
    // 1. Loads from thread state of two forms:
    //
    // 0xfffffff007ce9c2c      e8f23cd5       mrs x8, s3_4_c15_c2_7
    // 0xfffffff007ce9c30      a86a02f9       str x8, [x21, 0x4d0]
    // 0xfffffff007ce9c34      686a42f9       ldr x8, [x19, 0x4d0]
    // 0xfffffff007ce9c38      e8f21cd5       msr s3_4_c15_c2_7, x8
    //
    // 0xfffffff007b7ed5c      e9f23cd5       mrs x9, s3_4_c15_c2_7
    // 0xfffffff007b7ed60      a97202f9       str x9, [x21, 0x4e0]
    // 0xfffffff007b7ed64      687242f9       ldr x8, [x19, 0x4e0]
    // 0xfffffff007b7ed68      3f0108eb       cmp x9, x8
    // 0xfffffff007b7ed6c      40000054       b.eq 0xfffffff007b7ed74
    // 0xfffffff007b7ed70      e8f21cd5       msr s3_4_c15_c2_7, x8
    //
    // 0xfffffff00733bc0c      e9f23cd5       mrs x9, s3_4_c15_c2_7
    // 0xfffffff00733bc10      689a40f9       ldr x8, [x19, 0x130]
    // 0xfffffff00733bc14      3f0108eb       cmp x9, x8
    // 0xfffffff00733bc18      40000054       b.eq 0xfffffff00733bc20
    // 0xfffffff00733bc1c      e8f21cd5       msr s3_4_c15_c2_7, x8
    //
    // We ignore these.
    if
    (
        (
            (opcode_stream[-3] & 0xffffffe0) == 0xd53cf2e0 && // mrs x*, s3_4_c15_c2_7
            (opcode_stream[-2] & 0xffc00000) == 0xf9000000 && // str x*, [x*, 0x...]
            (opcode_stream[-1] & 0xffc00000) == 0xf9400000    // ldr x*, [x*, 0x...]
        )
        ||
        (
            (opcode_stream[-5] & 0xffffffe0) == 0xd53cf2e0 && // mrs x*, s3_4_c15_c2_7
            (opcode_stream[-4] & 0xffc00000) == 0xf9000000 && // str x*, [x*, 0x...]
            (opcode_stream[-3] & 0xffc00000) == 0xf9400000 && // ldr x*, [x*, 0x...]
            (opcode_stream[-2] & 0xffe0fc1f) == 0xeb00001f && // cmp x*, x*
            (opcode_stream[-1] & 0xff00001f) == 0x54000000    // b.eq 0x...
        )
        ||
        (
            (opcode_stream[-4] & 0xffffffe0) == 0xd53cf2e0 && // mrs x*, s3_4_c15_c2_7
            (opcode_stream[-3] & 0xffc00000) == 0xf9400000 && // ldr x*, [x*, 0x...]
            (opcode_stream[-2] & 0xffe0fc1f) == 0xeb00001f && // cmp x*, x*
            (opcode_stream[-1] & 0xff00001f) == 0x54000000    // b.eq 0x...
        )
    )
    {
        DEVLOG("Ignoring APRR load from thread state at 0x%" PRIx64 "", xnu_ptr_to_va(opcode_stream));
        return false;
    }
    // 2. Immediates of two forms:
    //
    // 0xfffffff0071c046c      4046e6f2       movk x0, 0x3232, lsl 48
    // 0xfffffff0071c0470      c0cecef2       movk x0, 0x7676, lsl 32
    // 0xfffffff0071c0474      0042a2f2       movk x0, 0x1210, lsl 16
    // 0xfffffff0071c0478      c0ce8ef2       movk x0, 0x7676
    // 0xfffffff0071c047c      e0f21cd5       msr s3_4_c15_c2_7, x0
    //
    // 0xfffffff007320f48      cace8ed2       mov x10, 0x7676
    // 0xfffffff007320f4c      0a42a2f2       movk x10, 0x1210, lsl 16
    // 0xfffffff007320f50      cacecef2       movk x10, 0x7676, lsl 32
    // 0xfffffff007320f54      4a46e6f2       movk x10, 0x3232, lsl 48
    // 0xfffffff007320f58      eaf21cd5       msr s3_4_c15_c2_7, x10
    //
    // Here we patch 0x1210 -> 0x1010.
    // NOTE: The first block really starts with "movk", it's hand-rolled asm.
    uint32_t *op = NULL;
    if
    (
        (opcode_stream[-4] & 0xffffffe0) == 0xf2e64640 && // movk x*, 0x3232, lsl 48
        (opcode_stream[-3] & 0xffffffe0) == 0xf2cecec0 && // movk x*, 0x7676, lsl 32
        (opcode_stream[-2] & 0xffffffe0) == 0xf2a24200 && // movk x*, 0x1210, lsl 16
        (opcode_stream[-1] & 0xffffffe0) == 0xf28ecec0    // movk x*, 0x7676
    )
    {
        op = opcode_stream - 2;
    }
    else if
    (
        (opcode_stream[-4] & 0xffffffe0) == 0xd28ecec0 && // mov x*, 0x7676
        (opcode_stream[-3] & 0xffffffe0) == 0xf2a24200 && // movk x*, 0x1210, lsl 16
        (opcode_stream[-2] & 0xffffffe0) == 0xf2cecec0 && // movk x*, 0x7676, lsl 32
        (opcode_stream[-1] & 0xffffffe0) == 0xf2e64640    // movk x*, 0x3232, lsl 48
    )
    {
        op = opcode_stream - 3;
    }
    else
    {
        panic_at(opcode_stream, "kpf_aprr: Unknown instruction sequence");
    }

    puts("KPF: Found APRR load");
    *op = (*op & 0xffe0001f) | (0x1010 << 5);
    return true;
}

static void kpf_aprr_patch(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    // The vm_map_protect patch allows setting RWX permissions at the page table level,
    // but on A11 APRR interferes with this by stripping the write bit via its
    // default register values. So we patch the default to allow RWX.
    // Applications that write to this register should be unaffected.

    // Special register, trivial match.
    // /x e0f21cd5:e0ffffff
    uint64_t matches[] =
    {
        0xd51cf2e0, // msr s3_4_c15_c2_7, xN
    };
    uint64_t masks[] =
    {
        0xffffffe0,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "aprr", matches, masks, sizeof(matches)/sizeof(uint64_t), false, (void*)kpf_aprr_callback);
}
#endif

static void kpf_vm_prot_patches(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    //kpf_aprr_patch(xnu_text_exec_patchset);
}

kpf_component_t kpf_vm_prot =
{
    .patches =
    {
        { NULL, "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_vm_prot_patches },
        {},
    },
};
