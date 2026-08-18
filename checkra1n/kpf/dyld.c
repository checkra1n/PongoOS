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
#include <string.h>

extern uint32_t dyld_shc[], dyld_shc_ctx[], dyld_shc_lookup[], dyld_shc_put[], dyld_shc_end[];

static uint32_t *dyld_hook_patchpoint;

static bool kpf_dyld_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    uint32_t adrp = opcode_stream[5],
             add  = opcode_stream[6];
    // Sanity check: make sure instrs use the same reg
    if((adrp & 0x1f) != (add & 0x1f) || (add & 0x1f) != ((add >> 5) & 0x1f))
    {
        return false;
    }
    // Actual match check
    const char *str = (const char *)(((uint64_t)(opcode_stream + 5) & ~0xfffULL) + adrp_off(adrp) + ((add >> 10) & 0xfff));
    if(strcmp(str, "/usr/lib/dyld") != 0)
    {
        return false;
    }

    static bool found_dyld = false;
    if(found_dyld)
    {
        panic("kpf_dyld: Found twice");
    }
    found_dyld = true;

    // We replace this bit of code:
    //
    // if (0 != strcmp(name, DEFAULT_DYLD_PATH)) {
    //     return (LOAD_BADMACHO);
    // }
    //
    // With this:
    //
    // name = dyld_hook();
    //
    // So instead of checking the path, we just always override it either
    // with our custom dyld path if it exists, and with /usr/lib/dyld otherwise.

    // Check whether strcmp is inlined or not
    uint32_t *target = NULL;
    if
    (
        (opcode_stream[7] & 0xfff0ffff) == 0xaa1003e0 && // mov x0, x{16-31}
        (opcode_stream[8] & 0xfc000000) == 0x94000000 && // bl sym._strcmp
        (opcode_stream[9] & 0xff00001f) == 0x34000000    // cbz w0, ...
    )
    {
        target = opcode_stream + 9 + sxt32(opcode_stream[9] >> 5, 19); // uint32 takes care of << 2
    }
    else if
    (
        (opcode_stream[ 7] & 0xfff0fff0) == 0xaa1003e0 && // mov x{0-15}, x{16-31}
        (opcode_stream[ 8] & 0xfffffe10) == 0x39400000 && // ldrb w{0-15}, [x{0-15}]
        (opcode_stream[ 9] & 0xfffffe10) == 0x39400000 && // ldrb w{0-15}, [x{0-15}]
        (opcode_stream[10] & 0xfff0fe1f) == 0x6b00001f && // cmp w{0-15}, w{0-15}
        (opcode_stream[11] & 0xff00001f) == 0x54000001 && // b.ne 0x...
        (opcode_stream[12] & 0xfffffe10) == 0x91000400 && // add x{0-15}, x{0-15}, 1
        (opcode_stream[13] & 0xfffffe10) == 0x91000400 && // add x{0-15}, x{0-15}, 1
        (opcode_stream[14] & 0xff800010) == 0x35800000    // cbnz w{0-15}, {backwards}

    )
    {
        target = opcode_stream + 15;
    }
    else
    {
        panic_at(opcode_stream + 7, "kpf_dyld: Bad instructions after adrp/add");
    }

    // We have at least 5 instructions we can overwrite.
    uint32_t reg = (opcode_stream[0] >> 16) & 0x1f;
    opcode_stream[5] = 0x94000000;                                  // bl dyld_hook
    opcode_stream[6] = 0xaa0003e0 | reg;                            // mov xN, x0
    opcode_stream[7] = 0x14000000 | (target - (opcode_stream + 7)); // b target
    // dyld_hook hasn't been emitted yet
    dyld_hook_patchpoint = opcode_stream + 5;

    puts("KPF: Found dyld");
    return true;
}

static void kpf_dyld_patches(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    // This patch allows the use of an alternate dyld at a hardcoded path, if it exists.
    //
    // There is a check in the kernel for "/usr/lib/dyld", with strcmp either inlined or not:
    //
    // 0xfffffff00769401c      e0031aaa       mov x0, x26
    // 0xfffffff007694020      e10313aa       mov x1, x19
    // 0xfffffff007694024      27b4ec97       bl sym._strnlen
    // 0xfffffff007694028      1f0013eb       cmp x0, x19
    // 0xfffffff00769402c      620d0054       b.hs 0xfffffff0076941d8
    // 0xfffffff007694030      48cfffd0       adrp x8, 0xfffffff00707e000
    // 0xfffffff007694034      08d91791       add x8, x8, 0x5f6
    // 0xfffffff007694038      e9031aaa       mov x9, x26
    // 0xfffffff00769403c      2a014039       ldrb w10, [x9]
    // 0xfffffff007694040      0b014039       ldrb w11, [x8]
    // 0xfffffff007694044      5f010b6b       cmp w10, w11
    // 0xfffffff007694048      810c0054       b.ne 0xfffffff0076941d8
    // 0xfffffff00769404c      08050091       add x8, x8, 1
    // 0xfffffff007694050      29050091       add x9, x9, 1
    // 0xfffffff007694054      4affff35       cbnz w10, 0xfffffff00769403c
    //
    // 0xfffffff00765c90c      e00315aa       mov x0, x21
    // 0xfffffff00765c910      e10313aa       mov x1, x19
    // 0xfffffff00765c914      ebb1ed97       bl sym._strnlen
    // 0xfffffff00765c918      1f0013eb       cmp x0, x19
    // 0xfffffff00765c91c      c2000054       b.hs 0xfffffff00765c934
    // 0xfffffff00765c920      21d1ff90       adrp x1, 0xfffffff007080000
    // 0xfffffff00765c924      21200891       add x1, x1, 0x208
    // 0xfffffff00765c928      e00315aa       mov x0, x21
    // 0xfffffff00765c92c      3454f297       bl sym._strcmp
    // 0xfffffff00765c930      20020034       cbz w0, 0xfffffff00765c974
    //
    // We match up to and including the adrp+add, and then make sure in the callback that the string is "/usr/lib/dyld".
    // /x e00310aae10310aa000000941f0010eb020000540000009000000091:fffff0fffffff0ff000000fcfffff0ff1f0000ff0000009f0000c0ff
    uint64_t matches[] =
    {
        0xaa1003e0, // mov x0, x{16-31}
        0xaa1003e1, // mov x1, x{16-31}
        0x94000000, // bl sym._strnlen
        0xeb10001f, // cmp x0, x{16-31}
        0x54000002, // b.hs 0x...
        0x90000000, // adrp xN, "/usr/lib/dyld"@PAGE
        0x91000000, // add xN, xN, "/usr/lib/dyld"@PAGEOFF
    };
    uint64_t masks[] =
    {
        0xfff0ffff,
        0xfff0ffff,
        0xfc000000,
        0xfff0ffff,
        0xff00001f,
        0x9f000000,
        0xffc00000,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "dyld", matches, masks, sizeof(matches)/sizeof(uint64_t), true, (void*)kpf_dyld_callback);
}

static uint32_t kpf_dyld_size(void)
{
    return dyld_shc_end - dyld_shc;
}

static uint32_t kpf_dyld_emit(uint32_t *shellcode_area)
{
    uint64_t vfs_context_current = kpf_vfs__vfs_context_current();
    uint64_t vnode_lookup        = kpf_vfs__vnode_lookup();
    uint64_t vnode_put           = kpf_vfs__vnode_put();

    uint64_t shellcode_addr  = xnu_ptr_to_va(shellcode_area);
    uint64_t patchpoint_addr = xnu_ptr_to_va(dyld_hook_patchpoint);

    size_t ctx_idx    = dyld_shc_ctx    - dyld_shc;
    size_t lookup_idx = dyld_shc_lookup - dyld_shc;
    size_t put_idx    = dyld_shc_put    - dyld_shc;

    int64_t ctx_off    = vfs_context_current - (shellcode_addr + (ctx_idx    << 2));
    int64_t lookup_off = vnode_lookup        - (shellcode_addr + (lookup_idx << 2));
    int64_t put_off    = vnode_put           - (shellcode_addr + (put_idx    << 2));
    int64_t patch_off  = shellcode_addr - patchpoint_addr;
    if(ctx_off > 0x7fffffcLL || ctx_off < -0x8000000LL || lookup_off > 0x7fffffcLL || lookup_off < -0x8000000LL || put_off > 0x7fffffcLL || put_off < -0x8000000LL || patch_off > 0x7fffffcLL || patch_off < -0x8000000LL)
    {
        panic("kpf_dyld: jump too far: 0x%llx/0x%llx/0x%llx/0x%llx", ctx_off, lookup_off, put_off, patch_off);
    }

    memcpy(shellcode_area, dyld_shc, (uintptr_t)dyld_shc_end - (uintptr_t)dyld_shc);

    shellcode_area[ctx_idx]    |= (ctx_off    >> 2) & 0x03ffffff;
    shellcode_area[lookup_idx] |= (lookup_off >> 2) & 0x03ffffff;
    shellcode_area[put_idx]    |= (put_off    >> 2) & 0x03ffffff;
    *dyld_hook_patchpoint      |= (patch_off  >> 2) & 0x03ffffff;

    return dyld_shc_end - dyld_shc;
}

kpf_component_t kpf_dyld =
{
    .shc_size = kpf_dyld_size,
    .shc_emit = kpf_dyld_emit,
    .patches =
    {
        { NULL, "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_dyld_patches },
        {},
    },
};
