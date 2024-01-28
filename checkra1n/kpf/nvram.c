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
#include <string.h>

extern uint32_t nvram_shc[], nvram_shc_end[];

static bool nvram_inline_patch = false;
static uint32_t *nvram_patchpoint = NULL;

static bool kpf_nvram_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    if(nvram_patchpoint || nvram_inline_patch)
    {
        panic("kpf_nvram_unlock: Found twice");
    }

    nvram_patchpoint = find_next_insn(opcode_stream, 0x10, RET, 0xffffffff);
    if(nvram_patchpoint)
    {
        puts("KPF: Found NVRAM unlock");
        return true;
    }
    return false;
}

static bool kpf_nvram_inline_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    if(nvram_patchpoint || nvram_inline_patch)
    {
        panic("kpf_nvram_unlock: Found twice");
    }

    // Most reliable marker of a stack frame seems to be "add x29, sp, 0x...".
    // And this function is HUGE, hence up to 2k insn.
    uint32_t *frame = find_prev_insn(opcode_stream, 2000, 0x910003fd, 0xff8003ff);
    if(!frame) return false;

    // Now find the insn that decrements sp. This can be either
    // "stp ..., ..., [sp, -0x...]!" or "sub sp, sp, 0x...".
    // Match top bit of imm on purpose, since we only want negative offsets.
    uint32_t  *start = find_prev_insn(frame, 10, 0xa9a003e0, 0xffe003e0);
    if(!start) start = find_prev_insn(frame, 10, 0xd10003ff, 0xff8003ff);
    if(!start) return false;

    nvram_inline_patch = true;

    start[0] = 0x52800020; // mov w0, 1
    start[1] = RET;

    puts("KPF: Found NVRAM unlock");
    return true;
}

static bool kpf_nvram_table_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    if(nvram_patchpoint || nvram_inline_patch)
    {
        panic("kpf_nvram_unlock: Found twice");
    }

    // Sanity checks
    uint32_t reg = opcode_stream[0] & 0x1f; // adrp
    if
    (
        ( opcode_stream[1]       & 0x3ff) != (reg | (reg << 5)) || // add src and dst
        ((opcode_stream[7] >> 5) &  0x1f) !=  reg               || // ldr src
        ((opcode_stream[9] >> 5) &  0x1f) !=  reg                  // ldr src
    )
    {
        return false;
    }
    const char *str = (const char *)(((uint64_t)(opcode_stream + 2) & ~0xfffULL) + adrp_off(opcode_stream[2]) + ((opcode_stream[3] >> 10) & 0xfff));
    if(strcmp(str, "aapl,pci") != 0)
    {
        return false;
    }
    nvram_inline_patch = true;

    uint32_t *tbnz = find_next_insn(opcode_stream + 10, 10, 0x37100000 | (opcode_stream[9] & 0x1f), 0xfff8001f); // tbnz wM, 2, 0xfffffff0077ae070
    if(!tbnz)
    {
        panic_at(opcode_stream, "kpf_nvram_unlock: Failed to find tbnz");
    }

    *tbnz = NOP;

    puts("KPF: Found NVRAM unlock");
    return true;
}

static void kpf_nvram_patches(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    // Find IODTNVRAM::getOFVariablePerm().
    // Gonna patch its "ret" to branch to our shellcode, where we update
    // the return value if appropriate (see _nvram_shc in shellcode.S).

    // iOS 13 and below:
    // /x 008c41f8000000b5000c40b9:00fcffff000000ff1ffcffff
    uint64_t matches1[] =
    {
        0xf8418c00, // ldr x*, [x*, 0x18]!
        0xb5000000, // cbnz x*, 0x...
        0xb9400c00, // ldr w0, [x*, 0xc]
    };
    uint64_t masks1[] =
    {
        0xfffffc00,
        0xff000000,
        0xfffffc1f,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "nvram_unlock", matches1, masks1, sizeof(matches1)/sizeof(uint64_t), false, (void*)kpf_nvram_callback);

    // iOS 14.0 and 14.1:
    // /x 008c41f8000000b5000009aa000c40b9:00fcffff000000ff00fcffff1ffcffff
    uint64_t matches2[] =
    {
        0xf8418c00, // ldr x*, [x*, 0x18]!
        0xb5000000, // cbnz x*, 0x...
        0xaa090000, // mov x*, x*
        0xb9400c00, // ldr w0, [x*, 0xc]
    };
    uint64_t masks2[] =
    {
        0xfffffc00,
        0xff000000,
        0xfffffc00,
        0xfffffc1f,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "nvram_unlock", matches2, masks2, sizeof(matches2)/sizeof(uint64_t), false, (void*)kpf_nvram_callback);

    // In iOS 14.2, IODTNVRAM saw a complete refactor. The virtual methods for
    // variable type/permission now just return 0, and there are dedicated
    // functions for white- and blacklisted variables. The blacklist has all
    // entries inlined as byte-by-byte comparisons like so:
    //
    // 0xfffffff007710b8c      28444039       ldrb w8, [x1, 0x11]
    // 0xfffffff007710b90      1f890171       cmp w8, 0x62
    // 0xfffffff007710b94      c1030054       b.ne 0xfffffff007710c0c
    // 0xfffffff007710b98      28484039       ldrb w8, [x1, 0x12]
    // 0xfffffff007710b9c      1fbd0171       cmp w8, 0x6f
    // 0xfffffff007710ba0      61030054       b.ne 0xfffffff007710c0c
    // 0xfffffff007710ba4      284c4039       ldrb w8, [x1, 0x13]
    // 0xfffffff007710ba8      1fbd0171       cmp w8, 0x6f
    // 0xfffffff007710bac      01030054       b.ne 0xfffffff007710c0c
    // 0xfffffff007710bb0      28504039       ldrb w8, [x1, 0x14]
    // 0xfffffff007710bb4      1fd10171       cmp w8, 0x74
    // 0xfffffff007710bb8      a1020054       b.ne 0xfffffff007710c0c
    // 0xfffffff007710bbc      28544039       ldrb w8, [x1, 0x15]
    // 0xfffffff007710bc0      1fb50071       cmp w8, 0x2d
    // 0xfffffff007710bc4      41020054       b.ne 0xfffffff007710c0c
    // 0xfffffff007710bc8      28584039       ldrb w8, [x1, 0x16]
    // 0xfffffff007710bcc      1fb90171       cmp w8, 0x6e
    // 0xfffffff007710bd0      e1010054       b.ne 0xfffffff007710c0c
    // 0xfffffff007710bd4      285c4039       ldrb w8, [x1, 0x17]
    // 0xfffffff007710bd8      1fbd0171       cmp w8, 0x6f
    // 0xfffffff007710bdc      81010054       b.ne 0xfffffff007710c0c
    // 0xfffffff007710be0      28604039       ldrb w8, [x1, 0x18]
    // 0xfffffff007710be4      1fb90171       cmp w8, 0x6e
    // 0xfffffff007710be8      21010054       b.ne 0xfffffff007710c0c
    // 0xfffffff007710bec      28644039       ldrb w8, [x1, 0x19]
    // 0xfffffff007710bf0      1f8d0171       cmp w8, 0x63
    // 0xfffffff007710bf4      c1000054       b.ne 0xfffffff007710c0c
    // 0xfffffff007710bf8      28684039       ldrb w8, [x1, 0x1a]
    // 0xfffffff007710bfc      1f950171       cmp w8, 0x65
    // 0xfffffff007710c00      61000054       b.ne 0xfffffff007710c0c
    //
    // The above code checks for the "boot-nonce" part of "com.apple.System.boot-nonce".
    // We find that bit specifically, then seek backwards to the start of the
    // function and just patch it to return true unconditionally.
    uint64_t matches3[] =
    {
        0x39404400, 0x7101881f, 0x54000001, // b
        0x39404800, 0x7101bc1f, 0x54000001, // o
        0x39404c00, 0x7101bc1f, 0x54000001, // o
        0x39405000, 0x7101d01f, 0x54000001, // t
        0x39405400, 0x7100b41f, 0x54000001, // -
        0x39405800, 0x7101b81f, 0x54000001, // n
        0x39405c00, 0x7101bc1f, 0x54000001, // o
        0x39406000, 0x7101b81f, 0x54000001, // n
        0x39406400, 0x71018c1f, 0x54000001, // c
        0x39406800, 0x7101941f, 0x54000001, // e
    };
    uint64_t masks3[] =
    {
        0xfffffc00, 0xfffffc1f, 0xff00001f,
        0xfffffc00, 0xfffffc1f, 0xff00001f,
        0xfffffc00, 0xfffffc1f, 0xff00001f,
        0xfffffc00, 0xfffffc1f, 0xff00001f,
        0xfffffc00, 0xfffffc1f, 0xff00001f,
        0xfffffc00, 0xfffffc1f, 0xff00001f,
        0xfffffc00, 0xfffffc1f, 0xff00001f,
        0xfffffc00, 0xfffffc1f, 0xff00001f,
        0xfffffc00, 0xfffffc1f, 0xff00001f,
        0xfffffc00, 0xfffffc1f, 0xff00001f,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "nvram_unlock", matches3, masks3, sizeof(matches3)/sizeof(uint64_t), false, (void*)kpf_nvram_inline_callback);

    // And iOS 16.4 must've seen big compiler changes or something, because now it's
    // no longer inlined, and it's once more just a table that is iterated over.
    //
    // 0xfffffff0077addc8      b4cdfff0       adrp x20, 0xfffffff007164000  <- this is the table
    // 0xfffffff0077addcc      94e21091       add x20, x20, 0x438
    // 0xfffffff0077addd0      40c7ff90       adrp x0, 0xfffffff007095000   <- this is the first entry of the table, preloaded ("aapl,pci")
    // 0xfffffff0077addd4      00ac0c91       add x0, x0, 0x32b
    // 0xfffffff0077addd8      e10317aa       mov x1, x23
    // 0xfffffff0077adddc      0910ed97       bl sym._strcmp
    // 0xfffffff0077adde0      60000034       cbz w0, 0xfffffff0077addec
    // 0xfffffff0077adde4      800e41f8       ldr x0, [x20, 0x10]!          <- this advances to the next entry
    // 0xfffffff0077adde8      80ffffb5       cbnz x0, 0xfffffff0077addd8
    // 0xfffffff0077addec      9a0640f9       ldr x26, [x20, 8]             <- this loads the flags / permissions
    //
    // Shortly afterwards, there is a "tbnz w26, 2", which checks for the kernel-only bit. We just get rid of that.
    // /x 10000090100200910000009000000091e10310aa0000009460000034000c40f880ffffb5100640f9:1000009f1002c0ff1f00009fff03c0fffffff0ff000000fcffffffff1f0ce0ffffffffff10feffff
    uint64_t matches4[] =
    {
        0x90000010, // adrp xN, 0x...
        0x91000210, // add xN, xN, 0x...
        0x90000000, // adrp x0, 0x...
        0x91000000, // add x0, x0, 0x...
        0xaa1003e1, // mov x1, x{16-31}
        0x94000000, // bl sym._strcmp
        0x34000060, // cbz w0, .+12
        0xf8400c00, // ldr x0, [xN, ...]!
        0xb5ffff80, // cbnz x0, .-16
        0xf9400610, // ldr x{16-31}, [xN, 8]
    };
    uint64_t masks4[] =
    {
        0x9f000010,
        0xffc00210,
        0x9f00001f,
        0xffc003ff,
        0xfff0ffff,
        0xfc000000,
        0xffffffff,
        0xffe00c1f,
        0xffffffff,
        0xfffffe10,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "nvram_unlock", matches4, masks4, sizeof(matches4)/sizeof(uint64_t), false, (void*)kpf_nvram_table_callback);
}

static void kpf_nvram_finish(struct mach_header_64 *hdr, checkrain_option_t *checkra1n_flags)
{
#ifdef DEV_BUILD
    // Treat this patch as optional in release
    if(!nvram_patchpoint && !nvram_inline_patch)
    {
        panic("Missing patch: nvram_unlock");
    }
#endif
}

static uint32_t kpf_nvram_size(void)
{
    return nvram_shc_end - nvram_shc;
}

static uint32_t kpf_nvram_emit(uint32_t *shellcode_area)
{
    if(!nvram_patchpoint)
    {
        return 0;
    }

    uint64_t nvram_patch_from = xnu_ptr_to_va(nvram_patchpoint);
    uint64_t nvram_patch_to = xnu_ptr_to_va(shellcode_area);
    int64_t nvram_off = nvram_patch_to - nvram_patch_from;
    if(nvram_off > 0x7fffffcLL || nvram_off < -0x8000000LL)
    {
        panic("kpf_nvram_unlock: jump too far: 0x%llx", nvram_off);
    }

    memcpy(shellcode_area, nvram_shc, (uintptr_t)nvram_shc_end - (uintptr_t)nvram_shc);
    *nvram_patchpoint = 0x14000000 | (((uint64_t)nvram_off >> 2) & 0x3ffffff);

    return nvram_shc_end - nvram_shc;
}

kpf_component_t kpf_nvram =
{
    .finish = kpf_nvram_finish,
    .shc_size = kpf_nvram_size,
    .shc_emit = kpf_nvram_emit,
    .patches =
    {
        { NULL, "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_nvram_patches },
        {},
    },
};
