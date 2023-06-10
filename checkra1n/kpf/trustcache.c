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

static bool found_trustcache = false;

static bool kpf_trustcache_old_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    if(found_trustcache)
    {
        panic("kpf_trustcache: Found more then one trustcache call");
    }
    found_trustcache = true;

    uint32_t *bl = opcode_stream - 1;
    if((*bl & 0xffff03f0) == 0xaa0003f0) // mov x{16-31}, x0
    {
        --bl;
    }
    if((*bl & 0xfc000000) != 0x94000000) // bl
    {
        panic_at(bl, "kpf_trustcache: Missing bl");
    }

    // Follow the call
    uint32_t *lookup_in_static_trust_cache = follow_call(bl);
    // Skip any redirects
    while((*lookup_in_static_trust_cache & 0xfc000000) == 0x14000000)
    {
        lookup_in_static_trust_cache = follow_call(lookup_in_static_trust_cache);
    }
    // We legit, trust me bro.
    lookup_in_static_trust_cache[0] = 0xd2802020; // movz x0, 0x101
    lookup_in_static_trust_cache[1] = RET;

    puts("KPF: Found trustcache");
    return true;
}

static bool kpf_trustcache_new_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    if(found_trustcache)
    {
        panic("kpf_trustcache: Found more then one trustcache func");
    }
    found_trustcache = true;

    // Seek backwards to start of func. This func uses local stack space,
    // so we should always have a "sub sp, sp, 0x..." instruction.
    uint32_t *start = find_prev_insn(opcode_stream, 20, 0xd10003ff, 0xffc003ff);
    if(!start)
    {
        panic_at(opcode_stream, "kpf_trustcache: Failed to find start of function");
    }

    // Just replace the entire func, no prisoners today.
    start[0] = 0xd2800020; // mov x0, 1
    start[1] = 0xb4000042; // cbz x2, .+0x8
    start[2] = 0xf9000040; // str x0, [x2]
    start[3] = RET;        // ret

    puts("KPF: Found trustcache");
    return true;
}

static void kpf_trustcache_patches(xnu_pf_patchset_t *amfi_text_exec_patchset)
{
    // This patch leads to AMFI believing that everything is in trustcache.
    // This is done by searching for the sequence below:
    //
    // 0xfffffff0057c3f30      92440094       bl pmap_lookup_in_static_trust_cache
    // 0xfffffff0057c3f34      28208052       mov w8, 0x101
    // 0xfffffff0057c3f38      1f01206a       bics wzr, w8, w0
    //
    // When searching with r2, just make sure to set bounds to AMFI __TEXT_EXEC.
    // /x 28208052
    uint64_t matches_old[] =
    {
        0x52802028, // mov w8, 0x101
    };
    uint64_t masks_old[] =
    {
        0xffffffff,
    };
    xnu_pf_maskmatch(amfi_text_exec_patchset, "trustcache", matches_old, masks_old, sizeof(matches_old)/sizeof(uint64_t), false, (void*)kpf_trustcache_old_callback);

    // But of course, as soon as we derived this beautiful patch that worked on all versions
    // from iOS 12.0 through 16.3, the 16.4 beta comes along and ruins it all.
    //
    // Use of pmap_lookup_in_static_trust_cache was replaced entirely, with this:
    //
    // 0xfffffff005684a34      ffc300d1       sub sp, sp, 0x30
    // 0xfffffff005684a38      f44f01a9       stp x20, x19, [sp, 0x10]
    // 0xfffffff005684a3c      fd7b02a9       stp x29, x30, [sp, 0x20]
    // 0xfffffff005684a40      fd830091       add x29, sp, 0x20
    // 0xfffffff005684a44      f30302aa       mov x19, x2
    // 0xfffffff005684a48      ff7f00a9       stp xzr, xzr, [sp]
    // 0xfffffff005684a4c      e2030091       mov x2, sp
    // 0xfffffff005684a50      e86a0094       bl query_trust_cache
    // 0xfffffff005684a54      f40300aa       mov x20, x0
    // 0xfffffff005684a58      c0000035       cbnz w0, 0xfffffff005684a70
    // 0xfffffff005684a5c      530000b4       cbz x19, 0xfffffff005684a64
    // 0xfffffff005684a60      7f0200f9       str xzr, [x19]
    // 0xfffffff005684a64      e0030091       mov x0, sp
    // 0xfffffff005684a68      e10313aa       mov x1, x19
    // 0xfffffff005684a6c      5e310094       bl trustCacheQueryGetFlags
    // 0xfffffff005684a70      9f020071       cmp w20, 0
    // 0xfffffff005684a74      e0179f1a       cset w0, eq
    // 0xfffffff005684a78      fd7b42a9       ldp x29, x30, [sp, 0x20]
    // 0xfffffff005684a7c      f44f41a9       ldp x20, x19, [sp, 0x10]
    // 0xfffffff005684a80      ffc30091       add sp, sp, 0x30
    // 0xfffffff005684a84      c0035fd6       ret
    //
    // Can be found trivially with this:
    // /x e0030091e10313aa000000949f020071e0179f1a:ffffffffffffffff000000fcffffffffffffffff
    uint64_t matches_new[] =
    {
        0x910003e0, // mov x0, sp
        0xaa1303e1, // mov x1, x19
        0x94000000, // bl trustCacheQueryGetFlags
        0x7100029f, // cmp w20, 0
        0x1a9f17e0, // cset w0, eq
    };
    uint64_t masks_new[] =
    {
        0xffffffff,
        0xffffffff,
        0xfc000000,
        0xffffffff,
        0xffffffff,
    };
    xnu_pf_maskmatch(amfi_text_exec_patchset, "trustcache", matches_new, masks_new, sizeof(matches_new)/sizeof(uint64_t), false, (void*)kpf_trustcache_new_callback);
}

static void kpf_trustcache_finish(struct mach_header_64 *hdr, checkrain_option_t *checkra1n_flags)
{
    if(!found_trustcache)
    {
        panic("Missing patch: trustcache");
    }
}

kpf_component_t kpf_trustcache =
{
    .finish = kpf_trustcache_finish,
    .patches =
    {
        { "com.apple.driver.AppleMobileFileIntegrity", "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_trustcache_patches },
        {},
    },
};
