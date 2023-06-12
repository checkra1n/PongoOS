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

static bool need_proc_selfname_patch = false;
static uint32_t* proc_selfname = NULL;

static bool kpf_proc_selfname_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    if(proc_selfname)
    {
        DEVLOG("proc_selfname_callback: already ran, skipping...");
        return false;
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
    
    puts("KPF: Found proc_selfname");
    proc_selfname = start;
#ifdef DEV_BUILD
    printf("proc_selfname 0x%016llx\n", xnu_ptr_to_va(proc_selfname));
#endif
    return true;
}

static void kpf_proc_selfname_patch(xnu_pf_patchset_t *patchset)
{
    // the IDSBlastDoorService process since 16.2 does not seem to like vnode_check_open being hooked.
    // so I will tentatively only do a normal check when this process is detected...
    // we need to run proc_selfname and look for this function to get the process name.
    // ...
    // fffffff0076117cc         ldr        x8, [x0, #0x10]
    // fffffff0076117d0         cbz        x8, loc_fffffff0076117ec
    // fffffff0076117d4         add        x1, x8, #0x381             ; argument "src"  for method _strlcpy
    // fffffff0076117d8         sxtw       x2, w20                    ; argument "size" for method _strlcpy
    // fffffff0076117dc         mov        x0, x19                    ; argument "dst"  for method _strlcpy
    // fffffff0076117e0         ldp        fp, lr, [sp, #0x10]
    // fffffff0076117e4         ldp        x20, x19, [sp], #0x20
    // fffffff0076117e8         b          _strlcpy
    // fffffff0076117ec         adrp       x8, #0xfffffff007195000
    // fffffff0076117f0         ldr        x8, [x8, #0x10]            ; _kernproc
    // fffffff0076117f4         cbnz       x8, loc_fffffff0076117d4
    
    uint64_t matches[] = {
        0xf9400000, // ldr xN, [xM, ...]
        0xb4000000, // cbz x*, ...
        0x91000001, // add x1, xn, #imm
        0x93407c02, // sxtw x2, wy
        0xaa0003e0, // mov x0, xN
        0x00000000, // ldp
        0x00000000, // ldp
        0x14000000, // b 0x...
        0x90000000, // adrp
        0xf9400000, // ldr xN, [xM, ...]
        0xb5000000, // cbnz x*, 0x...
    };
    
    uint64_t masks[] = {
        0xffc00000, // ldr xN, [xM, ...]
        0xff000000, // cbz x*, ...
        0xff00000f, // add xn, xn, #imm
        0xffff7c0f, // sxtw x2, wy
        0xffe0ffff, // mov x0, xn
        0x00000000, // ldp
        0x00000000, // ldp
        0xfc000000, // b 0x...
        0x9f000000, // adrp
        0xffc00000, // ldr xN, [xM, ...]
        0xff000000, // cbnz x*, 0x...
    };
    
    xnu_pf_maskmatch(patchset, "proc_selfname", matches, masks, sizeof(masks)/sizeof(uint64_t), false, (void*)kpf_proc_selfname_callback);

    uint64_t i_matches[] = {
        0xf9400000, // ldr xN, [xM, ...]
        0xb4000000, // cbz x*, ...
        0x91000001, // add x1, xn, #imm
        0x93407c02, // sxtw x2, wy
        0xaa0003e0, // mov x0, xN
        0x92800003, // mov x3, #-1
        0x00000000, // ldp
        0x00000000, // ldp
        0x14000000, // b 0x...
        0x90000000, // adrp
        0xf9400000, // ldr xN, [xM, ...]
        0xb5000000, // cbnz x*, 0x...
    };

    uint64_t i_masks[] = {
        0xffc00000, // ldr xN, [xM, ...]
        0xff000000, // cbz x*, ...
        0xff00000f, // add xn, xn, #imm
        0xffff7c0f, // sxtw x2, wy
        0xffe0ffff, // mov x0, xn
        0xffffffff, // mov x3, #-1
        0x00000000, // ldp
        0x00000000, // ldp
        0xfc000000, // b 0x...
        0x9f000000, // adrp
        0xffc00000, // ldr xN, [xM, ...]
        0xff000000, // cbnz x*, 0x...
    };

    xnu_pf_maskmatch(patchset, "proc_selfname", i_matches, i_masks, sizeof(i_masks)/sizeof(uint64_t), false, (void*)kpf_proc_selfname_callback);
}

static void kpf_proc_selfname_init(struct mach_header_64 *hdr, xnu_pf_range_t *cstring, palerain_option_t palera1n_flags)
{
    const char cryptex_string[] = "/private/preboot/Cryptexes";
    const char *cryptex_string_match = memmem(cstring->cacheable_base, cstring->size, cryptex_string, sizeof(cryptex_string));

#ifdef DEV_BUILD
    // 16.0 beta 1 onwards
    if((cryptex_string_match != NULL) != (gKernelVersion.darwinMajor >= 22))
    {
        panic("Cryptex presence doesn't match expected Darwin version");
    }
#endif

    need_proc_selfname_patch = cryptex_string_match != NULL;
}

static void kpf_proc_selfname_patches(xnu_pf_patchset_t *amfi_text_exec_patchset)
{
    if(need_proc_selfname_patch) // iOS 16+ only
    {
        kpf_proc_selfname_patch(amfi_text_exec_patchset);
    }
}

kpf_component_t kpf_proc_selfname =
{
    .init = kpf_proc_selfname_init,
    .patches =
    {
        { NULL, "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_proc_selfname_patches },
        {},
    },
};
