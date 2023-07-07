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
#include <kerninfo.h>
#include <pongo.h>
#include <xnu/xnu.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern uint32_t fsctl_shc[], fsctl_shc_vnode_open[], fsctl_shc_stolen_slowpath[], fsctl_shc_orig_bl[], fsctl_shc_vnode_close[], fsctl_shc_stolen_fastpath[], fsctl_shc_orig_b[], fsctl_shc_end[];

static bool do_bind_mounts = false;

static uint32_t *fsctl_patchpoint = NULL;
static uint64_t vnode_open_addr = 0, vnode_close_addr = 0;

static bool kpf_fsctl_dev_by_role_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    static bool found_fsctl_internal = false;
    if(found_fsctl_internal)
    {
        panic("kpf_fsctl_dev_by_role: Found twice");
    }
    found_fsctl_internal = true;

    uint32_t *stackframe = find_prev_insn(opcode_stream - 1, 0x20, 0xa9007bfd, 0xffc07fff); // stp x29, x30, [sp, ...]
    if(!stackframe)
    {
        panic_at(opcode_stream, "kpf_fsctl_dev_by_role: Failed to find stack frame");
    }

    uint32_t *start = find_prev_insn(stackframe - 1, 8, 0xd10003ff, 0xffc003ff); // sub sp, sp, ...
    if(!start)
    {
        panic_at(stackframe, "kpf_fsctl_dev_by_role: Failed to find start of function");
    }

    fsctl_patchpoint = start;

    puts("KPF: Found fsctl_dev_by_role");
    return true;
}

static bool kpf_vnode_open_close_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    static bool found_vnode_open_close = false;
    if(found_vnode_open_close)
    {
        panic("kpf_vnode_open_close: Found twice");
    }
    found_vnode_open_close = true;

    uint32_t *vnode_open = find_next_insn(opcode_stream + 2, 3, 0x94000000, 0xfc000000); // bl
    if(!vnode_open)
    {
        panic_at(opcode_stream, "kpf_vnode_open_close: Failed to find vnode_open");
    }

    uint32_t *vnode_close = find_next_insn(vnode_open + 1, 0x20, 0xaa1003e2, 0xfff0ffff); // mov x2, x{x16-31}
    if(
        !vnode_close ||
        (vnode_close[ 1] & 0xfc000000) != 0x94000000 || // bl
         vnode_close[-1]               != 0x52800001 || // mov w1, 0
        (vnode_close[-2] & 0xfff0ffff) != 0xaa1003e0 ||
        (vnode_close[-3] & 0xffc00210) != 0x91000210 || // add x{16-31}, x{16-31}, ...
        (vnode_close[-4] & 0x9f000010) != 0x90000010    // adrp x{16-31}, ...
    )
    {
        panic_at(vnode_open, "kpf_vnode_open_close: Failed to find vnode_close");
    }
    vnode_close++;

    vnode_open_addr  = xnu_ptr_to_va(vnode_open)  + (sxt32(*vnode_open,  26) << 2);
    vnode_close_addr = xnu_ptr_to_va(vnode_close) + (sxt32(*vnode_close, 26) << 2);

    puts("KPF: Found vnode_open/vnode_close");
    return true;
}

static void kpf_fsctl_dev_by_role_patch(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    // There is an APFS-specific fsctl to look up volumes by role within a container.
    // This is used on "/", which on bind mounts is the ramdisk and not the rootFS.
    // In order to make things work as expected, we check whether this specific fsctl
    // is invoked on the volume backed by "/dev/md0", and redirect it to "/fs/orig".
    // We do this by just finding the handler function by a specific marker, and patching
    // the first instruction to branch to shellcode. This is the first match below.
    // The second match is for utility functions we need for the shellcode.

    // /x 002088520000b072:e0ffffffe0ffffff
    uint64_t matches[] =
    {
        0x52882000, // mov wN, 0x4100
        0x72b00000, // movk wN, 0x8000, lsl 16
    };
    uint64_t masks[] =
    {
        0xffffffe0,
        0xffffffe0,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "fsctl_dev_by_role", matches, masks, sizeof(masks)/sizeof(uint64_t), true, (void*)kpf_fsctl_dev_by_role_callback);

    // /x 61c0805202308052
    uint64_t vn_matches[] =
    {
        0x5280c061, // mov w1, 0x603
        0x52803002, // mov w2, 0x180
    };
    uint64_t vn_masks[] =
    {
        0xffffffff,
        0xffffffff,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "vnode_open_close", vn_matches, vn_masks, sizeof(vn_masks)/sizeof(uint64_t), true, (void*)kpf_vnode_open_close_callback);
}

static bool kpf_shared_region_root_dir_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    uint32_t *ldr = opcode_stream + 2;
    uint32_t op = *ldr;
    uint32_t reg, mask;
    // Check if we have another load from stack
    if((op & 0xffc003e0) == 0xf94003e0) // ldr xN, [sp, 0x...]
    {
        reg = op & 0x1f;
        mask = 0x1f;
        op = *++ldr;
    }
    else
    {
        reg = 0x10; // 16-31
        mask = 0x10;
    }
    // Make sure we have another load from +0xd8
    if((op & (0xfffffc1f | (mask << 5))) != (0xf9406c09 | (reg << 5))) // ldr x9, [xN, 0xd8]
    {
        return false;
    }

    // And our cmp x8, x9
    uint32_t *cmp = ldr + 1;
    op = *cmp;
    if((op & 0xffffffff) != 0xeb09011f) // cmp x8, x9
    {
        return false;
    }

    // Then it's possible there's a load to a high reg from the stack
    uint32_t *bcond = cmp + 1;
    op = *bcond;
    if((op & 0xffc003f0) == 0xf94003f0) // ldr x{16-31}, [sp, 0x...]
    {
        op = *++bcond;
    }

    // And finally our branch
    if((op & 0xff00001e) != 0x54000000) // b.{eq|ne} 0x...
    {
        return false;
    }

    // Now that we're sure this is the right match, enforce uniqueness.
    static bool found_shared_region_root_dir = false;
    if(found_shared_region_root_dir)
    {
        panic("kpf_shared_region_root_dir: Found twice");
    }

    *cmp = 0xeb00001f; // cmp x0, x0
    found_shared_region_root_dir = true;

    puts("KPF: Found shared region root dir");
    return true;
}

static void kpf_shared_region_root_dir_patch(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    // Doing bind mounts means the shared cache is not on the volume mounted at /.
    // XNU has a check to require that though, so we patch that out.
    //
    // Variants we need to match against:
    //
    // 0xfffffff00764c998      801240f9       ldr x0, [x20, 0x20]
    // 0xfffffff00764c99c      086c40f9       ldr x8, [x0, 0xd8]
    // 0xfffffff00764c9a0      696f40f9       ldr x9, [x27, 0xd8]
    // 0xfffffff00764c9a4      1f0109eb       cmp x8, x9
    // 0xfffffff00764c9a8      a1f3ff54       b.ne 0xfffffff00764c81c
    //
    // 0xfffffff0080320f4      601340f9       ldr x0, [x27, 0x20]
    // 0xfffffff0080320f8      086c40f9       ldr x8, [x0, 0xd8]
    // 0xfffffff0080320fc      e92340f9       ldr x9, [sp, 0x40]
    // 0xfffffff008032100      296d40f9       ldr x9, [x9, 0xd8]
    // 0xfffffff008032104      1f0109eb       cmp x8, x9
    // 0xfffffff008032108      f41b40f9       ldr x20, [sp, 0x30]
    // 0xfffffff00803210c      410f0054       b.ne 0xfffffff0080322f4
    //
    // 0xfffffff007dcabc8      001140f9       ldr x0, [x8, 0x20]
    // 0xfffffff007dcabcc      086c40f9       ldr x8, [x0, 0xd8]
    // 0xfffffff007dcabd0      e91b40f9       ldr x9, [sp, 0x30]
    // 0xfffffff007dcabd4      296d40f9       ldr x9, [x9, 0xd8]
    // 0xfffffff007dcabd8      1f0109eb       cmp x8, x9
    // 0xfffffff007dcabdc      210f0054       b.ne 0xfffffff007dcadc0
    //
    // Due to the possible variants, we just match against the
    // first two instructions and check the rest in the callback.
    //
    // /x 001040f9086c40f9:1ffcffffffffffff
    uint64_t matches[] =
    {
        0xf9401000, // ldr x0, [x*, 0x20]
        0xf9406c08, // ldr x8, [x0, 0xd8]
    };
    uint64_t masks[] =
    {
        0xfffffc1f,
        0xffffffff,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "shared_region_root_dir", matches, masks, sizeof(matches)/sizeof(uint64_t), true, (void*)kpf_shared_region_root_dir_callback);
}

static void kpf_bindfs_patches(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    // iOS 15.0: Union mounts no longer work
    if(do_bind_mounts)
    {
        kpf_fsctl_dev_by_role_patch(xnu_text_exec_patchset);
        kpf_shared_region_root_dir_patch(xnu_text_exec_patchset);
    }
}

static void kpf_bindfs_init(struct mach_header_64 *hdr, xnu_pf_range_t *cstring, checkrain_option_t kpf_flags, checkrain_option_t checkra1n_flags)
{
    const char rootvp_string[] = "rootvp not authenticated after mounting";
    const char *rootvp_string_match = memmem(cstring->cacheable_base, cstring->size, rootvp_string, sizeof(rootvp_string) - 1); // don't match null byte

#ifdef DEV_BUILD
    // 15.0 beta 1 onwards
    if((rootvp_string_match != NULL) != (gKernelVersion.darwinMajor >= 21))
    {
        panic("rootvp_auth panic doesn't match expected Darwin version");
    }
#endif

    do_bind_mounts = rootvp_string_match != NULL;
}

static void kpf_bindfs_finish(struct mach_header_64 *hdr, checkrain_option_t *checkra1n_flags)
{
    // Signal to ramdisk whether we can have union mounts
    checkrain_set_option(*checkra1n_flags, checkrain_option_bind_mount, do_bind_mounts);
}

static uint32_t kpf_bindfs_size(void)
{
    if(!do_bind_mounts)
    {
        return 0;
    }
    return fsctl_shc_end - fsctl_shc;
}

static uint32_t kpf_bindfs_emit(uint32_t *shellcode_area)
{
    if(!do_bind_mounts)
    {
        return 0;
    }

    uint64_t shellcode_addr = xnu_ptr_to_va(shellcode_area);
    uint64_t patchpoint_addr = xnu_ptr_to_va(fsctl_patchpoint);
    uint64_t orig_func = patchpoint_addr + 4;

    size_t slow_idx  = fsctl_shc_stolen_slowpath - fsctl_shc;
    size_t fast_idx  = fsctl_shc_stolen_fastpath - fsctl_shc;
    size_t open_idx  = fsctl_shc_vnode_open      - fsctl_shc;
    size_t close_idx = fsctl_shc_vnode_close     - fsctl_shc;
    size_t bl_idx    = fsctl_shc_orig_bl         - fsctl_shc;
    size_t b_idx     = fsctl_shc_orig_b          - fsctl_shc;

    int64_t open_off  = vnode_open_addr  - (shellcode_addr + (open_idx  << 2));
    int64_t close_off = vnode_close_addr - (shellcode_addr + (close_idx << 2));
    int64_t bl_off    = orig_func - (shellcode_addr + (bl_idx << 2));
    int64_t b_off     = orig_func - (shellcode_addr + (b_idx  << 2));
    int64_t patch_off = shellcode_addr - patchpoint_addr;
    if(
        open_off  > 0x7fffffcLL || open_off  < -0x8000000LL ||
        close_off > 0x7fffffcLL || close_off < -0x8000000LL ||
        bl_off    > 0x7fffffcLL || bl_off    < -0x8000000LL ||
        b_off     > 0x7fffffcLL || b_off     < -0x8000000LL ||
        patch_off > 0x7fffffcLL || patch_off < -0x8000000LL
    )
    {
        panic("fsctl_patch jump too far: 0x%llx/0x%llx/0x%llx/0x%llx/0x%llx", open_off, close_off, bl_off, b_off, patch_off);
    }

    memcpy(shellcode_area, fsctl_shc, (uintptr_t)fsctl_shc_end - (uintptr_t)fsctl_shc);

    uint32_t stolen = *fsctl_patchpoint;
    shellcode_area[slow_idx]   = stolen;
    shellcode_area[fast_idx]   = stolen;
    shellcode_area[open_idx]  |= (open_off  >> 2) & 0x03ffffff;
    shellcode_area[close_idx] |= (close_off >> 2) & 0x03ffffff;
    shellcode_area[bl_idx]    |= (bl_off    >> 2) & 0x03ffffff;
    shellcode_area[b_idx]     |= (b_off     >> 2) & 0x03ffffff;

    *fsctl_patchpoint = 0x14000000 | ((patch_off >> 2) & 0x03ffffff);

    return fsctl_shc_end - fsctl_shc;
}

kpf_component_t kpf_bindfs =
{
    .init = kpf_bindfs_init,
    .finish = kpf_bindfs_finish,
    .shc_size = kpf_bindfs_size,
    .shc_emit = kpf_bindfs_emit,
    .patches =
    {
        { NULL, "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_bindfs_patches },
        {},
    },
};
