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

static bool do_bind_mounts = false;

static bool kpf_shared_region_root_dir_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    static bool found_shared_region_root_dir = false;
    if(found_shared_region_root_dir)
    {
        panic("kpf_shared_region_root_dir: Found twice");
    }

    opcode_stream[4] = 0xeb00001f; // cmp x0, x0
    found_shared_region_root_dir = true;

    puts("KPF: Found shared region root dir");
    return true;
}

static void kpf_shared_region_root_dir_patch(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    // Doing bind mounts means the shared cache is not on the volume mounted at /.
    // XNU has a check to require that though, so we patch that out.
    //
    // 0xfffffff007dcabc8      001140f9       ldr x0, [x8, 0x20]
    // 0xfffffff007dcabcc      086c40f9       ldr x8, [x0, 0xd8]
    // 0xfffffff007dcabd0      e91b40f9       ldr x9, [sp, 0x30]
    // 0xfffffff007dcabd4      296d40f9       ldr x9, [x9, 0xd8]
    // 0xfffffff007dcabd8      1f0109eb       cmp x8, x9
    // 0xfffffff007dcabdc      210f0054       b.ne 0xfffffff007dcadc0
    //
    // /x 001040f9086c40f9e90340f9296d40f91f0109eb00000054:1ffcffffffffffffff03c0ffffffffffffffffff1e0000ff
    uint64_t matches[] =
    {
        0xf9401000, // ldr x0, [x*, 0x20]
        0xf9406c08, // ldr x8, [x0, 0xd8]
        0xf94003e9, // ldr x9, [sp, 0x...]
        0xf9406d29, // ldr x9, [x9, 0xd8]
        0xeb09011f, // cmp x8, x9
        0x54000000, // b.{eq|ne} 0x...
    };
    uint64_t masks[] =
    {
        0xfffffc1f,
        0xffffffff,
        0xffc003ff,
        0xffffffff,
        0xffffffff,
        0xff00001e,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "shared_region_root_dir", matches, masks, sizeof(matches)/sizeof(uint64_t), false, (void*)kpf_shared_region_root_dir_callback);
}

static void kpf_bindfs_patches(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    // iOS 15.0: Union mounts no longer work
    if(do_bind_mounts)
    {
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
    // Signal to ramdisk that we can't have union mounts
    checkrain_set_option(*checkra1n_flags, checkrain_option_bind_mount, do_bind_mounts);
}

kpf_component_t kpf_bindfs =
{
    .init = kpf_bindfs_init,
    .finish = kpf_bindfs_finish,
    .patches =
    {
        { NULL, "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_bindfs_patches },
        {},
    },
};
