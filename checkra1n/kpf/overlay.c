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
#include <stdlib.h>
#include <string.h>

extern uint32_t kdi_shc[], kdi_shc_orig[], kdi_shc_get[], kdi_shc_addr[], kdi_shc_size[], kdi_shc_new[], kdi_shc_set[], kdi_shc_end[];

static bool did_run = false;
static bool do_patchfind = false;
static bool do_shellcode = false;

static void *overlay_buf = NULL;
static uint32_t overlay_size = 0;

static uint32_t *kdi_patchpoint = NULL;
static uint16_t OSDictionary_getObject_idx = 0, OSDictionary_setObject_idx = 0;
static uint64_t IOMemoryDescriptor_withAddress = 0;

static bool kpf_overlay_iomemdesc_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    if(IOMemoryDescriptor_withAddress)
    {
        panic("kpf_overlay: Ambiguous callsites to IOMemoryDescriptor::withAddress");
    }
    uint32_t *bl = opcode_stream + 2;
    IOMemoryDescriptor_withAddress = xnu_ptr_to_va(bl) + (sxt32(*bl, 26) << 2);
    puts("KPF: Found IOMemoryDescriptor");
    return true;
}

static void kpf_overlay_iomemdesc(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    uint64_t matches[] =
    {
        0x52800601, // mov w1, 0x30
        0x52800062, // mov w2, 3
        0x14000000, // b IOMemoryDescriptor::withAddress
    };
    uint64_t masks[] =
    {
        0xffffffff,
        0xffffffff,
        0xfc000000,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "iomemdesc", matches, masks, sizeof(matches)/sizeof(uint64_t), false, (void*)kpf_overlay_iomemdesc_callback);

    matches[0] = 0x321c07e1; // orr w1, wzr, 0x30
    matches[1] = 0x320007e2; // orr w2, wzr, 3
    xnu_pf_maskmatch(xnu_text_exec_patchset, "iomemdesc", matches, masks, sizeof(matches)/sizeof(uint64_t), false, (void*)kpf_overlay_iomemdesc_callback);
}

static bool kpf_overlay_kdi_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    uint64_t page = ((uint64_t)(opcode_stream + 1) & ~0xfffULL) + adrp_off(opcode_stream[1]);
    uint32_t off = (opcode_stream[2] >> 10) & 0xfff;
    const char *str = (const char*)(page + off);

    if(strcmp(str, "image-secrets") == 0)
    {
        if(!OSDictionary_getObject_idx) // first match
        {
            OSDictionary_getObject_idx = (opcode_stream[0] >> 10) & 0xfff;
        }
        else // second match
        {
            uint32_t *blr = find_next_insn(opcode_stream + 3, 5, 0xd63f0100, 0xffffffff); // blr x8
            if(!blr)
            {
                return false;
            }
            uint32_t *bl = find_next_insn(blr + 1, 8, 0x94000000, 0xfc000000); // bl
            if(!bl || (bl[1] & 0xff00001f) != 0xb5000000) // cbnz x0
            {
                return false;
            }
            kdi_patchpoint = bl;
        }
    }
    else if(strcmp(str, "netboot-image") == 0)
    {
        OSDictionary_setObject_idx = (opcode_stream[0] >> 10) & 0xfff;
    }
    else
    {
        return false;
    }

    // Return true once all found
    if(kdi_patchpoint != NULL && OSDictionary_getObject_idx != 0 && OSDictionary_setObject_idx != 0)
    {
        puts("KPF: Found KDI");
        return true;
    }
    return false;
}

static void kpf_overlay_kdi_patch(xnu_pf_patchset_t *kdi_text_exec_patchset)
{
    uint64_t matches[] =
    {
        0xf9400108, // ldr x8, [x8, 0x...]
        0x90000001, // adrp x1, 0x...
        0x91000021, // add x1, x1, 0x...
    };
    uint64_t masks[] =
    {
        0xffc003ff,
        0x9f00001f,
        0xffc003ff,
    };
    xnu_pf_maskmatch(kdi_text_exec_patchset, "KDI", matches, masks, sizeof(matches)/sizeof(uint64_t), true, (void*)kpf_overlay_kdi_callback);
}

static void kpf_overlay_xnu_patches(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    if(do_patchfind)
    {
        kpf_overlay_iomemdesc(xnu_text_exec_patchset);
    }
}

static void kpf_overlay_kdi_patches(xnu_pf_patchset_t *kdi_text_exec_patchset)
{
    if(do_patchfind)
    {
        kpf_overlay_kdi_patch(kdi_text_exec_patchset);
    }
}

static void kpf_overlay_init(struct mach_header_64 *hdr, xnu_pf_range_t *cstring, checkrain_option_t kpf_flags, checkrain_option_t checkra1n_flags)
{
    did_run = true;

    // Do this unconditionally on DEV_BUILD
    // TODO: Turn this into flags somehow.
#ifdef DEV_BUILD
    do_patchfind = true;
#else
    do_patchfind = overlay_size > 0;
#endif
    do_shellcode = overlay_size > 0;
}

static void kpf_overlay_finish(struct mach_header_64 *hdr, checkrain_option_t *checkra1n_flags)
{
    checkrain_set_option(*checkra1n_flags, checkrain_option_overlay, do_shellcode);
}

static uint32_t kpf_overlay_size(void)
{
    if(!do_shellcode)
    {
        return 0;
    }
    return kdi_shc_end - kdi_shc;
}

static uint32_t kpf_overlay_emit(uint32_t *shellcode_area)
{
    // Check this here, before we decide whether to actually emit shellcode.
    if(do_patchfind && !IOMemoryDescriptor_withAddress)
    {
        panic("Missing patch: IOMemoryDescriptor");
    }

    if(!do_shellcode)
    {
        return 0;
    }

    void *ov_static_buf = alloc_static(overlay_size);
    printf("Allocated static region for overlay: %p, sz: 0x%x\n", ov_static_buf, overlay_size);
    memcpy(ov_static_buf, overlay_buf, overlay_size);

    uint64_t overlay_addr = xnu_ptr_to_va(ov_static_buf);
    uint64_t shellcode_addr = xnu_ptr_to_va(shellcode_area);
    uint64_t patchpoint_addr = xnu_ptr_to_va(kdi_patchpoint);
    uint64_t orig_func = patchpoint_addr + (sxt32(*kdi_patchpoint, 26) << 2);

    size_t orig_idx = kdi_shc_orig - kdi_shc;
    size_t get_idx  = kdi_shc_get  - kdi_shc;
    size_t set_idx  = kdi_shc_set  - kdi_shc;
    size_t new_idx  = kdi_shc_new  - kdi_shc;
    size_t addr_idx = kdi_shc_addr - kdi_shc;
    size_t size_idx = kdi_shc_size - kdi_shc;

    int64_t orig_off  = orig_func - (shellcode_addr + (orig_idx << 2));
    int64_t new_off   = IOMemoryDescriptor_withAddress - (shellcode_addr + (new_idx << 2));
    int64_t patch_off = shellcode_addr - patchpoint_addr;
    if(orig_off > 0x7fffffcLL || orig_off < -0x8000000LL || new_off > 0x7fffffcLL || new_off < -0x8000000LL || patch_off > 0x7fffffcLL || patch_off < -0x8000000LL)
    {
        panic("kdi_patch jump too far: 0x%llx/0x%llx/0x%llx", orig_off, new_off, patch_off);
    }

    memcpy(shellcode_area, kdi_shc, (uintptr_t)kdi_shc_end - (uintptr_t)kdi_shc);

    shellcode_area[orig_idx] |= (orig_off >> 2) & 0x03ffffff;
    shellcode_area[get_idx]  |= OSDictionary_getObject_idx << 10;
    shellcode_area[set_idx]  |= OSDictionary_setObject_idx << 10;
    shellcode_area[new_idx]  |= (new_off >> 2) & 0x03ffffff;
    shellcode_area[addr_idx + 0] |= ((overlay_addr >> 48) & 0xffff) << 5;
    shellcode_area[addr_idx + 1] |= ((overlay_addr >> 32) & 0xffff) << 5;
    shellcode_area[addr_idx + 2] |= ((overlay_addr >> 16) & 0xffff) << 5;
    shellcode_area[addr_idx + 3] |= ((overlay_addr >>  0) & 0xffff) << 5;
    shellcode_area[size_idx + 0] |= ((overlay_size >> 16) & 0xffff) << 5;
    shellcode_area[size_idx + 1] |= ((overlay_size >>  0) & 0xffff) << 5;

    *kdi_patchpoint = 0x94000000 | ((patch_off >> 2) & 0x03ffffff);

    free(overlay_buf);
    overlay_buf = NULL;
    overlay_size = 0;

    return kdi_shc_end - kdi_shc;
}

void kpf_overlay_cmd(const char *cmd, char *args)
{
    if(did_run)
    {
        // TODO: Should this panic?
        //       Probably refactor if and when we ever get retval to pongoterm?
        puts("KPF ran already, overlay cannot be set anymore.");
        return;
    }
    if(!loader_xfer_recv_count)
    {
        puts("Please upload an overlay before issuing this command.");
        return;
    }
    if(overlay_buf)
    {
        free(overlay_buf);
    }
    overlay_buf = malloc(loader_xfer_recv_count);
    if(!overlay_buf)
    {
        panic("Failed to allocate heap for overlay");
    }
    overlay_size = loader_xfer_recv_count;
    memcpy(overlay_buf, loader_xfer_recv_data, overlay_size);
    loader_xfer_recv_count = 0;
}

kpf_component_t kpf_overlay =
{
    .init = kpf_overlay_init,
    .finish = kpf_overlay_finish,
    .shc_size = kpf_overlay_size,
    .shc_emit = kpf_overlay_emit,
    .patches =
    {
        { NULL,                          "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_overlay_xnu_patches },
        { "com.apple.driver.DiskImages", "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_overlay_kdi_patches },
        {},
    },
};
