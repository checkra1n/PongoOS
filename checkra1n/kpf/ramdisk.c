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
#include <paleinfo.h>
#include <pongo.h>
#include <xnu/xnu.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static bool have_ramdisk = false;
static char *rootdev_bootarg = NULL;
static uint32_t *rootdev_patchpoint = NULL;
static int32_t fakefs_offset = 0;

static bool kpf_rootdev_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    uint32_t adrp = opcode_stream[0],
             add  = opcode_stream[1];
    const char *str = (const char *)(((uint64_t)(opcode_stream) & ~0xfffULL) + adrp_off(adrp) + ((add >> 10) & 0xfff));
    if(strcmp(str, "rootdev") != 0)
    {
        return false;
    }

    // Make sure this is the correct match
    uint32_t *bl = find_next_insn(opcode_stream + 2, 6, 0x94000000, 0xfc000000);
    if(!bl || (bl[1] & 0xff00001f) != 0x35000000 || (bl[2] & 0xfffffe1f) != 0x3900021f) // cbnz w0, ...; strb wzr, [x{16-31}]
    {
        return false;
    }

    if(rootdev_patchpoint)
    {
        panic("kpf_rootdev: Found twice");
    }
    rootdev_patchpoint = opcode_stream;

    puts("KPF: Found rootdev");
    return true;
}

static void kpf_rootdev_patch(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    // A ton of kexts check for "rd=md*" and "rootdev=md*" in order to determine whether we're restoring.
    // We previously tried to patch all of those, but that is really tedious to do, and it's basically
    // impossible to determine whether you found all instances.
    // What we do now is just change the place that actually boots off the ramdisk from "rootdev" to "spartan",
    // and then patch the boot-args string to reflect that.
    //
    // Because codegen orders function args differently across versions and may or may not inline stuff,
    // we just match adrp+add to either x0 or x1, and check the string and the rest in the callback.
    //
    // /x 0000009000000091:1e00009fde03c0ff
    uint64_t matches[] =
    {
        0x90000000, // adrp x{0|1}, 0x...
        0x91000000, // add x{0|1}, x{0|1}, 0x...
    };
    uint64_t masks[] =
    {
        0x9f00001e,
        0xffc003de,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "rootdev", matches, masks, sizeof(matches)/sizeof(uint64_t), true, (void*)kpf_rootdev_callback);
}

static void kpf_ramdisk_patches(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    if(have_ramdisk)
    {
        kpf_rootdev_patch(xnu_text_exec_patchset);
    }
}


extern palerain_option_t palera1n_flags;

static bool gHasConstriants = false;
extern struct kernel_version gKernelVersion;

static void kpf_ramdisk_init(struct mach_header_64 *hdr, xnu_pf_range_t *cstring, palerain_option_t palera1n_flags)
{
    char *bootargs = (char*)((uintptr_t)gBootArgs->iOS13.CommandLine - 0x800000000 + kCacheableView);
    rootdev_bootarg = strstr(bootargs, "rootdev=");
    if(rootdev_bootarg > bootargs && rootdev_bootarg[-1] != ' ' && rootdev_bootarg[-1] != '\t')
    {
        rootdev_bootarg = NULL;
    }
    
    const char constraints_string[] = "mac_proc_check_launch_constraints";
    const char *constraints_string_match = memmem(cstring->cacheable_base, cstring->size, constraints_string, sizeof(constraints_string));
    gHasConstriants = (constraints_string_match != NULL);

    if (gKernelVersion.xnuMajor >= 10002 /* iOS 17 */
    && strstr(gKernelVersion.kernel_version_string, "root:xnu-10002.0.40.") == NULL /* iOS 17.0 beta 1 */) {
        if (xnu_platform() == PLATFORM_IOS) fakefs_offset = 1;
    }

    if (gKernelVersion.xnuMajor >= 11215 && xnu_platform() == PLATFORM_IOS) fakefs_offset++; /* iOS 18+ */

#ifdef DEV_BUILD
    have_ramdisk = true;
#else
    have_ramdisk = rootdev_bootarg != NULL;
#endif
}

#if !defined(KPF_TEST)
static const char* disk_prefix(void) {
    if (gKernelVersion.darwinMajor >= 19) {
        if (xnu_platform() == PLATFORM_TVOS) {
            if (gHasConstriants) {
                return "disk2s";
            } else {
                return "disk0s2s";
            }
        } else {
            if (gHasConstriants) {
                return "disk1s";
            } else {
                return "disk0s1s";
            }
        }
    } else {
        return "disk0s1s";
    }
}
#endif

static void kpf_ramdisk_bootprep(struct mach_header_64 *hdr, palerain_option_t palera1n_flags)
{

    if(rootdev_bootarg)
    {
        memcpy(rootdev_bootarg, "spartan", 7); // rootdev -> spartan
    }

#if defined(KPF_TEST)
    char BSDName[16] = "disk0s1s1";
#else
    char BSDName[16];
    uint32_t partid = 1;
    /* have SSV and rootful */
    if ((palera1n_flags & (palerain_option_rootful | palerain_option_ssv)) == (palerain_option_rootful | palerain_option_ssv)) {
        dt_node_t* chosen = dt_find(gDeviceTree, "chosen");
        if (!chosen) panic("invalid devicetree: no device!");
        size_t nvram_proxy_data_len = 0;
        char* nvram_proxy_data = dt_prop(chosen, "nvram-proxy-data", &nvram_proxy_data_len);
        if (!nvram_proxy_data) panic("invalid devicetree: no /chosen/nvram-proxy-data!");
        char* nvram_rootdev = memmem(nvram_proxy_data, nvram_proxy_data_len, "p1-fakefs-rootdev=", 18);
        if (nvram_rootdev) snprintf(BSDName, 16, "%s", &nvram_rootdev[18]);

        size_t root_matching_len = 0;
        char* root_matching = dt_prop(chosen, "root-matching", &root_matching_len);
        if (!root_matching) panic("invalid devicetree: no prop!");
        if (!nvram_rootdev) {
            dt_node_t* fstab = dt_find(gDeviceTree, "fstab");
            if (!fstab) panic("invalid devicetree: no fstab!"); /* iOS 12 and below should not have SSV */
            size_t max_fs_entries_len = 0;
            uint32_t* max_fs_entries = dt_prop(fstab, "max_fs_entries", &max_fs_entries_len);
            if (!max_fs_entries) panic("invalid devicetree: no prop!");
            uint32_t* patch = (uint32_t*)max_fs_entries;
            printf("fstab max_fs_entries: %016" PRIx64 ": %08x\n", (uint64_t)max_fs_entries, patch[0]);
            dt_node_t* baseband = dt_find(gDeviceTree, "baseband");
            if (baseband) partid = patch[0] + 1U;
            else partid = patch[0];
            if (socnum == 0x7000 || socnum == 0x7001) partid--;
            partid += fakefs_offset;
            snprintf(BSDName, 16, "%s%" PRIu32, disk_prefix(), partid);
        }
        /* Don't root from fakefs during fakefs setup or force revert */
        if ((palera1n_flags & (palerain_option_setup_rootful | palerain_option_force_revert)) == 0)
        snprintf(root_matching, root_matching_len, 
            "<dict ID=\"0\"><key>IOProviderClass</key><string ID=\"1\">IOService</string><key>BSD Name</key><string ID=\"2\">%s</string></dict>",
            BSDName);
        else
            printf("KPF: rooting from original rootfs for fakefs setup or force revert\n");
        printf("KPF: root BSD Name: %s\n", BSDName);
        printf("KPF: root_matching (raw): %s\n", root_matching);
    } else {
        snprintf(BSDName, 16, "%s%" PRIu32, disk_prefix() , partid);
        printf("KPF: root BSD Name: %s\n", BSDName);
    }
#endif

    if(ramdisk_size)
    {
        puts("KPF: Found ramdisk, appending paleinfo");
        uint64_t slide = xnu_slide_value(hdr);

        ramdisk_buf = realloc(ramdisk_buf, ramdisk_size + 0x10000);
        if(!ramdisk_buf)
        {
            panic("Failed to reallocate ramdisk with paleinfo");
        }

        struct paleinfo* pinfo_p = (struct paleinfo*)(ramdisk_buf + ramdisk_size);
        *pinfo_p = (struct paleinfo)
        {
            .magic = 'PLSH',
            .version = 2,
            .kbase  = slide + 0xfffffff007004000,
            .kslide = slide,
            .flags = palera1n_flags,
        };
        snprintf(pinfo_p->rootdev, 16, "%s", BSDName);

        *(uint32_t*)(ramdisk_buf) = ramdisk_size;
        ramdisk_size += 0x10000;
    }
}

static uint32_t kpf_ramdisk_size(void)
{
    if(!have_ramdisk)
    {
        return 0;
    }
    return 2;
}

static uint32_t kpf_ramdisk_emit(uint32_t *shellcode_area)
{
    if(!have_ramdisk)
    {
        return 0;
    }

    // We emit a new string because it's possible that strings have
    // been merged with kexts, and we don't wanna patch those.
    const char str[] = "spartan";
    memcpy(shellcode_area, str, sizeof(str));

    uint64_t shellcode_addr  = xnu_ptr_to_va(shellcode_area);
    uint64_t patchpoint_addr = xnu_ptr_to_va(rootdev_patchpoint);

    uint64_t shellcode_page  = shellcode_addr  & ~0xfffULL;
    uint64_t patchpoint_page = patchpoint_addr & ~0xfffULL;

    int64_t pagediff = (shellcode_page - patchpoint_page) >> 12;

    rootdev_patchpoint[0] = (rootdev_patchpoint[0] & 0x9f00001f) | ((pagediff & 0x3) << 29) | (((pagediff >> 2) & 0x7ffff) << 5);
    rootdev_patchpoint[1] = (rootdev_patchpoint[1] & 0xffc003ff) | ((shellcode_addr & 0xfff) << 10);

    return 2;
}

kpf_component_t kpf_ramdisk =
{
    .init = kpf_ramdisk_init,
    .bootprep = kpf_ramdisk_bootprep,
    .shc_size = kpf_ramdisk_size,
    .shc_emit = kpf_ramdisk_emit,
    .patches =
    {
        { NULL, "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_ramdisk_patches },
        {},
    },
};
