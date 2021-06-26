/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2019-2021 checkra1n team
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

#include <pongo.h>
void (*preboot_hook)(void);

#ifndef jit_set_exec
#   define jit_set_exec(mode) /* nop by default */
#endif

extern void* jit_alloc(size_t count, size_t size);
extern void jit_free(void *mem);

/*

    Name: pongo_boot_hard
    Description: command handler for bootux

*/

void pongo_boot_hard(const char *cmd, char *args) {
    gBootFlag = BOOT_FLAG_HARD;
    task_yield();
}

/*

    Name: pongo_boot_hook
    Description: command handler for bootx

*/

void pongo_boot_hook(const char *cmd, char *args) {
    gBootFlag = BOOT_FLAG_HOOK;
    task_yield();
}

/*

    Name: pongo_copy_xnu
    Description: command handler for copyx

*/

void pongo_copy_xnu(const char *cmd, char *args) {
    if (!loader_xfer_recv_count) {
        iprintf("please upload a raw image before issuing this command\n");
        return;
    }

    uint64_t entryp = (uint64_t) gEntryPoint;
    uint64_t gImagePhys = entryp & (~0xFFF);
    gImagePhys += 0x4000;
#define DEVICE_TO_CACHEABLE(device) (device - 0x800000000 + kCacheableView)
    gImagePhys = DEVICE_TO_CACHEABLE(gImagePhys);
    while (1) {
        if (*(uint32_t*)gImagePhys == 0xfeedfacf) {
            break;
        }
        gImagePhys -= 0x1000;
    }

    memcpy((void*)gImagePhys, loader_xfer_recv_data, loader_xfer_recv_count);
    /* Note that we only do the copying over part here, you are expected to have to modify gEntryPoint
     * TODO: parse Mach-O header and set gEntryPoint value
     */
}

/*

    Name: pongo_boot_xargs
    Description: command handler for xargs

*/

void pongo_boot_xargs(const char* cmd, char* args) {
    if (args[0] == 0) {
        // get
        iprintf("Xnu boot arg cmdline: [%s]\n", (char*)((int64_t)gBootArgs->iOS13.CommandLine - 0x800000000 + kCacheableView) );
    } else {
        strcpy((char*)((int64_t)gBootArgs->iOS13.CommandLine - 0x800000000 + kCacheableView ), args);
        iprintf("Set xnu boot arg cmdline to: [%s]\n", (char*)((int64_t)gBootArgs->iOS13.CommandLine - 0x800000000 + kCacheableView ));
        if (strlen(args) > BOOT_LINE_LENGTH_iOS12) {
            iprintf("This exceeds the size limit for iOS 12 and earlier, you better be on 13 or later.\n");
        }
    }
}

_Static_assert(__builtin_offsetof(struct boot_args, deviceTreeLength) + 4 == __builtin_offsetof(struct boot_args, iOS13.CommandLine), "boot-args CommandLine offset");

// DTree printing


typedef struct
{
    const char *name;
    const char *prop;
    size_t size;
} dt_arg_t;
#define LOG(str, args...) do { iprintf(str "\n", ##args); } while(0)
#define REQ(expr) \
    do \
    { \
        if(!(expr)) \
        { \
            ERR("!(" #expr ")"); \
            goto out; \
        } \
    } while(0)

static int dt_cbn(void *a, dt_node_t *node)
{
    if(a != node)
    {
        LOG("--------------------------------------------------------------------------------------------------------------------------------");
    }
    return 0;
}

static int dt_cbp(void *a, dt_node_t *node, int depth, const char *key, void *val, uint32_t len)
{
    int retval = 0;
    dt_arg_t *arg = a;
    const char *prop = arg->prop;
    if(!prop || strncmp(prop, key, DT_KEY_LEN) == 0)
    {
        // Print name, if we're in single-prop mode and recursive
        if(depth >= 0 && prop && strcmp(key, "name") != 0)
        {
            uint32_t l = 0;
            void *v = dt_prop(node, "name", &l);
            if(v)
            {
                dt_arg_t tmp = *arg;
                tmp.prop = NULL;
                retval = dt_cbp(&tmp, node, depth, "name", v, l);
            }
        }
        if(depth < 0) depth = 0;
        bool printable = true;
        char *str = val;
        for(size_t i = 0; i < len; ++i)
        {
            char c = str[i];
            if((c < 0x20 || c >= 0x7f) && c != '\t' && c != '\n')
            {
                if(c == 0x0 && i == len - 1)
                {
                    continue;
                }
                printable = false;
                break;
            }
        }
        if(printable)
        {
            LOG("%*s%-*s %s", depth * 4, "", DT_KEY_LEN, key, str);
        }
        else if(len == 1 || len == 2 || len == 4) // 8 is usually not uint64
        {
            uint64_t v = 0;
            for(size_t i = 0; i < len; ++i)
            {
                uint8_t c = str[i];
                v |= (uint64_t)c << (i * 8);
            }
            LOG("%*s%-*s 0x%0*llx", depth * 4, "", DT_KEY_LEN, key, (int)len * 2, v);
        }
        else
        {
            const char *k = key;
            const char *hex = "0123456789abcdef";
            char xs[49] = {};
            char cs[17] = {};
            size_t sz = arg->size;
            if(sz == 8)
            {
                xs[0]  = xs[19] = '0';
                xs[1]  = xs[20] = 'x';
                xs[18] = xs[37] = ' ';
            }
            else if(sz == 4)
            {
                xs[0]  = xs[11] =          xs[23] = xs[34] = '0';
                xs[1]  = xs[12] =          xs[24] = xs[35] = 'x';
                xs[10] = xs[21] = xs[22] = xs[33] = xs[44] = ' ';
            }
            else
            {
                xs[2] = xs[5] = xs[8] = xs[11] = xs[14] = xs[17] = xs[20] = xs[23] = xs[24] = xs[27] = xs[30] = xs[33] = xs[36] = xs[39] = xs[42] = xs[45] = ' ';
            }
            size_t i;
            for(i = 0; i < len; ++i)
            {
                uint8_t c = str[i];
                size_t is = i % 0x10;
                size_t ix;
                if(sz == 8)
                {
                    ix = (is >= 0x8 ? 51 : 16) - (2 * is);
                }
                else if(sz == 4)
                {
                    ix = (is >= 0x8 ? (is >= 0xc ? 66 : 47) : (is >= 0x4 ? 27 : 8)) - (2 * is);
                }
                else
                {
                    ix = 3 * is + (is >= 0x8 ? 1 : 0);
                }
                xs[ix    ] = hex[(c >> 4) & 0xf];
                xs[ix + 1] = hex[(c     ) & 0xf];
                cs[is] = c >= 0x20 && c < 0x7f ? c : '.';
                if(is == 0xf)
                {
                    LOG("%*s%-*s %-*s  |%s|", depth * 4, "", DT_KEY_LEN, k, (int)sizeof(xs), xs, cs);
                    k = "";
                }
            }
            if((i % 0x10) != 0)
            {
                size_t is = i % 0x10;
                size_t ix;
                if(sz == 8)
                {
                    ix = (is >= 0x8 ? 51 : 16) - (2 * is);
                    xs[ix    ] = '0';
                    xs[ix + 1] = 'x';
                    for(size_t iz = is >= 0x8 ? 19 : 0; iz < ix; ++iz)
                    {
                        xs[iz] = ' ';
                    }
                    ix = is > 0x8 ? 37 : 18;
                }
                else if(sz == 4)
                {
                    ix = (is >= 0x8 ? (is >= 0xc ? 66 : 47) : (is >= 0x4 ? 27 : 8)) - (2 * is);
                    xs[ix    ] = '0';
                    xs[ix + 1] = 'x';
                    for(size_t iz = is >= 0x8 ? (is >= 0xc ? 34 : 23) : (is >= 0x4 ? 11 : 0); iz < ix; ++iz)
                    {
                        xs[iz] = ' ';
                    }
                    ix = is > 0x8 ? (is > 0xc ? 44 : 33) : (is > 0x4 ? 21 : 10);
                }
                else
                {
                    ix = 3 * is + (is >= 0x8 ? 1 : 0);
                }
                xs[ix] = '\0';
                cs[is] = '\0';
                LOG("%*s%-*s %-*s  |%s|", depth * 4, "", DT_KEY_LEN, k, (int)sizeof(xs), xs, cs);
            }
        }
    }
    return retval;
}
void log_bootargs(const char *cmd, char *args)
{
    struct boot_args* cBootArgs = (struct boot_args*)((uint64_t)gBootArgs - 0x800000000 + kCacheableView);
    iprintf("gBootArgs:\n"
            "\tRevision: 0x%x\n"
            "\tVersion: 0x%x\n"
            "\tvirtBase: 0x%llx\n"
            "\tphysBase 0x%llx\n"
            "\tmemSize: 0x%llx\n"
            "\ttopOfKernelData: 0x%llx\n"
            "\tmachineType: 0x%x\n"
            "\tdeviceTreeP: 0x%llx\n"
            "\tdeviceTreeLength: 0x%x\n"
            "\tCommandLine: 0x%s\n"
            "\tbootFlags (<=iOS12): 0x%llx\n"
            "\tmemSizeActual (<=iOS12): 0x%llx\n"
            "\tbootFlags (>=iOS13): 0x%llx\n"
            "\tmemSizeActual (>=iOS13): 0x%llx\n",
            cBootArgs->Revision,
            cBootArgs->Version,
            cBootArgs->virtBase,
            cBootArgs->physBase,
            cBootArgs->memSize,
            cBootArgs->topOfKernelData,
            cBootArgs->machineType,
            (uint64_t)cBootArgs->deviceTreeP,
            cBootArgs->deviceTreeLength,
            cBootArgs->iOS13.CommandLine,
            cBootArgs->iOS12.bootFlags,
            cBootArgs->iOS12.memSizeActual,
            cBootArgs->iOS13.bootFlags,
            cBootArgs->iOS13.memSizeActual);
}
void log_dtree(const char *cmd, char *args)
{
    //struct boot_args* cBootArgs = (struct boot_args*)((uint64_t)gBootArgs - 0x800000000 + kCacheableView);
    //iprintf("gBootArgs:\n\tRevision: %x\n\tVersion: %x\n\tvirtBase: %llx\n\tphysBase %llx\n\tmemSize: %llx\n\ttopOfKernelData: %llx\n\tmachineType: %x\n\tdeviceTreeP: %llx\n\tdeviceTreeLength: %x\n\tCommandLine: %s\n\tbootFlags: %llx\n\tmemSizeActual: %llx\n", cBootArgs->Revision, cBootArgs->Version, cBootArgs->virtBase, cBootArgs->physBase, cBootArgs->memSize, cBootArgs->topOfKernelData, cBootArgs->machineType, (uint64_t)cBootArgs->deviceTreeP, cBootArgs->deviceTreeLength, cBootArgs->CommandLine, cBootArgs->bootFlags, cBootArgs->memSizeActual);
    dt_arg_t arg =
    {
        .name = NULL,
        .prop = NULL,
        .size = 0xFFFF,
    };

    dt_parse(gDeviceTree, 0, NULL, &dt_cbn, gDeviceTree, &dt_cbp, &arg);
}

void flip_video_display(const char *cmd, char *args) {
    gBootArgs->Video.v_display = !gBootArgs->Video.v_display;
    if (!gBootArgs->Video.v_display) {
        iprintf("xnu now owns the framebuffer\n");
    } else {
        iprintf("xnu no longer owns the framebuffer\n");
    }
}

extern void* ramdisk_buf;
extern uint32_t ramdisk_size;

struct mach_header_64* xnu_header_cached;
struct mach_header_64* xnu_header(void) {
    if (xnu_header_cached) return xnu_header_cached;
    uint64_t entryp = (uint64_t) gEntryPoint;
    entryp -= 0x800000000 - kCacheableView;
    entryp &= ~0xfff;
    while (1) {
        if (*(uint32_t*) entryp == MH_MAGIC_64) {
            break;
        }
        entryp -= 0x1000;
    }
    xnu_header_cached = (struct mach_header_64*) entryp;
    return xnu_header_cached;
}

struct segment_command_64* macho_get_segment(struct mach_header_64* header, const char* segname) {
    struct load_command* lc;
    lc = (struct load_command*)(header + 1);
    for (int i = 0; i < header->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64* seg = (struct segment_command_64*)lc;
            if (strcmp(seg->segname, segname) == 0) {
                return seg;
            }
        }
        lc = (struct load_command*)(lc->cmdsize + (char*)lc);
    }
    return NULL;
}
struct section_64 *macho_get_section(struct segment_command_64 *seg, const char *name)
{
    struct section_64 *sect, *fs = NULL;
    uint32_t i = 0;
    for (i = 0, sect = (struct section_64 *)((uint64_t)seg + (uint64_t)sizeof(struct segment_command_64));
         i < seg->nsects;
         i++, sect = (struct section_64 *)((uint64_t)sect + sizeof(struct section_64)))
    {
        if (!strcmp(sect->sectname, name)) {
            fs = sect;
            break;
        }
    }
    return fs;
}

bool xnu_is_slid(struct mach_header_64* header) {
    struct segment_command_64* seg = macho_get_segment(header, "__TEXT");
    if (seg->vmaddr == 0xFFFFFFF007004000ULL) return false;
    return true;
}
uint64_t xnu_slide_hdr_va(struct mach_header_64* header, uint64_t hdr_va) {
    if (xnu_is_slid(header)) return hdr_va;

    uint64_t text_va_base = ((uint64_t) header) - kCacheableView + 0x800000000ULL - gBootArgs->physBase + gBootArgs->virtBase;
    uint64_t slide = text_va_base - 0xFFFFFFF007004000ULL;
    return hdr_va + slide;
}
uint64_t xnu_slide_value(struct mach_header_64* header) {
    uint64_t text_va_base = ((uint64_t) header) - kCacheableView + 0x800000000ULL - gBootArgs->physBase + gBootArgs->virtBase;
    uint64_t slide = text_va_base - 0xFFFFFFF007004000ULL;
    return slide;
}
void* xnu_va_to_ptr(uint64_t va) {
    return (void*)(va - gBootArgs->virtBase + gBootArgs->physBase - 0x800000000ULL + kCacheableView);
}
uint64_t xnu_ptr_to_va(void* ptr) {
    return ((uint64_t)ptr) - kCacheableView + 0x800000000ULL - gBootArgs->physBase + gBootArgs->virtBase;
}

// NOTE: iBoot-based rebase only applies to main XNU.
//       Kexts will never ever have been rebased when Pongo runs.
static bool has_been_rebased(void) {
    static int8_t rebase_status = -1;
    // First, determine whether we've been rebased. This feels really hacky, but it correctly covers all cases:
    //
    // 1. New-style kernels rebase themselves, so this is always false.
    // 2. Old-style kernels on a live device will always have been rebased.
    // 3. Old-style kernels on kpf-test will not have been rebase, but we use a slide of 0x0 there
    //    and the pointers are valid by themselves, so they can be treated as correctly rebased.
    //
    if(rebase_status == -1)
    {
        struct segment_command_64 *seg = macho_get_segment(xnu_header(), "__TEXT");
        struct section_64 *sec = seg ? macho_get_section(seg, "__thread_starts") : NULL;
        rebase_status = sec->size == 0 ? 1 : 0;
    }

    return rebase_status == 1;
}

uint64_t xnu_rebase_va(uint64_t va) {
    if(!has_been_rebased())
    {
        va = (uint64_t)(((int64_t)va << 13) >> 13) + xnu_slide_value(xnu_header());
    }
    return va;
}

uint64_t kext_rebase_va(uint64_t va) {
    if(!has_been_rebased())
    {
        va = (uint64_t)(((int64_t)va << 13) >> 13);
    }
    return va + xnu_slide_value(xnu_header());
}

xnu_pf_range_t* xnu_pf_range_from_va(uint64_t va, uint64_t size) {
    xnu_pf_range_t* range = malloc(sizeof(xnu_pf_range_t));
    range->va = va;
    range->size = size;
    range->cacheable_base = ((uint8_t*)(va - gBootArgs->virtBase + gBootArgs->physBase - 0x800000000ULL + kCacheableView));
    range->device_base = ((uint8_t*)(va - gBootArgs->virtBase + gBootArgs->physBase));
    return range;
}
xnu_pf_range_t* xnu_pf_segment(struct mach_header_64* header, char* segment_name) {
    struct segment_command_64* seg = macho_get_segment(header, segment_name);
    if (!seg) return NULL;

    if (header != xnu_header())
        return xnu_pf_range_from_va(xnu_slide_value(xnu_header()) + (0xffff000000000000 | seg->vmaddr), seg->filesize);
    return xnu_pf_range_from_va(xnu_slide_hdr_va(header, seg->vmaddr), seg->filesize);
}

xnu_pf_range_t* xnu_pf_section(struct mach_header_64* header, void* segment_name, char* section_name) {
    struct segment_command_64* seg = macho_get_segment(header, segment_name);
    if (!seg) return NULL;
    struct section_64* sec = macho_get_section(seg, section_name);
    if (!sec) return NULL;

    if (header != xnu_header())
        return xnu_pf_range_from_va(xnu_slide_value(xnu_header()) + (0xffff000000000000 | sec->addr), sec->size);

    return xnu_pf_range_from_va(xnu_slide_hdr_va(header, sec->addr), sec->size);
}
struct mach_header_64* xnu_pf_get_first_kext(struct mach_header_64* kheader) {
    xnu_pf_range_t* kmod_start_range = xnu_pf_section(kheader, "__PRELINK_INFO", "__kmod_start");
    if (!kmod_start_range) {
        kmod_start_range = xnu_pf_section(kheader, "__PRELINK_TEXT", "__text");
        if (!kmod_start_range) panic("unsupported xnu");
        struct mach_header_64* rv = (struct mach_header_64*)kmod_start_range->cacheable_base;
        free(kmod_start_range);
        return rv;
    }

    uint64_t* start = (uint64_t*)(kmod_start_range->cacheable_base);
    uint64_t kextb = xnu_slide_value(kheader) + (0xffff000000000000 | start[0]);

    free(kmod_start_range);
    return (struct mach_header_64*)xnu_va_to_ptr(kextb);
}
struct mach_header_64* xnu_pf_get_kext_header(struct mach_header_64* kheader, const char* kext_bundle_id) {
    xnu_pf_range_t* kmod_info_range = xnu_pf_section(kheader, "__PRELINK_INFO", "__kmod_info");
    if (!kmod_info_range) {
        char kname[256];
        xnu_pf_range_t* kext_info_range = xnu_pf_section(kheader, "__PRELINK_INFO", "__info");
        if (!kext_info_range) panic("unsupported xnu");

        const char* prelinkinfo = strstr((const char*)kext_info_range->cacheable_base, "PrelinkInfoDictionary");
        const char* last_dict = strstr(prelinkinfo, "<array>") + 7;
        while (last_dict) {
            const char* end_dict = strstr(last_dict, "</dict>");
            if (!end_dict) break;

            const char* nested_dict = strstr(last_dict+1, "<dict>");
            while (nested_dict) {
                if (nested_dict > end_dict) break;

                nested_dict = strstr(nested_dict+1, "<dict>");
                end_dict = strstr(end_dict+1, "</dict>");
            }


            const char* ident = memmem(last_dict, end_dict - last_dict, "CFBundleIdentifier", strlen("CFBundleIdentifier"));
            if (ident) {
                const char* value = strstr(ident, "<string>");
                if (value) {
                    value += strlen("<string>");
                    const char* value_end = strstr(value, "</string>");
                    if (value_end) {
                        memcpy(kname, value, value_end - value);
                        kname[value_end - value] = 0;
                        if (strcmp(kname, kext_bundle_id) == 0) {
                            const char* addr = memmem(last_dict, end_dict - last_dict, "_PrelinkExecutableLoadAddr", strlen("_PrelinkExecutableLoadAddr"));
                            if (addr) {
                                const char* avalue = strstr(addr, "<integer");
                                if (avalue) {
                                    avalue = strstr(avalue, ">");
                                    if (avalue) {
                                        avalue++;
                                        free(kext_info_range);
                                        return xnu_va_to_ptr(xnu_slide_value(kheader) + strtoull(avalue, 0, 0));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            last_dict = strstr(end_dict, "<dict>");
        }

        free(kext_info_range);
        return NULL;
    }
    xnu_pf_range_t* kmod_start_range = xnu_pf_section(kheader, "__PRELINK_INFO", "__kmod_start");
    if (!kmod_start_range) return NULL;

    uint64_t* info = (uint64_t*)(kmod_info_range->cacheable_base);
    uint64_t* start = (uint64_t*)(kmod_start_range->cacheable_base);
    uint32_t count = kmod_info_range->size / 8;
    for (uint32_t i=0; i<count; i++) {
        const char* kext_name = (const char*)xnu_va_to_ptr(xnu_slide_value(kheader) + (0xffff000000000000 | info[i])) + 0x10;
        if (strcmp(kext_name, kext_bundle_id) == 0) {
            free(kmod_info_range);
            free(kmod_start_range);
            return (struct mach_header_64*) xnu_va_to_ptr(xnu_slide_value(kheader) + (0xffff000000000000 | start[i]));
        }
    }

    free(kmod_info_range);
    free(kmod_start_range);
    return NULL;
}
void xnu_pf_apply_each_kext(struct mach_header_64* kheader, xnu_pf_patchset_t* patchset)
{
    xnu_pf_range_t* kmod_start_range = xnu_pf_section(kheader, "__PRELINK_INFO", "__kmod_start");
    if (!kmod_start_range) {
        xnu_pf_range_t* kext_text_exec_range = xnu_pf_section(kheader, "__PLK_TEXT_EXEC", "__text");
        if (!kext_text_exec_range) panic("unsupported xnu");
        xnu_pf_apply(kext_text_exec_range, patchset);
        free(kext_text_exec_range);
        return;
    }

    bool is_required = patchset->is_required;
    patchset->is_required = false;

    uint64_t* start = (uint64_t*)(kmod_start_range->cacheable_base);
    uint32_t count = kmod_start_range->size / 8;
    for (uint32_t i=0; i<count; i++) {
        struct mach_header_64* kexth = (struct mach_header_64*)xnu_va_to_ptr(xnu_slide_value(kheader) + (0xffff000000000000 | start[i]));
        xnu_pf_range_t* apply_range = xnu_pf_section(kexth, "__TEXT_EXEC", "__text");
        if (apply_range) {
            xnu_pf_apply(apply_range, patchset);
            free(apply_range);
        }
    }
    free(kmod_start_range);

    patchset->is_required = is_required;
    if(is_required)
    {
        for(xnu_pf_patch_t* patch = patchset->patch_head; patch; patch = patch->next_patch)
        {
            if(patch->is_required && !patch->has_fired)
            {
                panic("Missing patch: %s", patch->name);
            }
        }
    }
}
xnu_pf_range_t* xnu_pf_all(struct mach_header_64* header) {
    return NULL;
}
xnu_pf_range_t* xnu_pf_all_x(struct mach_header_64* header) {
    return NULL;
}
xnu_pf_patchset_t* xnu_pf_patchset_create(uint8_t pf_accesstype) {
    xnu_pf_patchset_t* r = malloc(sizeof(xnu_pf_patchset_t));
    r->patch_head = NULL;
    r->jit_matcher = NULL;
    r->accesstype = pf_accesstype;
    r->is_required = true;
    return r;
}
struct xnu_pf_maskmatch {
    xnu_pf_patch_t patch;
    uint32_t pair_count;
    uint64_t pairs[][2];
};
static inline bool xnu_pf_maskmatch_match_8(struct xnu_pf_maskmatch* patch, uint8_t access_type, uint8_t* preread, uint8_t* cacheable_stream) {
    uint32_t count = patch->pair_count;
    for (uint32_t i = 0; i < count; i++) {
        if (count < 8) {
            if ((preread[i] & patch->pairs[i][1]) != patch->pairs[i][0]) {
                return false;
            }
        } else {
            if ((cacheable_stream[i] & patch->pairs[i][1]) != patch->pairs[i][0]) {
                return false;
            }
        }
    }
    return true;
}
static inline bool xnu_pf_maskmatch_match_16(struct xnu_pf_maskmatch* patch, uint8_t access_type, uint16_t* preread, uint16_t* cacheable_stream) {
    uint32_t count = patch->pair_count;
    for (uint32_t i = 0; i < count; i++) {
        if (count < 8) {
            if ((preread[i] & patch->pairs[i][1]) != patch->pairs[i][0]) {
                return false;
            }
        } else {
            if ((cacheable_stream[i] & patch->pairs[i][1]) != patch->pairs[i][0]) {
                return false;
            }
        }
    }
    return true;
}
static inline bool xnu_pf_maskmatch_match_32(struct xnu_pf_maskmatch* patch, uint8_t access_type, uint32_t* preread, uint32_t* cacheable_stream) {
    uint32_t count = patch->pair_count;
    for (uint32_t i = 0; i < count; i++) {
        if (count < 8) {
            if ((preread[i] & patch->pairs[i][1]) != patch->pairs[i][0]) {
                return false;
            }
        } else {
            if ((cacheable_stream[i] & patch->pairs[i][1]) != patch->pairs[i][0]) {
                return false;
            }
        }
    }
    return true;
}
static inline bool xnu_pf_maskmatch_match_64(struct xnu_pf_maskmatch* patch, uint8_t access_type, uint64_t* preread, uint64_t* cacheable_stream) {
    uint32_t count = patch->pair_count;
    for (uint32_t i = 0; i < count; i++) {
        if (count < 8) {
            if ((preread[i] & patch->pairs[i][1]) != patch->pairs[i][0]) {
                return false;
            }
        } else {
            if ((cacheable_stream[i] & patch->pairs[i][1]) != patch->pairs[i][0]) {
                return false;
            }
        }
    }
    return true;
}
void xnu_pf_maskmatch_match(struct xnu_pf_maskmatch* patch, uint8_t access_type, void* preread, void* cacheable_stream) {
    bool val = false;
    switch (access_type) {
        case XNU_PF_ACCESS_8BIT:
        val = xnu_pf_maskmatch_match_8(patch,access_type,preread,cacheable_stream);
        break;
        case XNU_PF_ACCESS_16BIT:
        val = xnu_pf_maskmatch_match_16(patch,access_type,preread,cacheable_stream);
        break;
        case XNU_PF_ACCESS_32BIT:
        val = xnu_pf_maskmatch_match_32(patch,access_type,preread,cacheable_stream);
        break;
        case XNU_PF_ACCESS_64BIT:
        val = xnu_pf_maskmatch_match_64(patch,access_type,preread,cacheable_stream);
        break;
        default:
        break;
    }
    if (val) {
        jit_set_exec(0);
        if (patch->patch.pf_callback((struct xnu_pf_patch *)patch, cacheable_stream)) {
            patch->patch.has_fired = true;
        }
        jit_set_exec(1);
    }
}

struct xnu_pf_ptr_to_datamatch {
    xnu_pf_patch_t patch;
    void* data;
    size_t datasz;
    uint64_t slide;
    xnu_pf_range_t* range;
};

void xnu_pf_ptr_to_data_match(struct xnu_pf_ptr_to_datamatch* patch, uint8_t access_type, void* preread, void* cacheable_stream) {
    uint64_t pointer = *(uint64_t*)preread;
    pointer |= 0xffff000000000000;
    pointer += patch->slide;

    if (pointer >= patch->range->va && pointer < (patch->range->va + patch->range->size)) {
        if (memcmp(patch->data, (void*)(pointer - patch->range->va + patch->range->cacheable_base), patch->datasz) == 0) {
            jit_set_exec(0);
            if (patch->patch.pf_callback((struct xnu_pf_patch *)patch, cacheable_stream)) {
                patch->patch.has_fired = true;
            }
            jit_set_exec(1);
        }
    }
}
uint32_t* xnu_pf_maskmatch_emit(struct xnu_pf_maskmatch* patch, struct xnu_pf_patchset *patchset, uint32_t* insn_stream, uint32_t** insn_stream_end, uint8_t access_type);
xnu_pf_patch_t* xnu_pf_maskmatch(xnu_pf_patchset_t* patchset, char * name, uint64_t* matches, uint64_t* masks, uint32_t entryc, bool required, bool (*callback)(struct xnu_pf_patch* patch, void* cacheable_stream))
{
    // Sanity check
    for (uint32_t i=0; i<entryc; i++)
    {
        if((matches[i] & masks[i]) != matches[i])
        {
            panic("Bad maskmatch: %s (index %u)", name, i);
        }
    }

    struct xnu_pf_maskmatch* mm = malloc(sizeof(struct xnu_pf_maskmatch) + 16 * entryc);
    bzero(mm, sizeof(struct xnu_pf_maskmatch));
    mm->patch.should_match = true;
    mm->patch.pf_callback = (void*)callback;
    mm->patch.pf_emit = (void*)xnu_pf_maskmatch_emit;
    mm->patch.pf_match = (void*)xnu_pf_maskmatch_match;
    mm->patch.is_required = required;
    mm->patch.name = name;
    mm->pair_count = entryc;

    uint32_t loadc = entryc;
    if (loadc > 8) loadc = 8;

    extern uint32_t pf_jit_slowpath_start, pf_jit_slowpath_next, pf_jit_slowpath_end;
    mm->patch.pfjit_max_emit_size = (&pf_jit_slowpath_next - &pf_jit_slowpath_start) + ((patchset->accesstype >> 4) * 2 + 4) * loadc;
    mm->patch.pfjit_max_emit_size *= 4;

    for (uint32_t i=0; i<entryc; i++) {
        mm->pairs[i][0] = matches[i];
        mm->pairs[i][1] = masks[i];
    }

    mm->patch.next_patch = patchset->patch_head;
    patchset->patch_head = &mm->patch;
    return &mm->patch;
}
uint32_t* xnu_pf_ptr_to_data_emit(struct xnu_pf_ptr_to_datamatch* patch, struct xnu_pf_patchset *patchset, uint32_t* insn_stream, uint32_t** insn_stream_end, uint8_t access_type);
xnu_pf_patch_t* xnu_pf_ptr_to_data(xnu_pf_patchset_t* patchset, uint64_t slide, xnu_pf_range_t* range, void* data, size_t datasz, bool required, bool (*callback)(struct xnu_pf_patch* patch, void* cacheable_stream)) {
    struct xnu_pf_ptr_to_datamatch* mm = malloc(sizeof(struct xnu_pf_ptr_to_datamatch));
    bzero(mm, sizeof(struct xnu_pf_ptr_to_datamatch));
    mm->patch.should_match = true;
    mm->patch.pf_callback = (void*)callback;
    mm->patch.pf_emit = (void*)xnu_pf_ptr_to_data_emit;
    mm->patch.pf_match = (void*)xnu_pf_ptr_to_data_match;
    mm->patch.is_required = required;
    extern uint32_t pf_jit_ptr_comparison_start, pf_jit_ptr_comparison_next;
    mm->patch.pfjit_max_emit_size = (&pf_jit_ptr_comparison_next - &pf_jit_ptr_comparison_start) * 4 + 16 * 4 + 32;

    mm->slide = slide;
    mm->range = range;
    mm->data = data;
    mm->datasz = datasz;

    mm->patch.next_patch = patchset->patch_head;
    patchset->patch_head = &mm->patch;
    return &mm->patch;
}
uint32_t* xnu_pf_emit_insns(uint32_t* insn_stream, uint32_t* begin, uint32_t* end) {
    if (!insn_stream) return NULL;

    uint32_t delta = (end - begin);
    memcpy(insn_stream, begin, delta * 4);
    return &insn_stream[delta];
}
#define NOP 0xd503201f

uint32_t* xnu_pf_align3_emit(uint32_t* insn_stream) {
    if (((uint64_t)insn_stream) & 0x4) {
        *insn_stream++ = NOP;
    }
    return insn_stream;
}
uint32_t* xnu_pf_b_emit(uint32_t* insn_stream, uint32_t* target) {
    uint32_t delta = target - insn_stream;
    delta &= 0x03ffffff;
    delta |= 0x14000000;
    *insn_stream = delta;
    return insn_stream+1;
}
uint32_t* xnu_pf_b_eq_emit(uint32_t* insn_stream, uint32_t* target) {
    uint32_t delta = target - insn_stream;
    delta <<= 5;

    delta &= 0xFFFFE0;
    delta |= 0x54000000;

    *insn_stream = delta;
    return insn_stream+1;
}
uint32_t* xnu_pf_b_ne_emit(uint32_t* insn_stream, uint32_t* target) {
    uint32_t delta = target - insn_stream;
    delta <<= 5;

    delta &= 0xFFFFE0;
    delta |= 0x54000001;

    *insn_stream = delta;
    return insn_stream+1;
}
uint32_t* xnu_pf_cmp_emit(uint32_t* insn_stream, uint8_t reg1, uint8_t reg2) {
    *insn_stream = 0xEB00001F | (((uint32_t)(reg1 & 0x1F)) << 5)  | (((uint32_t)(reg2 & 0x1F)) << 16);
    return insn_stream+1;
}
uint32_t* xnu_pf_and_emit(uint32_t* insn_stream, uint8_t reg1, uint8_t reg2, uint8_t reg3) {
    *insn_stream = 0x8A000000 | ((uint32_t)(reg1 & 0x1F)) | (((uint32_t)(reg2 & 0x1F)) << 5)  | (((uint32_t)(reg3 & 0x1F)) << 16);
    return insn_stream+1;
}
uint32_t* xnu_pf_imm64_load_emit(uint32_t* insn_stream, uint8_t reg, uint64_t value) {

    *insn_stream++ = ((0x6940000 | (value & 0xFFFF)) << 5) | ((uint32_t)(reg & 0x1f));

    if ((value >> 16) & 0xFFFF) {
        *insn_stream++ = ((0x7950000 | ((value >> 16) & 0xFFFF)) << 5) | ((uint32_t)(reg & 0x1f));
    }
    if ((value >> 32) & 0xFFFF) {
        *insn_stream++ = ((0x7960000 | ((value >> 32) & 0xFFFF)) << 5) | ((uint32_t)(reg & 0x1f));
    }
    if ((value >> 48) & 0xFFFF) {
        *insn_stream++ = ((0x7970000 | ((value >> 48) & 0xFFFF)) << 5) | ((uint32_t)(reg & 0x1f));
    }

    return insn_stream;
}
void xnu_pf_disable_patch(xnu_pf_patch_t* patch) {
    if (!patch->should_match) return;
    patch->should_match = false;
    if (!patch->pfjit_entry) return;

    patch->pfjit_stolen_opcode = *patch->pfjit_entry;
    xnu_pf_b_emit(patch->pfjit_entry, patch->pfjit_exit);
    invalidate_icache();
}
void xnu_pf_enable_patch(xnu_pf_patch_t* patch) {
    if (patch->should_match) return;
    patch->should_match = true;

    if (!patch->pfjit_entry) return;
    *patch->pfjit_entry = patch->pfjit_stolen_opcode;
    invalidate_icache();
}

uint32_t* xnu_pf_ptr_to_data_emit(struct xnu_pf_ptr_to_datamatch* patch, struct xnu_pf_patchset *patchset, uint32_t* insn_stream, uint32_t** insn_stream_end, uint8_t access_type) {
    extern uint32_t pf_jit_ptr_comparison_start, pf_jit_ptr_comparison_end;
    patch->patch.pfjit_entry = insn_stream;

    insn_stream = xnu_pf_imm64_load_emit(insn_stream, 0, patch->range->va);
    insn_stream = xnu_pf_imm64_load_emit(insn_stream, 1, patch->range->va + patch->range->size);
    insn_stream = xnu_pf_imm64_load_emit(insn_stream, 2, 0xffff000000000000);
    insn_stream = xnu_pf_imm64_load_emit(insn_stream, 3, patch->slide);
    insn_stream = xnu_pf_align3_emit(insn_stream);
    insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_ptr_comparison_start, &pf_jit_ptr_comparison_end);


    ((uint64_t*)insn_stream)[0] = (uint64_t)patch;
    ((uint64_t*)insn_stream)[1] = (uint64_t)&xnu_pf_ptr_to_data_match;

    patch->patch.pfjit_exit = (uint32_t*)(&((uint64_t*)insn_stream)[2]);
    return patch->patch.pfjit_exit;
}

uint32_t* xnu_pf_maskmatch_emit(struct xnu_pf_maskmatch* patch, struct xnu_pf_patchset *patchset, uint32_t* insn_stream_insert, uint32_t** insn_stream_end, uint8_t access_type) {
    extern uint32_t pf_jit_slowpath_start, pf_jit_slowpath_next, pf_jit_slowpath_end;
    uint32_t slowpath_stub_size = &pf_jit_slowpath_next - &pf_jit_slowpath_start;
    uint32_t* slowpath_stub = *insn_stream_end;
    slowpath_stub -= slowpath_stub_size + 1;
    slowpath_stub = xnu_pf_align3_emit(slowpath_stub);
    uint64_t* slowpath_stub_args = (uint64_t*)xnu_pf_emit_insns(slowpath_stub, &pf_jit_slowpath_start, &pf_jit_slowpath_end);
    *insn_stream_end = slowpath_stub;

    slowpath_stub_args[0] = (uint64_t)patch;
    slowpath_stub_args[1] = (uint64_t)&xnu_pf_maskmatch_match;

    patch->patch.pfjit_entry = insn_stream_insert;

    uint32_t* prev_stub = slowpath_stub;

    uint32_t* linkage[8] = {0};

    //bool has_used_inline = false;
    uint32_t cap = patch->pair_count;

    //uint32_t* bailout_p;

    uint64_t and_nop = 0;
    switch (access_type) {
        case XNU_PF_ACCESS_8BIT:
        and_nop = 0xFF;
        break;
        case XNU_PF_ACCESS_16BIT:
        and_nop = 0xFFFF;
        break;
        case XNU_PF_ACCESS_32BIT:
        and_nop = 0xFFFFFFFF;
        break;
        case XNU_PF_ACCESS_64BIT:
        and_nop = 0xFFFFFFFFFFFFFFFF;
        break;
        default:
        panic("unk access");
        break;
    }

    if (cap > 8) cap = 8;
    int hi_entropy = -1;
    uint8_t highest_rating = 0;
    for (int i=0; i<cap; i++) {
        uint64_t cur_entropy = patch->pairs[i][0] ^ patch->pairs[i][1];
        uint8_t cur_rating = 0;
        bool last = true;
        for (int z=0; z<64; z++) {
            if (((cur_entropy >> z) & 1) != last) {
                cur_rating++;
                last = ((cur_entropy >> z) & 1);
            }
        }
        if (patch->pairs[i][0] == 0xD65F03C0ULL) {
            cur_rating >>= 3;
        }
        if (patch->pairs[i][1] == and_nop) {
            cur_rating <<= 2;
        }
        if (cur_rating > highest_rating) {
            highest_rating = cur_rating;
            hi_entropy = i;
        }
    }

    uint32_t jit_test[(4*2 + 4)];
    for (int i=0; i<cap; i++) {
        if (i == hi_entropy) {
            continue;
        }
        if (patch->pairs[i][1] == 0 && patch->pairs[i][0] == 0) {
            continue;
        }
        if (patch->pairs[i][1] == 0) {
            cap = 0;
            continue;
        }

        uint32_t* cmp_stub = &jit_test[0];
        uint32_t* cmp_stub_stream = cmp_stub;

        for (int i=0; i < (4 * 2 + 4); i++) {
            cmp_stub[i] = NOP;
        }
        uint8_t reg0 = 0;
        uint8_t reg1 = 1;
        if (patch->pairs[hi_entropy][0] == patch->pairs[i][0]) {
        } else {
            reg0 = 2;
            cmp_stub_stream = xnu_pf_imm64_load_emit(cmp_stub_stream, reg0, patch->pairs[i][0] & and_nop);
        }
        if (patch->pairs[i][1] != and_nop) {
            if (patch->pairs[hi_entropy][1] != and_nop && patch->pairs[hi_entropy][1] == patch->pairs[i][1]) {
            } else {
                reg1 = 3;
                cmp_stub_stream = xnu_pf_imm64_load_emit(cmp_stub_stream, reg1, patch->pairs[i][1] & and_nop);
            }
            cmp_stub_stream = xnu_pf_and_emit(cmp_stub_stream, 8, 20 + i, reg1);
            cmp_stub_stream = xnu_pf_cmp_emit(cmp_stub_stream, 8, reg0);
        } else {
            cmp_stub_stream = xnu_pf_cmp_emit(cmp_stub_stream, 20 + i, reg0);
        }

        uint32_t* cmp_stub_out = *insn_stream_end;
        uint32_t insnc = (cmp_stub_stream - cmp_stub);
        cmp_stub_out -= insnc + 1;
        *insn_stream_end = cmp_stub_out;
        for (int i=0; i < insnc; i++) {
            cmp_stub_out[i] = cmp_stub[i];
        }

        linkage[i] = &cmp_stub_out[insnc];

        prev_stub = cmp_stub_out;
    }

    if (cap) {
        if (!patchset->p0 || patchset->p0 != patch->pairs[hi_entropy][0]) {
            insn_stream_insert = xnu_pf_imm64_load_emit(insn_stream_insert, 0, patch->pairs[hi_entropy][0] & and_nop);
            patchset->p0 = patch->pairs[hi_entropy][0] & and_nop;
        }
        if (patch->pairs[hi_entropy][1] != and_nop) {
            insn_stream_insert = xnu_pf_imm64_load_emit(insn_stream_insert, 1, patch->pairs[hi_entropy][1] & and_nop);
            insn_stream_insert = xnu_pf_and_emit(insn_stream_insert, 8, 20 + hi_entropy, 1);
            insn_stream_insert = xnu_pf_cmp_emit(insn_stream_insert, 8, 0);
        } else {
            insn_stream_insert = xnu_pf_cmp_emit(insn_stream_insert, 20 + hi_entropy, 0);
        }
        insn_stream_insert = xnu_pf_b_eq_emit(insn_stream_insert, prev_stub);


        for (int i=0; i<cap; i++) {
            if (linkage[i])
                xnu_pf_b_ne_emit(linkage[i], insn_stream_insert);
        }
        xnu_pf_imm64_load_emit(&slowpath_stub[6], 0, patchset->p0);
        xnu_pf_b_emit(&slowpath_stub[10], insn_stream_insert); // bailout
    }

    patch->patch.pfjit_exit = insn_stream_insert;
    return patch->patch.pfjit_exit;
}

void xnu_pf_jit_dump(uint32_t* insn_start, uint32_t* insn_end) {
#ifndef XNU_PF_DUMP_JIT
    return;
#endif
    puts("==== KPFJIT DUMP START ====");
    while (insn_start < insn_end) {
        uint8_t bytes[4];
        memcpy(bytes, insn_start, 4);
        iprintf("%02x %02x %02x %02x\n", bytes[0], bytes[1], bytes[2], bytes[3]);
        insn_start++;
    }
    puts("==== KPFJIT DUMP END ====");
}
void xnu_pf_emit(xnu_pf_patchset_t* patchset) { // converts a patchset to JIT
    uint32_t* pf_iter_loop_head_start, *pf_iter_loop_head_end;
    uint32_t* pf_iter_loop_tail_start, *pf_iter_loop_tail_end;

    if (patchset->accesstype == XNU_PF_ACCESS_8BIT) {
        extern uint32_t pf_jit_iter_loop_iter_load8_start, pf_jit_iter_loop_iter_load8_end;
        extern uint32_t pf_jit_iter_loop_head_load8_start, pf_jit_iter_loop_head_load8_end;

        pf_iter_loop_head_start = &pf_jit_iter_loop_head_load8_start;
        pf_iter_loop_head_end = &pf_jit_iter_loop_head_load8_end;

        pf_iter_loop_tail_start = &pf_jit_iter_loop_iter_load8_start;
        pf_iter_loop_tail_end = &pf_jit_iter_loop_iter_load8_end;
    } else
    if (patchset->accesstype == XNU_PF_ACCESS_16BIT) {
        extern uint32_t pf_jit_iter_loop_iter_load16_start, pf_jit_iter_loop_iter_load16_end;
        extern uint32_t pf_jit_iter_loop_head_load16_start, pf_jit_iter_loop_head_load16_end;

        pf_iter_loop_head_start = &pf_jit_iter_loop_head_load16_start;
        pf_iter_loop_head_end = &pf_jit_iter_loop_head_load16_end;

        pf_iter_loop_tail_start = &pf_jit_iter_loop_iter_load16_start;
        pf_iter_loop_tail_end = &pf_jit_iter_loop_iter_load16_end;
    } else
    if (patchset->accesstype == XNU_PF_ACCESS_32BIT) {
        extern uint32_t pf_jit_iter_loop_iter_load32_start, pf_jit_iter_loop_iter_load32_end;
        extern uint32_t pf_jit_iter_loop_head_load32_start, pf_jit_iter_loop_head_load32_end;

        pf_iter_loop_head_start = &pf_jit_iter_loop_head_load32_start;
        pf_iter_loop_head_end = &pf_jit_iter_loop_head_load32_end;

        pf_iter_loop_tail_start = &pf_jit_iter_loop_iter_load32_start;
        pf_iter_loop_tail_end = &pf_jit_iter_loop_iter_load32_end;
    } else
    if (patchset->accesstype == XNU_PF_ACCESS_64BIT) {
        extern uint32_t pf_jit_iter_loop_iter_load64_start, pf_jit_iter_loop_iter_load64_end;
        extern uint32_t pf_jit_iter_loop_head_load64_start, pf_jit_iter_loop_head_load64_end;

        pf_iter_loop_head_start = &pf_jit_iter_loop_head_load64_start;
        pf_iter_loop_head_end = &pf_jit_iter_loop_head_load64_end;

        pf_iter_loop_tail_start = &pf_jit_iter_loop_iter_load64_start;
        pf_iter_loop_tail_end = &pf_jit_iter_loop_iter_load64_end;
    } else {
        puts("xnu_pf_jit does not support this access type");
        return;
    }

    xnu_pf_patch_t* patch = patchset->patch_head;
    uint32_t jit_size = 0x100;

    while (patch) {
        if (!patch->pf_emit) {
            puts("xnu_pf_jit doesn't support this patch");
            return;
        } else {
            jit_size += patch->pfjit_max_emit_size;
        }
        patch = patch->next_patch;
    }

    uint32_t* insn_stream = jit_alloc(jit_size,1);
    uint32_t* insn_stream_end = &insn_stream[jit_size >> 2];
    uint32_t* insn_stream_end_real = insn_stream_end;
    uint32_t* jit_entry = insn_stream;

    extern uint32_t pf_jit_iter_loop_head_start, pf_jit_iter_loop_head_end;
    insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_iter_loop_head_start, &pf_jit_iter_loop_head_end);

    insn_stream = xnu_pf_emit_insns(insn_stream, pf_iter_loop_head_start, pf_iter_loop_head_end);
    uint32_t* bailout = insn_stream;
    insn_stream++;

    uint32_t* loop_head = insn_stream;

    patch = patchset->patch_head;
    while (patch) {
        uint64_t pre_emit = (uint64_t)insn_stream;
        insn_stream = patch->pf_emit(patch, patchset, insn_stream, &insn_stream_end, patchset->accesstype);
        uint64_t post_emit = (uint64_t)insn_stream;
        if (post_emit - pre_emit > patch->pfjit_max_emit_size) {
            panic("pf_jit: jit overflow");
        }
        patch = patch->next_patch;
    }

    insn_stream = xnu_pf_emit_insns(insn_stream, pf_iter_loop_tail_start, pf_iter_loop_tail_end);
    insn_stream = xnu_pf_b_emit(insn_stream, loop_head);

    xnu_pf_b_emit(bailout, insn_stream);

    extern uint32_t pf_jit_iter_loop_end_start, pf_jit_iter_loop_end_end;
    insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_iter_loop_end_start, &pf_jit_iter_loop_end_end);
    invalidate_icache();
    xnu_pf_jit_dump(jit_entry, insn_stream_end_real);
    patchset->jit_matcher = (void*) jit_entry;
}

void xnu_pf_apply_8(xnu_pf_range_t* range, xnu_pf_patchset_t* patchset) {
    uint8_t* stream = (uint8_t*)range->cacheable_base;
    uint8_t reads[8];
    uint32_t stream_iters = range->size;
    for (int i=0; i<8; i++) {
        reads[i] = stream[i];
    }
    for (uint32_t index = 0; index < stream_iters; index++) {
        xnu_pf_patch_t* patch = patchset->patch_head;

        while (patch) {
            if (patch->should_match)
                patch->pf_match(patch, XNU_PF_ACCESS_8BIT, reads, &stream[index]);
            patch = patch->next_patch;
        }

        for (int i=0; i<7; i++) {
            reads[i] = reads[i + 1];
        }
        reads[7] = stream[index + 8];
    }
}
void xnu_pf_apply_16(xnu_pf_range_t* range, xnu_pf_patchset_t* patchset) {
    uint16_t* stream = (uint16_t*)range->cacheable_base;
    uint16_t reads[8];
    uint32_t stream_iters = range->size >> 1;
    for (int i=0; i<8; i++) {
        reads[i] = stream[i];
    }
    for (uint32_t index = 0; index < stream_iters; index++) {
        xnu_pf_patch_t* patch = patchset->patch_head;

        while (patch) {
            if (patch->should_match)
                patch->pf_match(patch, XNU_PF_ACCESS_16BIT, reads, &stream[index]);
            patch = patch->next_patch;
        }

        for (int i=0; i<7; i++) {
            reads[i] = reads[i + 1];
        }
        reads[7] = stream[index + 8];
    }
}
void xnu_pf_apply_32(xnu_pf_range_t* range, xnu_pf_patchset_t* patchset) {
    uint32_t* stream = (uint32_t*)range->cacheable_base;
    uint32_t reads[8];
    uint32_t stream_iters = range->size >> 2;
    for (int i=0; i<8; i++) {
        reads[i] = stream[i];
    }
    for (uint32_t index = 0; index < stream_iters; index++) {
        xnu_pf_patch_t* patch = patchset->patch_head;

        while (patch) {
            if (patch->should_match)
                patch->pf_match(patch, XNU_PF_ACCESS_32BIT, reads, &stream[index]);
            patch = patch->next_patch;
        }

        for (int i=0; i<7; i++) {
            reads[i] = reads[i + 1];
        }
        reads[7] = stream[index + 8];
    }
}
void xnu_pf_apply_64(xnu_pf_range_t* range, xnu_pf_patchset_t* patchset) {
    uint64_t* stream = (uint64_t*)range->cacheable_base;
    uint64_t reads[8];
    uint32_t stream_iters = range->size >> 2;
    for (int i=0; i<8; i++) {
        reads[i] = stream[i];
    }
    for (uint32_t index = 0; index < stream_iters; index++) {
        xnu_pf_patch_t* patch = patchset->patch_head;

        while (patch) {
            if (patch->should_match)
                patch->pf_match(patch, XNU_PF_ACCESS_64BIT, reads, &stream[index]);
            patch = patch->next_patch;
        }

        for (int i=0; i<7; i++) {
            reads[i] = reads[i + 1];
        }
        reads[7] = stream[index + 8];
    }
}
void xnu_pf_apply(xnu_pf_range_t* range, xnu_pf_patchset_t* patchset) {
    if (patchset->jit_matcher) {
        // use JIT fastpath

        void (*jit_match)(void* stream, void* stream_end);
        jit_match = (void*)patchset->jit_matcher;
        jit_set_exec(1);
        jit_match(range->cacheable_base, range->cacheable_base + range->size);
        jit_set_exec(0);
    } else {
        if (patchset->accesstype == XNU_PF_ACCESS_8BIT) xnu_pf_apply_8(range, patchset);
        else if (patchset->accesstype == XNU_PF_ACCESS_16BIT) xnu_pf_apply_16(range, patchset);
        else if (patchset->accesstype == XNU_PF_ACCESS_32BIT) xnu_pf_apply_32(range, patchset);
        else if (patchset->accesstype == XNU_PF_ACCESS_64BIT) xnu_pf_apply_64(range, patchset);
    }
    if(patchset->is_required)
    {
        for(xnu_pf_patch_t* patch = patchset->patch_head; patch; patch = patch->next_patch)
        {
            if(patch->is_required && !patch->has_fired)
            {
                panic("Missing patch: %s", patch->name);
            }
        }
    }
}
void xnu_pf_patchset_destroy(xnu_pf_patchset_t* patchset) {
    xnu_pf_patch_t* o_patch;
    xnu_pf_patch_t* patch = patchset->patch_head;
    while (patch) {
        o_patch = patch;
        patch = patch->next_patch;
        free(o_patch);
    }
    if (patchset->jit_matcher) jit_free(patchset->jit_matcher);
    free(patchset);
}
void xnu_boot(void) {
    uint64_t addr = socnum == 0x8960 ? 0x200000910 : 0x200000490;
    if(*(volatile uint32_t*)addr != 0x1)
    {
        panic("Cannot boot XNU with TZ0 unlocked");
    }
}

void xnu_init(void) {
    command_register("dt", "parses loaded devicetree", log_dtree);
    command_register("xargs", "prints or sets xnu boot-args", pongo_boot_xargs);
    command_register("loadx", "loads xnu", pongo_copy_xnu);
    command_register("bootx", "boots xnu (patched, if such a module is loaded)", pongo_boot_hook);
    command_register("bootux", "boots unpatched xnu", pongo_boot_hard);
    command_register("bootargs", "prints xnu bootargs struct", log_bootargs);
    command_register("xfb", "gives xnu access to the framebuffer (for -v or -s)", flip_video_display);
}

void xnu_hook(void) {
    if (preboot_hook) preboot_hook();
}

void xnu_loadrd(void) {
    if (ramdisk_size) {
        dt_node_t* memory_map = (dt_node_t*)dt_find(gDeviceTree, "memory-map");
        if (!memory_map) panic("invalid devicetree: no memory_map!");
        struct memmap* map = dt_alloc_memmap(memory_map, "RAMDisk");
        if (!map) panic("invalid devicetree: dt_alloc_memmap failed");

        void* rd_static_buf = alloc_static(ramdisk_size);
        iprintf("allocated static region for rdsk: %p, sz: %x\n", rd_static_buf, ramdisk_size);
        memcpy(rd_static_buf, ramdisk_buf, ramdisk_size);

        struct memmap md0map;
        md0map.addr = ((uint64_t)rd_static_buf) + 0x800000000 - kCacheableView;
        md0map.size = ramdisk_size;
        memcpy(map, &md0map, 0x10);
    }
}
