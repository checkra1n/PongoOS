// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
//
//  Copyright (c) 2020 checkra1n team
//  This file is part of pongoOS.
//

#define LL_KTRW_INTERNAL 1
#include <pongo.h>
void (*preboot_hook)();

/*

    Name: pongo_boot_hard
    Description: command handler for bootux

*/

void pongo_boot_hard() {
    gBootFlag = BOOT_FLAG_HARD;
    task_yield();
}

/*

    Name: pongo_boot_hook
    Description: command handler for bootx

*/

void pongo_boot_hook() {
    gBootFlag = BOOT_FLAG_HOOK;
    task_yield();
}

/*

    Name: pongo_copy_xnu
    Description: command handler for copyx

*/

void pongo_copy_xnu() {
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
        iprintf("xnu boot arg cmdline: [%s]\n", (char*)((int64_t)gBootArgs->CommandLine - 0x800000000 + kCacheableView) );
    } else {
        strcpy((char*)((int64_t)gBootArgs->CommandLine - 0x800000000 + kCacheableView ), args);
        iprintf("set xnu boot arg cmdline to: [%s]\n", (char*)((int64_t)gBootArgs->CommandLine - 0x800000000 + kCacheableView ));
    }
}


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
void log_bootargs() 
{
    struct boot_args* cBootArgs = (struct boot_args*)((uint64_t)gBootArgs - 0x800000000 + kCacheableView);
    iprintf("gBootArgs:\n\tRevision: %x\n\tVersion: %x\n\tvirtBase: %llx\n\tphysBase %llx\n\tmemSize: %llx\n\ttopOfKernelData: %llx\n\tmachineType: %x\n\tdeviceTreeP: %llx\n\tdeviceTreeLength: %x\n\tCommandLine: %s\n\tbootFlags: %llx\n\tmemSizeActual: %llx\n", cBootArgs->Revision, cBootArgs->Version, cBootArgs->virtBase, cBootArgs->physBase, cBootArgs->memSize, cBootArgs->topOfKernelData, cBootArgs->machineType, (uint64_t)cBootArgs->deviceTreeP, cBootArgs->deviceTreeLength, &cBootArgs->CommandLine, cBootArgs->bootFlags, cBootArgs->memSizeActual);
}
void log_dtree()
{
    struct boot_args* cBootArgs = (struct boot_args*)((uint64_t)gBootArgs - 0x800000000 + kCacheableView);
    iprintf("gBootArgs:\n\tRevision: %x\n\tVersion: %x\n\tvirtBase: %llx\n\tphysBase %llx\n\tmemSize: %llx\n\ttopOfKernelData: %llx\n\tmachineType: %x\n\tdeviceTreeP: %llx\n\tdeviceTreeLength: %x\n\tCommandLine: %s\n\tbootFlags: %llx\n\tmemSizeActual: %llx\n", cBootArgs->Revision, cBootArgs->Version, cBootArgs->virtBase, cBootArgs->physBase, cBootArgs->memSize, cBootArgs->topOfKernelData, cBootArgs->machineType, (uint64_t)cBootArgs->deviceTreeP, cBootArgs->deviceTreeLength, &cBootArgs->CommandLine, cBootArgs->bootFlags, cBootArgs->memSizeActual);
    dt_arg_t arg =
    {
        .name = NULL,
        .prop = NULL,
        .size = 0xFFFF,
    };

    dt_parse(gDeviceTree, 0, NULL, &dt_cbn, gDeviceTree, &dt_cbp, &arg);
}

void flip_video_display() {
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
struct mach_header_64* xnu_header() {
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
/* 
typedef struct xnu_pf_range {
    uint64_t va;
    uint64_t size;
    uint8_t* cacheable_base;
    uint8_t* device_base;
} xnu_pf_range_t;
*/


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
    return xnu_pf_range_from_va(xnu_slide_hdr_va(header, seg->vmaddr), seg->filesize);
}
xnu_pf_range_t* xnu_pf_section(struct mach_header_64* header, void* segment_name, char* section_name) {
    struct segment_command_64* seg = macho_get_segment(header, segment_name);
    if (!seg) return NULL;
    struct section_64* sec = macho_get_section(seg, section_name);
    if (!sec) return NULL;
    return xnu_pf_range_from_va(xnu_slide_hdr_va(header, sec->addr), sec->size);
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
    return r;
}
struct xnu_pf_maskmatch {
    xnu_pf_patch_t patch;
    uint32_t pair_count;
    uint64_t pairs[][2];
};
inline bool xnu_pf_maskmatch_match_8(struct xnu_pf_maskmatch* patch, uint8_t access_type, uint8_t* preread, uint8_t* cacheable_stream) {
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
inline bool xnu_pf_maskmatch_match_16(struct xnu_pf_maskmatch* patch, uint8_t access_type, uint16_t* preread, uint16_t* cacheable_stream) {
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
inline bool xnu_pf_maskmatch_match_32(struct xnu_pf_maskmatch* patch, uint8_t access_type, uint32_t* preread, uint32_t* cacheable_stream) {
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
inline bool xnu_pf_maskmatch_match_64(struct xnu_pf_maskmatch* patch, uint8_t access_type, uint64_t* preread, uint64_t* cacheable_stream) {
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
        if (patch->patch.pf_callback((struct xnu_pf_patch *)patch, cacheable_stream)) {
            patch->patch.has_fired = true;
        }
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
            if (patch->patch.pf_callback((struct xnu_pf_patch *)patch, cacheable_stream)) {
                patch->patch.has_fired = true;
            }
        }
    }
}
uint32_t* xnu_pf_maskmatch_emit(struct xnu_pf_maskmatch* patch, uint32_t* insn_stream);
xnu_pf_patch_t* xnu_pf_maskmatch(xnu_pf_patchset_t* patchset, uint64_t* matches, uint64_t* masks, uint32_t entryc, bool required, bool (*callback)(struct xnu_pf_patch* patch, void* cacheable_stream)) {
    struct xnu_pf_maskmatch* mm = malloc(sizeof(struct xnu_pf_maskmatch) + 16 * entryc);
    bzero(mm, sizeof(struct xnu_pf_maskmatch));
    mm->patch.should_match = true;
    mm->patch.pf_callback = (void*)callback;
    mm->patch.pf_emit = (void*)xnu_pf_maskmatch_emit;
    mm->patch.pf_match = (void*)xnu_pf_maskmatch_match;
    mm->patch.is_required = required;
    mm->pair_count = entryc;
    
    uint32_t loadc = entryc;
    if (loadc > 8) loadc = 8;
    
    if (loadc == 7) {
        extern uint32_t pf_jit_mask_comparison_7_start, pf_jit_mask_comparison_7_next;
        mm->patch.pfjit_max_emit_size = (&pf_jit_mask_comparison_7_next - &pf_jit_mask_comparison_7_start) * 4 + 7 * 16;
    } else if (loadc == 6) {
        extern uint32_t pf_jit_mask_comparison_6_start, pf_jit_mask_comparison_6_next;
        mm->patch.pfjit_max_emit_size = (&pf_jit_mask_comparison_6_next - &pf_jit_mask_comparison_6_start) * 4 + 6 * 16;
    } else if (loadc == 5) {
        extern uint32_t pf_jit_mask_comparison_5_start, pf_jit_mask_comparison_5_next;
        mm->patch.pfjit_max_emit_size = (&pf_jit_mask_comparison_5_next - &pf_jit_mask_comparison_5_start) * 4 + 5 * 16;
    } else if (loadc == 4) {
        extern uint32_t pf_jit_mask_comparison_4_start, pf_jit_mask_comparison_4_next;
        mm->patch.pfjit_max_emit_size = (&pf_jit_mask_comparison_4_next - &pf_jit_mask_comparison_4_start) * 4 + 4 * 16;
    } else if (loadc == 3) {
        extern uint32_t pf_jit_mask_comparison_3_start, pf_jit_mask_comparison_3_next;
        mm->patch.pfjit_max_emit_size = (&pf_jit_mask_comparison_3_next - &pf_jit_mask_comparison_3_start) * 4 + 3 * 16;
    } else if (loadc == 2) {
        extern uint32_t pf_jit_mask_comparison_2_start, pf_jit_mask_comparison_2_next;
        mm->patch.pfjit_max_emit_size = (&pf_jit_mask_comparison_2_next - &pf_jit_mask_comparison_2_start) * 4 + 2 * 16;
    } else if (loadc == 1) {
        extern uint32_t pf_jit_mask_comparison_1_start, pf_jit_mask_comparison_1_next;
        mm->patch.pfjit_max_emit_size = (&pf_jit_mask_comparison_1_next - &pf_jit_mask_comparison_1_start) * 4 + 1 * 16;
    } else {
        extern uint32_t pf_jit_mask_comparison_8_start, pf_jit_mask_comparison_8_next;
        mm->patch.pfjit_max_emit_size = (&pf_jit_mask_comparison_8_next - &pf_jit_mask_comparison_8_start) * 4 + 8 * 16;
    }
    mm->patch.pfjit_max_emit_size += 32;
    
    for (uint32_t i=0; i<entryc; i++) {
        mm->pairs[i][0] = matches[i];
        mm->pairs[i][1] = masks[i];
    }
    
    mm->patch.next_patch = patchset->patch_head;
    patchset->patch_head = &mm->patch;
    return &mm->patch;
}
uint32_t* xnu_pf_ptr_to_data_emit(struct xnu_pf_ptr_to_datamatch* patch, uint32_t* insn_stream);
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

/*
void xnu_pf_ptr_to_data_match(struct xnu_pf_ptr_to_datamatch* patch, uint8_t access_type, void* preread, void* cacheable_stream) {
    uint64_t pointer = *(uint64_t*)preread;
    pointer |= 0xffff000000000000;
    pointer += patch->slide;
    
    if (pointer >= patch->range->va && pointer < (patch->range->va + patch->range->size)) {
        if (memcmp(patch->data, (void*)(pointer - patch->range->va + patch->range->cacheable_base), patch->datasz) == 0) {
            if (patch->patch.pf_callback((struct xnu_pf_patch *)patch, cacheable_stream)) {
                patch->patch.has_fired = true;
            }
        }
    }
}*/

uint32_t* xnu_pf_ptr_to_data_emit(struct xnu_pf_ptr_to_datamatch* patch, uint32_t* insn_stream) {
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

uint32_t* xnu_pf_maskmatch_emit(struct xnu_pf_maskmatch* patch, uint32_t* insn_stream) {
    extern uint32_t pf_jit_mask_comparison_1_start, pf_jit_mask_comparison_1_end;
    extern uint32_t pf_jit_mask_comparison_2_start, pf_jit_mask_comparison_2_end;
    extern uint32_t pf_jit_mask_comparison_3_start, pf_jit_mask_comparison_3_end;
    extern uint32_t pf_jit_mask_comparison_4_start, pf_jit_mask_comparison_4_end;
    extern uint32_t pf_jit_mask_comparison_5_start, pf_jit_mask_comparison_5_end;
    extern uint32_t pf_jit_mask_comparison_6_start, pf_jit_mask_comparison_6_end;
    extern uint32_t pf_jit_mask_comparison_7_start, pf_jit_mask_comparison_7_end;
    extern uint32_t pf_jit_mask_comparison_8_start, pf_jit_mask_comparison_8_end;
    
    patch->patch.pfjit_entry = insn_stream;
    
    switch (patch->pair_count) {
        case 0:
        return insn_stream;
        
        break;
        case 1:
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 0, patch->pairs[0][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 1, patch->pairs[0][1]);    
        insn_stream = xnu_pf_align3_emit(insn_stream);
        insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_mask_comparison_1_start, &pf_jit_mask_comparison_1_end);
        break;
        case 2:
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 0, patch->pairs[0][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 1, patch->pairs[0][1]);    
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 2, patch->pairs[1][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 3, patch->pairs[1][1]);    
        insn_stream = xnu_pf_align3_emit(insn_stream);
        insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_mask_comparison_2_start, &pf_jit_mask_comparison_2_end);
        break;
        case 3:
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 0, patch->pairs[0][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 1, patch->pairs[0][1]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 2, patch->pairs[1][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 3, patch->pairs[1][1]);    
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 4, patch->pairs[2][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 5, patch->pairs[2][1]);    
        insn_stream = xnu_pf_align3_emit(insn_stream);
        insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_mask_comparison_3_start, &pf_jit_mask_comparison_3_end);
        break;
        case 4:
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 0, patch->pairs[0][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 1, patch->pairs[0][1]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 2, patch->pairs[1][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 3, patch->pairs[1][1]);    
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 4, patch->pairs[2][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 5, patch->pairs[2][1]);    
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 6, patch->pairs[3][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 7, patch->pairs[3][1]);
        insn_stream = xnu_pf_align3_emit(insn_stream);
        insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_mask_comparison_4_start, &pf_jit_mask_comparison_4_end);
        break;
        case 5:
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 0, patch->pairs[0][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 1, patch->pairs[0][1]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 2, patch->pairs[1][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 3, patch->pairs[1][1]);    
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 4, patch->pairs[2][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 5, patch->pairs[2][1]);    
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 6, patch->pairs[3][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 7, patch->pairs[3][1]);    
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 9, patch->pairs[4][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 10, patch->pairs[4][1]);
        insn_stream = xnu_pf_align3_emit(insn_stream);
        insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_mask_comparison_5_start, &pf_jit_mask_comparison_5_end);
        break;
        case 6:
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 0, patch->pairs[0][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 1, patch->pairs[0][1]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 2, patch->pairs[1][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 3, patch->pairs[1][1]);    
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 4, patch->pairs[2][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 5, patch->pairs[2][1]);    
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 6, patch->pairs[3][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 7, patch->pairs[3][1]);    
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 9, patch->pairs[4][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 10, patch->pairs[4][1]);    
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 11, patch->pairs[5][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 12, patch->pairs[5][1]);
        insn_stream = xnu_pf_align3_emit(insn_stream);
        insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_mask_comparison_6_start, &pf_jit_mask_comparison_6_end);
        break;
        case 7:
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 0, patch->pairs[0][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 1, patch->pairs[0][1]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 2, patch->pairs[1][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 3, patch->pairs[1][1]);    
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 4, patch->pairs[2][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 5, patch->pairs[2][1]);    
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 6, patch->pairs[3][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 7, patch->pairs[3][1]);    
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 9, patch->pairs[4][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 10, patch->pairs[4][1]);    
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 11, patch->pairs[5][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 12, patch->pairs[5][1]);    
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 13, patch->pairs[6][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 14, patch->pairs[6][1]);    
        insn_stream = xnu_pf_align3_emit(insn_stream);
        insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_mask_comparison_7_start, &pf_jit_mask_comparison_7_end);
        break;
        default:
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 0, patch->pairs[0][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 1, patch->pairs[0][1]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 2, patch->pairs[1][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 3, patch->pairs[1][1]);    
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 4, patch->pairs[2][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 5, patch->pairs[2][1]);    
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 6, patch->pairs[3][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 7, patch->pairs[3][1]);    
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 9, patch->pairs[4][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 10, patch->pairs[4][1]);    
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 11, patch->pairs[5][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 12, patch->pairs[5][1]);    
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 13, patch->pairs[6][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 14, patch->pairs[6][1]);    
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 15, patch->pairs[7][0]);
        insn_stream = xnu_pf_imm64_load_emit(insn_stream, 16, patch->pairs[7][1]);    
        insn_stream = xnu_pf_align3_emit(insn_stream);
        insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_mask_comparison_8_start, &pf_jit_mask_comparison_8_end);
        break;
    }
    ((uint64_t*)insn_stream)[0] = (uint64_t)patch;
    ((uint64_t*)insn_stream)[1] = (uint64_t)&xnu_pf_maskmatch_match;
    
    patch->patch.pfjit_exit = (uint32_t*)(&((uint64_t*)insn_stream)[2]);
    return patch->patch.pfjit_exit;
}
void xnu_pf_emit_8(xnu_pf_patchset_t* patchset) { // converts a patchset to JIT
    if (patchset->accesstype != XNU_PF_ACCESS_8BIT) {
        puts("xnu_pf_jit only supports 8 bit accesses for now");
        return;
    }
    xnu_pf_patch_t* patch = patchset->patch_head;
    uint32_t jit_size = 0x400;
    
    while (patch) {
        if (!patch->pf_emit) {
            puts("xnu_pf_jit doesn't support this patch");
            return;
        } else {
            jit_size += patch->pfjit_max_emit_size;
        }
        patch = patch->next_patch;
    }
        
    uint32_t* insn_stream = malloc(jit_size);    
    uint32_t* jit_entry = insn_stream;
    
    extern uint32_t pf_jit_iter_loop_head_start, pf_jit_iter_loop_head_end;
    insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_iter_loop_head_start, &pf_jit_iter_loop_head_end);
    
    extern uint32_t pf_jit_iter_loop_head_load8_start, pf_jit_iter_loop_head_load8_end;
    insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_iter_loop_head_load8_start, &pf_jit_iter_loop_head_load8_end);
    uint32_t* bailout = insn_stream;
    insn_stream++;

    uint32_t* loop_head = insn_stream;
    
    patch = patchset->patch_head;
    while (patch) {
        uint64_t pre_emit = (uint64_t)insn_stream;
        insn_stream = patch->pf_emit(patch, insn_stream);
        uint64_t post_emit = (uint64_t)insn_stream;
        if (post_emit - pre_emit > patch->pfjit_max_emit_size) {
            panic("pf_jit: jit overflow");
        }
        patch = patch->next_patch;
    }

    extern uint32_t pf_jit_iter_loop_iter_load8_start, pf_jit_iter_loop_iter_load8_end;
    insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_iter_loop_iter_load8_start, &pf_jit_iter_loop_iter_load8_end);
    insn_stream = xnu_pf_b_emit(insn_stream, loop_head);
    
    xnu_pf_b_emit(bailout, insn_stream);
    
    extern uint32_t pf_jit_iter_loop_end_start, pf_jit_iter_loop_end_end;
    insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_iter_loop_end_start, &pf_jit_iter_loop_end_end);
    invalidate_icache();
    patchset->jit_matcher = (void*) jit_entry;
}
void xnu_pf_emit_16(xnu_pf_patchset_t* patchset) { // converts a patchset to JIT
    if (patchset->accesstype != XNU_PF_ACCESS_16BIT) {
        puts("xnu_pf_jit only supports 16 bit accesses for now");
        return;
    }
    xnu_pf_patch_t* patch = patchset->patch_head;
    uint32_t jit_size = 0x400;
    
    while (patch) {
        if (!patch->pf_emit) {
            puts("xnu_pf_jit doesn't support this patch");
            return;
        } else {
            jit_size += patch->pfjit_max_emit_size;
        }
        patch = patch->next_patch;
    }
        
    uint32_t* insn_stream = malloc(jit_size);    
    uint32_t* jit_entry = insn_stream;
    
    extern uint32_t pf_jit_iter_loop_head_start, pf_jit_iter_loop_head_end;
    insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_iter_loop_head_start, &pf_jit_iter_loop_head_end);
    
    extern uint32_t pf_jit_iter_loop_head_load16_start, pf_jit_iter_loop_head_load16_end;
    insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_iter_loop_head_load16_start, &pf_jit_iter_loop_head_load16_end);
    uint32_t* bailout = insn_stream;
    insn_stream++;

    uint32_t* loop_head = insn_stream;
    
    patch = patchset->patch_head;
    while (patch) {
        uint64_t pre_emit = (uint64_t)insn_stream;
        insn_stream = patch->pf_emit(patch, insn_stream);
        uint64_t post_emit = (uint64_t)insn_stream;
        if (post_emit - pre_emit > patch->pfjit_max_emit_size) {
            panic("pf_jit: jit overflow");
        }
        patch = patch->next_patch;
    }

    extern uint32_t pf_jit_iter_loop_iter_load16_start, pf_jit_iter_loop_iter_load16_end;
    insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_iter_loop_iter_load16_start, &pf_jit_iter_loop_iter_load16_end);
    insn_stream = xnu_pf_b_emit(insn_stream, loop_head);
    
    xnu_pf_b_emit(bailout, insn_stream);
    
    extern uint32_t pf_jit_iter_loop_end_start, pf_jit_iter_loop_end_end;
    insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_iter_loop_end_start, &pf_jit_iter_loop_end_end);
    invalidate_icache();
    patchset->jit_matcher = (void*) jit_entry;
}

void xnu_pf_emit_32(xnu_pf_patchset_t* patchset) { // converts a patchset to JIT
    if (patchset->accesstype != XNU_PF_ACCESS_32BIT) {
        puts("xnu_pf_jit only supports 32 bit accesses for now");
        return;
    }
    xnu_pf_patch_t* patch = patchset->patch_head;
    uint32_t jit_size = 0x400;
    
    while (patch) {
        if (!patch->pf_emit) {
            puts("xnu_pf_jit doesn't support this patch");
            return;
        } else {
            jit_size += patch->pfjit_max_emit_size;
        }
        patch = patch->next_patch;
    }
        
    uint32_t* insn_stream = malloc(jit_size);    
    uint32_t* jit_entry = insn_stream;
    
    extern uint32_t pf_jit_iter_loop_head_start, pf_jit_iter_loop_head_end;
    insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_iter_loop_head_start, &pf_jit_iter_loop_head_end);
    
    extern uint32_t pf_jit_iter_loop_head_load32_start, pf_jit_iter_loop_head_load32_end;
    insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_iter_loop_head_load32_start, &pf_jit_iter_loop_head_load32_end);
    uint32_t* bailout = insn_stream;
    insn_stream++;

    uint32_t* loop_head = insn_stream;
    
    patch = patchset->patch_head;
    while (patch) {
        uint64_t pre_emit = (uint64_t)insn_stream;
        insn_stream = patch->pf_emit(patch, insn_stream);
        uint64_t post_emit = (uint64_t)insn_stream;
        if (post_emit - pre_emit > patch->pfjit_max_emit_size) {
            panic("pf_jit: jit overflow");
        }
        patch = patch->next_patch;
    }

    extern uint32_t pf_jit_iter_loop_iter_load32_start, pf_jit_iter_loop_iter_load32_end;
    insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_iter_loop_iter_load32_start, &pf_jit_iter_loop_iter_load32_end);
    insn_stream = xnu_pf_b_emit(insn_stream, loop_head);
    
    xnu_pf_b_emit(bailout, insn_stream);
    
    extern uint32_t pf_jit_iter_loop_end_start, pf_jit_iter_loop_end_end;
    insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_iter_loop_end_start, &pf_jit_iter_loop_end_end);
    invalidate_icache();
    patchset->jit_matcher = (void*) jit_entry;
}
void xnu_pf_emit_64(xnu_pf_patchset_t* patchset) { // converts a patchset to JIT
    if (patchset->accesstype != XNU_PF_ACCESS_64BIT) {
        puts("xnu_pf_jit only supports 64 bit accesses for now");
        return;
    }
    xnu_pf_patch_t* patch = patchset->patch_head;
    uint32_t jit_size = 0x400;
    
    while (patch) {
        if (!patch->pf_emit) {
            puts("xnu_pf_jit doesn't support this patch");
            return;
        } else {
            jit_size += patch->pfjit_max_emit_size;
        }
        patch = patch->next_patch;
    }
        
    uint32_t* insn_stream = malloc(jit_size);    
    uint32_t* jit_entry = insn_stream;
    
    extern uint32_t pf_jit_iter_loop_head_start, pf_jit_iter_loop_head_end;
    insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_iter_loop_head_start, &pf_jit_iter_loop_head_end);
    
    extern uint32_t pf_jit_iter_loop_head_load64_start, pf_jit_iter_loop_head_load64_end;
    insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_iter_loop_head_load64_start, &pf_jit_iter_loop_head_load64_end);
    uint32_t* bailout = insn_stream;
    insn_stream++;

    uint32_t* loop_head = insn_stream;
    
    patch = patchset->patch_head;
    while (patch) {
        uint64_t pre_emit = (uint64_t)insn_stream;
        insn_stream = patch->pf_emit(patch, insn_stream);
        uint64_t post_emit = (uint64_t)insn_stream;
        if (post_emit - pre_emit > patch->pfjit_max_emit_size) {
            panic("pf_jit: jit overflow");
        }
        patch = patch->next_patch;
    }

    extern uint32_t pf_jit_iter_loop_iter_load64_start, pf_jit_iter_loop_iter_load64_end;
    insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_iter_loop_iter_load64_start, &pf_jit_iter_loop_iter_load64_end);
    insn_stream = xnu_pf_b_emit(insn_stream, loop_head);
    
    xnu_pf_b_emit(bailout, insn_stream);
    
    extern uint32_t pf_jit_iter_loop_end_start, pf_jit_iter_loop_end_end;
    insn_stream = xnu_pf_emit_insns(insn_stream, &pf_jit_iter_loop_end_start, &pf_jit_iter_loop_end_end);
    invalidate_icache();
    patchset->jit_matcher = (void*) jit_entry;
}

void xnu_pf_emit(xnu_pf_patchset_t* patchset) { // converts a patchset to JIT
    if (patchset->accesstype == XNU_PF_ACCESS_8BIT) {
        return xnu_pf_emit_8(patchset);
    }
    if (patchset->accesstype == XNU_PF_ACCESS_16BIT) {
        return xnu_pf_emit_16(patchset);
    }
    if (patchset->accesstype == XNU_PF_ACCESS_32BIT) {
        return xnu_pf_emit_32(patchset);
    }
    if (patchset->accesstype == XNU_PF_ACCESS_64BIT) {
        return xnu_pf_emit_64(patchset);
    }
    puts("xnu_pf_jit does not support this access type");
    return;
}

void xnu_pf_apply_8(xnu_pf_range_t* range, xnu_pf_patchset_t* patchset) {
    uint8_t* stream = (uint8_t*)range->cacheable_base;
    uint8_t* dstream = (uint8_t*)range->device_base;
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
    uint16_t* dstream = (uint16_t*)range->device_base;
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
    uint32_t* dstream = (uint32_t*)range->device_base;
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
        jit_match(range->cacheable_base, range->cacheable_base + range->size);
    } else {
        if (patchset->accesstype == XNU_PF_ACCESS_8BIT) xnu_pf_apply_8(range, patchset);
        else if (patchset->accesstype == XNU_PF_ACCESS_16BIT) xnu_pf_apply_16(range, patchset);
        else if (patchset->accesstype == XNU_PF_ACCESS_32BIT) xnu_pf_apply_32(range, patchset);
        else if (patchset->accesstype == XNU_PF_ACCESS_64BIT) xnu_pf_apply_64(range, patchset);
    }
    xnu_pf_patch_t* patch = patchset->patch_head;
    while (patch) {
        if (patch->is_required) {
            if (!patch->has_fired) {
                panic("missing patch");
            }
        }
        patch = patch->next_patch;
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
    free(patchset);
}
void xnu_boot() {

}

void xnu_init() {
    command_register("dt", "parses loaded devicetree", log_dtree);
    command_register("xargs", "prints or sets xnu boot-args", pongo_boot_xargs);
    command_register("loadx", "loads xnu", pongo_copy_xnu);
    command_register("bootx", "boots xnu (patched, if such a module is loaded)", pongo_boot_hook);
    command_register("bootux", "boots unpatched xnu", pongo_boot_hard);
    command_register("bootargs", "prints xnu bootargs struct", log_bootargs);
    command_register("xfb", "gives xnu access to the framebuffer (for -v or -s)", flip_video_display);
}

void xnu_hook() {
    if (preboot_hook) preboot_hook();
}

void xnu_loadrd() {
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
