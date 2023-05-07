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

#ifndef KPF_H
#define KPF_H

#include <stdint.h>
#include <stdio.h>
#include <mach-o/loader.h>
#include <pongo.h>
#include <xnu/xnu.h>

/********** ********** ********** ********** ********** Defines ********** ********** ********** ********** **********/

#ifdef DEV_BUILD
#   define DEVLOG(msg, ...) do { printf(msg "\n", ##__VA_ARGS__); } while(0)
#   define panic_at(addr, msg, ...) do { panic(msg " (0x%llx)", ##__VA_ARGS__, xnu_ptr_to_va(addr)); } while(0)
#else
#   define DEVLOG(msg, ...) do {} while (0)
#   define panic_at(addr, msg, ...) do { panic(msg, ##__VA_ARGS__); } while (0)
#endif

// Common enough that we want defines for these
#define NOP 0xd503201f
#define RET 0xd65f03c0

// Patches are called in alphabetical order of bundle, segment, section.
// NULL comes before everything else. Smaller granules come before larger ones.
typedef const struct
{
    const char *bundle;  // NULL = XNU
    const char *segment; // NULL = invalid
    const char *section; // NULL = all sections in segment
    uint8_t granule;     // Valid values: XNU_PF_ACCESS_{8,16,32,64}BIT
    void (*patch)(xnu_pf_patchset_t *patchset); // NULL = end of list
} kpf_patch_t;

// Order of invocations: init, shc_size, patches, shc_emit, finish.
// Both init and finish may be NULL independently.
// shc_size and shc_emit must either both be NULL or non-NULL.
// shc_size returns the maximum number of instructions to be emitted.
// shc_emit returns the actual number of instructions that were emitted.
typedef const struct
{
    void     (*init)(struct mach_header_64 *hdr, xnu_pf_range_t *cstring);
    void     (*finish)(struct mach_header_64 *hdr);
    uint32_t (*shc_size)(void);
    uint32_t (*shc_emit)(uint32_t *shellcode_area);
    kpf_patch_t patches[];
} kpf_component_t;

/********** ********** ********** ********** ********** Helpers ********** ********** ********** ********** **********/

extern uint32_t* find_next_insn(uint32_t *from, uint32_t num, uint32_t insn, uint32_t mask);
extern uint32_t* find_prev_insn(uint32_t *from, uint32_t num, uint32_t insn, uint32_t mask);
extern uint32_t* follow_call(uint32_t *from);

static inline int32_t sxt32(int32_t value, uint8_t bits)
{
    value = ((uint32_t)value) << (32 - bits);
    value >>= (32 - bits);
    return value;
}

static inline int64_t sxt64(int64_t value, uint8_t bits)
{
    value = ((uint64_t)value) << (64 - bits);
    value >>= (64 - bits);
    return value;
}

static inline int64_t adrp_off(uint32_t adrp)
{
    return sxt64((((((uint64_t)adrp >> 5) & 0x7ffffULL) << 2) | (((uint64_t)adrp >> 29) & 0x3ULL)) << 12, 33);
}

#ifdef DEV_BUILD
extern struct kernel_version
{
    uint32_t darwinMajor;
    uint32_t darwinMinor;
    uint32_t darwinRevision;
    uint32_t xnuMajor;
} gKernelVersion;
#endif

/********** ********** ********** ********** ********** Components ********** ********** ********** ********** **********/

extern kpf_component_t kpf_developer_mode;
extern kpf_component_t kpf_dyld;
extern kpf_component_t kpf_launch_constraints;
extern kpf_component_t kpf_mach_port;
extern kpf_component_t kpf_nvram;
extern kpf_component_t kpf_trustcache;
extern kpf_component_t kpf_vfs;
extern kpf_component_t kpf_vm_prot;

/********** ********** ********** ********** ********** Exports ********** ********** ********** ********** **********/

uint64_t kpf_vfs__vfs_context_current(void);
uint64_t kpf_vfs__vnode_lookup(void);
uint64_t kpf_vfs__vnode_put(void);

#endif /* KPF_H */
