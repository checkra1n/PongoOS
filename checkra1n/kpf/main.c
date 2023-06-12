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
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <mach-o/loader.h>
#include <paleinfo.h>
#include <mac.h>
#include <pongo.h>
#include <xnu/xnu.h>

uint32_t offsetof_p_flags;
static palerain_option_t palera1n_flags;

#if 0
        // AES, sigh
        else if((fetch & 0xfffffc00) == 0x510fa000 && (apfs_privcheck[i+1] & 0xfffffc1f) == 0x7100081f && (apfs_privcheck[i+2] & 0xff00001f) == 0x54000003) {
             apfs_privcheck_repatch[i+2] = 0xd503201f; // nop
             puts("KPF: Preparing keygen");
        }
        // AESs8000 patch, more sigh
        else if(fetch == 0x711f3c3f && (apfs_privcheck[i+1] & 0xff00001f) == 0x5400000c && apfs_privcheck[i+2] == 0x710fa03f && (apfs_privcheck[i+3] & 0xff00001f) == 0x54000000 && apfs_privcheck[i+4] == 0x710fa43f) {
            apfs_privcheck_repatch[i]   = 0x52800000; // mov w0, 0
            apfs_privcheck_repatch[i+1] = RET; // ret
            puts("KPF: Gatekeeping 0x3e8");
        }
        // Pre-s8000 AES patch, I'm getting tired of this
        else if((fetch & 0xfffffc1f) == 0x711f401f && (apfs_privcheck[i+1] & 0xff00001f) == 0x54000000 && (apfs_privcheck[i+2] & 0xfffffc1f) == 0x710fa41f) {
            uint32_t tmp = apfs_privcheck[i+1];
            apfs_privcheck_repatch[i+1] = (tmp & 0xfffffff0) | 0xf; // make unconditional
            int32_t idx = (int32_t)i + 1 + ((int32_t)(tmp << 8) >> 13);
            uint32_t tmp2 = apfs_privcheck[idx];
            apfs_privcheck_repatch[i] = 0xd2800000 | (tmp2 & 0x1f);
            // NOP if not strb
            if((tmp2 & 0xffc00000) == 0x39000000) {
                apfs_privcheck_repatch[idx] = 0xd503201f; // nop
            }
            puts("KPF: Gatekeeping 0x3e8");
        }
        // MacEFIManager patch
        // 3f 04 00 71 ? ? 00 54 3f 08 00 71 ? ? 00 54 ? ? ? 39
        else if (fetch == 0x7100043F && (apfs_privcheck[i+1] & 0xffff0000) == 0x54000000 && apfs_privcheck[i+2] == 0x7100083f && (apfs_privcheck[i+3] & 0xffff0000) == 0x54000000 && (apfs_privcheck[i+4] & 0xff000000) == 0x39000000) {
             puts("KPF: MacEFIManager img4 validation");
            uint32_t* cmp = find_next_insn(&apfs_privcheck_repatch[i], 0x10, 0x7100081f, 0xFFFFFFFF);
            if (!cmp) {
                goto fail;
            }
            *cmp = 0x6b00001f;
        }
#endif

uint32_t* find_next_insn(uint32_t* from, uint32_t num, uint32_t insn, uint32_t mask)
{
    while(num)
    {
        if((*from & mask) == (insn & mask))
        {
            return from;
        }
        from++;
        num--;
    }
    return NULL;
}
uint32_t* find_prev_insn(uint32_t* from, uint32_t num, uint32_t insn, uint32_t mask)
{
    while(num)
    {
        if((*from & mask) == (insn & mask))
        {
            return from;
        }
        from--;
        num--;
    }
    return NULL;
}

uint32_t* follow_call(uint32_t *from)
{
    uint32_t op = *from;
    if((op & 0x7c000000) != 0x14000000)
    {
        DEVLOG("follow_call 0x%llx is not B or BL", xnu_ptr_to_va(from));
        return NULL;
    }
    uint32_t *target = from + sxt32(op, 26);
    if(
        (target[0] & 0x9f00001f) == 0x90000010 && // adrp x16, ...
        (target[1] & 0xffc003ff) == 0xf9400210 && // ldr x16, [x16, ...]
        target[2] == 0xd61f0200                   // br x16
    ) {
        // Stub - read pointer
        int64_t pageoff = adrp_off(target[0]);
        uint64_t page = ((uint64_t)target&(~0xfffULL)) + pageoff;
        uint64_t ptr = *(uint64_t*)(page + ((((uint64_t)target[1] >> 10) & 0xfffULL) << 3));
        target = xnu_va_to_ptr(kext_rebase_va(ptr));
    }
    DEVLOG("followed call from 0x%llx to 0x%llx", xnu_ptr_to_va(from), xnu_ptr_to_va(target));
    return target;
}

#ifdef DEV_BUILD
struct kernel_version gKernelVersion;
static void kpf_kernel_version_init(xnu_pf_range_t *text_const_range)
{
    const char kernelVersionStringMarker[] = "@(#)VERSION: Darwin Kernel Version ";
    const char *kernelVersionString = memmem(text_const_range->cacheable_base, text_const_range->size, kernelVersionStringMarker, strlen(kernelVersionStringMarker));
    if(kernelVersionString == NULL)
    {
        panic("No kernel version string found");
    }
    const char *start = kernelVersionString + strlen(kernelVersionStringMarker);
    char *end = NULL;
    errno = 0;
    gKernelVersion.darwinMajor = strtoimax(start, &end, 10);
    if(errno) panic("Error parsing kernel version");
    start = end+1;
    gKernelVersion.darwinMinor = strtoimax(start, &end, 10);
    if(errno) panic("Error parsing kernel version");
    start = end+1;
    gKernelVersion.darwinRevision = strtoimax(start, &end, 10);
    if(errno) panic("Error parsing kernel version");
    start = strstr(end, "root:xnu");
    if(start) start = strchr(start + strlen("root:xnu"), '-');
    if(!start) panic("Error parsing kernel version");
    gKernelVersion.xnuMajor = strtoimax(start+1, &end, 10);
    if(errno) panic("Error parsing kernel version");
    printf("Detected Kernel version Darwin: %d.%d.%d xnu: %d\n", gKernelVersion.darwinMajor, gKernelVersion.darwinMinor, gKernelVersion.darwinRevision, gKernelVersion.xnuMajor);
}
#endif

// Imports from shellcode.S
extern uint32_t sandbox_shellcode[], sandbox_shellcode_setuid_patch[], sandbox_shellcode_ptrs[], sandbox_shellcode_end[];

bool kpf_has_done_mac_mount = false;
bool kpf_mac_mount_callback(struct xnu_pf_patch* patch, uint32_t* opcode_stream) {
    puts("KPF: Found mac_mount");
    uint32_t* mac_mount = &opcode_stream[0];
    // search for tbnz w*, 5, *
    // and nop it (enable MNT_UNION mounts)
    uint32_t* mac_mount_1 = find_prev_insn(mac_mount, 0x40, 0x37280000, 0xfffe0000);
    if (!mac_mount_1) {
        mac_mount_1 = find_next_insn(mac_mount, 0x40, 0x37280000, 0xfffe0000);
    }
    if (!mac_mount_1) {
        kpf_has_done_mac_mount = false;
        DEVLOG("kpf_mac_mount_callback: failed to find NOP point");
        return false;
    }
    mac_mount_1[0] = NOP;
    // search for ldrb w8, [x8, 0x71]
    mac_mount_1 = find_prev_insn(mac_mount, 0x40, 0x3941c508, 0xFFFFFFFF);
    if (!mac_mount_1) {
        mac_mount_1 = find_next_insn(mac_mount, 0x40, 0x3941c508, 0xFFFFFFFF);
    }
    if (!mac_mount_1) {
        kpf_has_done_mac_mount = false;
        DEVLOG("kpf_mac_mount_callback: failed to find xzr point");
        return false;
    }
    // replace with a mov x8, xzr
    // this will bypass the (vp->v_mount->mnt_flag & MNT_ROOTFS) check
    mac_mount_1[0] = 0xaa1f03e8;
    kpf_has_done_mac_mount = true;
    xnu_pf_disable_patch(patch);
    puts("KPF: Found mac_mount");
    return true;
}

void kpf_mac_mount_patch(xnu_pf_patchset_t* xnu_text_exec_patchset) {
    // This patch makes sure that we can remount the rootfs and that we can UNION mount
    // we first search for a pretty unique instruction movz/orr w9, 0x1ffe
    // then we search for a tbnz w*, 5, * (0x20 is MNT_UNION) and nop it
    // After that we search for a ldrb w8, [x8, 0x71] and replace it with a movz x8, 0
    // at 0x70 there are the flags and MNT_ROOTFS is 0x00004000 -> 0x4000 >> 8 -> 0x40 -> bit 6 -> the check is right below
    // that way we can also perform operations on the rootfs
    // r2: /x e92f1f32
    uint64_t matches[] = {
        0x321f2fe9, // orr w9, wzr, 0x1ffe
    };
    uint64_t masks[] = {
        0xFFFFFFFF,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "mac_mount_patch1", matches, masks, sizeof(matches)/sizeof(uint64_t), false, (void*)kpf_mac_mount_callback);
    
    // ios 16.4 changed the codegen, so we match both
    // r2: /x c9ff8312:ffffff3f
    matches[0] = 0x1283ffc9; // movz w/x9, 0x1ffe/-0x1fff
    masks[0] = 0x3fffffff;
    xnu_pf_maskmatch(xnu_text_exec_patchset, "mac_mount_patch2", matches, masks, sizeof(matches)/sizeof(uint64_t), false, (void*)kpf_mac_mount_callback);
}

bool dounmount_found;
bool kpf_mac_dounmount_callback(struct xnu_pf_patch* patch, uint32_t* opcode_stream) {
    uint8_t rn;
    if ((opcode_stream[-1]&0xFFE0FFFF) == 0xAA0003E0 &&  // MOV X0, Xn
         (opcode_stream[3]&0xFC000000) == 0x94000000) {  // BL vnode_rele_internal
        rn = (opcode_stream[-1]>>16)&0x1f;
        opcode_stream += 3;
    } else if ((opcode_stream[3]&0xFFE0FFFF) == 0xAA0003E0 &&    // MOV X0, Xn
               (opcode_stream[4]&0xFC000000) == 0x94000000) {    // BL vnode_rele_internal
        rn = (opcode_stream[3]>>16)&0x1f;
        opcode_stream += 4;
    } else {
        // not a match
        return false;
    }

    if ( opcode_stream[1] != (0xAA0003E0|(rn<<16))   || // MOV X0, Xn
        (opcode_stream[2]&0xFC000000) != 0x94000000) {  // BL lck_mtx_lock_spin || BL vnode_put
        // Also not a match
        return false;
    }

    // This is probably it...

    // Find call to vnode_getparent
    // MOV X0, Xn
    // BL vnode_getparent
    // MOV Xn, X0
    uint32_t* mov = find_prev_insn(opcode_stream-3, 0x20, 0xAA0003E0, 0xFFFFFFE0);

    uint8_t parent_rn = 0;
    if (mov &&
        (mov[-2]&0xFFE0FFFF) == 0xAA0003E0 && // MOV X0, Xn
        (mov[-1]&0xFC000000) == 0x94000000) { // BL vnode_getparent
#if DEBUG_DOUNMOUNT
        DEVLOG("Dounmount match for call to vnode_getparent at 0x%llx", xnu_rebase_va(xnu_ptr_to_va(opcode_stream)));
#endif
        parent_rn = *mov&0x1f;
    }

#if DEBUG_DOUNMOUNT
    DEVLOG("Dounmount tenative match at 0x%llx", xnu_rebase_va(xnu_ptr_to_va(opcode_stream)));
#endif

    // Check that we have code to release parent_vnode below
    // MOV W1, #2
    uint32_t* parent_lock = find_next_insn(opcode_stream, 0x100, 0x52800041, 0xFFFFFFFF);
    if (!parent_lock) parent_lock = find_next_insn(opcode_stream, 0x100, 0x321F03E1, 0xFFFFFFFF);
    if (!parent_lock) {
        DEVLOG("Dounmount no parent lock code");
        return false;
    }
#if DEBUG_DOUNMOUNT
    DEVLOG("Dounmount testing parent lock at 0x%llx", xnu_rebase_va(xnu_ptr_to_va(parent_lock)));
#endif

    uint32_t* call;
    if ((parent_lock[-1]&0xFFE0FFFF) == 0xAA0003E0 &&   // MOV X0, Xn
        (parent_lock[1] &0xFC000000) == 0x94000000) {   // BL lock_vnode_and_post
        call = parent_lock+1;
        if (!parent_rn) parent_rn = (parent_lock[-1]>>16)&0x1f;
    } else if ((parent_lock[1]&0xFFE0FFFF) == 0xAA0003E0 &&   // MOV X0, Xn
               (parent_lock[2]&0xFC000000) == 0x94000000) {   // BL lock_vnode_and_post
        if (!parent_rn) parent_rn = (parent_lock[1]>>16)&0x1f;
        call = parent_lock+2;
    } else {
        DEVLOG("Dounmount failed to find first call for parent_vp");
        return false;
    }

    if ( call[1] != (0xAA0003E0|(parent_rn<<16)) ||
        (call[2]&0xFC000000) != 0x94000000) {
        DEVLOG("Dounmount failed to find second call for parent_vp");
        return false;
    }

    if (dounmount_found) {
        panic("dounmount found twice!");
    }

    puts("KPF: Found dounmount");
    opcode_stream[0] = NOP;
#ifndef DEV_BUILD
    // Only disable in non-dev build on match so that when testing we ensure that the algorithm matches only a single place
    xnu_pf_disable_patch(patch);
#endif
    dounmount_found = true;
    return true;
}
void kpf_mac_dounmount_patch_0(xnu_pf_patchset_t* xnu_text_exec_patchset) {
    // This patches out a vnode_release so that we can unmount the rootfs etc without crashing the system
    // For that we search for the series of movs below to find _dounmount and then we patch out one call to vnode_rele inside of it
    // example from the i7 13.3 kernel:
    // 0xfffffff0072ad70c      e00317aa       mov x0, x23
    // 0xfffffff0072ad710      020080d2       movz x2, 0
    // 0xfffffff0072ad714      e32600d0       adrp x3, 0xfffffff00778b000
    // 0xfffffff0072ad718      63a01291       add x3, x3, 0x4a8
    // 0xfffffff0072ad71c      de8f0094       bl 0xfffffff0072d1694
    // 0xfffffff0072ad720      f80300aa       mov x24, x0
    // 0xfffffff0072ad724      80180035       cbnz w0, 0xfffffff0072ada34
    // 0xfffffff0072ad728      b8f642f9       ldr x24, [x21, 0x5e8] ; [0x5e8:4]=3
    // 0xfffffff0072ad72c      3f0318eb       cmp x25, x24
    // 0xfffffff0072ad730      c0020054       b.eq 0xfffffff0072ad788
    // 0xfffffff0072ad734      e00318aa       mov x0, x24
    // 0xfffffff0072ad738      3019fe97       bl sym._lck_mtx_lock_spin
    // 0xfffffff0072ad73c      01008052       movz w1, 0
    // 0xfffffff0072ad740      02008052       movz w2, 0
    // 0xfffffff0072ad744      e00318aa       mov x0, x24
    // 0xfffffff0072ad748      fcf5ff97       bl 0xfffffff0072aaf38
    // 0xfffffff0072ad74c      e00318aa       mov x0, x24
    // 0xfffffff0072ad750      091afe97       bl sym._IOLockUnlock
    // 0xfffffff0072ad754      a8f642f9       ldr x8, [x21, 0x5e8] ; [0x5e8:4]=3
    // 0xfffffff0072ad758      e8c204f9       str x8, [x23, 0x980]
    // 0xfffffff0072ad75c      01008052       movz w1, 0
    // 0xfffffff0072ad760      02008052       movz w2, 0
    // 0xfffffff0072ad764      03008052       movz w3, 0
    // 0xfffffff0072ad768      e00319aa       mov x0, x25
    // 0xfffffff0072ad76c      7bfaff97       bl 0xfffffff0072ac158 <- we patchfind this and then nop it (nfs_vfs_unmount call)
    // 0xfffffff0072ad770      e00319aa       mov x0, x25
    // 0xfffffff0072ad774      2119fe97       bl sym._lck_mtx_lock_spin
    // 0xfffffff0072ad778      e00319aa       mov x0, x25
    // 0xfffffff0072ad77c      75f6ff97       bl 0xfffffff0072ab150
    // r2 command:
    // /x 010080520200805203008052
    // This matches a small number of places, the callback identifies the correct place
    uint64_t matches[] = {
        0x52800001, // movz w1, 0
        0x52800002, // movz w2, 0
        0x52800003, // movz w3, 0
    };
    uint64_t masks[] = {
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "dounmount_patch", matches, masks, sizeof(matches)/sizeof(uint64_t), true, (void*)kpf_mac_dounmount_callback);
}

static bool found_vm_map_protect = false;
static bool kpf_vm_map_protect_callback(uint32_t *opcode_stream)
{
    if(found_vm_map_protect)
    {
        panic("vm_map_protect: found twice");
    }
    found_vm_map_protect = true;
    puts("KPF: Found vm_map_protect");

    uint32_t *tbz = find_next_insn(opcode_stream, 8, 0x36480000, 0xfef80010); // tb[n]z w{0-15}, 0x...
    if(!tbz)
    {
        panic("vm_map_protect: failed to find tb[n]z");
    }

    uint32_t op = *tbz;
    if(op & 0x1000000) // tbnz
    {
        *tbz = NOP;
    }
    else // tbz
    {
        *tbz = 0x14000000 | (uint32_t)sxt32(op >> 5, 14);
    }
    return true;
}

static bool kpf_vm_map_protect_branch(uint32_t *opcode_stream)
{
    int32_t off = sxt32(*opcode_stream >> 5, 19);
    *opcode_stream = 0x14000000 | (uint32_t)off;
    return kpf_vm_map_protect_callback(opcode_stream + off); // uint32 takes care of << 2
}

static bool kpf_vm_map_protect_branch_long(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    return kpf_vm_map_protect_branch(opcode_stream + 2);
}

static bool kpf_vm_map_protect_branch_short(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    return kpf_vm_map_protect_branch(opcode_stream + 1);
}

static bool kpf_vm_map_protect_inline(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    DEVLOG("vm_map_protect candidate at 0x%llx", xnu_ptr_to_va(opcode_stream));

    // Match all possible combo and adjust index to the "csel"
    uint32_t idx = 2;
    uint32_t op = opcode_stream[idx];
    if
    (
        (op & 0xfffffe10) == 0x12090000 ||  // and w{0-15}, w{0-15}, 0x800000
        (op & 0xfffffe1f) == 0xf269001f     // tst x{0-15}, 0x800000
    )
    {
        ++idx;
    }

    if
    (
        (opcode_stream[idx+0] & 0xfff0fe10) == 0x2a000000 && // orr w{0-15}, w{0-15}, w{0-15}
        (opcode_stream[idx+1] & 0xfffffe10) == 0x121d7a00 && // and w{0-15}, w{16-31}, 0xfffffffb
        (opcode_stream[idx+2] & 0xfffffe1f) == 0x7100001f    // cmp w{0-15}, 0
    )
    {
        idx += 3;
    }
    else if
    (
        (opcode_stream[idx+0] & 0xfffffe1f) == 0x7a400800 && // ccmp w{0-15}, 0, 0, eq
        (opcode_stream[idx+1] & 0xfffffe10) == 0x121d7a00    // and w{0-15}, w{16-31}, 0xfffffffb
    )
    {
        idx += 2;
    }
    else
    {
        return false;
    }

    op = opcode_stream[idx];
    uint32_t shift = 0;
    if((op & 0xfff0fe10) == 0x1a900010) // csel w{16-31}, w{0-15}, w{16-31}, eq
    {
        shift = 16;
    }
    else if((op & 0xfff0fe10) == 0x1a801210) // csel w{16-31}, w{16-31}, w{0-15}, ne
    {
        shift = 5;
    }
    else
    {
        return false;
    }

    // Make sure csel regs match
    if((op & 0x1f) != ((op >> shift) & 0x1f))
    {
        panic("vm_map_protect: mismatching csel regs");
    }
    opcode_stream[idx] = NOP;
    return kpf_vm_map_protect_callback(opcode_stream + idx + 1);
}

static void kpf_vm_map_protect_patch(xnu_pf_patchset_t* xnu_text_exec_patchset)
{
    // We do two things at once here: allow protecting to rwx, and ignore map->map_disallow_new_exec.
    // There's a total of 4 patters we look for. On iOS 13.3.x and older:
    //
    // 0xfffffff0071a10cc      c9061f12       and w9, w22, 6
    // 0xfffffff0071a10d0      3f190071       cmp w9, 6
    // 0xfffffff0071a10d4      81000054       b.ne 0xfffffff0071a10e4
    // 0xfffffff0071a10d8      6800a837       tbnz w8, 0x15, 0xfffffff0071a10e4
    //
    // On most versions from 13.4-15.2 and 16.0 onwards either this:
    //
    // 0xfffffff0072bb038      e903372a       mvn w9, w23
    // 0xfffffff0072bb03c      3f051f72       tst w9, 6
    // 0xfffffff0072bb040      21010054       b.ne 0xfffffff0072bb064
    // 0xfffffff0072bb044      0801b837       tbnz w8, 0x17, 0xfffffff0072bb064
    //
    // Or this:
    //
    // 0xfffffff007afe51c      e903362a       mvn w9, w22
    // 0xfffffff007afe520      3f051f72       tst w9, 6
    // 0xfffffff007afe524      a1000054       b.ne 0xfffffff007afe538
    // 0xfffffff007afe528      88000035       cbnz w8, 0xfffffff007afe538
    //
    // Or this, since iOS 17:
    //
    // 0xfffffff0072c5f84      5f01376a       bics wzr, w10, w23
    // 0xfffffff0072c5f88      61010054       b.ne 0xfffffff0072c5fb4
    // 0xfffffff0072c5f8c      4801b837       tbnz w8, 0x17, 0xfffffff0072c5fb4
    //
    // And then there's a weird carveout from iOS 15.2 to 15.7.x that has stuff inlined in variations of:
    //
    // [and w{0-15}, w{0-15}, 0x800000]                                                 | [tst x{0-15}, 0x800000]
    //                                              mvn w{0-15}, w{16-31}
    //                                              and w{0-15}, w{0-15}, 6
    // [and w{0-15}, w{0-15}, 0x800000]                                                 | [tst x{0-15}, 0x800000]
    //  orr w{0-15}, w{0-15}, w{0-15}                                                   | ccmp w{0-15}, 0, 0, eq
    //  and w{0-15}, w{16-31}, 0xfffffffb                                               | and w{0-15}, w{16-31}, 0xfffffffb
    //  cmp w{0-15}, 0                                                                  | {csel w{16-31}, w{0-15}, w{16-31}, eq | csel w{16-31}, w{16-31}, w{0-15}, ne}
    // {csel w{16-31}, w{0-15}, w{16-31}, eq | csel w{16-31}, w{16-31}, w{0-15}, ne}
    //
    // We just match the "mvn w{0-15}, w{16-31}; and w{0-15}, w{0-15}, w{16-31}" and check the rest in the callback.
    //
    // In the first three cases we simply patch the "b.ne" branch to unconditional, and in the last case we nop out the "csel".
    //
    // After all of these, the is a "tb[n]z w{0-15}, 9, ..." really soon, which we either patch to nop (if tbnz) or unconditional branch (if tbz).
    //
    // /x 00061f121f180071010000540000a837:10feffff1ffeffff1f0000ff1000f8ff
    // /x e003302a1f041f72010000540000a837:f0fff0ff1ffeffff1f0000ff1000e8ff
    // /x e003302a1f041f720100005400000035:f0fff0ff1ffeffff1f0000ff100000ff
    // /x 1f00306a010000540000a837:1ffef0ff1f0000ff1000e8ff
    // /x e003302a00041f12:f0fff0ff10feffff
    uint64_t matches_old[] = {
        0x121f0600, // and w{0-15}, w{16-31}, 6
        0x7100181f, // cmp w{0-15}, 6
        0x54000001, // b.ne 0x...
        0x37a80000, // tbnz w{0-15}, 0x15, 0x...
    };
    uint64_t masks_old[] = {
        0xfffffe10,
        0xfffffe1f,
        0xff00001f,
        0xfff80010,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "vm_map_protect", matches_old, masks_old, sizeof(matches_old)/sizeof(uint64_t), false, (void*)kpf_vm_map_protect_branch_long);

    uint64_t matches_new[] = {
        0x2a3003e0, // mvn w{0-15}, w{16-31}
        0x721f041f, // tst w{0-15}, 6
        0x54000001, // b.ne 0x...
        0x37a80000, // tbnz w{0-15}, {0x15 | 0x17}, 0x...
    };
    uint64_t masks_new[] = {
        0xfff0fff0,
        0xfffffe1f,
        0xff00001f,
        0xffe80010,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "vm_map_protect", matches_new, masks_new, sizeof(matches_new)/sizeof(uint64_t), false, (void*)kpf_vm_map_protect_branch_long);

    matches_new[3] = 0x35000000; // cbnz w{0-15}, 0x...
    masks_new[3]   = 0xff000010;
    xnu_pf_maskmatch(xnu_text_exec_patchset, "vm_map_protect", matches_new, masks_new, sizeof(matches_new)/sizeof(uint64_t), false, (void*)kpf_vm_map_protect_branch_long);

    uint64_t matches17[] = {
        0x6a30001f, // bics wzr, w{0-15}, w{16-31}
        0x54000001, // b.ne 0x...
        0x37a80000, // tbnz w{0-15}, {0x15 | 0x17}, 0x...
    };
    uint64_t masks17[] = {
        0xfff0fe1f,
        0xff00001f,
        0xffe80010,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "vm_map_protect", matches17, masks17, sizeof(matches17)/sizeof(uint64_t), false, (void*)kpf_vm_map_protect_branch_short);

    uint64_t matches_inline[] = {
        0x2a3003e0, // mvn w{0-15}, w{16-31}
        0x121f0400, // and w{0-15}, w{0-15}, 6
    };
    uint64_t masks_inline[] = {
        0xfff0fff0,
        0xfffffe10,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "vm_map_protect", matches_inline, masks_inline, sizeof(matches_inline)/sizeof(uint64_t), false, (void*)kpf_vm_map_protect_inline);
}

bool found_vm_fault_enter;
bool vm_fault_enter_callback(struct xnu_pf_patch* patch, uint32_t* opcode_stream)
{
    if(found_vm_fault_enter)
    {
        DEVLOG("vm_fault_enter_callback: already ran, skipping...");
        return false;
    }
    DEVLOG("Trying vm_fault_enter at 0x%llx", xnu_ptr_to_va(opcode_stream));
    // Should be followed by a TB(N)Z Wx, #2 shortly
    if (!find_next_insn(opcode_stream, 0x18, 0x36100000, 0xFEF80000)) {
        // Wrong place...
        return false;
    }
    uint32_t *b_loc = 0;
    if (!(b_loc = find_prev_insn(opcode_stream, 0x80, 0x14000000, 0xFF000000))) {
        return false;
    }

    uint32_t *wanted_addr = b_loc+1;
    for (int i=2; i<20; i++) {
        uint32_t *try_loc = wanted_addr - i;
        // TBZ or CBZ
        if (((*try_loc|(i<<5))&0xFD07FFE0) == (0x34000000|i<<5)) {
            // Found it!
            *try_loc = NOP;
            puts("KPF: Found vm_fault_enter");
            found_vm_fault_enter = true;
            xnu_pf_disable_patch(patch);
            return true;
        }
    }
    DEVLOG("vm_fault_enter_callback: failed to find patch point");
    return false;
}

bool vm_fault_enter_callback14(struct xnu_pf_patch* patch, uint32_t* opcode_stream)
{
    if(found_vm_fault_enter)
    {
        DEVLOG("vm_fault_enter_callback: already ran, skipping...");
        return false;
    }
    DEVLOG("Trying vm_fault_enter at 0x%llx", xnu_ptr_to_va(opcode_stream));
    // r2 /x
    // Make sure this was preceded by a "tbz w[16-31], 2, ..." that jumps to the code we're currently looking at
    uint32_t *tbz = find_prev_insn(opcode_stream, 0x18, 0x36100010, 0xfff80010);
    if(!tbz)
    {
        // This isn't our TBZ
        return false;
    }
    tbz += sxt32(*tbz >> 5, 14); // uint32 takes care of << 2
    // A few instructions close is good enough
    if(tbz > opcode_stream || opcode_stream - tbz > 2)
    {
        // Apparently still not our TBZ
        return false;
    }
    opcode_stream[0] = NOP;
    puts("KPF: Found vm_fault_enter");
    found_vm_fault_enter = true;
    xnu_pf_disable_patch(patch);
    return true;
}

void kpf_mac_vm_fault_enter_patch(xnu_pf_patchset_t* xnu_text_exec_patchset) {
    // this patch is in vm_fault_enter
    // there is a check for cs_bypass and if that's true it will just exit without validation
    // the opcode is tbz w*, 3, * (because it's the 4th bitflag) and we don't want to take that jump that's why we nop it
    // example from i7 13.3:
    // 0xfffffff0071b3e08      ba001836       tbz w26, 3, 0xfffffff0071b3e1c
    // 0xfffffff0071b3e0c      bf0313b8       stur wzr, [x29, -0xd0]
    // 0xfffffff0071b3e10      1c008052       movz w28, 0
    // 0xfffffff0071b3e14      b98356b8       ldur w25, [x29, -0x98]
    // 0xfffffff0071b3e18      0e010014       b 0xfffffff0071b4250
    // 0xfffffff0071b3e1c      09019837       tbnz w9, 0x13, 0xfffffff0071b3e3c
    // in C code:
    // if (cs_bypass) {
    //   /* code-signing is bypassed */
    //  cs_violation = FALSE;
    //  } else if (m->vmp_cs_tainted) {
    //  [...]
    // r2 cmd:
    // /x 000018361234567800008052:00ffffff0000000000ffffff
    // The problem with this patch was that on some 13.4 kernels they added an instruction between the tbz and movz
    // Because of that we decided to go with a more robuse patch
    // For that we first find the function by searching for the following:
    // 0xfffffff0071b3df0      99001036       tbz w25, 2, 0xfffffff0071b3e00
    // 0xfffffff0071b3df4      6900a036       tbz w9, 0x14, 0xfffffff0071b3e00
    // r2 cmd: /x 000010360000a036:0000ffff0000ffff
    // And then we search downwards for the tbz w*, 3, *  and nop it
    uint64_t matches[] = {
        0x37980000,  // TBNZ Wn, #0x13
        0x37900000   // TBNZ Wn, #0x12
    };
    uint64_t masks[] = {
        0xFFF80000,
        0xFFF80000
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "vm_fault_enter", matches, masks, sizeof(matches)/sizeof(uint64_t), false, (void*)vm_fault_enter_callback);
    uint64_t matches_i[] = {
        0x37980000,  // TBNZ Wn, #0x13
        0x34000000,  // CBZ
        0x37900000   // TBNZ Wn, #0x12
    };
    uint64_t masks_i[] = {
        0xFFF80000,
        0xFF000000,
        0xFFF80000
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "vm_fault_enter", matches_i, masks_i, sizeof(matches)/sizeof(uint64_t), false, (void*)vm_fault_enter_callback);
    uint64_t matches14[] = {
        0x36180000, // TBZ #3
        0x52800000, // MOV #0
    };
    uint64_t masks14[] = {
        0xFFF80000,
        0xFFFFFFE0,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "vm_fault_enter", matches14, masks14, sizeof(matches14)/sizeof(uint64_t), false, (void*)vm_fault_enter_callback14);
    uint64_t matches14_alt[] = {
        0x36180000, // TBZ #3
        0xAA170210, // MOV Xd, Xn (both regs >= 16)
        0x52800000, // MOV #0
    };
    uint64_t masks14_alt[] = {
        0xFFF80000,
        0xFFFFFE10,
        0xFFFFFFE0,
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "vm_fault_enter", matches14_alt, masks14_alt, sizeof(matches14_alt)/sizeof(uint64_t), false, (void*)vm_fault_enter_callback14);
}

uint32_t *vnode_gaddr;

bool vnode_getattr_callback(struct xnu_pf_patch* patch, uint32_t* opcode_stream) {
    if (vnode_gaddr) panic("vnode_getattr_callback: invoked twice");
    puts("KPF: Found vnode_getattr");
    vnode_gaddr = find_prev_insn(opcode_stream, 0x80, 0xd10000FF, 0xFF0000FF);
    xnu_pf_disable_patch(patch);
    return !!vnode_gaddr;
}

uint32_t repatch_ldr_x19_vnode_pathoff;
bool vnode_getpath_callback(struct xnu_pf_patch* patch, uint32_t* opcode_stream)
{
    if(repatch_ldr_x19_vnode_pathoff)
    {
        DEVLOG("vnode_getpath_callback: already ran, skipping...");
        return false;
    }
    puts("KPF: Found vnode_getpath");
    repatch_ldr_x19_vnode_pathoff = opcode_stream[-2];
    xnu_pf_disable_patch(patch);
    return true;
}
uint64_t ret0_gadget;
bool ret0_gadget_callback(struct xnu_pf_patch* patch, uint32_t* opcode_stream)
{
    if(ret0_gadget)
    {
        DEVLOG("ret0_gadget_callback: already ran, skipping...");
        return false;
    }
    puts("KPF: Found ret0 gadget");
    ret0_gadget = xnu_ptr_to_va(opcode_stream);
    xnu_pf_disable_patch(patch);
    return true;
}

uint32_t *vnode_lookup,
         *vnode_put,
         *vfs_context_current;

bool vnode_lookup_callback(struct xnu_pf_patch* patch, uint32_t* opcode_stream)
{
    if(vnode_lookup)
    {
        DEVLOG("vnode_lookup_callback: already ran, skipping...");
        return false;
    }
    uint32_t *try = &opcode_stream[8]+((opcode_stream[8]>>5)&0xFFF);
    if ((try[0]&0xFFE0FFFF) != 0xAA0003E0 ||    // MOV x0, Xn
        (try[1]&0xFC000000) != 0x94000000 ||    // BL _sfree
        (try[3]&0xFF000000) != 0xB4000000 ||    // CBZ
        (try[4]&0xFC000000) != 0x94000000 ) {   // BL _vnode_put
        DEVLOG("Failed match of vnode_lookup code at 0x%llx", kext_rebase_va(xnu_ptr_to_va(opcode_stream)));
        return false;
    }
    puts("KPF: Found vnode_lookup");
    vfs_context_current = follow_call(&opcode_stream[1]);
    vnode_lookup = follow_call(&opcode_stream[6]);
    vnode_put = follow_call(&try[4]);
    xnu_pf_disable_patch(patch);
    return true;
}

void kpf_find_shellcode_funcs(xnu_pf_patchset_t* xnu_text_exec_patchset) {
    // to find this with r2 run:
    // /x 00008192007fbef2:00ffffff00ffffff
    uint64_t matches[] = {
        0x92810000, // movn x*, 0x800
        0xf2be7f00  // movk x*, 0xf3f8, lsl 16
    };
    uint64_t masks[] = {
        0xffffff00,
        0xffffff00
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "vnode_getattr", matches, masks, sizeof(matches)/sizeof(uint64_t), true, (void*)vnode_getattr_callback);

    uint64_t ii_matches[] = {
        0xaa1303e0, // mov x0, x19
        0,
        0xaa0003e1, // mov x1, x0
        0x52800002, // movz w2, 0
        0x52800003, // movz w3, 0
        0xaa1303e0  // mov x0, x19
    };
    uint64_t ii_masks[] = {
        0xffffffff,
        0,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "vnode_getpath", ii_matches, ii_masks, sizeof(ii_matches)/sizeof(uint64_t), false, (void*)vnode_getpath_callback);
    uint64_t iii_matches[] = {
        0xaa1303e0, // mov x0, x19
        0,
        0xaa0003e1, // mov x1, x0
        0xaa1303e0, // mov x0, x19
        0x52800002, // movz w2, 0
        0x52800003  // movz w3, 0
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "vnode_getpath", iii_matches, ii_masks, sizeof(ii_matches)/sizeof(uint64_t), false, (void*)vnode_getpath_callback);

    uint64_t iiii_matches[] = {
        0xd2800000, // movz x0, 0
        RET
    };
    uint64_t iiii_masks[] = {
        0xffffffff,
        0xffffffff
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "ret0_gadget", iiii_matches, iiii_masks, sizeof(iiii_masks)/sizeof(uint64_t), true, (void*)ret0_gadget_callback);
}

static bool found_mach_traps = false;
uint64_t traps_mask[] =
{
    0xffffffffffffffff, 0, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0x0000000000000000, 0xffffffffffffffff,
};
uint64_t traps_match[] =
{
    0x0000000000000000, 0, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000004, 0, 0x0000000000000000, 0x0000000000000005,
};
uint64_t traps_mask_alt[] =
{
    0xffffffffffffffff, 0, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0x0000000000000000,
};
uint64_t traps_match_alt[] =
{
    0x0000000000000000, 0, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000,
    0x0000000000000504, 0, 0x0000000000000000,
};
bool mach_traps_common(uint64_t tfp)
{
    if(found_mach_traps)
    {
        panic("mach_traps found twice!");
    }
    puts("KPF: Found mach traps");

    // for the task for pid routine we only need to patch the first branch that checks if the pid == 0
    // we just replace it with a nop
    // see vm_unix.c in xnu
    uint32_t* tfp0check = find_next_insn((uint32_t*)xnu_va_to_ptr(tfp), 0x20, 0x34000000, 0xff000000);
    if(!tfp0check)
    {
        DEVLOG("mach_traps_callback: failed to find tfp0check");
        return false;
    }

    tfp0check[0] = NOP;
    puts("KPF: Found tfp0");
    found_mach_traps = true;

    return true;
}
bool mach_traps_callback(struct xnu_pf_patch *patch, uint64_t *mach_traps)
{
    return mach_traps_common(xnu_rebase_va(mach_traps[45 * 4 + 1]));
}
bool mach_traps_alt_callback(struct xnu_pf_patch *patch, uint64_t *mach_traps)
{
    return mach_traps_common(xnu_rebase_va(mach_traps[45 * 3 + 1]));
}

bool has_found_sbops = 0;
uint64_t* sbops;
bool sb_ops_callback(struct xnu_pf_patch* patch, uint64_t* sbops_stream) {
    puts("KPF: Found sbops");
    sbops = sbops_stream;
    has_found_sbops = true;
    xnu_pf_disable_patch(patch);
    return true;
}
bool kpf_apfs_patches_rename(struct xnu_pf_patch* patch, uint32_t* opcode_stream) {
    puts("KPF: Found APFS rename");
    opcode_stream[3] = NOP;
    return true;
}

bool kpf_apfs_patches_mount(struct xnu_pf_patch* patch, uint32_t* opcode_stream) {
    // cmp x0, x8
    uint32_t* f_apfs_privcheck = find_next_insn(opcode_stream, 0x10, 0xeb08001f, 0xFFFFFFFF);
    if (!f_apfs_privcheck) {
        DEVLOG("kpf_apfs_patches_mount: failed to find f_apfs_privcheck");
        return false;
    }
    puts("KPF: Found APFS mount");
    *f_apfs_privcheck = 0xeb00001f; // cmp x0, x0
    return true;
}

#if 0
bool kpf_apfs_seal_broken(struct xnu_pf_patch* patch, uint32_t* opcode_stream) {
    puts("KPF: Found root seal broken");
    
    opcode_stream[3] = NOP;

    return true;
}

bool personalized_hash_patched = false;
bool kpf_personalized_root_hash(struct xnu_pf_patch *patch, uint32_t *opcode_stream) {
    // ios 16.4 broke this a lot, so we're just gonna find the string and do stuff with that
    printf("KPF: found kpf_apfs_personalized_hash\n");

    uint32_t* cbz1 = find_prev_insn(opcode_stream, 0x10, 0x34000000, 0x7e000000);

    if (!cbz1) {
        printf("kpf_apfs_personalized_hash: failed to find first cbz\n");
        return false;
    }

    uint32_t* cbz_fail = find_prev_insn(cbz1 + 1, 0x50, 0x34000000, 0x7e000000);

    if (!cbz_fail) {
        printf("kpf_apfs_personalized_hash: failed to find fail cbz\n");
        return false;
    }

    uint64_t addr_fail = xnu_ptr_to_va(cbz_fail) + (sxt32(cbz_fail[0] >> 5, 19) << 2);

    uint32_t *fail_stream = xnu_va_to_ptr(addr_fail);
        
    uint32_t *success_stream = opcode_stream;
    uint32_t *temp_stream = opcode_stream;
        
    for (int i = 0; i < 0x500; i++) {
        if ((temp_stream[0] & 0x9f000000) == 0x90000000 && // adrp
            (temp_stream[1] & 0xff800000) == 0x91000000) { // add
                const char *str = get_string(temp_stream);
                if (strcmp(str, "%s:%d: %s successfully validated on-disk root hash\n") == 0) {
                    success_stream = find_prev_insn(temp_stream, 0x10, 0x35000000, 0x7f000000);

                    if (success_stream) {
                        success_stream++;
                    } else {
                        success_stream = find_prev_insn(temp_stream, 0x10, 0xf90003e0, 0xffc003e0); // str x*, [sp, #0x*]
                        
                        if (!success_stream) {
                            DEVLOG("kpf_apfs_personalized_hash: failed to find start of block");
                        }
                    }
                    
                    break;
                }
        }
                
       temp_stream++;
    }
        
    if (!success_stream) {
        printf("kpf_apfs_personalized_hash: failed to find success!\n");
        return false;
    }
        
    uint64_t addr_success = xnu_ptr_to_va(success_stream);

    DEVLOG("addrs: success is 0x%llx, fail is 0x%llx, target is 0x%llx", addr_success, xnu_ptr_to_va(cbz_fail), addr_fail);
        
    uint32_t branch_success = 0x14000000 | (((addr_success - addr_fail) >> 2) & 0x03ffffff);
        
    DEVLOG("branch is 0x%x (BE)", branch_success);

    fail_stream[0] = branch_success;
    
    personalized_hash_patched = true;

    return true;
}

bool kpf_apfs_auth_required(struct xnu_pf_patch* patch, uint32_t* opcode_stream) {
    printf("KPF: Found root authentication required\n");
    
    uint32_t* func_start = find_prev_insn(opcode_stream, 0x50, 0xa98003e0, 0xffc003e0); //stp x*, x*, [sp, -0x*]!
        
    if (!func_start) {
        func_start = find_prev_insn(opcode_stream, 0x50, 0xd10000ff, 0xffc003ff); // sub sp, sp, 0x*
            
        if (!func_start) {
            printf("root authentication: failed to find stack marker!\n");
            return false;
        }
    }
        
    func_start[0] = 0xd2800000;
    func_start[1] = RET;
        
    return true;
}
#endif

bool kpf_apfs_vfsop_mount(struct xnu_pf_patch *patch, uint32_t *opcode_stream) {
    if (!opcode_stream) {
        printf("Missing patch: apfs_vfsop_mount\n");
        return false;
    }
    uint32_t *tbnz = find_prev_insn(opcode_stream, 2, 0x37700000, 0xfff8001f); // tbnz w0, 0xe, *
    if (!tbnz) {
        return false;
    }

    *tbnz = 0x52800000; /* mov w0, 0 */
    
    printf("KPF: found apfs_vfsop_mount\n");
    
    return true;
}

#if 0
bool handled_eval_rootauth = false;
bool kpf_apfs_rootauth(struct xnu_pf_patch *patch, uint32_t *opcode_stream) {
    handled_eval_rootauth = true;

    opcode_stream[0] = NOP;
    opcode_stream[1] = 0x52800000; /* mov w0, 0 */

    printf("KPF: found handle_eval_rootauth\n");
    return true;
}

bool kpf_apfs_rootauth_new(struct xnu_pf_patch *patch, uint32_t *opcode_stream) {
    handled_eval_rootauth = true;

    uint32_t orig_register = (opcode_stream[1] & 0x1f);
    opcode_stream[0] = NOP;
    opcode_stream[1] = 0x52800000 | orig_register; /* mov wN, 0 */
    
    uint32_t *ret_stream = follow_call(opcode_stream + 2);
    
    if (!ret_stream) {
        printf("KPF: failed to follow branch\n");
        return false;
    }
    
    uint32_t *mov = ret_stream;
    while (true) {  
        mov = find_next_insn(mov, 0x10, 0xaa0003e0, 0xffe0ffff); // mov x0, xN

        if (!mov) {
            printf("KPF: failed to find mov\n");
            return false;
        }

        uint32_t mov_register = (mov[0] >> 16) & 0x1f;

        if (mov_register == orig_register) {
            break;
        }

        mov++;
    }
    
    mov[0] = 0xd2800000; /* mov x0, 0 */

    printf("KPF: found handle_eval_rootauth\n");
    return true;
}
#endif

void kpf_apfs_patches(xnu_pf_patchset_t* patchset, bool have_union) {
    // there is a check in the apfs mount function that makes sure that the kernel task is calling this function (current_task() == kernel_task)
    // we also want to call it so we patch that check out
    // example from i7 13.3:
    // 0xfffffff00692e67c      e8034139       ldrb w8, [sp, 0x40] ; [0x40:4]=392 <- we patchfind this
    // 0xfffffff00692e680      08011b32       orr w8, w8, 0x20
    // 0xfffffff00692e684      e8030139       strb w8, [sp, 0x40]
    // 0xfffffff00692e688      e83b40b9       ldr w8, [sp, 0x38]  ; [0x38:4]=0
    // 0xfffffff00692e68c      e85301b9       str w8, [sp, 0x150]
    // 0xfffffff00692e690      e85741b9       ldr w8, [sp, 0x154] ; [0x154:4]=0x7c95
    // 0xfffffff00692e694      08010032       orr w8, w8, 1
    // 0xfffffff00692e698      e85701b9       str w8, [sp, 0x154]
    // 0xfffffff00692e69c      59550194       bl sym.stub._current_task_31
    // 0xfffffff00692e6a0      e83100b0       adrp x8, 0xfffffff006f6b000 <- kernel task
    // 0xfffffff00692e6a4      089544f9       ldr x8, [x8, 0x928] ; [0x928:4]=0x5458
    // 0xfffffff00692e6a8      080140f9       ldr x8, [x8]
    // 0xfffffff00692e6ac      1f0008eb       cmp x0, x8 <- cmp (patches to cmp x0, x0)
    // r2 cmd:
    // /x 0000403908011b3200000039000000b9:0000c0bfffffffff0000c0bf000000ff
    uint64_t matches[] = {
        0x39400000, // ldr{b|h} w*, [x*]
        0x321b0108, // orr w8, w8, 0x20
        0x39000000, // str{b|h} w*, [x*]
        0xb9000000  // str w*, [x*]
    };
    uint64_t masks[] = {
        0xbfc00000,
        0xffffffff,
        0xbfc00000,
        0xff000000,
    };
    xnu_pf_maskmatch(patchset, "apfs_patch_mount", matches, masks, sizeof(matches)/sizeof(uint64_t), true, (void*)kpf_apfs_patches_mount);
    if(have_union)
    {
        // the rename function will prevent us from renaming a snapshot that's on the rootfs, so we will just patch that check out
        // example from i7 13.3
        // 0xfffffff0068f3d58      e02f00f9       str x0, [sp, 0x58]
        // 0xfffffff0068f3d5c      e01f00f9       str x0, [sp, 0x38]
        // 0xfffffff0068f3d60      08c44039       ldrb w8, [x0, 0x31] ; [0x31:4]=
        // 0xfffffff0068f3d64      68043037       tbnz w8, 6, 0xfffffff0068f3df0 <- patch this out
        // Since iOS 15, the "str" can also be "stur", so we mask out one of the upper bits to catch both,
        // and we apply a mask of 0x1d to the base register, to catch exactly x29 and sp.
        // r2 cmd:
        // /x a00300f8a00300f80000403900003037:a003c0fea003c0fe0000feff0000f8ff
        uint64_t i_matches[] = {
            0xf80003a0, // st(u)r x*, [x29/sp, *]
            0xf80003a0, // st(u)r x*, [x29/sp, *]
            0x39400000, // ldrb w*, [x*]
            0x37300000, // tbnz w*, 6, *
        };
        uint64_t i_masks[] = {
            0xfec003a0,
            0xfec003a0,
            0xfffe0000,
            0xfff80000,
        };
        xnu_pf_maskmatch(patchset, "apfs_patch_rename", i_matches, i_masks, sizeof(i_matches)/sizeof(uint64_t), true, (void*)kpf_apfs_patches_rename);
    }

    // if(palera1n_flags & palerain_option_rootful)
    {   
        // This patch is not required on rootless, but it is nice to have as still as some
        // actions over SSH would not be possible without it.
        // when mounting an apfs volume, there is a check to make sure the volume is not read/write
        // we just nop the check out
        // example from iPad 6 16.1.1:
        // 0xfffffff0064023a8      e8b340b9       ldr w8, [sp, 0xb0]  ; 5
        // 0xfffffff0064023ac      08791f12       and w8, w8, 0xfffffffe
        // 0xfffffff0064023b0      e8b300b9       str w8, [sp, 0xb0]
        // r2: /x a00340b900781f12a00300b9:a003feff00fcffffa003c0ff
        uint64_t remount_matches[] = {
            0xb94003a0, // ldr x*, [x29/sp, *]
            0x121f7800, // and w*, w*, 0xfffffffe
            0xb90003a0, // str x*, [x29/sp, *]
        };
        
        uint64_t remount_masks[] = {
            0xfffe03a0,
            0xfffffc00,
            0xffc003a0,
        };
        
        xnu_pf_maskmatch(patchset,
            "apfs_vfsop_mount", remount_matches, remount_masks, sizeof(remount_masks) / sizeof(uint64_t),
        !have_union
#ifndef DEV_BUILD
        && (palera1n_flags & palerain_option_rootful) != 0
#endif
    ,(void *)kpf_apfs_vfsop_mount);
        
    }
}
static uint32_t* amfi_ret;
bool kpf_amfi_execve_tail(struct xnu_pf_patch* patch, uint32_t* opcode_stream) {
    if(amfi_ret)
    {
        panic("kpf_amfi_execve_tail: found twice!");
    }
    amfi_ret = find_next_insn(opcode_stream, 0x80, RET, 0xFFFFFFFF);
    if (!amfi_ret)
    {
        DEVLOG("kpf_amfi_execve_tail: failed to find amfi_ret");
        return false;
    }
    puts("KPF: Found AMFI execve hook");
    return true;
}
bool kpf_amfi_sha1(struct xnu_pf_patch* patch, uint32_t* opcode_stream) {
    uint32_t* cmp = find_next_insn(opcode_stream, 0x10, 0x7100081f, 0xFFFFFFFF); // cmp w0, 2
    if (!cmp) {
        DEVLOG("kpf_amfi_sha1: failed to find cmp");
        return false;
    }
    puts("KPF: Found AMFI hashtype check");
    xnu_pf_disable_patch(patch);
    *cmp = 0x6b00001f; // cmp w0, w0
    return true;
}

void kpf_find_offset_p_flags(uint32_t *proc_issetugid) {
    DEVLOG("Found kpf_find_offset_p_flags 0x%llx", xnu_ptr_to_va(proc_issetugid));
    if (!proc_issetugid) {
        panic("kpf_find_offset_p_flags called with no argument");
    }
    // FIND LDR AND READ OFFSET
    if((*proc_issetugid & 0xffc003c0) != 0xb9400000)
    {
        panic("kpf_find_offset_p_flags failed to find LDR");
    }
    offsetof_p_flags = ((*proc_issetugid>>10)&0xFFF)<<2;
    DEVLOG("Found offsetof_p_flags %x", offsetof_p_flags);
}

bool found_amfi_mac_syscall = false;
bool kpf_amfi_mac_syscall(struct xnu_pf_patch *patch, uint32_t *opcode_stream) {
    if(found_amfi_mac_syscall)
    {
        panic("amfi_mac_syscall found twice!");
    }
    // Our initial masking match is extremely broad and we have two of them so
    // we have to mark both as non-required, which means returning false does
    // nothing. But we panic on failure, so if we survive, we patched successfully.
    found_amfi_mac_syscall = true;

    bool foundit = false;
    uint32_t *rep = opcode_stream;
    for(size_t i = 0; i < 25; ++i)
    {
        uint32_t op = *rep;
        if(op == 0x321c03e2 /* orr w2, wzr, 0x10 */ || op == 0x52800202 /* movz w2, 0x10 */)
        {
            foundit = true;
            puts("KPF: Found AMFI mac_syscall");
            break;
        }
        rep++;
    }
    if(!foundit)
    {
        panic_at(opcode_stream, "Failed to find w2 in mac_syscall");
    }
    uint32_t *copyin = find_next_insn(rep + 1, 2, 0x94000000, 0xfc000000); // bl
    if(!copyin)
    {
        panic_at(rep, "Failed to find copyin in mac_syscall");
    }
    uint32_t *bl = find_next_insn(copyin + 1, 10, 0x94000000, 0xfc000000);
    if(!bl)
    {
        panic_at(copyin, "Failed to find check_dyld_policy_internal in mac_syscall");
    }
    uint32_t *check_dyld_policy_internal = follow_call(bl);
    if(!check_dyld_policy_internal)
    {
        panic_at(bl, "Failed to follow call to check_dyld_policy_internal");
    }
    // Find call to proc_issetuid
    uint32_t *ref = find_next_insn(check_dyld_policy_internal, 10, 0x94000000, 0xfc000000);
    if((ref[1] & 0xff00001f) != 0x34000000)
    {
        panic_at(ref, "CBZ missing after call to proc_issetuid");
    }
    // Save offset of p_flags
    kpf_find_offset_p_flags(follow_call(ref));
    // Follow CBZ
    ref++;
    ref += sxt32(*ref >> 5, 19); // uint32 takes care of << 2
    // Check for new developer_mode_state()
    bool dev_mode = (ref[0] & 0xfc000000) == 0x94000000;
#ifdef DEV_BUILD
    // 16.0 beta and up
    if(dev_mode != (gKernelVersion.darwinMajor >= 22)) panic_at(ref, "Presence of developer_mode_state doesn't match expected Darwin version");
#endif
    if(dev_mode)
    {
        if((ref[1] & 0xff00001f) != 0x34000000)
        {
            panic_at(ref, "CBZ missing after call to developer_mode_state");
        }
        ref[0] = 0x52800020; // mov w0, 1
        ref += 2;
    }
    // This can be either proc_has_get_task_allow() or proc_has_entitlement()
    bool entitlement = (ref[0] & 0x9f00001f) == 0x90000001 && (ref[1] & 0xffc003ff) == 0x91000021;
#ifdef DEV_BUILD
    // iOS 13 and below
    if(entitlement != (gKernelVersion.darwinMajor <= 19)) panic_at(ref, "Call to proc_has_entitlement doesn't match expected Darwin version");
#endif
    if(entitlement) // adrp+add to x1
    {
        // This is proc_has_entitlement(), so make sure it's the right entitlement
        uint64_t page = ((uint64_t)ref & ~0xfffULL) + adrp_off(ref[0]);
        uint32_t off = (ref[1] >> 10) & 0xfff;
        const char *str = (const char*)(page + off);
        if(strcmp(str, "get-task-allow") != 0)
        {
            panic_at(ref, "Wrong entitlement passed to proc_has_entitlement");
        }
        ref += 2;
    }
    // Move from high reg, bl, and either tbz, 0 or cmp, 0
    uint32_t op = ref[2];
    if((ref[0] & 0xfff003ff) != 0xaa1003e0 || (ref[1] & 0xfc000000) != 0x94000000 || ((op & 0xfff8001f) != 0x36000000 && op != 0x7100001f))
    {
        panic_at(check_dyld_policy_internal, "CMP/TBZ missing after call to %s", entitlement ? "proc_has_entitlement" : "proc_has_get_task_allow");
    }
    ref[1] = 0x52800020; // mov w0, 1
    return true;
}
bool kpf_amfi_mac_syscall_low(struct xnu_pf_patch *patch, uint32_t *opcode_stream) {
    // Unlike the other matches, the case we want is *not* the fallthrough one here.
    // So we need to follow the b.eq for 0x5a here.
    return kpf_amfi_mac_syscall(patch, opcode_stream + 3 + sxt32(opcode_stream[3] >> 5, 19)); // uint32 takes care of << 2
}
void kpf_amfi_kext_patches(xnu_pf_patchset_t* patchset) {
    // this patch helps us find the return of the amfi function so that we can jump into shellcode from there and modify the cs flags
    // to do that we search for the sequence below also as an example from i7 13.3:
    // 0xfffffff005f340cc      00380b91       add x0, x0, 0x2ce
    // 0xfffffff005f340d0      48000014       b 0xfffffff005f341f0
    // 0xfffffff005f340d4      230c0094       bl sym.stub._cs_system_require_lv
    // 0xfffffff005f340d8      e80240b9       ldr w8, [x23]
    // 0xfffffff005f340dc      80000034       cbz w0, 0xfffffff005f340ec
    // 0xfffffff005f340e0      09408452       movz w9, 0x2200
    // 0xfffffff005f340e4      0801092a       orr w8, w8, w9
    //
    // On iOS 15.4, the control flow changed somewhat:
    // 0xfffffff005b76918      3d280094       bl sym.stub._cs_system_require_lv
    // 0xfffffff005b7691c      080340b9       ldr w8, [x24]
    // 0xfffffff005b76920      60000034       cbz w0, 0xfffffff005b7692c
    // 0xfffffff005b76924      09408452       mov w9, 0x2200
    // 0xfffffff005b76928      03000014       b 0xfffffff005b76934
    // 0xfffffff005b7692c      88002037       tbnz w8, 4, 0xfffffff005b7693c
    // 0xfffffff005b76930      09408052       mov w9, 0x200
    // 0xfffffff005b76934      0801092a       orr w8, w8, w9
    //
    // So now all that we look for is:
    // ldr w8, [x{16-31}]
    // cbz w0, {forward}
    // mov w9, 0x2200
    //
    // To find this with r2, run:
    // /x 080240b90000003409408452:1ffeffff1f0080ffffffffff
    uint64_t matches[] = {
        0xb9400208, // ldr w8, [x{16-31}]
        0x34000000, // cbz w0, {forward}
        0x52844009, // movz w9, 0x2200
    };
    uint64_t masks[] = {
        0xfffffe1f,
        0xff80001f,
        0xffffffff,
    };
    xnu_pf_maskmatch(patchset, "amfi_execve_tail", matches, masks, sizeof(matches)/sizeof(uint64_t), true, (void*)kpf_amfi_execve_tail);

    // this patch allows us to run binaries with SHA1 signatures
    // this is done by searching for the sequence below and then finding the cmp w0, 2 (hashtype) and turning that into a cmp w0, w0
    // Example from i7 13.3:
    // 0xfffffff005f36b30      2201d036       tbz w2, 0x1a, 0xfffffff005f36b54
    // 0xfffffff005f36b34      f30305aa       mov x19, x5
    // 0xfffffff005f36b38      f40304aa       mov x20, x4
    // 0xfffffff005f36b3c      f50303aa       mov x21, x3
    // 0xfffffff005f36b40      f60300aa       mov x22, x0
    // 0xfffffff005f36b44      e00301aa       mov x0, x1
    // 0xfffffff005f36b48      a1010094       bl sym.stub._csblob_get_hashtype
    // 0xfffffff005f36b4c      1f080071       cmp w0, 2
    // 0xfffffff005f36b50      61000054       b.ne 0xfffffff005f36b5c
    // to find this in r2 run (make sure to check if the address is aligned):
    // /x 0200d036:1f00f8ff
    uint64_t i_matches[] = {
        0x36d00002, // tbz w2, 0x1a, *
    };
    uint64_t i_masks[] = {
        0xfff8001f,
    };
    xnu_pf_maskmatch(patchset, "amfi_sha1",i_matches, i_masks, sizeof(i_matches)/sizeof(uint64_t), true, (void*)kpf_amfi_sha1);

    // this patch will patch out checks for get_task_allow inside of the mac_syscall
    // this is done by searching for the sequence below (both syscall numbers that are handled inside of the function), then following the call and patching out the get_task_allow check
    // this patch also provides the location to identify the offset of proc->p_flags which is used by the setuid shellcode
    // Example from i7 13.3:
    // 0xfffffff005f365a0      3f6c0171       cmp w1, 0x5b <- we first find this sequence
    // 0xfffffff005f365a4      e0020054       b.eq 0xfffffff005f36600
    // 0xfffffff005f365a8      3f680171       cmp w1, 0x5a
    // 0xfffffff005f365ac      41060054       b.ne 0xfffffff005f36674
    // 0xfffffff005f365b0      40e5054f       movi v0.16b, 0xaa
    // 0xfffffff005f365b4      e007803d       str q0, [sp, 0x10]
    // 0xfffffff005f365b8      ff0700f9       str xzr, [sp, 8]
    // 0xfffffff005f365bc      020600b4       cbz x2, 0xfffffff005f3667c
    // 0xfffffff005f365c0      f40300aa       mov x20, x0
    // 0xfffffff005f365c4      e1430091       add x1, sp, 0x10
    // 0xfffffff005f365c8      e00302aa       mov x0, x2
    // 0xfffffff005f365cc      e2031c32       orr w2, wzr, 0x10
    // 0xfffffff005f365d0      cf020094       bl sym.stub._copyin
    // 0xfffffff005f365d4      f30300aa       mov x19, x0
    // 0xfffffff005f365d8      40050035       cbnz w0, 0xfffffff005f36680
    // 0xfffffff005f365dc      e1230091       add x1, sp, 8
    // 0xfffffff005f365e0      e00314aa       mov x0, x20
    // 0xfffffff005f365e4      ed000094       bl 0xfffffff005f36998 <- then nops this and make sure x1 is -1
    // 0xfffffff005f365e8      e10f40f9       ldr x1, [sp, 0x18]  ; [0x18
    // 0xfffffff005f365ec      e0230091       add x0, sp, 8
    // 0xfffffff005f365f0      e2031d32       orr w2, wzr, 8 <- then this
    // 0xfffffff005f365f4      c9020094       bl sym.stub._copyout_1
    // to find this in r2 run:
    // /x 3f6c0171000000543f68017101000054:ffffffff1f0000ffffffffff1f0000ff
    uint64_t ii_matches[] = {
        0x71016c3f, // cmp w1, 0x5b
        0x54000000, // b.eq
        0x7101683f, // cmp w1, 0x5a
        0x54000001, // b.ne
    };
    uint64_t ii_masks[] = {
        0xffffffff,
        0xff00001f,
        0xffffffff,
        0xff00001f,
    };
    xnu_pf_maskmatch(patchset, "amfi_mac_syscall", ii_matches, ii_masks, sizeof(ii_matches)/sizeof(uint64_t), false, (void*)kpf_amfi_mac_syscall);

    // iOS 15 changed to a switch/case:
    //
    // 0xfffffff00830e9cc      ff4303d1       sub sp, sp, 0xd0
    // 0xfffffff00830e9d0      f6570aa9       stp x22, x21, [sp, 0xa0]
    // 0xfffffff00830e9d4      f44f0ba9       stp x20, x19, [sp, 0xb0]
    // 0xfffffff00830e9d8      fd7b0ca9       stp x29, x30, [sp, 0xc0]
    // 0xfffffff00830e9dc      fd030391       add x29, sp, 0xc0
    // 0xfffffff00830e9e0      08a600b0       adrp x8, 0xfffffff0097cf000
    // 0xfffffff00830e9e4      1f2003d5       nop
    // 0xfffffff00830e9e8      083940f9       ldr x8, [x8, 0x70]
    // 0xfffffff00830e9ec      a8831df8       stur x8, [x29, -0x28]
    // 0xfffffff00830e9f0      d3098052       mov w19, 0x4e
    // 0xfffffff00830e9f4      28680151       sub w8, w1, 0x5a
    // 0xfffffff00830e9f8      1f290071       cmp w8, 0xa
    // 0xfffffff00830e9fc      88150054       b.hi 0xfffffff00830ecac
    // 0xfffffff00830ea00      f40302aa       mov x20, x2
    // 0xfffffff00830ea04      f50300aa       mov x21, x0
    // 0xfffffff00830ea08      296afff0       adrp x9, 0xfffffff007055000
    // 0xfffffff00830ea0c      29c13d91       add x9, x9, 0xf70
    // 0xfffffff00830ea10      8a000010       adr x10, 0xfffffff00830ea20
    // 0xfffffff00830ea14      2b696838       ldrb w11, [x9, x8]
    // 0xfffffff00830ea18      4a090b8b       add x10, x10, x11, lsl 2
    // 0xfffffff00830ea1c      40011fd6       br x10
    // 0xfffffff00830ea20      40e5054f       movi v0.16b, 0xaa
    // 0xfffffff00830ea24      e00f803d       str q0, [sp, 0x30]
    // 0xfffffff00830ea28      ff0f00f9       str xzr, [sp, 0x18]
    // 0xfffffff00830ea2c      f41300b4       cbz x20, 0xfffffff00830eca8
    // 0xfffffff00830ea30      e1c30091       add x1, sp, 0x30
    // 0xfffffff00830ea34      e00314aa       mov x0, x20
    // 0xfffffff00830ea38      02028052       mov w2, 0x10
    // 0xfffffff00830ea3c      8e3ee797       bl 0xfffffff007cde474
    // 0xfffffff00830ea40      f30300aa       mov x19, x0
    // 0xfffffff00830ea44      40130035       cbnz w0, 0xfffffff00830ecac
    // 0xfffffff00830ea48      e1630091       add x1, sp, 0x18
    // 0xfffffff00830ea4c      e00315aa       mov x0, x21
    // 0xfffffff00830ea50      7c020094       bl 0xfffffff00830f440
    // 0xfffffff00830ea54      e11f40f9       ldr x1, [sp, 0x38]
    // 0xfffffff00830ea58      e0630091       add x0, sp, 0x18
    // 0xfffffff00830ea5c      02018052       mov w2, 8
    // 0xfffffff00830ea60      50000014       b 0xfffffff00830eba0
    //
    // We find the "sub wN, w1, 0x5a", then the "mov w2, 0x10; bl ..." after that, then the "bl" after that.
    // /x 20680151:e0ffffff
    uint64_t iii_matches[] = {
        0x51016820, // sub wN, w1, 0x5a
    };
    uint64_t iii_masks[] = {
        0xffffffe0,
    };
    xnu_pf_maskmatch(patchset, "amfi_mac_syscall_alt", iii_matches, iii_masks, sizeof(iii_matches)/sizeof(uint64_t), false, (void*)kpf_amfi_mac_syscall);

    // tvOS/audioOS 16 and bridgeOS 7 apparently got some cases removed, so their codegen looks different again.
    //
    // 0xfffffff008b0ad48      3f780171       cmp w1, 0x5e
    // 0xfffffff008b0ad4c      cc030054       b.gt 0xfffffff008b0adc4
    // 0xfffffff008b0ad50      3f680171       cmp w1, 0x5a
    // 0xfffffff008b0ad54      40060054       b.eq 0xfffffff008b0ae1c
    // 0xfffffff008b0ad58      3f6c0171       cmp w1, 0x5b
    // 0xfffffff008b0ad5c      210e0054       b.ne 0xfffffff008b0af20
    //
    // r2:
    // /x 3f7801710c0000543f680171000000543f6c017101000054:ffffffff1f0000ffffffffff1f0000ffffffffff1f0000ff
    uint64_t iiii_matches[] = {
        0x7101783f, // cmp w1, 0x5e
        0x5400000c, // b.gt
        0x7101683f, // cmp w1, 0x5a
        0x54000000, // b.eq
        0x71016c3f, // cmp w1, 0x5b
        0x54000001, // b.ne
    };
    uint64_t iiii_masks[] = {
        0xffffffff,
        0xff00001f,
        0xffffffff,
        0xff00001f,
        0xffffffff,
        0xff00001f,
    };
    xnu_pf_maskmatch(patchset, "amfi_mac_syscall_low", iiii_matches, iiii_masks, sizeof(iiii_matches)/sizeof(uint64_t), false, (void*)kpf_amfi_mac_syscall_low);
}

void kpf_sandbox_kext_patches(xnu_pf_patchset_t* patchset) {
    uint64_t matches[] = {
        0x35000000, // CBNZ
        0x94000000, // BL _vfs_context_current
        0xAA0003E0, // MOV Xn, X0
        0xD1006002, // SUB
        0x00000000, // MOV X0, Xn || MOV W1, #0
        0x00000000, // MOV X0, Xn || MOV W1, #0
        0x94000000, // BL _vnode_lookup
        0xAA0003E0, // MOV Xn, X0
        0x35000000  // CBNZ
    };
    uint64_t masks[] = {
        0xFF000000,
        0xFC000000,
        0xFFFFFFE0,
        0xFFFFE01F,
        0x00000000,
        0x00000000,
        0xFC000000,
        0xFFFFFFE0,
        0xFF000000
    };
    xnu_pf_maskmatch(patchset, "vnode_lookup", matches, masks, sizeof(masks)/sizeof(uint64_t), true, (void*)vnode_lookup_callback);
}

bool vnop_rootvp_auth_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream) {
    // cmp xN, xM - wrong match
    if((opcode_stream[2] & 0xffe0ffe0) == 0xeb000300)
    {
        return false;
    }
    // Old sequence like:
    // 0xfffffff00759d9f8      61068d52       mov w1, 0x6833
    // 0xfffffff00759d9fc      8100b072       movk w1, 0x8004, lsl 16
    // 0xfffffff00759da00      020080d2       mov x2, 0
    // 0xfffffff00759da04      03008052       mov w3, 0
    // 0xfffffff00759da08      4ca3f797       bl sym._VNOP_IOCTL
    if
    (
        opcode_stream[0] == 0x528d0661 &&
        opcode_stream[1] == 0x72b00081 &&
        opcode_stream[2] == 0xd2800002 &&
        opcode_stream[3] == 0x52800003 &&
        (opcode_stream[4] & 0xfc000000) == 0x94000000
    )
    {
        puts("KPF: Found vnop_rootvp_auth");
        // Replace the call with mov x0, 0
        opcode_stream[4] = 0xd2800000;
        return true;
    }
    // New sequence like:
    // 0xfffffff00759c994      6a068d52       mov w10, 0x6833
    // 0xfffffff00759c998      8a00b072       movk w10, 0x8004, lsl 16
    // 0xfffffff00759c99c      ea7f0ca9       stp x10, xzr, [sp, 0xc0]
    // 0xfffffff00759c9a0      ffd300b9       str wzr, [sp, 0xd0]
    // 0xfffffff00759c9a4      f36f00f9       str x19, [sp, 0xd8]
    // 0xfffffff00759c9a8      086940f9       ldr x8, [x8, 0xd0]
    // 0xfffffff00759c9ac      290180b9       ldrsw x9, [x9]
    // 0xfffffff00759c9b0      087969f8       ldr x8, [x8, x9, lsl 3]
    // 0xfffffff00759c9b4      e0c30291       add x0, sp, 0xb0
    // 0xfffffff00759c9b8      00013fd6       blr x8
    uint32_t reg = opcode_stream[1] & 0x1f;
    uint32_t op = opcode_stream[2];
    uint32_t *sp = NULL;
    if((op & 0xffe07fff) == (0xa9007fe0 | reg)) // stp xN, xzr, [sp, 0x...]
    {
        sp = find_next_insn(opcode_stream + 3, 0x10, 0x910003e0, 0xffc003ff); // add x0, sp, 0x...
    }
    else if((op & 0xffe07fff) == (0xa9207fa0 | reg)) // stp xN, xzr, [x29, -0x...]
    {
        sp = find_next_insn(opcode_stream + 3, 0x10, 0xd10003a0, 0xffc003ff); // sub x0, x29, 0x...
    }
    if(sp && (sp[1] & 0xfffffc1f) == 0xd63f0000) // blr
    {
        puts("KPF: Found vnop_rootvp_auth");
        // Replace the call with mov x0, 0
        sp[1] = 0xd2800000;
        return true;
    }
    return false;
}

void kpf_vnop_rootvp_auth_patch(xnu_pf_patchset_t* patchset) {
    // /x 60068d528000b072:f0fffffff0ffffff
    uint64_t matches[] = {
        0x528d0660, // movz w{0-15}, 0x6833
        0x72b00080, // movk w{0-15}, 0x8004, lsl 16
    };
    uint64_t masks[] = {
        0xfffffff0,
        0xfffffff0,
    };
    xnu_pf_maskmatch(patchset, "vnop_rootvp_auth", matches, masks, sizeof(masks)/sizeof(uint64_t), true, (void*)vnop_rootvp_auth_callback);
}

#if 0
bool root_livefs_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream) {
    puts("KPF: Found root_livefs");
    opcode_stream[2] = NOP;
    return true;
}

void kpf_root_livefs_patch(xnu_pf_patchset_t* patchset) {
    uint64_t matches[] = {
        0xF9406108, // LDR             X8, [X8,#0xC0]
        0x3940E108, // LDRB            W8, [X8,#0x38]
        0x37280008, // TBNZ            W8, #5, loc_FFFFFFF008E60F1C
    };
    uint64_t masks[] = {
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFF8001F,
    };
    xnu_pf_maskmatch(patchset, "root_livefs", matches, masks, sizeof(masks)/sizeof(uint64_t), true, (void*)root_livefs_callback);
}
#endif

static uint32_t shellcode_count;
static uint32_t *shellcode_area;

static bool kpf_find_shellcode_area_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    // For anything else we wouldn't want to disable the patch to make sure that
    // we only match what we want to, but this is literally just empty space.
    xnu_pf_disable_patch(patch);
    shellcode_area = opcode_stream;
    puts("KPF: Found shellcode area");
    return true;
}

static void kpf_find_shellcode_area(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    // Find a place inside of the executable region that has no opcodes in it (just zeros/padding)
    uint32_t count = shellcode_count;
    // TODO: get rid of this
    {
        count += (sandbox_shellcode_end - sandbox_shellcode);
    }
    uint64_t matches[count];
    uint64_t masks[count];
    for(size_t i = 0; i < count; ++i)
    {
        matches[i] = 0;
        masks[i] = 0xffffffff;
    }
    xnu_pf_maskmatch(xnu_text_exec_patchset, "shellcode_area", matches, masks, count, true, (void*)kpf_find_shellcode_area_callback);
}

static kpf_component_t kpf_shellcode =
{
    .patches =
    {
        { NULL, "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_find_shellcode_area },
        {},
    },
};

static int kpf_compare_patches(const void *a, const void *b)
{
    kpf_patch_t *one = *(kpf_patch_t**)a,
                *two = *(kpf_patch_t**)b;
    int cmp;
    // Bundle
    cmp = one->bundle ? (two->bundle ? strcmp(one->bundle, two->bundle) : 1) : (two->bundle ? -1 : 0);
    if(cmp != 0)
    {
        return cmp;
    }
    // Segment
    cmp = strcmp(one->segment, two->segment);
    if(cmp != 0)
    {
        return cmp;
    }
    // Section
    cmp = one->section ? (two->section ? strcmp(one->section, two->section) : 1) : (two->section ? -1 : 0);
    if(cmp != 0)
    {
        return cmp;
    }
    // Granule
    return (int)one->granule - (int)two->granule;
}

kpf_component_t* const kpf_components[] = {
    &kpf_bindfs,
    &kpf_developer_mode,
    &kpf_dyld,
    &kpf_launch_constraints,
    &kpf_mach_port,
    &kpf_nvram,
    &kpf_shellcode,
    &kpf_overlay,
    &kpf_ramdisk,
    &kpf_trustcache,
    &kpf_vfs,
    &kpf_vm_prot,
};

static void kpf_cmd(const char *cmd, char *args)
{
    static bool kpf_didrun = false;
    if(kpf_didrun)
    {
        puts("checkra1n KPF did run already! Behavior here is undefined.\n");
    }
    kpf_didrun = true;

    uint64_t tick_0 = get_ticks();
    uint64_t tick_1;

    size_t npatches = 0;
    for(size_t i = 0; i < sizeof(kpf_components)/sizeof(kpf_components[0]); ++i)
    {
        kpf_component_t *component = kpf_components[i];
        for(size_t j = 0; component->patches[j].patch; ++j)
        {
            ++npatches;
        }
    }

    kpf_patch_t **patches = malloc(npatches * sizeof(kpf_patch_t*));
    if(!patches)
    {
        panic("Failed to allocate patches array");
    }

    for(size_t i = 0, n = 0; i < sizeof(kpf_components)/sizeof(kpf_components[0]); ++i)
    {
        kpf_component_t *component = kpf_components[i];
        for(size_t j = 0; component->patches[j].patch; ++j)
        {
            kpf_patch_t *patch = &component->patches[j];
            if(!patch->segment)
            {
                panic("KPF component %zu, patch %zu has NULL segment", i, j);
            }
            if(patch->granule != XNU_PF_ACCESS_8BIT && patch->granule != XNU_PF_ACCESS_16BIT && patch->granule != XNU_PF_ACCESS_32BIT && patch->granule != XNU_PF_ACCESS_64BIT)
            {
                panic("KPF component %zu, patch %zu has invalid granule", i, j);
            }
            patches[n++] = patch;
        }
    }

    qsort(patches, npatches, sizeof(kpf_patch_t*), kpf_compare_patches);

    xnu_pf_patchset_t* xnu_text_exec_patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT);
    found_vm_fault_enter = false;
    kpf_has_done_mac_mount = false;
    vnode_gaddr = NULL;
    vfs_context_current = NULL;
    offsetof_p_flags = -1;

    struct mach_header_64* hdr = xnu_header();
    xnu_pf_range_t* text_cstring_range = xnu_pf_section(hdr, "__TEXT", "__cstring");

#ifdef DEV_BUILD
    xnu_pf_range_t *text_const_range = xnu_pf_section(hdr, "__TEXT", "__const");
    kpf_kernel_version_init(text_const_range);
    free(text_const_range);
#endif

    // extern struct mach_header_64* xnu_pf_get_kext_header(struct mach_header_64* kheader, const char* kext_bundle_id);

    xnu_pf_patchset_t* apfs_patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT);
    struct mach_header_64* apfs_header = xnu_pf_get_kext_header(hdr, "com.apple.filesystems.apfs");
    xnu_pf_range_t* apfs_text_exec_range = xnu_pf_section(apfs_header, "__TEXT_EXEC", "__text");
    //xnu_pf_range_t* apfs_text_cstring_range = xnu_pf_section(apfs_header, "__TEXT", "__cstring");

    const char rootvp_string[] = "rootvp not authenticated after mounting";
    const char *rootvp_string_match = memmem(text_cstring_range->cacheable_base, text_cstring_range->size, rootvp_string, sizeof(rootvp_string) - 1);
#if 0
    const char livefs_string[] = "Rooting from the live fs of a sealed volume is not allowed on a RELEASE build";
    const char *livefs_string_match = apfs_text_cstring_range ? memmem(apfs_text_cstring_range->cacheable_base, apfs_text_cstring_range->size, livefs_string, sizeof(livefs_string) - 1) : NULL;
    if(!livefs_string_match) livefs_string_match = memmem(text_cstring_range->cacheable_base, text_cstring_range->size, livefs_string, sizeof(livefs_string) - 1);
#endif

#ifdef DEV_BUILD
#if 0
    // 15.0 beta 1 onwards, but only iOS/iPadOS
    if((livefs_string_match != NULL) != (gKernelVersion.darwinMajor >= 21 && xnu_platform() == PLATFORM_IOS)) panic("livefs panic doesn't match expected Darwin version");
#endif
#endif

    for(size_t i = 0; i < sizeof(kpf_components)/sizeof(kpf_components[0]); ++i)
    {
        kpf_component_t *component = kpf_components[i];
        if(component->init)
        {
            component->init(hdr, text_cstring_range, palera1n_flags);
        }
    }

    shellcode_count = 0;
    for(size_t i = 0; i < sizeof(kpf_components)/sizeof(kpf_components[0]); ++i)
    {
        kpf_component_t *component = kpf_components[i];
        if((component->shc_size != NULL) != (component->shc_emit != NULL))
        {
            panic("KPF component %zu has mismatching shc_size/shc_emit", i);
        }
        if(component->shc_size)
        {
            shellcode_count += component->shc_size();
        }
    }

    xnu_pf_patchset_t *patchset = NULL;
    for(size_t i = 0; i < npatches; ++i)
    {
        kpf_patch_t *patch = patches[i];
        if(!patchset)
        {
            patchset = xnu_pf_patchset_create(patch->granule);
        }
        patch->patch(patchset);
        if(i + 1 >= npatches || kpf_compare_patches(patches + i, patches + i + 1) != 0)
        {
            struct mach_header_64 *bundle;
            if(patch->bundle)
            {
                bundle = xnu_pf_get_kext_header(hdr, patch->bundle);
                if(!bundle)
                {
                    panic("Failed to find bundle %s", patch->bundle);
                }
            }
            else
            {
                bundle = hdr;
            }
            xnu_pf_range_t *range = patch->section ? xnu_pf_section(bundle, patch->segment, patch->section) : xnu_pf_segment(bundle, patch->segment);
            if(!range)
            {
                if(patch->section)
                {
                    panic("Failed to find section %s.%s in %s", patch->segment, patch->section, patch->bundle ? patch->bundle : "XNU");
                }
                else
                {
                    panic("Failed to find segment %s in %s", patch->segment, patch->bundle ? patch->bundle : "XNU");
                }
            }
            xnu_pf_emit(patchset);
            xnu_pf_apply(range, patchset);
            xnu_pf_patchset_destroy(patchset);
            free(range);
            patchset = NULL;
        }
    }

    kpf_apfs_patches(apfs_patchset, rootvp_string_match == NULL);
#if 0
    if(livefs_string_match)
    {
        kpf_root_livefs_patch(apfs_patchset);
    }
#endif
    xnu_pf_emit(apfs_patchset);
    xnu_pf_apply(apfs_text_exec_range, apfs_patchset);
    xnu_pf_patchset_destroy(apfs_patchset);

    xnu_pf_patchset_t* amfi_patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT);
    struct mach_header_64* amfi_header = xnu_pf_get_kext_header(hdr, "com.apple.driver.AppleMobileFileIntegrity");
    xnu_pf_range_t* amfi_text_exec_range = xnu_pf_section(amfi_header, "__TEXT_EXEC", "__text");
    kpf_amfi_kext_patches(amfi_patchset);
    xnu_pf_emit(amfi_patchset);
    xnu_pf_apply(amfi_text_exec_range, amfi_patchset);
    xnu_pf_patchset_destroy(amfi_patchset);

    xnu_pf_patchset_t* sandbox_patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT);
    struct mach_header_64* sandbox_header = xnu_pf_get_kext_header(hdr, "com.apple.security.sandbox");
    xnu_pf_range_t* sandbox_text_exec_range = xnu_pf_section(sandbox_header, "__TEXT_EXEC", "__text");
    kpf_sandbox_kext_patches(sandbox_patchset);
    xnu_pf_emit(sandbox_patchset);
    xnu_pf_apply(sandbox_text_exec_range, sandbox_patchset);
    xnu_pf_patchset_destroy(sandbox_patchset);

    // TODO
    //struct mach_header_64* accessory_header = xnu_pf_get_kext_header(hdr, "com.apple.iokit.IOAccessoryManager");

    xnu_pf_range_t* text_exec_range = xnu_pf_section(hdr, "__TEXT_EXEC", "__text");
    struct mach_header_64* first_kext = xnu_pf_get_first_kext(hdr);
    if (first_kext) {
        xnu_pf_range_t* first_kext_text_exec_range = xnu_pf_section(first_kext, "__TEXT_EXEC", "__text");

        if (first_kext_text_exec_range) {
            uint64_t text_exec_end_real;
            uint64_t text_exec_end = text_exec_end_real = ((uint64_t) (text_exec_range->va)) + text_exec_range->size;
            uint64_t first_kext_p = ((uint64_t) (first_kext_text_exec_range->va));

            if (text_exec_end > first_kext_p && first_kext_text_exec_range->va > text_exec_range->va) {
                text_exec_end = first_kext_p;
            }

            text_exec_range->size -= text_exec_end_real - text_exec_end;
        }
    }
    xnu_pf_range_t* plk_text_range = xnu_pf_section(hdr, "__PRELINK_TEXT", "__text");
    xnu_pf_range_t* data_const_range = xnu_pf_section(hdr, "__DATA_CONST", "__const");
    xnu_pf_range_t* plk_data_const_range = xnu_pf_section(hdr, "__PLK_DATA_CONST", "__data");
    xnu_pf_patchset_t* xnu_data_const_patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_64BIT);

    has_found_sbops = false;
    xnu_pf_maskmatch(xnu_data_const_patchset, "mach_traps", traps_match, traps_mask, sizeof(traps_match)/sizeof(uint64_t), false, (void*)mach_traps_callback);
    xnu_pf_maskmatch(xnu_data_const_patchset, "mach_traps_alt", traps_match_alt, traps_mask_alt, sizeof(traps_match_alt)/sizeof(uint64_t), false, (void*)mach_traps_alt_callback);
    xnu_pf_ptr_to_data(xnu_data_const_patchset, xnu_slide_value(hdr), text_cstring_range, "Seatbelt sandbox policy", strlen("Seatbelt sandbox policy")+1, false, (void*)sb_ops_callback);
    xnu_pf_emit(xnu_data_const_patchset);
    xnu_pf_apply(data_const_range, xnu_data_const_patchset);
    xnu_pf_patchset_destroy(xnu_data_const_patchset);
    if(!found_mach_traps)
    {
        panic("Missing patch: mach_traps");
    }
    //bool is_unified = true;

    if (!has_found_sbops) {
        //is_unified = false;
        if (!plk_text_range) panic("no plk_text_range");
        xnu_pf_patchset_t* xnu_plk_data_const_patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_64BIT);
        xnu_pf_ptr_to_data(xnu_plk_data_const_patchset, xnu_slide_value(hdr), plk_text_range, "Seatbelt sandbox policy", strlen("Seatbelt sandbox policy")+1, true, (void*)sb_ops_callback);
        xnu_pf_emit(xnu_plk_data_const_patchset);
        xnu_pf_apply(plk_data_const_range, xnu_plk_data_const_patchset);
        xnu_pf_patchset_destroy(xnu_plk_data_const_patchset);
    }

    kpf_mac_mount_patch(xnu_text_exec_patchset);
    kpf_mac_dounmount_patch_0(xnu_text_exec_patchset);
    kpf_vm_map_protect_patch(xnu_text_exec_patchset);
    kpf_mac_vm_fault_enter_patch(xnu_text_exec_patchset);
    kpf_find_shellcode_funcs(xnu_text_exec_patchset);
    if(rootvp_string_match) // Union mounts no longer work
    {
        kpf_vnop_rootvp_auth_patch(xnu_text_exec_patchset);
    }

    xnu_pf_emit(xnu_text_exec_patchset);
    xnu_pf_apply(text_exec_range, xnu_text_exec_patchset);
    xnu_pf_patchset_destroy(xnu_text_exec_patchset);

    if (!found_amfi_mac_syscall) panic("no amfi_mac_syscall");
    if (!dounmount_found) panic("no dounmount");
    if (!repatch_ldr_x19_vnode_pathoff) panic("no repatch_ldr_x19_vnode_pathoff");
    if (!has_found_sbops) panic("no sbops?");
    if (!amfi_ret) panic("no amfi_ret?");
    if (!vnode_lookup) panic("no vnode_lookup?");
    DEVLOG("Found vnode_lookup: 0x%llx", xnu_rebase_va(xnu_ptr_to_va(vnode_lookup)));
    if (!vnode_put) panic("no vnode_put?");
    DEVLOG("Found vnode_put: 0x%llx", xnu_rebase_va(xnu_ptr_to_va(vnode_put)));
    if (offsetof_p_flags == -1) panic("no p_flags?");
    if (!found_vm_fault_enter) panic("no vm_fault_enter");
    if (!found_vm_map_protect) panic("Missing patch: vm_map_protect");
    if (!vfs_context_current) panic("Missing patch: vfs_context_current");
    if (!kpf_has_done_mac_mount) panic("Missing patch: mac_mount");

    uint32_t delta = (&shellcode_area[1]) - amfi_ret;
    delta &= 0x03ffffff;
    delta |= 0x14000000;
    *amfi_ret = delta;

    uint64_t sandbox_shellcode_p = xnu_ptr_to_va(shellcode_area);

    struct mac_policy_ops* ops = xnu_va_to_ptr(kext_rebase_va(sbops[3]));
    uint64_t ret_zero = ((ret0_gadget - xnu_slide_value(hdr)) & 0xFFFFFFFF);
    uint64_t open_shellcode = ((sandbox_shellcode_p - xnu_slide_value(hdr)) & 0xFFFFFFFF);

#define PATCH_OP(ops, op, val)         \
    if (ops->op) {                     \
        ops->op &= 0xFFFFFFFF00000000; \
        ops->op |= val;                \
    }

    PATCH_OP(ops, mpo_mount_check_mount, ret_zero);
    PATCH_OP(ops, mpo_mount_check_remount, ret_zero);
    PATCH_OP(ops, mpo_mount_check_umount, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_write, ret_zero);
    PATCH_OP(ops, mpo_file_check_mmap, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_rename, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_access, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_chroot, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_create, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_deleteextattr, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_exchangedata, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_exec, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_getattrlist, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_getextattr, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_ioctl, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_link, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_listextattr, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_open, open_shellcode);
    PATCH_OP(ops, mpo_vnode_check_readlink, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_setattrlist, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_setextattr, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_setflags, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_setmode, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_setowner, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_setutimes, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_stat, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_truncate, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_unlink, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_fsgetpath, ret_zero);
    PATCH_OP(ops, mpo_vnode_check_getattr, ret_zero);
    PATCH_OP(ops, mpo_mount_check_stat, ret_zero);
    PATCH_OP(ops, mpo_proc_check_get_cs_info, ret_zero);
    PATCH_OP(ops, mpo_proc_check_set_cs_info, ret_zero);
    uint64_t update_execve = ops->mpo_cred_label_update_execve;
    PATCH_OP(ops, mpo_cred_label_update_execve, open_shellcode+8);

    update_execve = kext_rebase_va(update_execve);

    uint32_t* shellcode_from = sandbox_shellcode;
    uint32_t* shellcode_end = sandbox_shellcode_end;
    uint32_t* shellcode_to = shellcode_area;
    // Identify where the LDR/STR insns that will need to be patched will be
    uint32_t* repatch_sandbox_shellcode_setuid_patch = sandbox_shellcode_setuid_patch - shellcode_from + shellcode_to;
    uint64_t* repatch_sandbox_shellcode_ptrs = (uint64_t*)(sandbox_shellcode_ptrs - shellcode_from + shellcode_to);

    while(shellcode_from < shellcode_end)
    {
        *shellcode_to++ = *shellcode_from++;
    }
    if (repatch_sandbox_shellcode_ptrs[0] != 0x4141413341414132) {
        panic("Shellcode corruption");
    }
    // Patch offset into LDR and STR p->p_flags
    repatch_sandbox_shellcode_setuid_patch[0] |= ((offsetof_p_flags>>2)&0x1ff)<<10;
    repatch_sandbox_shellcode_setuid_patch[2] |= ((offsetof_p_flags>>2)&0x1ff)<<10;

    // Patch shellcode pointers
    repatch_sandbox_shellcode_ptrs[0] = update_execve;
    repatch_sandbox_shellcode_ptrs[1] = xnu_ptr_to_va(vnode_gaddr);
    repatch_sandbox_shellcode_ptrs[2] = xnu_ptr_to_va(vfs_context_current);
    repatch_sandbox_shellcode_ptrs[3] = xnu_ptr_to_va(vnode_lookup);
    repatch_sandbox_shellcode_ptrs[4] = xnu_ptr_to_va(vnode_put);

    uint32_t* repatch_vnode_shellcode = &shellcode_area[4];
    *repatch_vnode_shellcode = repatch_ldr_x19_vnode_pathoff;

    if(!rootvp_string_match) // Only use underlying fs on union mounts
    {
        char *snapshotString = (char*)memmem((unsigned char *)text_cstring_range->cacheable_base, text_cstring_range->size, (uint8_t *)"com.apple.os.update-", strlen("com.apple.os.update-"));
        if (!snapshotString) snapshotString = (char*)memmem((unsigned char *)plk_text_range->cacheable_base, plk_text_range->size, (uint8_t *)"com.apple.os.update-", strlen("com.apple.os.update-"));
        if (!snapshotString) panic("no snapshot string");

        *snapshotString = 'x';
        puts("KPF: Disabled snapshot temporarily");
    }

    // TODO: tmp
    shellcode_area = shellcode_to;

    for(size_t i = 0; i < sizeof(kpf_components)/sizeof(kpf_components[0]); ++i)
    {
        kpf_component_t *component = kpf_components[i];
        if(component->shc_emit)
        {
            shellcode_area += component->shc_emit(shellcode_area);
        }
    }

    for(size_t i = 0; i < sizeof(kpf_components)/sizeof(kpf_components[0]); ++i)
    {
        if(kpf_components[i]->finish)
        {
            kpf_components[i]->finish(hdr, &palera1n_flags);
        }
    }

    for(size_t i = 0; i < sizeof(kpf_components)/sizeof(kpf_components[0]); ++i)
    {
        if(kpf_components[i]->bootprep)
        {
            kpf_components[i]->bootprep(hdr, palera1n_flags);
        }
    }

    if(palera1n_flags & palerain_option_verbose_boot)
    {
        gBootArgs->Video.v_display = 0;
    }

    tick_1 = get_ticks();
    printf("KPF: Applied patchset in %llu ms\n", (tick_1 - tick_0) / TICKS_IN_1MS);
}

static void set_flags(char *args, palerain_option_t *flags, const char *name)
{
    if(args[0] != '\0')
    {
        palerain_option_t val = strtoul(args, NULL, 16);
        printf("Setting %s to 0x%016llx\n", name, val);
        *flags = val;
    }
    else
    {
        printf("%s: 0x%016llx\n", name, *flags);
    }
}

static void palera1n_flags_cmd(const char *cmd, char *args)
{
    set_flags(args, &palera1n_flags, "palera1n_flags");
}

void module_entry(void)
{
    puts("");
    puts("");
    puts("#==================");
    puts("#");
    puts("# checkra1n kpf " CHECKRA1N_VERSION);
    puts("#");
    puts("# Proudly written in nano");
    puts("# (c) 2019-2023 Kim Jong Cracks");
    puts("#");
    puts("# This software is not for sale");
    puts("# If you purchased this, please");
    puts("# report the seller.");
    puts("#");
    puts("# Get it for free at https://checkra.in");
    puts("#");
    puts("#====  Made by  ===");
    puts("# argp, axi0mx, danyl931, jaywalker, kirb, littlelailo, nitoTV");
    puts("# never_released, nullpixel, pimskeks, qwertyoruiop, sbingner, siguza");
    puts("#==== Thanks to ===");
    puts("# haifisch, jndok, jonseals, xerub, lilstevie, psychotea, sferrini");
    puts("# Cellebrite (ih8sn0w, cjori, ronyrus et al.)");
    puts("#==================");

    for(size_t i = 0; i < sizeof(kpf_components)/sizeof(kpf_components[0]); ++i)
    {
        kpf_component_t *component = kpf_components[i];
        if(component->pre_init)
        {
            component->pre_init();
        }
    }

    preboot_hook = kpf_cmd;
    command_register("palera1n_flags", "set flags for checkra1n userland", palera1n_flags_cmd);
    command_register("kpf", "running checkra1n-kpf without booting (use bootux afterwards)", kpf_cmd);
    command_register("overlay", "loads an overlay disk image", kpf_overlay_cmd);
}
const char *module_name = "checkra1n-kpf2-12.0,16.4";

struct pongo_exports exported_symbols[] =
{
    { .name = NULL, .value = NULL },
};
