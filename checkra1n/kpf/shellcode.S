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
.globl _sandbox_shellcode
.globl _sandbox_shellcode_ptrs
.globl _sandbox_shellcode_end
.globl _sandbox_shellcode_setuid_patch
.globl _dyld_hook_shellcode

.globl _vnode_check_open_shc
.globl _vnode_check_open_shc_ptr
.globl _vnode_check_open_shc_end

.align 2
_sandbox_shellcode:
    b sandbox_shellcode_m
    b amfi_execve_hook
    b pre_execve_hook
vnode_getpath:
    mov x19, x0
    nop
    mov x0, x19
    ret
sandbox_shellcode_m: // deny .fsevent accesses
    mov x6, x30
    mov x4, x19
    mov x5, x0
    mov x0, x1
    cbz x0, nopath
    bl vnode_getpath
    cbz x0, nopath
    ldr x7, [x0]
    adr x0, pattern
    ldr x8, [x0]
    mov x0, xzr
    cmp x8, x7
    b.ne nomatch
mov x0, #1
nomatch:
nopath:
    mov x19, x4
    br x6
amfi_execve_hook: // you can't kill me :P (makes sure amfi doesn't try to kill our binaries)
    ldr x0, [sp, #8] // cs_flags
    ldr w1, [x0]
    orr w1, w1,   #0x04000000 // CS_PLATFORM_BINARY
    orr w1, w1,   #0x10000000 // CS_DEBUGGED
    orr w1, w1,   #0x000f // CS_VALID | CS_ADHOC | CS_GET_TASK_ALLOW | CS_INSTALLER
    and w1, w1, #(~0x3f00) // clearing CS_HARD | CS_KILL | CS_CHECK_EXPIRATION | CS_RESTRICT | CS_ENFORCEMENT | CS_REQUIRE_LV
    //and w1, w1, #(~0x00000000)
    str w1, [x0]
    mov x0, xzr
    ret
// call signature
//int mpo_cred_label_update_execve_t(
//    kauth_cred_t old_cred,
//    kauth_cred_t new_cred,
//    struct proc *p,
//    struct vnode *vp,
//    off_t offset,
//    struct vnode *scriptvp,
//    struct label *vnodelabel,
//    struct label *scriptvnodelabel,
//    struct label *execlabel,
//    u_int *csflags,
//    void *macpolicyattr,
//    size_t macpolicyattrlen,
//    int *disjointp
//    );
// setuid patch
pre_execve_hook:
    cbz x3, pre_execve_hook$orig
    sub sp, sp, #0x400
    stp x29, x30, [sp]
    stp x0, x1, [sp, #0x10]
    stp x2, x3, [sp, #0x20]
    stp x4, x5, [sp, #0x30]
    stp x6, x7, [sp, #0x40]
    ldr x16, vfs
    blr x16 // getting current vfs context
    mov x2, x0
    ldr x0, [sp, #0x28]
    add x1, sp, #0x80
    mov w8, #0x380
    stp xzr, x8, [x1]
    stp xzr, xzr, [x1, 0x10]
    ldr x16, vnode // getting vnode attributes
    blr x16
    cbnz x0, pre_execve_hook$orig$epilog // failed so we just jump out
    mov w2, #0
    ldr w8, [sp, #0xcc] // va_mode
    tbz w8, #11, pre_execve_hook$orig$gid
    ldr w8, [sp, #0xc4] // va_uid
    ldr x0, [sp, #0x18] // this is new_cred->uid
    str w8, [x0, #0x18]
    mov w2, #1 // Mark this as having been setuid or setgid
pre_execve_hook$orig$gid:
    ldr w8, [sp, #0xcc]
    tbz w8, #10, pre_execve_hook$orig$p_flags
    mov w2, #1
    ldr w8, [sp, #0xc8]
    ldr x0, [sp, #0x18]
    str w8, [x0, #0x28]
pre_execve_hook$orig$p_flags:
    cbz w2, pre_execve_hook$orig$epilog // didn't change UID or GID
    ldr x0, [sp, #0x20]
_sandbox_shellcode_setuid_patch:
    ldr w8, [x0, #0] // Gets replaced with real offset by kpf
    orr w8, w8, #0x100 // Add P_SUGID
    str w8, [x0, #0] // Gets replaced with real offset by kpf
pre_execve_hook$orig$epilog:
    ldp x0, x1, [sp, #0x10]
    ldp x2, x3, [sp, #0x20]
    ldp x4, x5, [sp, #0x30]
    ldp x6, x7, [sp, #0x40]
    ldp x29, x30, [sp]
    add sp, sp, #0x400
pre_execve_hook$orig:
    ldr x16, orig
    br x16

.align 3
_sandbox_shellcode_ptrs:
orig:
.quad 0x4141413341414132
vnode:
.quad 0x4141413541414134
vfs:
.quad 0x4141413741414136
vnode_lookup:
.quad 0x4141413941414138
vnode_put:
.quad 0x4141414141414140
pattern:
.quad 0x746E65766573662E // .fsevent

.align 2
_vnode_check_open_shc:
vnode_check_open_hook:
    sub  sp, sp, #0x50
    stp  x22, x21, [sp, #0x20]
    stp  x20, x19, [sp, #0x30]
    stp  x29, x30, [sp, #0x40]
    add  x29, sp, #0x40
    mov  x19, x3
    mov  x20, x2
    mov  x21, x1
    mov  x22, x0
    add  x0, sp, #0xc
    mov  w1, #0x14
    ldr  x8, proc_selfname      // get proc name
    blr  x8

    ldp  w8, w9, [sp, #0xc]     // check if procname is 'IDSBlastDoorService' or not.
    ldp  w10, w11, [sp, #0x14]
    ldr  w12, [sp, #0x1c]
    mov  w13, #0x4449
    movk w13, #0x4253, lsl #16  // 'IDSB'
    cmp  w8, w13
    mov  w8, #0x616c
    movk w8, #0x7473, lsl #16   // 'last'
    ccmp w9, w8, #0x0, eq
    mov  w8, #0x6f44
    movk w8, #0x726f, lsl #16   // 'Door'
    ccmp w10, w8, #0x0, eq
    mov  w8, #0x6553
    movk w8, #0x7672, lsl #16   // 'Serv'
    ccmp w11, w8, #0x0, eq
    mov  w8, #0x6369
    movk w8, #0x65, lsl #16     // 'ice\x00'
    ccmp w12, w8, #0x0, eq
    b.eq vnode_check_open_shc$orig  // go to normal checks.

vnode_check_open_shc$shellcode: // go to sandbox_shellcode_m and make sure deny .fsevent accesses
    mov  x0, x22
    mov  x1, x21
    mov  x2, x20
    mov  x3, x19
    ldp  x29, x30, [sp, #0x40]
    ldp  x20, x19, [sp, #0x30]
    ldp  x22, x21, [sp, #0x20]
    add  sp, sp, #0x50
    b    sandbox_shellcode_m

vnode_check_open_shc$orig:
    mov  x0, x22
    mov  x1, x21
    mov  x2, x20
    mov  x3, x19
    ldp  x29, x30, [sp, #0x40]
    ldp  x20, x19, [sp, #0x30]
    ldp  x22, x21, [sp, #0x20]
    add  sp, sp, #0x50
    ldr  x8, vnode_check_open_orig
    br   x8

.align 3
_vnode_check_open_shc_ptr:
proc_selfname:
.quad 0x5151515151515151
vnode_check_open_orig:
.quad 0x5252525252525252

.globl _proc_set_syscall_filter_mask_shc
.globl _proc_set_syscall_filter_mask_shc_target
.globl _zalloc_ro_mut
.globl one_area
one_area:
.balign 0x100, 0xff

_proc_set_syscall_filter_mask_shc:
cbz x2, _proc_set_syscall_filter_mask_shc_target
sub sp, sp, 0x40
stp x19, x20, [sp, 0x10]
stp x21, x22, [sp, 0x20]
stp x29, x30, [sp, 0x30]
mov x19, x0
mov x20, x1
mov x21, x2
mov x22, x3
mov x8, #8
mov x0, x17
mov x1, x21
mov x2, #0
adr x3, one_area
udiv x4, x22, x8
msub x10, x4, x8, x22
cbz x10, Lbl_zalloc_ro_mut
add x4, x4, #1
Lbl_zalloc_ro_mut:
bl _zalloc_ro_mut
mov x0, x19
mov x1, x20
mov x2, x21
mov x3, x22
ldp x19, x20, [sp, 0x10]
ldp x21, x22, [sp, 0x20]
ldp x29, x30, [sp, 0x30]
add sp, sp, 0x40
_proc_set_syscall_filter_mask_shc_target:
b .
_zalloc_ro_mut:
b .
 
.align 2
.globl _launchd_execve_hook
.globl _launchd_execve_hook_ptr
.globl _launchd_execve_hook_end
.globl _launchd_execve_hook_offset
.globl _launchd_execve_hook_pagesize
.globl _launchd_execve_hook_mach_vm_allocate_kernel

_launchd_execve_hook:
b          launchd_execve_hook$start

launchd_execve_hook$start:
sub        sp, sp, #0xa0
stp        x26, x25, [sp, #0x50]
stp        x24, x23, [sp, #0x60]
stp        x22, x21, [sp, #0x70]
stp        x20, x19, [sp, #0x80]
stp        x29, x30, [sp, #0x90]
add        x29, sp, #0x90
mov        x19, x2
mov        x20, x1
mov        x21, x0
stur       wzr, [x29, #-0x44]
str        xzr, [sp, #0x40]

mrs        x8, tpidr_el1
_launchd_execve_hook_offset:
ldr        x0, [x8, #0x0] // Gets replaced with real offset by kpf
cbz        x0, launchd_execve_hook$current_map$zero
launchd_execve_hook$current_map$notzero:
ldrh       w8, [x0, #0x0] // Gets replaced with real offset by kpf
b          launchd_execve_hook$get_map_page_size
_launchd_execve_hook_pagesize:
launchd_execve_hook$current_map$zero:
b launchd_execve_hook$current_map$zero_4k // Replaced with NOP by KPF on 16K
launchd_execve_hook$current_map$zero_16k:
mov        w8, #0xe       // 16k page
b launchd_execve_hook$get_map_page_size
launchd_execve_hook$current_map$zero_4k:
mov w8, #0xc // 4K page
launchd_execve_hook$get_map_page_size:
mov        w1, #0x1
lsl        w2, w1, w8    // map_page_size

add        x1, sp, #0x40 // &scratch_addr
mov        w3, #0x1      // VM_FLAGS_ANYWHERE
mov        x4, #0x0      // VM_KERN_MEMORY_NONE
_launchd_execve_hook_mach_vm_allocate_kernel:
mov        x3, x4        // Replaced with NOP on xnu 10063 and lower
ldr        x8, mach_vm_allocate_kernel
blr        x8

ldr        x22, [sp, #0x40]
adr        x0, fstype  // 'hfs'
mov        x1, x22     // scratch_addr
mov        w2, #0x4    // len
ldr        x8, copyout
blr        x8
cbnz       w0, launchd_execve_hook$panik_1

ldr        x8, [sp, #0x40]
add        x23, x8, #0x8    // align
str        x23, [sp, #0x40]
adr        x0, mountpoint   // '/cores'
mov        x1, x23          // scratch_addr
mov        w2, #0x7         // len
ldr        x8, copyout
blr        x8
cbnz       w0, launchd_execve_hook$panik_1

ldr        x8, [sp, #0x40]
add        x24, x8, #0x8    // align
str        x24, [sp, #0x40]
adr        x0, devfs_path   // '/dev/md0'
mov        x1, x24          // scratch_addr
mov        w2, #0x9         // len
ldr        x8, copyout
blr        x8
cbnz       w0, launchd_execve_hook$panik_1

ldr        x8, [sp, #0x40]
add        x1, x8, #0x10    // align
str        x1, [sp, #0x40]  // scratch_addr
stp        x24, xzr, [sp, #0x8]
add        x0, sp, #0x8     // argv64bit
mov        w2, #0x8         // sizeof(uint64_t)
ldr        x8, copyout
blr        x8
cbnz       w0, launchd_execve_hook$panik_1

stp        x22, x23, [sp, #0x18]
ldr        x8, [sp, #0x40]
stp        xzr, x8, [sp, #0x28]
str        xzr, [sp, #0x38]
mov        x0, x21       // proc
add        x1, sp, #0x18 // &muap
sub        x2, x29, #0x44 // retval
ldr        x8, mac_mount // call mac_mount
blr        x8
cbnz       w0, launchd_execve_hook$panik_2

launchd_execve_hook$orig:
mov        x0, x21
mov        x1, x20
mov        x2, x19
ldr        x8, mac_execve
blr        x8
launchd_execve_hook$ret:
ldp        x29, x30, [sp, #0x90]
ldp        x20, x19, [sp, #0x80]
ldp        x22, x21, [sp, #0x70]
ldp        x24, x23, [sp, #0x60]
ldp        x26, x25, [sp, #0x50]
add        sp, sp, #0xa0
ret

launchd_execve_hook$panik_1:
b          launchd_execve_hook$orig // copyout failed
launchd_execve_hook$panik_2:
b          launchd_execve_hook$orig // mac_mount failed

.align 3
_launchd_execve_hook_ptr:
mac_execve:
.quad 0x4141414141414141
mac_mount:
.quad 0x4242424242424242
mach_vm_allocate_kernel:
.quad 0x4343434343434343
copyout:
.quad 0x4444444444444444

.align 2
devfs_path:
.asciz "/dev/md0"
.align 2
fstype:
.asciz "hfs"
.align 2
mountpoint:
.asciz "/cores"

.align 2
_launchd_execve_hook_end:
_sandbox_shellcode_end:





// Function logic
// const char* dyld_hook(void)
// {
//     void *vnode;
//     errno_t ret = vnode_lookup(alt_dyld_path, 0, &vnode, vfs_context_current());
//     if(ret == 0)
//     {
//         vnode_put(vnode);
//         return alt_dyld_path;
//     }
//     return dyld_path;
// }
.globl _dyld_shc
.globl _dyld_shc_ctx
.globl _dyld_shc_lookup
.globl _dyld_shc_put
.globl _dyld_shc_end
.align 2
_dyld_shc:
    stp x29, x30, [sp, -0x20]!
_dyld_shc_ctx:
    bl . // vfs_context_current
    mov x3, x0
    add x2, sp, 0x18
    mov w1, 0
    adr x0, L_alt_dyld_path
_dyld_shc_lookup:
    bl . // vnode_lookup
    cbnz w0, L_dyld_shc_no_hook
    ldr x0, [sp, 0x18]
_dyld_shc_put:
    bl . // vnode_put
    adr x0, L_alt_dyld_path
    b L_dyld_shc_epilog
L_dyld_shc_no_hook:
    adr x0, L_dyld_path
L_dyld_shc_epilog:
    ldp x29, x30, [sp], 0x20
    ret
L_alt_dyld_path:
    .asciz "/cores/usr/lib/dyld"
L_dyld_path:
    .asciz "/usr/lib/dyld"
.align 2
_dyld_shc_end:



.globl _nvram_shc
.globl _nvram_shc_end
.align 2
_nvram_shc:
    // We get here from a patched ret.
    // Just check for kOFVariablePermKernelOnly (0x3) and turn it into kOFVariablePermRootOnly (0x0).
    cmp w0, 0x3
    csel w0, wzr, w0, eq
    ret
_nvram_shc_end:

.globl _kdi_shc
.globl _kdi_shc_orig
.globl _kdi_shc_get
.globl _kdi_shc_addr
.globl _kdi_shc_size
.globl _kdi_shc_new
.globl _kdi_shc_set
.globl _kdi_shc_end
.align 2
_kdi_shc:
    stp x29, x30, [sp, -0x10]!
_kdi_shc_orig:
    bl . // bl OSMetaClassBase::safeMetaCast
    cbz x0, L_kdi_shc_ret
    stp x19, x20, [sp, -0x10]!
    mov x19, x0
    ldr x8, [x0]
_kdi_shc_get:
    ldr x8, [x8] // OSDictionary::getObject
    adr x1, L_kdi_shc_str
    blr x8
    cbz x0, L_kdi_shc_out
_kdi_shc_addr:
    movz x0, 0x0000, lsl 48
    movk x0, 0x0000, lsl 32
    movk x0, 0x0000, lsl 16
    movk x0, 0x0000
_kdi_shc_size:
    movz w1, 0x0000, lsl 16
    movk w1, 0x0000
    mov w2, 3
_kdi_shc_new:
    bl . // IOMemoryDescriptor::withAddress
    mov x20, x0
    ldr x8, [x19]
_kdi_shc_set:
    ldr x8, [x8] // OSDictionary::setObject
    mov x2, x0
    adr x1, L_kdi_shc_ramfile
    mov x0, x19
    blr x8
    ldr x8, [x20]
    ldr x8, [x8, 0x28] // OSObject::release
    mov x0, x20
    blr x8
L_kdi_shc_out:
    mov x0, x19
    ldp x19, x20, [sp], 0x10
L_kdi_shc_ret:
    ldp x29, x30, [sp], 0x10
    ret
L_kdi_shc_str:
    .asciz "checkra1n-overlay"
L_kdi_shc_ramfile:
    .asciz "ramfile-memory-descriptor"
.align 2
_kdi_shc_end:

.globl _fsctl_shc
.globl _fsctl_shc_vnode_open
.globl _fsctl_shc_stolen_slowpath
.globl _fsctl_shc_orig_bl
.globl _fsctl_shc_vnode_close
.globl _fsctl_shc_stolen_fastpath
.globl _fsctl_shc_orig_b
.globl _fsctl_shc_end
.align 2
_fsctl_shc:
    movz w9, 0xc104, lsl 16
    movk w9, 0x4a50
    cmp w2, w9
    b.ne _fsctl_shc_stolen_fastpath
    ldr x9, [x1] // vnode
    ldr x9, [x9, 0xd8] // v_mount [XXX: offsetfinder?]
    add x9, x9, 0x4e4 // f_mntfromname [XXX: offsetfinder?]
    ldur x10, [x9]
    ldr x11, L_fsctl_shc_dev
    cmp x10, x11
    b.ne _fsctl_shc_stolen_fastpath
    ldrb w10, [x9, 8] // f_mntfromname byte 8
    cbnz w10, _fsctl_shc_stolen_fastpath
    // Slow path
    sub sp, sp, 0x40
    stp x19, x20, [sp, 0x10]
    stp x21, x22, [sp, 0x20]
    stp x29, x30, [sp, 0x30]
    mov x19, x0
    mov x20, x3
    mov x21, x4
    mov x22, x5
    str xzr, [sp]
    adr x0, L_fsctl_shc_mnt
    mov w1, 0x1 // FREAD
    mov w2, 0x0
    mov w3, 0x0
    mov x4, sp
    // x5 is already in place
_fsctl_shc_vnode_open:
    bl . // vnode_open
    cbnz w0, L_fsctl_shc_err
    mov x0, x19
    mov x1, sp
    movz w2, 0xc104, lsl 16
    movk w2, 0x4a50
    mov x3, x20
    mov x4, x21
    mov x5, x22
_fsctl_shc_stolen_slowpath:
    brk 0x41 // stolen instruction
_fsctl_shc_orig_bl:
    bl . // invoke orig
    mov x19, x0
    ldr x0, [sp]
    mov w1, 0x1 // FREAD
    mov x2, x22
_fsctl_shc_vnode_close:
    bl . // vnode_close
    mov x0, x19
L_fsctl_shc_err:
    ldp x19, x20, [sp, 0x10]
    ldp x21, x22, [sp, 0x20]
    ldp x29, x30, [sp, 0x30]
    add sp, sp, 0x40
    ret
_fsctl_shc_stolen_fastpath:
    brk 0x41 // stolen instruction
_fsctl_shc_orig_b:
    b . // invoke orig
L_fsctl_shc_dev:
    .ascii "/dev/md0"
L_fsctl_shc_mnt:
    .asciz "/fs/orig"
.align 2
_fsctl_shc_end:
