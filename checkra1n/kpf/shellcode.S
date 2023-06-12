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
    .asciz "/cores/dyld"
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
